import { connect } from "cloudflare:sockets";
import {
  composeRfc822,
  dotStuffForSmtp,
  smtpRecipients,
  type ComposeInput,
  validateAddress,
} from "../mime";
import { SocketConnection, withTimeout, type SocketLike } from "../network";
import type { MailConfig } from "../types";
import { containsAsciiControl } from "../security";
import { protocolCommandName, withSpan } from "../tracing";

const SMTP_TIMEOUT_MS = 30_000;

export const SMTP_SOCKET_OPTIONS = {
  secureTransport: "starttls",
  allowHalfOpen: false,
} as const;

export type SmtpConnector = (config: MailConfig) => Promise<SocketLike>;

async function defaultConnector(config: MailConfig): Promise<SocketLike> {
  const socket = connect(
    { hostname: config.smtpHost, port: config.smtpPort },
    SMTP_SOCKET_OPTIONS,
  );
  if (socket.opened) await socket.opened;
  return socket;
}

interface SmtpReply {
  code: number;
  lines: string[];
}

function base64Encode(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export class SmtpProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SmtpProtocolError";
  }
}

export class SmtpClient {
  private readonly connection: SocketConnection;
  private readonly config: MailConfig;
  private capabilities = new Set<string>();
  private authenticated = false;

  private constructor(connection: SocketConnection, config: MailConfig) {
    this.connection = connection;
    this.config = config;
  }

  static async open(config: MailConfig, connector: SmtpConnector = defaultConnector): Promise<SmtpClient> {
    return withSpan(
      "mail.smtp.open",
      {
        "server.address": config.smtpHost,
        "server.port": config.smtpPort,
      },
      async (span) => {
        const socket = await connector(config);
        const client = new SmtpClient(new SocketConnection(socket), config);
        try {
          const greeting = await client.readReply();
          client.expect(greeting, 220, "SMTP greeting");
          client.capabilities = await client.ehlo();
          span.setAttribute("mail.smtp.capability_count", client.capabilities.size);
          return client;
        } catch (error) {
          client.close();
          throw error;
        }
      },
    );
  }

  private async readReply(): Promise<SmtpReply> {
    const lines: string[] = [];
    let code: number | null = null;
    while (true) {
      const line = await withTimeout(this.connection.readLine(), SMTP_TIMEOUT_MS, "SMTP response");
      const match = line.match(/^(\d{3})([ -])(.*)$/u);
      if (!match) throw new SmtpProtocolError("Malformed SMTP response");
      const currentCode = Number(match[1]);
      if (code === null) code = currentCode;
      if (currentCode !== code) throw new SmtpProtocolError("Inconsistent SMTP response code");
      lines.push(match[3]);
      if (match[2] === " ") return { code, lines };
    }
  }

  private expect(reply: SmtpReply, expected: number, operation: string): void {
    if (reply.code !== expected) throw new SmtpProtocolError(`${operation} failed with SMTP ${reply.code}`);
  }

  private async command(command: string, expected: number): Promise<SmtpReply> {
    return withSpan(
      "mail.smtp.command",
      {
        "mail.smtp.command_name": protocolCommandName(command),
        "mail.smtp.expected_code": expected,
      },
      async (span) => {
        if (containsAsciiControl(command)) throw new SmtpProtocolError("SMTP command contains an injection character");
        await this.connection.writeText(`${command}\r\n`);
        const reply = await this.readReply();
        span.setAttribute("mail.smtp.response_code", reply.code);
        span.setAttribute("mail.smtp.response_line_count", reply.lines.length);
        this.expect(reply, expected, command.split(" ")[0]);
        return reply;
      },
    );
  }

  private async ehlo(): Promise<Set<string>> {
    const reply = await this.command("EHLO icloud-mail-mcp.invalid", 250);
    return new Set(reply.lines.map((line) => line.trim().split(/\s+/u)[0].toUpperCase()));
  }

  async authenticate(): Promise<void> {
    if (this.authenticated) return;
    return withSpan("mail.smtp.authenticate", {}, async (span) => {
      if (!this.capabilities.has("STARTTLS")) throw new SmtpProtocolError("SMTP server does not advertise STARTTLS");
      await this.command("STARTTLS", 220);
      await this.connection.startTls();
      this.capabilities = await this.ehlo();
      const auth = base64Encode(`\u0000${this.config.email}\u0000${this.config.password}`);
      await this.command(`AUTH PLAIN ${auth}`, 235);
      this.authenticated = true;
      span.setAttribute("mail.smtp.authenticated", true);
    });
  }

  async send(input: ComposeInput): Promise<{ raw: Uint8Array; messageId: string }> {
    return withSpan(
      "mail.smtp.send",
      { "mail.smtp.input_attachment_count": input.attachments?.length ?? 0 },
      async (span) => {
        const composed = composeRfc822({ ...input, from: this.config.email });
        span.setAttribute("mail.smtp.message_bytes", composed.raw.byteLength);
        await this.authenticate();

        const from = validateAddress(this.config.email);
        const recipients = smtpRecipients(input);
        span.setAttribute("mail.smtp.recipient_count", recipients.length);
        await this.command(`MAIL FROM:<${from}>`, 250);
        for (const recipient of recipients) await this.command(`RCPT TO:<${recipient}>`, 250);
        await this.command("DATA", 354);
        await this.connection.writeBytes(dotStuffForSmtp(composed.raw));
        await this.connection.writeText(".\r\n");
        const delivered = await this.readReply();
        span.setAttribute("mail.smtp.delivery_code", delivered.code);
        this.expect(delivered, 250, "SMTP message delivery");
        return composed;
      },
    );
  }

  async quit(): Promise<void> {
    try {
      await this.command("QUIT", 221);
    } catch {
      // A successful DATA response is still a delivery result if QUIT is rejected.
    }
  }

  close(): void {
    this.connection.close();
  }

  static async sendWithConfig(config: MailConfig, input: ComposeInput): Promise<{ raw: Uint8Array; messageId: string }> {
    return withSpan("mail.smtp.session", {}, async () => {
      const client = await SmtpClient.open(config);
      try {
        return await client.send(input);
      } finally {
        await client.quit();
        client.close();
      }
    });
  }
}
