import { connect } from "cloudflare:sockets";
import { getMailConfig } from "../config";
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

const SMTP_TIMEOUT_MS = 30_000;

export type SmtpConnector = (config: MailConfig) => Promise<SocketLike>;

async function defaultConnector(config: MailConfig): Promise<SocketLike> {
  const socket = connect(
    { hostname: config.smtpHost, port: config.smtpPort },
    { secureTransport: "off", allowHalfOpen: false },
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

  private constructor(connection: SocketConnection, config: MailConfig) {
    this.connection = connection;
    this.config = config;
  }

  static async open(config: MailConfig, connector: SmtpConnector = defaultConnector): Promise<SmtpClient> {
    const socket = await connector(config);
    const client = new SmtpClient(new SocketConnection(socket), config);
    try {
      const greeting = await client.readReply();
      client.expect(greeting, 220, "SMTP greeting");
      client.capabilities = await client.ehlo();
      return client;
    } catch (error) {
      client.close();
      throw error;
    }
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
    if (containsAsciiControl(command)) throw new SmtpProtocolError("SMTP command contains an injection character");
    await this.connection.writeText(`${command}\r\n`);
    const reply = await this.readReply();
    this.expect(reply, expected, command.split(" ")[0]);
    return reply;
  }

  private async ehlo(): Promise<Set<string>> {
    const reply = await this.command("EHLO icloud-mail-mcp.invalid", 250);
    return new Set(reply.lines.map((line) => line.trim().split(/\s+/u)[0].toUpperCase()));
  }

  async send(input: ComposeInput): Promise<{ raw: Uint8Array; messageId: string }> {
    const composed = composeRfc822({ ...input, from: this.config.email });
    if (!this.capabilities.has("STARTTLS")) throw new SmtpProtocolError("SMTP server does not advertise STARTTLS");
    await this.command("STARTTLS", 220);
    await this.connection.startTls();
    this.capabilities = await this.ehlo();
    const auth = base64Encode(`\u0000${this.config.email}\u0000${this.config.password}`);
    await this.command(`AUTH PLAIN ${auth}`, 235);

    const from = validateAddress(this.config.email);
    const recipients = smtpRecipients(input);
    await this.command(`MAIL FROM:<${from}>`, 250);
    for (const recipient of recipients) await this.command(`RCPT TO:<${recipient}>`, 250);
    await this.command("DATA", 354);
    await this.connection.writeBytes(dotStuffForSmtp(composed.raw));
    await this.connection.writeText(".\r\n");
    const delivered = await this.readReply();
    this.expect(delivered, 250, "SMTP message delivery");
    return composed;
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

  static async sendWithEnv(env: AppEnv, input: ComposeInput): Promise<{ raw: Uint8Array; messageId: string }> {
    const config = getMailConfig(env);
    const client = await SmtpClient.open(config);
    try {
      return await client.send(input);
    } finally {
      await client.quit();
      client.close();
    }
  }
}

type AppEnv = Env & {
  ICLOUD_EMAIL: string;
  ICLOUD_IMAP_USER: string;
  ICLOUD_APP_PASSWORD: string;
  IMAP_HOST?: string;
  IMAP_PORT?: string;
  SMTP_HOST?: string;
  SMTP_PORT?: string;
};
