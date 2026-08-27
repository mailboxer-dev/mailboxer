import { StrictMode, useRef, useState, type FormEvent } from "react";
import { createRoot } from "react-dom/client";
import {
  CalendarDays,
  Cloud,
  ContactRound,
  Mail,
  Plus,
  Server,
  ShieldCheck,
} from "lucide-react";
import type {
  AccountPreset,
  AuthPageModel,
  TlsMode,
} from "../src/auth-ui";
import { decodeAuthPageModel, detectAccountPreset } from "../src/auth-ui";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet,
  FieldTitle,
} from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import "./styles.css";

const previewModel: AuthPageModel = {
  version: 1,
  kind: "account-form",
  title: "Connect Email MCP",
  clientName: "ChatGPT",
  state: "preview-state",
  target: "start",
  draftNotice: false,
  account: {
    preset: "icloud",
    label: "Personal",
    address: "",
    services: { mail: true, calendar: true, contacts: true },
    imap: { host: "", port: "993", tlsMode: "implicit", user: "" },
    smtp: { host: "", port: "587", tlsMode: "starttls", user: "", sameCredentials: true },
  },
};

function Hidden({ name, value }: { name: string; value: string }) {
  return <input type="hidden" name={name} value={value} />;
}

function PageFrame({ page, children }: { page: AuthPageModel; children: React.ReactNode }) {
  return (
    <main className="mx-auto flex min-h-screen w-full max-w-3xl items-center px-4 py-8 sm:px-6 sm:py-12">
      <div className="w-full">
        <div className="mb-6 flex items-center gap-3 px-1">
          <div className="flex size-10 items-center justify-center rounded-xl bg-primary text-primary-foreground">
            <Mail aria-hidden="true" className="size-5" />
          </div>
          <div>
            <p className="text-sm font-medium">Email MCP</p>
            <p className="text-sm text-muted-foreground">Secure account connection</p>
          </div>
        </div>
        <Card className="shadow-sm">
          <CardHeader className="border-b">
            <CardTitle className="text-2xl tracking-tight sm:text-3xl">{page.title}</CardTitle>
            <CardDescription className="text-base">
              {page.kind === "account-form"
                ? "Choose the email account to connect. We'll detect its provider and verify the connection."
                : <><strong className="font-medium text-foreground">{page.clientName || "MCP client"}</strong> will use the accounts you connect here.</>}
            </CardDescription>
          </CardHeader>
          <CardContent className="pt-6">
            {page.message ? (
              <Alert className="mb-6">
                <ShieldCheck aria-hidden="true" />
                <AlertTitle>{page.message.kind === "error" ? "Connection issue" : "Account updated"}</AlertTitle>
                <AlertDescription>{page.message.text}</AlertDescription>
              </Alert>
            ) : null}
            {children}
          </CardContent>
        </Card>
        <p className="mt-4 px-1 text-center text-xs leading-relaxed text-muted-foreground">
          Credentials are encrypted. Message, calendar, and contact content is fetched live and is never stored by this Worker.
        </p>
      </div>
    </main>
  );
}

function ServiceSwitch({
  name,
  title,
  checked,
  onChange,
  icon: Icon,
}: {
  name: string;
  title: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  icon: typeof Mail;
}) {
  const id = `service-${name}`;
  return (
    <Field orientation="horizontal" className="items-center px-4 py-3">
      {checked ? <Hidden name={name} value="1" /> : null}
      <Icon aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
      <FieldLabel htmlFor={id} className="flex-1">{title}</FieldLabel>
      <Switch id={id} checked={checked} onCheckedChange={onChange} aria-label={title} />
    </Field>
  );
}

function TlsSelect({ name, value, onChange, service }: { name: string; value: TlsMode; onChange: (value: TlsMode) => void; service: "IMAP" | "SMTP" }) {
  return (
    <Field>
      <FieldLabel>{service} security</FieldLabel>
      <Hidden name={name} value={value} />
      <Select value={value} onValueChange={(next) => onChange(next as TlsMode)}>
        <SelectTrigger className="w-full" aria-label={`${service} security`}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem value="implicit">Implicit TLS ({service === "IMAP" ? "993" : "465"})</SelectItem>
            <SelectItem value="starttls">STARTTLS ({service === "IMAP" ? "143" : "587 or 2525"})</SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>
    </Field>
  );
}

function AccountForm({ page }: { page: Extract<AuthPageModel, { kind: "account-form" }> }) {
  const [address, setAddress] = useState(page.account.address);
  const [stage, setStage] = useState<"email" | "details">(
    page.target === "edit" || Boolean(page.account.address) ? "details" : "email",
  );
  const [preset, setPreset] = useState(page.account.address ? page.account.preset : "custom");
  const [mail, setMail] = useState(page.account.services.mail);
  const [calendar, setCalendar] = useState(page.account.services.calendar);
  const [contacts, setContacts] = useState(page.account.services.contacts);
  const [sameSmtp, setSameSmtp] = useState(page.account.smtp.sameCredentials);
  const [imapTls, setImapTls] = useState(page.account.imap.tlsMode);
  const [smtpTls, setSmtpTls] = useState(page.account.smtp.tlsMode);
  const emailInput = useRef<HTMLInputElement>(null);
  const isCustom = preset === "custom";

  function chooseProvider(next: AccountPreset) {
    setPreset(next);
    if (next === "custom") {
      setMail(true);
      setCalendar(false);
      setContacts(false);
    } else if (preset === "custom") {
      setMail(page.account.services.mail);
      setCalendar(page.account.services.calendar);
      setContacts(page.account.services.contacts);
    }
  }

  function continueFromEmail() {
    if (!emailInput.current?.reportValidity()) return;
    chooseProvider(detectAccountPreset(address));
    setStage("details");
  }

  function submitAccountForm(event: FormEvent<HTMLFormElement>) {
    if (stage !== "email") return;
    const submitter = (event.nativeEvent as SubmitEvent).submitter;
    if (submitter instanceof HTMLButtonElement && submitter.name === "decision") return;
    event.preventDefault();
    continueFromEmail();
  }

  const defaultLabel = page.account.label || (preset === "icloud" ? "iCloud" : address.split("@")[0] || "Email");

  return (
    <PageFrame page={page}>
      <form
        method="post"
        action="/authorize"
        onSubmit={submitAccountForm}
      >
        <Hidden name="authorization_state" value={page.state} />
        {stage === "email" ? (
          <>
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="email-discovery">What email would you like to configure?</FieldLabel>
                <Input
                  ref={emailInput}
                  id="email-discovery"
                  type="email"
                  autoComplete="username"
                  maxLength={320}
                  value={address}
                  onChange={(event) => setAddress(event.target.value)}
                  placeholder="you@example.com"
                  autoFocus
                  required
                />
                <FieldDescription>We'll detect iCloud automatically. Other addresses use custom IMAP and SMTP settings.</FieldDescription>
              </Field>
            </FieldGroup>
            <div className="mt-8 flex flex-col-reverse gap-3 border-t pt-5 sm:flex-row sm:justify-between">
              <Button type="submit" name="decision" value="deny" variant="ghost">Cancel</Button>
              <Button type="submit" size="lg">Continue</Button>
            </div>
          </>
        ) : (
          <>
            <Hidden name="target" value={page.target} />
            <Hidden name="preset" value={preset} />
            <Hidden name="address" value={address} />
            {page.accountId ? <Hidden name="account_id" value={page.accountId} /> : null}

            <FieldGroup>
              {page.draftNotice ? (
                <p className="text-sm leading-relaxed text-muted-foreground">
                  Changes stay in this encrypted reconnect draft until you continue from the account list.
                </p>
              ) : null}

              <Field orientation="horizontal" className="items-center rounded-lg border p-3">
                <div className="flex size-9 shrink-0 items-center justify-center rounded-lg border bg-background">
                  {isCustom ? <Server aria-hidden="true" className="size-4" /> : <Cloud aria-hidden="true" className="size-4" />}
                </div>
                <FieldContent className="min-w-0">
                  <FieldTitle className="truncate">{address}</FieldTitle>
                  <FieldDescription>{isCustom ? "Custom IMAP/SMTP server" : "iCloud detected"}</FieldDescription>
                </FieldContent>
                {page.target !== "edit" ? <Button type="button" variant="ghost" size="sm" onClick={() => setStage("email")}>Change email</Button> : null}
              </Field>

              <FieldSet>
                <FieldLegend>Account details</FieldLegend>
                <FieldGroup>
                  <Field>
                    <FieldLabel htmlFor="label">Account name</FieldLabel>
                    <Input id="label" name="label" type="text" maxLength={80} defaultValue={defaultLabel} placeholder="Personal" required />
                  </Field>

                  {isCustom ? (
                    <>
                      <Hidden name="custom_fields_present" value="1" />
                      <div className="grid gap-4 sm:grid-cols-[1fr_7rem]">
                        <Field>
                          <FieldLabel htmlFor="imap_host">IMAP hostname</FieldLabel>
                          <Input id="imap_host" name="imap_host" maxLength={253} defaultValue={page.account.imap.host} placeholder="imap.example.com" required />
                        </Field>
                        <Field>
                          <FieldLabel htmlFor="imap_port">Port</FieldLabel>
                          <Input id="imap_port" name="imap_port" type="number" min={1} max={65535} defaultValue={page.account.imap.port} required />
                        </Field>
                      </div>
                      <TlsSelect name="imap_tls_mode" value={imapTls} onChange={setImapTls} service="IMAP" />
                      <div className="grid gap-4 sm:grid-cols-2">
                        <Field>
                          <FieldLabel htmlFor="imap_user">IMAP username</FieldLabel>
                          <Input id="imap_user" name="imap_user" autoComplete="username" maxLength={320} defaultValue={page.account.imap.user || address} required />
                        </Field>
                        <Field>
                          <FieldLabel htmlFor="imap_password">IMAP password</FieldLabel>
                          <Input id="imap_password" name="imap_password" type="password" autoComplete="current-password" maxLength={256} required />
                        </Field>
                      </div>
                    </>
                  ) : (
                    <Field>
                      <FieldLabel htmlFor="app_password">Apple app-specific password</FieldLabel>
                      <Input id="app_password" name="app_password" type="password" autoComplete="current-password" maxLength={256} placeholder="xxxx-xxxx-xxxx-xxxx" required />
                      <FieldDescription>Create an app-specific password in your Apple Account security settings.</FieldDescription>
                    </Field>
                  )}
                </FieldGroup>
              </FieldSet>

              {isCustom ? (
                <FieldSet>
                  <FieldLegend>Outgoing mail</FieldLegend>
                  <FieldGroup>
                    <div className="grid gap-4 sm:grid-cols-[1fr_7rem]">
                      <Field>
                        <FieldLabel htmlFor="smtp_host">SMTP hostname</FieldLabel>
                        <Input id="smtp_host" name="smtp_host" maxLength={253} defaultValue={page.account.smtp.host} placeholder="smtp.example.com" required />
                      </Field>
                      <Field>
                        <FieldLabel htmlFor="smtp_port">Port</FieldLabel>
                        <Input id="smtp_port" name="smtp_port" type="number" min={1} max={65535} defaultValue={page.account.smtp.port} required />
                      </Field>
                    </div>
                    <TlsSelect name="smtp_tls_mode" value={smtpTls} onChange={setSmtpTls} service="SMTP" />
                    <Field orientation="horizontal" className="rounded-lg border p-3">
                      {sameSmtp ? <Hidden name="same_smtp_credentials" value="1" /> : null}
                      <FieldContent>
                        <FieldLabel htmlFor="same-smtp">Use IMAP credentials for SMTP</FieldLabel>
                        <FieldDescription>Most providers use the same username and password.</FieldDescription>
                      </FieldContent>
                      <Switch id="same-smtp" checked={sameSmtp} onCheckedChange={setSameSmtp} />
                    </Field>
                    {!sameSmtp ? (
                      <div className="grid gap-4 sm:grid-cols-2">
                        <Field>
                          <FieldLabel htmlFor="smtp_user">SMTP username</FieldLabel>
                          <Input id="smtp_user" name="smtp_user" autoComplete="username" maxLength={320} defaultValue={page.account.smtp.user || address} required />
                        </Field>
                        <Field>
                          <FieldLabel htmlFor="smtp_password">SMTP password</FieldLabel>
                          <Input id="smtp_password" name="smtp_password" type="password" autoComplete="current-password" maxLength={256} required />
                        </Field>
                      </div>
                    ) : null}
                  </FieldGroup>
                </FieldSet>
              ) : null}

              <FieldSet>
                <FieldLegend>Services</FieldLegend>
                <Hidden name="service_options_present" value="1" />
                <div className="overflow-hidden rounded-lg border">
                  <ServiceSwitch name="enable_mail" title="Mail" checked={mail} onChange={setMail} icon={Mail} />
                  {!isCustom ? (
                    <>
                      <Separator />
                      <ServiceSwitch name="enable_calendar" title="Calendar" checked={calendar} onChange={setCalendar} icon={CalendarDays} />
                      <Separator />
                      <ServiceSwitch name="enable_contacts" title="Contacts" checked={contacts} onChange={setContacts} icon={ContactRound} />
                    </>
                  ) : null}
                </div>
              </FieldSet>
            </FieldGroup>

            <div className="mt-8 flex flex-col-reverse gap-3 border-t pt-5 sm:flex-row sm:justify-between">
              {page.target === "start" ? (
                <Button type="submit" name="decision" value="deny" variant="ghost">Cancel</Button>
              ) : (
                <Button type="submit" name="action" value="list" variant="ghost">Back to accounts</Button>
              )}
              <div className="flex flex-col-reverse gap-2 sm:flex-row">
                <Button type="button" variant="outline" onClick={() => chooseProvider(isCustom ? "icloud" : "custom")}>
                  {isCustom ? "Use iCloud instead" : "Use custom server"}
                </Button>
                <Button type="submit" name="action" value="verify" size="lg">
                  {page.target === "start" ? "Verify and continue" : "Verify and save"}
                </Button>
              </div>
            </div>
          </>
        )}
      </form>
    </PageFrame>
  );
}

function capabilityLabels(account: Extract<AuthPageModel, { kind: "management" }>["accounts"][number]): string[] {
  return [
    account.capabilities.mail ? "Mail" : "",
    account.capabilities.calendar ? "Calendar" : "",
    account.capabilities.contacts ? "Contacts" : "",
  ].filter(Boolean);
}

function ManagementPage({ page }: { page: Extract<AuthPageModel, { kind: "management" }> }) {
  return (
    <PageFrame page={page}>
      <div className="flex flex-col gap-4">
        {page.accounts.map((account) => (
          <Card key={account.accountId} className="gap-4 shadow-none">
            <CardHeader>
              <div className="flex min-w-0 items-start gap-3">
                <div className="flex size-9 shrink-0 items-center justify-center rounded-lg border bg-muted">
                  {account.preset === "icloud" ? <Cloud aria-hidden="true" className="size-4" /> : <Server aria-hidden="true" className="size-4" />}
                </div>
                <div className="min-w-0">
                  <CardTitle className="truncate text-base">{account.label}</CardTitle>
                  <CardDescription className="truncate">{account.address}</CardDescription>
                </div>
              </div>
              {account.isDefault ? <CardAction><Badge>Default</Badge></CardAction> : null}
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                <Badge variant="outline">{account.preset === "icloud" ? "iCloud" : "Custom IMAP/SMTP"}</Badge>
                {capabilityLabels(account).map((capability) => <Badge key={capability} variant="secondary">{capability}</Badge>)}
              </div>
            </CardContent>
            <CardFooter className="flex flex-wrap gap-2 border-t pt-4">
              <form method="post" action="/authorize" className="contents">
                <Hidden name="authorization_state" value={page.state} />
                <Hidden name="mode" value="manage" />
                <Hidden name="account_id" value={account.accountId} />
                <Button type="submit" name="action" value="test" variant="outline" size="sm">Test</Button>
                <Button type="submit" name="action" value="edit" variant="outline" size="sm">Edit</Button>
                {!account.isDefault ? <Button type="submit" name="action" value="set_default" variant="outline" size="sm">Make default</Button> : null}
                <Button type="submit" name="action" value="remove" variant="ghost" size="sm">Remove</Button>
              </form>
            </CardFooter>
          </Card>
        ))}
      </div>

      <form method="post" action="/authorize" className="mt-6 flex flex-col-reverse gap-3 border-t pt-5 sm:flex-row sm:items-center">
        <Hidden name="authorization_state" value={page.state} />
        <Hidden name="mode" value="manage" />
        <Button type="submit" name="decision" value="deny" variant="ghost">Cancel</Button>
        <Button type="submit" name="action" value="add" variant="outline" className="sm:ml-auto">
          <Plus aria-hidden="true" data-icon="inline-start" /> Add account
        </Button>
        <Button type="submit" name="action" value="continue" size="lg">Continue</Button>
      </form>
    </PageFrame>
  );
}

function App({ page }: { page: AuthPageModel }) {
  return page.kind === "management" ? <ManagementPage page={page} /> : <AccountForm page={page} />;
}

const rootElement = document.getElementById("root");
if (!rootElement) throw new Error("Missing authorization UI root");
const encodedModel = rootElement.dataset.page;
const page = encodedModel ? decodeAuthPageModel(encodedModel) : previewModel;
createRoot(rootElement).render(<StrictMode><App page={page} /></StrictMode>);
