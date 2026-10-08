import { StrictMode, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  CalendarDays,
  ContactRound,
  Info,
  Mail,
} from "lucide-react";
import type {
  AuthPageModel,
  TlsMode,
  UiPageModel,
} from "../src/auth-ui";
import { decodeUiPageModel } from "../src/auth-ui";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
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
import { LandingPage } from "@/landing";
import "./styles.css";

const previewModel: AuthPageModel = {
  version: 1,
  kind: "account-form",
  title: "Connect mailboxer",
  clientName: "ChatGPT",
  state: "preview-state",
  target: "start",
  step: "email",
  account: {
    preset: "icloud",
    label: "Personal",
    address: "",
    services: { mail: true, calendar: true, contacts: true },
    imap: { host: "", port: "993", tlsMode: "implicit", user: "" },
    smtp: { host: "", port: "587", tlsMode: "starttls", user: "", sameCredentials: true },
    dav: { calendarUrl: "", contactsUrl: "", user: "" },
  },
};

function Hidden({ name, value }: { name: string; value: string }) {
  return <input type="hidden" name={name} value={value} />;
}

function ApplePasswordHelp({ includeWarning = false }: { includeWarning?: boolean }) {
  return (
    <>
      Use an <a href="https://support.apple.com/102654" target="_blank" rel="noreferrer" className="font-medium text-foreground underline underline-offset-4">app-specific password</a> from your Apple Account{includeWarning ? ", not your usual Apple password" : ""}.
    </>
  );
}

function PageFrame({ page, children }: { page: AuthPageModel; children: React.ReactNode }) {
  const description = page.step === "email"
    ? "Start with the email address you want to connect."
    : page.step === "password"
      ? `Enter the password for ${page.account.address} to connect this account.`
      : `Finish setting up ${page.account.address}.`;
  return (
    <main className="mx-auto flex min-h-screen w-full max-w-3xl items-center px-4 py-8 sm:px-6 sm:py-12">
      <div className="w-full">
        <header className="mb-6 px-1">
          <img src="/mailboxer-logo.png" alt="mailboxer" className="h-10 w-auto shrink-0" />
        </header>
        <Card className="shadow-sm">
          <CardHeader className="border-b">
            <CardTitle className="text-2xl tracking-tight sm:text-3xl">{page.title}</CardTitle>
            <CardDescription className="text-base">{description}</CardDescription>
          </CardHeader>
          <CardContent>
            {page.message?.kind === "error" ? (
              <Alert className="mb-6">
                <Info aria-hidden="true" />
                <AlertTitle>We couldn't continue</AlertTitle>
                <AlertDescription>{page.message.text}</AlertDescription>
              </Alert>
            ) : null}
            {children}
          </CardContent>
        </Card>
        <p className="mt-4 px-1 text-center text-xs leading-relaxed text-muted-foreground">
          Your sign-in details are encrypted. Your email, calendars, and contacts are read only when you ask for them.
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

const SECURITY_OPTIONS = [
  { value: "implicit", label: "Encrypted from the start" },
  { value: "starttls", label: "Connect first, then encrypt" },
] as const;

function SecuritySelect({ name, value, onChange, direction }: { name: string; value: TlsMode; onChange: (value: TlsMode) => void; direction: "incoming" | "outgoing" }) {
  return (
    <Field>
      <FieldLabel>Connection security</FieldLabel>
      <Hidden name={name} value={value} />
      <Select items={SECURITY_OPTIONS} value={value} onValueChange={(next) => onChange(next as TlsMode)}>
        <SelectTrigger className="w-full" aria-label={`${direction} mail connection security`}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            {SECURITY_OPTIONS.map((option) => (
              <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
            ))}
          </SelectGroup>
        </SelectContent>
      </Select>
    </Field>
  );
}

function AccountForm({ page }: { page: Extract<AuthPageModel, { kind: "account-form" }> }) {
  const [mail, setMail] = useState(page.account.services.mail);
  const [calendar, setCalendar] = useState(page.account.services.calendar);
  const [contacts, setContacts] = useState(page.account.services.contacts);
  const [sameSmtp, setSameSmtp] = useState(page.account.smtp.sameCredentials);
  const [imapTls, setImapTls] = useState(page.account.imap.tlsMode);
  const [smtpTls, setSmtpTls] = useState(page.account.smtp.tlsMode);
  const [appPassword, setAppPassword] = useState("");
  const [imapPassword, setImapPassword] = useState("");
  const [smtpPassword, setSmtpPassword] = useState("");
  const isCustom = page.account.preset === "custom";
  const defaultLabel = page.account.label || (isCustom ? page.account.address.split("@")[0] || "Email" : "iCloud");

  return (
    <PageFrame page={page}>
      <form method="post" action="/authorize">
        <Hidden name="authorization_state" value={page.state} />
        <Hidden name="target" value={page.target} />
        {page.step === "email" ? (
          <>
            <FieldGroup className="gap-4">
              <Field>
                <FieldLabel htmlFor="email-discovery">Email address</FieldLabel>
                <Input
                  id="email-discovery"
                  name="address"
                  type="email"
                  autoComplete="username"
                  maxLength={320}
                  defaultValue={page.account.address}
                  placeholder="you@example.com"
                  autoFocus
                  required
                />
                <FieldDescription>
                  Enter a previously connected email to sign in using its saved settings.
                </FieldDescription>
              </Field>
            </FieldGroup>
            <div className="mt-6 flex flex-col-reverse gap-3 border-t pt-4 sm:flex-row sm:justify-between">
              <Button type="submit" name="decision" value="deny" variant="ghost">Cancel</Button>
              <Button type="submit" name="action" value="lookup" size="lg">Continue</Button>
            </div>
          </>
        ) : page.step === "password" ? (
          <>
            <Hidden name="address" value={page.account.address} />
            <FieldGroup className="gap-4">
              <Field>
                <FieldLabel htmlFor="account_password">Password</FieldLabel>
                <Input id="account_password" name="account_password" type="password" autoComplete="current-password" maxLength={256} autoFocus required />
                <FieldDescription>
                  {isCustom ? "Use the password for this email account." : <ApplePasswordHelp />}
                </FieldDescription>
              </Field>
            </FieldGroup>
            <div className="mt-6 flex flex-col-reverse gap-3 border-t pt-4 sm:flex-row sm:justify-between">
              <Button type="submit" name="action" value="restart" variant="ghost" formNoValidate>Use a different email</Button>
              <Button type="submit" name="action" value="new_password" variant="outline" formNoValidate>Use a new password</Button>
              <Button type="submit" name="action" value="unlock" size="lg">Connect account</Button>
            </div>
          </>
        ) : page.step === "new-password" ? (
          <>
            <Hidden name="address" value={page.account.address} />
            <FieldGroup className="gap-4">
              <Field>
                <FieldLabel htmlFor="new_account_password">
                  {isCustom ? "Password" : "Apple app-specific password"}
                </FieldLabel>
                <Input
                  id="new_account_password"
                  name="new_account_password"
                  type="password"
                  autoComplete="current-password"
                  maxLength={256}
                  autoFocus
                  required
                />
                <FieldDescription>
                  {isCustom
                    ? "We'll find your provider settings and connect the available services automatically."
                    : <ApplePasswordHelp includeWarning />}
                </FieldDescription>
              </Field>
            </FieldGroup>
            <div className="mt-6 flex flex-col-reverse gap-3 border-t pt-4 sm:flex-row sm:justify-between">
              <Button type="submit" name="action" value="restart" variant="ghost" formNoValidate>Use a different email</Button>
              <Button type="submit" name="action" value="discover" size="lg">Continue</Button>
            </div>
          </>
        ) : (
          <>
            <Hidden name="onboarding_step" value="config" />
            <Hidden name="preset" value={page.account.preset} />
            <Hidden name="address" value={page.account.address} />

            <FieldGroup className="gap-4">
              <FieldSet>
                <FieldLegend>Account</FieldLegend>
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
                          <FieldLabel htmlFor="imap_host">Incoming mail server</FieldLabel>
                          <Input id="imap_host" name="imap_host" maxLength={253} defaultValue={page.account.imap.host} placeholder="mail.example.com" required />
                        </Field>
                        <Field>
                          <FieldLabel htmlFor="imap_port">Port</FieldLabel>
                          <Input id="imap_port" name="imap_port" type="number" min={1} max={65535} defaultValue={page.account.imap.port} required />
                        </Field>
                      </div>
                      <SecuritySelect name="imap_tls_mode" value={imapTls} onChange={setImapTls} direction="incoming" />
                      <div className="grid gap-4 sm:grid-cols-2">
                        <Field>
                          <FieldLabel htmlFor="imap_user">Sign-in name</FieldLabel>
                          <Input id="imap_user" name="imap_user" autoComplete="username" maxLength={320} defaultValue={page.account.imap.user || page.account.address} required />
                        </Field>
                        <Field>
                          <FieldLabel htmlFor="imap_password">Password</FieldLabel>
                          <div className="flex gap-2">
                            <Input
                              id="imap_password"
                              name="imap_password"
                              type="password"
                              autoComplete="current-password"
                              maxLength={256}
                              value={imapPassword}
                              onChange={(event) => setImapPassword(event.target.value)}
                              required
                            />

                          </div>
                          <FieldDescription>
                            Use the password for this email account.
                          </FieldDescription>
                        </Field>
                      </div>
                    </>
                  ) : (
                    <Field>
                      <FieldLabel htmlFor="app_password">Apple app-specific password</FieldLabel>
                      <div className="flex gap-2">
                        <Input
                          id="app_password"
                          name="app_password"
                          type="password"
                          autoComplete="current-password"
                          maxLength={256}
                          placeholder="xxxx-xxxx-xxxx-xxxx"
                          value={appPassword}
                          onChange={(event) => setAppPassword(event.target.value)}
                          required
                        />

                      </div>
                      <FieldDescription>
                        <ApplePasswordHelp includeWarning />
                      </FieldDescription>
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
                        <FieldLabel htmlFor="smtp_host">Outgoing mail server</FieldLabel>
                        <Input id="smtp_host" name="smtp_host" maxLength={253} defaultValue={page.account.smtp.host} placeholder="mail.example.com" required />
                      </Field>
                      <Field>
                        <FieldLabel htmlFor="smtp_port">Port</FieldLabel>
                        <Input id="smtp_port" name="smtp_port" type="number" min={1} max={65535} defaultValue={page.account.smtp.port} required />
                      </Field>
                    </div>
                    <SecuritySelect name="smtp_tls_mode" value={smtpTls} onChange={setSmtpTls} direction="outgoing" />
                    <Field orientation="horizontal" className="rounded-lg border p-3">
                      {sameSmtp ? <Hidden name="same_smtp_credentials" value="1" /> : null}
                      <FieldContent>
                        <FieldLabel htmlFor="same-smtp">Use the same sign-in details</FieldLabel>
                        <FieldDescription>Most email providers use the same details for incoming and outgoing mail.</FieldDescription>
                      </FieldContent>
                      <Switch id="same-smtp" checked={sameSmtp} onCheckedChange={setSameSmtp} />
                    </Field>
                    {!sameSmtp ? (
                      <div className="grid gap-4 sm:grid-cols-2">
                        <Field>
                          <FieldLabel htmlFor="smtp_user">Outgoing sign-in name</FieldLabel>
                          <Input id="smtp_user" name="smtp_user" autoComplete="username" maxLength={320} defaultValue={page.account.smtp.user || page.account.address} required />
                        </Field>
                        <Field>
                          <FieldLabel htmlFor="smtp_password">Outgoing password</FieldLabel>
                          <div className="flex gap-2">
                            <Input
                              id="smtp_password"
                              name="smtp_password"
                              type="password"
                              autoComplete="current-password"
                              maxLength={256}
                              value={smtpPassword}
                              onChange={(event) => setSmtpPassword(event.target.value)}
                              required
                            />

                          </div>
                          <FieldDescription>
                            Use the password for outgoing mail.
                          </FieldDescription>
                        </Field>
                      </div>
                    ) : null}
                  </FieldGroup>
                </FieldSet>
              ) : null}

              <FieldSet>
                <FieldLegend>What to connect</FieldLegend>
                <Hidden name="service_options_present" value="1" />
                <div className="overflow-hidden rounded-lg border">
                  <ServiceSwitch name="enable_mail" title="Mail" checked={mail} onChange={setMail} icon={Mail} />
                  <Separator />
                  <ServiceSwitch name="enable_calendar" title="Calendar" checked={calendar} onChange={setCalendar} icon={CalendarDays} />
                  <Separator />
                  <ServiceSwitch name="enable_contacts" title="Contacts" checked={contacts} onChange={setContacts} icon={ContactRound} />
                </div>
              </FieldSet>

              {isCustom && (calendar || contacts) ? (
                <FieldSet>
                  <FieldLegend>Calendar and contacts</FieldLegend>
                  <FieldGroup>
                    <Field>
                      <FieldLabel htmlFor="dav_user">Calendar and contacts sign-in name</FieldLabel>
                      <Input
                        id="dav_user"
                        name="dav_user"
                        autoComplete="username"
                        maxLength={320}
                        defaultValue={page.account.dav.user || page.account.imap.user || page.account.address}
                        required
                      />
                    </Field>
                    {calendar ? (
                      <Field>
                        <FieldLabel htmlFor="caldav_url">Calendar server address</FieldLabel>
                        <Input
                          id="caldav_url"
                          name="caldav_url"
                          type="url"
                          inputMode="url"
                          maxLength={2_048}
                          defaultValue={page.account.dav.calendarUrl}
                          placeholder="https://calendar.example.com/"
                          required
                        />
                      </Field>
                    ) : null}
                    {contacts ? (
                      <Field>
                        <FieldLabel htmlFor="carddav_url">Contacts server address</FieldLabel>
                        <Input
                          id="carddav_url"
                          name="carddav_url"
                          type="url"
                          inputMode="url"
                          maxLength={2_048}
                          defaultValue={page.account.dav.contactsUrl}
                          placeholder="https://contacts.example.com/"
                          required
                        />
                      </Field>
                    ) : null}
                    <FieldDescription>Find these addresses in your provider's calendar or contacts setup guide.</FieldDescription>
                  </FieldGroup>
                </FieldSet>
              ) : null}
            </FieldGroup>

            <div className="mt-6 flex flex-col-reverse gap-3 border-t pt-4 sm:flex-row sm:justify-between">
              <Button type="submit" name="action" value="restart" variant="ghost" formNoValidate>Use a different email</Button>
              <Button type="submit" name="action" value="verify" size="lg">
                Connect account
              </Button>
            </div>
          </>
        )}
      </form>
    </PageFrame>
  );
}

function App({ page }: { page: UiPageModel }) {
  if (page.kind === "landing") return <LandingPage page={page} />;
  return <AccountForm page={page} />;
}

const rootElement = document.getElementById("root");
if (!rootElement) throw new Error("Missing authorization UI root");
const encodedModel = rootElement.dataset.page;
const page = encodedModel ? decodeUiPageModel(encodedModel) : previewModel;
createRoot(rootElement).render(<StrictMode><App page={page} /></StrictMode>);
