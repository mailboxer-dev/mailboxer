import { useEffect, useRef, useState } from "react";
import {
  ArrowRight,
  Braces,
  Check,
  Cloud,
  ContactRound,
  Copy,
  ExternalLink,
  Mail,
  Menu,
  MessageCircle,
  Sparkles,
  X,
} from "lucide-react";
import type { LandingPageModel } from "../src/auth-ui";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const GITHUB_URL = "https://github.com/mailboxer-dev/mailboxer";
const SELF_HOST_URL = `${GITHUB_URL}#deploy-it-yourself`;

type CopyState = "idle" | "copied" | "error";

async function copyText(value: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // Some self-hosted HTTP origins do not expose the Clipboard API.
    }
  }

  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("Copy failed");
}

function CopyButton({ value, label, className = "", variant = "default" }: {
  value: string;
  label: string;
  className?: string;
  variant?: "default" | "outline";
}) {
  const [state, setState] = useState<CopyState>("idle");

  useEffect(() => {
    if (state === "idle") return;
    const timer = window.setTimeout(() => setState("idle"), 4_000);
    return () => window.clearTimeout(timer);
  }, [state]);

  const visibleLabel = state === "copied" ? "Copied" : state === "error" ? "Select and copy" : label;

  return (
    <>
      <Button
        type="button"
        variant={variant}
        size="lg"
        className={`h-12 gap-2 px-5 text-base ${className}`}
        onClick={() => {
          void copyText(value).then(() => setState("copied"), () => setState("error"));
        }}
      >
        {state === "copied" ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
        {visibleLabel}
      </Button>
      <span className="sr-only" aria-live="polite">
        {state === "copied" ? `${label} copied to clipboard.` : state === "error" ? "Automatic copy failed. Select the text and copy it manually." : ""}
      </span>
    </>
  );
}

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <a href="#top" aria-label="Mailboxer home" className="inline-flex shrink-0 items-center rounded-sm focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-primary">
      <img src="/mailboxer-logo.png" alt="mailboxer" className={compact ? "h-10 w-auto" : "h-14 w-auto sm:h-16"} />
    </a>
  );
}

function Header() {
  const [open, setOpen] = useState(false);
  const links = [
    ["How it works", "#how-it-works"],
    ["Choose your agent", "#choose-your-agent"],
    ["Privacy", "#privacy"],
  ] as const;

  return (
    <header className="relative z-20 mx-auto flex w-full max-w-[1440px] items-center justify-between px-5 py-6 sm:px-8 lg:px-14 lg:py-8">
      <Brand />
      <nav aria-label="Primary navigation" className="hidden items-center gap-9 text-[15px] font-medium text-foreground lg:flex">
        {links.map(([label, href]) => (
          <a key={href} href={href} className="rounded-sm underline-offset-8 transition-colors hover:text-primary hover:underline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-primary">
            {label}
          </a>
        ))}
        <a href={GITHUB_URL} target="_blank" rel="noreferrer" className="rounded-sm underline-offset-8 transition-colors hover:text-primary hover:underline focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-primary">
          GitHub
        </a>
      </nav>
      <Button type="button" variant="ghost" size="icon-lg" className="lg:hidden" aria-label={open ? "Close navigation" : "Open navigation"} aria-expanded={open} onClick={() => setOpen((value) => !value)}>
        {open ? <X aria-hidden="true" /> : <Menu aria-hidden="true" />}
      </Button>
      {open ? (
        <nav aria-label="Mobile navigation" className="absolute inset-x-5 top-[76px] flex flex-col rounded-xl border bg-white p-3 shadow-lg sm:inset-x-8 lg:hidden">
          {links.map(([label, href]) => (
            <a key={href} href={href} className="rounded-lg px-4 py-3 text-base font-medium hover:bg-muted focus-visible:outline-2 focus-visible:outline-primary" onClick={() => setOpen(false)}>
              {label}
            </a>
          ))}
          <a href={GITHUB_URL} target="_blank" rel="noreferrer" className="flex items-center justify-between rounded-lg px-4 py-3 text-base font-medium hover:bg-muted focus-visible:outline-2 focus-visible:outline-primary">
            GitHub <ExternalLink aria-hidden="true" className="size-4" />
          </a>
        </nav>
      ) : null}
    </header>
  );
}

function HeroMailboxIllustration() {
  return (
    <svg viewBox="0 0 620 570" role="img" aria-labelledby="hero-illustration-title" className="h-auto w-full max-w-[600px] text-primary">
      <title id="hero-illustration-title">A mailbox connecting email, calendar, and contacts to an agent</title>
      <g fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round">
        <path d="M95 452V210c0-93 61-160 146-160s146 67 146 160v242" strokeWidth="2.5" />
        <path d="M119 452V214c0-78 49-137 122-137s122 59 122 137v238" opacity=".45" strokeWidth="1.5" />
        <path d="M95 452l24 13V216" strokeWidth="2.5" />
        <path d="M246 452h148" strokeWidth="2.5" />
        <rect x="175" y="246" width="126" height="82" rx="7" strokeWidth="2.5" />
        <path d="m181 255 56 47a13 13 0 0 0 17 0l41-39" strokeWidth="2.5" />
        <path d="M168 341h142" strokeWidth="2.5" />
        <circle cx="339" cy="282" r="8" fill="currentColor" stroke="none" />
        <path d="M350 282h70c27 0 39-18 39-43v-30" strokeDasharray="7 9" strokeWidth="2" />
        <path d="M350 282h109" strokeDasharray="7 9" strokeWidth="2" />
        <path d="M350 282h70c27 0 39 18 39 43v30" strokeDasharray="7 9" strokeWidth="2" />
        <circle cx="493" cy="160" r="49" strokeWidth="1.5" />
        <circle cx="493" cy="282" r="49" strokeWidth="1.5" />
        <circle cx="493" cy="404" r="49" strokeWidth="1.5" />
        <rect x="471" y="145" width="44" height="31" rx="4" strokeWidth="2.5" />
        <path d="m474 150 17 14a4 4 0 0 0 5 0l16-14" strokeWidth="2.5" />
        <rect x="471" y="262" width="44" height="40" rx="5" strokeWidth="2.5" />
        <path d="M480 255v14m25-14v14m-25 11h26m-25 10h3m8 0h3m8 0h3" strokeWidth="2.5" />
        <circle cx="493" cy="389" r="13" strokeWidth="2.5" />
        <path d="M469 422c3-15 12-22 24-22s21 7 24 22" strokeWidth="2.5" />
      </g>
      <g fill="currentColor" fontFamily="ui-sans-serif, system-ui" fontSize="14.5" fontWeight="600">
        <text x="548" y="166">Email</text>
        <text x="548" y="288">Calendar</text>
        <text x="548" y="410">Contacts</text>
      </g>
    </svg>
  );
}

function SetupPanel({ page, prompt }: { page: LandingPageModel; prompt: string }) {
  return (
    <div className="max-w-[760px] rounded-xl border bg-white p-5 shadow-[0_18px_50px_rgba(16,33,61,0.06)] sm:p-6">
      <div className="flex gap-4">
        <div className="mt-0.5 flex size-11 shrink-0 items-center justify-center rounded-full bg-primary text-primary-foreground sm:size-12">
          <Sparkles aria-hidden="true" className="size-5" />
        </div>
        <div className="min-w-0 flex-1">
          <h2 className="text-xl font-bold tracking-tight sm:text-2xl">Let your agent set it up</h2>
          <div className="mt-3 flex flex-col gap-3 xl:flex-row">
            <code className="min-w-0 flex-1 select-all break-words rounded-lg border bg-[#fbfdff] px-4 py-3 text-[13px] leading-6 text-foreground sm:text-sm">
              {prompt}
            </code>
            <CopyButton value={prompt} label="Copy prompt" className="xl:self-center" />
          </div>
          <p className="mt-3 text-sm leading-6 text-muted-foreground">Best for Codex, Claude Code, and other setup-capable agents.</p>
        </div>
      </div>

      <div className="my-5 flex items-center gap-4 text-sm text-muted-foreground" aria-hidden="true">
        <span className="h-px flex-1 bg-border" /> or <span className="h-px flex-1 bg-border" />
      </div>

      <div className="flex gap-4">
        <div className="mt-0.5 flex size-11 shrink-0 items-center justify-center rounded-full bg-muted text-primary sm:size-12">
          <ContactRound aria-hidden="true" className="size-5" />
        </div>
        <div className="min-w-0 flex-1">
          <h2 className="text-xl font-bold tracking-tight sm:text-2xl">Prefer to set it up yourself?</h2>
          <div className="mt-3 flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
            <code className="min-w-0 flex-1 select-all overflow-x-auto rounded-lg border bg-[#fbfdff] px-4 py-3.5 text-sm whitespace-nowrap text-foreground">{page.mcpUrl}</code>
            <CopyButton value={page.mcpUrl} label="Copy address" variant="outline" />
            <a href="#choose-your-agent" className="inline-flex h-12 items-center justify-center gap-2 rounded-lg px-2 text-sm font-semibold text-primary underline-offset-4 hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary">
              See manual steps <ArrowRight aria-hidden="true" className="size-4" />
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}

function Hero({ page }: { page: LandingPageModel }) {
  const prompt = `Fetch and execute the appropriate instructions to connect this agent to Mailboxer from ${page.agentSetupUrl}`;
  return (
    <section className="mx-auto grid w-full max-w-[1440px] items-center gap-12 px-5 py-10 sm:px-8 lg:grid-cols-[1.08fr_0.92fr] lg:px-14 lg:py-8">
      <div>
        <h1 className="max-w-[760px] text-[clamp(3.25rem,6.25vw,5.75rem)] leading-[0.95] font-bold tracking-[-0.055em] text-foreground">
          Give your agent<br />a mailbox.
        </h1>
        <p className="mt-7 max-w-[660px] text-xl leading-8 text-foreground/88 sm:text-2xl sm:leading-10">
          Connect your email, calendar, and contacts to ChatGPT, Claude, or Codex — then ask for what you need in plain language.
        </p>
        <div className="mt-8">
          <SetupPanel page={page} prompt={prompt} />
        </div>
      </div>
      <div className="mx-auto hidden w-full items-center justify-center lg:flex">
        <HeroMailboxIllustration />
      </div>
    </section>
  );
}

const journey = [
  {
    title: "Add Mailboxer to your agent",
    body: "Use the setup prompt, or paste this instance’s address yourself.",
    icon: Mail,
  },
  {
    title: "Connect your account",
    body: "Sign in and choose mail, calendar, or contacts. Add a separate connection for each account.",
    icon: ContactRound,
  },
  {
    title: "Start asking",
    body: "Try: ‘What needs my reply today?’ or ‘What’s on my calendar tomorrow?’",
    icon: MessageCircle,
  },
] as const;

function Journey() {
  return (
    <section id="how-it-works" className="scroll-mt-8 border-y bg-[#f4f8fe] px-5 py-16 sm:px-8 lg:px-14 lg:py-20">
      <div className="mx-auto max-w-[1320px]">
        <div className="text-center">
          <h2 className="text-4xl font-bold tracking-[-0.04em] sm:text-5xl">Three steps. A few minutes.</h2>
          <p className="mt-4 text-lg text-muted-foreground sm:text-xl">Mailboxer handles the handoff. You stay in control.</p>
        </div>
        <div className="relative mt-16 grid gap-10 md:grid-cols-3 md:gap-8">
          <div className="absolute top-5 right-[16.5%] left-[16.5%] hidden h-px bg-primary md:block" aria-hidden="true" />
          {journey.map(({ title, body, icon: Icon }, index) => (
            <article key={title} className="relative text-center">
              <div className="relative z-10 mx-auto flex size-10 items-center justify-center rounded-full bg-primary text-sm font-bold text-primary-foreground">{index + 1}</div>
              <div className="mx-auto mt-8 flex h-32 w-44 items-center justify-center rounded-xl border bg-white shadow-[0_10px_28px_rgba(16,33,61,0.04)]">
                <Icon aria-hidden="true" className="size-12 stroke-[1.35] text-primary" />
              </div>
              <h3 className="mt-7 text-xl font-bold tracking-tight sm:text-2xl">{title}</h3>
              <p className="mx-auto mt-2 max-w-sm text-base leading-7 text-muted-foreground sm:text-lg">{body}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

const agents = [
  {
    id: "chatgpt",
    name: "ChatGPT",
    icon: MessageCircle,
    instruction: "Open Settings → Apps, create a custom app, paste your Mailboxer address, then follow the sign-in prompt.",
  },
  {
    id: "claude",
    name: "Claude",
    icon: Sparkles,
    instruction: "Open Settings → Connectors, add a custom connector, paste your Mailboxer address, then choose Connect.",
  },
  {
    id: "codex",
    name: "Codex",
    icon: Braces,
    instruction: "Open Settings → MCP Servers, add a server with your Mailboxer address, then complete sign-in.",
  },
] as const;

function AgentGuide({ page }: { page: LandingPageModel }) {
  const [selected, setSelected] = useState<(typeof agents)[number]["id"]>("chatgpt");
  const tabListRef = useRef<HTMLDivElement>(null);
  const active = agents.find((agent) => agent.id === selected) ?? agents[0];
  const ActiveIcon = active.icon;

  useEffect(() => {
    const tabList = tabListRef.current;
    if (!tabList || tabList.scrollWidth <= tabList.clientWidth) return;
    const index = agents.findIndex((agent) => agent.id === selected);
    const tab = tabList.querySelectorAll<HTMLElement>("[role=tab]")[index];
    if (tab) {
      tabList.scrollLeft = Math.max(0, tab.offsetLeft - tabList.offsetLeft - 8);
    }
  }, [selected]);

  function moveTab(event: React.KeyboardEvent<HTMLButtonElement>, direction: number) {
    const current = agents.findIndex((agent) => agent.id === selected);
    const next = (current + direction + agents.length) % agents.length;
    setSelected(agents[next].id);
    window.requestAnimationFrame(() => {
      tabListRef.current?.querySelectorAll<HTMLButtonElement>("[role=tab]")[next]?.focus();
    });
    event.preventDefault();
  }

  return (
    <section id="choose-your-agent" className="scroll-mt-8 bg-white px-5 py-20 sm:px-8 lg:px-14 lg:py-24">
      <div className="mx-auto max-w-[1320px]">
        <div className="lg:ml-[340px]">
          <h2 className="text-4xl font-bold tracking-[-0.04em] sm:text-5xl">Choose your agent</h2>
          <p className="mt-3 text-lg text-muted-foreground sm:text-xl">The words differ a little. The connection is the same.</p>
        </div>
        <div className="mt-10 grid gap-6 lg:grid-cols-[310px_1fr] lg:gap-10">
          <div ref={tabListRef} role="tablist" aria-label="Agent setup instructions" className="flex overflow-x-auto rounded-xl border bg-[#fbfdff] lg:flex-col lg:overflow-visible">
            {agents.map((agent) => {
              const Icon = agent.icon;
              const isActive = selected === agent.id;
              return (
                <button
                  key={agent.id}
                  id={`agent-tab-${agent.id}`}
                  type="button"
                  role="tab"
                  aria-selected={isActive}
                  aria-controls="agent-instructions"
                  tabIndex={isActive ? 0 : -1}
                  className={`flex min-w-[170px] flex-1 items-center gap-3 border-b-2 px-5 py-5 text-left text-lg font-bold transition-colors focus-visible:z-10 focus-visible:outline-2 focus-visible:outline-primary lg:min-w-0 lg:border-r-0 lg:border-b lg:py-7 ${isActive ? "border-primary bg-[#edf4ff] text-primary lg:border-l-4" : "border-transparent hover:bg-muted lg:border-b-border"}`}
                  onClick={() => setSelected(agent.id)}
                  onKeyDown={(event) => {
                    if (["ArrowRight", "ArrowDown"].includes(event.key)) moveTab(event, 1);
                    if (["ArrowLeft", "ArrowUp"].includes(event.key)) moveTab(event, -1);
                    if (event.key === "Home") { setSelected(agents[0].id); event.preventDefault(); }
                    if (event.key === "End") { setSelected(agents.at(-1)?.id ?? "codex"); event.preventDefault(); }
                  }}
                >
                  <Icon aria-hidden="true" className="size-6 stroke-[1.6]" />
                  {agent.name}
                  <ArrowRight aria-hidden="true" className="ml-auto size-4" />
                </button>
              );
            })}
          </div>
          <div id="agent-instructions" role="tabpanel" aria-labelledby={`agent-tab-${active.id}`} className="overflow-hidden rounded-xl border bg-white shadow-[0_16px_42px_rgba(16,33,61,0.05)]">
            <div className="flex min-h-44 gap-5 p-6 sm:p-8">
              <div className="flex size-12 shrink-0 items-center justify-center rounded-full bg-muted text-primary">
                <ActiveIcon aria-hidden="true" className="size-6 stroke-[1.6]" />
              </div>
              <div>
                <h3 className="text-2xl font-bold tracking-tight sm:text-3xl">{active.name}</h3>
                <p className="mt-3 max-w-3xl text-lg leading-8 text-foreground/82">{active.instruction}</p>
              </div>
            </div>
            <div className="flex flex-col gap-3 border-t bg-[#fbfdff] p-5 sm:flex-row sm:items-center sm:p-7">
              <div className="flex min-w-0 flex-1 items-center gap-3 rounded-lg border bg-white px-4 py-3.5">
                <Mail aria-hidden="true" className="size-5 shrink-0 text-primary" />
                <code className="select-all overflow-x-auto text-sm whitespace-nowrap sm:text-base">{page.mcpUrl}</code>
              </div>
              <CopyButton value={page.mcpUrl} label="Copy address" />
            </div>
          </div>
        </div>
        <p className="mt-5 text-center text-sm text-muted-foreground">Options and availability can vary by plan.</p>
      </div>
    </section>
  );
}

function PrivacyMailboxIllustration() {
  return (
    <svg viewBox="0 0 300 240" aria-hidden="true" className="mx-auto h-auto w-full max-w-[300px] text-primary">
      <g fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.4">
        <path d="M67 154V93c0-47 30-78 74-78s74 31 74 78v61" />
        <path d="M141 15v139m74 0h28" opacity=".45" />
        <path d="M116 28h26v33h-26" />
        <path d="M116 28V7" />
        <rect x="83" y="102" width="104" height="66" rx="6" fill="#f6f8fc" />
        <path d="m89 109 39 33a11 11 0 0 0 14 0l39-33" />
        <path d="M67 155h176M141 168v60" opacity=".55" />
      </g>
    </svg>
  );
}

function Privacy() {
  return (
    <section id="privacy" className="scroll-mt-8 px-5 py-20 sm:px-8 lg:px-14 lg:py-28">
      <div className="mx-auto max-w-[1320px]">
        <div className="text-center">
          <h2 className="text-4xl font-bold tracking-[-0.04em] sm:text-6xl">Your inbox stays yours.</h2>
          <p className="mx-auto mt-5 max-w-3xl text-lg leading-8 text-muted-foreground sm:text-xl">
            Mailboxer connects your agent to the accounts you choose.<br className="hidden sm:block" /> It doesn’t create a second inbox or keep a copy of your messages.
          </p>
        </div>
        <div className="mt-16 grid items-center gap-12 md:grid-cols-[1fr_300px_1fr] md:gap-8">
          <div className="text-center md:text-right">
            <h3 className="text-xl font-bold text-primary sm:text-2xl">Protected sign-in details</h3>
            <p className="mt-3 text-base leading-7 text-muted-foreground sm:text-lg">Your account details are encrypted before they’re saved.</p>
          </div>
          <PrivacyMailboxIllustration />
          <div className="space-y-10 text-center md:text-left">
            <div>
              <h3 className="text-xl font-bold text-primary sm:text-2xl">Fetched when you ask</h3>
              <p className="mt-3 text-base leading-7 text-muted-foreground sm:text-lg">Messages, events, and contacts come directly from your provider when your agent needs them.</p>
            </div>
            <div>
              <h3 className="text-xl font-bold text-primary sm:text-2xl">You choose what connects</h3>
              <p className="mt-3 text-base leading-7 text-muted-foreground sm:text-lg">Connect mail, calendar, contacts, or more than one account. You can change that choice later.</p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function SelfHost() {
  return (
    <section className="px-5 pb-8 sm:px-8 lg:px-14">
      <div className="mx-auto grid max-w-[1320px] gap-10 rounded-xl border bg-[#edf4ff] p-7 sm:p-10 lg:grid-cols-[1fr_0.9fr] lg:items-center lg:p-14">
        <div>
          <h2 className="text-4xl leading-[1.03] font-bold tracking-[-0.04em] sm:text-5xl">Don’t trust us?<br />Deploy it yourself.</h2>
          <p className="mt-5 max-w-xl text-lg leading-8 text-muted-foreground">Run Mailboxer in your own Cloudflare account. The README includes a one-click deploy button and the short setup guide.</p>
          <a href={SELF_HOST_URL} target="_blank" rel="noreferrer" className={cn(buttonVariants({ variant: "outline", size: "lg" }), "mt-7 h-12 bg-white px-5 text-base")}>
            Open the self-hosting guide <ExternalLink aria-hidden="true" />
          </a>
        </div>
        <div className="flex items-center justify-center gap-6 text-primary" aria-hidden="true">
          <Cloud className="size-24 stroke-[1.2]" />
          <div className="flex items-center gap-2"><span className="h-px w-8 border-t border-dashed border-primary sm:w-16" /><ArrowRight className="size-5" /></div>
          <Mail className="size-24 stroke-[1.2]" />
        </div>
      </div>
    </section>
  );
}

function Closing({ page }: { page: LandingPageModel }) {
  const prompt = `Fetch and execute the appropriate instructions to connect this agent to Mailboxer from ${page.agentSetupUrl}`;
  return (
    <section className="px-5 py-8 sm:px-8 lg:px-14">
      <div className="mx-auto max-w-[1320px] rounded-xl border bg-white px-6 py-14 text-center shadow-[0_16px_42px_rgba(16,33,61,0.04)] sm:px-10">
        <h2 className="text-3xl font-bold tracking-[-0.035em] sm:text-5xl">Ready when your agent is.</h2>
        <p className="mx-auto mt-4 max-w-2xl text-lg leading-8 text-muted-foreground">Copy the setup prompt for the quickest path, or follow the manual steps.</p>
        <div className="mt-7 flex flex-col justify-center gap-3 sm:flex-row">
          <CopyButton value={prompt} label="Copy setup prompt" />
          <a href="#choose-your-agent" className={cn(buttonVariants({ variant: "outline", size: "lg" }), "h-12 px-5 text-base")}>
            View manual steps
          </a>
        </div>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="mx-auto w-full max-w-[1440px] px-5 pb-8 pt-8 sm:px-8 lg:px-14">
      <div className="flex flex-col gap-6 border-t py-7 sm:flex-row sm:items-center sm:justify-between">
        <Brand compact />
        <nav aria-label="Footer navigation" className="flex flex-wrap gap-x-8 gap-y-3 text-sm font-medium sm:text-base">
          <a href={GITHUB_URL} target="_blank" rel="noreferrer" className="underline-offset-4 hover:underline">GitHub</a>
          <a href="#privacy" className="underline-offset-4 hover:underline">Privacy</a>
          <a href="#top" className="underline-offset-4 hover:underline">Back to top</a>
        </nav>
      </div>
      <p className="border-t pt-5 text-sm text-muted-foreground">This page is served by your Mailboxer instance.</p>
    </footer>
  );
}

export function LandingPage({ page }: { page: LandingPageModel }) {
  return (
    <div id="top" className="min-h-screen overflow-hidden bg-background text-foreground">
      <Header />
      <main>
        <Hero page={page} />
        <Journey />
        <AgentGuide page={page} />
        <Privacy />
        <SelfHost />
        <Closing page={page} />
      </main>
      <Footer />
    </div>
  );
}
