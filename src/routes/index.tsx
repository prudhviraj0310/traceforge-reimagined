import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { ArrowRight, Check, ChevronDown, Minus, Play, Plus, RotateCcw, ShieldCheck, X } from "lucide-react";
import { GraphView } from "@/components/tf/GraphView";
import { NODES, blastRadius, buildInvestigation, nodeById, type FeedEvent } from "@/lib/traceforge-data";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "TRACEFORGE — Graph-native incident response" },
      { name: "description", content: "Trace a security alert across workloads, identities, roles and keys to the data it can reach — and the smallest safe fix." },
      { property: "og:title", content: "TRACEFORGE — Graph-native incident response" },
      { property: "og:description", content: "An incident response agent that shows its work, from alert to crown jewel." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

const ALERTS = NODES.filter((n) => n.type === "Alert");
const SEV: Record<string, string> = {
  CRITICAL: "bg-accent text-accent-foreground",
  HIGH: "bg-foreground text-primary-foreground",
  MEDIUM: "bg-secondary text-secondary-foreground",
};
const fmt = (n: number) => n.toLocaleString("en-US");

function Index() {
  const [alertId, setAlertId] = useState(ALERTS[0]!.id);
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [revealed, setRevealed] = useState(0);
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(false);
  const [severed, setSevered] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [modal, setModal] = useState<"remediate" | "guide" | null>(null);
  const [view, setView] = useState<"graph" | "matrix">("graph");
  const timers = useRef<number[]>([]);

  const inv = buildInvestigation(alertId);
  const wl = inv.path[0];
  const br = blastRadius(wl!);

  const reset = () => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
    setEvents([]); setRevealed(0); setRunning(false); setDone(false); setSevered(false);
  };
  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  const run = () => {
    reset();
    setRunning(true);
    inv.events.forEach((ev, i) => {
      timers.current.push(window.setTimeout(() => {
        setEvents((e) => [...e, ev]);
        if (ev.reveal) setRevealed(ev.reveal);
        if (i === inv.events.length - 1) { setRunning(false); setDone(true); }
      }, 700 * (i + 1)));
    });
  };

  const sel = selected ? nodeById(selected) : null;
  const target = nodeById(inv.path[inv.path.length - 1]!)!;
  const chokeNode = nodeById(inv.choke)!;

  return (
    <div className="min-h-screen bg-background">
      <header className="mx-auto flex max-w-[1440px] items-center justify-between px-6 py-5 lg:px-10">
        <div className="flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-full bg-foreground text-primary-foreground">
            <span className="font-serif text-lg">T</span>
          </div>
          <div>
            <div className="font-serif text-xl leading-none tracking-tight">Traceforge</div>
            <div className="mt-1 text-xs text-muted-foreground">Mission control</div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="hidden items-center gap-1.5 rounded-full bg-secondary px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.18em] sm:inline-flex">
            <span className="h-1.5 w-1.5 rounded-full bg-accent" /> Simulation mode
          </span>
          <button onClick={() => setModal("guide")} className="rounded-full border border-foreground px-5 py-2 text-sm font-medium transition hover:bg-foreground hover:text-primary-foreground">
            How it works
          </button>
        </div>
      </header>

      <main className="mx-auto max-w-[1440px] px-6 pb-16 lg:px-10">
        <section className="mb-8 mt-4 flex flex-wrap items-end justify-between gap-6">
          <div className="max-w-2xl">
            <h1 className="font-serif text-4xl leading-[1.1] tracking-tight md:text-5xl">
              Follow the alert to <em className="text-accent">what it can reach.</em>
            </h1>
            <p className="mt-3 text-muted-foreground">Workload → identity → role → policy → key → datastore. Every hop is evidence.</p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={reset} aria-label="Reset" className="grid h-12 w-12 place-items-center rounded-full bg-secondary transition hover:bg-border">
              <RotateCcw className="h-4 w-4" />
            </button>
            <button onClick={run} disabled={running} className="inline-flex items-center gap-2 rounded-full bg-foreground px-7 py-3.5 text-sm font-medium text-primary-foreground transition hover:opacity-90 disabled:opacity-60">
              {running ? <Spinner /> : <Play className="h-4 w-4 fill-current" />}
              {running ? "Investigating…" : "Run investigation"}
            </button>
          </div>
        </section>

        <div className="grid items-start gap-5 xl:grid-cols-[300px_1fr_360px]">
          {/* Alerts */}
          <Card label="Alerts">
            <div className="space-y-2.5">
              {ALERTS.map((a) => {
                const on = a.id === alertId;
                return (
                  <button key={a.id} onClick={() => { setAlertId(a.id); reset(); setSelected(null); }}
                    className={cn("w-full rounded-2xl p-4 text-left transition", on ? "border border-foreground bg-card" : "bg-muted hover:bg-secondary")}>
                    <div className="flex items-center justify-between">
                      <span className={cn("rounded-full px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-[0.16em]", SEV[String(a.props["severity"])])}>{String(a.props["severity"])}</span>
                      {on && <ArrowRight className="h-4 w-4" />}
                    </div>
                    <div className="mt-2.5 font-serif text-[17px] leading-snug">{a.name}</div>
                    <div className="mt-1 text-xs text-muted-foreground">{a.id} · {String(a.props["detector"])}</div>
                  </button>
                );
              })}
            </div>
            <div className="mt-5 rounded-2xl bg-muted p-4 text-[13px] leading-relaxed">
              <div className="flex gap-2.5">
                <span className="mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded-full bg-foreground text-primary-foreground"><Check className="h-2.5 w-2.5" /></span>
                <p><b className="font-semibold">Seeded scenario.</b> <span className="text-muted-foreground">The figures are demo data modeling a fintech cloud, not a real environment.</span></p>
              </div>
            </div>
          </Card>

          {/* Graph */}
          <Card
            label="Attack graph"
            right={
              <div className="flex rounded-full border border-foreground p-1">
                {(["graph", "matrix"] as const).map((v) => (
                  <button key={v} onClick={() => setView(v)} className={cn("rounded-full px-4 py-1.5 text-xs font-medium capitalize transition", view === v ? "bg-foreground text-primary-foreground" : "")}>
                    {v === "graph" ? "Graph" : "Blast radius"}
                  </button>
                ))}
              </div>
            }
          >
            {view === "graph" ? (
              <div className="relative">
                <div className="aspect-[900/520] w-full overflow-hidden rounded-2xl bg-muted">
                  <GraphView path={inv.path} revealed={revealed} choke={inv.choke} severed={severed} selected={selected} onSelect={setSelected} />
                </div>
                {sel && (
                  <div className="rise-in absolute right-3 top-3 w-64 rounded-2xl bg-card p-4 shadow-soft">
                    <div className="flex items-start justify-between">
                      <span className="rounded-full bg-secondary px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-[0.16em]">{sel.type}</span>
                      <button onClick={() => setSelected(null)} aria-label="Close"><X className="h-4 w-4" /></button>
                    </div>
                    <div className="mt-2 font-serif text-lg leading-tight">{sel.name}</div>
                    <dl className="mt-3 space-y-1.5 text-xs">
                      {Object.entries(sel.props).map(([k, v]) => (
                        <div key={k} className="flex justify-between gap-3">
                          <dt className="text-muted-foreground">{k.replace(/_/g, " ")}</dt>
                          <dd className="text-right font-medium">{typeof v === "number" ? fmt(v) : String(v)}</dd>
                        </div>
                      ))}
                    </dl>
                  </div>
                )}
              </div>
            ) : (
              <Matrix path={inv.path} choke={inv.choke} />
            )}

            <div className="mt-5 grid grid-cols-2 gap-3 md:grid-cols-4">
              <Stat k="Hops" v={done ? String(inv.path.length - 1) : "—"} />
              <Stat k="Reachable nodes" v={done ? String(br.reachable) : "—"} />
              <Stat k="Crown jewels" v={done ? String(br.crownJewels) : "—"} />
              <Stat k="Records at risk" v={done ? fmt(br.sensitiveRecords) : "—"} accent />
            </div>
          </Card>

          {/* Feed */}
          <Card label="Reasoning feed" right={<span className="text-xs text-muted-foreground">{events.length}/{inv.events.length}</span>}>
            {events.length === 0 && !running ? (
              <div className="flex h-[380px] flex-col items-center justify-center rounded-2xl bg-muted text-center">
                <div className="h-10 w-10 rounded-full border-2 border-secondary" />
                <p className="mt-4 max-w-[220px] text-sm text-muted-foreground">Run the investigation to watch each tool call and decision appear.</p>
              </div>
            ) : (
              <ol className="relative space-y-3 before:absolute before:bottom-3 before:left-[11px] before:top-3 before:w-px before:bg-border">
                {events.map((e, i) => (
                  <li key={i} className="rise-in relative pl-9">
                    <span className={cn("absolute left-0 top-1 grid h-6 w-6 place-items-center rounded-full text-[10px] font-bold",
                      e.step === "DECISION" ? "bg-accent text-accent-foreground" : e.step === "ACTION" ? "bg-foreground text-primary-foreground" : "bg-secondary")}>{i + 1}</span>
                    <div className="text-[9px] font-bold uppercase tracking-[0.18em] text-muted-foreground">{e.step === "TOOL" ? "MCP tool" : e.step}</div>
                    <div className={cn("mt-0.5 text-sm font-semibold", e.tool && "font-mono text-[12px]")}>{e.title}</div>
                    <p className="mt-0.5 text-[13px] leading-relaxed text-muted-foreground">{e.description}</p>
                  </li>
                ))}
                {running && <li className="flex items-center gap-2 pl-9 text-xs text-muted-foreground"><Spinner /> Thinking…</li>}
              </ol>
            )}
            {done && (
              <div className="rise-in mt-5 rounded-2xl border border-foreground p-4">
                <div className="flex items-center gap-3">
                  <div className="grid h-10 w-10 shrink-0 place-items-center rounded-full bg-secondary"><ShieldCheck className="h-5 w-5" /></div>
                  <div className="min-w-0 flex-1">
                    <div className="font-serif text-[16px] leading-tight">{severed ? "Containment proposed" : "Choke point found"}</div>
                    <div className="mt-1 inline-block rounded-full bg-secondary px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.16em]">{chokeNode.name}</div>
                  </div>
                  <button onClick={() => setModal("remediate")} aria-label="Review remediation" className="grid h-9 w-9 place-items-center rounded-full bg-secondary transition hover:bg-foreground hover:text-primary-foreground">
                    <ArrowRight className="h-4 w-4" />
                  </button>
                </div>
              </div>
            )}
          </Card>
        </div>
      </main>

      {modal && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-foreground/30 p-4 backdrop-blur-sm" onClick={() => setModal(null)}>
          <div className="rise-in max-h-[90vh] w-full max-w-lg overflow-auto rounded-3xl bg-card p-8 shadow-soft" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between">
              <h2 className="font-serif text-3xl tracking-tight">{modal === "guide" ? "How it works" : "Remediation"}</h2>
              <button onClick={() => setModal(null)} aria-label="Close" className="grid h-8 w-8 place-items-center rounded-full bg-secondary"><X className="h-4 w-4" /></button>
            </div>
            {modal === "guide" ? <Guide /> : (
              <div className="mt-5 space-y-3">
                <p className="text-sm text-muted-foreground">Severing <b className="text-foreground">{chokeNode.name}</b> disconnects <b className="text-foreground">{target.name}</b> ({fmt(Number(target.props["records"]))} records) from the compromised workload.</p>
                {["Isolate the workload's network egress", `Detach ${chokeNode.name} from its role`, "Rotate the reachable KMS key", "Replace wildcard grants with scoped actions"].map((s) => (
                  <div key={s} className="flex items-center gap-3 rounded-full bg-muted px-4 py-2.5 text-sm">
                    <span className="grid h-4 w-4 place-items-center rounded-full bg-foreground text-primary-foreground"><Check className="h-2.5 w-2.5" /></span>{s}
                  </div>
                ))}
                <div className="rounded-2xl bg-secondary p-4 text-[13px]"><b>Simulation only.</b> Nothing changes in a real cloud account — steps are recorded as proposals.</div>
                <div className="flex gap-2 pt-2">
                  <button onClick={() => { setSevered(true); setModal(null); }} className="flex-1 rounded-full bg-foreground py-3 text-sm font-medium text-primary-foreground">Record proposal</button>
                  <button onClick={() => setModal(null)} className="flex-1 rounded-full bg-secondary py-3 text-sm font-medium">Cancel</button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function Card({ label, right, children }: { label: string; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="rounded-[1.75rem] bg-card p-6 shadow-soft">
      <div className="mb-5 flex min-h-8 items-center justify-between">
        <h2 className="text-sm text-muted-foreground">{label}</h2>
        {right}
      </div>
      {children}
    </section>
  );
}

function Stat({ k, v, accent }: { k: string; v: string; accent?: boolean }) {
  return (
    <div className="rounded-2xl bg-muted px-4 py-3.5">
      <div className="text-[11px] text-muted-foreground">{k}</div>
      <div className={cn("mt-1 font-serif text-2xl tracking-tight", accent && v !== "—" && "text-accent")}>{v}</div>
    </div>
  );
}

function Spinner() {
  return <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-r-transparent" />;
}

function Matrix({ path, choke }: { path: string[]; choke: string }) {
  const rows = path.map((id, i) => ({ n: nodeById(id)!, i, centrality: i === 0 || i === path.length - 1 ? 0 : +(((i * (path.length - 1 - i)) / ((path.length - 1) ** 2 / 4))).toFixed(2) }));
  return (
    <div className="overflow-hidden rounded-2xl border border-border">
      <table className="w-full text-sm">
        <thead className="bg-muted text-left text-[11px] uppercase tracking-[0.14em] text-muted-foreground">
          <tr><th className="px-4 py-3 font-medium">Hop</th><th className="px-4 py-3 font-medium">Node</th><th className="px-4 py-3 font-medium">Type</th><th className="px-4 py-3 text-right font-medium">Centrality</th></tr>
        </thead>
        <tbody>
          {rows.map(({ n, i, centrality }) => (
            <tr key={n.id} className="border-t border-border">
              <td className="px-4 py-3 text-muted-foreground">{i}</td>
              <td className="px-4 py-3 font-medium">
                {n.name}
                {n.id === choke && <span className="ml-2 rounded-full bg-accent px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.14em] text-accent-foreground">Choke</span>}
                {n.props["crown_jewel"] && <span className="ml-2 rounded-full bg-gold px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.14em]">Gold</span>}
              </td>
              <td className="px-4 py-3 text-muted-foreground">{n.type}</td>
              <td className="px-4 py-3 text-right">
                <div className="ml-auto flex w-28 items-center gap-2">
                  <div className="h-1 flex-1 rounded-full bg-secondary"><div className="h-1 rounded-full bg-foreground" style={{ width: `${centrality * 100}%` }} /></div>
                  <span className="w-8 text-xs tabular-nums">{centrality}</span>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const FAQ = [
  ["What does Traceforge do?", "It investigates a security alert by following relationships flat logs miss — from a workload through identities, roles and policies to the data it can decrypt."],
  ["How is the choke point picked?", "Graph centrality across the attack path: the node whose removal cuts the path with the least collateral to running services."],
  ["Does it change my cloud?", "No. Actions run in simulation mode and are recorded as proposals. Live integrations fail closed."],
  ["Is this real data?", "This demo runs a seeded fintech scenario. The 4.5M records figure is scenario data."],
];
function Guide() {
  const [open, setOpen] = useState(0);
  return (
    <div className="mt-5 space-y-2.5">
      {FAQ.map(([q, a], i) => (
        <div key={q} className="rounded-2xl bg-muted px-5 py-4">
          <button onClick={() => setOpen(open === i ? -1 : i)} className="flex w-full items-center justify-between text-left font-serif text-[17px]">
            {q}
            <span className="grid h-6 w-6 place-items-center rounded-full bg-secondary">{open === i ? <Minus className="h-3.5 w-3.5" /> : <Plus className="h-3.5 w-3.5" />}</span>
          </button>
          {open === i && <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{a}</p>}
        </div>
      ))}
      <ChevronDown className="hidden" />
    </div>
  );
}
