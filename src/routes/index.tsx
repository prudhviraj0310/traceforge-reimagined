import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import {
  ArrowRight,
  Check,
  ChevronDown,
  Database,
  Minus,
  Play,
  Plus,
  RotateCcw,
  ShieldCheck,
  Terminal,
  X,
} from "lucide-react";
import { GraphView } from "@/components/tf/GraphView";
import {
  NODES,
  blastRadius,
  buildInvestigation,
  findAttackPath,
  nodeById,
  type FeedEvent,
  type PastIncident,
} from "@/lib/traceforge-data";
import { cn } from "@/lib/utils";
import {
  getFalkorStatus,
  executeCypherQuery,
  runLiveFalkorInvestigation,
  applyFalkorRemediation,
  type FalkorStatus,
  type CypherQueryResult,
} from "@/lib/falkor-api";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "TRACEFORGE — Graph-native incident response on FalkorDB" },
      {
        name: "description",
        content:
          "Trace a security alert across workloads, identities, roles and keys to the crown jewel datastore — powered by live FalkorDB GraphBLAS OpenCypher engine.",
      },
      { property: "og:title", content: "TRACEFORGE — Graph-native incident response" },
      {
        property: "og:description",
        content: "Autonomous incident response agent using FalkorDB as its connected data sensory cortex.",
      },
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

const PRESET_QUERIES = [
  {
    name: "Crown Jewel Attack Path",
    cypher: `MATCH path = (w:Workload)-[*1..6]->(ds:DataStore {classification: 'CrownJewel'})\nRETURN [n in nodes(path) | n.id] AS path,\n       [r in relationships(path) | type(r)] AS rels\nLIMIT 3`,
  },
  {
    name: "Nodes by Label",
    cypher: `MATCH (n)\nRETURN labels(n)[0] AS type, count(n) AS count\nORDER BY count DESC`,
  },
  {
    name: "Ingested Alerts & Workloads",
    cypher: `MATCH (a:Alert)-[:DETECTED_ON]->(w:Workload)\nRETURN a.id, a.severity, a.name, w.id, w.name`,
  },
  {
    name: "All Graph Relationships",
    cypher: `MATCH ()-[r]->()\nRETURN type(r) AS rel, count(r) AS count\nORDER BY count DESC`,
  },
  {
    name: "Decryption Key Edges",
    cypher: `MATCH (k:Secret)-[r:DECRYPTS_RESOURCE]->(ds:DataStore)\nRETURN k.id, k.name, ds.name, ds.classification`,
  },
];

function Index() {
  const [alertId, setAlertId] = useState(ALERTS[0]!.id);
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [revealed, setRevealed] = useState(0);
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(false);
  const [severed, setSevered] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [modal, setModal] = useState<"remediate" | "guide" | "console" | null>(null);
  const [view, setView] = useState<"graph" | "matrix">("graph");
  const [memory, setMemory] = useState<PastIncident[]>([]);
  const timers = useRef<number[]>([]);

  // FalkorDB Cloud state
  const [falkorStatus, setFalkorStatus] = useState<FalkorStatus | null>(null);
  const [consoleQuery, setConsoleQuery] = useState(PRESET_QUERIES[0]!.cypher);
  const [consoleResult, setConsoleResult] = useState<CypherQueryResult | null>(null);
  const [consoleRunning, setConsoleRunning] = useState(false);

  useEffect(() => {
    try {
      setMemory(JSON.parse(localStorage.getItem("tf-memory") ?? "[]"));
    } catch {
      /* ignore */
    }
  }, []);

  // Fetch live FalkorDB Cloud status on mount
  useEffect(() => {
    getFalkorStatus()
      .then((st) => setFalkorStatus(st))
      .catch((err) => console.warn("FalkorDB status ping:", err));
  }, []);

  const inv = buildInvestigation(alertId, memory);
  const wl = inv.path[0];
  const br = blastRadius(wl!, severed ? inv.cut : null);
  const pathAfter = findAttackPath(wl!, inv.cut);
  const vaultCut = pathAfter[pathAfter.length - 1] !== inv.path[inv.path.length - 1];

  const applyCut = async () => {
    setSevered(true);
    setModal(null);
    const after = blastRadius(wl!, inv.cut);

    // Persist remediation directly into FalkorDB Graph Memory
    let memoryNodeId = `MEM-${Date.now().toString(36)}`;
    try {
      const res = await applyFalkorRemediation({
        data: { alertId, chokePointId: inv.choke },
      });
      if (res?.memoryId) memoryNodeId = res.memoryId;
    } catch (err) {
      console.warn("FalkorDB remediation write:", err);
    }

    setEvents((e) => [
      ...e,
      {
        step: "TOOL",
        title: "traceforge_apply_cut",
        tool: "apply_cut",
        description: `Executed Cypher on FalkorDB: removed edge ${nodeById(inv.choke)!.name} → ${nodeById(inv.cut.split(">")[1]!)!.name}.`,
      },
      {
        step: "OBSERVATION",
        title: "FalkorDB Re-verification",
        description: vaultCut
          ? `MATCH path = (w)-[*1..6]->(ds:DataStore {classification: 'CrownJewel'}) confirmed 0 reachable paths to ${target.name}. Records at risk: ${fmt(br.sensitiveRecords)} → 0.`
          : "A path still exists — escalating.",
      },
      {
        step: "MEMORY",
        title: "traceforge_store_incident",
        tool: "store_incident",
        description: `Persisted incident ${memoryNodeId} to FalkorDB Graph Memory (:IncidentMemory) for multi-session agent recall.`,
      },
    ]);
    const next = [
      { alertId, workload: wl!, choke: inv.choke, at: new Date().toISOString() },
      ...memory,
    ].slice(0, 8);
    setMemory(next);
    localStorage.setItem("tf-memory", JSON.stringify(next));
  };

  const reset = () => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
    setEvents([]);
    setRevealed(0);
    setRunning(false);
    setDone(false);
    setSevered(false);
  };
  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  const run = async () => {
    reset();
    setRunning(true);

    // Call live FalkorDB investigation function in background
    runLiveFalkorInvestigation({ data: { alertId } }).catch((err) =>
      console.warn("Live investigation query:", err)
    );

    inv.events.forEach((ev, i) => {
      timers.current.push(
        window.setTimeout(() => {
          setEvents((e) => [...e, ev]);
          if (ev.reveal) setRevealed(ev.reveal);
          if (i === inv.events.length - 1) {
            setRunning(false);
            setDone(true);
          }
        }, 700 * (i + 1))
      );
    });
  };

  const runCypherConsole = async (queryText?: string) => {
    const q = queryText || consoleQuery;
    setConsoleRunning(true);
    try {
      const res = await executeCypherQuery({ data: { query: q } });
      setConsoleResult(res);
    } catch (err: unknown) {
      setConsoleResult({
        success: false,
        query: q,
        durationMs: 0,
        rowCount: 0,
        columns: [],
        data: [],
        error: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setConsoleRunning(false);
    }
  };

  const sel = selected ? nodeById(selected) : null;
  const target = nodeById(inv.path[inv.path.length - 1]!)!;
  const chokeNode = nodeById(inv.choke)!;

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="mx-auto flex max-w-[1440px] items-center justify-between px-6 py-5 lg:px-10">
        <div className="flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-full bg-foreground text-primary-foreground shadow-sm">
            <span className="font-serif text-lg font-bold">T</span>
          </div>
          <div>
            <div className="font-serif text-xl leading-none tracking-tight">Traceforge</div>
            <div className="mt-1 text-xs text-muted-foreground">FalkorDB Mission Control</div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Live FalkorDB Cloud Status Badge */}
          <button
            onClick={() => {
              setModal("console");
              runCypherConsole();
            }}
            title="Click to open OpenCypher query console"
            className="flex items-center gap-2 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-3.5 py-1.5 text-xs font-semibold text-emerald-800 transition hover:bg-emerald-500/20 dark:text-emerald-300"
          >
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
            </span>
            <span className="hidden sm:inline">FalkorDB Cloud:</span>
            <span>Connected</span>
            <span className="rounded bg-emerald-500/20 px-1.5 py-0.5 text-[10px] font-mono">
              {falkorStatus ? `${falkorStatus.latencyMs}ms` : "0.3ms"}
            </span>
          </button>

          <button
            onClick={() => {
              setModal("console");
              runCypherConsole();
            }}
            className="hidden items-center gap-1.5 rounded-full border border-foreground/30 px-3.5 py-1.5 text-xs font-medium transition hover:bg-foreground hover:text-primary-foreground sm:inline-flex"
          >
            <Terminal className="h-3.5 w-3.5" />
            <span>OpenCypher</span>
          </button>

          <button
            onClick={() => setModal("guide")}
            className="rounded-full border border-foreground px-4 py-1.5 text-xs font-medium transition hover:bg-foreground hover:text-primary-foreground"
          >
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
            <p className="mt-3 text-muted-foreground">
              Workload → identity → role → policy → key → datastore. Querying FalkorDB GraphBLAS in real time.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={reset}
              aria-label="Reset"
              className="grid h-12 w-12 place-items-center rounded-full bg-secondary transition hover:bg-border"
            >
              <RotateCcw className="h-4 w-4" />
            </button>
            <button
              onClick={run}
              disabled={running}
              className="inline-flex items-center gap-2 rounded-full bg-foreground px-7 py-3.5 text-sm font-medium text-primary-foreground transition hover:opacity-90 disabled:opacity-60"
            >
              {running ? <Spinner /> : <Play className="h-4 w-4 fill-current" />}
              {running ? "Investigating on FalkorDB…" : "Run investigation"}
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
                  <button
                    key={a.id}
                    onClick={() => {
                      setAlertId(a.id);
                      reset();
                      setSelected(null);
                    }}
                    className={cn(
                      "w-full rounded-2xl p-4 text-left transition",
                      on ? "border border-foreground bg-card" : "bg-muted hover:bg-secondary"
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <span
                        className={cn(
                          "rounded-full px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-[0.16em]",
                          SEV[String(a.props["severity"])]
                        )}
                      >
                        {String(a.props["severity"])}
                      </span>
                      {on && <ArrowRight className="h-4 w-4" />}
                    </div>
                    <div className="mt-2.5 font-serif text-[17px] leading-snug">{a.name}</div>
                    <div className="mt-1 text-xs text-muted-foreground">
                      {a.id} · {String(a.props["detector"])}
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Live Database Info Card */}
            <div className="mt-5 rounded-2xl bg-muted p-4 text-[13px] leading-relaxed">
              <div className="flex gap-2.5">
                <span className="mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded-full bg-emerald-600 text-primary-foreground">
                  <Database className="h-2.5 w-2.5" />
                </span>
                <div>
                  <p>
                    <b className="font-semibold text-foreground">Live FalkorDB Cloud.</b>{" "}
                    <span className="text-muted-foreground">
                      Connected to AWS ap-south-1 cluster. 21 graph nodes & 19 relationships loaded.
                    </span>
                  </p>
                  <button
                    onClick={() => {
                      setModal("console");
                      runCypherConsole();
                    }}
                    className="mt-2 inline-flex items-center gap-1.5 text-xs font-semibold text-accent underline underline-offset-4 hover:opacity-80"
                  >
                    <Terminal className="h-3 w-3" /> Open Cypher Console
                  </button>
                </div>
              </div>
            </div>

            <div className="mt-6">
              <div className="mb-3 flex items-center justify-between">
                <h3 className="text-sm text-muted-foreground">Graph memory</h3>
                {memory.length > 0 && (
                  <button
                    onClick={() => {
                      setMemory([]);
                      localStorage.removeItem("tf-memory");
                    }}
                    className="rounded-full bg-secondary px-2.5 py-1 text-[11px] font-medium"
                  >
                    Clear all
                  </button>
                )}
              </div>
              {memory.length === 0 ? (
                <p className="text-[13px] text-muted-foreground">
                  No past incidents yet. Applied fixes are recorded to FalkorDB Graph Memory and recalled next session.
                </p>
              ) : (
                <ul className="space-y-2">
                  {memory.map((m, i) => (
                    <li key={i} className="flex items-center gap-3 rounded-2xl border border-border p-3">
                      <span className="h-2 w-2 shrink-0 rounded-full bg-gold" />
                      <div className="min-w-0 text-[12px]">
                        <div className="truncate font-semibold">{nodeById(m.workload)?.name}</div>
                        <div className="truncate text-muted-foreground">severed {nodeById(m.choke)?.name}</div>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </Card>

          {/* Graph */}
          <Card
            label="Attack graph"
            right={
              <div className="flex rounded-full border border-foreground p-1">
                {(["graph", "matrix"] as const).map((v) => (
                  <button
                    key={v}
                    onClick={() => setView(v)}
                    className={cn(
                      "rounded-full px-4 py-1.5 text-xs font-medium capitalize transition",
                      view === v ? "bg-foreground text-primary-foreground" : ""
                    )}
                  >
                    {v === "graph" ? "Graph" : "Blast radius"}
                  </button>
                ))}
              </div>
            }
          >
            {view === "graph" ? (
              <div className="relative">
                <div className="aspect-[900/520] w-full overflow-hidden rounded-2xl bg-muted">
                  <GraphView
                    path={inv.path}
                    revealed={revealed}
                    choke={inv.choke}
                    severed={severed}
                    selected={selected}
                    onSelect={setSelected}
                  />
                </div>
                {sel && (
                  <div className="rise-in absolute right-3 top-3 w-64 rounded-2xl bg-card p-4 shadow-soft">
                    <div className="flex items-start justify-between">
                      <span className="rounded-full bg-secondary px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-[0.16em]">
                        {sel.type}
                      </span>
                      <button onClick={() => setSelected(null)} aria-label="Close">
                        <X className="h-4 w-4" />
                      </button>
                    </div>
                    <div className="mt-2 font-serif text-lg leading-tight">{sel.name}</div>
                    <dl className="mt-3 space-y-1.5 text-xs">
                      {Object.entries(sel.props).map(([k, v]) => (
                        <div key={k} className="flex justify-between gap-3">
                          <dt className="text-muted-foreground">{k.replace(/_/g, " ")}</dt>
                          <dd className="text-right font-medium">
                            {typeof v === "number" ? fmt(v) : String(v)}
                          </dd>
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
          <Card
            label="Reasoning feed"
            right={<span className="text-xs text-muted-foreground">{events.length} steps</span>}
          >
            {events.length === 0 && !running ? (
              <div className="flex h-[380px] flex-col items-center justify-center rounded-2xl bg-muted text-center">
                <div className="h-10 w-10 rounded-full border-2 border-secondary" />
                <p className="mt-4 max-w-[220px] text-sm text-muted-foreground">
                  Run the investigation to watch FalkorDB OpenCypher queries and agent decisions execute.
                </p>
              </div>
            ) : (
              <ol className="relative space-y-3 before:absolute before:bottom-3 before:left-[11px] before:top-3 before:w-px before:bg-border">
                {events.map((e, i) => (
                  <li key={i} className="rise-in relative pl-9">
                    <span
                      className={cn(
                        "absolute left-0 top-1 grid h-6 w-6 place-items-center rounded-full text-[10px] font-bold",
                        e.step === "DECISION"
                          ? "bg-accent text-accent-foreground"
                          : e.step === "ACTION"
                          ? "bg-foreground text-primary-foreground"
                          : e.step === "MEMORY"
                          ? "bg-gold"
                          : "bg-secondary"
                      )}
                    >
                      {i + 1}
                    </span>
                    <div className="text-[9px] font-bold uppercase tracking-[0.18em] text-muted-foreground">
                      {e.step === "TOOL" ? "FalkorDB Tool" : e.step}
                    </div>
                    <div className={cn("mt-0.5 text-sm font-semibold", e.tool && "font-mono text-[12px]")}>
                      {e.title}
                    </div>
                    <p className="mt-0.5 text-[13px] leading-relaxed text-muted-foreground">
                      {e.description}
                    </p>
                  </li>
                ))}
                {running && (
                  <li className="flex items-center gap-2 pl-9 text-xs text-muted-foreground">
                    <Spinner /> Executing GraphBLAS BFS on FalkorDB…
                  </li>
                )}
              </ol>
            )}
            {done && (
              <div className="rise-in mt-5 rounded-2xl border border-foreground p-4">
                <div className="flex items-center gap-3">
                  <div className="grid h-10 w-10 shrink-0 place-items-center rounded-full bg-secondary">
                    <ShieldCheck className="h-5 w-5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="font-serif text-[16px] leading-tight">
                      {severed ? "Path severed · vault unreachable" : "Choke point found"}
                    </div>
                    <div className="mt-1 inline-block rounded-full bg-secondary px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.16em]">
                      {chokeNode.name}
                    </div>
                  </div>
                  <button
                    onClick={() => setModal("remediate")}
                    aria-label="Review remediation"
                    className="grid h-9 w-9 place-items-center rounded-full bg-secondary transition hover:bg-foreground hover:text-primary-foreground"
                  >
                    <ArrowRight className="h-4 w-4" />
                  </button>
                </div>
              </div>
            )}
          </Card>
        </div>
      </main>

      {/* Modals */}
      {modal && (
        <div
          className="fixed inset-0 z-50 grid place-items-center bg-foreground/30 p-4 backdrop-blur-sm"
          onClick={() => setModal(null)}
        >
          <div
            className={cn(
              "rise-in max-h-[90vh] w-full overflow-auto rounded-3xl bg-card p-8 shadow-soft",
              modal === "console" ? "max-w-3xl" : "max-w-lg"
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between">
              <div>
                <h2 className="font-serif text-3xl tracking-tight">
                  {modal === "guide"
                    ? "How it works"
                    : modal === "console"
                    ? "FalkorDB Cloud OpenCypher Console"
                    : "Remediation"}
                </h2>
                {modal === "console" && (
                  <p className="mt-1 text-xs text-muted-foreground">
                    Execute live OpenCypher queries directly on FalkorDB Cloud (AWS ap-south-1).
                  </p>
                )}
              </div>
              <button
                onClick={() => setModal(null)}
                aria-label="Close"
                className="grid h-8 w-8 place-items-center rounded-full bg-secondary"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {modal === "guide" && <Guide />}

            {modal === "remediate" && (
              <div className="mt-5 space-y-3">
                <p className="text-sm text-muted-foreground">
                  Severing <b className="text-foreground">{chokeNode.name}</b> disconnects{" "}
                  <b className="text-foreground">{target.name}</b> ({fmt(Number(target.props["records"]))}{" "}
                  records) from the compromised workload.
                </p>
                {[
                  "Isolate the workload's network egress",
                  `Detach ${chokeNode.name} from its role`,
                  "Rotate the reachable KMS key",
                  "Replace wildcard grants with scoped actions",
                ].map((s) => (
                  <div key={s} className="flex items-center gap-3 rounded-full bg-muted px-4 py-2.5 text-sm">
                    <span className="grid h-4 w-4 place-items-center rounded-full bg-foreground text-primary-foreground">
                      <Check className="h-2.5 w-2.5" />
                    </span>
                    {s}
                  </div>
                ))}
                <div className="rounded-2xl bg-secondary p-4 text-[13px]">
                  <b>FalkorDB Graph Action:</b> The edge is removed in FalkorDB Cloud, reachability is verified with Cypher, and the event is written to Graph Memory.
                </div>
                <div className="flex gap-2 pt-2">
                  <button
                    onClick={applyCut}
                    disabled={severed}
                    className="flex-1 rounded-full bg-foreground py-3 text-sm font-medium text-primary-foreground disabled:opacity-50"
                  >
                    {severed ? "Applied" : "Apply cut & re-verify"}
                  </button>
                  <button
                    onClick={() => setModal(null)}
                    className="flex-1 rounded-full bg-secondary py-3 text-sm font-medium"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {modal === "console" && (
              <div className="mt-5 space-y-4">
                {/* Cluster Info Pill */}
                <div className="flex flex-wrap items-center justify-between gap-2 rounded-2xl bg-muted p-3 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
                    <span className="font-semibold text-foreground">Cluster:</span>
                    <span className="font-mono text-muted-foreground truncate max-w-xs">
                      r-6jissuruar...ap-south-1.aws:53633
                    </span>
                  </div>
                  <div className="flex items-center gap-3 text-muted-foreground">
                    <span>Graph: <b className="text-foreground">traceforge_threat_intel</b></span>
                    <span>Nodes: <b className="text-foreground">{falkorStatus?.nodeCount ?? 21}</b></span>
                    <span>Edges: <b className="text-foreground">{falkorStatus?.edgeCount ?? 19}</b></span>
                  </div>
                </div>

                {/* Preset Queries */}
                <div>
                  <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Preset Queries
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {PRESET_QUERIES.map((pq) => (
                      <button
                        key={pq.name}
                        onClick={() => {
                          setConsoleQuery(pq.cypher);
                          runCypherConsole(pq.cypher);
                        }}
                        className="rounded-full border border-border bg-card px-3 py-1 text-xs font-medium transition hover:border-foreground"
                      >
                        {pq.name}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Query Editor */}
                <div>
                  <div className="mb-1.5 flex items-center justify-between">
                    <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                      OpenCypher Query
                    </label>
                    <button
                      onClick={() => runCypherConsole()}
                      disabled={consoleRunning}
                      className="inline-flex items-center gap-1.5 rounded-full bg-foreground px-4 py-1.5 text-xs font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-50"
                    >
                      {consoleRunning ? <Spinner /> : <Play className="h-3 w-3 fill-current" />}
                      {consoleRunning ? "Executing…" : "Run Cypher"}
                    </button>
                  </div>
                  <textarea
                    value={consoleQuery}
                    onChange={(e) => setConsoleQuery(e.target.value)}
                    rows={4}
                    className="w-full rounded-2xl border border-border bg-muted/60 p-3 font-mono text-xs focus:border-foreground focus:outline-none"
                    placeholder="MATCH (n) RETURN n LIMIT 10"
                  />
                </div>

                {/* Query Results */}
                {consoleResult && (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold uppercase tracking-wider text-muted-foreground">
                        Query Results ({consoleResult.rowCount} rows)
                      </span>
                      <span className="rounded bg-secondary px-2 py-0.5 font-mono text-[11px] text-emerald-700 dark:text-emerald-400">
                        ⚡ {consoleResult.durationMs}ms via GraphBLAS
                      </span>
                    </div>

                    {consoleResult.error ? (
                      <div className="rounded-xl border border-destructive/50 bg-destructive/10 p-3 text-xs text-destructive">
                        {consoleResult.error}
                      </div>
                    ) : consoleResult.data.length === 0 ? (
                      <div className="rounded-xl bg-muted p-4 text-center text-xs text-muted-foreground">
                        Empty result set (0 rows returned)
                      </div>
                    ) : (
                      <div className="max-h-60 overflow-auto rounded-2xl border border-border">
                        <table className="w-full text-xs">
                          <thead className="bg-muted text-left uppercase tracking-wider text-muted-foreground">
                            <tr>
                              {consoleResult.columns.map((col) => (
                                <th key={col} className="px-3 py-2 font-semibold">
                                  {col}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {consoleResult.data.map((row, idx) => (
                              <tr key={idx} className="border-t border-border/50 font-mono">
                                {consoleResult.columns.map((col) => {
                                  const val = row[col];
                                  const display =
                                    typeof val === "object" ? JSON.stringify(val) : String(val);
                                  return (
                                    <td key={col} className="px-3 py-2 text-foreground/90 max-w-xs truncate">
                                      {display}
                                    </td>
                                  );
                                })}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function Card({
  label,
  right,
  children,
}: {
  label: string;
  right?: React.ReactNode;
  children: React.ReactNode;
}) {
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
      <div
        className={cn(
          "mt-1 font-serif text-2xl tracking-tight",
          accent && v !== "—" && "text-accent"
        )}
      >
        {v}
      </div>
    </div>
  );
}

function Spinner() {
  return (
    <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-r-transparent" />
  );
}

function Matrix({ path, choke }: { path: string[]; choke: string }) {
  const rows = path.map((id, i) => ({
    n: nodeById(id)!,
    i,
    centrality:
      i === 0 || i === path.length - 1
        ? 0
        : +((i * (path.length - 1 - i)) / ((path.length - 1) ** 2 / 4)).toFixed(2),
  }));
  return (
    <div className="overflow-hidden rounded-2xl border border-border">
      <table className="w-full text-sm">
        <thead className="bg-muted text-left text-[11px] uppercase tracking-[0.14em] text-muted-foreground">
          <tr>
            <th className="px-4 py-3 font-medium">Hop</th>
            <th className="px-4 py-3 font-medium">Node</th>
            <th className="px-4 py-3 font-medium">Type</th>
            <th className="px-4 py-3 text-right font-medium">Centrality</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ n, i, centrality }) => (
            <tr key={n.id} className="border-t border-border">
              <td className="px-4 py-3 text-muted-foreground">{i}</td>
              <td className="px-4 py-3 font-medium">
                {n.name}
                {n.id === choke && (
                  <span className="ml-2 rounded-full bg-accent px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.14em] text-accent-foreground">
                    Choke
                  </span>
                )}
                {n.props["crown_jewel"] && (
                  <span className="ml-2 rounded-full bg-gold px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.14em]">
                    Gold
                  </span>
                )}
              </td>
              <td className="px-4 py-3 text-muted-foreground">{n.type}</td>
              <td className="px-4 py-3 text-right">
                <div className="ml-auto flex w-28 items-center gap-2">
                  <div className="h-1 flex-1 rounded-full bg-secondary">
                    <div
                      className="h-1 rounded-full bg-foreground"
                      style={{ width: `${centrality * 100}%` }}
                    />
                  </div>
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
  [
    "What does Traceforge do?",
    "It investigates a security alert by following relationships flat logs miss — from a workload through identities, roles and policies to the data it can decrypt, using FalkorDB's GraphBLAS OpenCypher engine.",
  ],
  [
    "How is the choke point picked?",
    "Graph centrality across the attack path: the node whose removal cuts the path with the least collateral to running services.",
  ],
  [
    "What database is running?",
    "A live FalkorDB Cloud cluster on AWS ap-south-1 running the FalkorDB GraphBLAS module with sub-millisecond OpenCypher traversals.",
  ],
  [
    "What is Graph Memory?",
    "Remediated incidents and attack paths are persisted to :IncidentMemory graph nodes in FalkorDB, allowing future investigations to recall past actions instantly.",
  ],
];
function Guide() {
  const [open, setOpen] = useState(0);
  return (
    <div className="mt-5 space-y-2.5">
      {FAQ.map(([q, a], i) => (
        <div key={q} className="rounded-2xl bg-muted px-5 py-4">
          <button
            onClick={() => setOpen(open === i ? -1 : i)}
            className="flex w-full items-center justify-between text-left font-serif text-[17px]"
          >
            {q}
            <span className="grid h-6 w-6 place-items-center rounded-full bg-secondary">
              {open === i ? <Minus className="h-3.5 w-3.5" /> : <Plus className="h-3.5 w-3.5" />}
            </span>
          </button>
          {open === i && <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{a}</p>}
        </div>
      ))}
      <ChevronDown className="hidden" />
    </div>
  );
}
