import React, { useEffect, useState, useRef } from "react";
import {
  Sparkles,
  Play,
  Pause,
  ArrowRight,
  ArrowLeft,
  RotateCcw,
  X,
  Terminal,
  ShieldAlert,
  Scissors,
  Database,
  Zap,
  CheckCircle2,
  ExternalLink,
  BookOpen,
} from "lucide-react";
import { cn } from "@/lib/utils";

export interface WalkthroughStep {
  id: string;
  phase: string;
  title: string;
  badge: string;
  targetElementId: string;
  narration: string;
  technicalDetails: string;
  cypherSnippet?: string;
  actionLabel?: string;
  actionType?: "select_alert" | "run_investigation" | "focus_target" | "sever_choke" | "open_console";
}

export const WALKTHROUGH_STEPS: WalkthroughStep[] = [
  {
    id: "step-1",
    phase: "1 / 6 · INGESTION",
    badge: "The Ingress Alert",
    title: "An Ingress Alert Hides a Deep Graph Mesh",
    targetElementId: "tf-tour-alerts",
    narration:
      "A container runtime exploit alert (ALERT-2026-9812) triggers on payment-ingress-api. In traditional SIEMs, this looks like an isolated pod error. In TRACEFORGE, it is the entry point of a complex cloud permission graph.",
    technicalDetails:
      "FalkorDB stores the live environment topology as 21 nodes and 19 relationships in AWS ap-south-1. Workloads are connected to IAM ServiceAccounts, assume roles, evaluate policies, and bind to encryption keys.",
    cypherSnippet: "MATCH (a:Alert {id: 'ALERT-2026-9812'})-[:DETECTED_ON]->(w:Workload) RETURN a, w",
    actionLabel: "Next: Run Agent Traversal →",
  },
  {
    id: "step-2",
    phase: "2 / 6 · GRAPHBLAS TRAVERSAL",
    badge: "Sub-Millisecond BFS",
    title: "Agent OpenCypher Multi-Hop Traversal",
    targetElementId: "tf-tour-reasoning",
    narration:
      "The autonomous agent queries FalkorDB using GraphBLAS matrix multiplication. Instead of slow recursive SQL joins or probabilistic vector search, FalkorDB executes a deterministic 6-hop reachability BFS in under 1 millisecond.",
    technicalDetails:
      "Linear algebra sparse adjacency matrix multiplications compute transitive closure at hardware speed. The agent traverses: Workload → ServiceAccount → IAM Role → Policy → Master KMS Key → Customer Vault.",
    cypherSnippet:
      "MATCH path = (w:Workload {id: 'wl-payment-ingress'})-[*1..6]->(ds:DataStore) RETURN path ORDER BY ds.classification = 'CrownJewel' DESC LIMIT 1",
    actionLabel: "▶ Run Live Investigation",
    actionType: "run_investigation",
  },
  {
    id: "step-3",
    phase: "3 / 6 · BLAST RADIUS",
    badge: "Crown Jewel Reach",
    title: "4,500,000 Sensitive Records at Risk",
    targetElementId: "tf-tour-metrics",
    narration:
      "The agent's GraphBLAS traversal reveals the blast radius: 5 hops away sits fintech-pci-cardholder-vault, containing 4.5M credit card records classified as a Crown Jewel. An attacker compromising this container has direct decrypt reach.",
    technicalDetails:
      "Vector databases fail at transitive graph connectivity. Relational databases require 6 nested self-joins with index thrashing. FalkorDB computes full multi-hop blast radius metrics in 0.3ms.",
    cypherSnippet:
      "MATCH (w:Workload)-[*1..6]->(ds:DataStore {classification: 'CrownJewel'}) RETURN ds.name, ds.records_count",
    actionLabel: "Next: Identify Choke Point →",
  },
  {
    id: "step-4",
    phase: "4 / 6 · CENTRALITY & CHOKE POINT",
    badge: "Surgical Defense",
    title: "Graph Centrality Finds the Optimal Choke Point",
    targetElementId: "tf-tour-chokepoint",
    narration:
      "Naive incident response pulls the plug on the container, breaking checkout payments for real customers. TRACEFORGE applies graph cut vertex analysis to find the single optimal choke point: Policy-LegacyPayments-Overprivileged.",
    technicalDetails:
      "Severing the GRANTS_DECRYPT edge between this legacy policy and the KMS key eliminates 100% of attack reachability to the crown jewel while keeping payment-ingress-api running for benign traffic.",
    cypherSnippet:
      "MATCH (p:Policy {id: 'pol-legacy-payments'})-[r:GRANTS_DECRYPT]->(k:KMSKey) RETURN p, r, k",
    actionLabel: "✂ Sever Choke Point & Verify",
    actionType: "sever_choke",
  },
  {
    id: "step-5",
    phase: "5 / 6 · GRAPH RE-VERIFICATION & MEMORY",
    badge: "Lifelong Agent Memory",
    title: "Verified Zero Reachability + Graph Memory",
    targetElementId: "tf-tour-memory",
    narration:
      "The agent deletes the malicious permission edge in FalkorDB Cloud. It instantly runs a verification Cypher query confirming 0 reachable paths remain (4.5M records at risk → 0), and writes an :IncidentMemory node into the graph.",
    technicalDetails:
      "Graph Memory allows future agent sessions to recall past incident patterns, remediation effectiveness, and workload histories across restarts without context window exhaustion.",
    cypherSnippet:
      "CREATE (m:IncidentMemory {id: 'INCIDENT-9812', alert: 'ALERT-2026-9812', choke_point: 'pol-legacy-payments', status: 'remediated'})",
    actionLabel: "Explore Raw Cypher Console →",
    actionType: "open_console",
  },
  {
    id: "step-6",
    phase: "6 / 6 · CLUSTER VALIDATION",
    badge: "Live FalkorDB Cloud",
    title: "Direct OpenCypher on AWS ap-south-1",
    targetElementId: "tf-tour-header",
    narration:
      "The entire workflow runs against a live FalkorDB Cloud cluster in AWS ap-south-1 (Mumbai). Presenters and judges can run raw OpenCypher queries directly in the console to inspect nodes, edges, and verify sub-millisecond GraphBLAS performance.",
    technicalDetails:
      "Direct Redis protocol client dispatches GRAPH.QUERY commands directly to FalkorDB Cloud. Real-time stats confirm 0.1ms – 0.4ms query latencies.",
    cypherSnippet:
      "MATCH (w:Workload)-[r]->(target) RETURN w.name, type(r), target.name LIMIT 5",
    actionLabel: "⚡ Open Cypher Console",
    actionType: "open_console",
  },
];

interface DemoWalkthroughProps {
  active: boolean;
  onClose: () => void;
  currentStep: number;
  onStepChange: (step: number) => void;
  onRunInvestigation: () => void;
  onApplyCut: () => void;
  onOpenConsole: () => void;
  onOpenStoryboard: () => void;
  isInvestigating: boolean;
  isDone: boolean;
  isSevered: boolean;
  falkorLatency: string | number;
}

export function DemoWalkthrough({
  active,
  onClose,
  currentStep,
  onStepChange,
  onRunInvestigation,
  onApplyCut,
  onOpenConsole,
  onOpenStoryboard,
  isInvestigating,
  isDone,
  isSevered,
  falkorLatency,
}: DemoWalkthroughProps) {
  const [autoPlay, setAutoPlay] = useState(false);
  const autoPlayTimerRef = useRef<NodeJS.Timeout | null>(null);

  const step = WALKTHROUGH_STEPS[currentStep] || WALKTHROUGH_STEPS[0]!;

  // Keyboard navigation: Left/Right arrows, Escape
  useEffect(() => {
    if (!active) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "ArrowRight") {
        e.preventDefault();
        if (currentStep < WALKTHROUGH_STEPS.length - 1) {
          onStepChange(currentStep + 1);
        }
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        if (currentStep > 0) {
          onStepChange(currentStep - 1);
        }
      } else if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [active, currentStep, onStepChange, onClose]);

  // Auto-play timer
  useEffect(() => {
    if (!active || !autoPlay) {
      if (autoPlayTimerRef.current) clearInterval(autoPlayTimerRef.current);
      return;
    }

    autoPlayTimerRef.current = setInterval(() => {
      onStepChange((prev) => {
        if (prev < WALKTHROUGH_STEPS.length - 1) {
          return prev + 1;
        } else {
          setAutoPlay(false);
          return prev;
        }
      });
    }, 9000);

    return () => {
      if (autoPlayTimerRef.current) clearInterval(autoPlayTimerRef.current);
    };
  }, [active, autoPlay, onStepChange]);

  // Scroll active element into view and apply highlight
  useEffect(() => {
    if (!active) return;
    const targetEl = document.getElementById(step.targetElementId);
    if (targetEl) {
      targetEl.scrollIntoView({ behavior: "smooth", block: "center" });
      targetEl.classList.add("tour-highlight-active");
      return () => {
        targetEl.classList.remove("tour-highlight-active");
      };
    }
  }, [active, currentStep, step.targetElementId]);

  if (!active) return null;

  const handleAction = () => {
    if (step.actionType === "run_investigation") {
      onRunInvestigation();
    } else if (step.actionType === "sever_choke") {
      onApplyCut();
    } else if (step.actionType === "open_console") {
      onOpenConsole();
    } else {
      if (currentStep < WALKTHROUGH_STEPS.length - 1) {
        onStepChange(currentStep + 1);
      } else {
        onClose();
      }
    }
  };

  return (
    <div className="fixed inset-x-0 bottom-4 z-40 px-4 sm:px-6 pointer-events-none">
      <div className="mx-auto max-w-4xl rounded-3xl border border-foreground/20 bg-card/95 p-5 shadow-2xl backdrop-blur-xl pointer-events-auto transition-all duration-300">
        {/* Top bar: Phase & Progress */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/60 pb-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="flex h-5 items-center gap-1.5 rounded-full bg-accent/15 px-2.5 py-0.5 font-bold uppercase tracking-wider text-accent">
              <Sparkles className="h-3 w-3" />
              <span>{step.phase}</span>
            </span>
            <span className="font-semibold text-foreground">{step.badge}</span>
            <span className="hidden text-muted-foreground sm:inline">· FalkorDB Latency: <b className="text-foreground">{falkorLatency}ms</b></span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => onOpenStoryboard()}
              className="hidden items-center gap-1 rounded-full border border-border px-2.5 py-1 text-[11px] font-medium text-muted-foreground hover:bg-muted hover:text-foreground md:inline-flex"
              title="View full demo storyboard and FalkorDB benchmarks"
            >
              <BookOpen className="h-3 w-3" />
              <span>Storyboard</span>
            </button>

            <button
              onClick={() => setAutoPlay(!autoPlay)}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-medium transition",
                autoPlay
                  ? "bg-accent text-accent-foreground"
                  : "bg-secondary text-muted-foreground hover:text-foreground"
              )}
              title={autoPlay ? "Pause auto-tour" : "Auto-advance tour every 9s"}
            >
              {autoPlay ? <Pause className="h-3 w-3" /> : <Play className="h-3 w-3" />}
              <span>{autoPlay ? "Auto: ON" : "Auto-Play"}</span>
            </button>

            <button
              onClick={onClose}
              className="grid h-6 w-6 place-items-center rounded-full bg-secondary text-muted-foreground hover:text-foreground"
              aria-label="Exit walkthrough"
              title="Exit walkthrough (Esc)"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>

        {/* Step Content */}
        <div className="mt-3 grid gap-4 lg:grid-cols-[1fr_auto]">
          <div className="space-y-2">
            <h3 className="font-serif text-xl tracking-tight text-foreground md:text-2xl">
              {step.title}
            </h3>
            <p className="text-sm leading-relaxed text-muted-foreground">
              {step.narration}
            </p>
            {step.cypherSnippet && (
              <div className="mt-2 flex items-center gap-2 overflow-x-auto rounded-xl bg-muted/80 px-3 py-1.5 font-mono text-[11px] text-foreground">
                <Terminal className="h-3.5 w-3.5 shrink-0 text-accent" />
                <span className="truncate">{step.cypherSnippet}</span>
              </div>
            )}
          </div>

          {/* Step Action Button */}
          <div className="flex flex-col justify-center sm:items-end">
            <button
              onClick={handleAction}
              disabled={isInvestigating && step.actionType === "run_investigation"}
              className="inline-flex items-center justify-center gap-2 rounded-full bg-foreground px-5 py-3 text-xs font-semibold text-primary-foreground shadow-md transition hover:opacity-90 disabled:opacity-50"
            >
              {isInvestigating && step.actionType === "run_investigation" ? (
                <>
                  <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-primary-foreground border-t-transparent" />
                  <span>Traversing GraphBLAS…</span>
                </>
              ) : step.actionType === "sever_choke" && isSevered ? (
                <>
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                  <span>Choke Point Severed</span>
                </>
              ) : (
                <>
                  <span>{step.actionLabel || "Next Step →"}</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Bottom controls: Steps navigation pills */}
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-border/40 pt-3 text-xs">
          <div className="flex items-center gap-1.5">
            {WALKTHROUGH_STEPS.map((s, idx) => {
              const isPast = idx < currentStep;
              const isCurrent = idx === currentStep;
              return (
                <button
                  key={s.id}
                  onClick={() => onStepChange(idx)}
                  className={cn(
                    "flex h-6 items-center gap-1.5 rounded-full px-2.5 text-[11px] font-medium transition",
                    isCurrent
                      ? "bg-foreground text-primary-foreground font-semibold"
                      : isPast
                      ? "bg-muted text-foreground hover:bg-secondary"
                      : "text-muted-foreground hover:bg-muted"
                  )}
                  title={s.title}
                >
                  <span>{idx + 1}</span>
                  <span className="hidden md:inline">{s.badge}</span>
                </button>
              );
            })}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => onStepChange(Math.max(0, currentStep - 1))}
              disabled={currentStep === 0}
              className="inline-flex items-center gap-1 rounded-full border border-border px-3 py-1 text-xs font-medium transition hover:bg-secondary disabled:opacity-40"
            >
              <ArrowLeft className="h-3 w-3" />
              <span>Back</span>
            </button>
            <button
              onClick={() => {
                if (currentStep < WALKTHROUGH_STEPS.length - 1) {
                  onStepChange(currentStep + 1);
                } else {
                  onClose();
                }
              }}
              className="inline-flex items-center gap-1 rounded-full bg-secondary px-3 py-1 text-xs font-medium transition hover:bg-border"
            >
              <span>{currentStep === WALKTHROUGH_STEPS.length - 1 ? "Finish" : "Next"}</span>
              <ArrowRight className="h-3 w-3" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/** Rich Storyboard Modal for Hackathon Judges & Presenters */
export function WalkthroughStoryboardModal({
  open,
  onClose,
  onStartTour,
}: {
  open: boolean;
  onClose: () => void;
  onStartTour: () => void;
}) {
  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 grid place-items-center bg-foreground/35 p-4 backdrop-blur-sm overflow-y-auto"
      onClick={onClose}
    >
      <div
        className="rise-in my-8 max-h-[90vh] w-full max-w-4xl overflow-y-auto rounded-3xl bg-card p-8 shadow-soft"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between border-b border-border/60 pb-5">
          <div>
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-accent">
              <Sparkles className="h-3.5 w-3.5" />
              <span>Hackathon Judge & Presentation Guide</span>
            </div>
            <h2 className="mt-1 font-serif text-3xl tracking-tight">
              TRACEFORGE: The Graph-Native Incident Cortex
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Why FalkorDB GraphBLAS beats Vector RAG and Relational SIEMs for Autonomous Incident Response.
            </p>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="grid h-8 w-8 place-items-center rounded-full bg-secondary text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* 3-Act Demo Script */}
        <div className="mt-6 space-y-6">
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              The 3-Act Stage Presentation Arc
            </h3>
            <div className="mt-3 grid gap-3 md:grid-cols-3">
              <div className="rounded-2xl border border-border bg-muted/50 p-4">
                <div className="text-xs font-bold text-accent">ACT I · THE BLIND SPOT</div>
                <div className="mt-1 font-serif text-lg">Alert Ingestion</div>
                <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                  Ingress alert triggers on <code>payment-ingress-api</code>. Traditional SIEMs see a container pod log. They have zero perception of the IAM roles, policies, and KMS keys reachable beyond the container boundary.
                </p>
              </div>

              <div className="rounded-2xl border border-border bg-muted/50 p-4">
                <div className="text-xs font-bold text-accent">ACT II · GRAPHBLAS POWER</div>
                <div className="mt-1 font-serif text-lg">Sub-ms Blast Radius</div>
                <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                  The agent queries FalkorDB via OpenCypher. Using sparse matrix linear algebra, it traverses 5 transitive permission hops in <b>0.3ms</b> to find <b>4,500,000 credit cards</b> exposed in the PCI vault.
                </p>
              </div>

              <div className="rounded-2xl border border-border bg-muted/50 p-4">
                <div className="text-xs font-bold text-accent">ACT III · SURGICAL DEFENSE</div>
                <div className="mt-1 font-serif text-lg">Choke Point & Memory</div>
                <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                  Instead of shutting down production, TRACEFORGE computes the minimum cut vertex (<code>Policy-LegacyPayments-Overprivileged</code>), cuts the edge, verifies 0 paths, and logs to Graph Memory.
                </p>
              </div>
            </div>
          </div>

          {/* Database Comparison Table */}
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Why Traditional Architectures Fail at Transitive Permissions
            </h3>
            <div className="mt-3 overflow-hidden rounded-2xl border border-border">
              <table className="w-full text-left text-xs">
                <thead className="bg-muted text-muted-foreground">
                  <tr>
                    <th className="p-3">Capability</th>
                    <th className="p-3 font-semibold text-foreground">FalkorDB GraphBLAS</th>
                    <th className="p-3">Vector RAG / Embeddings</th>
                    <th className="p-3">Relational SQL (Postgres)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  <tr>
                    <td className="p-3 font-medium">Multi-Hop Reachability</td>
                    <td className="p-3 font-semibold text-emerald-600 dark:text-emerald-400">⚡ Native BFS in 0.3ms</td>
                    <td className="p-3 text-red-500">❌ Blind to transitive edges</td>
                    <td className="p-3 text-amber-600">⚠️ 6 recursive self-joins (&gt;120ms)</td>
                  </tr>
                  <tr>
                    <td className="p-3 font-medium">Optimal Cut Vertex</td>
                    <td className="p-3 font-semibold text-emerald-600 dark:text-emerald-400">⚡ Graph centrality cut</td>
                    <td className="p-3 text-red-500">❌ Hallucinates choke points</td>
                    <td className="p-3 text-red-500">❌ Complex procedural PL/pgSQL</td>
                  </tr>
                  <tr>
                    <td className="p-3 font-medium">Agent Memory Persistence</td>
                    <td className="p-3 font-semibold text-emerald-600 dark:text-emerald-400">⚡ Native :IncidentMemory graph</td>
                    <td className="p-3 text-amber-600">⚠️ Fuzzy semantic retrieval</td>
                    <td className="p-3 text-muted-foreground">Flat audit tables</td>
                  </tr>
                  <tr>
                    <td className="p-3 font-medium">Cloud Cluster Region</td>
                    <td className="p-3 font-semibold text-foreground">AWS ap-south-1 (Mumbai)</td>
                    <td className="p-3 text-muted-foreground">Generic API</td>
                    <td className="p-3 text-muted-foreground">Standard RDS</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Live Deployment Specs */}
          <div className="rounded-2xl bg-secondary/60 p-4 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-accent" />
                <span className="font-semibold text-foreground">Live Cluster:</span>
                <span className="font-mono text-muted-foreground">
                  r-6jissuruar.instance-4i2tmzunw.hc-7up0crkyn.ap-south-1.aws.f2e0a955bb84.cloud:53633
                </span>
              </div>
              <div className="flex items-center gap-3">
                <span>Graph: <b className="text-foreground">traceforge_threat_intel</b></span>
                <span>Nodes: <b className="text-foreground">21</b></span>
                <span>Edges: <b className="text-foreground">19</b></span>
              </div>
            </div>
          </div>
        </div>

        {/* Modal footer CTA */}
        <div className="mt-8 flex flex-wrap items-center justify-between gap-3 border-t border-border/60 pt-5">
          <button
            onClick={onClose}
            className="rounded-full border border-border px-5 py-2.5 text-xs font-medium hover:bg-secondary"
          >
            Close Guide
          </button>

          <button
            onClick={() => {
              onClose();
              onStartTour();
            }}
            className="inline-flex items-center gap-2 rounded-full bg-foreground px-6 py-2.5 text-xs font-semibold text-primary-foreground shadow hover:opacity-90"
          >
            <Sparkles className="h-3.5 w-3.5" />
            <span>Launch Interactive Walkthrough Tour</span>
          </button>
        </div>
      </div>
    </div>
  );
}
