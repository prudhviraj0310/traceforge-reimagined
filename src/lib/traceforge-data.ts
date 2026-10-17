export type NodeType = "Alert" | "Workload" | "Identity" | "IAMRole" | "Policy" | "Key" | "Datastore";

export interface GNode {
  id: string;
  type: NodeType;
  name: string;
  props: Record<string, string | number | boolean>;
}
export interface GEdge {
  source: string;
  target: string;
  rel: string;
}

export const COLUMNS: NodeType[] = ["Alert", "Workload", "Identity", "IAMRole", "Policy", "Key", "Datastore"];
export const TYPE_LABEL: Record<NodeType, string> = {
  Alert: "Alerts",
  Workload: "Workloads",
  Identity: "Identities",
  IAMRole: "IAM roles",
  Policy: "Policies",
  Key: "KMS keys",
  Datastore: "Datastores",
};

export const NODES: GNode[] = [
  { id: "ALERT-2026-9812", type: "Alert", name: "C&C beaconing", props: { severity: "CRITICAL", detector: "GuardDuty + Falco", rule: "CVE-2026-2241 RCE in ingress gateway" } },
  { id: "ALERT-2026-9815", type: "Alert", name: "/etc/shadow read", props: { severity: "HIGH", detector: "K8s Falco", rule: "Privilege escalation probe" } },
  { id: "ALERT-2026-9820", type: "Alert", name: "S3 enumeration", props: { severity: "MEDIUM", detector: "CloudTrail anomaly", rule: "Data recon" } },
  { id: "wl-payment-ingress", type: "Workload", name: "payment-ingress-api", props: { namespace: "payments-prod", ip: "10.244.3.42", internet_exposed: true, status: "compromised" } },
  { id: "wl-auth-service", type: "Workload", name: "auth-identity-svc", props: { namespace: "auth-prod", ip: "10.244.5.19", internet_exposed: false } },
  { id: "wl-analytics-worker", type: "Workload", name: "analytics-worker", props: { namespace: "data-platform", ip: "10.244.8.88", internet_exposed: false } },
  { id: "id-k8s-payment-sa", type: "Identity", name: "sa-payment-frontend", props: { kind: "K8sServiceAccount", namespace: "payments-prod" } },
  { id: "id-k8s-auth-sa", type: "Identity", name: "sa-auth-service", props: { kind: "K8sServiceAccount", namespace: "auth-prod" } },
  { id: "id-k8s-analytics-sa", type: "Identity", name: "sa-analytics-batch", props: { kind: "K8sServiceAccount", namespace: "data-platform" } },
  { id: "role-payment-app", type: "IAMRole", name: "PaymentAppRole", props: { risk: "Critical", trust: "IRSA / OIDC" } },
  { id: "role-super-admin", type: "IAMRole", name: "CloudAdminEmergency", props: { risk: "Extreme", trust: "IRSA / OIDC" } },
  { id: "role-analytics-read", type: "IAMRole", name: "AnalyticsReadOnly", props: { risk: "Low", trust: "IRSA / OIDC" } },
  { id: "pol-legacy-payments", type: "Policy", name: "LegacyPayments-Overpriv", props: { actions: "kms:*, s3:GetObject, secrets:Get", resources: "*", flaw: "Wildcard kms:* decrypts any KMS-managed bucket" } },
  { id: "pol-full-admin", type: "Policy", name: "AdministratorAccess", props: { actions: "*", resources: "*" } },
  { id: "pol-analytics-readonly", type: "Policy", name: "Analytics-S3Read", props: { actions: "s3:GetObject", resources: "assets/*" } },
  { id: "sec-master-kms", type: "Key", name: "customer-vault-kms", props: { region: "eu-west-1", rotation: "disabled" } },
  { id: "sec-disaster-recovery-kms", type: "Key", name: "key-backup-dr-global", props: { region: "global", rotation: "365d" } },
  { id: "ds-customer-vault", type: "Datastore", name: "pci-cardholder-vault", props: { records: 4500000, classification: "PCI-DSS", crown_jewel: true } },
  { id: "ds-corp-backup", type: "Datastore", name: "global-dr-vault", props: { records: 12000000, classification: "Confidential", crown_jewel: true } },
  { id: "ds-auth-redis", type: "Datastore", name: "redis-session-cluster", props: { records: 85000, classification: "Session" } },
  { id: "ds-public-assets", type: "Datastore", name: "static-assets-cdn", props: { records: 12500, classification: "Public" } },
];

export const EDGES: GEdge[] = [
  { source: "ALERT-2026-9812", target: "wl-payment-ingress", rel: "DETECTED_ON" },
  { source: "ALERT-2026-9815", target: "wl-auth-service", rel: "DETECTED_ON" },
  { source: "ALERT-2026-9820", target: "wl-analytics-worker", rel: "DETECTED_ON" },
  { source: "wl-payment-ingress", target: "id-k8s-payment-sa", rel: "AUTHENTICATES_AS" },
  { source: "wl-auth-service", target: "id-k8s-auth-sa", rel: "AUTHENTICATES_AS" },
  { source: "wl-analytics-worker", target: "id-k8s-analytics-sa", rel: "AUTHENTICATES_AS" },
  { source: "id-k8s-payment-sa", target: "role-payment-app", rel: "CAN_ASSUME" },
  { source: "id-k8s-auth-sa", target: "role-super-admin", rel: "CAN_ASSUME" },
  { source: "id-k8s-analytics-sa", target: "role-analytics-read", rel: "CAN_ASSUME" },
  { source: "role-payment-app", target: "pol-legacy-payments", rel: "HAS_POLICY" },
  { source: "role-super-admin", target: "pol-full-admin", rel: "HAS_POLICY" },
  { source: "role-analytics-read", target: "pol-analytics-readonly", rel: "HAS_POLICY" },
  { source: "pol-legacy-payments", target: "sec-master-kms", rel: "PERMITS_ACCESS" },
  { source: "pol-full-admin", target: "sec-disaster-recovery-kms", rel: "PERMITS_ACCESS" },
  { source: "sec-master-kms", target: "ds-customer-vault", rel: "DECRYPTS_RESOURCE" },
  { source: "sec-disaster-recovery-kms", target: "ds-corp-backup", rel: "DECRYPTS_RESOURCE" },
  { source: "pol-analytics-readonly", target: "ds-public-assets", rel: "PERMITS_ACCESS" },
  { source: "wl-payment-ingress", target: "ds-auth-redis", rel: "CAN_NETWORK_REACH" },
  { source: "wl-auth-service", target: "ds-auth-redis", rel: "CAN_NETWORK_REACH" },
];

export const nodeById = (id: string) => NODES.find((n) => n.id === id);

/** BFS from a workload to the reachable crown-jewel datastore with the most records. */
export function findAttackPath(workloadId: string): string[] {
  const prev = new Map<string, string | null>([[workloadId, null]]);
  const queue = [workloadId];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const e of EDGES.filter((e) => e.source === cur)) {
      if (!prev.has(e.target)) {
        prev.set(e.target, cur);
        queue.push(e.target);
      }
    }
  }
  const jewels = [...prev.keys()]
    .map(nodeById)
    .filter((n): n is GNode => !!n && n.type === "Datastore")
    .sort((a, b) => Number(b.props.crown_jewel ?? 0) - Number(a.props.crown_jewel ?? 0) || Number(b.props.records) - Number(a.props.records));
  if (!jewels.length) return [workloadId];
  const path: string[] = [];
  let cur: string | null = jewels[0].id;
  while (cur) {
    path.unshift(cur);
    cur = prev.get(cur) ?? null;
  }
  return path;
}

export function blastRadius(workloadId: string) {
  const seen = new Set<string>([workloadId]);
  const queue = [workloadId];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const e of EDGES.filter((e) => e.source === cur)) if (!seen.has(e.target)) { seen.add(e.target); queue.push(e.target); }
  }
  const stores = [...seen].map(nodeById).filter((n): n is GNode => !!n && n.type === "Datastore");
  return {
    reachable: seen.size - 1,
    datastores: stores,
    crownJewels: stores.filter((s) => s.props.crown_jewel).length,
    records: stores.reduce((s, d) => s + Number(d.props.records), 0),
    sensitiveRecords: stores.filter((s) => s.props.crown_jewel).reduce((s, d) => s + Number(d.props.records), 0),
  };
}

export interface FeedEvent {
  step: "PLAN" | "TOOL" | "OBSERVATION" | "DECISION" | "ACTION";
  title: string;
  description: string;
  tool?: string;
  reveal?: number; // how many path hops become visible
}

export function buildInvestigation(alertId: string): { events: FeedEvent[]; path: string[]; choke: string } {
  const alertEdge = EDGES.find((e) => e.source === alertId)!;
  const wl = alertEdge.target;
  const path = findAttackPath(wl);
  const br = blastRadius(wl);
  const choke = path.find((id) => nodeById(id)?.type === "Policy") ?? path[1] ?? wl;
  const target = nodeById(path[path.length - 1])!;
  const fmt = (n: number) => n.toLocaleString("en-US");
  return {
    path,
    choke,
    events: [
      { step: "PLAN", title: "Validate alert origin", description: `Confirm ${alertId} maps to a live workload before traversing.` },
      { step: "TOOL", title: "traceforge_validate_alert", tool: "validate_alert", description: `Alert anchored to ${nodeById(wl)!.name} via DETECTED_ON.`, reveal: 1 },
      { step: "TOOL", title: "traceforge_find_attack_paths", tool: "find_attack_paths", description: `Multi-hop traversal from ${nodeById(wl)!.name} across AUTHENTICATES_AS → CAN_ASSUME → HAS_POLICY → PERMITS_ACCESS.`, reveal: Math.ceil(path.length / 2) },
      { step: "OBSERVATION", title: `${path.length - 1}-hop path discovered`, description: `${path.map((id) => nodeById(id)!.name).join(" → ")}`, reveal: path.length },
      { step: "TOOL", title: "traceforge_calculate_blast_radius", tool: "calculate_blast_radius", description: `${br.reachable} reachable nodes, ${br.crownJewels} crown jewel(s), ${fmt(br.sensitiveRecords)} sensitive records exposed.` },
      { step: "TOOL", title: "traceforge_identify_optimal_choke_point", tool: "identify_optimal_choke_point", description: "Brandes betweenness centrality across the compromised subgraph." },
      { step: "DECISION", title: `Sever ${nodeById(choke)!.name}`, description: `Smallest intervention that disconnects ${target.name} with least collateral to running services.` },
      { step: "ACTION", title: "Proposal recorded — simulation", description: "Containment and hardening steps are drafted, not executed. Live integrations fail closed." },
    ],
  };
}
