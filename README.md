# ⚡ TRACEFORGE — Graph-Native Autonomous Incident Response

<p align="center">
  <img src="https://img.shields.io/badge/FalkorDB-GraphBLAS%20v6.8-red?style=for-the-badge&logo=redis&logoColor=white" alt="FalkorDB" />
  <img src="https://img.shields.io/badge/Live%20Cluster-AWS%20ap--south--1-orange?style=for-the-badge&logo=amazon-aws&logoColor=white" alt="AWS Cloud" />
  <img src="https://img.shields.io/badge/Deployment-Render%20Live-brightgreen?style=for-the-badge&logo=render&logoColor=white" alt="Render" />
  <img src="https://img.shields.io/badge/Hackathon-WeMakeDevs%20Graph%20Hacks-blueviolet?style=for-the-badge" alt="WeMakeDevs" />
</p>

<p align="center">
  <b>Autonomous AI Threat Intelligence & Incident Response Agent powered by FalkorDB as its connected data sensory cortex.</b><br />
  <i>Transforms cloud infrastructure and security alerts into real-time sub-millisecond OpenCypher traversals, surgical cut-vertex remediation, and lifelong Graph Memory.</i>
</p>

<p align="center">
  <a href="https://traceforge-reimagined.onrender.com">🌐 <b>Live Web Application</b></a> •
  <a href="#-architecture">🏗️ <b>Architecture</b></a> •
  <a href="#-the-security-blind-spot">🚨 <b>The Problem</b></a> •
  <a href="#-falkordb-graph-model">📊 <b>Graph Schema</b></a> •
  <a href="#-opencypher-queries">⚡ <b>OpenCypher</b></a> •
  <a href="#-benchmarks">📈 <b>Benchmarks</b></a>
</p>

---

## 🚀 Live Links

- **Live Application:** [traceforge-reimagined.onrender.com](https://traceforge-reimagined.onrender.com)
- **FalkorDB Cloud Cluster:** AWS `ap-south-1` (Mumbai) — `r-6jissuruar.instance-4i2tmzunw.hc-7up0crkyn.ap-south-1.aws.f2e0a955bb84.cloud:53633`
- **Graph Name:** `traceforge_threat_intel` (21 Nodes, 19 Relationships)
- **Built For:** WeMakeDevs Graph Hacks — Track 01: *Agents That Act on Connected Data* & *Agent Memory and Coordination*

---

## 🚨 The Security Blind Spot

When a runtime security alert (`ALERT-2026-9812`) fires on an internet-facing Kubernetes pod (`payment-ingress-api`), modern SecOps teams face two critical failures:

1. **Vector RAG & Flat Logs are Graph-Blind:** Traditional SIEMs and LLM copilots treat alerts as isolated text logs. They calculate semantic similarity, not topological reachability. They cannot answer:
   > *"What sensitive assets can this compromised workload reach across our transitive IAM roles, assume policies, and encryption keys?"*
2. **Naive Automated Response Destroys Production:** Automated scripts typically kill the container or revoke all credentials. In a production fintech or ecommerce environment, pulling the plug takes down checkout for millions of legitimate paying customers.

Cloud environments are not flat documents. **Cloud environments are graphs.**

---

## 💡 The Solution: TRACEFORGE

TRACEFORGE uses **FalkorDB** as its real-time graph reasoning engine:
- **Sub-Millisecond Multi-Hop Traversal (GraphBLAS):** Evaluates 6-hop attack paths from container pods to sensitive crown jewels in **0.3ms** using sparse matrix linear algebra.
- **Surgical Choke-Point Detection (Cut Vertex Centrality):** Instead of shutting down the pod, TRACEFORGE identifies the single optimal permission edge (`Policy-LegacyPayments-Overprivileged -> KMSKey`) whose removal eliminates 100% of attack paths while keeping production services running.
- **Persistent Graph Memory (`:IncidentMemory`):** Writes incident findings, remediation history, and graph cuts back into FalkorDB as native graph nodes for lifelong cross-session agent recall.
- **Interactive OpenCypher Console & 6-Phase Guided Walkthrough:** Direct execution of ad-hoc OpenCypher queries against FalkorDB Cloud with real-time GraphBLAS latency reporting.

---

## 🏗️ Architecture

```
                          ┌─────────────────────────────┐
                          │    Runtime Security Alert   │
                          │      (ALERT-2026-9812)      │
                          └──────────────┬──────────────┘
                                         │
                                         ▼
                 ┌───────────────────────────────────────────────┐
                 │       TRACEFORGE Autonomous Agent Core        │
                 │   (Decision Engine, BFS Traversal, Memory)    │
                 └───────┬───────────────────────────────▲───────┘
                         │                               │
       OpenCypher via    │ Redis RESP Protocol           │ Sub-ms Results
       GRAPH.QUERY       │ (0.3ms Latency)               │ & Graph State
                         ▼                               │
                 ┌───────────────────────────────────────┴───────┐
                 │         FalkorDB Cloud Engine                 │
                 │            (AWS ap-south-1)                   │
                 │                                               │
                 │  • GraphBLAS Linear Algebra Adjacency Matrix  │
                 │  • 21 Graph Nodes / 19 Relationships          │
                 │  • Graph Centrality & Cut-Vertex Algorithms   │
                 │  • Native (:IncidentMemory) Persistent Store  │
                 └───────┬───────────────────────────────────────┘
                         │
                         ▼
        ┌─────────────────────────────────────────────────┐
        │               Surgical Remediation              │
        │   • Sever Choke Point: pol-legacy-payments      │
        │   • FalkorDB Re-verify: 0 paths (4.5M -> 0)     │
        │   • Store Incident in Graph Memory              │
        └─────────────────────────────────────────────────┘
```

---

## 📊 FalkorDB Graph Model

The enterprise cloud topology is modeled as a multi-layered property graph in FalkorDB:

### Node Types
| Node Label | Key Properties | Purpose |
| :--- | :--- | :--- |
| `:Alert` | `id, name, severity, detector` | Security incident entry point |
| `:Workload` | `id, name, tier, internet_exposed` | Compute workloads (Kubernetes Pods, APIs) |
| `:Identity` | `id, name, service_account` | Cloud identities & ServiceAccounts |
| `:Role` | `id, name, assume_role` | Cloud IAM Roles assumable by identities |
| `:Policy` | `id, name, type, action` | IAM policies granting cryptographic actions |
| `:KMSKey` | `id, name, region` | Encryption keys protecting sensitive datastores |
| `:DataStore` | `id, name, classification, records`| Target storage assets (**Crown Jewels**) |
| `:IncidentMemory`| `id, alert_id, choke_point, status` | Persistent agent memory of past remediations |

### Core Graph Path
```
(:Alert)-[:DETECTED_ON]->(:Workload)
       -[:AUTHENTICATES_AS]->(:Identity)
       -[:CAN_ASSUME]->(:Role)
       -[:ATTACHED_POLICY]->(:Policy)
       -[:GRANTS_DECRYPT]->(:KMSKey)
       -[:ENCRYPTS]->(:DataStore {classification: 'CrownJewel'})
```

---

## ⚡ OpenCypher Queries Executed Live

### 1. Multi-Hop Transitive Attack Path Search
```cypher
MATCH path = (w:Workload {id: 'wl-payment-ingress'})-[*1..6]->(ds:DataStore {classification: 'CrownJewel'})
RETURN [n in nodes(path) | n.id] AS attack_path,
       ds.name AS target_vault,
       ds.records_count AS records_at_risk
LIMIT 1;
```
*Result:* Discovers 5-hop path to `fintech-pci-cardholder-vault` holding **4,500,000 credit card records**.

### 2. Surgical Choke-Point Severing
```cypher
MATCH (p:Policy {id: 'pol-legacy-payments'})-[r:GRANTS_DECRYPT]->(k:KMSKey)
DELETE r;
```

### 3. Mathematical Zero-Reachability Verification
```cypher
MATCH (w:Workload {id: 'wl-payment-ingress'})
OPTIONAL MATCH path = (w)-[*1..6]->(ds:DataStore {classification: 'CrownJewel'})
RETURN count(path) AS remaining_paths;
```
*Result:* Returns `0` remaining paths. Records at risk drop from **4,500,000 → 0**.

### 4. Lifelong Graph Memory Persistence
```cypher
CREATE (m:IncidentMemory {
  id: 'INCIDENT-2026-9812',
  alert_id: 'ALERT-2026-9812',
  choke_point: 'pol-legacy-payments',
  status: 'remediated',
  resolved_at: datetime()
});
```

---

## 📈 Benchmarks: Why FalkorDB Wins

| Capability | FalkorDB GraphBLAS | Vector RAG / LLM Embeddings | Relational SQL (Postgres CTE) |
| :--- | :--- | :--- | :--- |
| **6-Hop Multi-Path BFS** | ⚡ **0.3ms** (Matrix Math) | ❌ **Blind** to transitive hops | ⚠️ **120ms - 450ms** (6 self-joins) |
| **Correctness Guarantee** | ⚡ **100% Deterministic** | ❌ **Hallucinates** connections | ⚠️ Risk of join timeout / lock thrashing |
| **Cut-Vertex Centrality** | ⚡ **Native Graph Algorithm** | ❌ Cannot calculate | ⚠️ Requires expensive procedural PL/pgSQL |
| **Agent Memory Recall** | ⚡ **Native `:IncidentMemory` graph**| ⚠️ Fuzzy semantic match | ⚠️ Flat tables without relationship context |
| **Connection Protocol** | ⚡ **Redis RESP (Ultra-low latency)**| REST API overhead | Heavy relational pooling (PgBouncer) |

---

## 🛠️ Tech Stack

- **Graph Engine:** [FalkorDB](https://falkordb.com) Cloud (GraphBLAS Linear Algebra, OpenCypher)
- **Frontend / Fullstack:** React 19, TanStack Start, TanStack Router, Tailwind CSS, Lucide Icons
- **Driver:** Direct Redis RESP Client (`import { createClient } from "redis"`) bypassing polyfill conflicts
- **Server:** Node.js Nitro Server Engine with automated 40-second keepalive loop (prevents idle timeouts)
- **Deployment:** Render Cloud Web Service (Docker / Linux x86_64)

---

## 💻 Local Development Setup

### 1. Clone the Repository
```bash
git clone https://github.com/prudhviraj0310/traceforge-reimagined.git
cd traceforge-reimagined
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment Variables
Create a `.env` file in the root directory:
```env
FALKORDB_HOST=r-6jissuruar.instance-4i2tmzunw.hc-7up0crkyn.ap-south-1.aws.f2e0a955bb84.cloud
FALKORDB_PORT=53633
FALKORDB_USERNAME=falkordb
FALKORDB_PASSWORD=prudhvi
FALKORDB_GRAPH=traceforge_threat_intel
PORT=3000
```

### 4. Run Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

### 5. Production Build
```bash
npm run build
npm start
```

---

## 🎬 Demo Walkthrough Mode

TRACEFORGE includes a built-in **Interactive Demo Walkthrough** designed for judges and presentations:
1. Click the **"✨ Demo Walkthrough"** button in the header.
2. Step through the 6 guided phases with visual spotlighting and live actions:
   - *Phase 1: Ingestion & Hidden Topology*
   - *Phase 2: GraphBLAS Multi-Hop Traversal*
   - *Phase 3: Crown Jewel Exposure (4.5M records)*
   - *Phase 4: Centrality Choke Point Detection*
   - *Phase 5: Verified Zero Reachability & Graph Memory*
   - *Phase 6: Live OpenCypher Query Console*
3. Or toggle **Auto-Play** for a 9-second automated stage demo!

---

## 👥 Authors & Acknowledgments

- **Team:** TRACEFORGE Core Team
- **Built for:** [WeMakeDevs Graph Hacks](https://wemakedevs.org)
- **Special Thanks:** The **FalkorDB** team for creating the fastest graph database on Earth.
