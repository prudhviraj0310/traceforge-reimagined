"""
TRACEFORGE LLM-driven investigator (v2).

The model picks which graph tool to call next instead of following a fixed
pipeline. Adds graph memory (incidents persisted in a separate FalkorDB graph
that reseeding never wipes) and a gated containment action (sever an edge,
then re-verify reachability).

Drop-in for the existing investigator: same `investigate(alert_id,
auto_remediate=..., event_callback=...)` signature used by backend/main.py.
"""

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

MAX_STEPS = 16
MEMORY_GRAPH = os.getenv("FALKORDB_MEMORY_GRAPH", "traceforge_memory")
_REL_TYPE = re.compile(r"^[A-Z][A-Z0-9_]{0,40}$")
# Relationship types the agent may cut. Never alerts or memory edges.
SEVERABLE = {"AUTHENTICATES_AS", "CAN_ASSUME", "HAS_POLICY", "PERMITS_ACCESS", "DECRYPTS_RESOURCE", "CAN_NETWORK_REACH"}

SYSTEM = """You are TRACEFORGE, a security incident investigator working over an
infrastructure graph (Workload -> Identity -> IAMRole -> Policy -> Key -> DataStore).
Decide which tool to call next from what you have learned so far. Usually: recall
prior incidents on the workload, find attack paths, measure blast radius, rank
choke points, then (if remediation is allowed) sever the single edge that cuts the
path with least collateral and re-verify reachability. If a path survives, choose
another cut. Always store the incident before finishing. Reply with a short
explanation that cites node ids. Never invent node ids."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class GraphMemory:
    """Incident memory. Lives in its own FalkorDB graph so `db_engine.clear()` on reseed keeps it."""

    def __init__(self, engine: Any) -> None:
        self.engine = engine
        self._local: List[Dict[str, Any]] = []  # fallback when FalkorDB is offline (lost on restart)

    def _graph(self) -> Any:
        if getattr(self.engine, "is_connected", False) and getattr(self.engine, "client", None):
            return self.engine.client.select_graph(MEMORY_GRAPH)
        return None

    def recall(self, workload_id: str) -> List[Dict[str, Any]]:
        g = self._graph()
        if g is not None:
            res = g.query(
                "MATCH (i:Incident {workload_id: $wid}) RETURN i.id, i.alert_id, i.cut, i.summary, i.at "
                "ORDER BY i.at DESC LIMIT 5",
                {"wid": workload_id},
            )
            keys = ["id", "alert_id", "cut", "summary", "at"]
            return [dict(zip(keys, row)) for row in res.result_set]
        return [i for i in self._local if i["workload_id"] == workload_id][:5]

    def store(self, alert_id: str, workload_id: str, cut: str, summary: str) -> Dict[str, Any]:
        at = _now()
        inc = {"id": f"INC-{alert_id}-{at[:19]}", "alert_id": alert_id, "workload_id": workload_id,
               "cut": cut, "summary": summary, "at": at}
        g = self._graph()
        if g is not None:
            g.query("CREATE (i:Incident) SET i = $p", {"p": inc})
        else:
            self._local.insert(0, inc)
        return inc


class LLMInvestigator:
    def __init__(self, engine: Any = None, tools: Optional[Dict[str, Callable[..., Any]]] = None,
                 client: Any = None, model: Optional[str] = None) -> None:
        if engine is None:
            from traceforge.engine.db import db_engine as engine  # noqa: N813
        self.engine = engine
        self.memory = GraphMemory(engine)
        self.model = model or os.getenv("TRACEFORGE_MODEL", "gpt-4o-mini")
        self._client = client
        self.transport = "injected"
        self._mcp: Any = None
        if tools is not None:
            self.graph_tools = tools
        else:
            self.graph_tools, self.transport = self._default_tools()
            if self.transport == "mcp-stdio":
                from traceforge.agent.mcp_bridge import shared_bridge
                self._mcp = shared_bridge()

    @property
    def client(self) -> Any:
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI()
        return self._client

    @staticmethod
    def _default_tools() -> "tuple[Dict[str, Callable[..., Any]], str]":
        # Default: real MCP over stdio. TRACEFORGE_TOOL_TRANSPORT=inprocess opts out.
        if os.getenv("TRACEFORGE_TOOL_TRANSPORT", "mcp").lower() == "mcp":
            try:
                from traceforge.agent.mcp_bridge import shared_bridge
                return shared_bridge().tools(), "mcp-stdio"
            except Exception as exc:  # noqa: BLE001
                import logging
                logging.getLogger("traceforge.agent").warning("MCP transport unavailable (%s); using in-process tools", exc)
        from traceforge.mcp_server import server as s
        return {
            "list_alerts": s.traceforge_list_alerts,
            "query_graph": s.traceforge_query_graph,  # read-only, validated by db_engine.execute_query
            "find_attack_paths": s.traceforge_find_attack_paths,
            "calculate_blast_radius": s.traceforge_calculate_blast_radius,
            "betweenness_centrality": s.traceforge_calculate_betweenness_centrality,
            "identify_choke_point": s.traceforge_identify_optimal_choke_point,
        }, "inprocess"

    # ----- agent-owned tools -----
    def _sever_edge(self, ctx: Dict[str, Any], source_id: str, target_id: str, rel_type: str) -> Dict[str, Any]:
        if not ctx["auto_remediate"]:
            return {"severed": False, "reason": "Remediation not authorised for this caller; proposal only.",
                    "proposed_cut": f"{source_id}-[:{rel_type}]->{target_id}"}
        if not _REL_TYPE.match(rel_type) or rel_type not in SEVERABLE:
            return {"severed": False, "reason": f"Relationship type '{rel_type}' may not be severed."}
        if self._mcp:
            ok = self._mcp.call("traceforge_sever_edge", {"source_id": source_id, "target_id": target_id, "rel_type": rel_type}).get("severed")
        else:
            ok = self.engine.sever_relationship(source_id, target_id, rel_type)
        if ok:
            ctx["cuts"].append(f"{source_id}-[:{rel_type}]->{target_id}")
        return {"severed": bool(ok), "edge": f"{source_id}-[:{rel_type}]->{target_id}"}

    def _verify(self, ctx: Dict[str, Any], workload_id: str) -> Dict[str, Any]:
        if self._mcp:
            r = self._mcp.call("traceforge_verify_reachability", {"workload_id": workload_id})
            ctx["verified_paths_remaining"] = r["crown_jewel_paths_remaining"]
            return r
        paths = self.engine.find_shortest_attack_paths(workload_id)
        ctx["verified_paths_remaining"] = len(paths)
        return {"crown_jewel_paths_remaining": len(paths), "paths": paths[:3]}

    def _recall(self, ctx: Dict[str, Any], workload_id: str) -> Dict[str, Any]:
        if self._mcp:
            return self._mcp.call("traceforge_recall_incidents", {"workload_id": workload_id})
        return {"workload_id": workload_id, "prior_incidents": self.memory.recall(workload_id)}

    def _store(self, ctx: Dict[str, Any], workload_id: str, summary: str) -> Dict[str, Any]:
        cut = "; ".join(ctx["cuts"]) or "none"
        ctx["stored"] = True
        if self._mcp:
            return self._mcp.call("traceforge_store_incident", {"alert_id": ctx["alert_id"], "workload_id": workload_id, "cut": cut, "summary": summary})
        return {"stored": self.memory.store(ctx["alert_id"], workload_id, cut, summary)["id"]}

    def _schemas(self) -> List[Dict[str, Any]]:
        S = {"type": "string"}

        def fn(name: str, desc: str, props: Dict[str, Any], req: List[str]) -> Dict[str, Any]:
            return {"type": "function", "function": {"name": name, "description": desc, "parameters": {
                "type": "object", "properties": props, "required": req, "additionalProperties": False}}}

        all_schemas = [
            fn("list_alerts", "List open security alerts.", {}, []),
            fn("query_graph", "Run a read-only Cypher MATCH/RETURN query.", {"cypher": S}, ["cypher"]),
            fn("find_attack_paths", "Multi-hop paths from an alert's workload to crown-jewel datastores.", {"alert_id": S}, ["alert_id"]),
            fn("calculate_blast_radius", "Everything reachable from a node and sensitive records exposed.", {"node_id": S}, ["node_id"]),
            fn("betweenness_centrality", "Top nodes by betweenness centrality.", {"top_k": {"type": "integer"}}, ["top_k"]),
            fn("identify_choke_point", "Best node on a path to cut with least collateral.",
               {"path_node_ids": {"type": "array", "items": S}}, ["path_node_ids"]),
            fn("recall_incidents", "Past incidents on this workload from graph memory.", {"workload_id": S}, ["workload_id"]),
            fn("store_incident", "Persist this incident and any cuts to graph memory.", {"workload_id": S, "summary": S}, ["workload_id", "summary"]),
            fn("sever_edge", "Containment: remove one relationship from the graph.",
               {"source_id": S, "target_id": S, "rel_type": S}, ["source_id", "target_id", "rel_type"]),
            fn("verify_reachability", "Re-check whether any crown-jewel path remains from a workload.", {"workload_id": S}, ["workload_id"]),
        ]
        allowed = set(self.graph_tools) | {"recall_incidents", "store_incident", "sever_edge", "verify_reachability"}
        return [s for s in all_schemas if s["function"]["name"] in allowed]

    def _call(self, ctx: Dict[str, Any], name: str, args: Dict[str, Any]) -> Any:
        own = {"sever_edge": self._sever_edge, "verify_reachability": self._verify,
               "recall_incidents": self._recall, "store_incident": self._store}
        if name in own:
            return own[name](ctx, **args)
        if name in self.graph_tools:
            return self.graph_tools[name](**args)
        raise KeyError(f"Unknown tool '{name}'")

    def investigate(self, alert_id: str, auto_remediate: bool = False,
                    event_callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        emit = event_callback or (lambda e: None)
        ctx: Dict[str, Any] = {"alert_id": alert_id, "auto_remediate": auto_remediate, "cuts": [],
                               "stored": False, "verified_paths_remaining": None}
        msgs: List[Dict[str, Any]] = [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"Investigate alert {alert_id}. Remediation allowed: {auto_remediate}."},
        ]
        trace: List[Dict[str, Any]] = []
        events: List[Dict[str, Any]] = []

        def push(ev: Dict[str, Any]) -> None:
            ev["timestamp"] = _now()
            events.append(ev)
            emit(ev)

        summary = "Step limit reached before the agent finished."
        for _ in range(MAX_STEPS):
            msg = self.client.chat.completions.create(model=self.model, messages=msgs, tools=self._schemas()).choices[0].message
            msgs.append(msg.model_dump(exclude_none=True))
            if msg.content:
                push({"step": "AGENT_REASONING", "title": "Reasoning", "description": msg.content})
            if not msg.tool_calls:
                summary = msg.content or ""
                break
            for call in msg.tool_calls:
                name = call.function.name
                try:
                    args = json.loads(call.function.arguments or "{}")
                    result = self._call(ctx, name, args)
                except Exception as exc:  # returned to the model so it can adapt
                    args, result = {}, {"error": f"{type(exc).__name__}: {exc}"}
                trace.append({"tool": name, "args": args, "result": result})
                push({"step": "MCP_TOOL_RESULT", "title": f"traceforge_{name}", "tool": name,
                      "description": json.dumps(args, default=str), "data": {"result": result}})
                msgs.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result, default=str)[:6000]})

        if not ctx["stored"]:  # memory is guaranteed, not left to the model
            wl = next((t["result"].get("origin_workload_id") for t in trace
                       if t["tool"] == "find_attack_paths" and isinstance(t["result"], dict)), None)
            if wl:
                self._store(ctx, wl, summary[:500])

        path = next((t["result"]["paths"][0] for t in trace if t["tool"] == "find_attack_paths"
                     and isinstance(t["result"], dict) and t["result"].get("paths")), None)
        choke = next((t["result"].get("optimal_choke_point") for t in reversed(trace)
                      if t["tool"] == "identify_choke_point" and isinstance(t["result"], dict)), None)
        push({"step": "STEP_8_INVESTIGATION_COMPLETE", "title": "Investigation complete", "description": summary})
        return {
            "status": "contained" if ctx["cuts"] and ctx["verified_paths_remaining"] == 0 else "investigated",
            "alert_id": alert_id,
            "summary": summary,
            "attack_path": path,
            "optimal_choke_point": choke,
            "cuts_applied": ctx["cuts"],
            "paths_remaining_after_cut": ctx["verified_paths_remaining"],
            "tool_sequence": [t["tool"] for t in trace],
            "tool_transport": self.transport,
            "events": events,
        }
