"""
TRACEFORGE FastMCP Server
Exposes standardized Model Context Protocol tools for graph investigation,
pathfinding, blast radius analysis, and autonomous security remediation.
"""

import json
import logging
import os
from typing import Dict, Any, List, Optional
from mcp.server.fastmcp import FastMCP
from traceforge.engine.db import db_engine
from traceforge.engine.seed import seed_enterprise_environment

logger = logging.getLogger("traceforge.mcp")
logging.basicConfig(level=logging.INFO)

# Initialize FastMCP Server
mcp = FastMCP("traceforge-security-graph")

@mcp.tool()
def traceforge_list_alerts() -> List[Dict[str, Any]]:
    """
    List all pending and unresolved security alerts ingested into TRACEFORGE.
    Returns alert identifiers, rules, severities, detectors, and target workloads.
    """
    alerts = []
    for nid, data in db_engine.node_store.items():
        if data.get("label") == "Alert" and data.get("status") in {"unresolved", "investigating"}:
            alerts.append(data)
    return alerts

@mcp.tool()
def traceforge_query_graph(cypher: str) -> List[Dict[str, Any]]:
    """
    Execute an arbitrary OpenCypher pattern matching query directly on the FalkorDB graph.
    Useful for inspecting specific entity attributes, relationship properties, or ad-hoc joins.
    """
    logger.info(f"[MCP Tool: query_graph] Cypher: {cypher}")
    return db_engine.execute_query(cypher)

@mcp.tool()
def traceforge_find_attack_paths(alert_id: str) -> Dict[str, Any]:
    """
    Given a security alert ID, identifies the compromised origin workload and computes
    all multi-hop privilege escalation attack paths leading to sensitive Crown Jewel assets.
    """
    alert = db_engine.node_store.get(alert_id)
    if not alert:
        return {"error": f"Alert {alert_id} not found in graph."}
        
    workload_id = alert.get("target_workload_id")
    if not workload_id:
        # Check incident edge
        for edge in db_engine.edge_store:
            if edge["source"] == alert_id and edge["type"] == "DETECTED_ON":
                workload_id = edge["target"]
                break
                
    if not workload_id:
        return {"error": f"No target workload linked to alert {alert_id}."}
    workload = db_engine.node_store.get(workload_id)
    if not workload or workload.get("label") != "Workload":
        return {"error": f"Alert {alert_id} does not target a valid Workload node."}
        
    logger.info(f"[MCP Tool: find_attack_paths] Tracing from origin: {workload_id}")
    paths = db_engine.find_shortest_attack_paths(workload_id)
    
    return {
        "alert_id": alert_id,
        "origin_workload_id": workload_id,
        "origin_workload_name": db_engine.node_store.get(workload_id, {}).get("name", workload_id),
        "total_paths_discovered": len(paths),
        "paths": paths
    }

@mcp.tool()
def traceforge_calculate_blast_radius(node_id: str) -> Dict[str, Any]:
    """
    Calculates the transitive blast radius and centrality metrics for any node in the graph.
    Returns the count of reachable assets, exposed sensitive record counts, and betweenness score.
    """
    logger.info(f"[MCP Tool: calculate_blast_radius] Target Node: {node_id}")
    return db_engine.calculate_blast_radius(node_id)

@mcp.tool()
def traceforge_calculate_betweenness_centrality(top_k: int = 10) -> Dict[str, Any]:
    """
    Executes Brandes betweenness centrality algorithm across the entire infrastructure graph.
    Identifies the most critical bridge nodes that appear on the greatest number of shortest paths.
    """
    logger.info(f"[MCP Tool: calculate_betweenness_centrality] Top {top_k}")
    centrality_scores = db_engine.calculate_betweenness_centrality(top_k)
    enriched = []
    for nid, score in centrality_scores.items():
        node = db_engine.node_store.get(nid, {})
        enriched.append({
            "node_id": nid,
            "name": node.get("name", nid),
            "label": node.get("label", "Unknown"),
            "betweenness_score": score,
            "status": node.get("status", "active")
        })
    return {
        "algorithm": "Brandes Betweenness Centrality",
        "top_k": top_k,
        "critical_transit_nodes": enriched
    }

@mcp.tool()
def traceforge_identify_optimal_choke_point(path_node_ids: List[str]) -> Dict[str, Any]:
    """
    Evaluates an attack path sequence and calculates the optimal choke-point
    (the single node or relationship to sever) that halts the attack with minimum collateral damage.
    """
    logger.info(f"[MCP Tool: identify_optimal_choke_point] Path Nodes: {path_node_ids}")
    return db_engine.identify_optimal_choke_point(path_node_ids)

@mcp.tool()
def traceforge_quarantine_workload(workload_id: str, reason: str = "Active Compromise Containment") -> Dict[str, Any]:
    """
    Autonomous remediation action: Isolates a compromised Kubernetes pod or cloud instance.
    Applies a zero-egress NetworkPolicy and marks the workload as quarantined in FalkorDB.
    """
    logger.info(f"[MCP Tool: quarantine_workload] Quarantining {workload_id} ({reason})")
    workload = db_engine.node_store.get(workload_id)
    if not workload or workload.get("label") != "Workload":
        return {
            "success": False,
            "message": f"Workload '{workload_id}' not found in graph topology.",
            "k8s_audit": {"status": "FAILED_NOT_FOUND", "workload_id": workload_id}
        }

    if not _simulation_mode():
        return {
            "success": False,
            "performed": False,
            "mode": "live",
            "message": "Live Kubernetes integration is not configured; refusing to claim workload isolation."
        }

    graph_updated = db_engine.quarantine_node(workload_id)
    node_name = db_engine.node_store.get(workload_id, {}).get("name", workload_id)
    simulation_mode = _simulation_mode()
    
    simulated_k8s_action = {
        "action": "K8s_NetworkPolicy_Apply",
        "workload_id": workload_id,
        "workload_name": node_name,
        "applied_policy": {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": f"quarantine-{node_name}", "namespace": "payments-prod"},
            "spec": {
                "podSelector": {"matchLabels": {"app": node_name}},
                "policyTypes": ["Ingress", "Egress"]
            }
        },
        "status": "SIMULATED" if simulation_mode and graph_updated else ("APPLIED_SUCCESSFULLY" if graph_updated else "FAILED")
    }
    
    return {
        "success": graph_updated,
        "performed": not simulation_mode and graph_updated,
        "mode": "simulation" if simulation_mode else "live",
        "message": (
            f"Simulation only: workload '{node_name}' was marked quarantined in the graph; "
            "no Kubernetes API call was made."
            if simulation_mode else
            f"Workload '{node_name}' isolated from cluster network."
        ),
        "k8s_audit": simulated_k8s_action
    }

@mcp.tool()
def traceforge_revoke_iam_privilege(role_id: str, policy_id: str) -> Dict[str, Any]:
    """
    Autonomous remediation action: Severs the relationship between an IAM Role and an overprivileged policy.
    Attaches an explicit inline Deny boundary to neutralize wildcard cloud grants.
    """
    logger.info(f"[MCP Tool: revoke_iam_privilege] Severing {role_id} -> {policy_id}")
    role = db_engine.node_store.get(role_id)
    policy = db_engine.node_store.get(policy_id)
    if not role or role.get("label") != "IAMRole" or not policy or policy.get("label") != "Policy":
        return {"success": False, "performed": False, "message": "Role and policy must be valid graph entities."}
    if not _simulation_mode():
        return {
            "success": False,
            "performed": False,
            "mode": "live",
            "message": "Live AWS IAM integration is not configured; refusing to claim privilege revocation."
        }
    graph_updated = db_engine.sever_relationship(role_id, policy_id, "HAS_POLICY")
    role_name = db_engine.node_store.get(role_id, {}).get("name", role_id)
    policy_name = db_engine.node_store.get(policy_id, {}).get("name", policy_id)
    
    if not graph_updated:
        return {
            "success": False,
            "message": f"Edge {role_id} -[HAS_POLICY]-> {policy_id} not found or already severed."
        }

    return {
        "success": True,
        "performed": False,
        "mode": "simulation",
        "severed_edge": f"{role_name} -[HAS_POLICY]-> {policy_name}",
        "message": f"Simulation only: graph edge detached for '{policy_name}' from '{role_name}'. AWS IAM was not changed."
    }

_pr_seq = 142

def _simulation_mode() -> bool:
    return os.getenv("TRACEFORGE_ACTION_MODE", "simulation").lower() == "simulation"

@mcp.tool()
def traceforge_create_remediation_pr(
    title: str,
    description: str,
    affected_role_name: str,
    terraform_patch_hcl: str
) -> Dict[str, Any]:
    """
    Autonomous remediation action: Dispatches a Pull Request to the infrastructure repository
    containing the least-privilege Terraform HCL code diff to permanently fix the security flaw.
    """
    global _pr_seq
    if not _simulation_mode():
        return {
            "success": False,
            "performed": False,
            "status": "NOT_CONFIGURED",
            "message": "Live GitHub integration is not configured; refusing to claim a Pull Request was created."
        }
    _pr_seq += 1
    pr_number = _pr_seq
    pr_url = f"https://github.com/fintech-org/infrastructure-live/pull/{pr_number}"
    logger.info(f"[MCP Tool: create_remediation_pr] Generating PR #{pr_number}: {title}")
    
    return {
        "pull_request_number": pr_number,
        "pull_request_url": pr_url,
        "title": title,
        "description": description,
        "affected_role": affected_role_name,
        "status": "SIMULATED",
        "performed": False,
        "mode": "simulation",
        "terraform_diff": terraform_patch_hcl,
        "message": f"Simulation only: generated PR payload #{pr_number}; no GitHub Pull Request was created."
    }

# ----- containment + memory tools (used by the LLM investigator over MCP) -----
@mcp.tool()
def traceforge_sever_edge(source_id: str, target_id: str, rel_type: str) -> Dict[str, Any]:
    """Containment: remove one allow-listed relationship from the live graph. Callers must gate authorisation."""
    from traceforge.agent.llm_agent import SEVERABLE, _REL_TYPE
    if not _REL_TYPE.match(rel_type) or rel_type not in SEVERABLE:
        return {"severed": False, "reason": f"Relationship type '{rel_type}' may not be severed."}
    ok = db_engine.sever_relationship(source_id, target_id, rel_type)
    return {"severed": bool(ok), "edge": f"{source_id}-[:{rel_type}]->{target_id}"}

@mcp.tool()
def traceforge_verify_reachability(workload_id: str) -> Dict[str, Any]:
    """Re-check whether any crown-jewel path remains from a workload."""
    paths = db_engine.find_shortest_attack_paths(workload_id)
    return {"crown_jewel_paths_remaining": len(paths), "paths": paths[:3]}

@mcp.tool()
def traceforge_recall_incidents(workload_id: str) -> Dict[str, Any]:
    """Past incidents on this workload from the FalkorDB memory graph."""
    from traceforge.agent.llm_agent import GraphMemory
    return {"workload_id": workload_id, "prior_incidents": GraphMemory(db_engine).recall(workload_id)}

@mcp.tool()
def traceforge_store_incident(alert_id: str, workload_id: str, cut: str, summary: str) -> Dict[str, Any]:
    """Persist an incident to the FalkorDB memory graph."""
    from traceforge.agent.llm_agent import GraphMemory
    return {"stored": GraphMemory(db_engine).store(alert_id, workload_id, cut, summary)["id"]}

if __name__ == "__main__":
    # Ensure seed data exists
    if len(db_engine.node_store) == 0:
        seed_enterprise_environment()
    mcp.run()
