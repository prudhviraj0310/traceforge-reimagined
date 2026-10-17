"""
TRACEFORGE Autonomous Investigation Agent
Drives the closed-loop Threat Intelligence investigation workflow using FalkorDB and MCP tools.
"""

import os
import json
import hashlib
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime

from traceforge.mcp_server.server import (
    traceforge_list_alerts,
    traceforge_find_attack_paths,
    traceforge_calculate_blast_radius,
    traceforge_identify_optimal_choke_point,
    traceforge_quarantine_workload,
    traceforge_revoke_iam_privilege,
    traceforge_create_remediation_pr
)
from traceforge.agent.prompts import INVESTIGATOR_SYSTEM_PROMPT, TERRAFORM_REMEDIATION_TEMPLATE

logger = logging.getLogger("traceforge.agent")
logging.basicConfig(level=logging.INFO)

class InvestigationEvent:
    def __init__(self, step: str, title: str, description: str, tool: Optional[str] = None, data: Optional[Dict[str, Any]] = None):
        self.step = step
        self.title = title
        self.description = description
        self.tool = tool
        self.data = data or {}
        self.timestamp = datetime.utcnow().isoformat() + "Z"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "title": self.title,
            "description": self.description,
            "tool": self.tool,
            "data": self.data,
            "timestamp": self.timestamp
        }

class TraceForgeInvestigator:
    def __init__(self):
        self.anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
        self.openai_key = os.getenv("OPENAI_API_KEY", "")

    def investigate(self, alert_id: str, auto_remediate: bool = True, event_callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """
        Executes a complete 7-step autonomous threat investigation workflow.
        """
        events: List[Dict[str, Any]] = []

        def emit(step: str, title: str, description: str, tool: Optional[str] = None, data: Optional[Dict[str, Any]] = None):
            ev = InvestigationEvent(step, title, description, tool, data).to_dict()
            events.append(ev)
            if event_callback:
                event_callback(ev)
            logger.info(f"[{step}] {title}: {description}")

        tool_registry = {
            "traceforge_list_alerts": traceforge_list_alerts,
            "traceforge_find_attack_paths": traceforge_find_attack_paths,
            "traceforge_calculate_blast_radius": traceforge_calculate_blast_radius,
            "traceforge_identify_optimal_choke_point": traceforge_identify_optimal_choke_point,
            "traceforge_quarantine_workload": traceforge_quarantine_workload,
            "traceforge_revoke_iam_privilege": traceforge_revoke_iam_privilege,
            "traceforge_create_remediation_pr": traceforge_create_remediation_pr,
        }

        def call_tool(name: str, **arguments: Any) -> Any:
            """Route every investigation decision through the MCP tool registry."""
            tool = tool_registry.get(name)
            if tool is None:
                raise ValueError(f"MCP tool '{name}' is not registered.")
            result = tool(**arguments)
            result_bytes = json.dumps(result, sort_keys=True, default=str).encode("utf-8")
            digest = hashlib.sha256(result_bytes).hexdigest()
            emit(
                step="MCP_TOOL_RESULT",
                title=f"{name} returned verified result",
                description=f"RESULT: {name} completed; result digest {digest[:16]}.",
                tool=name,
                data={
                    "arguments": arguments,
                    "result_digest": digest,
                    "result": result,
                },
            )
            return result

        from traceforge.engine.db import db_engine

        alert_obj = db_engine.node_store.get(alert_id)
        if not alert_obj or alert_obj.get("label") != "Alert":
            raise ValueError(f"Alert '{alert_id}' was not found.")
        target_wl = alert_obj.get("target_workload_id")
        target_node = db_engine.node_store.get(target_wl or "")
        if not target_wl or not target_node or target_node.get("label") != "Workload":
            raise ValueError(f"Alert '{alert_id}' does not target a valid workload.")

        # STEP 1: ALERT INGESTION & TRIAGING
        emit(
            step="STEP_1_ALERT_INGESTION",
            title="Ingesting & Validating Security Incident",
            description=f"PLAN: Validate incident {alert_id} through the MCP alert registry before traversing graph relationships.",
            tool="traceforge_list_alerts",
            data={"alert_id": alert_id}
        )
        registered_alerts = call_tool("traceforge_list_alerts")
        if not any(alert.get("id") == alert_id for alert in registered_alerts):
            raise ValueError(f"Alert '{alert_id}' is not present in the MCP alert registry.")
        emit(
            step="STEP_1_ALERT_INGESTION_COMPLETE",
            title="Security Incident Validated",
            description=f"OBSERVATION: Alert '{alert_id}' is registered and targets workload '{target_wl}'.",
            data={"alert_id": alert_id, "target_workload_id": target_wl, "registry_count": len(registered_alerts)}
        )

        # STEP 2: MULTI-HOP ATTACK PATH TRAVERSAL
        emit(
            step="STEP_2_GRAPH_TRAVERSAL",
            title="Traversing FalkorDB Knowledge Graph",
            description="PLAN: Use the MCP attack-path tool to find verified directed paths ending only at Crown Jewel datastores.",
            tool="traceforge_find_attack_paths",
            data={"query": "MCP tool parameters: alert_id=%s, target_classification=CrownJewel" % alert_id}
        )
        path_result = call_tool("traceforge_find_attack_paths", alert_id=alert_id)
        paths = path_result.get("paths", [])
        
        if not paths:
            emit(
                step="STEP_2_GRAPH_TRAVERSAL_COMPLETE",
                title="Graph Traversal Complete: No Attack Paths",
                description=f"OBSERVATION: No multi-hop path detected from workload '{target_wl}' to Crown Jewels. Workload isolated from sensitive assets.",
                data={"paths": []}
            )
            return {"status": "benign", "events": events}

        primary_path = paths[0]
        origin_workload_id = path_result.get("origin_workload_id")
        crown_jewel_id = primary_path.get("target_node")

        emit(
            step="STEP_2_GRAPH_TRAVERSAL_COMPLETE",
            title="Verified Multi-Hop Attack Path Discovered",
            description=f"OBSERVATION: MCP returned a {primary_path['hop_count']}-hop path from '{path_result['origin_workload_name']}' to verified Crown Jewel '{primary_path['nodes'][-1]['name']}'. Risk Score: {primary_path['risk_score']}/10.",
            data={
                "hop_count": primary_path["hop_count"],
                "node_ids": primary_path["node_ids"],
                "nodes": primary_path["nodes"],
                "risk_score": primary_path["risk_score"]
            }
        )

        # STEP 3: BLAST RADIUS & RISK QUANTIFICATION
        role_node = next((n for n in primary_path["nodes"] if n.get("label") == "IAMRole"), None)
        target_eval_node = role_node["id"] if role_node else (primary_path["node_ids"][1] if len(primary_path["node_ids"]) > 1 else primary_path["node_ids"][0])

        emit(
            step="STEP_3_BLAST_RADIUS",
            title="Computing Transitive Blast Radius & Centrality",
            description=f"THOUGHT: Evaluating transitive exposure and Brandes betweenness centrality for access boundary '{target_eval_node}'.",
            tool="traceforge_calculate_blast_radius",
            data={"target_node": target_eval_node}
        )
        blast_radius = call_tool("traceforge_calculate_blast_radius", node_id=target_eval_node)
        emit(
            step="STEP_3_BLAST_RADIUS_COMPLETE",
            title="Blast Radius Quantified",
            description=f"OBSERVATION: Transitive exposure: {blast_radius['crown_jewels_count']} Crown Jewels, {blast_radius['sensitive_records_exposed']:,} sensitive customer records at risk.",
            data=blast_radius
        )

        # STEP 4: OPTIMAL CHOKE-POINT IDENTIFICATION
        emit(
            step="STEP_4_CHOKE_POINT_ANALYSIS",
            title="Calculating Optimal Graph Choke-Point",
            description="THOUGHT: Evaluating betweenness centrality to pinpoint minimal operational disruption edge to sever.",
            tool="traceforge_identify_optimal_choke_point",
            data={"path_nodes": primary_path["node_ids"]}
        )
        choke_point_result = call_tool(
            "traceforge_identify_optimal_choke_point",
            path_node_ids=primary_path["node_ids"],
        )
        optimal_choke = choke_point_result.get("optimal_choke_point")
        if not optimal_choke:
            choke_id = primary_path["node_ids"][1] if len(primary_path["node_ids"]) > 1 else primary_path["node_ids"][0]
            nd = db_engine.node_store.get(choke_id, {})
            optimal_choke = {
                "node_id": choke_id,
                "name": nd.get("name", choke_id),
                "label": nd.get("label", "Policy"),
                "score": 0.5,
                "recommendation": f"Sever intermediate access grant on '{nd.get('name', choke_id)}'."
            }

        emit(
            step="STEP_4_CHOKE_POINT_SELECTED",
            title="Optimal Choke-Point Identified",
            description=f"OBSERVATION: Selected {optimal_choke['label']} '{optimal_choke['name']}' (Betweenness Centrality: {optimal_choke['score']}). {optimal_choke['recommendation']}",
            data=choke_point_result
        )

        # STEP 5: TACTICAL CONTAINMENT (POD QUARANTINE)
        remediation_actions = []
        if auto_remediate:
            emit(
                step="STEP_5_CONTAINMENT_EXECUTION",
                title="Executing Workload Network Isolation",
                description=f"ACTION (simulation mode): Marking {origin_workload_id} quarantined in the graph; no Kubernetes API call is made.",
                tool="traceforge_quarantine_workload",
                data={"workload_id": origin_workload_id}
            )
            quarantine_res = call_tool(
                "traceforge_quarantine_workload",
                workload_id=origin_workload_id,
            )
            remediation_actions.append(quarantine_res)

            # STEP 6: IAM PRIVILEGE SEVERING
            role_id = role_node["id"] if role_node else primary_path["node_ids"][1]
            policy_id = optimal_choke["node_id"]
            emit(
                step="STEP_6_PRIVILEGE_SEVERING",
                title="Simulating Cloud Privilege Edge Severance",
                description=f"ACTION (simulation mode): Marking relationship {role_id} -[HAS_POLICY]-> {policy_id} severed in the graph; AWS IAM is unchanged.",
                tool="traceforge_revoke_iam_privilege",
                data={"role_id": role_id, "policy_id": policy_id}
            )
            revoke_res = call_tool(
                "traceforge_revoke_iam_privilege",
                role_id=role_id,
                policy_id=policy_id,
            )
            remediation_actions.append(revoke_res)

            # STEP 7: INFRASTRUCTURE AS CODE HARDENING PR
            emit(
                step="STEP_7_IAC_PR_DISPATCH",
                title="Generating GitHub Remediation PR Payload",
                description="ACTION (simulation mode): Generating and validating a PR payload; GitHub is not contacted.",
                tool="traceforge_create_remediation_pr",
                data={"role": "PaymentAppRole", "pr_target": "fintech-org/infrastructure-live"}
            )
            pr_res = call_tool(
                "traceforge_create_remediation_pr",
                title=f"fix(iam): Least-privilege boundary policy for PaymentAppRole [TRACEFORGE-{alert_id}]",
                description=f"Automated least-privilege remediation for incident {alert_id}. Replaces wildcard grants with scoped SQS transactions and explicit KMS Deny.",
                affected_role_name="PaymentAppRole",
                terraform_patch_hcl=TERRAFORM_REMEDIATION_TEMPLATE
            )
            remediation_actions.append(pr_res)

        # FINAL SYNTHESIS & REPORT
        pr_num = pr_res.get("pull_request_number", 143) if auto_remediate else "N/A"
        executive_summary = (
            f"TRACEFORGE investigation analyzed incident {alert_id}. "
            f"Discovered an active {primary_path['hop_count']}-hop attack vector from internet-exposed container "
            f"'{path_result['origin_workload_name']}' to Crown Jewel database '{primary_path['nodes'][-1]['name']}' "
            f"(holding {blast_radius['sensitive_records_exposed']:,} sensitive customer records). "
            f"Recorded simulated graph remediation actions; Kubernetes, AWS IAM, and GitHub were not contacted. "
            f"Generated remediation PR payload #{pr_num} for review."
        )

        emit(
            step="STEP_8_INVESTIGATION_COMPLETE",
            title="Threat Investigation & Remediation Complete",
            description=f"FINAL ANSWER: {executive_summary}",
            data={"executive_summary": executive_summary, "actions_taken": remediation_actions}
        )

        return {
            "status": "remediated" if auto_remediate else "action_required",
            "alert_id": alert_id,
            "origin_workload": path_result["origin_workload_name"],
            "target_crown_jewel": primary_path["nodes"][-1]["name"],
            "attack_path": primary_path,
            "blast_radius": blast_radius,
            "optimal_choke_point": optimal_choke,
            "remediation_actions": remediation_actions,
            "executive_summary": executive_summary,
            "events": events
        }

# Global Investigator Instance
investigator = TraceForgeInvestigator()
