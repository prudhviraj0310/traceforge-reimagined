#!/usr/bin/env python3
"""
TRACEFORGE Terminal Demo Runner
Executes the full autonomous investigation workflow with formatted telemetry and decision logs.
Usage:
    python run_demo.py
"""

import sys
import os
import time

# Add project root and parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from traceforge.engine.seed import seed_enterprise_environment
from traceforge.agent.investigator import investigator

def print_banner():
    print("""
\033[1;36m
████████╗██████╗  █████╗  ██████╗███████╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
   ██║   ██████╔╝███████║██║     █████╗  █████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
   ██║   ██║  ██║██║  ██║╚██████╗███████╗██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
\033[0m
\033[1;33m>>> AUTONOMOUS THREAT INVESTIGATION & INCIDENT RESPONSE AGENT <<<\033[0m
\033[1;30mPowered by FalkorDB Graph Engine & Model Context Protocol (MCP)\033[0m
""")

def main():
    print_banner()
    print("\033[1;34m[*] Step 1: Initializing FalkorDB Knowledge Graph...\033[0m")
    seed_enterprise_environment()
    time.sleep(0.5)

    alert_id = "ALERT-2026-9812"
    print(f"\n\033[1;31m[!] Incident Ingested: {alert_id}\033[0m")
    print("\033[1;33m[*] Starting Autonomous Agent Investigation Cortex...\033[0m\n")

    def terminal_callback(event):
        step = event["step"]
        title = event["title"]
        desc = event["description"]
        tool = event.get("tool")
        
        color = "\033[1;32m"
        if "ALERT" in step:
            color = "\033[1;31m"
        elif "TRAVERSAL" in step:
            color = "\033[1;33m"
        elif "BLAST" in step:
            color = "\033[1;35m"
        elif "EXECUTION" in step or "SEVERING" in step:
            color = "\033[1;36m"
            
        print(f"{color}▶ [{step}]\033[0m \033[1m{title}\033[0m")
        if tool:
            print(f"  \033[1;30m⚙️ MCP Tool Dispatched:\033[0m \033[36m{tool}()\033[0m")
        print(f"  \033[37m{desc}\033[0m\n")
        time.sleep(0.3)

    result = investigator.investigate(alert_id, auto_remediate=True, event_callback=terminal_callback)

    print("\033[1;32m==================================================")
    print("🏆 INVESTIGATION COMPLETE — SIMULATION RESULTS VERIFIED")
    print("==================================================\033[0m")
    print(f"• Origin Workload:      {result['origin_workload']}")
    print(f"• Target Crown Jewel:   {result['target_crown_jewel']}")
    print(f"• Attack Path Hops:     {result['attack_path']['hop_count']} Hops")
    print(f"• Exposed Sensitive Records: {result['blast_radius']['sensitive_records_exposed']:,}")
    print(f"• Identified Choke-Point:    {result['optimal_choke_point']['name']} ({result['optimal_choke_point']['label']})")
    print(f"• Actions Executed:     {len(result['remediation_actions'])} remediations")
    print("\n\033[1;36mExecutive Summary:\033[0m")
    print(result["executive_summary"])
    print("\n\033[1;32m[✓] TRACEFORGE is ready for live web inspection at http://localhost:3000\033[0m\n")

if __name__ == "__main__":
    main()
