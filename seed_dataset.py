#!/usr/bin/env python3
"""
TRACEFORGE Quick Seeder CLI
Seeds the FalkorDB graph database with the multi-hop enterprise breach dataset.
Usage:
    python seed_dataset.py
"""

import sys
import os

# Add project root and parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from traceforge.engine.seed import seed_enterprise_environment
from traceforge.engine.db import db_engine

def main():
    print("==================================================")
    print("🛡️  TRACEFORGE: FalkorDB Graph Environment Seeder")
    print("==================================================")
    print(f"Target DB: {db_engine.host}:{db_engine.port} [{db_engine.graph_name}]")
    print(f"Connection Status: {'🟢 LIVE FALKORDB' if db_engine.is_connected else '🟡 EMBEDDED GRAPH ENGINE'}")
    print("Seeding enterprise cloud infrastructure and attack vectors...")
    
    res = seed_enterprise_environment()
    
    print("\n✅ SEEDING COMPLETE!")
    print(f"• Total Nodes Created: {res['nodes_seeded']}")
    print(f"• Total Relationships: {res['edges_seeded']}")
    print("\nPrimary Investigation Targets:")
    print("1. ALERT-2026-9812: GuardDuty Critical C2 Beaconing on 'payment-ingress-api'")
    print("2. ALERT-2026-9815: Falco High Privilege Escalation on 'auth-identity-svc'")
    print("3. ALERT-2026-9820: CloudTrail Suspicious S3 Enumeration on 'analytics-worker-batch'")
    print("==================================================")

if __name__ == "__main__":
    main()
