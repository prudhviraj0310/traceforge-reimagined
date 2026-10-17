import os
import sys
from dotenv import load_dotenv

load_dotenv()

host = os.getenv("FALKORDB_HOST", "")
port = int(os.getenv("FALKORDB_PORT", "6379"))
username = os.getenv("FALKORDB_USERNAME", "default")
password = os.getenv("FALKORDB_PASSWORD", "")
graph_name = os.getenv("FALKORDB_GRAPH", "traceforge_threat_intel")

print(f"Connecting to FalkorDB Cloud at {host}:{port} (User: {username}, Graph: {graph_name})...")

if not host or not password:
    print("ERROR: FALKORDB_HOST or FALKORDB_PASSWORD not set in .env")
    sys.exit(1)

try:
    import falkordb
    db = falkordb.FalkorDB(
        host=host,
        port=port,
        username=username if username else None,
        password=password if password else None
    )
    graph = db.select_graph(graph_name)
    
    # 1. Test query
    res = graph.query("RETURN 'FALKORDB_CONNECTED' AS status, 2026 AS year")
    print("\n✅ Handshake Succeeded!")
    for row in res.result_set:
        print(f"   Status: {row[0]}, Year: {row[1]}")
        
    # 2. Check existing nodes
    cnt = graph.query("MATCH (n) RETURN count(n) AS node_count")
    node_count = cnt.result_set[0][0] if cnt.result_set else 0
    print(f"   Nodes in graph '{graph_name}': {node_count}")

except Exception as e:
    print(f"\n❌ Connection Error: {e}")
    sys.exit(2)
