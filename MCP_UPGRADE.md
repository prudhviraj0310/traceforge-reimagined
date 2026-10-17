# v4: every agent tool call now goes over real MCP

## What changed
- `agent/mcp_bridge.py` (new): starts `python -m traceforge.mcp_server.server` and talks to it over stdio with the official `mcp.ClientSession` (`initialize` -> `list_tools` -> `call_tool`).
- `agent/llm_agent.py`: uses the MCP bridge by default (`tool_transport: "mcp-stdio"` in the result). `TRACEFORGE_TOOL_TRANSPORT=inprocess` opts out; if the MCP server can't start it logs a warning and falls back.
- `mcp_server/server.py`: 4 new MCP tools - `traceforge_sever_edge` (allow-listed rel types only), `traceforge_verify_reachability`, `traceforge_recall_incidents`, `traceforge_store_incident`. Admin gating stays in the agent: a non-admin run never sends the sever call.
- `tests/test_mcp_transport.py` (new): spawns the real server, checks all tools are advertised, attack path, refused rel type, cut + re-verify, agent defaults to MCP.

## Verified live (real FalkorDB + real model, google/gemini-3.8-flash)
ALERT-2026-9812, admin: status contained in 27 s, 0 paths remaining.
Model-chosen order: list_alerts -> recall_incidents -> find_attack_paths -> calculate_blast_radius -> identify_choke_point -> sever_edge -> verify_reachability -> store_incident.
All 8 calls crossed MCP (traceforge_* names logged by the server). Cut: role-payment-app -[:HAS_POLICY]-> pol-legacy-payments.

Tests: 22 offline pass (17 agent + 5 MCP transport); live tests skip unless FalkorDB is up.

## Notes
- The MCP server process seeds the graph when it starts (once per backend process - the bridge is shared). Start it after the backend seeds, which is what happens by default.
- With FalkorDB offline, the MCP server keeps its own in-memory graph, separate from the backend's. Run with FalkorDB up for the demo.
- Write-up: you can now say "tool selection through MCP" honestly.
