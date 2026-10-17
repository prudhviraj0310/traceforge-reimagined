"""Real MCP stdio transport: spawns the TRACEFORGE MCP server and drives it with mcp.ClientSession.
Works with FalkorDB offline (the server uses its embedded graph) or online."""
import pytest

from traceforge.agent.mcp_bridge import McpBridge, TOOL_MAP
from traceforge.agent.llm_agent import LLMInvestigator


@pytest.fixture(scope="module")
def bridge():
    b = McpBridge()
    yield b
    b.close()


def test_server_advertises_every_agent_tool(bridge):
    need = set(TOOL_MAP.values()) | {"traceforge_sever_edge", "traceforge_verify_reachability",
                                     "traceforge_recall_incidents", "traceforge_store_incident"}
    assert need <= set(bridge.server_tools)


def test_attack_path_over_mcp(bridge):
    res = bridge.tools()["find_attack_paths"](alert_id="ALERT-2026-9812")
    ids = res["paths"][0]["node_ids"]
    assert ids[0] == "wl-payment-ingress" and ids[-1] == "ds-customer-vault"


def test_disallowed_rel_type_refused_over_mcp(bridge):
    r = bridge.call("traceforge_sever_edge", {"source_id": "a", "target_id": "b", "rel_type": "TRIGGERED_BY"})
    assert r["severed"] is False


def test_cut_then_reverify_over_mcp(bridge):
    r = bridge.call("traceforge_sever_edge", {"source_id": "pol-legacy-payments", "target_id": "sec-master-kms",
                                              "rel_type": "PERMITS_ACCESS"})
    assert r["severed"] is True
    v = bridge.call("traceforge_verify_reachability", {"workload_id": "wl-payment-ingress"})
    assert v["crown_jewel_paths_remaining"] == 0


def test_agent_defaults_to_mcp(monkeypatch, bridge):
    import traceforge.agent.mcp_bridge as mb
    monkeypatch.setattr(mb, "_shared", bridge)
    monkeypatch.delenv("TRACEFORGE_TOOL_TRANSPORT", raising=False)
    a = LLMInvestigator(client=object())
    assert a.transport == "mcp-stdio" and a._mcp is bridge


if __name__ == "__main__":
    print("Running TRACEFORGE MCP Transport Tests against FalkorDB Cloud...")
    b = McpBridge()
    try:
        test_server_advertises_every_agent_tool(b)
        print("  ✓ test_server_advertises_every_agent_tool passed")
        test_attack_path_over_mcp(b)
        print("  ✓ test_attack_path_over_mcp passed")
        test_disallowed_rel_type_refused_over_mcp(b)
        print("  ✓ test_disallowed_rel_type_refused_over_mcp passed")
        test_cut_then_reverify_over_mcp(b)
        print("  ✓ test_cut_then_reverify_over_mcp passed")
        print("\nAll MCP transport tests passed successfully!")
    finally:
        b.close()

