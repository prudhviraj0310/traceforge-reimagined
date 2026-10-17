"""
Real MCP transport for the LLM investigator.

Spawns `python -m traceforge.mcp_server.server` as a subprocess and talks to it
over stdio with the official MCP client (`mcp.ClientSession`). Graph tools the
model picks are discovered with `list_tools` and executed with `call_tool`, so
every graph call crosses the Model Context Protocol boundary.

The investigator is synchronous, so the async session runs on its own event
loop in a daemon thread. One bridge is shared per process.
"""

import asyncio
import json
import os
import sys
import threading
from typing import Any, Callable, Dict, List, Optional

# agent tool name -> MCP server tool name
TOOL_MAP = {
    "list_alerts": "traceforge_list_alerts",
    "query_graph": "traceforge_query_graph",
    "find_attack_paths": "traceforge_find_attack_paths",
    "calculate_blast_radius": "traceforge_calculate_blast_radius",
    "betweenness_centrality": "traceforge_calculate_betweenness_centrality",
    "identify_choke_point": "traceforge_identify_optimal_choke_point",
}


def _decode(result: Any) -> Any:
    if getattr(result, "isError", False):
        text = " ".join(getattr(c, "text", "") for c in result.content)
        raise RuntimeError(f"MCP tool error: {text}")
    sc = getattr(result, "structuredContent", None)
    if sc is not None:
        return sc["result"] if isinstance(sc, dict) and set(sc) == {"result"} else sc
    texts = [getattr(c, "text", "") for c in result.content]
    if len(texts) == 1:
        try:
            return json.loads(texts[0])
        except ValueError:
            return texts[0]
    out = []
    for t in texts:
        try:
            out.append(json.loads(t))
        except ValueError:
            out.append(t)
    return out


class McpBridge:
    def __init__(self, command: Optional[str] = None, args: Optional[List[str]] = None,
                 env: Optional[Dict[str, str]] = None, timeout: float = 60.0) -> None:
        self.command = command or sys.executable
        self.args = args or ["-m", "traceforge.mcp_server.server"]
        self.env = {**os.environ, **(env or {})}
        self.timeout = timeout
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self._thread.start()
        self._session: Any = None
        self._closer: Optional[asyncio.Event] = None
        self.server_tools: Dict[str, Any] = {}
        self.calls: List[str] = []  # every MCP tool name actually invoked
        self._run(self._open(), timeout)

    def _run(self, coro: Any, timeout: Optional[float] = None) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout or self.timeout)

    async def _open(self) -> None:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        ready: asyncio.Future = self.loop.create_future()
        self._closer = asyncio.Event()

        async def hold() -> None:
            try:
                params = StdioServerParameters(command=self.command, args=self.args, env=self.env)
                async with stdio_client(params) as (r, w):
                    async with ClientSession(r, w) as session:
                        await session.initialize()
                        listed = await session.list_tools()
                        self.server_tools = {t.name: t for t in listed.tools}
                        self._session = session
                        ready.set_result(True)
                        await self._closer.wait()
            except BaseException as exc:  # surface startup failures to the caller
                if not ready.done():
                    ready.set_exception(exc)

        self._task = self.loop.create_task(hold())
        await ready

    def call(self, name: str, args: Dict[str, Any]) -> Any:
        if name not in self.server_tools:
            raise KeyError(f"MCP server does not expose '{name}'")
        self.calls.append(name)
        return _decode(self._run(self._session.call_tool(name, args)))

    def tools(self) -> Dict[str, Callable[..., Any]]:
        """Agent-name callables for every mapped tool the server actually advertises."""
        out: Dict[str, Callable[..., Any]] = {}
        for agent_name, server_name in TOOL_MAP.items():
            if server_name in self.server_tools:
                out[agent_name] = (lambda sn: (lambda **kw: self.call(sn, kw)))(server_name)
        return out

    def close(self) -> None:
        if self._closer is not None:
            self.loop.call_soon_threadsafe(self._closer.set)
            try:
                asyncio.run_coroutine_threadsafe(asyncio.wait_for(asyncio.shield(self._task), 10), self.loop).result(15)
            except Exception:
                pass
        self.loop.call_soon_threadsafe(self.loop.stop)


_shared: Optional[McpBridge] = None
_lock = threading.Lock()


def shared_bridge() -> McpBridge:
    global _shared
    with _lock:
        if _shared is None:
            _shared = McpBridge()
        return _shared
