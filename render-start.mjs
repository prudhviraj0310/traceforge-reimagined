/**
 * TRACEFORGE Production Server & Keep-Alive Ping Worker for Render
 *
 * Keeps the Render Web Service and FalkorDB Cloud TCP connection permanently warm
 * by sending an active keep-alive heartbeat every 40 seconds (safely under the 50-second idle shutdown).
 */

import { spawn } from "node:child_process";
import http from "node:http";
import https from "node:https";

const PORT = process.env.PORT || "3000";
const PING_INTERVAL_MS = 40_000; // 40 seconds keepalive
const EXTERNAL_URL = process.env.RENDER_EXTERNAL_URL || process.env.EXTERNAL_URL;

console.log("==================================================================");
console.log("🚀 TRACEFORGE: Starting Production Web Service on Render");
console.log(`📡 Port: ${PORT}`);
console.log(`⏱️ Keep-Alive Ping Interval: Every 40 seconds (Prevents 50s idle shutdown)`);
if (EXTERNAL_URL) {
  console.log(`🌐 Public URL: ${EXTERNAL_URL}`);
}
console.log("==================================================================");

// 1. Launch the Nitro production server
const serverProcess = spawn("node", [".output/server/index.mjs"], {
  env: {
    ...process.env,
    PORT: PORT,
    NITRO_PORT: PORT,
    HOST: "0.0.0.0",
  },
  stdio: "inherit",
});

serverProcess.on("error", (err) => {
  console.error("❌ Failed to start Nitro server:", err);
  process.exit(1);
});

serverProcess.on("exit", (code, signal) => {
  console.warn(`⚠️ Nitro server exited with code ${code} (${signal})`);
  process.exit(code ?? 1);
});

// Helper for HTTP GET
function httpGet(urlStr) {
  return new Promise((resolve, reject) => {
    try {
      const parsed = new URL(urlStr);
      const client = parsed.protocol === "https:" ? https : http;
      const req = client.get(
        urlStr,
        {
          headers: {
            "User-Agent": "TraceForge-KeepAlive/1.0",
            "Cache-Control": "no-cache",
          },
          timeout: 8000,
        },
        (res) => {
          res.resume();
          resolve(res.statusCode);
        }
      );
      req.on("error", reject);
      req.on("timeout", () => {
        req.destroy();
        reject(new Error("Ping timeout after 8s"));
      });
    } catch (e) {
      reject(e);
    }
  });
}

// 2. Keep-Alive Ping Function (Every 40 seconds)
async function sendKeepAlivePing() {
  const uptime = Math.floor(process.uptime());
  const now = new Date().toLocaleTimeString();

  // A. Local self-ping
  try {
    const localStatus = await httpGet(`http://127.0.0.1:${PORT}/api/ping`);
    console.log(`[${now}] 🟢 [Keep-Alive 40s] Local ping: HTTP ${localStatus} (Uptime: ${uptime}s)`);
  } catch (err) {
    console.warn(`[${now}] 🟡 [Keep-Alive 40s] Local ping notice: ${err.message}`);
  }

  // B. External public URL ping (resets Render's external router idle timer)
  if (EXTERNAL_URL) {
    try {
      const targetUrl = EXTERNAL_URL.startsWith("http")
        ? `${EXTERNAL_URL}/api/ping`
        : `https://${EXTERNAL_URL}/api/ping`;
      const extStatus = await httpGet(targetUrl);
      console.log(`[${now}] 🌐 [Keep-Alive 40s] Render public ping: HTTP ${extStatus}`);
    } catch (err) {
      console.warn(`[${now}] 🟡 [Keep-Alive 40s] External ping notice: ${err.message}`);
    }
  }

  // C. FalkorDB Cloud TCP ping to prevent connection timeout
  try {
    const host = process.env.FALKORDB_HOST || "r-6jissuruar.instance-4i2tmzunw.hc-7up0crkyn.ap-south-1.aws.f2e0a955bb84.cloud";
    const port = parseInt(process.env.FALKORDB_PORT || "53633", 10);
    const username = process.env.FALKORDB_USERNAME || "falkordb";
    const password = process.env.FALKORDB_PASSWORD || "prudhvi";
    const graphName = process.env.FALKORDB_GRAPH || "traceforge_threat_intel";

    const { FalkorDB } = await import("falkordb");
    const db = await FalkorDB.connect({
      username,
      password,
      socket: { host, port, timeout: 5000 },
    });
    const graph = db.selectGraph(graphName);
    await graph.query("RETURN 1");
    await db.close();
    console.log(`[${now}] ⚡ [Keep-Alive 40s] FalkorDB Cloud: Socket active & verified`);
  } catch (err) {
    console.warn(`[${now}] 🟡 [Keep-Alive 40s] FalkorDB keepalive: ${err.message}`);
  }
}

// Allow server 3 seconds to bind to port, then begin 40s ping cycle
setTimeout(() => {
  sendKeepAlivePing();
  setInterval(sendKeepAlivePing, PING_INTERVAL_MS);
}, 3000);

// Graceful shutdown handling
process.on("SIGINT", () => {
  serverProcess.kill("SIGINT");
  process.exit(0);
});

process.on("SIGTERM", () => {
  serverProcess.kill("SIGTERM");
  process.exit(0);
});
