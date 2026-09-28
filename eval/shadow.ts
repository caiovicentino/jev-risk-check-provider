import { appendEntries, buildProvider, runCases, LIVE_LOG } from "./harness.js";
import { JevClient } from "../src/jev.js";
import { GatewayJevClient } from "../src/backends/gateway.js";
import { CASES } from "./cases.js";

const typesafeKey = process.env.TYPESAFE_API_KEY;
const gatewayKey = process.env.AI_GATEWAY_API_KEY;
const baseUrl = process.env.TYPESAFE_BASE_URL;

if (!typesafeKey && !gatewayKey) {
  console.error("shadow requires TYPESAFE_API_KEY or AI_GATEWAY_API_KEY (set TYPESAFE_BASE_URL to override api.typesafe.ai)");
  process.exit(1);
}

async function main(): Promise<void> {
  const backend = typesafeKey
    ? new JevClient({ apiKey: typesafeKey, baseUrl })
    : new GatewayJevClient();
  console.log(`backend: ${typesafeKey ? "typesafe-direct" : "vercel-ai-gateway"}`);
  const provider = buildProvider(backend);
  const onlyIdx = process.argv.indexOf("--only");
  const onlyPrefix = onlyIdx !== -1 ? (process.argv[onlyIdx + 1] ?? "") : "";
  const selected = onlyPrefix ? CASES.filter((c) => c.id.startsWith(onlyPrefix)) : CASES;
  const screeningIdx = process.argv.indexOf("--screening");
  const screeningMode = screeningIdx !== -1 ? (process.argv[screeningIdx + 1] ?? "") : "";
  const enriched = screeningMode
    ? selected.map((c) => ({
        ...c,
        request: { ...c.request, screening: { sanctions: c.expected === "safe" ? ("clean" as const) : ("flagged" as const) } },
      }))
    : selected;
  console.log(`cases: ${enriched.length}${onlyPrefix ? ` (only ${onlyPrefix}*)` : ""}${screeningMode ? ` | screening-integrated simulation (${screeningMode})` : ""}`);
  const entries = await runCases(provider, enriched);
  appendEntries(LIVE_LOG, entries, "live");

  const latencies = entries.map((e) => e.latency_ms).sort((a, b) => a - b);
  const p = (q: number): number => latencies[Math.min(latencies.length - 1, Math.floor(q * latencies.length))] ?? 0;
  const totalInput = entries.reduce((acc, e) => acc + (e.input_tokens ?? 0), 0);
  const cost = entries.reduce((acc, e) => acc + (e.input_tokens ?? 0) * 0.042 / 1_000_000, 0);

  console.log("== JEV live shadow run ==");
  console.log(`cases: ${entries.length} | unchecked: ${entries.filter((e) => !e.checked).length}`);
  console.log(`latency: p50=${p(0.5)}ms p95=${p(0.95)}ms`);
  console.log(`input tokens: ${totalInput} | est. cost: $${cost.toFixed(6)} ($0.042/MTok)`);
  console.log(`evidence appended to ${LIVE_LOG}`);
  console.log(`run 'npm run board report' to compute the switch-over gate`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
