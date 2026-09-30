import { JevClient } from "./jev.js";
import { GatewayJevClient } from "./backends/gateway.js";
import { Provider } from "./provider.js";
import { generateKeyPair } from "./jws.js";
import { startServer } from "./server.js";
import { createOnchainLookup } from "./onchain.js";
import { loadFeedsFromDisk } from "./feeds-node.js";
import { createSimulator } from "./simulation.js";
import { createContractIntel } from "./contract-intel.js";

const typesafeKey = process.env.TYPESAFE_API_KEY;
const gatewayKey = process.env.AI_GATEWAY_API_KEY;
const host = process.env.PROVIDER_HOST ?? "localhost:8799";
const port = Number(process.env.PORT ?? 8799);
const baseUrl = process.env.TYPESAFE_BASE_URL;

const jev = typesafeKey
  ? new JevClient({ apiKey: typesafeKey, baseUrl })
  : gatewayKey
    ? new GatewayJevClient()
    : null;

if (!jev) {
  console.error("No TYPESAFE_API_KEY or AI_GATEWAY_API_KEY set. The provider will run in fail-closed mode (checked:false).");
} else {
  console.log(`JEV backend: ${typesafeKey ? "typesafe-direct" : "vercel-ai-gateway"}`);
}

// On-chain facts are on by default; ONCHAIN=off disables them (e.g. offline runs).
const onchain = process.env.ONCHAIN === "off" ? null : createOnchainLookup({ timeoutMs: Number(process.env.ONCHAIN_TIMEOUT_MS ?? 1500) });

const feeds = loadFeedsFromDisk();
const contractIntel = process.env.CONTRACT_INTEL === "off" ? null : createContractIntel();
const simulator = process.env.SIMULATION === "off" ? null : createSimulator({ contractIntel });
const provider = new Provider({ host, keyPair: generateKeyPair("jev-attest-v1"), jev, onchain, feeds: () => feeds, simulator, contractIntel });

startServer({ provider, port });
console.log(`x402check provider listening on :${port} (host=${host}, jev=${jev ? "enabled" : "disabled"}, onchain=${onchain ? "on" : "off"})`);
