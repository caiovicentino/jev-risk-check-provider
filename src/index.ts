import { JevClient } from "./jev.js";
import { GatewayJevClient } from "./backends/gateway.js";
import { Provider } from "./provider.js";
import { generateKeyPair } from "./jws.js";
import { startServer } from "./server.js";

const typesafeKey = process.env.TYPESAFE_API_KEY;
const gatewayKey = process.env.AI_GATEWAY_API_KEY;
const host = process.env.PROVIDER_HOST ?? "localhost:8787";
const port = Number(process.env.PORT ?? 8787);
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

const provider = new Provider({ host, keyPair: generateKeyPair("jev-attest-v1"), jev });

startServer({ provider, port });
console.log(`jev-risk-check-provider listening on :${port} (host=${host}, jev=${jev ? "enabled" : "disabled"})`);
