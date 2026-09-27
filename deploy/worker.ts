import { generateKeyPair, type KeyPair } from "../src/jws.js";
import { Provider } from "../src/provider.js";
import { GatewayJevClient } from "../src/backends/gateway.js";
import { JevClient } from "../src/jev.js";
import { createHandler, type HandlerDeps } from "../src/handler.js";

export type WorkerEnv = {
  PROVIDER_HOST?: string;
  TYPESAFE_API_KEY?: string;
  AI_GATEWAY_API_KEY?: string;
  JEV_ATTEST_PRIVATE_KEY?: string;
};

let cached: { deps: HandlerDeps; envKey: string } | null = null;

function loadKeyPair(env: WorkerEnv): KeyPair {
  if (env.JEV_ATTEST_PRIVATE_KEY) {
    const pair = generateKeyPair("jev-attest-v1");
    return { privatePem: env.JEV_ATTEST_PRIVATE_KEY, publicJwk: pair.publicJwk };
  }
  return generateKeyPair("jev-attest-v1");
}

function buildDeps(env: WorkerEnv): HandlerDeps {
  const host = env.PROVIDER_HOST ?? "risk-check.paysol.dev";
  const jev = env.TYPESAFE_API_KEY
    ? new JevClient({ apiKey: env.TYPESAFE_API_KEY })
    : env.AI_GATEWAY_API_KEY
      ? new GatewayJevClient()
      : null;
  return { provider: new Provider({ host, keyPair: loadKeyPair(env), jev }) };
}

export default {
  async fetch(request: Request, env: WorkerEnv): Promise<Response> {
    const envKey = JSON.stringify([env.TYPESAFE_API_KEY ? "d" : env.AI_GATEWAY_API_KEY ? "g" : "n", env.PROVIDER_HOST, env.JEV_ATTEST_PRIVATE_KEY]);
    if (!cached || cached.envKey !== envKey) {
      cached = { deps: buildDeps(env), envKey };
    }
    return createHandler(cached.deps)(request);
  },
};
