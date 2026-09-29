import { generateKeyPair, type KeyPair } from "../src/jws.js";
import { Provider } from "../src/provider.js";
import { GatewayJevClient } from "../src/backends/gateway.js";
import { JevClient } from "../src/jev.js";
import { createHandler, type HandlerDeps } from "../src/handler.js";
import { HTTPFacilitatorClient, x402ResourceServer } from "@x402/core/server";
import { x402HTTPResourceServer, type HTTPAdapter, type HTTPRequestContext, type HTTPProcessResult, type HTTPResponseInstructions, type PaymentOption } from "@x402/core/http";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { ExactSvmScheme } from "@x402/svm/exact/server";

interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
}

export type WorkerEnv = {
  PROVIDER_HOST?: string;
  TYPESAFE_API_KEY?: string;
  AI_GATEWAY_API_KEY?: string;
  JEV_ATTEST_PRIVATE_KEY?: string;
  JEV_ATTEST_PUBLIC_JWK?: string;
  PAY_TO_EVM?: string;
  PAY_TO_SOL?: string;
  X402_FACILITATOR_URL?: string;
  FREE_TIER_DAILY?: string;
  SOL_RPC_URL?: string;
  SOL_RPC_URL_MAINNET?: string;
  X402_FACILITATOR_URL_MAINNET?: string;
  X402_FACILITATOR_URL_PAYAI?: string;
  RATE?: KVNamespace;
};

const PROTECTED = new Set(["/v1/risk-check", "/v1/risk-check/batch"]);
const DEFAULT_FACILITATOR = "https://x402.org/facilitator";
const DEFAULT_MAINNET_FACILITATOR = "https://x402.dexter.cash";
const DEFAULT_PAYAI_FACILITATOR = "https://facilitator.payai.network";
const BASE_MAINNET = "eip155:8453";
const BASE_SEPOLIA = "eip155:84532";
const SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const SOLANA_DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

type Stack = {
  deps: HandlerDeps;
  http: x402HTTPResourceServer;
  envKey: string;
  initError?: string;
};

let cached: Stack | null = null;

function loadKeyPair(env: WorkerEnv): KeyPair {
  if (env.JEV_ATTEST_PRIVATE_KEY && env.JEV_ATTEST_PUBLIC_JWK) {
    const jwk = JSON.parse(env.JEV_ATTEST_PUBLIC_JWK) as KeyPair["publicJwk"];
    if (jwk.kty === "EC" && jwk.crv === "P-256" && typeof jwk.x === "string" && typeof jwk.y === "string") {
      return { privatePem: env.JEV_ATTEST_PRIVATE_KEY, publicJwk: jwk };
    }
  }
  return generateKeyPair("jev-attest-v1");
}

function buildStack(env: WorkerEnv): Stack {
  const host = env.PROVIDER_HOST ?? "x402check.xyz";
  const jev = env.TYPESAFE_API_KEY
    ? new JevClient({ apiKey: env.TYPESAFE_API_KEY })
    : env.AI_GATEWAY_API_KEY
      ? new GatewayJevClient()
      : null;
  const deps: HandlerDeps = { provider: new Provider({ host, keyPair: loadKeyPair(env), jev }) };

  const payToEvm = env.PAY_TO_EVM ?? "0xbF88b1F49B5e8Ec386289341c4a5ee00bB0E0178";
  const payToSol = env.PAY_TO_SOL ?? "Bofhoe2ye2adNQwZJtLepeKrBZq8CtHzRwPJXgWDH69X";
  const facilitators = [
    new HTTPFacilitatorClient({ url: env.X402_FACILITATOR_URL_MAINNET ?? DEFAULT_MAINNET_FACILITATOR }),
    new HTTPFacilitatorClient({ url: env.X402_FACILITATOR_URL_PAYAI ?? DEFAULT_PAYAI_FACILITATOR }),
    new HTTPFacilitatorClient({ url: env.X402_FACILITATOR_URL ?? DEFAULT_FACILITATOR }),
  ];
  const resourceServer = new x402ResourceServer(facilitators);
  resourceServer.register("eip155:*", new ExactEvmScheme());
  resourceServer.register(SOLANA_MAINNET, new ExactSvmScheme({ rpcUrl: env.SOL_RPC_URL_MAINNET ?? "https://api.mainnet-beta.solana.com" }));
  resourceServer.register(SOLANA_DEVNET, new ExactSvmScheme({ rpcUrl: env.SOL_RPC_URL ?? "https://api.devnet.solana.com" }));

  const accepts: PaymentOption[] = [
    { scheme: "exact", network: BASE_MAINNET, payTo: payToEvm, price: "$0.001" },
    { scheme: "exact", network: "eip155:137", payTo: payToEvm, price: "$0.001" },
    { scheme: "exact", network: "eip155:42161", payTo: payToEvm, price: "$0.001" },
    { scheme: "exact", network: "eip155:43114", payTo: payToEvm, price: "$0.001" },
    { scheme: "exact", network: "eip155:143", payTo: payToEvm, price: "$0.001" },
    { scheme: "exact", network: "eip155:1329", payTo: payToEvm, price: "$0.001" },
    { scheme: "exact", network: SOLANA_MAINNET, payTo: payToSol, price: "$0.002" },
    { scheme: "exact", network: BASE_SEPOLIA, payTo: payToEvm, price: "$0.001" },
    { scheme: "exact", network: "eip155:421614", payTo: payToEvm, price: "$0.001" },
    { scheme: "exact", network: SOLANA_DEVNET, payTo: payToSol, price: "$0.001" },
  ];
  const routes = {
    "POST /v1/risk-check": {
      accepts,
      description: "JEV payer-intent risk check with signed attestation",
      mimeType: "application/json",
    },
    "POST /v1/risk-check/batch": {
      accepts,
      description: "Batch risk check (up to 25 requests per call)",
      mimeType: "application/json",
    },
  };
  const http = new x402HTTPResourceServer(resourceServer, routes);
  return { deps, http, envKey: JSON.stringify([env.TYPESAFE_API_KEY ? "d" : env.AI_GATEWAY_API_KEY ? "g" : "n", env.PROVIDER_HOST, env.JEV_ATTEST_PRIVATE_KEY, env.JEV_ATTEST_PUBLIC_JWK, env.PAY_TO_EVM, env.PAY_TO_SOL, env.X402_FACILITATOR_URL, env.X402_FACILITATOR_URL_MAINNET, env.X402_FACILITATOR_URL_PAYAI]) };
}

async function ensureStack(env: WorkerEnv): Promise<Stack> {
  if (cached && cached.envKey === buildStackCacheKey(env)) return cached;
  cached = buildStack(env);
  try {
    await cached.http.initialize();
  } catch (err) {
    cached.initError = String(err);
  }
  return cached;
}

function buildStackCacheKey(env: WorkerEnv): string {
  return JSON.stringify([env.TYPESAFE_API_KEY ? "d" : env.AI_GATEWAY_API_KEY ? "g" : "n", env.PROVIDER_HOST, env.JEV_ATTEST_PRIVATE_KEY, env.JEV_ATTEST_PUBLIC_JWK, env.PAY_TO_EVM, env.PAY_TO_SOL, env.X402_FACILITATOR_URL, env.X402_FACILITATOR_URL_MAINNET, env.X402_FACILITATOR_URL_PAYAI]);
}

function fetchAdapter(request: Request): HTTPAdapter {
  return {
    getHeader: (name) => request.headers.get(name) ?? undefined,
    getMethod: () => request.method,
    getPath: () => new URL(request.url).pathname,
    getUrl: () => request.url,
    getAcceptHeader: () => request.headers.get("accept") ?? "*/*",
    getUserAgent: () => request.headers.get("user-agent") ?? "",
  };
}

function instructionsToResponse(instr: HTTPResponseInstructions): Response {
  return new Response(typeof instr.body === "string" ? instr.body : JSON.stringify(instr.body), {
    status: instr.status,
    headers: instr.headers,
  });
}

const NEW_CLIENT_BUDGET_DAILY = 1000;

async function freeQuota(env: WorkerEnv, ip: string): Promise<number> {
  const daily = Number(env.FREE_TIER_DAILY ?? "25");
  if (!env.RATE || !Number.isFinite(daily) || daily <= 0) return 0;
  const day = new Date().toISOString().slice(0, 10);
  const key = `free:${ip}:${day}`;
  const used = Number((await env.RATE.get(key)) ?? "0");
  if (used >= daily) return 0;
  await env.RATE.put(key, String(used + 1), { expirationTtl: 172800 });
  const totalKey = `free-total:${day}`;
  const total = Number((await env.RATE.get(totalKey)) ?? "0");
  await env.RATE.put(totalKey, String(total + 1), { expirationTtl: 172800 });
  return daily - used;
}

async function clientQuota(env: WorkerEnv, clientId: string): Promise<number> {
  const daily = Number(env.FREE_TIER_DAILY ?? "25");
  if (!env.RATE || !Number.isFinite(daily) || daily <= 0) return 0;
  const day = new Date().toISOString().slice(0, 10);
  const newClients = Number((await env.RATE.get(`new-clients:${day}`)) ?? "0");
  const known = (await env.RATE.get(`client-known:${clientId}`)) === "1";
  if (!known) {
    if (newClients >= NEW_CLIENT_BUDGET_DAILY) return 0;
    await env.RATE.put(`client-known:${clientId}`, "1", { expirationTtl: 172800 });
    await env.RATE.put(`new-clients:${day}`, String(newClients + 1), { expirationTtl: 172800 });
  }
  const key = `client:${clientId}:${day}`;
  const used = Number((await env.RATE.get(key)) ?? "0");
  if (used >= daily) return 0;
  await env.RATE.put(key, String(used + 1), { expirationTtl: 172800 });
  const totalKey = `free-total:${day}`;
  const total = Number((await env.RATE.get(totalKey)) ?? "0");
  await env.RATE.put(totalKey, String(total + 1), { expirationTtl: 172800 });
  return daily - used;
}

async function handleProtected(request: Request, env: WorkerEnv, stack: Stack, serve: (req: Request) => Promise<Response>): Promise<Response> {
  const paymentHeader = request.headers.get("PAYMENT-SIGNATURE") ?? request.headers.get("X-PAYMENT");
  const forcePaid = (request.headers.get("X-Risk-Check-Paid") ?? "").trim().length > 0;
  if (!paymentHeader && !forcePaid) {
    const clientId = (request.headers.get("X-Risk-Check-Client") ?? "").trim();
    const remaining = clientId
      ? await clientQuota(env, clientId.slice(0, 64))
      : await freeQuota(env, request.headers.get("CF-Connecting-IP") ?? "unknown");
    if (remaining > 0) {
      const res = await serve(request);
      res.headers.set("X-Risk-Check-Free", "true");
      return res;
    }
  }
  const ctx: HTTPRequestContext = {
    adapter: fetchAdapter(request),
    path: new URL(request.url).pathname,
    method: request.method,
    paymentHeader: paymentHeader ?? undefined,
  };
  let result: HTTPProcessResult;
  try {
    result = await stack.http.processHTTPRequest(ctx);
  } catch (err) {
    return Response.json({ error: "payment_processing_failed", detail: String(err) }, { status: 500 });
  }
  if (result.type === "payment-error") return instructionsToResponse(result.response);
  if (result.type === "no-payment-required") {
    return Response.json({ error: "payment_required" }, { status: 402 });
  }
  const res = await serve(request);
  if (res.status === 200) {
    try {
      const settle = await stack.http.processSettlement(result.paymentPayload, result.paymentRequirements);
      if (settle.success) {
        for (const [k, v] of Object.entries(settle.headers)) res.headers.set(k, v);
      } else {
        res.headers.set("X-Payment-Error", settle.errorReason ?? "settlement_failed");
      }
    } catch (err) {
      res.headers.set("X-Payment-Error", String(err));
    }
  }
  return res;
}

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Accept, PAYMENT-SIGNATURE, X-PAYMENT, X-Risk-Check-Paid, X-Risk-Check-Client",
  "Access-Control-Expose-Headers": "PAYMENT-RESPONSE, X-PAYMENT-RESPONSE, PAYMENT-REQUIRED, X-Risk-Check-Free, X-Payment-Error",
  "Access-Control-Max-Age": "86400",
};

export default {
  async fetch(request: Request, env: WorkerEnv): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }
    const stack = await ensureStack(env);
    const path = new URL(request.url).pathname;
    let res: Response;
    if (request.method === "GET" && path === "/healthz" && env.RATE) {
      const day = new Date().toISOString().slice(0, 10);
      const freeEvalsToday = Number((await env.RATE.get(`free-total:${day}`)) ?? "0");
      res = Response.json({ ok: true, freeEvalsToday });
    } else if (PROTECTED.has(path)) {
      res = await handleProtected(request, env, stack, (req) => createHandler(stack.deps)(req));
    } else {
      res = await createHandler(stack.deps)(request);
    }
    for (const [k, v] of Object.entries(CORS_HEADERS)) res.headers.set(k, v);
    return res;
  },
};
