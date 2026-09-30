// A stub x402check (API and DID document) and a stub x402 merchant behind one FetchLike, for the
// security tests of x402check_pay. Everything is local: throwaway keys, no network, no money.
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { normalizeHost, requestHash, toCaip2, type FetchInitLike, type FetchLike, type FetchResponseLike, type RiskCheckRequest, type RiskCheckResult } from "@x402check/client";
import { createX402CheckServer, type ServerConfig } from "../src/server.js";
import { DID_URL, didDocument, json, signedResult, USDC_BASE, type Issuer } from "./helpers.js";

export const MERCHANT = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4";
export const X402CHECK_PAY_TO = "0xbF88b1F49B5e8Ec386289341c4a5ee00bB0E0178";
export const ORIGIN = "https://api.weather.example";
export const RESOURCE = `${ORIGIN}/v1/forecast`;
export const TOKEN = `x402c_${"t".repeat(43)}`;
export const TX = `0x${"7a".repeat(32)}`;

export type Verdict = { tier: "low" | "medium" | "high" | "critical"; score: number; categories: string[] };
export const LOW: Verdict = { tier: "low", score: 88, categories: [] };
export const WARN: Verdict = { tier: "medium", score: 55, categories: ["new_address"] };
export const BLOCK: Verdict = { tier: "critical", score: 4, categories: ["known_scam_address"] };

export const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64");

/** One x402 v2 payment option (USDC on Base to the merchant, valid 300 s), with overrides. */
export function option(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { scheme: "exact", network: "eip155:8453", amount: "10000", asset: USDC_BASE, payTo: MERCHANT, maxTimeoutSeconds: 300, extra: { name: "USD Coin", version: "2" }, ...overrides };
}

export function challenge(accepts: unknown[] = [option()], overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { x402Version: 2, error: "Payment required", resource: { url: RESOURCE, description: "Lisbon forecast", mimeType: "application/json" }, accepts, ...overrides };
}

/** A 402 carrying the challenge in its PAYMENT-REQUIRED header. */
export function paymentRequired(accepts?: unknown[], overrides?: Record<string, unknown>): Response {
  return json(402, {}, { "PAYMENT-REQUIRED": b64(challenge(accepts, overrides)) });
}

/** The attestation the real provider would sign for `request`: every binding the guard verifies. */
export async function bound(issuer: Issuer, request: RiskCheckRequest, v: Verdict): Promise<RiskCheckResult> {
  const network = request.chain ? toCaip2(request.chain) : undefined;
  return signedResult(issuer, {
    sub: request.wallet,
    tier: v.tier,
    score: v.score,
    categories: v.categories,
    claims: {
      request_hash: await requestHash(request),
      checks: {
        sanctions: { list: "ofac-sdn", as_of: "2026-09-23", status: "not_listed" },
        ...(network ? { onchain: { status: "ok", network, activity: "some" } } : {}),
        model: "jev-wallet-risk/v6",
        ...(request.domain ? { domain: { host: normalizeHost(request.domain), registrable: normalizeHost(request.domain), official: false } } : {}),
      },
      ...(request.interaction ? { interaction: request.interaction.type } : {}),
      ...(request.payment ? { payment: request.payment } : {}),
    },
  });
}

export type Call = { url: string; init: FetchInitLike & { redirect?: string }; paid: boolean; payload?: Record<string, unknown> };

export interface WorldOptions {
  decide?: (request: RiskCheckRequest) => Verdict;
  /** x402check's API origin (default https://x402check.xyz). */
  api?: string;
  /** Answers a check instead of the default signed verdict (return undefined for the default). */
  onCheck?: (request: RiskCheckRequest, init: FetchInitLike) => Response | undefined | Promise<Response | undefined>;
  /** What each check costs from credits (X-Credits-Charged). */
  charged?: string;
  /** The merchant: every URL other than the API and the DID document. Default: 402 until paid, then 200 with a receipt. */
  merchant?: (call: Call) => Response | FetchResponseLike | Promise<Response | FetchResponseLike>;
}

/** The authorization a merchant received (EIP-3009). */
export function authorizationOf(call: Call | undefined): Record<string, string> {
  return ((call?.payload?.payload as { authorization?: Record<string, string> } | undefined)?.authorization ?? {}) as Record<string, string>;
}

export function world(issuer: Issuer, o: WorldOptions = {}) {
  const calls: Call[] = [];
  const checks: RiskCheckRequest[] = [];
  const api = `${o.api ?? "https://x402check.xyz"}/v1/risk-check`;
  const fetch: FetchLike = async (url, init) => {
    const header = init.headers["payment-signature"];
    const payload = header ? (JSON.parse(Buffer.from(header, "base64").toString("utf8")) as Record<string, unknown>) : undefined;
    const call: Call = { url, init, paid: header !== undefined, ...(payload ? { payload } : {}) };
    calls.push(call);
    if (url === DID_URL) return json(200, didDocument(issuer));
    if (url === api) {
      const request = JSON.parse(init.body ?? "{}") as RiskCheckRequest;
      checks.push(request);
      const custom = await o.onCheck?.(request, init);
      if (custom) return custom;
      const result = await bound(issuer, request, (o.decide ?? (() => LOW))(request));
      return json(200, result, { "X-Credits-Charged": o.charged ?? "$0.001", "X-Credits-Balance": "$0.412" });
    }
    if (o.merchant) return o.merchant(call);
    if (!call.paid) return paymentRequired();
    const from = authorizationOf(call).from ?? "";
    return json(200, { city: "Lisbon", forecast: "sunny" }, { "PAYMENT-RESPONSE": b64({ success: true, transaction: TX, network: "eip155:8453", payer: from }) });
  };
  const merchantCalls = (): Call[] => calls.filter((c) => c.url !== DID_URL && c.url !== api);
  return { fetch, calls, checks, merchantCalls, payments: () => merchantCalls().filter((c) => c.paid) };
}

type ElicitAnswer = { action: "accept" | "decline" | "cancel"; content?: Record<string, unknown> };

/**
 * Server and client over linked in-memory transports. The client lists the tools first, so it
 * validates every result's structuredContent against the tool's outputSchema (error results too).
 */
export async function session(config: ServerConfig, user?: (message: string, signal: AbortSignal) => ElicitAnswer | Promise<ElicitAnswer>) {
  const server = createX402CheckServer(config);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  // Every message the server sends (requests such as elicitations, and notifications).
  const serverSent: Array<{ id?: unknown; method?: string; params?: Record<string, unknown> }> = [];
  const send = serverTransport.send.bind(serverTransport);
  serverTransport.send = async (message, options) => {
    serverSent.push(message as (typeof serverSent)[number]);
    return send(message, options);
  };
  const client = new Client({ name: "x402check-test", version: "0.0.0" }, user ? { capabilities: { elicitation: { form: {} } } } : {});
  const asked: string[] = [];
  if (user) {
    client.setRequestHandler(ElicitRequestSchema, async (request, extra) => {
      asked.push(String(request.params.message));
      return (await user(String(request.params.message), extra.signal)) as never;
    });
  }
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  await client.listTools();
  return {
    client,
    asked,
    serverSent,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

export type ToolResult = { content: Array<{ type: string; text?: string }>; structuredContent?: Record<string, unknown>; isError?: boolean; text: string };

export async function call(client: Client, name: string, args: Record<string, unknown> = {}, options: { signal?: AbortSignal } = {}): Promise<ToolResult> {
  const result = (await client.callTool({ name, arguments: args }, undefined, options)) as Omit<ToolResult, "text">;
  const texts = result.content.filter((c) => c.type === "text").map((c) => c.text ?? "");
  if (texts[1] !== undefined && result.structuredContent) assert.deepEqual(JSON.parse(texts[1]), result.structuredContent, "the JSON text block mirrors structuredContent");
  return { ...result, text: texts[0] ?? "" };
}

/** Polls until `predicate` holds (or fails after `timeoutMs`). */
export async function waitFor(predicate: () => boolean, what: string, timeoutMs = 3000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) assert.fail(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

export function assertNoSecret(outputs: unknown[], secrets: string[]): void {
  for (const out of outputs) {
    const s = (typeof out === "string" ? out : JSON.stringify(out)).toLowerCase();
    for (const secret of secrets) assert.ok(!s.includes(secret.toLowerCase()), "a secret must never appear in any output");
  }
}

export function errorCode(r: ToolResult): string | undefined {
  return (r.structuredContent?.error as { code?: string } | undefined)?.code;
}
