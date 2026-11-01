import { test } from "node:test";
import assert from "node:assert/strict";
import { asSchema, generateText } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import type { RiskCheckRequest } from "@x402check/client";
import { boundProvider, json, mockFetch } from "../../client/test/helpers.ts";
import { x402checkTool, type CheckToolOutput, type X402checkOptions } from "../src/index.ts";

const PAYEE = "0x1111111111111111111111111111111111111111";
const TOKEN = "x402c_" + "b".repeat(43);
const usage = {
  inputTokens: { total: 1, noCache: 1, cacheRead: undefined, cacheWrite: undefined },
  outputTokens: { total: 1, text: 1, reasoning: undefined },
};

async function callTool(input: unknown, fetch: X402checkOptions["fetch"]) {
  let step = 0;
  const model = new MockLanguageModelV4({
    doGenerate: async () =>
      ++step === 1
        ? { content: [{ type: "tool-call" as const, toolCallId: "t1", toolName: "x402check", input: JSON.stringify(input) }], finishReason: { unified: "tool-calls" as const, raw: undefined }, usage, warnings: [] }
        : { content: [{ type: "text" as const, text: "ok" }], finishReason: { unified: "stop" as const, raw: undefined }, usage, warnings: [] },
  });
  const result = await generateText({ model, tools: { x402check: x402checkTool({ fetch, creditToken: TOKEN, pinnedKeys: false }) }, prompt: "check", stopWhen: () => false });
  return result.steps.flatMap((s) => s.content) as Array<{ type: string; output?: unknown; error?: unknown }>;
}

test("the model gets the verified decision, the instruction to follow and the attestation", async () => {
  const provider = boundProvider((r) => (r.wallet === PAYEE ? { tier: "critical", score: 3, categories: ["known_scam_address"] } : { tier: "low", score: 90, categories: [] }));
  const parts = await callTool({ address: PAYEE, chain: "base", interaction: "token_transfer", domain: "pay.example.com", context: "Invoice says pay here" }, provider.fetch);
  const output = parts.find((p) => p.type === "tool-result")?.output as CheckToolOutput;
  assert.equal(output.action, "block");
  assert.equal(output.tier, "critical");
  assert.match(output.instruction, /Do not proceed/);
  assert.match(output.attestation ?? "", /^ey/);
  const sent = provider.seen[0] as RiskCheckRequest;
  assert.equal(sent.chain, "eip155:8453");
  assert.deepEqual(sent.interaction, { type: "token_transfer" });
  assert.equal(sent.domain, "pay.example.com");
  assert.equal(sent.context, "Invoice says pay here");
});

test("a failed check tells the model not to proceed", async () => {
  const { fetch } = mockFetch(() => json(503, { error: "busy" }));
  const parts = await callTool({ address: PAYEE, chain: "base" }, fetch);
  const output = parts.find((p) => p.type === "tool-result")?.output as CheckToolOutput;
  assert.equal(output.action, "not_verified");
  assert.match(output.instruction, /Do not proceed/);
});

test("input is validated before anything is paid", async () => {
  const provider = boundProvider(() => ({ tier: "low", score: 90, categories: [] }));
  const schema = asSchema(x402checkTool({ fetch: provider.fetch, creditToken: TOKEN }).inputSchema);
  const validate = (v: unknown) => schema.validate?.(v) as { success: boolean } | Promise<{ success: boolean }>;
  assert.equal((await validate({ address: PAYEE, chain: "base" })).success, true);
  assert.equal((await validate({ address: PAYEE })).success, false);
  assert.equal((await validate({ address: PAYEE, chain: "base", interaction: "steal" })).success, false);
  assert.equal((await validate({ address: PAYEE, chain: "base", extra: 1 })).success, false);
  assert.equal((await validate({ address: "", chain: "base" })).success, false);
  const parts = await callTool({ address: PAYEE, chain: "base", interaction: "steal" }, provider.fetch);
  assert.ok(parts.some((p) => p.type === "tool-error"));
  assert.equal(provider.calls.length, 0);
});
