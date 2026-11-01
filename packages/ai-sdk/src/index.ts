import { jsonSchema, tool, type InferSchema, type ModelMessage, type Tool, type ToolSet } from "ai";
import { INTERACTION_TYPES, toCaip2, type InteractionType, type RiskCheckRequest } from "@x402check/client";
import { createScreener, type Screening, type X402checkOptions } from "./screen.js";

export { createScreener } from "./screen.js";
export type { Screener, Screening, ScreenedCheck, X402checkOptions } from "./screen.js";

/** The API's limit on `context`. */
const MAX_CONTEXT = 4096;
/** How long a verdict answers the same tool call again (approval replays re-resolve the policy). */
const REPLAY_TTL_MS = 300_000;
const MAX_REMEMBERED = 256;

/** A tool's input type, read from its input schema. */
export type ToolInput<T> = T extends { inputSchema: infer S } ? InferSchema<S> : unknown;

/** The counterparties a tool call names: who receives value or rights. Nothing → the call is not screened. */
export type Counterparties<INPUT> = (
  input: INPUT,
  call: { toolName: string; toolCallId: string },
) => RiskCheckRequest | readonly RiskCheckRequest[] | undefined | Promise<RiskCheckRequest | readonly RiskCheckRequest[] | undefined>;

/** What the policy decides for a call (a `ToolApprovalStatus` of the AI SDK). */
export type ApprovalDecision = { type: "not-applicable" } | { type: "approved" | "denied" | "user-approval"; reason: string };

/** One screened tool call, for audit logs. */
export interface ApprovalEvent {
  toolName: string;
  toolCallId: string;
  screening: Screening;
  status: ApprovalDecision;
}

export interface ApprovalOptions<TOOLS extends ToolSet> extends X402checkOptions {
  /** For each tool that moves value or grants rights: the counterparties its input names. Other tools are not screened. */
  tools: { [K in keyof TOOLS]?: Counterparties<ToolInput<TOOLS[K]>> };
  /** What a `warn` verdict becomes. Default "user-approval" (a human decides); "denied" for agents with no one to ask. */
  onWarn?: "user-approval" | "denied" | undefined;
  /**
   * The content the agent acted on, sent as each check's `context` so injected instructions are
   * detected. Default: the latest user message and the tool results after it. `false` sends none.
   */
  context?: false | ((messages: readonly ModelMessage[]) => string | undefined) | undefined;
  /** Every screened call, approved or not. */
  onVerdict?: ((event: ApprovalEvent) => void | Promise<void>) | undefined;
}

/** The `toolApproval` function `generateText` and `streamText` call before a tool runs (structurally, for any TOOLS). */
export type X402checkApproval = (options: {
  toolCall: { toolName: string; toolCallId: string; input: unknown };
  messages: ModelMessage[];
}) => Promise<ApprovalDecision>;

/**
 * A tool-approval policy for `generateText` / `streamText` (AI SDK 7): before a tool listed in
 * `tools` runs, x402check screens the counterparties its input names. allow → approved (it
 * runs) · warn → user-approval (or denied, per `onWarn`) · block or not_verified → denied. Each
 * reason is recorded on the approval. A check that fails or cannot be verified denies the call.
 *
 * ```ts
 * await generateText({ model, tools, prompt, toolApproval: x402checkApproval({ creditToken, tools: {
 *   sendUsdc: (input) => ({ wallet: input.to, chain: "base", interaction: { type: "token_transfer" } }),
 * } }) });
 * ```
 */
export function x402checkApproval<TOOLS extends ToolSet>(options: ApprovalOptions<TOOLS>): X402checkApproval {
  const screen = createScreener(options);
  const mappers = options.tools as Record<string, Counterparties<unknown> | undefined>;
  const onWarn = options.onWarn ?? "user-approval";
  const remembered = new Map<string, { at: number; screening: Screening }>();

  async function screenOnce(key: string, requests: RiskCheckRequest[]): Promise<Screening> {
    const now = Date.now();
    for (const [k, v] of remembered) if (now - v.at > REPLAY_TTL_MS) remembered.delete(k);
    const hit = remembered.get(key);
    if (hit) return hit.screening;
    const screening = await screen(requests);
    // A verdict that did not complete is never reused: the replay checks again.
    if (screening.action !== "not_verified") {
      if (remembered.size >= MAX_REMEMBERED) remembered.delete(remembered.keys().next().value as string);
      remembered.set(key, { at: now, screening });
    }
    return screening;
  }

  return async ({ toolCall, messages }) => {
    const mapper = Object.prototype.hasOwnProperty.call(mappers, toolCall.toolName) ? mappers[toolCall.toolName] : undefined;
    if (!mapper) return { type: "not-applicable" };
    let screening: Screening;
    try {
      const named = await mapper(toolCall.input, { toolName: toolCall.toolName, toolCallId: toolCall.toolCallId });
      if (named === undefined) return { type: "not-applicable" };
      const list = (Array.isArray(named) ? [...named] : [named]) as RiskCheckRequest[];
      if (list.length === 0) return { type: "not-applicable" };
      // `context: false` sends nothing of the conversation, not even the call's input.
      const shared =
        options.context === false
          ? []
          : [(options.context ?? defaultContext)(messages), `About to run the tool "${toolCall.toolName}" with ${truncate(safeJson(toolCall.input), 600)}`];
      const requests = list.map((r) => withContext(r, shared));
      screening = await screenOnce(`${toolCall.toolCallId}\n${safeJson(requests)}`, requests);
    } catch (err) {
      screening = { action: "not_verified", reasons: [`x402check could not screen this call: ${err instanceof Error ? err.message : String(err)}`], checks: [] };
    }
    const status = statusOf(screening, onWarn);
    if (options.onVerdict) await options.onVerdict({ toolName: toolCall.toolName, toolCallId: toolCall.toolCallId, screening, status });
    return status;
  };
}

function statusOf(screening: Screening, onWarn: "user-approval" | "denied"): ApprovalDecision {
  const reason = `x402check: ${screening.action}${screening.tier ? ` (tier ${screening.tier})` : ""}${screening.reasons.length ? `: ${screening.reasons.slice(0, 3).join("; ")}` : ""}`.slice(0, 600);
  switch (screening.action) {
    case "allow":
      return { type: "approved", reason };
    case "warn":
      return { type: onWarn, reason };
    default:
      return { type: "denied", reason };
  }
}

/** The mapper's own context first, then the conversation and the call; never longer than the API accepts. */
function withContext(request: RiskCheckRequest, shared: readonly (string | undefined)[]): RiskCheckRequest {
  const parts = [request.context?.trim(), ...shared].filter((p): p is string => typeof p === "string" && p.length > 0);
  if (parts.length === 0) {
    const { context: _none, ...rest } = request;
    return rest;
  }
  return { ...request, context: fitTail(parts.join("\n\n"), MAX_CONTEXT) };
}

/** The latest user message and every tool result after it: what the agent acted on in this turn. */
export function defaultContext(messages: readonly ModelMessage[]): string | undefined {
  let start = 0;
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i]?.role === "user") {
      start = i;
      break;
    }
  }
  const parts: string[] = [];
  for (const message of messages.slice(start)) {
    if (message.role === "user") {
      const text = textOf(message.content);
      if (text) parts.push(`User: ${text}`);
    } else if (message.role === "tool") {
      for (const part of message.content) {
        if (part.type !== "tool-result") continue;
        const text = outputText(part.output);
        if (text) parts.push(`Tool result (${part.toolName}, untrusted): ${text}`);
      }
    }
  }
  return parts.length ? fitTail(parts.join("\n\n"), MAX_CONTEXT - 700) : undefined;
}

function textOf(content: unknown): string {
  if (typeof content === "string") return content.trim();
  if (!Array.isArray(content)) return "";
  return content
    .map((p) => (p && typeof p === "object" && (p as { type?: unknown }).type === "text" ? String((p as { text?: unknown }).text ?? "") : ""))
    .filter(Boolean)
    .join("\n")
    .trim();
}

function outputText(output: unknown): string {
  if (!output || typeof output !== "object") return "";
  const o = output as { type?: unknown; value?: unknown };
  if (o.type === "text" || o.type === "error-text") return String(o.value ?? "").trim();
  if (o.type === "json" || o.type === "error-json") return safeJson(o.value);
  if (o.type === "content" && Array.isArray(o.value)) return textOf(o.value);
  return "";
}

/** Keeps the end: the most recent content matters most. */
function fitTail(text: string, max: number): string {
  return text.length <= max ? text : `…${text.slice(text.length - (max - 1))}`;
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? v.toString() : v)) ?? String(value);
  } catch {
    return String(value);
  }
}

export interface CheckToolInput {
  address: string;
  chain: string;
  domain?: string | undefined;
  interaction?: InteractionType | undefined;
  context?: string | undefined;
}

/** What the model receives: the decision, why, and the signed attestation. */
export interface CheckToolOutput {
  action: Screening["action"];
  tier?: string | undefined;
  reasons: string[];
  /** What to do: allow → proceed · warn → ask the user · block / not_verified → do not proceed. */
  instruction: string;
  attestation?: string | undefined;
}

const INSTRUCTIONS: Record<Screening["action"], string> = {
  allow: "No check fired. You may proceed (this is not a guarantee of safety).",
  warn: "Ask the user to confirm before proceeding, and show them the reasons.",
  block: "Do not proceed with this counterparty.",
  not_verified: "The check did not complete or could not be verified. Do not proceed.",
};

/**
 * A tool the model calls before it sends funds, approves a spender, signs an order or pays an
 * x402 invoice. It returns x402check's verified decision. The model can skip a tool: enforce
 * with `x402checkApproval` on the tools that move value.
 */
export function x402checkTool(options: X402checkOptions = {}): Tool<CheckToolInput, CheckToolOutput> {
  const screen = createScreener(options);
  return tool({
    description:
      "Pre-payment risk check (x402check): call it BEFORE sending funds, approving a spender, signing an order or permit, or paying an x402 invoice, with the address that would receive value or rights. It screens OFAC sanctions, phishing and drainer lists, drainer infrastructure, look-alike domains, and the content you acted on for injected instructions. Follow the returned instruction.",
    inputSchema: jsonSchema<CheckToolInput>(
      {
        type: "object",
        properties: {
          address: { type: "string", description: "The counterparty that would receive value or rights: recipient, spender, operator or payee (EVM 0x… or Solana base58)." },
          chain: { type: "string", description: "Chain name (base, ethereum, polygon, arbitrum, solana…) or CAIP-2 id (eip155:8453)." },
          domain: { type: "string", description: "The site or app involved, if any (hostname or URL)." },
          interaction: { type: "string", enum: [...INTERACTION_TYPES], description: "What is about to happen with this counterparty." },
          context: { type: "string", description: "The content that led you here, verbatim (a message, page or tool output). It is checked for injected instructions." },
        },
        required: ["address", "chain"],
        additionalProperties: false,
      },
      { validate: validateCheckInput },
    ),
    execute: async (input, { abortSignal }): Promise<CheckToolOutput> => {
      const request: RiskCheckRequest = {
        wallet: input.address.trim(),
        chain: toCaip2(input.chain.trim()) ?? input.chain.trim(),
        ...(input.domain ? { domain: input.domain.trim() } : {}),
        ...(input.context ? { context: fitTail(input.context, MAX_CONTEXT) } : {}),
        ...(input.interaction ? { interaction: { type: input.interaction } } : {}),
      };
      const screening = await screen([request], abortSignal);
      const attestation = screening.checks[0]?.jws;
      return {
        action: screening.action,
        ...(screening.tier ? { tier: screening.tier } : {}),
        reasons: screening.reasons,
        instruction: INSTRUCTIONS[screening.action],
        ...(attestation ? { attestation } : {}),
      };
    },
  });
}

function validateCheckInput(value: unknown): { success: true; value: CheckToolInput } | { success: false; error: Error } {
  const fail = (message: string) => ({ success: false as const, error: new TypeError(message) });
  if (!value || typeof value !== "object" || Array.isArray(value)) return fail("input must be an object");
  const v = value as Record<string, unknown>;
  for (const key of Object.keys(v)) if (!["address", "chain", "domain", "interaction", "context"].includes(key)) return fail(`unknown field "${key}"`);
  if (typeof v.address !== "string" || !v.address.trim() || v.address.length > 256) return fail("address must be a non-empty string");
  if (typeof v.chain !== "string" || !v.chain.trim() || v.chain.length > 64) return fail("chain must be a non-empty string");
  if (v.domain !== undefined && (typeof v.domain !== "string" || v.domain.length > 512)) return fail("domain must be a string");
  if (v.interaction !== undefined && !(INTERACTION_TYPES as readonly unknown[]).includes(v.interaction)) return fail(`interaction must be one of ${INTERACTION_TYPES.join(", ")}`);
  if (v.context !== undefined && typeof v.context !== "string") return fail("context must be a string");
  return { success: true, value: v as unknown as CheckToolInput };
}
