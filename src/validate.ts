import { chainFits, evmChecksumValid, parseSubject, sameSubject } from "./address.js";
import { normalizeChain } from "./chains.js";
import { requestHash } from "./jws.js";
import { normalizeHost } from "./domain-analysis.js";
import { INTERACTION_TYPES, type Interaction, type PaymentBinding, type RiskCheckRequest } from "./types.js";

export const MAX_BATCH = 25;
// Every string field reaches the model state or the signed claims; cap each one so a
// single call cannot amplify model cost or smuggle a long injection payload.
export const MAX_FIELD_LEN = { context: 4096, aud: 256, source: 128, resource: 512 } as const;

export type Invalid = { ok: false; field: string };
export type Valid<T> = { ok: true; value: T };

const invalid = (field: string): Invalid => ({ ok: false, field });

function optionalString(obj: Record<string, unknown>, key: string, max: number): string | undefined | Invalid {
  const v = obj[key];
  if (v === undefined) return undefined;
  // In code points, as JSON Schema's maxLength (the published schemas) counts them: an emoji is one.
  if (typeof v !== "string" || codePoints(v) > max) return invalid(key);
  return v;
}

function codePoints(s: string): number {
  let n = 0;
  for (const _ of s) n++;
  return n;
}

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** The bytes as UTF-8 text, or null when they are not valid UTF-8 (never silently replaced with U+FFFD). */
export function strictUtf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/**
 * Whether a JSON text repeats a key within one object (keys compared after unescaping, so
 * "w\u0061llet" repeats "wallet"). JSON.parse keeps the last; another parser in front of us may
 * keep the first and read a different request. Call it on text that parses.
 */
export function repeatedKey(text: string): boolean {
  const scopes: Array<Set<string> | null> = [];
  let keyNext = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const scope = scopes[scopes.length - 1];
      if (scope && keyNext) {
        const key = JSON.parse(text.slice(i, j + 1)) as string;
        if (scope.has(key)) return true;
        scope.add(key);
        keyNext = false;
      }
      i = j;
    } else if (c === "{") {
      scopes.push(new Set());
      keyNext = true;
    } else if (c === "[") {
      scopes.push(null);
      keyNext = false;
    } else if (c === "}" || c === "]") {
      scopes.pop();
      keyNext = false;
    } else if (c === ",") keyNext = scopes[scopes.length - 1] instanceof Set;
  }
  return false;
}

/** Whether every string in a JSON value is well-formed Unicode (no lone surrogate). */
function wellFormed(v: unknown, depth = 0): boolean {
  if (depth > 64) return false;
  if (typeof v === "string") return !LONE_SURROGATE.test(v);
  if (Array.isArray(v)) return v.every((x) => wellFormed(x, depth + 1));
  if (v && typeof v === "object") return Object.entries(v).every(([k, x]) => !LONE_SURROGATE.test(k) && wellFormed(x, depth + 1));
  return true;
}

function isInvalid(v: unknown): v is Invalid {
  return typeof v === "object" && v !== null && (v as { ok?: unknown }).ok === false;
}

function validatePayment(raw: unknown): PaymentBinding | Invalid {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return invalid("payment");
  const p = raw as Record<string, unknown>;
  const allowed = new Set(["network", "pay_to", "amount", "asset", "resource"]);
  if (Object.keys(p).some((k) => !allowed.has(k))) return invalid("payment");
  const out: PaymentBinding = {};
  if (p.network !== undefined) {
    const chain = typeof p.network === "string" ? normalizeChain(p.network) : null;
    if (!chain) return invalid("payment.network");
    out.network = chain.caip2;
  }
  if (p.pay_to !== undefined) {
    const payTo = typeof p.pay_to === "string" ? parseSubject(p.pay_to) : null;
    if (!payTo) return invalid("payment.pay_to");
    // The payment's network must be able to hold its pay_to (an EVM network, a Solana pay_to: refused).
    if (out.network && !chainFits(payTo, out.network)) return invalid("payment.pay_to");
    out.pay_to = p.pay_to as string;
  }
  if (p.amount !== undefined) {
    if (typeof p.amount !== "string" || !/^\d{1,78}$/.test(p.amount) || BigInt(p.amount) >= 2n ** 256n) return invalid("payment.amount");
    out.amount = p.amount;
  }
  if (p.asset !== undefined) {
    if (typeof p.asset !== "string" || !(p.asset === "native" || parseSubject(p.asset) || /^[A-Za-z0-9._-]{1,32}$/.test(p.asset))) return invalid("payment.asset");
    out.asset = p.asset;
  }
  if (p.resource !== undefined) {
    if (typeof p.resource !== "string" || p.resource.length > MAX_FIELD_LEN.resource || !/^https?:\/\/\S+$/.test(p.resource)) return invalid("payment.resource");
    out.resource = p.resource;
  }
  return out;
}

function validateInteraction(raw: unknown): Interaction | Invalid {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return invalid("interaction");
  const i = raw as Record<string, unknown>;
  if (Object.keys(i).some((k) => k !== "type" && k !== "unlimited")) return invalid("interaction");
  if (typeof i.type !== "string" || !(INTERACTION_TYPES as readonly string[]).includes(i.type)) return invalid("interaction.type");
  if (i.unlimited !== undefined && typeof i.unlimited !== "boolean") return invalid("interaction.unlimited");
  return { type: i.type as Interaction["type"], ...(i.unlimited !== undefined ? { unlimited: i.unlimited } : {}) };
}

const MAX_CALLDATA_HEX = 48 * 1024; // chars, well inside the 64 KiB body cap

function validateTransaction(raw: unknown): NonNullable<RiskCheckRequest["transaction"]> | Invalid {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return invalid("transaction");
  const t = raw as Record<string, unknown>;
  if (Object.keys(t).some((k) => !["from", "to", "value", "data"].includes(k))) return invalid("transaction");
  // An EVM address, with a valid EIP-55 checksum when mixed-case (as the subject's).
  const evm = (v: unknown) => typeof v === "string" && /^0x[0-9a-fA-F]{40}$/.test(v) && evmChecksumValid(v);
  if (!evm(t.from)) return invalid("transaction.from");
  if (t.to !== undefined && !evm(t.to)) return invalid("transaction.to");
  let value: string | undefined;
  if (t.value !== undefined) {
    if (typeof t.value !== "string" || !/^(0x[0-9a-fA-F]{1,64}|\d{1,78})$/.test(t.value) || BigInt(t.value) >= 2n ** 256n) return invalid("transaction.value");
    value = t.value;
  }
  if (t.data !== undefined && (typeof t.data !== "string" || !/^0x([0-9a-fA-F]{2})*$/.test(t.data) || t.data.length > MAX_CALLDATA_HEX)) return invalid("transaction.data");
  return {
    from: t.from as string,
    ...(t.to !== undefined ? { to: t.to as string } : {}),
    ...(value !== undefined ? { value } : {}),
    ...(t.data !== undefined ? { data: t.data as string } : {}),
  };
}

/** Validates and normalizes one request. chain → CAIP-2, domain → hostname. */
/** The request's fields: exactly those `request_hash` covers. Anything else is refused, never ignored. */
const REQUEST_FIELDS = new Set(["wallet", "chain", "domain", "context", "aud", "screening", "authorization", "payment", "interaction", "transaction"]);

export function validateRequest(body: unknown): Valid<RiskCheckRequest> | Invalid {
  if (!body || typeof body !== "object" || Array.isArray(body)) return invalid("body");
  const obj = body as Record<string, unknown>;
  // A misspelled field ("contxt", "Context") would otherwise be dropped: its content never analysed,
  // and the verdict silently answering a different request than the caller meant.
  const unknown = Object.keys(obj).find((k) => !REQUEST_FIELDS.has(k));
  if (unknown !== undefined) return invalid(unknown.length <= 64 ? unknown : "body");
  // Every string must be well-formed Unicode: a lone surrogate cannot be canonicalized (RFC 8785),
  // so a client could never recompute request_hash.
  if (!wellFormed(obj)) return invalid("body");
  const subject = typeof obj.wallet === "string" ? parseSubject(obj.wallet) : null;
  if (typeof obj.wallet !== "string" || !subject) return invalid("wallet");
  // A CAIP-10 wallet's chain must be a canonical one too ("eip155:0008453" is refused).
  if (subject.caip2 && normalizeChain(subject.caip2)?.caip2 !== subject.caip2) return invalid("wallet");
  const req: RiskCheckRequest = { wallet: obj.wallet };

  if (obj.chain !== undefined) {
    const chain = typeof obj.chain === "string" ? normalizeChain(obj.chain) : null;
    if (!chain) return invalid("chain");
    // A chain that cannot hold the wallet ({wallet: 0x…, chain: "solana"}) would skip every chain-keyed check.
    if (!chainFits(subject, chain.caip2)) return invalid("chain");
    // A CAIP-10 wallet carries its own chain; a disagreeing `chain` would let the caller
    // pick which chain's on-chain facts are consulted.
    if (subject.caip2 && subject.caip2 !== chain.caip2) return invalid("chain");
    req.chain = chain.caip2;
  }
  if (obj.domain !== undefined) {
    const host = typeof obj.domain === "string" && obj.domain.length <= 2048 ? normalizeHost(obj.domain) : null;
    if (!host) return invalid("domain");
    req.domain = host;
  }
  const context = optionalString(obj, "context", MAX_FIELD_LEN.context);
  if (isInvalid(context)) return context;
  if (context !== undefined) req.context = context;
  const aud = optionalString(obj, "aud", MAX_FIELD_LEN.aud);
  if (isInvalid(aud)) return aud;
  if (aud !== undefined) req.aud = aud;

  if (obj.screening !== undefined) {
    const s = obj.screening as Record<string, unknown> | null;
    if (!s || typeof s !== "object" || Array.isArray(s) || Object.keys(s).some((k) => k !== "sanctions") || !(s.sanctions === "clean" || s.sanctions === "flagged" || s.sanctions === "unknown")) {
      return invalid("screening");
    }
    req.screening = { sanctions: s.sanctions };
  }
  if (obj.authorization !== undefined) {
    const a = obj.authorization as Record<string, unknown> | null;
    if (!a || typeof a !== "object" || Array.isArray(a) || Object.keys(a).some((k) => k !== "pre_authorized" && k !== "source") || typeof a.pre_authorized !== "boolean") return invalid("authorization");
    if (a.source !== undefined && (typeof a.source !== "string" || a.source.length > MAX_FIELD_LEN.source)) return invalid("authorization.source");
    req.authorization = { pre_authorized: a.pre_authorized, source: typeof a.source === "string" ? a.source : undefined };
  }
  if (obj.payment !== undefined) {
    const payment = validatePayment(obj.payment);
    if (isInvalid(payment)) return payment;
    const effective = subject.caip2 ?? req.chain;
    if (payment.network && effective && payment.network !== effective) return invalid("payment.network");
    // The payment's network must be able to hold the wallet checked: it becomes the verdict's chain
    // (2026-10-16 review: an EVM wallet "paid" on Solana skipped the chain-keyed checks).
    if (payment.network && !chainFits(subject, payment.network)) return invalid("payment.network");
    // The verdict covers the wallet: a payment to anyone else would be signed but never screened.
    if (payment.pay_to !== undefined && !sameSubject(payment.pay_to, String(obj.wallet))) return invalid("payment.pay_to");
    req.payment = payment;
  }
  if (obj.interaction !== undefined) {
    const interaction = validateInteraction(obj.interaction);
    if (isInvalid(interaction)) return interaction;
    req.interaction = interaction;
  }
  if (obj.transaction !== undefined) {
    const transaction = validateTransaction(obj.transaction);
    if (isInvalid(transaction)) return transaction;
    // Simulation needs to know which EVM chain to run on.
    const effective = subject.caip2 ?? req.chain;
    if (!effective || !effective.startsWith("eip155:")) return invalid("chain");
    req.transaction = transaction;
  }
  try {
    req.request_hash = requestHash(obj);
  } catch {
    // Values JSON can carry but RFC 8785 cannot canonicalize (1e400 → Infinity), or nesting too deep.
    return invalid("body");
  }
  return { ok: true, value: req };
}

export type BatchInvalid = { ok: false; status: 413 | 422; body: Record<string, unknown> };

/** All-or-nothing: results carry no wallet, so dropping an item would misalign results[i]. */
export function validateBatch(body: unknown): Valid<RiskCheckRequest[]> | BatchInvalid {
  if (!body || typeof body !== "object" || !Array.isArray((body as { requests?: unknown }).requests)) {
    return { ok: false, status: 422, body: { error: "invalid_request", field: "requests" } };
  }
  // A batch carries `requests` only: anything else is refused, as in a single request.
  const extra = Object.keys(body).find((k) => k !== "requests");
  if (extra !== undefined) return { ok: false, status: 422, body: { error: "invalid_request", field: extra.length <= 64 ? extra : "body" } };
  const raw = (body as { requests: unknown[] }).requests;
  if (raw.length === 0) return { ok: false, status: 422, body: { error: "invalid_request", field: "requests" } };
  if (raw.length > MAX_BATCH) return { ok: false, status: 413, body: { error: "batch_too_large", max: MAX_BATCH } };
  const out: RiskCheckRequest[] = [];
  for (let i = 0; i < raw.length; i++) {
    const r = validateRequest(raw[i]);
    if (!r.ok) return { ok: false, status: 422, body: { error: "invalid_request", field: r.field, index: i } };
    out.push(r.value);
  }
  return { ok: true, value: out };
}
