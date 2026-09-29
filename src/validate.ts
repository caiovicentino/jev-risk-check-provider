import { parseSubject } from "./address.js";
import { normalizeChain } from "./chains.js";
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
  if (typeof v !== "string" || v.length > max) return invalid(key);
  return v;
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
    if (typeof p.pay_to !== "string" || !parseSubject(p.pay_to)) return invalid("payment.pay_to");
    out.pay_to = p.pay_to;
  }
  if (p.amount !== undefined) {
    if (typeof p.amount !== "string" || !/^\d{1,78}$/.test(p.amount)) return invalid("payment.amount");
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

/** Validates and normalizes one request. chain → CAIP-2, domain → hostname. */
export function validateRequest(body: unknown): Valid<RiskCheckRequest> | Invalid {
  if (!body || typeof body !== "object" || Array.isArray(body)) return invalid("body");
  const obj = body as Record<string, unknown>;
  if (typeof obj.wallet !== "string" || !parseSubject(obj.wallet)) return invalid("wallet");
  const req: RiskCheckRequest = { wallet: obj.wallet };

  if (obj.chain !== undefined) {
    const chain = typeof obj.chain === "string" ? normalizeChain(obj.chain) : null;
    if (!chain) return invalid("chain");
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
    if (!s || typeof s !== "object" || Array.isArray(s) || !(s.sanctions === "clean" || s.sanctions === "flagged" || s.sanctions === "unknown")) {
      return invalid("screening");
    }
    req.screening = { sanctions: s.sanctions };
  }
  if (obj.authorization !== undefined) {
    const a = obj.authorization as Record<string, unknown> | null;
    if (!a || typeof a !== "object" || Array.isArray(a) || typeof a.pre_authorized !== "boolean") return invalid("authorization");
    if (a.source !== undefined && (typeof a.source !== "string" || a.source.length > MAX_FIELD_LEN.source)) return invalid("authorization.source");
    req.authorization = { pre_authorized: a.pre_authorized, source: typeof a.source === "string" ? a.source : undefined };
  }
  if (obj.payment !== undefined) {
    const payment = validatePayment(obj.payment);
    if (isInvalid(payment)) return payment;
    req.payment = payment;
  }
  if (obj.interaction !== undefined) {
    const interaction = validateInteraction(obj.interaction);
    if (isInvalid(interaction)) return interaction;
    req.interaction = interaction;
  }
  return { ok: true, value: req };
}

export type BatchInvalid = { ok: false; status: 413 | 422; body: Record<string, unknown> };

/** All-or-nothing: results carry no wallet, so dropping an item would misalign results[i]. */
export function validateBatch(body: unknown): Valid<RiskCheckRequest[]> | BatchInvalid {
  if (!body || typeof body !== "object" || !Array.isArray((body as { requests?: unknown }).requests)) {
    return { ok: false, status: 422, body: { error: "invalid_request", field: "requests" } };
  }
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
