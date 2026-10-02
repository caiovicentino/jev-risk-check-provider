import type { HTTPAdapter } from "@x402/core/http";
import { decodeSolanaMessage } from "../packages/client/src/solana.js";
import { parseSubject } from "../src/address.js";
import { screenSubject } from "../src/sanctions.js";
import { acquirePayerSlot, claimPayment, paymentIdentity, paymentVersion, RETENTION_MS, settlementIdentity } from "./payment-claims.js";
import type { WorkerEnv } from "./runtime.js";

// Small HTTP helpers shared by the paywall (deploy/protected.ts) and credits (deploy/credits.ts).

export function fetchAdapter(request: Request, body: unknown): HTTPAdapter {
  return {
    // x402 core reads the payment from here: only an x402 v2 PAYMENT-SIGNATURE is handed over, and
    // never the v1 X-PAYMENT header, so no payment reaches verification without passing the claim.
    getHeader: (name) => {
      const lower = name.toLowerCase();
      if (lower === "x-payment") return undefined;
      const value = request.headers.get(name) ?? undefined;
      if (lower === "payment-signature" && value !== undefined && paymentVersion(value) !== 2) return undefined;
      return value;
    },
    getMethod: () => request.method,
    getPath: () => new URL(request.url).pathname,
    getUrl: () => request.url,
    getAcceptHeader: () => request.headers.get("accept") ?? "*/*",
    getUserAgent: () => request.headers.get("user-agent") ?? "",
    getBody: () => body,
  };
}

export function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return Response.json(body, { status, headers });
}

/** Whether every evaluation in a 200 response was produced (checked: true): only then is anything charged. */
export async function allChecked(res: Response): Promise<boolean> {
  try {
    const body = (await res.json()) as { checked?: unknown; results?: Array<{ checked?: unknown }> };
    if (Array.isArray(body.results)) return body.results.length > 0 && body.results.every((r) => r.checked === true);
    return body.checked === true;
  } catch {
    return false;
  }
}

/** Reads a request body up to `max` bytes while streaming (null when larger: never fully buffered). */
export async function readCapped(request: Request, max: number): Promise<Uint8Array | null> {
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > max) return null;
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

/** The settlement receipt in a PAYMENT-RESPONSE header: network and transaction, when present. */
export function settlementReceipt(headers: Record<string, string>): { network: string; transaction: string } | null {
  const raw = headers["PAYMENT-RESPONSE"] ?? headers["payment-response"] ?? headers["X-PAYMENT-RESPONSE"];
  if (!raw) return null;
  try {
    const r = JSON.parse(atob(raw)) as { transaction?: unknown; network?: unknown };
    return typeof r.transaction === "string" && r.transaction ? { network: String(r.network ?? ""), transaction: r.transaction } : null;
  } catch {
    return null;
  }
}

/** Who pays: the EIP-3009 or Permit2 `from`, or the Solana transfer's authority (null when unknown). */
export function payerOf(paymentPayload: unknown): string | null {
  const p = (paymentPayload as { payload?: Record<string, unknown> } | null)?.payload;
  if (!p || typeof p !== "object") return null;
  const from = (p["authorization"] as { from?: unknown } | undefined)?.from ?? (p["permit2Authorization"] as { from?: unknown } | undefined)?.from;
  if (typeof from === "string") return from;
  const tx = p["transaction"];
  return typeof tx === "string" ? svmTransferAuthority(tx) : null;
}

const TOKEN_PROGRAMS = new Set(["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"]);

/** The authority of the (first) TransferChecked in a base64 wire transaction: the x402 SVM payer. */
function svmTransferAuthority(base64: string): string | null {
  try {
    const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
    // compact-u16 signature count, then 64 bytes per signature, then the message.
    let count = 0;
    let at = 0;
    for (let shift = 0; shift < 21; shift += 7) {
      const b = bytes[at++] as number;
      count |= (b & 0x7f) << shift;
      if ((b & 0x80) === 0) break;
    }
    const message = decodeSolanaMessage(bytes.subarray(at + 64 * count));
    for (const ix of message.instructions) {
      const program = message.staticAccounts[ix.programIndex];
      if (program && TOKEN_PROGRAMS.has(program) && ix.data[0] === 12) {
        const authority = message.staticAccounts[ix.accounts[3] ?? -1];
        if (authority) return authority;
      }
    }
  } catch {
    // Not a readable transaction: no payer.
  }
  return null;
}

/** Whether a payer is on the OFAC SDN list (exact address or the same key in another encoding). */
export function sanctionedPayer(payer: string | null): boolean {
  const subject = payer ? parseSubject(payer) : null;
  return !!subject && screenSubject(subject).status === "listed";
}

/**
 * Keeps a record of a settlement, for reconciliation against the pay_to transfers on-chain:
 * one KV entry per transaction (no token, no request data) and one log line.
 */
export async function recordSettlement(env: { RATE?: { put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void> } }, entry: { path: string; network: string; transaction: string; micro?: number }): Promise<void> {
  console.log(JSON.stringify({ event: "settlement", ...entry }));
  await env.RATE?.put(`st:${entry.network}:${entry.transaction}`, JSON.stringify({ at: new Date().toISOString(), path: entry.path, ...(entry.micro !== undefined ? { micro: entry.micro } : {}) }), { expirationTtl: 400 * 86400 }).catch((err: unknown) => console.error(`settlement record failed: ${String(err).slice(0, 120)}`));
}

/** Seconds an authorization must still be valid when it arrives: a settlement must be possible after the evaluation. */
const MIN_VALIDITY_S = 60;

/** When the signed authorization stops being settleable (EIP-3009 validBefore, Permit2 deadline), in seconds. */
function expiresAt(paymentPayload: unknown): number | null {
  const p = (paymentPayload as { payload?: Record<string, unknown> } | null)?.payload;
  const raw = (p?.["authorization"] as { validBefore?: unknown } | undefined)?.validBefore ?? (p?.["permit2Authorization"] as { deadline?: unknown } | undefined)?.deadline;
  const n = typeof raw === "string" || typeof raw === "number" ? Number(raw) : Number.NaN;
  return Number.isFinite(n) ? n : null;
}

/** How a paid request ended: its claim and the payer's slot are closed accordingly. */
export type PaymentOutcome = "settled" | "refused" | "unused";

export type Admission = { ok: true; id: string; finish: (outcome: PaymentOutcome) => Promise<void> } | { ok: false; response: Response };

/**
 * Admits a verified payment before any work is done for it:
 * - the payer is screened (no service is sold to an SDN-listed wallet);
 * - an authorization about to expire is refused (it could not settle after the evaluation), and
 *   one valid for longer than its claim is kept is refused too (single use for its whole validity);
 * - the payer may have only a few payments in flight, and is held back after repeated settlement failures;
 * - the payment is claimed once, by what its payer signed, however it is re-encoded.
 */
export async function admitPayment(env: WorkerEnv, paymentPayload: unknown): Promise<Admission> {
  const payer = payerOf(paymentPayload);
  if (sanctionedPayer(payer)) return { ok: false, response: json(403, { error: "payer_sanctioned", detail: "the paying wallet is on the OFAC SDN list; nothing was charged" }) };
  const expiry = expiresAt(paymentPayload);
  const now = Math.floor(Date.now() / 1000);
  if (expiry !== null && expiry < now + MIN_VALIDITY_S) {
    return { ok: false, response: json(402, { error: "authorization_expires_too_soon", detail: `sign an authorization valid for at least ${MIN_VALIDITY_S} s more; nothing was charged` }) };
  }
  if (expiry !== null && expiry > now + RETENTION_MS / 1000) {
    return { ok: false, response: json(402, { error: "authorization_valid_too_long", detail: "sign an authorization that expires within 24 hours (the challenge's maxTimeoutSeconds); nothing was charged" }) };
  }
  const slot = await acquirePayerSlot(env, payer);
  if (!slot.ok) {
    const detail = slot.reason === "failures" ? "recent payments from this wallet did not settle; retry later" : "too many payments from this wallet are in flight; retry shortly";
    return { ok: false, response: json(429, { error: slot.reason === "failures" ? "payer_settlement_failures" : "payer_busy", detail }, { "Retry-After": String(slot.retryAfter) }) };
  }
  const id = await paymentIdentity(paymentPayload);
  const claim = await claimPayment(env, id);
  if (!claim.claimed) {
    await slot.done(false);
    const response =
      claim.reason === "duplicate"
        ? json(409, { error: "payment_already_used", detail: "this payment was already presented; sign a new one" })
        : claim.reason === "unidentified"
          ? json(402, { error: "payment_unrecognized", detail: "the payment's scheme payload could not be identified; nothing was charged" })
          : json(503, { error: "payment_claims_unavailable", detail: "no charge: retry shortly" }, { "Retry-After": "5" });
    return { ok: false, response };
  }
  return {
    ok: true,
    id: id ?? "",
    finish: async (outcome) => {
      await (outcome === "settled" ? claim.settled() : claim.release());
      await slot.done(outcome === "refused");
    },
  };
}

/**
 * A settlement the payer is answerable for: a definitive refusal (funds moved, nonce used, expired),
 * not our facilitator failing (timeouts and unexpected errors never count against a payer).
 */
export function payerRefusal(reason: string | undefined): boolean {
  return !!reason && !/unexpected|timeout|unavailable|facilitator|network_error|internal/i.test(reason);
}

/**
 * True when this settlement transaction was already used for another verdict or credit pack
 * (a facilitator that confirms an identical transaction twice): the caller then releases nothing.
 */
export async function settlementReused(env: WorkerEnv, receipt: { network: string; transaction: string } | null): Promise<boolean> {
  if (!receipt) return false;
  const claim = await claimPayment(env, await settlementIdentity(receipt.network, receipt.transaction));
  if (claim.claimed) {
    await claim.settled();
    return false;
  }
  if (claim.reason === "unavailable") console.error("settlement claim unavailable: proceeding on the payment claim alone");
  return claim.reason === "duplicate";
}
