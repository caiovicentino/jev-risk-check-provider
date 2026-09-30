import type { HTTPAdapter } from "@x402/core/http";
import { decodeSolanaMessage } from "../packages/client/src/solana.js";
import { parseSubject } from "../src/address.js";
import { screenSubject } from "../src/sanctions.js";

// Small HTTP helpers shared by the paywall (deploy/protected.ts) and credits (deploy/credits.ts).

export function fetchAdapter(request: Request, body: unknown): HTTPAdapter {
  return {
    getHeader: (name) => request.headers.get(name) ?? undefined,
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
