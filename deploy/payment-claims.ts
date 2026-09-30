// Single use of a payment. Each x402 payment payload is claimed once, after it verifies and
// before it is evaluated: concurrent or repeated copies of the same PAYMENT-SIGNATURE get a
// 409 instead of N evaluations, N settlements or N credit tokens. Correctness no longer rests
// on every facilitator refusing a duplicate settle (identical Solana transactions share one
// signature, so each settle call could confirm it).
//
// One Durable Object per payment, named by the SHA-256 of its network and scheme payload:
// every operation on one payment is serialized. A claim is released when nothing was settled
// (the payer may retry with the same payment) and kept for a day once it settles.
import type { DurableObjectState, WorkerEnv } from "./runtime.js";

const RETENTION_MS = 24 * 60 * 60 * 1000;

export class PaymentClaim {
  constructor(private readonly state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const op = new URL(request.url).pathname.slice(1);
    const current = await this.state.storage.get<{ state: "pending" | "settled"; at: number }>("claim");
    if (op === "claim") {
      if (current) return Response.json({ claimed: false, state: current.state }, { status: 409 });
      await this.state.storage.put("claim", { state: "pending", at: Date.now() });
      await this.state.storage.setAlarm(Date.now() + RETENTION_MS);
      return Response.json({ claimed: true });
    }
    if (op === "settled") {
      await this.state.storage.put("claim", { state: "settled", at: Date.now() });
      return Response.json({ ok: true });
    }
    if (op === "release") {
      if (current?.state === "pending") await this.state.storage.delete("claim");
      return Response.json({ ok: true });
    }
    return Response.json({ error: "not_found" }, { status: 404 });
  }

  async alarm(): Promise<void> {
    await this.state.storage.deleteAll();
  }
}

/** A payment's identity: SHA-256 of its network and scheme payload (the signed authorization or transaction). */
export async function paymentId(header: string | null): Promise<string | null> {
  if (!header) return null;
  let decoded: { accepted?: { network?: unknown }; payload?: unknown };
  try {
    decoded = JSON.parse(atob(header)) as typeof decoded;
  } catch {
    return null;
  }
  if (!decoded || typeof decoded !== "object" || decoded.payload === undefined) return null;
  const material = `${String(decoded.accepted?.network ?? "")}|${JSON.stringify(decoded.payload)}`;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(material)));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** The x402 protocol version a PAYMENT-SIGNATURE declares (null when it does not decode). */
export function paymentVersion(header: string | null): number | null {
  if (!header) return null;
  try {
    const v = (JSON.parse(atob(header)) as { x402Version?: unknown }).x402Version;
    return typeof v === "number" ? v : null;
  } catch {
    return null;
  }
}

export type Claim = { claimed: true; settled: () => Promise<void>; release: () => Promise<void> } | { claimed: false; reason: "duplicate" | "unavailable" };

/**
 * Claims a payment. Without the Durable Object binding (local development, tests) every payment
 * is claimable; with it, a failure to reach the object refuses the payment (no double spend).
 */
export async function claimPayment(env: WorkerEnv, id: string | null): Promise<Claim> {
  const ns = env.PAYMENT_CLAIMS;
  if (!ns || !id) return { claimed: true, settled: async () => undefined, release: async () => undefined };
  const stub = ns.get(ns.idFromName(id));
  const call = (op: string) => stub.fetch(`https://claims/${op}`, { method: "POST" });
  try {
    const res = await call("claim");
    if (res.status === 409) return { claimed: false, reason: "duplicate" };
    if (!res.ok) return { claimed: false, reason: "unavailable" };
  } catch {
    return { claimed: false, reason: "unavailable" };
  }
  return {
    claimed: true,
    settled: async () => {
      await call("settled").catch((err: unknown) => console.error(`payment claim: settled mark failed: ${String(err).slice(0, 120)}`));
    },
    release: async () => {
      await call("release").catch((err: unknown) => console.error(`payment claim: release failed: ${String(err).slice(0, 120)}`));
    },
  };
}
