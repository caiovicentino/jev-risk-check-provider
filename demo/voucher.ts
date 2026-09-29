import { sign as edSign, verify as edVerify, generateKeyPairSync } from "node:crypto";

export type Voucher = {
  resource: string;
  payTo: string;
  amount: string;
  nonce: string;
  ts: number;
  payer: string;
};

export function genPayerKey(): { privatePem: string; publicPem: string; payerId: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const pub = publicKey.export({ format: "pem", type: "spki" }).toString();
  const raw = publicKey.export({ format: "der", type: "spki" });
  // EVM-shaped payer id (0x + 20 bytes) so it passes the provider's address validation.
  const payerId = `0x${raw.subarray(-32).toString("hex").slice(0, 40)}`;
  return { privatePem: priv, publicPem: pub, payerId };
}

function canonical(v: Voucher): string {
  return JSON.stringify(v, ["resource", "payTo", "amount", "nonce", "ts", "payer"]);
}

export function signVoucher(v: Voucher, privatePem: string): string {
  return edSign(null, Buffer.from(canonical(v)), { key: privatePem, format: "pem", type: "pkcs8" }).toString("base64");
}

export function verifyVoucher(v: Voucher, signature: string, publicPem: string, maxAgeMs = 60_000): { ok: boolean; reason?: string } {
  const ok = edVerify(null, Buffer.from(canonical(v)), { key: publicPem, format: "pem", type: "spki" }, Buffer.from(signature, "base64"));
  if (!ok) return { ok: false, reason: "invalid_signature" };
  if (Date.now() - v.ts > maxAgeMs) return { ok: false, reason: "stale_voucher" };
  return { ok: true };
}
