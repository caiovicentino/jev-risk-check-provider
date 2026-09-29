// Reference verifier for x402check attestations.
//
//   npx tsx scripts/verify-attest.ts <jws> [--issuer did:web:x402check.xyz] [--aud <url>] [--sub <wallet>]
//
// Trust is pinned to the ISSUER you expect: the key is resolved from that issuer's
// did:web document, never from a URL carried in the response or the token.
import { createPublicKey, createVerify, type JsonWebKey } from "node:crypto";
import { sameSubject } from "../src/address.js";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 ? process.argv[i + 1] : undefined;
}

function decode(part: string | undefined): Record<string, unknown> | null {
  if (!part) return null;
  try {
    return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>;
  } catch {
    return null;
  }
}

async function resolveKeys(issuer: string): Promise<Array<JsonWebKey & { kid?: string }>> {
  const m = issuer.match(/^did:web:([a-z0-9.-]+(?:%3A\d+)?)$/i);
  if (!m) throw new Error(`unsupported issuer ${issuer} (expected did:web:<host>)`);
  const host = decodeURIComponent(m[1] as string);
  const res = await fetch(`https://${host}/.well-known/did.json`);
  if (!res.ok) throw new Error(`did document fetch failed: HTTP ${res.status}`);
  const doc = (await res.json()) as { id?: string; verificationMethod?: Array<{ id?: string; publicKeyJwk?: JsonWebKey & { kid?: string } }>; assertionMethod?: string[] };
  if (doc.id !== issuer) throw new Error(`did document id ${doc.id} != ${issuer}`);
  const assertion = new Set(doc.assertionMethod ?? []);
  return (doc.verificationMethod ?? []).filter((vm) => vm.id && assertion.has(vm.id) && vm.publicKeyJwk).map((vm) => vm.publicKeyJwk as JsonWebKey & { kid?: string });
}

async function main(): Promise<void> {
  const jws = process.argv[2];
  if (!jws || jws.startsWith("--")) {
    console.error("usage: tsx scripts/verify-attest.ts <jws> [--issuer did:web:host] [--aud url] [--sub wallet]");
    process.exit(1);
  }
  const issuer = arg("issuer") ?? "did:web:x402check.xyz";
  const [h, p, s] = jws.split(".");
  const header = decode(h);
  const payload = decode(p);
  if (!header || !payload || !s || jws.split(".").length !== 3) {
    console.log(JSON.stringify({ valid: false, reason: "malformed_jws" }));
    process.exit(2);
  }
  const keys = await resolveKeys(issuer);
  const jwk = keys.find((k) => k.kid === header.kid);
  const now = Math.floor(Date.now() / 1000);
  const failures: string[] = [];
  if (header.alg !== "ES256") failures.push("alg_not_es256");
  if (header.typ !== "risk-check+jwt") failures.push("unexpected_typ");
  if (!jwk) failures.push("kid_not_in_issuer_did_document");
  let signatureValid = false;
  if (jwk && header.alg === "ES256") {
    signatureValid = createVerify("SHA256")
      .update(`${h}.${p}`)
      .verify({ key: createPublicKey({ key: jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url"));
    if (!signatureValid) failures.push("signature_invalid");
  }
  if (payload.iss !== issuer) failures.push("issuer_mismatch");
  if (typeof payload.exp !== "number" || payload.exp <= now) failures.push("expired_or_missing_exp");
  if (typeof payload.iat !== "number" || payload.iat > now + 300) failures.push("iat_in_future");
  const aud = arg("aud");
  if (aud !== undefined && payload.aud !== aud) failures.push("audience_mismatch");
  const sub = arg("sub");
  if (sub !== undefined) {
    // Canonical comparison: EVM/bech32/cashaddr are case-insensitive, base58 (Solana,
    // Tron, BTC legacy) is case-SENSITIVE — a case-flipped base58 string is another address.
    if (!sameSubject(sub, String(payload.sub))) failures.push("subject_mismatch");
  }
  const valid = failures.length === 0;
  console.log(
    JSON.stringify(
      {
        valid,
        failures,
        signature_valid: signatureValid,
        issuer,
        kid: header.kid,
        sub: payload.sub,
        score: payload.score,
        tier: payload.tier,
        categories: payload.categories,
        checks: payload.checks,
        asserted: payload.asserted,
        aud: payload.aud,
        payment: payload.payment,
        jti: payload.jti,
        input_hash: payload.input_hash,
        expires: typeof payload.exp === "number" ? new Date(payload.exp * 1000).toISOString() : undefined,
        note: payload.asserted ? "asserted fields were self-reported by the caller and NOT verified by the provider" : undefined,
      },
      null,
      2,
    ),
  );
  if (!valid) process.exit(2);
}

main().catch((err) => {
  console.error(String(err));
  process.exit(3);
});
