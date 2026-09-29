import { createPublicKey, createVerify } from "node:crypto";

const jws = process.argv[2];
if (!jws) {
  console.error("usage: tsx scripts/verify-attest.ts <jws>");
  process.exit(1);
}
const [h, p, s] = jws.split(".");
const header = JSON.parse(Buffer.from(h, "base64url").toString());
const payload = JSON.parse(Buffer.from(p, "base64url").toString());
const jwksUrl = process.env.JWKS_URL ?? "https://x402check.xyz/.well-known/jwks.json";
const res = await fetch(jwksUrl);
if (!res.ok) {
  console.error(`jwks fetch failed: ${res.status}`);
  process.exit(3);
}
const jwks = (await res.json()) as { keys: Array<Record<string, unknown>> };
// No fallback key and no algorithm other than ES256: a verdict is only valid if its
// kid is published, the signature checks out, and it has not expired.
const jwk = jwks.keys.find((k) => k.kid === header.kid);
const sigOk =
  header.alg === "ES256" && !!jwk &&
  createVerify("SHA256").update(`${h}.${p}`).verify({ key: createPublicKey({ key: jwk as never, format: "jwk" }), dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url"));
const expired = typeof payload.exp !== "number" || payload.exp <= Math.floor(Date.now() / 1000);
const ok = sigOk && !expired;
console.log(
  JSON.stringify(
    {
      valid: ok,
      signature_valid: sigOk,
      expired,
      alg: header.alg,
      kid: header.kid,
      iss: payload.iss,
      sub: payload.sub,
      score: payload.score,
      tier: payload.tier,
      input_hash: payload.input_hash,
      asserted: payload.asserted,
      expires: payload.exp ? new Date(payload.exp * 1000).toISOString() : undefined,
    },
    null,
    2,
  ),
);
if (!ok) process.exit(2);
