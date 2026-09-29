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
const jwk = jwks.keys.find((k) => k.kid === header.kid) ?? jwks.keys[0];
const key = createPublicKey({ key: jwk as never, format: "jwk" });
const sig = Buffer.from(s, "base64url");
const ok = createVerify("SHA256").update(`${h}.${p}`).verify({ key, dsaEncoding: "ieee-p1363" }, sig);
console.log(
  JSON.stringify(
    {
      valid: ok,
      alg: header.alg,
      kid: header.kid,
      iss: payload.iss,
      sub: payload.sub,
      score: payload.score,
      tier: payload.tier,
      input_hash: payload.input_hash,
      expires: payload.exp ? new Date(payload.exp * 1000).toISOString() : undefined,
    },
    null,
    2,
  ),
);
if (!ok) process.exit(2);
