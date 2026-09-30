// Reference verifier for x402check attestations: the SDK's verifyAttestation behind a CLI.
//
//   npx tsx scripts/verify-attest.ts <jws> [options]
//
//   --request <json | @file>   the exact request body the verdict must answer: binds request_hash
//                              (and sub, aud, interaction, payment, domain, chain) to it
//   --max-age <seconds>        refuse a verdict older than this, plus the SDK's 300 s clock-skew
//                              allowance (without it, a reused verdict stays valid for its full hour)
//   --aud <url>                required audience        --sub <wallet>   expected subject
//   --interaction <type>       expected interaction     --issuer <did>   default did:web:x402check.xyz
//   --pay-to <addr> --amount <atomic> --network <caip2> --asset <addr>   expected payment binding
//   --pin <thumbprint,...>     accepted attestation keys (RFC 7638); default: x402check's published
//                              key for the default issuer. --no-pin accepts any key the DID assigns.
//
// Trust is pinned to the ISSUER you expect: the key is resolved from that issuer's did:web
// document, never from a URL carried in the response or the token. Exit code 0 = valid,
// 2 = invalid, 1 = usage, 3 = error.
import { readFileSync } from "node:fs";
import { verifyAttestation, type VerifyOptions } from "../packages/client/src/verify.js";
import { X402CHECK_KEY_THUMBPRINTS } from "../packages/client/src/keys.js";
import type { RiskCheckRequest } from "../packages/client/src/types.js";

const USAGE = "usage: tsx scripts/verify-attest.ts <jws> [--request <json|@file>] [--max-age s] [--aud url] [--sub wallet] [--interaction type] [--pay-to addr] [--amount n] [--network caip2] [--asset addr] [--issuer did] [--pin t1,t2 | --no-pin]";
const FLAGS = new Set(["request", "max-age", "aud", "sub", "interaction", "pay-to", "amount", "network", "asset", "issuer", "pin"]);

function parseArgs(argv: string[]): { jws: string; flags: Map<string, string>; noPin: boolean } {
  const [jws, ...rest] = argv;
  if (!jws || jws.startsWith("--")) throw new Error(USAGE);
  const flags = new Map<string, string>();
  let noPin = false;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i] as string;
    if (a === "--no-pin") {
      noPin = true;
      continue;
    }
    const name = a.startsWith("--") ? a.slice(2) : "";
    const value = rest[i + 1];
    if (!FLAGS.has(name) || value === undefined || value.startsWith("--")) throw new Error(`bad argument ${a}\n${USAGE}`);
    flags.set(name, value);
    i++;
  }
  return { jws, flags, noPin };
}

function readRequest(raw: string): RiskCheckRequest {
  const text = raw.startsWith("@") ? readFileSync(raw.slice(1), "utf8") : raw;
  const value = JSON.parse(text) as unknown;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("--request must be a JSON object (the body sent to /v1/risk-check)");
  return value as RiskCheckRequest;
}

async function main(): Promise<void> {
  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error((err as Error).message);
    process.exit(1);
  }
  const { jws, flags, noPin } = parsed;
  const issuer = flags.get("issuer") ?? "did:web:x402check.xyz";
  const maxAge = flags.get("max-age");
  if (maxAge !== undefined && !/^\d+$/.test(maxAge)) {
    console.error("--max-age takes whole seconds");
    process.exit(1);
  }
  const payment = Object.fromEntries(
    (
      [
        ["pay_to", flags.get("pay-to")],
        ["amount", flags.get("amount")],
        ["network", flags.get("network")],
        ["asset", flags.get("asset")],
      ] as const
    ).filter(([, v]) => v !== undefined),
  );
  const pin = flags.get("pin");
  const pinnedKeys = noPin ? undefined : pin ? pin.split(",").map((t) => t.trim()).filter(Boolean) : issuer === "did:web:x402check.xyz" ? X402CHECK_KEY_THUMBPRINTS : undefined;
  const options: VerifyOptions = {
    issuer,
    ...(flags.has("request") ? { request: readRequest(flags.get("request") as string) } : {}),
    ...(maxAge !== undefined ? { maxAgeSeconds: Number(maxAge) } : {}),
    ...(flags.has("aud") ? { aud: flags.get("aud") as string } : {}),
    ...(flags.has("sub") ? { sub: flags.get("sub") as string } : {}),
    ...(flags.has("interaction") ? { interaction: flags.get("interaction") as string } : {}),
    ...(Object.keys(payment).length ? { payment } : {}),
    ...(pinnedKeys ? { pinnedKeys } : {}),
  };
  const v = await verifyAttestation(jws, options);
  const c = v.claims;
  const bound = [
    ...(options.request ? ["request"] : []),
    ...(options.maxAgeSeconds !== undefined ? [`max-age ${options.maxAgeSeconds}s`] : []),
    ...(options.payment ? ["payment"] : []),
    ...(pinnedKeys ? ["pinned key"] : []),
  ];
  console.log(
    JSON.stringify(
      {
        valid: v.valid,
        failures: v.failures,
        issuer,
        bound_to: bound,
        kid: v.header?.kid,
        sub: c?.sub,
        score: c?.score,
        tier: c?.tier,
        categories: c?.categories,
        checks: c?.checks,
        asserted: c?.asserted,
        aud: c?.aud,
        payment: c?.payment,
        interaction: c?.interaction,
        jti: c?.jti,
        input_hash: c?.input_hash,
        request_hash: c?.request_hash,
        issued: typeof c?.iat === "number" ? new Date(c.iat * 1000).toISOString() : undefined,
        expires: typeof c?.exp === "number" ? new Date(c.exp * 1000).toISOString() : undefined,
        note: [
          ...(c?.asserted ? ["asserted fields were self-reported by the caller and NOT verified by the provider"] : []),
          ...(!options.request ? ["not bound to a request: pass --request with the exact body to reject a verdict issued for anything else"] : []),
          ...(options.maxAgeSeconds === undefined ? ["no --max-age: a verdict stays valid for its full hour"] : []),
        ],
      },
      null,
      2,
    ),
  );
  if (!v.valid) process.exit(2);
}

main().catch((err) => {
  console.error(String(err));
  process.exit(3);
});
