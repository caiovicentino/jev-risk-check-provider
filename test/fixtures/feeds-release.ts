// A signed feeds release for tests (the shape scripts/publish-feeds.ts writes), served by a fake
// fetch, plus a memory KV. The signing key is generated per process.
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { buildHashBlob } from "../../src/threat-intel.js";
import { OFAC_SDN_ADDRESSES, OFAC_SDN_META } from "../../src/data/ofac-sdn.js";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
export const TEST_PUBLIC_KEY = publicKey.export({ format: "jwk" }).x as string;
export const NEW_SANCTIONED = "0x9999999999999999999999999999999999999999";
/** One day after the embedded OFAC snapshot. */
export const OFAC_NEXT = new Date(Date.parse(`${OFAC_SDN_META.publish_date}T00:00:00Z`) + 86_400_000).toISOString().slice(0, 10);
export const EMBEDDED = { metamaskAsOf: "2026-01-01", metamaskEntries: 150, ofacRows: OFAC_SDN_META.addresses };
const sha = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");

export function release(ofacDate = OFAC_NEXT) {
  const bin = buildHashBlob(Array.from({ length: 200 }, (_, i) => `phish-${i}.example`));
  const mmJson = JSON.stringify({ meta: { as_of: "2026-01-02" }, allowlist: [] });
  const rows = [...OFAC_SDN_ADDRESSES, [NEW_SANCTIONED, "ETH", 1, "TEST ENTITY"] as const];
  const ofacJson = JSON.stringify({ meta: { source: "test" }, rows });
  const manifest = JSON.stringify({
    format: 1,
    generated_at: "2026-10-03T11:00:00Z",
    metamask: { as_of: "2026-01-02", entries: bin.byteLength / 8, bin_sha256: sha(bin), json_sha256: sha(mmJson) },
    ofac: { publish_date: ofacDate, addresses: rows.length, json_sha256: sha(ofacJson) },
  });
  const sig = sign(null, Buffer.from(manifest), privateKey).toString("base64url");
  const files: Record<string, Uint8Array | string> = { "manifest.json": manifest, "manifest.sig": sig, "metamask-phishing.bin": bin, "metamask.json": mmJson, "ofac-sdn.json": ofacJson };
  const fetched: string[] = [];
  const fetchImpl = (async (url: string) => {
    const name = new URL(url).pathname.slice(1);
    fetched.push(name);
    const body = files[name];
    return body === undefined ? new Response("nope", { status: 404 }) : new Response(typeof body === "string" ? body : new Uint8Array(body));
  }) as unknown as typeof fetch;
  return { manifest, sig, ofacJson, fetchImpl, fetched };
}

export function memoryKv() {
  const data = new Map<string, string>();
  const puts: string[] = [];
  return {
    data,
    puts,
    get: async (key: string) => data.get(key) ?? null,
    put: async (key: string, value: string) => {
      puts.push(key);
      data.set(key, value);
    },
  };
}

/** A fetch that never answers (a network that hangs). */
export const hangingFetch = (() => new Promise<Response>(() => undefined)) as unknown as typeof fetch;
