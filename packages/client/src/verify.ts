import { base64UrlToBytes, decodeJsonSegment, isRecord, parseJson } from "./encoding.js";
import { normalizeHost, toCaip2 } from "./normalize.js";
import { requestHash } from "./request-hash.js";
import { parseSubject, sameSubject } from "./subject.js";
import { defaultFetch, exchange } from "./transport.js";
import type { AttestationClaims, FetchLike, JwsHeader, PaymentBinding, RiskCheckRequest } from "./types.js";
import { RISK_TIERS } from "./types.js";

export const DEFAULT_ISSUER = "did:web:x402check.xyz";
export const ATTESTATION_TYP = "risk-check+jwt";
/** Tolerated clock skew for `iat`, `nbf` and `maxAgeSeconds`, in seconds. `exp` gets none: expired is expired. */
export const MAX_CLOCK_SKEW_SECONDS = 300;
export const DID_CACHE_TTL_MS = 5 * 60 * 1000;
/** An unknown `kid` refreshes a cached DID document at most this often (key rotation). */
export const DID_REFRESH_COOLDOWN_MS = 30 * 1000;
const DEFAULT_DID_TIMEOUT_MS = 10_000;
const MAX_TIMER_MS = 2_147_483_647;

export type VerificationFailure =
  /** No attestation at all (e.g. a checked result without `jws`): nothing to trust. */
  | "missing_attestation"
  /** Not three non-empty canonical base64url segments whose header and payload are JSON objects. */
  | "malformed_jws"
  /** Header `alg` is not ES256 (e.g. "none", "HS256"): the signature is not even checked. */
  | "alg_not_es256"
  /** Header `typ` is not "risk-check+jwt". */
  | "unexpected_typ"
  /** Header carries `crit` or `b64` (unsupported extensions). */
  | "unsupported_header"
  | "missing_kid"
  /** The expected issuer is not a resolvable did:web DID. */
  | "unsupported_issuer"
  /** The issuer's DID document could not be fetched or parsed. */
  | "did_resolution_failed"
  /** The DID document's `id` is not the expected issuer. */
  | "did_document_id_mismatch"
  /** No verification method in the issuer's DID document matches `kid`. */
  | "unknown_kid"
  /** The key exists but is not referenced by `assertionMethod`. */
  | "kid_not_in_assertion_method"
  /** The key is not a usable EC P-256 signing key. */
  | "unsupported_key"
  /** The key is valid in the DID document but is not one of `pinnedKeys`. */
  | "key_not_pinned"
  /** `crypto.subtle` is not available in this runtime. */
  | "webcrypto_unavailable"
  | "signature_invalid"
  /** `iss` is not the expected issuer. */
  | "issuer_mismatch"
  | "missing_exp"
  | "expired"
  | "missing_iat"
  /** `iat` more than 5 minutes in the future. */
  | "iat_in_future"
  /** `nbf` more than 5 minutes in the future. */
  | "not_yet_valid"
  /** `now` is not a valid time: nothing time-based can be checked. */
  | "invalid_time"
  /** `sub`, `score` or `tier` missing or of the wrong type. */
  | "invalid_claims"
  | "audience_mismatch"
  | "subject_mismatch"
  /** The `interaction` claim is not the expected one. */
  | "interaction_mismatch"
  /** The `payment` claim does not carry the expected payment fields. */
  | "payment_mismatch"
  /** The signed `checks.domain.host` is not the request's (normalized) domain. */
  | "domain_mismatch"
  /** The signed `checks.onchain.network` is not the request's chain. */
  | "chain_mismatch"
  /** The request carried a transaction but no simulation was signed (or the reverse). */
  | "transaction_mismatch"
  /** The signed `request_hash` is not the hash of the request that was sent: a field was altered or dropped. */
  | "request_mismatch"
  /** Issued longer ago than `maxAgeSeconds` (plus the clock-skew allowance). */
  | "stale";

export interface VerifyOptions {
  /** The issuer you trust (the key is resolved from ITS did:web document). Default "did:web:x402check.xyz". */
  issuer?: string | undefined;
  /**
   * The request this attestation must answer: the object passed to `check()` (for a batch, the
   * item). Use it when you verify a check you just made.
   * - When the provider signs `request_hash`, it must equal the hash of this request (see
   *   `requestHash`): every field as sent is bound, `context` and `interaction.unlimited`
   *   included. An older provider without the claim skips this check.
   * - Always: `sub` (wallet), `aud`, `interaction` type, `payment`, the domain analyzed, the chain
   *   whose on-chain facts were used, and whether a transaction was simulated. A field absent
   *   from the request must be absent from the claims.
   */
  request?: RiskCheckRequest | undefined;
  /** Required audience: fails unless the token's `aud` equals (or contains) it. `null`: the token must carry no `aud`. */
  aud?: string | null | undefined;
  /** Expected subject: compared with the provider's canonical rules (`sameSubject`). */
  sub?: string | undefined;
  /** Expected `interaction` claim (e.g. "permit_signature"). `null`: the token must carry none. */
  interaction?: string | null | undefined;
  /**
   * Expected payment binding: every field given must match the signed `payment` claim (`pay_to` by
   * `sameSubject`, `network` after alias normalization, other fields exactly as submitted).
   * `null`: the token must carry no payment.
   */
  payment?: PaymentBinding | null | undefined;
  /** Maximum age (now − iat) in seconds, e.g. 300 when verifying a check you just made (limits replay). */
  maxAgeSeconds?: number | undefined;
  /** Verification time: a Date or epoch milliseconds (as `Date.now()`). Default now. */
  now?: Date | number | undefined;
  /** Fetch used for the DID document. Pass a stable reference: the 5-minute cache is keyed by it. */
  fetch?: FetchLike | undefined;
  /** DID document fetch timeout. Default 10000 ms. */
  timeoutMs?: number | undefined;
  /**
   * RFC 7638 SHA-256 thumbprints (base64url) of the attestation keys you accept, e.g.
   * `X402CHECK_KEY_THUMBPRINTS`. A key outside the list fails with `key_not_pinned`, even when
   * the issuer's DID document serves it: whoever controls the issuer's domain or deployment
   * cannot swap in their own key. Unset: any key the DID document assigns.
   */
  pinnedKeys?: readonly string[] | undefined;
}

interface VerificationCommon {
  /** Stable failure codes; empty when valid. */
  failures: VerificationFailure[];
  /** The issuer the token was checked against. */
  issuer: string;
  /** DID URL of the verification method whose key verified the signature. */
  verificationMethod?: string;
}

/** Every check passed: `claims` can be relied on. */
export interface ValidVerification extends VerificationCommon {
  valid: true;
  claims: AttestationClaims;
  header: JwsHeader;
}

/** At least one check failed. `claims` is the decoded payload, UNTRUSTED (null when undecodable). */
export interface InvalidVerification extends VerificationCommon {
  valid: false;
  claims: AttestationClaims | null;
  header: JwsHeader | null;
}

/** Narrow on `valid`: after `if (!v.valid) …`, `v.claims` is non-null and trusted. */
export type VerificationResult = ValidVerification | InvalidVerification;

// ---------------------------------------------------------------------------
// did:web resolution
// ---------------------------------------------------------------------------

const DID_WEB = /^did:web:([A-Za-z0-9.-]+(?:%3[Aa][0-9]{1,5})?)((?::[A-Za-z0-9._~-]+)*)$/;

/**
 * The HTTPS URL of a did:web DID document (did:web method spec): `did:web:example.com` →
 * `https://example.com/.well-known/did.json`; `did:web:example.com:a:b` →
 * `https://example.com/a/b/did.json`; a port is encoded as `%3A`. Null when not did:web.
 */
export function didWebDocumentUrl(did: string): string | null {
  if (typeof did !== "string") return null;
  const m = DID_WEB.exec(did);
  if (!m) return null;
  const hostPort = (m[1] as string).replace(/%3a/i, ":");
  const host = hostPort.split(":")[0] as string;
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$/.test(host)) return null;
  const path = m[2] ? `${(m[2] as string).slice(1).split(":").join("/")}/did.json` : ".well-known/did.json";
  return `https://${hostPort}/${path}`;
}

type DidDocument = Record<string, unknown>;
type CacheEntry = { fetchedAt: number; doc: Promise<DidDocument> };

// Keyed by fetch implementation so independent fetch stacks (and tests) never share entries.
let didCache = new WeakMap<FetchLike, Map<string, CacheEntry>>();

/** Drops every cached DID document (e.g. right after a key rotation). */
export function clearDidCache(): void {
  didCache = new WeakMap();
}

async function fetchDidDocument(url: string, fetchImpl: FetchLike, timeoutMs: number): Promise<DidDocument> {
  const { res, text } = await exchange(fetchImpl, url, { method: "GET", headers: { Accept: "application/did+json, application/json" } }, timeoutMs);
  if (res.status !== 200) throw new Error(`DID document fetch failed: HTTP ${res.status}`);
  const doc = parseJson(text);
  if (!isRecord(doc)) throw new Error("DID document is not a JSON object");
  return doc;
}

/**
 * The cached DID document, fetched when missing, expired, or fetched before `staleBefore`.
 * Concurrent callers share one in-flight request; failures are not cached.
 */
function loadDidDocument(url: string, fetchImpl: FetchLike, timeoutMs: number, staleBefore = 0): CacheEntry {
  let perFetch = didCache.get(fetchImpl);
  if (!perFetch) {
    perFetch = new Map();
    didCache.set(fetchImpl, perFetch);
  }
  const now = Date.now();
  const hit = perFetch.get(url);
  if (hit && hit.fetchedAt + DID_CACHE_TTL_MS > now && hit.fetchedAt >= staleBefore) return hit;
  const entry: CacheEntry = { fetchedAt: now, doc: fetchDidDocument(url, fetchImpl, timeoutMs) };
  perFetch.set(url, entry);
  const map = perFetch;
  entry.doc.catch(() => {
    if (map.get(url) === entry) map.delete(url);
  });
  return entry;
}

type P256Jwk = { kty: "EC"; crv: "P-256"; x: string; y: string };

function usableP256Jwk(jwk: unknown): P256Jwk | null {
  if (!isRecord(jwk) || jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") return null;
  if (jwk.alg !== undefined && jwk.alg !== "ES256") return null;
  if (jwk.use !== undefined && jwk.use !== "sig") return null;
  if (jwk.key_ops !== undefined && !(Array.isArray(jwk.key_ops) && jwk.key_ops.includes("verify"))) return null;
  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
}

type KeySelection = { jwk: P256Jwk; id: string } | { failure: VerificationFailure };

/**
 * Picks the key for `kid` from the issuer's DID document. Only verification methods referenced
 * (or embedded) in `assertionMethod` may sign attestations. `kid` may be an absolute DID URL,
 * a fragment ("#key") or a bare name matched against the DID URL fragment (or, failing that,
 * the JWK's own `kid`).
 */
export function selectAssertionKey(doc: Record<string, unknown>, did: string, kid: string): KeySelection {
  const absolute = (ref: string): string => (ref.startsWith("#") ? `${did}${ref}` : ref);
  const wanted = kid.startsWith("did:") ? kid : kid.startsWith("#") ? `${did}${kid}` : `${did}#${kid}`;
  const methods: Array<{ id: string; jwk: unknown }> = [];
  const authorized = new Set<string>();
  for (const vm of Array.isArray(doc.verificationMethod) ? doc.verificationMethod : []) {
    if (isRecord(vm) && typeof vm.id === "string") methods.push({ id: absolute(vm.id), jwk: vm.publicKeyJwk });
  }
  for (const ref of Array.isArray(doc.assertionMethod) ? doc.assertionMethod : []) {
    if (typeof ref === "string") authorized.add(absolute(ref));
    else if (isRecord(ref) && typeof ref.id === "string") {
      const id = absolute(ref.id);
      authorized.add(id);
      methods.push({ id, jwk: ref.publicKeyJwk });
    }
  }
  const byId = methods.filter((m) => m.id === wanted);
  const candidates = byId.length > 0 ? byId : methods.filter((m) => isRecord(m.jwk) && m.jwk.kid === kid);
  if (candidates.length === 0) return { failure: "unknown_kid" };
  const allowed = candidates.find((m) => authorized.has(m.id));
  if (!allowed) return { failure: "kid_not_in_assertion_method" };
  const jwk = usableP256Jwk(allowed.jwk);
  return jwk ? { jwk, id: allowed.id } : { failure: "unsupported_key" };
}

/** RFC 7638 SHA-256 thumbprint (base64url) of an EC P-256 public JWK. */
export async function jwkThumbprint(jwk: { crv: string; kty: string; x: string; y: string }): Promise<string> {
  const canonical = `{"crv":${JSON.stringify(jwk.crv)},"kty":${JSON.stringify(jwk.kty)},"x":${JSON.stringify(jwk.x)},"y":${JSON.stringify(jwk.y)}}`;
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical)));
  let binary = "";
  for (const b of digest) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function verifyEs256(jwk: P256Jwk, signingInput: string, signature: Uint8Array<ArrayBuffer>): Promise<VerificationFailure | null> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return "webcrypto_unavailable";
  // Typed from WebCrypto itself: the DOM `CryptoKey` name is absent in Node-only type setups.
  let key: Awaited<ReturnType<typeof subtle.importKey>>;
  try {
    key = await subtle.importKey("jwk", { ...jwk, ext: true }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  } catch {
    return "unsupported_key";
  }
  // ES256 signatures are the 64-byte IEEE P1363 r||s form (RFC 7518 §3.4), which is also
  // WebCrypto's format; a DER-encoded signature is invalid here.
  if (signature.length !== 64) return "signature_invalid";
  try {
    const ok = await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, new TextEncoder().encode(signingInput));
    return ok ? null : "signature_invalid";
  } catch {
    return "signature_invalid";
  }
}

// ---------------------------------------------------------------------------
// Claim binding
// ---------------------------------------------------------------------------

function isFiniteNumber(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

function audienceMatches(aud: unknown, expected: string | null): boolean {
  if (expected === null) return aud === undefined;
  return typeof aud === "string" ? aud === expected : Array.isArray(aud) && aud.includes(expected);
}

const PAYMENT_FIELDS = ["network", "pay_to", "amount", "asset", "resource"] as const;

function paymentMatches(claim: unknown, expected: PaymentBinding | null): boolean {
  if (expected === null) return claim === undefined;
  const fields = PAYMENT_FIELDS.filter((k) => typeof expected[k] === "string");
  if (fields.length === 0) return true;
  if (!isRecord(claim)) return false;
  return fields.every((key) => {
    const want = expected[key] as string;
    const got = claim[key];
    if (typeof got !== "string") return false;
    if (key === "pay_to") return sameSubject(want, got);
    if (key === "network") {
      const caip2 = toCaip2(want);
      return caip2 === null ? true : got === caip2; // an alias this client does not know: not comparable
    }
    return got === want;
  });
}

const UNKNOWN = Symbol("unknown");

/** The CAIP-2 network the provider used for on-chain facts, as it derives it from the request. */
function expectedNetwork(request: RiskCheckRequest): string | null | typeof UNKNOWN {
  const fromWallet = parseSubject(request.wallet)?.caip2;
  if (fromWallet) return fromWallet;
  if (request.chain === undefined) return null;
  return toCaip2(request.chain) ?? UNKNOWN;
}

function hasPayment(payment: PaymentBinding | undefined): payment is PaymentBinding {
  return !!payment && PAYMENT_FIELDS.some((k) => typeof payment[k] === "string");
}

function requestFailures(c: Record<string, unknown>, request: RiskCheckRequest): VerificationFailure[] {
  const out: VerificationFailure[] = [];
  if (!(typeof c.sub === "string" && typeof request.wallet === "string" && sameSubject(request.wallet, c.sub))) out.push("subject_mismatch");
  if (!audienceMatches(c.aud, request.aud ?? null)) out.push("audience_mismatch");
  if ((c.interaction ?? null) !== (request.interaction?.type ?? null)) out.push("interaction_mismatch");
  if (!paymentMatches(c.payment, hasPayment(request.payment) ? request.payment : null)) out.push("payment_mismatch");

  const checks = isRecord(c.checks) ? c.checks : {};
  const wantHost = request.domain === undefined ? null : normalizeHost(request.domain);
  const gotHost = isRecord(checks.domain) && typeof checks.domain.host === "string" ? checks.domain.host : null;
  if (wantHost !== gotHost) out.push("domain_mismatch");

  const wantNetwork = expectedNetwork(request);
  const gotNetwork = isRecord(checks.onchain) && typeof checks.onchain.network === "string" ? checks.onchain.network : null;
  if (wantNetwork !== UNKNOWN && wantNetwork !== gotNetwork) out.push("chain_mismatch");

  // A deterministic sanctions verdict ("skipped" model) runs nothing else, simulation included.
  const simulated = isRecord(checks.simulation);
  const shortCircuit = checks.model === "skipped";
  if (request.transaction !== undefined ? !simulated && !shortCircuit : simulated) out.push("transaction_mismatch");
  return out;
}

/**
 * Verifies an x402check attestation (compact JWS, ES256) with WebCrypto.
 *
 * Trust is pinned to the ISSUER you expect: the key comes from that issuer's did:web document
 * (`https://<host>/.well-known/did.json`, cached 5 minutes), never from `jwks_url`, a `jku`/`jwk`
 * header, or anything else carried by a response or the token. Never throws.
 *
 * @example
 * // A check you just made: bind the attestation to it.
 * const v = await verifyAttestation(result.jws, { request, maxAgeSeconds: 300 });
 * if (!v.valid) throw new Error(`attestation rejected: ${v.failures.join(", ")}`);
 *
 * @param jws The compact JWS (a result's `jws`). Missing or empty → `missing_attestation`.
 */
export async function verifyAttestation(jws: string | null | undefined, options?: VerifyOptions | null): Promise<VerificationResult> {
  const opts: VerifyOptions = options ?? {};
  const issuer = typeof opts.issuer === "string" ? opts.issuer : DEFAULT_ISSUER;
  const failures: VerificationFailure[] = [];
  let claims: AttestationClaims | null = null;
  let header: JwsHeader | null = null;
  let verificationMethod: string | undefined;
  const done = (): VerificationResult => {
    const unique = [...new Set(failures)];
    const method = verificationMethod ? { verificationMethod } : {};
    if (unique.length === 0 && claims && header) return { valid: true, failures: [], claims, header, issuer, ...method };
    return { valid: false, failures: unique.length > 0 ? unique : ["malformed_jws"], claims, header, issuer, ...method };
  };

  const nowMs = opts.now instanceof Date ? opts.now.getTime() : typeof opts.now === "number" ? opts.now : Date.now();
  if (!Number.isFinite(nowMs)) {
    failures.push("invalid_time");
    return done();
  }
  const now = Math.floor(nowMs / 1000);

  if (jws === undefined || jws === null || (typeof jws === "string" && jws.trim() === "")) {
    failures.push("missing_attestation");
    return done();
  }
  const parts = typeof jws === "string" ? jws.trim().split(".") : [];
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
    failures.push("malformed_jws");
    return done();
  }
  const [h, p, s] = parts as [string, string, string];
  const decodedHeader = decodeJsonSegment(h);
  const decodedPayload = decodeJsonSegment(p);
  const signature = base64UrlToBytes(s);
  header = decodedHeader as JwsHeader | null;
  claims = decodedPayload as AttestationClaims | null;
  if (!decodedHeader || !decodedPayload || !signature) {
    failures.push("malformed_jws");
    return done();
  }

  // Protected header
  const alg = decodedHeader.alg;
  if (alg !== "ES256") failures.push("alg_not_es256");
  if (decodedHeader.typ !== ATTESTATION_TYP) failures.push("unexpected_typ");
  if ("crit" in decodedHeader || "b64" in decodedHeader) failures.push("unsupported_header");
  const kid = typeof decodedHeader.kid === "string" && decodedHeader.kid.length > 0 ? decodedHeader.kid : null;
  if (!kid) failures.push("missing_kid");

  // Key (from the pinned issuer's DID document only) and signature
  if (alg === "ES256" && kid) {
    const url = didWebDocumentUrl(issuer);
    if (!url) {
      failures.push("unsupported_issuer");
    } else {
      const fetchImpl = opts.fetch ?? defaultFetch;
      const t = opts.timeoutMs;
      const timeoutMs = isFiniteNumber(t) && t > 0 && t <= MAX_TIMER_MS ? t : DEFAULT_DID_TIMEOUT_MS;
      let selected: KeySelection | null = null;
      try {
        let entry = loadDidDocument(url, fetchImpl, timeoutMs);
        let doc = await entry.doc;
        selected = doc.id === issuer ? selectAssertionKey(doc, issuer, kid) : { failure: "did_document_id_mismatch" };
        // Key rotation: an unknown kid refreshes a document cached for a while (rate-limited).
        if ("failure" in selected && selected.failure === "unknown_kid" && Date.now() - entry.fetchedAt > DID_REFRESH_COOLDOWN_MS) {
          entry = loadDidDocument(url, fetchImpl, timeoutMs, entry.fetchedAt + 1);
          doc = await entry.doc;
          selected = doc.id === issuer ? selectAssertionKey(doc, issuer, kid) : { failure: "did_document_id_mismatch" };
        }
      } catch {
        failures.push("did_resolution_failed");
      }
      if (selected && "failure" in selected) failures.push(selected.failure);
      else if (selected && opts.pinnedKeys && !opts.pinnedKeys.includes(await jwkThumbprint(selected.jwk).catch(() => ""))) failures.push("key_not_pinned");
      else if (selected) {
        const failure = await verifyEs256(selected.jwk, `${h}.${p}`, signature);
        if (failure) failures.push(failure);
        else verificationMethod = selected.id;
      }
    }
  }

  // Claims
  const c = decodedPayload;
  if (c.iss !== issuer) failures.push("issuer_mismatch");
  if (!isFiniteNumber(c.exp)) failures.push("missing_exp");
  else if (c.exp <= now) failures.push("expired");
  if (!isFiniteNumber(c.iat)) failures.push("missing_iat");
  else if (c.iat > now + MAX_CLOCK_SKEW_SECONDS) failures.push("iat_in_future");
  if (c.nbf !== undefined && !(isFiniteNumber(c.nbf) && c.nbf <= now + MAX_CLOCK_SKEW_SECONDS)) failures.push("not_yet_valid");
  const scoreOk = isFiniteNumber(c.score) && c.score >= 0 && c.score <= 100;
  if (typeof c.sub !== "string" || !scoreOk || !(RISK_TIERS as readonly unknown[]).includes(c.tier)) failures.push("invalid_claims");
  if (opts.maxAgeSeconds !== undefined) {
    const maxAge = opts.maxAgeSeconds;
    if (!isFiniteNumber(maxAge) || !isFiniteNumber(c.iat) || c.iat < now - maxAge - MAX_CLOCK_SKEW_SECONDS) failures.push("stale");
  }

  // Binding to what the caller expects
  if (isRecord(opts.request)) {
    failures.push(...requestFailures(c, opts.request));
    // Signed by providers from v0.3 on: covers every field exactly as sent. Absent → skipped
    // (older provider); present but not a matching string → the request was altered in transit.
    if (c.request_hash !== undefined) {
      let expected: string | null = null;
      try {
        expected = await requestHash(opts.request);
      } catch {
        expected = null;
      }
      if (typeof c.request_hash !== "string" || expected === null || c.request_hash !== expected) failures.push("request_mismatch");
    }
  }
  if (opts.aud !== undefined && !audienceMatches(c.aud, opts.aud)) failures.push("audience_mismatch");
  if (opts.sub !== undefined && !(typeof c.sub === "string" && sameSubject(opts.sub, c.sub))) failures.push("subject_mismatch");
  if (opts.interaction !== undefined && (c.interaction ?? null) !== opts.interaction) failures.push("interaction_mismatch");
  if (opts.payment !== undefined && !paymentMatches(c.payment, opts.payment)) failures.push("payment_mismatch");

  return done();
}
