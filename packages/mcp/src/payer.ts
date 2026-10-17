// Built-in x402 payer: every x402check evaluation is paid (USDC, x402 "exact" scheme, which is
// gasless for the payer). The private key lives only inside the viem signer; it is never logged,
// echoed or put in an error message, and every tool output is additionally scrubbed of it.
//
// Why a payment was refused is recorded by this module's own hooks, in per-call state, and read
// from there: never from the text of an error, which can carry the 402's own (third-party) fields.
//
// x402check's own checks are paid only to x402check's pay_to, and never more than a check costs:
// a hijacked API origin cannot collect more. A payee that may still settle an authorization this
// server signed for a site (not accepted yet, or awaiting its answer) gets no new one there, on
// any network and for any path, until that one is accepted or expires; while one call checks a
// payee for a site (or asks the user), another call to that payee there is refused before it
// buys a check of its own.
import { findDefaultAsset } from "@x402/evm";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { decodePaymentResponseHeader, wrapFetchWithPayment, x402Client, x402HTTPClient, type PaymentRequirements } from "@x402/fetch";
import type { FetchLike } from "@x402check/client";
import { X402CHECK_PAY_TO } from "@x402check/client/guard";
import { privateKeyToAccount } from "viem/accounts";
import { readLimited } from "./body.js";
import { NonPublicAddressError, publicOnlyFetch, type Resolver } from "./net.js";

export const DEFAULT_MAX_PAYMENT_USD = 0.05;
export const DEFAULT_BUDGET_USD = 1;
/** The cheapest per-call evaluation ($0.001 on Avalanche and Monad; $0.0035 on Base). Below it the budget cannot buy a check. */
export const MIN_CHECK_USD = 0.001;
/** Preferred first when the 402 offers it: Base. */
export const PREFERRED_NETWORK = "eip155:8453";
/** The longest a signed authorization may stay valid (the 402's `maxTimeoutSeconds`): 15 minutes. */
export const MAX_AUTHORIZATION_SECONDS = 900;
/** The most of a 402 response body read before paying (x402 v2 challenges travel in the PAYMENT-REQUIRED header). */
export const MAX_CHALLENGE_BYTES = 64 * 1024;
/**
 * The most one check may cost, in USD: x402check's dearest network charges $0.009 per check, and a
 * simulated check costs the network's price or $0.005, whichever is higher. A check's 402 asking
 * for more is refused (test/consistency.test.ts keeps this above every published price).
 */
export const MAX_CHECK_PAYMENT_USD = 0.01;

export type PaymentRefusalKind =
  | "budget_exhausted"
  | "over_max_payment"
  | "no_payable_option"
  | "payment_error"
  | "not_authorized"
  /** The 402 is not an x402 version 2 challenge. */
  | "unsupported_x402_version"
  /** The 402 asks for an authorization valid longer than MAX_AUTHORIZATION_SECONDS. */
  | "authorization_too_long"
  /** The 402's body is larger than MAX_CHALLENGE_BYTES. */
  | "challenge_too_large"
  /** The 402's body did not arrive within the request's time limit. */
  | "challenge_timeout"
  /** The response came from a redirect (a custom fetch followed it). */
  | "redirected"
  /** The host name resolves to a non-public address. */
  | "private_address"
  /** The call was cancelled before anything was sent with a signature. */
  | "cancelled"
  /** A check's 402 names a payee other than x402check's pay_to. */
  | "untrusted_check_payee"
  /** A check's 402 asks for more than a check costs (MAX_CHECK_PAYMENT_USD). */
  | "over_check_price"
  /**
   * An earlier authorization to the same payee on the same site (any network, any path) was not
   * accepted, or still awaits its answer, and has not expired; or another call is about to sign
   * one there (its check of the payee, or the user's decision, is under way).
   */
  | "authorization_outstanding";

/** A payment this server refused or could not make. The message never contains secrets. */
export class PaymentRefused extends Error {
  override readonly name = "PaymentRefused";
  constructor(
    readonly kind: PaymentRefusalKind,
    message: string,
  ) {
    super(message);
  }
}

export interface PayerOptions {
  /** EVM private key: 0x followed by 64 hex characters. */
  privateKey: string;
  /** Per-payment cap in USD (x402 spend controls). Default 0.05. */
  maxPaymentUsd?: number | undefined;
  /** Total spend allowed for this process, in USD. Default 1.00. */
  budgetUsd?: number | undefined;
  /**
   * Underlying fetch (standard signature), for x402check's API and for resources. It must honor
   * `redirect: "manual"`: a resource response that shows a followed redirect is refused. Default:
   * `globalThis.fetch` for the API, and for resources a fetch that connects only to public
   * addresses (host names resolved, and the connection pinned to the addresses checked).
   */
  fetch?: typeof globalThis.fetch | undefined;
  /** DNS resolution for resource hosts when `fetch` is not set (default: the system resolver). For tests. */
  resolve?: Resolver | undefined;
  /** Who a check's 402 may be paid to (x402check's API). Default: x402check's own pay_to. */
  checkPayees?: readonly string[] | undefined;
  /** The most one check may cost, in USD. Default MAX_CHECK_PAYMENT_USD. */
  maxCheckPaymentUsd?: number | undefined;
}

export interface Payer {
  /** The payer's public address (safe to show). */
  readonly address: `0x${string}`;
  readonly maxPaymentUsd: number;
  readonly budgetUsd: number;
  /** USD committed so far: every signed payment authorization that was sent counts, settled or not. */
  spentUsd(): number;
  /** Whether the remaining budget still covers the cheapest check. */
  canAfford(): boolean;
  /** An x402-paying fetch for `createClient` (pays x402check's own checks). Payment failures reject with `PaymentRefused`. */
  readonly fetch: FetchLike;
  /**
   * Fetches a third-party x402 resource. When it asks for payment, `authorize` decides right
   * before the payment is signed, on exactly what would be signed: nothing is signed unless it
   * returns undefined. At most one payment per call, within the cap and the budget, and none to a
   * payee that may still settle an earlier one from this server on that site, or that another call
   * is about to pay there (`authorization_outstanding`, decided before `authorize` runs).
   */
  payResource(url: string, init: RequestInit, options: ResourcePaymentOptions): Promise<Response>;
  /** Removes the private key from text (defense in depth for every output). */
  redact(text: string): string;
}

/** A resource payment about to be signed. */
export interface ResourcePayment {
  scheme: string;
  network: string;
  payTo: string;
  asset: string;
  /** Atomic units of `asset`. */
  amount: string;
  /** The same amount in USD, rounded up (the asset is a USD stablecoin this payer recognizes). */
  usd: number;
  /** How long the signed authorization stays valid, in seconds (at most MAX_AUTHORIZATION_SECONDS). */
  maxTimeoutSeconds: number;
  /** The resource's own description, from its 402 (untrusted text). */
  description?: string | undefined;
}

/** A signed authorization (public values only). */
export interface SignedPayment {
  /** Unix time (seconds) until which it can be settled. */
  validUntil?: number | undefined;
  /** Its nonce: identifies it on-chain. */
  nonce?: string | undefined;
}

/** Called once, right before signing: undefined → sign; a string → refuse, nothing signed. */
export type PaymentAuthorizer = (payment: ResourcePayment) => Promise<string | undefined>;

export interface ResourcePaymentOptions {
  authorize: PaymentAuthorizer;
  /** Runs once the authorization is signed (it is not sent yet). */
  onSigned?: ((signed: SignedPayment) => void) | undefined;
  /** Runs when the request carrying the signed authorization is handed to the network: from then on it may be settled whatever follows. */
  onSent?: (() => void) | undefined;
  /** Per HTTP request to the resource: until its headers arrive, and for a 402 until its body is read (the check and the user's decision do not count). */
  timeoutMs?: number | undefined;
  /** Cancels the call: nothing is signed or sent once it fires, and requests in flight are aborted. */
  signal?: AbortSignal | undefined;
}

const PRIVATE_KEY = /^0x[0-9a-fA-F]{64}$/;
const MICRO = 1_000_000n; // budget accounting in integer micro-USD (USDC has 6 decimals)

const TEXT = {
  budget: "the payment budget of this server is exhausted",
  overCap: "the price exceeds the per-payment cap (X402CHECK_MAX_PAYMENT_USD)",
  unpayable: "none of the offered payment options can be paid by this server (EVM USDC via x402 exact)",
  notAuthorized: "the payment was not authorized, so nothing was signed",
  cancelled: "the call was cancelled (by the client, or its time limit) before anything was signed",
  cancelledUnsent: "the call was cancelled right after signing: the signed authorization was discarded, never sent",
  tooLarge: `the resource's 402 response is larger than ${MAX_CHALLENGE_BYTES / 1024} KiB, so it was not read`,
  redirected: "the response came from a redirect (the configured fetch followed it), and redirects are refused",
  privateAddress: "the host name resolves to a private, loopback, link-local or reserved address",
  unreadable: "the x402 payment could not be created from the resource's 402 response",
  checkPayee: "the check's 402 names a payee that is not x402check's pay_to, so it was not paid",
  checkPrice: "the check's 402 asks for more than any check costs, so it was not paid",
} as const;

// Marks why a request was aborted: compared by identity, never by text.
const TIMED_OUT = Symbol("timed out");
const CANCELLED = Symbol("cancelled");

/** A USD amount from the configuration (0.000001 to 1000000), or a TypeError naming the setting. */
export function usdAmount(name: string, value: number | undefined, fallback: number): number {
  const v = value ?? fallback;
  if (!Number.isFinite(v) || v < 0.000001 || v > 1_000_000) throw new TypeError(`${name} must be a USD amount between 0.000001 and 1000000`);
  return v;
}

/** Atomic token amount → micro-USD, rounded up (budgeting errs on the safe side). */
function toMicroUsd(amount: string, decimals: number): bigint {
  const scale = 10n ** BigInt(decimals);
  return (BigInt(amount) * MICRO + scale - 1n) / scale;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The price of an option this payer can pay (x402 "exact", a known USD stablecoin on EVM), in micro-USD. */
function priceMicro(option: unknown): bigint | undefined {
  if (!isRecord(option) || option.scheme !== "exact" || typeof option.network !== "string" || !option.network.startsWith("eip155:")) return undefined;
  if (typeof option.asset !== "string" || typeof option.amount !== "string" || !/^\d{1,78}$/.test(option.amount)) return undefined;
  let asset: { decimals: number } | undefined;
  try {
    asset = findDefaultAsset(option.asset, option.network as `${string}:${string}`);
  } catch {
    return undefined;
  }
  return asset && Number.isInteger(asset.decimals) ? toMicroUsd(option.amount, asset.decimals) : undefined;
}

/** A lifetime this payer signs: a whole number of seconds, 1 to MAX_AUTHORIZATION_SECONDS (a string would be concatenated, not added). */
function lifetimeOk(option: unknown): boolean {
  const t = isRecord(option) ? option.maxTimeoutSeconds : undefined;
  return typeof t === "number" && Number.isInteger(t) && t > 0 && t <= MAX_AUTHORIZATION_SECONDS;
}

function tooLong(option: unknown): string {
  const t = isRecord(option) ? option.maxTimeoutSeconds : undefined;
  const asked = typeof t === "number" && Number.isInteger(t) && t > 0 && t < 1e12 ? `${t} s` : "an unreadable time";
  return `the resource asks for a payment authorization valid for ${asked}; this server signs authorizations valid for at most ${MAX_AUTHORIZATION_SECONDS} s (15 minutes)`;
}

/**
 * What this payer would refuse in a 402 challenge, decided on the parsed challenge itself (never
 * on an error's text): not x402 version 2, no payable option, above the cap, too long-lived.
 */
function assess(paymentRequired: unknown, maxMicro: bigint): PaymentRefused | undefined {
  const pr = isRecord(paymentRequired) ? paymentRequired : {};
  if (pr.x402Version !== 2) {
    const v = pr.x402Version;
    const which = typeof v === "number" && Number.isInteger(v) && v >= 0 && v < 1000 ? `x402 version ${v}` : "an unknown x402 version";
    return new PaymentRefused("unsupported_x402_version", `the resource asks for payment with ${which}; this server pays x402 version 2 challenges only`);
  }
  const accepts: unknown[] = Array.isArray(pr.accepts) ? pr.accepts : [];
  const priced = accepts.filter((a) => priceMicro(a) !== undefined);
  if (priced.length === 0) return new PaymentRefused("no_payable_option", TEXT.unpayable);
  const affordable = priced.filter((a) => (priceMicro(a) as bigint) <= maxMicro);
  if (affordable.length === 0) return new PaymentRefused("over_max_payment", TEXT.overCap);
  if (!affordable.some(lifetimeOk)) return new PaymentRefused("authorization_too_long", tooLong(affordable.find((a) => isRecord(a) && a.network === PREFERRED_NETWORK) ?? affordable[0]));
  return undefined;
}

/** The expiry and nonce of a signed EIP-3009 or Permit2 authorization, when well formed. */
function signedInfo(paymentPayload: unknown): SignedPayment {
  const inner = isRecord(paymentPayload) && isRecord(paymentPayload.payload) ? paymentPayload.payload : {};
  const auth = isRecord(inner.authorization) ? inner.authorization : isRecord(inner.permit2Authorization) ? inner.permit2Authorization : {};
  const until = auth.validBefore ?? auth.deadline;
  const nonce = auth.nonce;
  return {
    ...(typeof until === "string" && /^\d{1,12}$/.test(until) ? { validUntil: Number(until) } : {}),
    ...(typeof nonce === "string" && /^(?:0x[0-9a-fA-F]{1,64}|\d{1,78})$/.test(nonce) ? { nonce } : {}),
  };
}

/**
 * The site a resource is on, as authorizations are remembered: its origin as the URL parser
 * normalizes it (lowercase, punycode, no default port), without a trailing dot. Not the path: every
 * spelling of it (`/x/`, `%66`, `//`, `./`), and every other resource there, is the same site.
 */
function siteOf(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.hostname.replace(/\.$/, "")}${u.port ? `:${u.port}` : ""}`;
  } catch {
    return url;
  }
}

/**
 * The settlement receipt a response carries (PAYMENT-RESPONSE, else X-PAYMENT-RESPONSE, read as
 * @x402/fetch reads them): undefined when there is none, null when it does not decode to an object.
 */
export function settlementReceipt(res: unknown): Record<string, unknown> | null | undefined {
  const headers = (res as { headers?: unknown } | null)?.headers as { get?: unknown } | null | undefined;
  if (!headers || typeof headers.get !== "function") return undefined;
  const get = (name: string): string | undefined => {
    try {
      const value: unknown = (headers as { get(name: string): unknown }).get(name);
      return typeof value === "string" && value !== "" ? value : undefined;
    } catch {
      return undefined;
    }
  };
  const header = get("PAYMENT-RESPONSE") ?? get("X-PAYMENT-RESPONSE");
  if (header === undefined) return undefined;
  try {
    const receipt: unknown = decodePaymentResponseHeader(header);
    return isRecord(receipt) ? receipt : null;
  } catch {
    return null;
  }
}

/**
 * Whether the resource accepted the signed authorization it was sent: a 2xx whose settlement
 * receipt decodes and says `success: true`. Anything else (a 402, an error, a redirect, a 2xx with
 * no receipt, or with one that cannot be read or does not say `success: true`) leaves it to be
 * settled until it expires. x402check_pay reports "paid" on exactly this.
 */
export function paymentAccepted(res: { status: number }): boolean {
  if (!(res.status >= 200 && res.status < 300)) return false;
  return settlementReceipt(res)?.success === true;
}

/** Whether `err`, or an error in its `cause` chain, is an instance of `type` (identity, never text). */
function causedBy(err: unknown, type: new (...args: never[]) => Error): boolean {
  let e: unknown = err;
  for (let depth = 0; depth < 8 && e instanceof Error; depth++) {
    if (e instanceof type) return true;
    e = (e as Error).cause;
  }
  return false;
}

/** A response that shows a followed redirect: `redirected`, or a final URL other than the one requested. */
function followedRedirect(res: unknown, requested: string): boolean {
  const r = res as { redirected?: unknown; url?: unknown };
  if (r.redirected === true) return true;
  if (typeof r.url !== "string" || r.url === "") return false;
  const bare = (u: string): string => {
    try {
      const url = new URL(u);
      url.hash = "";
      return url.href;
    } catch {
      return u;
    }
  };
  return bare(r.url) !== bare(requested);
}

/** A copy of a response's headers (a minimal custom-fetch response may only offer `get`). */
function copyHeaders(headers: unknown): Headers {
  const out = new Headers();
  const h = headers as { forEach?: unknown; get?: unknown } | null;
  try {
    if (h && typeof h.forEach === "function") {
      (h as Headers).forEach((value, name) => {
        try {
          out.append(name, value);
        } catch {
          // an invalid header is dropped
        }
      });
    } else if (h && typeof h.get === "function") {
      for (const name of ["payment-required", "content-type", "x-payment-error"]) {
        const value = (h as { get(name: string): string | null }).get(name);
        if (typeof value === "string") out.set(name, value);
      }
    }
  } catch {
    // nothing more to copy
  }
  return out;
}

function discard(res: unknown): void {
  try {
    const body = (res as { body?: ReadableStream | null }).body;
    if (body && typeof body.cancel === "function") void body.cancel().catch(() => undefined);
  } catch {
    // nothing to release
  }
}

/** Per call: why this server stopped a payment, and how far it got. Set by this module only. */
interface CallState {
  refusal?: PaymentRefused;
  /** The resource answered 402. */
  challenged: boolean;
  /** Committed from the budget for the authorization being signed. */
  reservedMicro?: bigint | undefined;
  signed: boolean;
  /** The request carrying the signed authorization was handed to the network. */
  sent: boolean;
  /** A resource payment: the site it pays on (siteOf). */
  site?: string | undefined;
  /** The key (payee and site) of the record this call made in `outstanding`, before the payee's check. */
  paid?: string | undefined;
  /** Until when that authorization can be settled (unix seconds). */
  validUntil?: number | undefined;
}

/** An authorization this server signed, or is deciding whether to sign, for a payee on a site. */
interface Held {
  /** The call it belongs to: only that call updates or clears it. */
  owner: CallState;
  /**
   * Until when it can be settled (unix seconds): its validBefore once signed. While the call is
   * still checking, the longest the record may hold the key should the call never end.
   */
  until: number;
  /** Nothing is signed yet: the payee's check, or the user's decision, is under way. */
  checking: boolean;
  /** The request carrying it has not been answered yet. */
  inFlight: boolean;
}

function refuse(state: CallState, kind: PaymentRefusalKind, message: string): PaymentRefused {
  state.refusal ??= new PaymentRefused(kind, message);
  return state.refusal;
}

/** What a failed call means, from this module's own state (never from the error's text). */
function outcomeOf(state: CallState, err: unknown): unknown {
  if (state.sent) return err; // the exchange failed after a signed payment went out: reported as such
  if (state.refusal) return state.refusal;
  if (state.challenged) return new PaymentRefused("payment_error", TEXT.unreadable);
  return err; // not a payment problem (e.g. the resource could not be reached)
}

interface Bounds {
  /** Per request: until the headers arrive, and for an unpaid 402 until its body is read. */
  timeoutMs?: number | undefined;
  signal?: AbortSignal | undefined;
  onSent?: (() => void) | undefined;
  /** Resources: a response that shows a followed redirect is refused. */
  refuseRedirects: boolean;
}

/**
 * The fetch the x402 wrapper calls. Each request is bounded in time and cancellable. An unpaid
 * 402's body is read here, at most MAX_CHALLENGE_BYTES within the same deadline, before @x402/fetch
 * would read it whole (it has no limit).
 */
function boundedFetch(inner: typeof globalThis.fetch, state: CallState, bounds: Bounds): typeof globalThis.fetch {
  return async (input, init) => {
    const request = new Request(input, init);
    const paid = request.headers.has("payment-signature") || request.headers.has("x-payment");
    if (bounds.signal?.aborted) throw refuse(state, "cancelled", paid ? TEXT.cancelledUnsent : TEXT.cancelled);
    // The caller's own signal (e.g. the client's time limit on a paid check) aborted already: send nothing.
    if (request.signal.aborted) throw new Error(paid ? "the request was aborted before the signed payment was sent" : "the request was aborted");

    const stop = new AbortController();
    const timer = bounds.timeoutMs === undefined ? undefined : setTimeout(() => stop.abort(TIMED_OUT), bounds.timeoutMs);
    const onCancel = (): void => stop.abort(CANCELLED);
    const onRequestAbort = (): void => stop.abort(request.signal.reason);
    bounds.signal?.addEventListener("abort", onCancel, { once: true });
    request.signal.addEventListener("abort", onRequestAbort, { once: true });
    // Racing (not only aborting) bounds the request even when a custom fetch ignores the signal.
    const halted = new Promise<never>((_resolve, reject) => {
      stop.signal.addEventListener("abort", () => reject(stop.signal.reason), { once: true });
    });
    halted.catch(() => undefined);
    try {
      if (paid) {
        state.sent = true;
        bounds.onSent?.();
      }
      let res: Response;
      try {
        const pending = inner(new Request(request, { signal: stop.signal }));
        pending.catch(() => undefined);
        res = await Promise.race([pending, halted]);
      } catch (err) {
        const reason: unknown = stop.signal.aborted ? stop.signal.reason : undefined;
        if (reason === CANCELLED) {
          if (!paid) throw refuse(state, "cancelled", TEXT.cancelled);
          throw new Error("the call was cancelled while the request carrying the signed payment was in flight");
        }
        if (reason === TIMED_OUT) throw new Error(`the resource did not answer within ${bounds.timeoutMs} ms`);
        if (!paid && causedBy(err, NonPublicAddressError)) throw refuse(state, "private_address", TEXT.privateAddress);
        throw err;
      }
      if (bounds.refuseRedirects && followedRedirect(res, request.url)) {
        discard(res);
        if (!paid) throw refuse(state, "redirected", TEXT.redirected);
        throw new Error("the response came from a redirect, which this server does not follow: it is not shown");
      }
      if (res.status !== 402 || paid) return res;

      state.challenged = true;
      const read = await readLimited(res, MAX_CHALLENGE_BYTES, stop.signal);
      if (read.overflow) throw refuse(state, "challenge_too_large", TEXT.tooLarge);
      if (read.stopped) {
        if (stop.signal.reason === CANCELLED) throw refuse(state, "cancelled", TEXT.cancelled);
        if (stop.signal.reason === TIMED_OUT) throw refuse(state, "challenge_timeout", `the resource's 402 response did not arrive in full within ${bounds.timeoutMs} ms`);
        throw new Error("the request was aborted");
      }
      return new Response(read.data.byteLength > 0 ? read.data : null, { status: 402, headers: copyHeaders(res.headers) });
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      bounds.signal?.removeEventListener("abort", onCancel);
      request.signal.removeEventListener("abort", onRequestAbort);
    }
  };
}

export function createPayer(options: PayerOptions): Payer {
  const key = typeof options.privateKey === "string" ? options.privateKey.trim() : "";
  if (!PRIVATE_KEY.test(key)) throw new TypeError("X402CHECK_PAYER_KEY must be an EVM private key: 0x followed by 64 hex characters");
  let account: ReturnType<typeof privateKeyToAccount>;
  try {
    account = privateKeyToAccount(key as `0x${string}`);
  } catch {
    throw new TypeError("X402CHECK_PAYER_KEY is not a valid secp256k1 private key");
  }
  const maxPaymentUsd = usdAmount("X402CHECK_MAX_PAYMENT_USD", options.maxPaymentUsd, DEFAULT_MAX_PAYMENT_USD);
  const budgetUsd = usdAmount("X402CHECK_BUDGET_USD", options.budgetUsd, DEFAULT_BUDGET_USD);
  const budgetMicro = BigInt(Math.round(budgetUsd * 1e6));
  const maxMicro = BigInt(Math.round(maxPaymentUsd * 1e6));
  const maxCheckMicro = BigInt(Math.round(usdAmount("maxCheckPaymentUsd", options.maxCheckPaymentUsd, MAX_CHECK_PAYMENT_USD) * 1e6));
  const checkPayees = (options.checkPayees ?? X402CHECK_PAY_TO).map((p) => p.toLowerCase());
  let spentMicro = 0n;
  const secret = key.slice(2).toLowerCase();
  /**
   * Payee (lowercase) and site → the call deciding whether to sign there, or the latest
   * authorization this server signed there that can still be settled: not accepted, or awaiting
   * its answer. A call takes its key's record in the same step that finds it free (no await
   * between them), before the payee's check: a concurrent call is refused before it buys a check.
   * The record is given back when the call signs nothing, and the call signs only while the record
   * is still its own (checked again right before signing), so one key never holds two settleable
   * authorizations from this process, and a success clears only the record of the call that made it.
   */
  const outstanding = new Map<string, Held>();
  const nowSeconds = (): number => Math.floor(Date.now() / 1000);
  /** The live record for `key` (an expired one is dropped: it can no longer be settled). */
  const holding = (key: string): Held | undefined => {
    const held = outstanding.get(key);
    if (held !== undefined && held.until <= nowSeconds()) {
      outstanding.delete(key);
      return undefined;
    }
    return held;
  };
  /** Records `state`'s authorization for `key` (expired records are dropped first). */
  const hold = (key: string, state: CallState, record: Omit<Held, "owner">): void => {
    for (const [k, h] of outstanding) if (h.until <= nowSeconds()) outstanding.delete(k);
    outstanding.set(key, { owner: state, ...record });
    state.paid = key;
  };
  const heldText = (held: Held): string => {
    if (held.checking) {
      return "another call is about to sign an authorization for this payee and resource (its check of the payee, or the user's decision, is under way): nothing new is signed until that call signs nothing, or its authorization is accepted or expires";
    }
    const until = new Date(held.until * 1000).toISOString();
    return held.inFlight
      ? `an authorization this server signed for this payee and resource is still awaiting the resource's answer (another call), and it can be settled until ${until}: nothing new is signed until it is accepted or expires`
      : `an authorization this server signed for this payee and resource was not accepted, and it can still be settled until ${until}: nothing new is signed until then`;
  };
  /** Drops the record `state` made, when it is still that call's. */
  const release = (state: CallState): void => {
    if (state.paid !== undefined && outstanding.get(state.paid)?.owner === state) outstanding.delete(state.paid);
  };

  // Among the options the x402 client kept, the one this payer pays: within the cap, with an
  // acceptable lifetime, Base first.
  const select = (_version: number, requirements: PaymentRequirements[]): PaymentRequirements => {
    const fits = requirements.filter((r) => {
      const price = priceMicro(r);
      return price !== undefined && price <= maxMicro && lifetimeOk(r);
    });
    const pool = fits.length > 0 ? fits : requirements;
    return (pool.find((r) => r.network === PREFERRED_NETWORK) ?? pool.find((r) => r.network.startsWith("eip155:")) ?? pool[0]) as PaymentRequirements;
  };

  // One x402 client per call (its hooks write that call's state), for x402check's own checks
  // and for resource payments (with their gate), sharing the budget.
  const makeClient = (state: CallState, gate?: PaymentAuthorizer, signal?: AbortSignal, onSigned?: (signed: SignedPayment) => void): x402HTTPClient => {
    const client = new x402Client(select)
      .register("eip155:*", new ExactEvmScheme(account))
      .setSpendControls({ maxAmountPerPayment: `$${maxPaymentUsd.toFixed(6)}` })
      .onBeforePaymentCreation(async ({ selectedRequirements: r, paymentRequired }) => {
        // Whether this run took its key's record (below). A refusal gives back only that one: the
        // x402 wrapper's retry runs this hook again in the same call, whose record from the first
        // run (an authorization that was sent) must stay. An abort runs no failure hook.
        let took = false;
        const stopWith = (kind: PaymentRefusalKind, message: string) => {
          refuse(state, kind, message);
          if (took) release(state);
          return { abort: true as const, reason: kind };
        };
        if (signal?.aborted) return stopWith("cancelled", TEXT.cancelled);
        const cost = priceMicro(r);
        if (cost === undefined) return stopWith("no_payable_option", TEXT.unpayable);
        if (!gate) {
          // x402check's own checks: only to its pay_to, and never more than a check costs.
          if (!checkPayees.includes(String(r.payTo).toLowerCase())) return stopWith("untrusted_check_payee", TEXT.checkPayee);
          if (cost > maxCheckMicro) return stopWith("over_check_price", TEXT.checkPrice);
        }
        if (cost > maxMicro) return stopWith("over_max_payment", TEXT.overCap);
        if (!lifetimeOk(r)) return stopWith("authorization_too_long", tooLong(r));
        if (spentMicro + cost > budgetMicro) return stopWith("budget_exhausted", TEXT.budget);
        // A resource payment: none while this payee may still settle another one from this server
        // on this site, whatever the network, or while another call is deciding whether to sign one
        // there. The key's record is taken in the same step that finds it free (no await between
        // them), before the payee's check: a concurrent call is refused before it buys a check. It
        // holds the key for at most MAX_AUTHORIZATION_SECONDS should this call never end (the check
        // and the user's decision are bounded well below that).
        const paid = gate && state.site !== undefined ? `${String(r.payTo).toLowerCase()}|${state.site}` : undefined;
        if (paid !== undefined) {
          const held = holding(paid);
          if (held) return stopWith("authorization_outstanding", heldText(held));
          hold(paid, state, { until: nowSeconds() + MAX_AUTHORIZATION_SECONDS, checking: true, inFlight: false });
          took = true;
        }
        if (gate) {
          // Decided on exactly what would be signed, right before signing. A failure refuses.
          const description = paymentRequired.resource?.description;
          const payment: ResourcePayment = {
            scheme: r.scheme,
            network: r.network,
            payTo: r.payTo,
            asset: r.asset,
            amount: r.amount,
            usd: Number(cost) / 1e6,
            maxTimeoutSeconds: r.maxTimeoutSeconds,
            ...(typeof description === "string" && description.trim() ? { description: description.trim().slice(0, 600) } : {}),
          };
          const refusal = await gate(payment).catch(() => "the authorization failed");
          // Cancelled while the check or the user's decision was pending: nothing is signed.
          if (signal?.aborted) return stopWith("cancelled", TEXT.cancelled);
          if (refusal !== undefined) return stopWith("not_authorized", TEXT.notAuthorized);
          // A paid check inside the authorization may itself have spent from the budget.
          if (spentMicro + cost > budgetMicro) return stopWith("budget_exhausted", TEXT.budget);
        }
        if (paid !== undefined) {
          // Signing now, while the record is still this call's. It is another call's only if this
          // one's lapsed during the check (or the user's decision) and that call took the key:
          // then nothing is signed. Otherwise (this call's, or dropped as lapsed with the key still
          // free) it is recorded again, in the same step, for the authorization about to be signed.
          const heldNow = holding(paid);
          if (heldNow && heldNow.owner !== state) return stopWith("authorization_outstanding", heldText(heldNow));
          hold(paid, state, { until: nowSeconds() + r.maxTimeoutSeconds, checking: false, inFlight: true });
        }
        // Committed before signing: a signed authorization can be settled even if the response is lost.
        spentMicro += cost;
        state.reservedMicro = cost;
        return undefined;
      })
      .onAfterPaymentCreation(async ({ paymentPayload }) => {
        state.signed = true;
        const info = signedInfo(paymentPayload);
        state.validUntil = info.validUntil;
        // The record now holds the signed authorization's own expiry.
        const record = state.paid === undefined ? undefined : outstanding.get(state.paid);
        if (record?.owner === state) record.until = info.validUntil ?? nowSeconds() + MAX_AUTHORIZATION_SECONDS;
        try {
          onSigned?.(info);
        } catch {
          // reporting only
        }
      })
      .onPaymentCreationFailure(async () => {
        // Nothing was signed (or it is discarded): give the reservation and the record back.
        if (state.reservedMicro !== undefined) {
          spentMicro -= state.reservedMicro;
          state.reservedMicro = undefined;
        }
        release(state);
      });
    // Before anything is created, on the parsed challenge: refusals are recorded, not inferred.
    return new x402HTTPClient(client).onPaymentRequired(async ({ paymentRequired }) => {
      state.challenged = true;
      const refusal = assess(paymentRequired, maxMicro);
      if (refusal) throw refuse(state, refusal.kind, refusal.message);
    });
  };

  const apiFetch: typeof globalThis.fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const resourceFetch: typeof globalThis.fetch = options.fetch ?? publicOnlyFetch(options.resolve);

  /** A signed authorization that never left this process cannot be settled: its budget comes back. */
  const failure = (state: CallState, err: unknown): unknown => {
    if (state.signed && !state.sent && state.reservedMicro !== undefined) {
      spentMicro -= state.reservedMicro;
      state.reservedMicro = undefined;
    }
    return outcomeOf(state, err);
  };

  return {
    address: account.address,
    maxPaymentUsd,
    budgetUsd,
    spentUsd: () => Number(spentMicro) / 1e6,
    canAfford: () => budgetMicro - spentMicro >= BigInt(Math.round(MIN_CHECK_USD * 1e6)),
    fetch: async (url, init) => {
      const state: CallState = { challenged: false, signed: false, sent: false };
      // The client bounds the whole exchange in time (its own timeout and signal).
      const paying = wrapFetchWithPayment(boundedFetch(apiFetch, state, { refuseRedirects: false }), makeClient(state));
      try {
        return await paying(url, init as RequestInit);
      } catch (err) {
        throw failure(state, err);
      }
    },
    payResource: async (url, init, { authorize, onSigned, onSent, timeoutMs, signal }) => {
      const state: CallState = { challenged: false, signed: false, sent: false };
      if (signal?.aborted) throw refuse(state, "cancelled", TEXT.cancelled);
      // One signature per call: the x402 wrapper signs a second payment when a response hook
      // reports a "recoverable" failure, and a server could then settle both.
      let asked = false;
      const gate: PaymentAuthorizer = async (payment) => {
        if (asked) return "only one payment per call";
        asked = true;
        return authorize(payment);
      };
      const fetchResource = boundedFetch(resourceFetch, state, { timeoutMs, signal, onSent, refuseRedirects: true });
      state.site = siteOf(url);
      // This call's record: cleared when the resource accepts the payment, or when nothing was sent
      // (it cannot be settled); otherwise kept, no longer in flight, until the authorization expires.
      // A record that is another call's by now (this one's expired meanwhile) is left alone.
      const settle = (res: Response | undefined): void => {
        const record = state.paid === undefined ? undefined : outstanding.get(state.paid);
        if (record?.owner !== state) return;
        if (!state.sent || (res !== undefined && paymentAccepted(res))) release(state);
        else record.inFlight = false;
      };
      try {
        const res = await wrapFetchWithPayment(fetchResource, makeClient(state, gate, signal, onSigned))(url, init);
        settle(res);
        return res;
      } catch (err) {
        settle(undefined);
        throw failure(state, err);
      }
    },
    redact: (text) => (text.toLowerCase().includes(secret) ? text.replace(new RegExp(`(0x)?${secret}`, "gi"), "[redacted]") : text),
  };
}
