// Signing guard: x402check between an agent and its keys.
//
// `guardAccount(account)` wraps a viem-style account. Every signature it would produce
// (a transaction, EIP-712 typed data including x402 EIP-3009 and Permit2 payments, permits and
// orders, a message, an EIP-7702 delegation) is decoded first: the real counterparty
// is found inside the calldata or the typed data, with the same decoders as the
// x402check MetaMask Snap. That counterparty is then checked, along with the
// transaction itself, which is simulated. The key signs only after a verified `allow`.
//
// - `block`, `not_verified` (any failure: network, payment, timeout, a bad, unbound or
//   unpinned attestation), or locally proven danger → it throws `X402CheckBlockedError` and
//   nothing is signed.
// - What the guard cannot read is never signed: opaque bytes and hashes, calldata it cannot
//   decode on the signer's own account, a transaction it cannot simulate, a delegation valid
//   on every chain, and any signing method of the account it does not intercept.
// - `warn` → it signs only if `onWarn` approves. Without `onWarn`, it refuses.
// - Every attestation is verified against the pinned issuer and its pinned keys, and bound to
//   the exact request (`request_hash`), so an old or foreign `allow` cannot unlock this signature.
// - The request is copied before it is checked, and the copy is what gets signed.
//
// `x402PaymentGuard()` is the same check as an x402 client hook (`onBeforePaymentCreation`):
// the payment is aborted before anything is signed.
//
// `guardSolanaSigner(signer)` does the same for a Solana signer (@solana/kit's
// `signTransactions` / `signMessages` and their modifying and sending variants): each
// transaction is decoded (lookup tables and token-account owners resolved over RPC), and its
// recipients, delegates and called programs are checked. A message that is itself a
// transaction, or an instruction that hands the account, its token accounts or its stake to
// someone else, is refused without a check. The RPC is trusted for lookup tables and
// token-account owners: pass `solanaRpcUrls` to require several endpoints to agree.
//
// Pay for the checks with prepaid credits (`creditToken`): never with a per-call payer
// that uses the guarded account itself, or each check would need a guarded signature.
import { createClient, type X402CheckClient } from "./client.js";
import { interpret, type Action, type Interpretation } from "./interpret.js";
import { DEFAULT_ISSUER, verifyAttestation } from "./verify.js";
import { X402CHECK_KEY_THUMBPRINTS } from "./keys.js";
import { normalizeHost, toCaip2 } from "./normalize.js";
import type { FetchLike, PaymentBinding, RiskCheckRequest, RiskCheckResult } from "./types.js";
import { decodeTransaction } from "./decode/tx.js";
import { decodeTypedData } from "./decode/typed.js";
import { decodePersonalSign } from "./decode/personal.js";
import { buildRiskCheckBodies, type RiskCheckBody } from "./decode/request.js";
import type { Decoded } from "./decode/util.js";
import {
  accountKeys,
  ADDRESS_LOOKUP_TABLE_PROGRAM,
  analyzeSolanaMessage,
  DEFAULT_SOLANA_RPC,
  decodeSolanaMessage,
  getSolanaAccounts,
  isSolanaTransactionMessage,
  lookupTableAddresses,
  SOLANA_MAINNET,
  tokenAccountInfo,
  type SolanaAccount,
  type SolanaAnalysis,
  type SolanaFinding,
  type SolanaMessage,
} from "./solana.js";

export { X402CHECK_KEY_THUMBPRINTS } from "./keys.js";

/** x402check's own `pay_to` addresses: paying for a check is never itself checked. */
export const X402CHECK_PAY_TO: readonly string[] = ["0xbF88b1F49B5e8Ec386289341c4a5ee00bB0E0178", "Bofhoe2ye2adNQwZJtLepeKrBZq8CtHzRwPJXgWDH69X"];
/** Payments to a trusted payee up to this many atomic units ($0.25 of USDC) are not checked. */
export const TRUSTED_PAYEE_MAX_AMOUNT = 250_000n;

/** x402's Permit2 proxies (exact and upto schemes): a PermitWitnessTransferFrom to one of them is an x402 payment to its witness `to`. */
export const X402_PERMIT2_PROXIES: readonly string[] = ["0x402085c248eea27d92e8b30b2c58ed07f9e20001", "0x4020a4f3b7b90cca423b9fabcc0ce57c6c240002"];

export type SigningKind = "transaction" | "typed_data" | "message" | "authorization" | "raw_hash" | "x402_payment" | "solana_transaction" | "solana_message" | "unguarded_method";

export interface GuardCheck {
  request: RiskCheckRequest;
  result?: RiskCheckResult | undefined;
  interpretation: Interpretation;
}

export interface GuardVerdict {
  /** allow → signed · warn → signed only if `onWarn` approved · block / not_verified → refused. */
  action: Action;
  /** True when the signature was (or may be) produced. */
  signed: boolean;
  kind: SigningKind;
  /** What was about to be signed, decoded. */
  summary: string;
  /** Most important first. */
  reasons: string[];
  /**
   * Why it was refused: "blocked", "not_verified", "warn_declined", "local_danger",
   * "raw_hash_signing", "opaque_signature", "not_simulated", "unreadable_self_call", "no_chain",
   * "every_chain_authorization", "fee_cap", "unguarded_method", "uncopyable", "undecodable",
   * "unreadable_instruction".
   */
  code?: string | undefined;
  /** One per checked address (primary first). Empty when nothing needed checking. */
  checks: GuardCheck[];
}

export class X402CheckBlockedError extends Error {
  override readonly name = "X402CheckBlockedError";
  readonly verdict: GuardVerdict;
  constructor(verdict: GuardVerdict) {
    const tier = verdict.checks.find((c) => c.interpretation.action === verdict.action)?.interpretation.tier;
    super(`x402check refused to sign (${verdict.code ?? verdict.action}${tier ? `, tier ${tier}` : ""}): ${verdict.reasons[0] ?? "no verdict"}. ${verdict.summary}`.slice(0, 600));
    this.verdict = verdict;
  }
}

export interface GuardOptions {
  /** An x402check client. Default: one built from the options below. */
  client?: X402CheckClient | undefined;
  /** Prepaid credit token (x402c_…): each check is debited from it ($0.001, $0.005 simulated). */
  creditToken?: string | undefined;
  baseUrl?: string | undefined;
  /** Fetch for the API, the issuer's DID document and the Solana RPC. Pass a stable reference (the DID cache is keyed by it). */
  fetch?: FetchLike | undefined;
  /** Per API call. Default 10000 ms: a slow check fails closed. */
  timeoutMs?: number | undefined;
  /** The attestation issuer trusted. Default "did:web:x402check.xyz". */
  issuer?: string | undefined;
  /**
   * RFC 7638 thumbprints of the attestation keys accepted. Default: `X402CHECK_KEY_THUMBPRINTS`
   * when the issuer is did:web:x402check.xyz, so a DID document serving any other key (a
   * compromised deployment or domain) is refused. `false` disables pinning, e.g. for tests
   * against a local issuer.
   */
  pinnedKeys?: readonly string[] | false | undefined;
  /** A `warn` verdict: return true to sign anyway (e.g. after asking a human). Default: refuse. */
  onWarn?: ((verdict: GuardVerdict) => boolean | Promise<boolean>) | undefined;
  /** Every verdict, signed or refused, for audit logs. */
  onVerdict?: ((verdict: GuardVerdict) => void | Promise<void>) | undefined;
  /** The content the agent acted on (a page, a message, a tool output), checked for injected instructions. */
  context?: string | (() => string | undefined) | undefined;
  /** The site or app the agent is dealing with (URL or host). */
  origin?: string | undefined;
  /** Payees whose x402 payments are not checked (up to `trustedPayeeMaxAmount`). Default: x402check's own `pay_to`. */
  trustedPayees?: readonly string[] | undefined;
  /**
   * The largest payment to a trusted payee that is not checked, in atomic units (default 250000:
   * $0.25 of USDC, more than any check). A larger payment (a credit pack) is checked like any
   * other, so a stale or compromised pay_to can never take more than the price of checks.
   */
  trustedPayeeMaxAmount?: bigint | undefined;
  /** `sign({ hash })` and messages of opaque bytes sign anything, unreadable: refused unless true (some smart-account flows need it). */
  allowRawHashSigning?: boolean | undefined;
  /** EIP-7702 authorizations valid on every chain (chainId 0): refused unless true; then the delegate is checked on each chain the kit watch covers. */
  allowEveryChainAuthorization?: boolean | undefined;
  /** EVM: refuse a transaction whose maximum fee (gas × maxFeePerGas, or gas × gasPrice) exceeds this, in wei. Default: no cap. */
  maxFeeWei?: bigint | undefined;
  /** Chain of a message signature, and of a transaction that carries none, as a number. */
  chainId?: number | undefined;
  /**
   * Other signing or sending methods of the wrapped account or signer to pass through, UNCHECKED
   * (by name, e.g. ["signUserOperation"]). Default: none; they throw `X402CheckBlockedError`.
   */
  passthrough?: readonly string[] | undefined;
  /** Solana JSON-RPC, to resolve address lookup tables and token-account owners. Default: the public mainnet-beta endpoint. */
  solanaRpcUrl?: string | undefined;
  /** More Solana RPC endpoints that must return the same lookup tables and token-account owners (the RPC decides which address is checked). */
  solanaRpcUrls?: readonly string[] | undefined;
  /** CAIP-2 cluster of the Solana transactions signed. Default: mainnet. */
  solanaNetwork?: string | undefined;
  /** Solana: refuse when the signer pays fees above this, in lamports (signatures plus priority fee). Default 10,000,000 (0.01 SOL). */
  maxSolanaFeeLamports?: bigint | number | undefined;
}

/** What a signature request is, before decoding. */
export type SigningRequest =
  | {
      kind: "transaction";
      from: string;
      transaction: { to?: unknown; value?: unknown; data?: unknown; input?: unknown; chainId?: unknown; gas?: unknown; maxFeePerGas?: unknown; gasPrice?: unknown };
    }
  | { kind: "typed_data"; from: string; typedData: { domain?: Record<string, unknown> | undefined; types?: Record<string, unknown> | undefined; primaryType?: unknown; message?: unknown } }
  | { kind: "message"; from: string; message: unknown }
  | { kind: "authorization"; from: string; contractAddress: string; chainId?: unknown }
  | { kind: "x402_payment"; payTo: string; network: string; amount?: string | undefined; asset?: string | undefined; resource?: string | undefined }
  | { kind: "solana_transaction"; from: string; messageBytes: Uint8Array }
  | { kind: "solana_message"; from: string; message: Uint8Array };

const SEVERITY: Record<Action, number> = { allow: 0, warn: 1, block: 2, not_verified: 3 };
const MAX_CONTEXT = 4096;
/** Counterparties checked for one Solana transaction (a batch); more is refused, never partly checked. */
const MAX_SOLANA_CHECKS = 5;
const DEFAULT_MAX_SOLANA_FEE_LAMPORTS = 10_000_000n;
/** The chains an every-chain (chainId 0) delegation is checked on when allowed: those the kit watch covers. */
const EVERY_CHAIN_CHECKS = ["eip155:1", "eip155:8453"];
/** Account members that sign or send: intercepted, or refused unless passed through by name. */
const SIGNING_METHOD = /^(sign|send|execute|transfer|write|approve|permit|swap|withdraw|deploy)/i;
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

function sameAddress(a: string, b: string): boolean {
  return /^0x/i.test(a) && /^0x/i.test(b) ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function jsonSafe(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
}

function hexValue(value: unknown): unknown {
  return typeof value === "bigint" ? `0x${value.toString(16)}` : typeof value === "number" && Number.isSafeInteger(value) ? `0x${value.toString(16)}` : value;
}

/** A non-negative integer from a bigint, a safe integer, or a decimal or 0x-hex string (null otherwise). */
function toBigInt(value: unknown): bigint | null {
  if (typeof value === "bigint") return value >= 0n ? value : null;
  if (typeof value === "number") return Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : null;
  if (typeof value === "string" && (/^\d{1,78}$/.test(value) || /^0x[0-9a-fA-F]{1,64}$/.test(value))) return BigInt(value);
  return null;
}

/** EIP712Domain from the fields a domain actually has (viem omits the type; the decoder wants it). */
function withDomainType(td: Extract<SigningRequest, { kind: "typed_data" }>["typedData"]): Record<string, unknown> {
  const domain = td.domain ?? {};
  const types: Record<string, unknown> = { ...(td.types ?? {}) };
  if (!types["EIP712Domain"]) {
    const fields: Array<{ name: string; type: string }> = [];
    if (domain["name"] !== undefined) fields.push({ name: "name", type: "string" });
    if (domain["version"] !== undefined) fields.push({ name: "version", type: "string" });
    if (domain["chainId"] !== undefined) fields.push({ name: "chainId", type: "uint256" });
    if (domain["verifyingContract"] !== undefined) fields.push({ name: "verifyingContract", type: "address" });
    if (domain["salt"] !== undefined) fields.push({ name: "salt", type: "bytes32" });
    types["EIP712Domain"] = fields;
  }
  return jsonSafe({ types, domain, primaryType: td.primaryType, message: td.message }) as Record<string, unknown>;
}

type X402Signature = { payTo: string; amount: string; asset?: string; chainId?: string };

/** x402's EVM payment signature (EIP-3009): the Snap decoder does not model it, so it is read here. */
function eip3009(td: Extract<SigningRequest, { kind: "typed_data" }>["typedData"]): X402Signature | null {
  if (td.primaryType !== "TransferWithAuthorization" && td.primaryType !== "ReceiveWithAuthorization") return null;
  const message = (td.message ?? {}) as Record<string, unknown>;
  const to = message["to"];
  const amount = toBigInt(message["value"]);
  if (typeof to !== "string" || !EVM_ADDRESS.test(to) || amount === null) return null;
  const domain = td.domain ?? {};
  const verifying = domain["verifyingContract"];
  const chainId = domain["chainId"];
  return {
    payTo: to,
    amount: amount.toString(),
    ...(typeof verifying === "string" && EVM_ADDRESS.test(verifying) ? { asset: verifying } : {}),
    ...(chainId !== undefined ? { chainId: String(chainId) } : {}),
  };
}

/** x402's Permit2 payment (exact and upto schemes): spender is an x402 proxy, the payee is the witness `to`. */
function x402Permit2(td: Extract<SigningRequest, { kind: "typed_data" }>["typedData"]): X402Signature | null {
  if (td.primaryType !== "PermitWitnessTransferFrom") return null;
  const message = (td.message ?? {}) as Record<string, unknown>;
  const spender = message["spender"];
  if (typeof spender !== "string" || !X402_PERMIT2_PROXIES.includes(spender.toLowerCase())) return null;
  const witness = (message["witness"] ?? {}) as Record<string, unknown>;
  const permitted = (message["permitted"] ?? {}) as Record<string, unknown>;
  const to = witness["to"];
  const amount = toBigInt(permitted["amount"]);
  if (typeof to !== "string" || !EVM_ADDRESS.test(to) || amount === null) return null;
  const token = permitted["token"];
  const chainId = (td.domain ?? {})["chainId"];
  return { payTo: to, amount: amount.toString(), ...(typeof token === "string" && EVM_ADDRESS.test(token) ? { asset: token } : {}), ...(chainId !== undefined ? { chainId: String(chainId) } : {}) };
}

/** The bytes of a message signed as raw data when they are not readable text; null for text. */
function opaqueBytes(message: unknown): number | null {
  const raw = message instanceof Uint8Array ? message : typeof message === "object" && message !== null && "raw" in message ? (message as { raw: unknown }).raw : undefined;
  // A string message is text: viem signs it as UTF-8.
  if (raw === undefined) return null;
  let bytes: Uint8Array | null = null;
  if (raw instanceof Uint8Array) bytes = raw;
  else if (typeof raw === "string" && /^0x(?:[0-9a-fA-F]{2})*$/.test(raw)) bytes = Uint8Array.from((raw.slice(2).match(/../g) ?? []).map((h) => parseInt(h, 16)));
  if (!bytes) return 0;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (text.length > 0 && !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(text)) return null;
  } catch {
    // Not UTF-8: opaque.
  }
  return bytes.length;
}

/** The lowercase hostname the provider accepts, or undefined (an invalid host is omitted, not sent). */
function host(url: string | undefined): string | undefined {
  return url ? (normalizeHost(url) ?? undefined) : undefined;
}

function pinnedKeysFor(options: GuardOptions): readonly string[] | undefined {
  if (options.pinnedKeys === false) return undefined;
  if (options.pinnedKeys) return options.pinnedKeys;
  return (options.issuer ?? DEFAULT_ISSUER) === DEFAULT_ISSUER ? X402CHECK_KEY_THUMBPRINTS : undefined;
}

/** Deep copy of what is about to be signed: the copy is checked, and the copy is signed. */
function snapshot<T>(value: T): T {
  return value === undefined || value === null ? value : structuredClone(value);
}

/** A guard with its own client: `check` decides, `enforce` throws when the key must not sign. */
export function createGuard(options: GuardOptions = {}) {
  const client = options.client ?? createClient({ baseUrl: options.baseUrl, fetch: options.fetch, timeoutMs: options.timeoutMs ?? 10_000, creditToken: options.creditToken });
  const trusted = options.trustedPayees ?? X402CHECK_PAY_TO;
  const pinnedKeys = pinnedKeysFor(options);
  const isTrusted = (address: string) => trusted.some((t) => sameAddress(t, address));
  const agentContext = () => {
    const c = typeof options.context === "function" ? options.context() : options.context;
    return typeof c === "string" && c.trim() ? c.trim() : undefined;
  };

  /** Adds the agent's own context in front of the decoded description (the request is then bound as sent). */
  function withAgentContext(body: RiskCheckBody): RiskCheckRequest {
    const extra = agentContext();
    const context = extra ? `${extra.slice(0, MAX_CONTEXT - 200)}\n\nAbout to sign: ${body.context}`.slice(0, MAX_CONTEXT) : body.context;
    return { ...(body as RiskCheckRequest), context };
  }

  function verdictOf(kind: SigningKind, summary: string, action: Action, reasons: string[], checks: GuardCheck[], code?: string): GuardVerdict {
    return { action, signed: action === "allow", kind, summary, reasons, checks, ...(code ? { code } : {}) };
  }

  /** Checks the requests and combines the verdicts: the worst one decides. */
  async function evaluate(kind: SigningKind, summary: string, requests: RiskCheckRequest[]): Promise<GuardVerdict> {
    let results: RiskCheckResult[];
    try {
      results = requests.length === 1 ? [await client.check(requests[0] as RiskCheckRequest)] : await client.checkBatch(requests);
    } catch (err) {
      const interpretation = interpret(err);
      return verdictOf(kind, summary, "not_verified", interpretation.reasons, [{ request: requests[0] as RiskCheckRequest, interpretation }], "not_verified");
    }
    const checks: GuardCheck[] = await Promise.all(
      requests.map(async (request, i) => {
        const result = results[i];
        const verification = await verifyAttestation(result?.jws, { issuer: options.issuer, request, maxAgeSeconds: 300, fetch: options.fetch, pinnedKeys });
        return { request, result, interpretation: interpret(result, { verification }) };
      }),
    );
    const worst = checks.reduce((w, c) => (SEVERITY[c.interpretation.action] > SEVERITY[w.interpretation.action] ? c : w));
    const action = worst.interpretation.action;
    const reasons = [...worst.interpretation.reasons, ...checks.filter((c) => c !== worst && c.interpretation.action !== "allow").flatMap((c) => c.interpretation.reasons)];
    return verdictOf(kind, summary, action, reasons, checks, action === "block" ? "blocked" : action === "not_verified" ? "not_verified" : undefined);
  }

  /** Decodes a signature request and checks it: never throws, even on failure (the verdict says so). */
  async function check(request: SigningRequest): Promise<GuardVerdict> {
    if (request.kind === "solana_transaction") return checkSolanaTransaction(request.from, request.messageBytes);
    if (request.kind === "solana_message") return checkSolanaMessage(request.from, request.message);
    if (request.kind === "x402_payment") {
      // x402 v1 network names ("base", "solana", ...) become the CAIP-2 ids the provider accepts.
      const network = toCaip2(request.network) ?? request.network;
      const summary = `x402 payment of ${request.amount ?? "?"} (atomic units) of ${request.asset ?? "?"} on ${network} to ${request.payTo}${request.resource ? ` for ${request.resource}` : ""}`;
      const small = typeof request.amount === "string" && /^\d{1,78}$/.test(request.amount) && BigInt(request.amount) <= (options.trustedPayeeMaxAmount ?? TRUSTED_PAYEE_MAX_AMOUNT);
      if (isTrusted(request.payTo) && small) return verdictOf("x402_payment", summary, "allow", ["payment to x402check itself for checks (trusted payee, small amount): not checked"], []);
      const payment: PaymentBinding = {
        network,
        pay_to: request.payTo,
        ...(request.amount && /^\d{1,78}$/.test(request.amount) ? { amount: request.amount } : {}),
        ...(request.asset ? { asset: request.asset } : {}),
        ...(request.resource && request.resource.length <= 512 && /^https?:\/\/\S+$/.test(request.resource) ? { resource: request.resource } : {}),
      };
      const domain = host(request.resource) ?? host(options.origin);
      const body: RiskCheckBody = { wallet: request.payTo, chain: network, ...(domain ? { domain } : {}), context: summary, payment, interaction: { type: "token_transfer" } };
      return evaluate("x402_payment", summary, [withAgentContext(body)]);
    }
    if (request.kind === "authorization") {
      const chainId = toBigInt(request.chainId);
      const everyChain = chainId === 0n;
      const summary = `EIP-7702 authorization: ${request.from} delegates its code to ${request.contractAddress}${everyChain ? " on EVERY chain (chainId 0)" : chainId !== null ? ` on eip155:${chainId}` : ""}. The delegate gains full control of the account and its assets.`;
      if (chainId === null) return verdictOf("authorization", summary, "not_verified", ["the authorization names no chain, so the delegate cannot be checked where it would act"], [], "no_chain");
      if (everyChain && !options.allowEveryChainAuthorization) {
        return verdictOf("authorization", summary, "block", ["an EIP-7702 authorization with chainId 0 hands the account to the delegate on every chain at once (allowEveryChainAuthorization enables it)"], [], "every_chain_authorization");
      }
      // Every-chain delegations (when allowed) are checked on each chain the kit watch covers, so code and delegate intelligence apply.
      const chains = everyChain ? [...new Set([...EVERY_CHAIN_CHECKS, ...(options.chainId !== undefined ? [`eip155:${options.chainId}`] : [])])] : [`eip155:${chainId}`];
      const domain = host(options.origin);
      const bodies: RiskCheckBody[] = chains.map((chain) => ({ wallet: request.contractAddress, chain, ...(domain ? { domain } : {}), context: summary, interaction: { type: "contract_call" } }));
      return evaluate("authorization", summary, bodies.map(withAgentContext));
    }

    let decoded: Decoded;
    let kind: SigningKind;
    if (request.kind === "typed_data") {
      // x402 on EVM: an EIP-3009 authorization or a Permit2 transfer to an x402 proxy is a payment,
      // checked exactly like one and bound to its payee, amount and asset.
      const payment = eip3009(request.typedData) ?? x402Permit2(request.typedData);
      if (payment) {
        const network = payment.chainId && /^\d+$/.test(payment.chainId) ? `eip155:${payment.chainId}` : undefined;
        if (network) return check({ kind: "x402_payment", payTo: payment.payTo, network, amount: payment.amount, asset: payment.asset });
      }
    }

    let hasData = false;
    let hasValue = false;
    let deployment = false;
    let selfCall = false;
    if (request.kind === "transaction") {
      kind = "transaction";
      const tx = request.transaction;
      const chainId = tx.chainId ?? options.chainId;
      const data = tx.data ?? tx.input;
      hasData = typeof data === "string" && data !== "" && data !== "0x";
      hasValue = (toBigInt(tx.value) ?? 0n) > 0n;
      deployment = tx.to === undefined || tx.to === null;
      selfCall = typeof tx.to === "string" && tx.to.toLowerCase() === request.from.toLowerCase();
      decoded = decodeTransaction({ from: request.from, to: tx.to, value: hexValue(tx.value), data }, chainId);
      if (chainId === undefined || chainId === null) {
        return verdictOf(kind, decoded.summary, "not_verified", ["the transaction carries no chainId: a pre-EIP-155 transaction is valid on every chain, and the checks need its chain (set chainId or options.chainId)"], [], "no_chain");
      }
      if (options.maxFeeWei !== undefined) {
        const gas = toBigInt(tx.gas);
        const price = toBigInt(tx.maxFeePerGas ?? tx.gasPrice);
        if (gas !== null && price !== null && gas * price > options.maxFeeWei) {
          return verdictOf(kind, decoded.summary, "block", [`the transaction can charge up to ${gas * price} wei in fees, above the cap of ${options.maxFeeWei} wei (maxFeeWei)`], [], "fee_cap");
        }
      }
    } else if (request.kind === "typed_data") {
      kind = "typed_data";
      decoded = decodeTypedData(withDomainType(request.typedData), request.from, "eth_signTypedData_v4");
    } else {
      kind = "message";
      const m = request.message as unknown;
      const opaque = opaqueBytes(m);
      if (opaque !== null && !options.allowRawHashSigning) {
        return verdictOf(
          kind,
          `signMessage of ${opaque} bytes of binary data`,
          "block",
          [`a message of opaque bytes${opaque === 32 ? " (a 32-byte hash)" : ""} can authorize anything, e.g. a smart-account user operation or a Safe transaction; it is refused like sign({ hash }) (allowRawHashSigning: true enables it, unchecked)`],
          [],
          "raw_hash_signing",
        );
      }
      const raw = typeof m === "object" && m !== null && "raw" in m ? (m as { raw: unknown }).raw : m;
      const data = raw instanceof Uint8Array ? `0x${[...raw].map((b) => b.toString(16).padStart(2, "0")).join("")}` : raw;
      decoded = decodePersonalSign(data, request.from, host(options.origin));
      if (!decoded.chain && options.chainId !== undefined) decoded = { ...decoded, chain: `eip155:${options.chainId}` };
    }

    if (decoded.danger.length > 0) return verdictOf(kind, decoded.summary, "block", decoded.danger, [], "local_danger");
    // A signature over content the decoders mark unreadable (an opaque hash or calldata carrier) is never made blind.
    const opaque = (decoded as Decoded & { opaque?: string | undefined }).opaque;
    if (opaque) return verdictOf(kind, decoded.summary, "not_verified", [`it authorizes content this guard cannot read (${opaque}); nothing unreadable is signed`], [], "opaque_signature");
    // A transaction whose effects cannot be simulated (calldata too large, malformed fields) is not signed on an address check alone.
    if (kind === "transaction" && (deployment ? hasValue : decoded.simulationSkipped !== undefined)) {
      const why = decoded.simulationSkipped ?? "contract deployments are not simulated, and this one carries value";
      return verdictOf(kind, decoded.summary, "not_verified", [`its effects could not be simulated (${why}); a transaction that moves value or calls code is not signed on an address check alone`], [], "not_simulated");
    }
    const bodies = buildRiskCheckBodies(decoded, options.origin);
    if (bodies.length === 0) {
      // Only provably inert requests pass with nothing to check.
      if (kind === "transaction" && selfCall && hasData) {
        return verdictOf(kind, decoded.summary, "not_verified", ["a call to the signer's own account with calldata this guard cannot read (on an EIP-7702 account it can install modules, add owners or upgrade)"], [], "unreadable_self_call");
      }
      return verdictOf(kind, decoded.summary, "allow", [decoded.localNote ?? "nothing to check: no counterparty"], []);
    }
    return evaluate(kind, decoded.summary, bodies.map(withAgentContext));
  }

  const solanaNetwork = options.solanaNetwork ?? SOLANA_MAINNET;
  const rpcFetch: FetchLike = options.fetch ?? ((url, init) => globalThis.fetch(url, init));
  const rpcTimeout = options.timeoutMs ?? 10_000;
  const maxSolanaFee = BigInt(options.maxSolanaFeeLamports ?? DEFAULT_MAX_SOLANA_FEE_LAMPORTS);

  /** The accounts, read from every configured RPC endpoint; `same` compares what is used from each. */
  async function solanaAccounts<T>(addresses: string[], use: (account: SolanaAccount | null, address: string) => T, same: (a: T, b: T) => boolean): Promise<T[]> {
    const urls = [options.solanaRpcUrl ?? DEFAULT_SOLANA_RPC, ...(options.solanaRpcUrls ?? [])];
    const answers = await Promise.all(urls.map(async (url) => (await getSolanaAccounts(url, addresses, rpcFetch, rpcTimeout)).map((a, i) => use(a, addresses[i] as string))));
    const [first, ...rest] = answers as [T[], ...T[][]];
    if (rest.some((other) => other.some((value, i) => !same(value, first[i] as T)))) throw new Error("the Solana RPC endpoints disagree");
    return first;
  }

  async function checkSolanaTransaction(from: string, messageBytes: Uint8Array): Promise<GuardVerdict> {
    const kind: SigningKind = "solana_transaction";
    let message: SolanaMessage;
    try {
      message = decodeSolanaMessage(messageBytes);
    } catch (err) {
      return verdictOf(kind, "a Solana transaction that could not be decoded", "not_verified", [`the transaction could not be decoded (${(err as Error).message}): nothing unreadable is signed`], [], "undecodable");
    }
    let keys: string[];
    try {
      const tables = new Map<string, string[]>();
      const tableAddresses = message.lookups.map((l) => l.table);
      const read = await solanaAccounts(
        tableAddresses,
        (table, address) => {
          if (!table || table.owner !== ADDRESS_LOOKUP_TABLE_PROGRAM) throw new Error(`${address} is not an address lookup table`);
          return lookupTableAddresses(table.data);
        },
        // Only the entries this message loads must agree (a table may grow between two reads).
        (a, b) => message.lookups.every((l) => [...l.writable, ...l.readonly].every((i) => a[i] === b[i])),
      );
      tableAddresses.forEach((address, i) => tables.set(address, read[i] as string[]));
      keys = accountKeys(message, tables);
    } catch (err) {
      return verdictOf(kind, "a Solana v0 transaction with address lookup tables", "not_verified", [`its address lookup tables could not be resolved (${String((err as Error).message).slice(0, 160)}), so its accounts are unknown`], [], "not_verified");
    }
    const analysis = analyzeSolanaMessage(message, keys, from);
    const draft = solanaSummary(message, analysis, analysis.findings);
    if (!analysis.required) return verdictOf(kind, draft, "allow", ["the signer is not a required signer of this transaction: its signature authorizes nothing"], []);
    if (analysis.danger.length > 0) return verdictOf(kind, draft, "block", analysis.danger, [], "local_danger");
    if (analysis.maxFeeLamports !== undefined && analysis.maxFeeLamports > maxSolanaFee) {
      return verdictOf(kind, draft, "block", [`as fee payer, the signer can be charged up to ${analysis.maxFeeLamports} lamports in fees (priority fees go to the block producer), above the cap of ${maxSolanaFee} (maxSolanaFeeLamports)`], [], "fee_cap");
    }
    if (analysis.unreadable.length > 0) {
      return verdictOf(kind, draft, "not_verified", [`the signer authorizes instructions this guard cannot read: ${analysis.unreadable.join(", ")}. Nothing unreadable is signed`], [], "unreadable_instruction");
    }

    // The owner of each receiving token account: the ATA program's create instruction names it; otherwise the chain does.
    const pending = [...new Set(analysis.findings.flatMap((f) => (f.kind === "token_transfer" && !analysis.created.has(f.account) ? [f.account] : [])))];
    const owners = new Map<string, { owner: string; mint: string }>(analysis.created);
    try {
      const infos = await solanaAccounts(
        pending,
        (account, address) => {
          const info = account ? tokenAccountInfo(account) : null;
          if (!info) throw new Error(`${address} ${account ? "is not a token account" : "does not exist, and the transaction does not create it"}`);
          return info;
        },
        (a, b) => a.owner === b.owner && a.mint === b.mint,
      );
      pending.forEach((address, i) => owners.set(address, infos[i] as { owner: string; mint: string }));
    } catch (err) {
      return verdictOf(kind, draft, "not_verified", [`the owner of a receiving token account could not be established (${String((err as Error).message).slice(0, 160)})`], [], "not_verified");
    }
    const findings = analysis.findings.flatMap((f): SolanaFinding[] => {
      if (f.kind !== "token_transfer") return [f];
      const info = owners.get(f.account);
      // Between the signer's own token accounts: nothing leaves the signer.
      return info && info.owner !== from ? [{ ...f, owner: info.owner, mint: f.mint ?? info.mint }] : [];
    });
    const summary = solanaSummary(message, analysis, findings);
    const bodies = solanaBodies(findings, summary);
    if (bodies.length === 0) return verdictOf(kind, summary, "allow", ["nothing to check: the signer sends nothing, approves no one and calls no program"], []);
    if (bodies.length > MAX_SOLANA_CHECKS) {
      return verdictOf(kind, summary, "not_verified", [`${bodies.length} counterparties in one transaction; at most ${MAX_SOLANA_CHECKS} are checked, and none is left unchecked`], [], "not_verified");
    }
    const verdict = await evaluate(kind, summary, bodies.map(withAgentContext));
    // A durable nonce keeps a signed transfer valid forever: never an unremarked allow.
    if (verdict.action === "allow" && analysis.durableNonce) {
      return { ...verdict, action: "warn", signed: false, reasons: ["it uses a durable nonce: once signed, it never expires and can be submitted at any later time", ...verdict.reasons] };
    }
    return verdict;
  }

  /** One check per counterparty: amounts to the same payee and asset are added up. */
  function solanaBodies(findings: SolanaFinding[], summary: string): RiskCheckBody[] {
    const domain = host(options.origin);
    const merged = new Map<string, RiskCheckBody>();
    const ordered = [...findings.filter((f) => f.kind !== "program_call"), ...findings.filter((f) => f.kind === "program_call")];
    for (const f of ordered) {
      const base = { chain: solanaNetwork, ...(domain ? { domain } : {}), context: summary };
      let key: string;
      let body: RiskCheckBody;
      if (f.kind === "native_transfer") {
        key = `native|${f.to}`;
        body = { ...base, wallet: f.to, interaction: { type: "native_transfer" }, payment: { network: solanaNetwork, pay_to: f.to, asset: "native", ...(f.lamports ? { amount: f.lamports } : {}) } };
      } else if (f.kind === "token_transfer") {
        const owner = f.owner as string;
        key = `token|${owner}|${f.mint ?? ""}`;
        body = { ...base, wallet: owner, interaction: { type: "token_transfer" }, payment: { network: solanaNetwork, pay_to: owner, amount: f.amount, ...(f.mint ? { asset: f.mint } : {}) } };
      } else if (f.kind === "token_approval") {
        key = `approval|${f.delegate}|${f.mint ?? ""}`;
        body = {
          ...base,
          wallet: f.delegate,
          interaction: f.unlimited ? { type: "token_approval", unlimited: true } : { type: "token_approval" },
          payment: { network: solanaNetwork, pay_to: f.delegate, ...(f.unlimited ? {} : { amount: f.amount }), ...(f.mint ? { asset: f.mint } : {}) },
        };
      } else {
        key = `program|${f.program}`;
        body = { ...base, wallet: f.program, interaction: { type: "contract_call" } };
      }
      const seen = merged.get(key);
      if (!seen) {
        merged.set(key, body);
        continue;
      }
      if (body.interaction.unlimited) seen.interaction = body.interaction;
      if (seen.payment) {
        const [a, b] = [seen.payment.amount, body.payment?.amount];
        if (a !== undefined && b !== undefined && !seen.interaction.unlimited) {
          seen.payment = { ...seen.payment, amount: (BigInt(a) + BigInt(b)).toString() };
        } else {
          // An unknown or unlimited part makes the total unknown: bound without an amount.
          const { amount: _unknown, ...rest } = seen.payment;
          seen.payment = rest;
        }
      }
    }
    return [...merged.values()];
  }

  async function checkSolanaMessage(from: string, message: Uint8Array): Promise<GuardVerdict> {
    const kind: SigningKind = "solana_message";
    // A "message" whose bytes are a transaction message: its signature would authorize that transaction.
    if (isSolanaTransactionMessage(message)) {
      return verdictOf(kind, "a Solana message whose bytes are a transaction", "block", ["the message is a serialized Solana transaction: signing it would authorize that transaction"], [], "local_danger");
    }
    let text: string | undefined;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(message);
    } catch {
      text = undefined;
    }
    // Sign-In With Solana names the site it signs in to; a different requesting origin is the login-phishing pattern.
    const siws = text ? /^(?:https?:\/\/)?([A-Za-z0-9.-]{1,253}(?::\d{1,5})?) wants you to sign in with your Solana account:/.exec(text) : null;
    const summary = text ? `Solana message signature (${message.length} bytes): ${text.slice(0, 300)}` : `Solana message signature of ${message.length} bytes of binary data`;
    const signsInTo = siws?.[1] ? host(siws[1]) : undefined;
    const origin = host(options.origin);
    if (signsInTo && origin && signsInTo !== origin) {
      return verdictOf(kind, summary, "block", [`the message signs in to ${signsInTo}, but the request comes from ${origin}: the login-phishing pattern`], [], "local_danger");
    }
    const domain = origin ?? signsInTo;
    if (!domain) return verdictOf(kind, summary, "allow", ["nothing to check: a message with no counterparty and no site"], []);
    const body: RiskCheckBody = { wallet: from, chain: solanaNetwork, domain, context: summary, interaction: { type: "message_signature" } };
    return evaluate(kind, summary, [withAgentContext(body)]);
  }

  /** Checks, reports (`onVerdict`), and throws `X402CheckBlockedError` unless the key may sign. */
  async function enforce(request: SigningRequest): Promise<GuardVerdict> {
    let verdict = await check(request);
    if (verdict.action === "warn") {
      const approved = options.onWarn ? await Promise.resolve(options.onWarn(verdict)).catch(() => false) : false;
      verdict = approved ? { ...verdict, signed: true } : { ...verdict, signed: false, code: "warn_declined" };
    }
    await Promise.resolve(options.onVerdict?.(verdict)).catch(() => undefined);
    if (!verdict.signed) throw new X402CheckBlockedError(verdict);
    return verdict;
  }

  return { check, enforce, client };
}

/** The account methods the guard intercepts (a viem `LocalAccount`, or any object shaped like one). */
export interface GuardableAccount {
  address: string;
  // Loose signatures on purpose: viem's are generic and overloaded; the wrapper passes arguments through unchanged.
  signTransaction?: ((transaction: any, options?: any) => Promise<any>) | undefined;
  signTypedData?: ((parameters: any) => Promise<any>) | undefined;
  signMessage?: ((parameters: any) => Promise<any>) | undefined;
  signAuthorization?: ((parameters: any) => Promise<any>) | undefined;
  sign?: ((parameters: any) => Promise<any>) | undefined;
}

/** A refusal thrown after reporting it (`onVerdict`). */
async function refuse(verdict: GuardVerdict, options: GuardOptions): Promise<never> {
  await Promise.resolve(options.onVerdict?.(verdict)).catch(() => undefined);
  throw new X402CheckBlockedError(verdict);
}

/**
 * A copy of `source` without the intercepted methods: plain properties are kept, and any other
 * member that signs or sends (e.g. a smart account's `signUserOperation`) refuses, unless
 * `options.passthrough` names it.
 */
function guardedCopy<T extends object>(source: T, intercepted: readonly string[], options: GuardOptions): T {
  const copy: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(source)) {
    if (intercepted.includes(name)) continue;
    const refused = typeof value === "function" && SIGNING_METHOD.test(name) && !(options.passthrough ?? []).includes(name);
    copy[name] = refused
      ? () =>
          refuse(
            {
              action: "block",
              signed: false,
              kind: "unguarded_method",
              summary: `${name}() is not checked by the x402check guard`,
              reasons: [`${name} signs or sends without a check, so the guarded account refuses it (options.passthrough: ["${name}"] lets it through, unchecked)`],
              code: "unguarded_method",
              checks: [],
            },
            options,
          )
      : value;
  }
  return copy as T;
}

/** A copy of the request, or a refusal when it cannot be copied (the checked value must be the signed value). */
async function copied<T>(value: T, kind: SigningKind, options: GuardOptions): Promise<T> {
  try {
    return snapshot(value);
  } catch {
    return refuse({ action: "not_verified", signed: false, kind, summary: "a request that cannot be copied for checking", reasons: ["the request holds values that cannot be copied (functions, proxies), so what is checked could differ from what is signed"], code: "uncopyable", checks: [] }, options);
  }
}

/**
 * The same account, with x402check between it and every signature: decode, check, verify, then
 * sign or throw `X402CheckBlockedError`. Pass it wherever the agent signs: a viem wallet client,
 * an x402 client (`new ExactEvmScheme(guarded)`), an agent framework. Smart accounts: members
 * that sign or send other than the five intercepted here (e.g. `signUserOperation`) refuse.
 */
export function guardAccount<A extends GuardableAccount>(account: A, options: GuardOptions = {}): A {
  const guard = createGuard(options);
  const from = account.address;
  const wrapped = guardedCopy(account, ["signTransaction", "signTypedData", "signMessage", "signAuthorization", "sign"], options);
  if (account.signTransaction) {
    const sign = account.signTransaction.bind(account);
    wrapped.signTransaction = async (transaction: any, opts?: any) => {
      const tx = await copied(transaction ?? {}, "transaction", options);
      await guard.enforce({ kind: "transaction", from, transaction: tx });
      return sign(tx, opts);
    };
  }
  if (account.signTypedData) {
    const sign = account.signTypedData.bind(account);
    wrapped.signTypedData = async (parameters: any) => {
      const params = await copied(parameters ?? {}, "typed_data", options);
      await guard.enforce({ kind: "typed_data", from, typedData: params });
      return sign(params);
    };
  }
  if (account.signMessage) {
    const sign = account.signMessage.bind(account);
    wrapped.signMessage = async (parameters: any) => {
      const params = await copied(parameters ?? {}, "message", options);
      await guard.enforce({ kind: "message", from, message: params?.message });
      return sign(params);
    };
  }
  if (account.signAuthorization) {
    const sign = account.signAuthorization.bind(account);
    wrapped.signAuthorization = async (parameters: any) => {
      const params = await copied(parameters ?? {}, "authorization", options);
      const contractAddress = String(params?.contractAddress ?? params?.address ?? "");
      await guard.enforce({ kind: "authorization", from, contractAddress, chainId: params?.chainId });
      return sign(params);
    };
  }
  if (account.sign) {
    if (options.allowRawHashSigning) {
      wrapped.sign = account.sign.bind(account);
    } else {
      wrapped.sign = () =>
        refuse(
          {
            action: "block",
            signed: false,
            kind: "raw_hash",
            summary: "sign({ hash }) signs an opaque 32-byte value that could authorize anything.",
            reasons: ["raw hash signing is disabled by the x402check guard (allowRawHashSigning: true enables it, unchecked)"],
            code: "raw_hash_signing",
            checks: [],
          },
          options,
        );
    }
  }
  return wrapped;
}

/** A Solana signer (@solana/kit), structurally: any of its signing methods, each taking a batch. */
export interface GuardableSolanaSigner {
  address: string;
  // Loose on purpose: @solana/kit's types are branded; the wrapper passes arguments through unchanged.
  signTransactions?: ((transactions: readonly any[], config?: any) => Promise<any>) | undefined;
  modifyAndSignTransactions?: ((transactions: readonly any[], config?: any) => Promise<any>) | undefined;
  signAndSendTransactions?: ((transactions: readonly any[], config?: any) => Promise<any>) | undefined;
  signMessages?: ((messages: readonly any[], config?: any) => Promise<any>) | undefined;
  modifyAndSignMessages?: ((messages: readonly any[], config?: any) => Promise<any>) | undefined;
}

const SOLANA_TRANSACTION_METHODS = ["signTransactions", "modifyAndSignTransactions", "signAndSendTransactions"] as const;
const SOLANA_MESSAGE_METHODS = ["signMessages", "modifyAndSignMessages"] as const;

/**
 * The same Solana signer, with x402check between it and every signature. Every transaction of a
 * batch is copied, decoded and checked first; one refusal refuses the batch, and nothing is
 * signed. The copies are what gets signed. Pass it wherever the agent signs:
 * `signTransactionMessageWithSigners`, an x402 client (`new ExactSvmScheme(guarded)`), an
 * agent framework. Other members that sign or send refuse unless `options.passthrough` names them.
 */
export function guardSolanaSigner<S extends GuardableSolanaSigner>(signer: S, options: GuardOptions = {}): S {
  const guard = createGuard(options);
  const from = String(signer.address);
  const wrapped = guardedCopy(signer, [...SOLANA_TRANSACTION_METHODS, ...SOLANA_MESSAGE_METHODS], options);
  const undecodable = (kind: SigningKind, what: string) =>
    refuse({ action: "not_verified", signed: false, kind, summary: `a Solana ${what} without its bytes`, reasons: [`only ${what}s with byte content can be checked`], code: "undecodable", checks: [] }, options);
  for (const method of SOLANA_TRANSACTION_METHODS) {
    const sign = signer[method]?.bind(signer);
    if (!sign) continue;
    wrapped[method] = async (txs: readonly any[], config?: any) => {
      const copies: any[] = [];
      for (const tx of txs ?? []) {
        if (!(tx?.messageBytes instanceof Uint8Array)) return undecodable("solana_transaction", "transaction");
        copies.push({ ...tx, messageBytes: new Uint8Array(tx.messageBytes) });
      }
      for (const tx of copies) await guard.enforce({ kind: "solana_transaction", from, messageBytes: tx.messageBytes });
      return sign(copies, config);
    };
  }
  for (const method of SOLANA_MESSAGE_METHODS) {
    const sign = signer[method]?.bind(signer);
    if (!sign) continue;
    wrapped[method] = async (msgs: readonly any[], config?: any) => {
      const copies: any[] = [];
      for (const m of msgs ?? []) {
        if (!(m?.content instanceof Uint8Array)) return undecodable("solana_message", "message");
        copies.push({ ...m, content: new Uint8Array(m.content) });
      }
      for (const m of copies) await guard.enforce({ kind: "solana_message", from, message: m.content });
      return sign(copies, config);
    };
  }
  return wrapped;
}

/** A Solana transaction, in words: what the signer sends, approves and calls. */
function solanaSummary(message: SolanaMessage, analysis: SolanaAnalysis, findings: SolanaFinding[]): string {
  const parts = findings.map((f) => {
    switch (f.kind) {
      case "native_transfer":
        return `sends ${f.lamports ? `${f.lamports} lamports` : "an account's lamports"} to ${f.to} (${f.how})`;
      case "token_transfer":
        return `transfers ${f.amount} base units of ${f.mint ? `token ${f.mint}` : "a token"} to ${f.owner ? `${f.owner} (token account ${f.account})` : `token account ${f.account}`}`;
      case "token_approval":
        return `approves ${f.delegate} to spend ${f.unlimited ? "an UNLIMITED amount" : `${f.amount} base units`} of ${f.mint ? `token ${f.mint}` : "a token"}`;
      default:
        return `calls program ${f.program} with the signer's authority`;
    }
  });
  const what = parts.length > 0 ? parts.join("; ") : "sends nothing, approves no one and calls no program";
  const notes = [...analysis.danger, ...analysis.notes];
  return `Solana transaction (${message.version === 0 ? "v0" : "legacy"}, ${message.instructions.length} instructions): the signer ${what}${notes.length ? `. Also: ${notes.join("; ")}` : ""}.`.slice(0, 1200);
}

/** The x402 client hook's context (`onBeforePaymentCreation`), structurally. */
export interface PaymentCreationContextLike {
  paymentRequired?: { resource?: { url?: string } | undefined } | undefined;
  selectedRequirements: { network: string; payTo: string; amount?: string | undefined; asset?: string | undefined };
}

/**
 * An x402 client hook: `client.onBeforePaymentCreation(x402PaymentGuard(options))`. The payee is
 * checked before the payment is created; anything but a verified allow aborts it.
 */
export function x402PaymentGuard(options: GuardOptions = {}): (context: PaymentCreationContextLike) => Promise<void | { abort: true; reason: string }> {
  const guard = createGuard(options);
  return async (context) => {
    const r = context.selectedRequirements;
    try {
      await guard.enforce({ kind: "x402_payment", payTo: r.payTo, network: r.network, amount: r.amount, asset: r.asset, resource: context.paymentRequired?.resource?.url });
      return undefined;
    } catch (err) {
      const reason = err instanceof X402CheckBlockedError ? err.message : `x402check guard failed: ${String(err)}`;
      return { abort: true, reason };
    }
  };
}
