// Signing guard: x402check between an agent and its keys.
//
// `guardAccount(account)` wraps a viem-style account. Every signature it would produce
// (a transaction, EIP-712 typed data including x402 EIP-3009 payments, permits and
// orders, a message, an EIP-7702 delegation) is decoded first: the real counterparty
// is found inside the calldata or the typed data, with the same decoders as the
// x402check MetaMask Snap. That counterparty is then checked, along with the
// transaction itself, which is simulated. The key signs only after a verified `allow`.
//
// - `block`, `not_verified` (any failure: network, payment, timeout, a bad or unbound
//   attestation), or locally proven danger → it throws `X402CheckBlockedError` and
//   nothing is signed.
// - `warn` → it signs only if `onWarn` approves. Without `onWarn`, it refuses.
// - Every attestation is verified against the pinned issuer and bound to the exact
//   request (`request_hash`), so an old or foreign `allow` cannot unlock this signature.
//
// `x402PaymentGuard()` is the same check as an x402 client hook (`onBeforePaymentCreation`):
// the payment is aborted before anything is signed.
//
// `guardSolanaSigner(signer)` does the same for a Solana signer (@solana/kit's
// `signTransactions` / `signMessages` and their modifying and sending variants): each
// transaction is decoded (lookup tables and token-account owners resolved over RPC), and its
// recipients, delegates and called programs are checked. A message that is itself a
// transaction, or an instruction that hands the account or its token accounts to someone
// else, is refused without a check.
//
// Pay for the checks with prepaid credits (`creditToken`): never with a per-call payer
// that uses the guarded account itself, or each check would need a guarded signature.
import { createClient, type X402CheckClient } from "./client.js";
import { interpret, type Action, type Interpretation } from "./interpret.js";
import { verifyAttestation } from "./verify.js";
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
  type SolanaAnalysis,
  type SolanaFinding,
  type SolanaMessage,
} from "./solana.js";

/** x402check's own `pay_to` addresses: paying for a check is never itself checked. */
export const X402CHECK_PAY_TO: readonly string[] = ["0xbF88b1F49B5e8Ec386289341c4a5ee00bB0E0178", "Bofhoe2ye2adNQwZJtLepeKrBZq8CtHzRwPJXgWDH69X"];

export type SigningKind = "transaction" | "typed_data" | "message" | "authorization" | "raw_hash" | "x402_payment" | "solana_transaction" | "solana_message";

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
  /** Why it was refused: "blocked", "not_verified", "warn_declined", "local_danger", "raw_hash_signing". */
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
  /** Fetch for the API and the issuer's DID document. Pass a stable reference (the DID cache is keyed by it). */
  fetch?: FetchLike | undefined;
  /** Per API call. Default 10000 ms: a slow check fails closed. */
  timeoutMs?: number | undefined;
  /** The attestation issuer trusted. Default "did:web:x402check.xyz". */
  issuer?: string | undefined;
  /** A `warn` verdict: return true to sign anyway (e.g. after asking a human). Default: refuse. */
  onWarn?: ((verdict: GuardVerdict) => boolean | Promise<boolean>) | undefined;
  /** Every verdict, signed or refused, for audit logs. */
  onVerdict?: ((verdict: GuardVerdict) => void | Promise<void>) | undefined;
  /** The content the agent acted on (a page, a message, a tool output), checked for injected instructions. */
  context?: string | (() => string | undefined) | undefined;
  /** The site or app the agent is dealing with (URL or host). */
  origin?: string | undefined;
  /** Payees whose x402 / EIP-3009 payments are not checked. Default: x402check's own `pay_to`. */
  trustedPayees?: readonly string[] | undefined;
  /** `sign({ hash })` signs anything, unreadable: refused unless true (some smart-account flows need it). */
  allowRawHashSigning?: boolean | undefined;
  /** Chain for a message signature (no chain of its own), as a number. */
  chainId?: number | undefined;
  /** Solana JSON-RPC, to resolve address lookup tables and token-account owners. Default: the public mainnet-beta endpoint. */
  solanaRpcUrl?: string | undefined;
  /** CAIP-2 cluster of the Solana transactions signed. Default: mainnet. */
  solanaNetwork?: string | undefined;
}

/** What a signature request is, before decoding. */
export type SigningRequest =
  | { kind: "transaction"; from: string; transaction: { to?: unknown; value?: unknown; data?: unknown; input?: unknown; chainId?: unknown } }
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

function sameAddress(a: string, b: string): boolean {
  return /^0x/i.test(a) && /^0x/i.test(b) ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function jsonSafe(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
}

function hexValue(value: unknown): unknown {
  return typeof value === "bigint" ? `0x${value.toString(16)}` : typeof value === "number" && Number.isSafeInteger(value) ? `0x${value.toString(16)}` : value;
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

/** x402's EVM payment signature (EIP-3009): the Snap decoder does not model it, so it is read here. */
function eip3009(td: Extract<SigningRequest, { kind: "typed_data" }>["typedData"]): { payTo: string; amount: string; asset?: string; chainId?: string } | null {
  if (td.primaryType !== "TransferWithAuthorization" && td.primaryType !== "ReceiveWithAuthorization") return null;
  const message = (td.message ?? {}) as Record<string, unknown>;
  const to = message["to"];
  const value = message["value"];
  if (typeof to !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(to)) return null;
  const amount = typeof value === "bigint" ? value.toString() : typeof value === "number" ? String(value) : typeof value === "string" && /^\d{1,78}$/.test(value) ? value : null;
  if (amount === null) return null;
  const domain = td.domain ?? {};
  const verifying = domain["verifyingContract"];
  const chainId = domain["chainId"];
  return {
    payTo: to,
    amount,
    ...(typeof verifying === "string" && /^0x[0-9a-fA-F]{40}$/.test(verifying) ? { asset: verifying } : {}),
    ...(chainId !== undefined ? { chainId: String(chainId) } : {}),
  };
}

function host(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    return new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`).hostname || undefined;
  } catch {
    return undefined;
  }
}

/** A guard with its own client: `check` decides, `enforce` throws when the key must not sign. */
export function createGuard(options: GuardOptions = {}) {
  const client = options.client ?? createClient({ baseUrl: options.baseUrl, fetch: options.fetch, timeoutMs: options.timeoutMs ?? 10_000, creditToken: options.creditToken });
  const trusted = options.trustedPayees ?? X402CHECK_PAY_TO;
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
        const verification = await verifyAttestation(result?.jws, { issuer: options.issuer, request, maxAgeSeconds: 300, fetch: options.fetch });
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
      const summary = `x402 payment of ${request.amount ?? "?"} (atomic units) of ${request.asset ?? "?"} on ${request.network} to ${request.payTo}${request.resource ? ` for ${request.resource}` : ""}`;
      if (isTrusted(request.payTo)) return verdictOf("x402_payment", summary, "allow", ["payment to x402check itself (trusted payee): not checked"], []);
      const payment: PaymentBinding = {
        network: request.network,
        pay_to: request.payTo,
        ...(request.amount && /^\d{1,78}$/.test(request.amount) ? { amount: request.amount } : {}),
        ...(request.asset ? { asset: request.asset } : {}),
        ...(request.resource && request.resource.length <= 512 && /^https?:\/\/\S+$/.test(request.resource) ? { resource: request.resource } : {}),
      };
      const domain = host(request.resource) ?? host(options.origin);
      const body: RiskCheckBody = { wallet: request.payTo, chain: request.network, ...(domain ? { domain } : {}), context: summary, payment, interaction: { type: "token_transfer" } };
      return evaluate("x402_payment", summary, [withAgentContext(body)]);
    }
    if (request.kind === "authorization") {
      const chain = request.chainId === undefined || request.chainId === null ? undefined : String(request.chainId);
      const everyChain = chain === "0";
      const summary = `EIP-7702 authorization: ${request.from} delegates its code to ${request.contractAddress}${everyChain ? " on EVERY chain (chainId 0)" : chain ? ` on eip155:${chain}` : ""}. The delegate gains full control of the account and its assets.`;
      const body: RiskCheckBody = { wallet: request.contractAddress, ...(chain && !everyChain ? { chain: `eip155:${chain}` } : {}), ...(host(options.origin) ? { domain: host(options.origin) } : {}), context: summary, interaction: { type: "contract_call" } };
      return evaluate("authorization", summary, [withAgentContext(body)]);
    }

    let decoded: Decoded;
    let kind: SigningKind;
    if (request.kind === "typed_data") {
      // An EIP-3009 authorization is a payment (x402 on EVM): checked exactly like one, bound to its payee and amount.
      const payment = eip3009(request.typedData);
      if (payment) {
        const network = payment.chainId && /^\d+$/.test(payment.chainId) ? `eip155:${payment.chainId}` : undefined;
        if (network) return check({ kind: "x402_payment", payTo: payment.payTo, network, amount: payment.amount, asset: payment.asset });
      }
    }
    if (request.kind === "transaction") {
      kind = "transaction";
      const tx = request.transaction;
      decoded = decodeTransaction({ from: request.from, to: tx.to, value: hexValue(tx.value), data: tx.data ?? tx.input }, tx.chainId ?? options.chainId);
    } else if (request.kind === "typed_data") {
      kind = "typed_data";
      decoded = decodeTypedData(withDomainType(request.typedData), request.from, "eth_signTypedData_v4");
    } else {
      kind = "message";
      const m = request.message as unknown;
      const raw = typeof m === "object" && m !== null && "raw" in m ? (m as { raw: unknown }).raw : m;
      const data = raw instanceof Uint8Array ? `0x${[...raw].map((b) => b.toString(16).padStart(2, "0")).join("")}` : raw;
      decoded = decodePersonalSign(data, request.from, host(options.origin));
      if (!decoded.chain && options.chainId !== undefined) decoded = { ...decoded, chain: `eip155:${options.chainId}` };
    }

    if (decoded.danger.length > 0) return verdictOf(kind, decoded.summary, "block", decoded.danger, [], "local_danger");
    const bodies = buildRiskCheckBodies(decoded, options.origin);
    if (bodies.length === 0) return verdictOf(kind, decoded.summary, "allow", [decoded.localNote ?? "nothing to check: no counterparty"], []);
    return evaluate(kind, decoded.summary, bodies.map(withAgentContext));
  }

  const solanaNetwork = options.solanaNetwork ?? SOLANA_MAINNET;
  const rpcFetch: FetchLike = options.fetch ?? ((url, init) => globalThis.fetch(url, init));
  const rpcTimeout = options.timeoutMs ?? 10_000;

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
      const accounts = await getSolanaAccounts(options.solanaRpcUrl ?? DEFAULT_SOLANA_RPC, message.lookups.map((l) => l.table), rpcFetch, rpcTimeout);
      message.lookups.forEach((l, i) => {
        const table = accounts[i];
        if (!table || table.owner !== ADDRESS_LOOKUP_TABLE_PROGRAM) throw new Error(`${l.table} is not an address lookup table`);
        tables.set(l.table, lookupTableAddresses(table.data));
      });
      keys = accountKeys(message, tables);
    } catch (err) {
      return verdictOf(kind, "a Solana v0 transaction with address lookup tables", "not_verified", [`its address lookup tables could not be resolved (${String((err as Error).message).slice(0, 160)}), so its accounts are unknown`], [], "not_verified");
    }
    const analysis = analyzeSolanaMessage(message, keys, from);
    const draft = solanaSummary(message, analysis, analysis.findings);
    if (!analysis.required) return verdictOf(kind, draft, "allow", ["the signer is not a required signer of this transaction: its signature authorizes nothing"], []);
    if (analysis.danger.length > 0) return verdictOf(kind, draft, "block", analysis.danger, [], "local_danger");
    if (analysis.unreadable.length > 0) {
      return verdictOf(kind, draft, "not_verified", [`the signer authorizes instructions this guard cannot read: ${analysis.unreadable.join(", ")}. Nothing unreadable is signed`], [], "unreadable_instruction");
    }

    // The owner of each receiving token account: the ATA program's create instruction names it; otherwise the chain does.
    const pending = [...new Set(analysis.findings.flatMap((f) => (f.kind === "token_transfer" && !analysis.created.has(f.account) ? [f.account] : [])))];
    const owners = new Map<string, { owner: string; mint: string }>(analysis.created);
    try {
      const accounts = await getSolanaAccounts(options.solanaRpcUrl ?? DEFAULT_SOLANA_RPC, pending, rpcFetch, rpcTimeout);
      pending.forEach((address, i) => {
        const account = accounts[i];
        const info = account ? tokenAccountInfo(account) : null;
        if (!info) throw new Error(`${address} ${account ? "is not a token account" : "does not exist, and the transaction does not create it"}`);
        owners.set(address, info);
      });
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
    return evaluate(kind, summary, bodies.map(withAgentContext));
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
    // Sign-In With Solana names the site asking: that domain is checked.
    const siws = text ? /^([A-Za-z0-9.-]{1,253}(?::\d{1,5})?) wants you to sign in with your Solana account:/.exec(text) : null;
    const summary = text ? `Solana message signature (${message.length} bytes): ${text.slice(0, 300)}` : `Solana message signature of ${message.length} bytes of binary data`;
    const domain = siws?.[1] ? host(siws[1]) : host(options.origin);
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

/**
 * The same account, with x402check between it and every signature: decode, check, verify, then
 * sign or throw `X402CheckBlockedError`. Pass it wherever the agent signs: a viem wallet client,
 * an x402 client (`new ExactEvmScheme(guarded)`), an agent framework.
 */
export function guardAccount<A extends GuardableAccount>(account: A, options: GuardOptions = {}): A {
  const guard = createGuard(options);
  const from = account.address;
  const wrapped: A = { ...account };
  if (account.signTransaction) {
    const sign = account.signTransaction.bind(account);
    wrapped.signTransaction = async (transaction: any, opts?: any) => {
      await guard.enforce({ kind: "transaction", from, transaction: transaction ?? {} });
      return sign(transaction, opts);
    };
  }
  if (account.signTypedData) {
    const sign = account.signTypedData.bind(account);
    wrapped.signTypedData = async (parameters: any) => {
      await guard.enforce({ kind: "typed_data", from, typedData: parameters ?? {} });
      return sign(parameters);
    };
  }
  if (account.signMessage) {
    const sign = account.signMessage.bind(account);
    wrapped.signMessage = async (parameters: any) => {
      await guard.enforce({ kind: "message", from, message: parameters?.message });
      return sign(parameters);
    };
  }
  if (account.signAuthorization) {
    const sign = account.signAuthorization.bind(account);
    wrapped.signAuthorization = async (parameters: any) => {
      const contractAddress = String(parameters?.contractAddress ?? parameters?.address ?? "");
      await guard.enforce({ kind: "authorization", from, contractAddress, chainId: parameters?.chainId });
      return sign(parameters);
    };
  }
  if (account.sign && !options.allowRawHashSigning) {
    wrapped.sign = async () => {
      const verdict: GuardVerdict = {
        action: "block",
        signed: false,
        kind: "raw_hash",
        summary: "sign({ hash }) signs an opaque 32-byte value that could authorize anything.",
        reasons: ["raw hash signing is disabled by the x402check guard (allowRawHashSigning: true enables it, unchecked)"],
        code: "raw_hash_signing",
        checks: [],
      };
      await Promise.resolve(options.onVerdict?.(verdict)).catch(() => undefined);
      throw new X402CheckBlockedError(verdict);
    };
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

/**
 * The same Solana signer, with x402check between it and every signature. Every transaction of a
 * batch is decoded and checked first; one refusal refuses the batch, and nothing is signed.
 * Pass it wherever the agent signs: `signTransactionMessageWithSigners`, an x402 client
 * (`new ExactSvmScheme(guarded)`), an agent framework.
 */
export function guardSolanaSigner<S extends GuardableSolanaSigner>(signer: S, options: GuardOptions = {}): S {
  const guard = createGuard(options);
  const from = String(signer.address);
  const wrapped: S = { ...signer };
  const transactions = (method: "signTransactions" | "modifyAndSignTransactions" | "signAndSendTransactions") => {
    const sign = signer[method]?.bind(signer);
    if (!sign) return;
    wrapped[method] = async (txs: readonly any[], config?: any) => {
      for (const tx of txs ?? []) {
        const bytes = tx?.messageBytes;
        if (!(bytes instanceof Uint8Array)) {
          throw new X402CheckBlockedError({ action: "not_verified", signed: false, kind: "solana_transaction", summary: "a Solana transaction without its compiled message", reasons: ["only compiled transactions (messageBytes) can be checked"], code: "undecodable", checks: [] });
        }
        await guard.enforce({ kind: "solana_transaction", from, messageBytes: bytes });
      }
      return sign(txs, config);
    };
  };
  const messages = (method: "signMessages" | "modifyAndSignMessages") => {
    const sign = signer[method]?.bind(signer);
    if (!sign) return;
    wrapped[method] = async (msgs: readonly any[], config?: any) => {
      for (const m of msgs ?? []) {
        const content = m?.content;
        if (!(content instanceof Uint8Array)) {
          throw new X402CheckBlockedError({ action: "not_verified", signed: false, kind: "solana_message", summary: "a Solana message without its content", reasons: ["only messages with byte content can be checked"], code: "undecodable", checks: [] });
        }
        await guard.enforce({ kind: "solana_message", from, message: content });
      }
      return sign(msgs, config);
    };
  };
  transactions("signTransactions");
  transactions("modifyAndSignTransactions");
  transactions("signAndSendTransactions");
  messages("signMessages");
  messages("modifyAndSignMessages");
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
