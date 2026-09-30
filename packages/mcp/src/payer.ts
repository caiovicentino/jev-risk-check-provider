// Built-in x402 payer: every x402check evaluation is paid (USDC, x402 "exact" scheme, which is
// gasless for the payer). The private key lives only inside the viem signer; it is never logged,
// echoed or put in an error message, and every tool output is additionally scrubbed of it.
import { findDefaultAsset } from "@x402/evm";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { wrapFetchWithPayment, x402Client } from "@x402/fetch";
import type { FetchLike } from "@x402check/client";
import { privateKeyToAccount } from "viem/accounts";

export const DEFAULT_MAX_PAYMENT_USD = 0.05;
export const DEFAULT_BUDGET_USD = 1;
/** The cheapest per-call evaluation ($0.001 on Avalanche and Monad; $0.0035 on Base). Below it the budget cannot buy a check. */
export const MIN_CHECK_USD = 0.001;
/** Preferred first when the 402 offers it: Base. */
export const PREFERRED_NETWORK = "eip155:8453";

export type PaymentRefusalKind = "budget_exhausted" | "over_max_payment" | "no_payable_option" | "payment_error" | "not_authorized";

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
  /** Underlying fetch (standard signature). Default `globalThis.fetch`. */
  fetch?: typeof globalThis.fetch | undefined;
}

export interface Payer {
  /** The payer's public address (safe to show). */
  readonly address: `0x${string}`;
  readonly maxPaymentUsd: number;
  readonly budgetUsd: number;
  /** USD committed so far: every signed payment authorization counts, settled or not. */
  spentUsd(): number;
  /** Whether the remaining budget still covers the cheapest check. */
  canAfford(): boolean;
  /** An x402-paying fetch for `createClient` (pays x402check's own checks). Payment failures reject with `PaymentRefused`. */
  readonly fetch: FetchLike;
  /**
   * Fetches a third-party x402 resource. When it asks for payment, `authorize` decides right
   * before the payment is signed, on exactly what would be signed: nothing is signed unless it
   * returns undefined. At most one payment per call, within the cap and the budget.
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
  /** The resource's own description, from its 402 (untrusted text). */
  description?: string | undefined;
}

/** Called once, right before signing: undefined → sign; a string → refuse, nothing signed. */
export type PaymentAuthorizer = (payment: ResourcePayment) => Promise<string | undefined>;

export interface ResourcePaymentOptions {
  authorize: PaymentAuthorizer;
  /** Runs once the authorization is signed: it is then sent with the request, and may be settled whatever follows. */
  onSigned?: (() => void) | undefined;
  /** Per HTTP request to the resource, until its headers arrive (the check and the user's decision do not count). */
  timeoutMs?: number | undefined;
}

const PRIVATE_KEY = /^0x[0-9a-fA-F]{64}$/;
const AUTHORIZE_ABORT = "x402check-mcp payment not authorized";
const MICRO = 1_000_000n; // budget accounting in integer micro-USD (USDC has 6 decimals)
const BUDGET_ABORT = "x402check-mcp budget exhausted";
const ASSET_ABORT = "x402check-mcp unrecognized payment asset";

function usd(name: string, value: number | undefined, fallback: number): number {
  const v = value ?? fallback;
  if (!Number.isFinite(v) || v < 0.000001 || v > 1_000_000) throw new TypeError(`${name} must be a USD amount between 0.000001 and 1000000`);
  return v;
}

/** Atomic token amount → micro-USD, rounded up (budgeting errs on the safe side). */
function toMicroUsd(amount: string, decimals: number): bigint {
  const scale = 10n ** BigInt(decimals);
  return (BigInt(amount) * MICRO + scale - 1n) / scale;
}

function classify(err: unknown): unknown {
  const message = err instanceof Error ? err.message : "";
  if (message.includes(AUTHORIZE_ABORT)) return new PaymentRefused("not_authorized", "the payment was not authorized, so nothing was signed");
  if (message.includes(BUDGET_ABORT)) return new PaymentRefused("budget_exhausted", "the payment budget of this server is exhausted");
  if (message.includes("spendControls.maxAmountPerPayment")) return new PaymentRefused("over_max_payment", "the price exceeds the per-payment cap (X402CHECK_MAX_PAYMENT_USD)");
  if (/^Failed to (create payment payload|parse payment requirements)|^Payment already attempted/.test(message)) {
    const unpayable = message.includes(ASSET_ABORT) || /No network\/scheme registered|rejected by spendControls|filtered out by policies|No client registered|recognized paymentFlow/.test(message);
    return unpayable
      ? new PaymentRefused("no_payable_option", "none of the offered payment options can be paid by this server (EVM USDC via x402 exact)")
      : new PaymentRefused("payment_error", "the x402 payment could not be created");
  }
  return err; // not a payment problem (e.g. a network error): the client reports it as such
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
  const maxPaymentUsd = usd("X402CHECK_MAX_PAYMENT_USD", options.maxPaymentUsd, DEFAULT_MAX_PAYMENT_USD);
  const budgetUsd = usd("X402CHECK_BUDGET_USD", options.budgetUsd, DEFAULT_BUDGET_USD);
  const budgetMicro = BigInt(Math.round(budgetUsd * 1e6));
  let spentMicro = 0n;
  const reserved = new WeakMap<object, bigint>();
  const secret = key.slice(2).toLowerCase();

  // One x402 client for x402check's own checks, and one per resource payment (with its gate),
  // sharing the budget.
  const makeClient = (gate?: PaymentAuthorizer, onSigned?: () => void) =>
    new x402Client((_version, requirements) => {
      const evm = requirements.filter((r) => r.network.startsWith("eip155:"));
      return (requirements.find((r) => r.network === PREFERRED_NETWORK) ?? evm[0] ?? requirements[0]) as (typeof requirements)[number];
    })
      .register("eip155:*", new ExactEvmScheme(account))
      .setSpendControls({ maxAmountPerPayment: `$${maxPaymentUsd.toFixed(6)}` })
      .onBeforePaymentCreation(async ({ selectedRequirements: r, paymentRequired }) => {
        const asset = findDefaultAsset(r.asset, r.network);
        if (!asset || !/^\d{1,78}$/.test(r.amount)) return { abort: true, reason: ASSET_ABORT };
        const cost = toMicroUsd(r.amount, asset.decimals);
        if (spentMicro + cost > budgetMicro) return { abort: true, reason: BUDGET_ABORT };
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
            ...(typeof description === "string" && description.trim() ? { description: description.trim().slice(0, 600) } : {}),
          };
          const refusal = await gate(payment).catch(() => "the authorization failed");
          if (refusal !== undefined) return { abort: true, reason: AUTHORIZE_ABORT };
          // A paid check inside the authorization may itself have spent from the budget.
          if (spentMicro + cost > budgetMicro) return { abort: true, reason: BUDGET_ABORT };
        }
        // Committed before signing: a signed authorization can be settled even if the response is lost.
        spentMicro += cost;
        reserved.set(r, cost);
      })
      .onAfterPaymentCreation(async () => {
        onSigned?.();
      })
      .onPaymentCreationFailure(async ({ selectedRequirements: r }) => {
        // Nothing was signed: give the reservation back.
        const cost = reserved.get(r);
        if (cost !== undefined) {
          spentMicro -= cost;
          reserved.delete(r);
        }
      });

  const inner: typeof globalThis.fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const paying = wrapFetchWithPayment(inner, makeClient());

  return {
    address: account.address,
    maxPaymentUsd,
    budgetUsd,
    spentUsd: () => Number(spentMicro) / 1e6,
    canAfford: () => budgetMicro - spentMicro >= BigInt(Math.round(MIN_CHECK_USD * 1e6)),
    fetch: async (url, init) => {
      try {
        return await paying(url, init as RequestInit);
      } catch (err) {
        throw classify(err);
      }
    },
    payResource: async (url, init, { authorize, onSigned, timeoutMs }) => {
      // One signature per call: the x402 wrapper signs a second payment when a response hook
      // reports a "recoverable" failure, and a server could then settle both.
      let asked = false;
      const gate: PaymentAuthorizer = async (payment) => {
        if (asked) return "only one payment per call";
        asked = true;
        return authorize(payment);
      };
      const fetchResource: typeof globalThis.fetch =
        timeoutMs === undefined
          ? inner
          : async (input, requestInit) => {
              const controller = new AbortController();
              const timer = setTimeout(() => controller.abort(new Error(`the resource did not answer within ${timeoutMs} ms`)), timeoutMs);
              try {
                return await inner(new Request(new Request(input, requestInit), { signal: controller.signal }));
              } finally {
                clearTimeout(timer);
              }
            };
      try {
        return await wrapFetchWithPayment(fetchResource, makeClient(gate, onSigned))(url, init);
      } catch (err) {
        throw classify(err);
      }
    },
    redact: (text) => (text.toLowerCase().includes(secret) ? text.replace(new RegExp(`(0x)?${secret}`, "gi"), "[redacted]") : text),
  };
}
