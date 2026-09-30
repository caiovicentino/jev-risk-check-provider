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

export type PaymentRefusalKind = "budget_exhausted" | "over_max_payment" | "no_payable_option" | "payment_error";

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
  /** An x402-paying fetch for `createClient`. Payment failures reject with `PaymentRefused`. */
  readonly fetch: FetchLike;
  /** Removes the private key from text (defense in depth for every output). */
  redact(text: string): string;
}

const PRIVATE_KEY = /^0x[0-9a-fA-F]{64}$/;
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

  const client = new x402Client((_version, requirements) => {
    const evm = requirements.filter((r) => r.network.startsWith("eip155:"));
    return (requirements.find((r) => r.network === PREFERRED_NETWORK) ?? evm[0] ?? requirements[0]) as (typeof requirements)[number];
  })
    .register("eip155:*", new ExactEvmScheme(account))
    .setSpendControls({ maxAmountPerPayment: `$${maxPaymentUsd.toFixed(6)}` })
    .onBeforePaymentCreation(async ({ selectedRequirements: r }) => {
      const asset = findDefaultAsset(r.asset, r.network);
      if (!asset || !/^\d{1,78}$/.test(r.amount)) return { abort: true, reason: ASSET_ABORT };
      const cost = toMicroUsd(r.amount, asset.decimals);
      if (spentMicro + cost > budgetMicro) return { abort: true, reason: BUDGET_ABORT };
      // Committed before signing: a signed authorization can be settled even if the response is lost.
      spentMicro += cost;
      reserved.set(r, cost);
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
  const paying = wrapFetchWithPayment(inner, client);

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
    redact: (text) => (text.toLowerCase().includes(secret) ? text.replace(new RegExp(`(0x)?${secret}`, "gi"), "[redacted]") : text),
  };
}
