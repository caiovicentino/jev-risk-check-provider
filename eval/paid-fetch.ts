import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { ExactSvmScheme } from "@x402/svm/exact/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import { createKeyPairSignerFromBytes } from "@solana/kit";
import { base58 } from "@scure/base";

export type PayFetch = (input: string, init?: RequestInit) => Promise<Response>;

let cached: PayFetch | null = null;

/** An x402-paying fetch for the eval payer. `baseFetch` lets a probe observe what is sent (not cached). */
export async function buildPayFetch(baseFetch?: typeof fetch): Promise<PayFetch> {
  if (cached && !baseFetch) return cached;
  const client = new x402Client();
  client.setSpendControls({ maxAmountPerPayment: "$1" });
  const scheme = (process.env.PAY_NETWORK ?? "solana:*").split(":")[0];
  if (scheme === "eip155") {
    const key = readFileSync(`${homedir()}/.config/paysol/payer-evm.key`, "utf8").trim();
    client.register("eip155:*", new ExactEvmScheme(privateKeyToAccount(key as `0x${string}`)));
  } else {
    const secret = readFileSync(`${homedir()}/.config/paysol/payer-sol.b58`, "utf8").trim();
    const signer = await createKeyPairSignerFromBytes(base58.decode(secret));
    client.register("solana:*", new ExactSvmScheme(signer));
  }
  const paying = wrapFetchWithPayment(baseFetch ?? fetch.bind(globalThis), client) as PayFetch;
  if (!baseFetch) cached = paying;
  return paying;
}

export type SettlementReceipt = { success?: boolean | undefined; transaction?: string | undefined; network?: string | undefined; payer?: string | undefined };

/** The x402 settlement receipt of a paid response (PAYMENT-RESPONSE, base64 JSON), if any. */
export function settlementReceipt(headers: Headers): SettlementReceipt | null {
  const raw = headers.get("payment-response") ?? headers.get("x-payment-response");
  if (!raw) return null;
  try {
    const r = JSON.parse(Buffer.from(raw, "base64").toString("utf8")) as SettlementReceipt;
    return { success: r.success, transaction: r.transaction, network: r.network, payer: r.payer };
  } catch {
    return null;
  }
}
