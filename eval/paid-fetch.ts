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

export async function buildPayFetch(): Promise<PayFetch> {
  if (cached) return cached;
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
  cached = wrapFetchWithPayment(fetch.bind(globalThis), client) as PayFetch;
  return cached;
}
