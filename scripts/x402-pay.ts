import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { ExactSvmScheme } from "@x402/svm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import { createKeyPairSignerFromBytes } from "@solana/kit";
import { base58 } from "@scure/base";

const ENDPOINT = process.env.X402CHECK_URL ?? "https://x402check.xyz/v1/risk-check";
const NETWORK = process.env.PAY_NETWORK ?? "eip155:8453";

async function main() {
  const client = new x402Client();
  client.setSpendControls({ maxAmountPerPayment: "$1" });
  if (NETWORK.startsWith("eip155")) {
    const key = readFileSync(`${homedir()}/.config/paysol/payer-evm.key`, "utf8").trim();
    client.register("eip155:*", new ExactEvmScheme(privateKeyToAccount(key as `0x${string}`)));
    console.log("payer: EVM", privateKeyToAccount(key as `0x${string}`).address);
  } else {
    const secret = readFileSync(`${homedir()}/.config/paysol/payer-sol.b58`, "utf8").trim();
    const signer = await createKeyPairSignerFromBytes(base58.decode(secret));
    client.register("solana:*", new ExactSvmScheme(signer));
    console.log("payer: SOL", signer.address);
  }
  const fetchWithPay = wrapFetchWithPayment(fetch, client);

  const body = {
    wallet: "7Xf2KrLzVqRT7pWruvFh4m6cBYuYEuNoXcRMKnvsLmBh",
    chain: "solana",
    domain: "api.merchant-labs.com",
    context: "agent pays $0.05 voucher for a pricing API call",
    screening: { sanctions: "clean" },
  };
  console.log("POST", ENDPOINT, "| network:", NETWORK);
  const res = await fetchWithPay(ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const settle = res.headers.get("PAYMENT-RESPONSE") ?? res.headers.get("X-PAYMENT-RESPONSE");
  if (settle) {
    const s = JSON.parse(Buffer.from(settle, "base64").toString("utf8"));
    console.log("SETTLED:", JSON.stringify({ success: s.success, transaction: s.transaction, network: s.network, payer: s.payer }));
  }
  console.log("STATUS:", res.status);
  const pr = res.headers.get("payment-required");
  if (pr) {
    const decoded = JSON.parse(Buffer.from(pr, "base64").toString("utf8"));
    console.log("PAYMENT-REQUIRED error:", decoded.error ?? "(none)");
    console.log("PAYMENT-REQUIRED full:", JSON.stringify(decoded).slice(0, 600));
  }
  const data = await res.json();
  console.log(JSON.stringify(data).slice(0, 400));
}

main();
