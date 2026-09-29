import "./shims";
import { onTransaction, onSignature, onInstall } from "../index";

async function run() {
  const installed = await onInstall();
  console.log("onInstall ok");
  const t = await onTransaction({
    transaction: {
      from: "0xB48057E647B2572f5eAe241b515fBc58B7cE249E",
      to: "0xbF88b1F49B5e8Ec386289341c4a5ee00bB0E0178",
      nonce: "0x0",
      value: "10000000000000000",
      data: "0x",
      gas: "21000",
      maxFeePerGas: "1000000000",
      maxPriorityFeePerGas: "100000000",
    },
    chainId: "eip155:8453",
    transactionOrigin: "https://example-dapp.xyz",
  });
  console.log("onTransaction ->", JSON.stringify(t, null, 2).slice(0, 700));
  const s = await onSignature({
    signature: {
      from: "0xB48057E647B2572f5eAe241b515fBc58B7cE249E",
      data: "0x4578616d706c65206d6573736167652066726f6d2068747470733a2f2f6a7570317465722d61756469742e636c69636b",
    },
    signatureOrigin: "https://untrusted-airdrop.example",
  });
  console.log("onSignature ->", JSON.stringify(s, null, 2).slice(0, 700));
}

run().catch((e) => {
  console.error("FAIL", e);
  process.exit(1);
});
