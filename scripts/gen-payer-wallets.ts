import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import nacl from "tweetnacl";
import { base58 } from "@scure/base";
import { writeFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";

async function main() {
  mkdirSync(`${homedir()}/.config/paysol`, { recursive: true });
  const evmKey = generatePrivateKey();
  const evmAcct = privateKeyToAccount(evmKey);
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const naclPair = nacl.sign.keyPair.fromSeed(seed);
  const solBytes = new Uint8Array(naclPair.secretKey);
  const solKeypair = { address: base58.encode(new Uint8Array(naclPair.publicKey)) };
  writeFileSync(`${homedir()}/.config/paysol/payer-evm.key`, evmKey + "\n", { mode: 0o600 });
  writeFileSync(`${homedir()}/.config/paysol/payer-sol.b58`, base58.encode(solBytes) + "\n", { mode: 0o600 });
  console.log("EVM payer (Base mainnet):", evmAcct.address);
  console.log("SOL payer (Solana mainnet):", solKeypair.address);
}

main();
