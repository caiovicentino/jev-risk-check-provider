import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { Connection, Keypair, PublicKey, Transaction, sendAndConfirmTransaction } from "@solana/web3.js";
import { createAssociatedTokenAccountInstruction, getAssociatedTokenAddress, createTransferCheckedInstruction, getMint, getAccount } from "@solana/spl-token";

const RPC = process.env.SOL_RPC ?? "https://api.mainnet-beta.solana.com";

async function main() {
  const b58 = (await import("@scure/base")).base58;
  const secret = b58.decode(readFileSync(`${homedir()}/.config/paysol/payer-sol.b58`, "utf8").trim());
  const payer = Keypair.fromSecretKey(secret);
  const MINT = new PublicKey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
  const DEST_OWNER = new PublicKey(process.env.DEST ?? "Bofhoe2ye2adNQwZJtLepeKrBZq8CtHzRwPJXgWDH69X");
  const AMOUNT = Number(process.env.AMOUNT ?? 0.10);
  const conn = new Connection(RPC, "confirmed");

  const sourceAta = await getAssociatedTokenAddress(MINT, payer.publicKey);
  const destAta = await getAssociatedTokenAddress(MINT, DEST_OWNER);
  let needAta = true;
  try { await getAccount(conn, destAta); needAta = false; console.log("dest ATA exists"); }
  catch { console.log("dest ATA missing — will create"); }
  const mint = await getMint(conn, MINT);

  const tx = new Transaction();
  if (needAta) {
    tx.add(createAssociatedTokenAccountInstruction(payer.publicKey, destAta, DEST_OWNER, MINT));
    console.log("+ create ATA", destAta.toBase58());
  }
  tx.add(createTransferCheckedInstruction(
    sourceAta, MINT, destAta, payer.publicKey,
    Math.round(AMOUNT * 10 ** mint.decimals), mint.decimals,
  ));
  const sig = await sendAndConfirmTransaction(conn, tx, [payer]);
  console.log("TX:", sig);
  console.log(`https://solscan.io/tx/${sig}`);
  const bal = await getAccount(conn, sourceAta);
  console.log(`payer balance now: ${Number(bal.amount) / 10 ** mint.decimals} USDC`);
}
main();
