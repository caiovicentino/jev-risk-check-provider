// The account an x402 Solana payment is paid from. The x402 SVM client pays from the payer's own
// associated token account (ATA): a program-derived address of (owner, token program, mint). A
// transfer whose authority is a delegate of someone else's account would screen the delegate, not
// the owner of the funds, so the paid flow accepts only a source that is the authority's own ATA.
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2.js";
import { base58Decode } from "../src/address-codec.js";

const ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const PDA_MARKER = new TextEncoder().encode("ProgramDerivedAddress");

function onCurve(bytes: Uint8Array): boolean {
  try {
    ed25519.ExtendedPoint.fromHex(bytes);
    return true;
  } catch {
    return false;
  }
}

function key(address: string): Uint8Array | null {
  const bytes = base58Decode(address);
  return bytes && bytes.length === 32 ? bytes : null;
}

/** The associated token account of `owner` for `mint` under `tokenProgram` (32 bytes), or null on bad input. */
export function associatedTokenAccount(owner: string, mint: string, tokenProgram: string): Uint8Array | null {
  const o = key(owner);
  const m = key(mint);
  const t = key(tokenProgram);
  const p = key(ATA_PROGRAM);
  if (!o || !m || !t || !p) return null;
  const head = new Uint8Array([...o, ...t, ...m]);
  for (let bump = 255; bump >= 0; bump--) {
    const h = sha256(new Uint8Array([...head, bump, ...p, ...PDA_MARKER]));
    if (!onCurve(h)) return h;
  }
  return null;
}

/** Whether `account` is `owner`'s associated token account for `mint`. */
export function isAssociatedTokenAccount(account: string, owner: string, mint: string, tokenProgram: string): boolean {
  const ata = associatedTokenAccount(owner, mint, tokenProgram);
  const acc = key(account);
  return !!ata && !!acc && ata.every((b, i) => b === acc[i]);
}
