/**
 * Creates NEW probe-payer keys (EVM for Base, Solana) in ~/.config/paysol/:
 * payer-evm.key and payer-sol.b58 (mode 600). Prints only the public addresses.
 *
 * Those files hold the FUNDED probe payer that eval/paid-fetch.ts and the money scripts
 * spend from (AGENTS.md §2.4). Replacing them strands whatever the old payer holds, so:
 *   - if either file exists, the script writes nothing and exits 1;
 *   - replacing them takes BOTH the `--force` flag and, in the environment,
 *     PAYSOL_REPLACE_FUNDED_KEYS=owner-approved, and only with the owner's explicit OK
 *     (AGENTS.md §4). The old files are then renamed to <name>.replaced-<timestamp> in the
 *     same directory (same mode), never deleted.
 *
 * Usage: npx tsx scripts/gen-payer-wallets.ts [--force]
 */
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import nacl from "tweetnacl";
import { base58 } from "@scure/base";
import { lstatSync, mkdirSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const DIR = join(homedir(), ".config", "paysol");
const EVM_KEY_FILE = join(DIR, "payer-evm.key");
const SOL_KEY_FILE = join(DIR, "payer-sol.b58");
const CONFIRM_VAR = "PAYSOL_REPLACE_FUNDED_KEYS";
const CONFIRM_VALUE = "owner-approved";

function fail(message: string): never {
  console.error(`gen-payer-wallets: ${message}`);
  process.exit(1);
}

/** True when anything (a file, a directory, even a dangling symlink) is at `path`. */
function occupied(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}

function main(): void {
  const args = process.argv.slice(2);
  const unknown = args.filter((a) => a !== "--force");
  if (unknown.length > 0) fail(`unknown argument(s): ${unknown.join(" ")}. Usage: npx tsx scripts/gen-payer-wallets.ts [--force]`);
  const force = args.includes("--force");

  const existing = [EVM_KEY_FILE, SOL_KEY_FILE].filter(occupied);
  if (existing.length > 0) {
    if (!force) {
      fail(
        [
          "refusing to overwrite existing payer key files; nothing was written.",
          ...existing.map((p) => `  ${p}`),
          "They hold the funded probe payer (AGENTS.md §2.4): replacing them strands its funds.",
          "Replacing them needs the owner's explicit OK (AGENTS.md §4); see this script's header.",
        ].join("\n"),
      );
    }
    if (process.env[CONFIRM_VAR] !== CONFIRM_VALUE) {
      fail(`--force also needs ${CONFIRM_VAR}=${CONFIRM_VALUE} in the environment, given only with the owner's explicit OK (AGENTS.md §4). Nothing was written.`);
    }
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    for (const path of existing) {
      const kept = `${path}.replaced-${stamp}`;
      renameSync(path, kept);
      console.log(`Kept the old key file as ${kept}`);
    }
  }

  mkdirSync(DIR, { recursive: true, mode: 0o700 });
  const evmKey = generatePrivateKey();
  const evmAddress = privateKeyToAccount(evmKey).address;
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const solPair = nacl.sign.keyPair.fromSeed(seed);
  const solAddress = base58.encode(new Uint8Array(solPair.publicKey));
  // flag "wx": fail rather than overwrite if a file appeared since the check above.
  writeFileSync(EVM_KEY_FILE, evmKey + "\n", { mode: 0o600, flag: "wx" });
  writeFileSync(SOL_KEY_FILE, base58.encode(new Uint8Array(solPair.secretKey)) + "\n", { mode: 0o600, flag: "wx" });
  console.log("EVM payer (Base mainnet):", evmAddress);
  console.log("SOL payer (Solana mainnet):", solAddress);
}

main();
