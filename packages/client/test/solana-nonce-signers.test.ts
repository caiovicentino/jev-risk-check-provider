// Review 2026-10-17 (Solana, client 0.5.0). The System program checks a nonce account's authority
// against every signer of the instruction (the native processor's get_signers), not one position:
// the victim's signature anywhere among WithdrawNonceAccount's or AuthorizeNonceAccount's accounts
// authorizes it. The guard is expected to refuse both drains below.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AccountRole,
  address,
  appendTransactionMessageInstructions,
  blockhash,
  createTransactionMessage,
  generateKeyPairSigner,
  getAddressEncoder,
  pipe,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  type Address,
  type KeyPairSigner,
} from "@solana/kit";
import { guardSolanaSigner, X402CheckBlockedError, type GuardVerdict } from "../src/guard.js";
import { STAKE_PROGRAM } from "../src/solana.js";
import { boundProvider } from "./helpers.js";

const enc = getAddressEncoder();
const le32 = (n: number) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
const le64 = (n: bigint) => Uint8Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));
const cat = (...parts: ArrayLike<number>[]) => Uint8Array.from(parts.flatMap((p) => Array.from(p)));
const CLOCK = address("SysvarC1ock11111111111111111111111111111111");
const HISTORY = address("SysvarStakeHistory1111111111111111111111111");
const SOL_100 = 100_000_000_000n;
type Acc = { address: Address; role: AccountRole; signer?: KeyPairSigner };
type Ix = { programAddress: Address; accounts: Acc[]; data: Uint8Array };

/** Same harness as packages/client/test/solana-stake-v5.test.ts: the attacker is a known scam (critical). */
async function run(build: (signer: KeyPairSigner, stake: KeyPairSigner, attacker: KeyPairSigner) => Ix[]) {
  const attacker = await generateKeyPairSigner();
  const api = boundProvider((r) => (r.wallet === attacker.address ? { tier: "critical", score: 2, categories: ["known_scam_address"] } : { tier: "low", score: 90, categories: [] }));
  const base = await generateKeyPairSigner();
  let signed = 0;
  const spy = { ...base, signTransactions: async (txs: Parameters<KeyPairSigner["signTransactions"]>[0]) => (signed++, base.signTransactions(txs)) } as KeyPairSigner;
  const guarded = guardSolanaSigner(spy, { pinnedKeys: false, fetch: api.fetch, solanaRpcUrl: "https://rpc.invalid/" });
  const stake = await generateKeyPairSigner();
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayerSigner(guarded, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash({ blockhash: blockhash(stake.address), lastValidBlockHeight: 1000n }, m),
    (m) => appendTransactionMessageInstructions(build(guarded, stake, attacker) as Parameters<typeof appendTransactionMessageInstructions>[0], m),
  );
  let verdict: GuardVerdict | undefined;
  try {
    await signTransactionMessageWithSigners(message);
  } catch (err) {
    assert.ok(err instanceof X402CheckBlockedError, String(err));
    verdict = err.verdict;
  }
  return { api, signed, verdict, attacker: attacker.address };
}

const W = AccountRole.WRITABLE;
const RO = AccountRole.READONLY;
const ROS = AccountRole.READONLY_SIGNER;
const SYSTEM = address("11111111111111111111111111111111");
const RECENT = address("SysvarRecentB1ockHashes11111111111111111111");
const RENT = address("SysvarRent111111111111111111111111111111111");

// Out of the diff (System program, unchanged): the native processor passes every signer of the
// instruction (get_signers) to withdraw_nonce_account / authorize_nonce_account.
test("System WithdrawNonceAccount: the attacker in the authority slot, the victim as an extra signer", async () => {
  const r = await run((signer, nonce, attacker) => [
    {
      programAddress: SYSTEM,
      accounts: [
        { address: nonce.address, role: W }, // the victim's nonce account (authority = victim)
        { address: attacker.address, role: W }, // recipient
        { address: RECENT, role: RO },
        { address: RENT, role: RO },
        { address: attacker.address, role: ROS, signer: attacker }, // "authority" slot
        { address: signer.address, role: ROS, signer }, // extra account: the victim signs
      ],
      data: cat(le32(5), le64(SOL_100)),
    },
  ]);
  assert.equal(r.signed, 0);
});

test("System AuthorizeNonceAccount: the victim as an extra signer hands the nonce authority over", async () => {
  const r = await run((signer, nonce, attacker) => [
    {
      programAddress: SYSTEM,
      accounts: [
        { address: nonce.address, role: W },
        { address: attacker.address, role: ROS, signer: attacker }, // "authority" slot
        { address: signer.address, role: ROS, signer }, // extra: the victim
      ],
      data: cat(le32(7), enc.encode(attacker.address)),
    },
  ]);
  assert.equal(r.signed, 0);
});
