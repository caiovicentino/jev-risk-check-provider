// Review 2026-10-17 (Solana, client 0.5.0). The Stake program (BPF, every release 1.0.0 -> v5.1.0 and main)
// builds Withdraw's, AuthorizeWithSeed's and AuthorizeCheckedWithSeed's signer set with
// collect_signers_checked(authority, custodian): the lockup custodian slot's key is inserted into the
// SAME set the withdrawer/staker check reads. So the victim's signature in the custodian slot authorizes
// the operation, while the guard only looks at the authority/base slot.
// Each case below is a drain the program accepts; the guard is expected to refuse it.
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

for (const old of [false, true]) {
  const layout = old ? "old layout" : "v5 layout";

  test(`${layout} Withdraw: the attacker signs the authority slot, the victim the custodian slot -> 100 SOL to the attacker`, async () => {
    // Program: withdraw_authority = accounts[2] (v5) or [4] (old); custodian = the next account;
    // signers = {authority, custodian}; meta.authorized.check(signers, Withdrawer) passes on the custodian.
    const r = await run((signer, stake, attacker) => [
      {
        programAddress: address(STAKE_PROGRAM),
        accounts: [
          { address: stake.address, role: W }, // the victim's stake account (withdrawer = victim)
          { address: attacker.address, role: W }, // recipient
          ...(old ? [{ address: CLOCK, role: RO }, { address: HISTORY, role: RO }] : []),
          { address: attacker.address, role: ROS, signer: attacker }, // "withdraw authority" slot
          { address: signer.address, role: ROS, signer }, // lockup custodian slot: the victim
        ],
        data: cat(le32(4), le64(SOL_100)),
      },
    ]);
    assert.equal(r.signed, 0, "the guard signed a withdrawal of the victim's stake to a known-scam address");
  });

  test(`${layout} AuthorizeWithSeed: any base, the victim in the custodian slot -> withdraw authority to the attacker`, async () => {
    // Program: signers = {custodian (must sign)} + derived(base) when base signs; do_authorize reads that set.
    const seed = new TextEncoder().encode("x");
    const r = await run((signer, stake, attacker) => [
      {
        programAddress: address(STAKE_PROGRAM),
        accounts: [
          { address: stake.address, role: W },
          { address: attacker.address, role: RO }, // base: not even a signer
          ...(old ? [{ address: CLOCK, role: RO }] : []),
          { address: signer.address, role: ROS, signer }, // custodian slot: the victim
        ],
        data: cat(le32(8), enc.encode(attacker.address), le32(1), le64(BigInt(seed.length)), seed, enc.encode(attacker.address)),
      },
    ]);
    assert.equal(r.signed, 0, "the guard signed a hand-over of the victim's withdraw authority");
  });

  test(`${layout} AuthorizeCheckedWithSeed: the attacker as new authority, the victim in the custodian slot`, async () => {
    // Program: signers = {new authority, custodian} + derived(base) when base signs.
    const seed = new TextEncoder().encode("x");
    const r = await run((signer, stake, attacker) => [
      {
        programAddress: address(STAKE_PROGRAM),
        accounts: [
          { address: stake.address, role: W },
          { address: attacker.address, role: RO }, // base
          ...(old ? [{ address: CLOCK, role: RO }] : []),
          { address: attacker.address, role: ROS, signer: attacker }, // new authority (must sign)
          { address: signer.address, role: ROS, signer }, // custodian slot: the victim
        ],
        data: cat(le32(11), le32(1), le64(BigInt(seed.length)), seed, enc.encode(attacker.address)),
      },
    ]);
    assert.equal(r.signed, 0, "the guard signed a hand-over of the victim's withdraw authority");
  });
}
