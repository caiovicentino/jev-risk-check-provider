// Review 2026-10-17: legitimate stake flows, as @solana/web3.js 1.99 StakeProgram builds them (old layout,
// sysvars included) and in the v5 layout (sysvars dropped), through the 0.5.0 guard. Expected: signed
// (allow), except a real hand-over of authority to someone else (blocked, as before the change).
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { test } from "node:test";
import {
  AccountRole,
  address,
  appendTransactionMessageInstructions,
  blockhash,
  createTransactionMessage,
  generateKeyPairSigner,
  pipe,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  type Address,
  type KeyPairSigner,
} from "@solana/kit";
import { guardSolanaSigner, X402CheckBlockedError, type GuardVerdict } from "../src/guard.js";
import { boundProvider } from "./helpers.js";

// @solana/web3.js builds the legitimate instructions (an encoder independent of this guard). It is a
// dependency of the repository root, not of this package: where it is not installed (the package's CI
// job), these tests are skipped; the root's npm ci makes it available.
const require = createRequire(import.meta.url);
const web3 = (() => {
  try {
    return require("@solana/web3.js");
  } catch {
    return undefined;
  }
})();
const { PublicKey, StakeProgram, Authorized, Lockup, StakeAuthorizationLayout } = web3 ?? {};
const CLOCK = "SysvarC1ock11111111111111111111111111111111";
const RENT = "SysvarRent111111111111111111111111111111111";
const HISTORY = "SysvarStakeHistory1111111111111111111111111";
const CONFIG = "StakeConfig11111111111111111111111111111111";
const SYSVARS = new Set([CLOCK, RENT, HISTORY, CONFIG]);

type Acc = { address: Address; role: AccountRole; signer?: KeyPairSigner };
type Ix = { programAddress: Address; accounts: Acc[]; data: Uint8Array };

/** web3.js TransactionInstruction(s) -> kit instructions; `v5` drops the sysvar accounts (SIMD-0490 layout). */
function toKit(ixs: any[], signers: Map<string, KeyPairSigner>, v5 = false): Ix[] {
  return ixs.map((ix) => ({
    programAddress: address(ix.programId.toBase58()),
    data: Uint8Array.from(ix.data),
    accounts: ix.keys
      .filter((k: any) => !(v5 && ix.programId.toBase58() === StakeProgram.programId.toBase58() && SYSVARS.has(k.pubkey.toBase58())))
      .map((k: any) => {
        const a = k.pubkey.toBase58();
        const role = k.isSigner ? (k.isWritable ? AccountRole.WRITABLE_SIGNER : AccountRole.READONLY_SIGNER) : k.isWritable ? AccountRole.WRITABLE : AccountRole.READONLY;
        const s = signers.get(a);
        return { address: address(a), role, ...(k.isSigner && s ? { signer: s } : {}) };
      }),
  }));
}

async function run(build: (signer: KeyPairSigner, stake: KeyPairSigner, other: KeyPairSigner) => Ix[]) {
  const other = await generateKeyPairSigner();
  const api = boundProvider(() => ({ tier: "low", score: 90, categories: [] }));
  const base = await generateKeyPairSigner();
  let signed = 0;
  const spy = { ...base, signTransactions: async (txs: Parameters<KeyPairSigner["signTransactions"]>[0]) => (signed++, base.signTransactions(txs)) } as KeyPairSigner;
  const guarded = guardSolanaSigner(spy, { pinnedKeys: false, fetch: api.fetch, solanaRpcUrl: "https://rpc.invalid/" });
  const stake = await generateKeyPairSigner();
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayerSigner(guarded, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash({ blockhash: blockhash(stake.address), lastValidBlockHeight: 1000n }, m),
    (m) => appendTransactionMessageInstructions(build(guarded, stake, other) as Parameters<typeof appendTransactionMessageInstructions>[0], m),
  );
  let verdict: GuardVerdict | undefined;
  try {
    await signTransactionMessageWithSigners(message);
  } catch (err) {
    assert.ok(err instanceof X402CheckBlockedError, String(err));
    verdict = err.verdict;
  }
  return { api, signed, verdict };
}

const pk = (a: string) => new PublicKey(a);
const VOTE = "Vote111111111111111111111111111111111111111";
const someVote = "CertusDeBmqN8ZawdkxK5kFGMwBXdudvWHYwtNgNhvLu";

if (!web3) test("legitimate stake flows built by @solana/web3.js (installed at the repository root)", { skip: "@solana/web3.js is not installed here" }, () => undefined);
for (const v5 of web3 ? [false, true] : []) {
  const L = v5 ? "v5" : "old";
  test(`${L}: create + initialize (signer = staker & withdrawer) + delegate`, async () => {
    const r = await run((signer, stake) => {
      const create = StakeProgram.createAccount({ fromPubkey: pk(signer.address), stakePubkey: pk(stake.address), authorized: new Authorized(pk(signer.address), pk(signer.address)), lockup: Lockup.default, lamports: 10_000_000_000 }).instructions;
      const delegate = StakeProgram.delegate({ stakePubkey: pk(stake.address), authorizedPubkey: pk(signer.address), votePubkey: pk(someVote) }).instructions;
      return toKit([...create, ...delegate], new Map([[signer.address, signer], [stake.address, stake]]), v5);
    });
    assert.equal(r.signed, 1);
  });

  test(`${L}: deactivate, then withdraw everything to the signer`, async () => {
    const r = await run((signer, stake) => {
      const deact = StakeProgram.deactivate({ stakePubkey: pk(stake.address), authorizedPubkey: pk(signer.address) }).instructions;
      const wd = StakeProgram.withdraw({ stakePubkey: pk(stake.address), authorizedPubkey: pk(signer.address), toPubkey: pk(signer.address), lamports: 10_000_000_000 }).instructions;
      return toKit([...deact, ...wd], new Map([[signer.address, signer]]), v5);
    });
    assert.equal(r.signed, 1);
  });

  test(`${L}: withdraw to another address (an exchange deposit): checked, signed`, async () => {
    const r = await run((signer, stake, other) => toKit(StakeProgram.withdraw({ stakePubkey: pk(stake.address), authorizedPubkey: pk(signer.address), toPubkey: pk(other.address), lamports: 5 }).instructions, new Map([[signer.address, signer]]), v5));
    assert.equal(r.signed, 1);
    assert.equal(r.api.seen.length, 1);
  });

  test(`${L}: split and merge between the signer's own stake accounts`, async () => {
    const r = await run((signer, stake, other) => {
      const merge = StakeProgram.merge({ stakePubkey: pk(stake.address), sourceStakePubKey: pk(other.address), authorizedPubkey: pk(signer.address) }).instructions;
      return toKit(merge, new Map([[signer.address, signer]]), v5);
    });
    assert.equal(r.signed, 1);
  });

  test(`${L}: Authorize the staker role to the signer itself (no-op): signed; to someone else: blocked`, async () => {
    for (const toOther of [false, true]) {
      const r = await run((signer, stake, other) =>
        toKit(
          StakeProgram.authorize({ stakePubkey: pk(stake.address), authorizedPubkey: pk(signer.address), newAuthorizedPubkey: pk(toOther ? other.address : signer.address), stakeAuthorizationType: StakeAuthorizationLayout.Staker }).instructions,
          new Map([[signer.address, signer]]),
          v5,
        ),
      );
      assert.equal(r.signed, toOther ? 0 : 1);
    }
  });
}
