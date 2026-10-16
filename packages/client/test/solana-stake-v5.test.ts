// Stake v5 (SIMD-0490, on mainnet since 2026-06-18) made the sysvar accounts optional: each
// instruction has an old layout (clock, rent, stake history after the first accounts) and a new
// one without them, and the program tells them apart by the sysvar's key (maintenance review of
// 2026-10-16, C2). The guard reads both, and an authority the program accepts from any signer
// among the accounts is judged by the signer's presence, never its position. Local only.
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
import { STAKE_PROGRAM, SYSTEM_PROGRAM } from "../src/solana.js";
import { boundProvider } from "./helpers.js";

const enc = getAddressEncoder();
const le32 = (n: number) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
const le64 = (n: bigint) => Uint8Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));
const cat = (...parts: ArrayLike<number>[]) => Uint8Array.from(parts.flatMap((p) => Array.from(p)));
const CLOCK = address("SysvarC1ock11111111111111111111111111111111");
const RENT = address("SysvarRent111111111111111111111111111111111");
const HISTORY = address("SysvarStakeHistory1111111111111111111111111");
const SOL_100 = 100_000_000_000n;
type Acc = { address: Address; role: AccountRole; signer?: KeyPairSigner };
type Ix = { programAddress: Address; accounts: Acc[]; data: Uint8Array };

const createStake = (payer: KeyPairSigner, stake: KeyPairSigner): Ix => ({
  programAddress: address(SYSTEM_PROGRAM),
  accounts: [
    { address: payer.address, role: AccountRole.WRITABLE_SIGNER, signer: payer },
    { address: stake.address, role: AccountRole.WRITABLE_SIGNER, signer: stake },
  ],
  data: cat(le32(0), le64(SOL_100), le64(200n), enc.encode(address(STAKE_PROGRAM))),
});

/** Runs `build` as a guarded transaction; the attacker is blocked, everyone else low. */
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

test("v5 InitializeChecked [stake, staker, withdrawer]: 100 SOL into a stake account the attacker withdraws is checked and blocked", async () => {
  const r = await run((signer, stake, attacker) => [
    createStake(signer, stake),
    {
      programAddress: address(STAKE_PROGRAM),
      accounts: [
        { address: stake.address, role: AccountRole.WRITABLE },
        { address: attacker.address, role: AccountRole.READONLY },
        { address: attacker.address, role: AccountRole.READONLY_SIGNER, signer: attacker },
        { address: signer.address, role: AccountRole.READONLY_SIGNER, signer }, // padding the old layout would read as the withdrawer
      ],
      data: le32(9),
    },
  ]);
  assert.equal(r.signed, 0);
  assert.equal(r.verdict?.action, "block");
  assert.ok(r.api.seen.some((q) => q.wallet === r.attacker), "the withdrawer was checked");
});

test("v5 InitializeChecked with the signer as withdrawer is signed; the old layout too", async () => {
  for (const withRent of [false, true]) {
    const r = await run((signer, stake) => [
      createStake(signer, stake),
      {
        programAddress: address(STAKE_PROGRAM),
        accounts: [
          { address: stake.address, role: AccountRole.WRITABLE },
          ...(withRent ? [{ address: RENT, role: AccountRole.READONLY }] : []),
          { address: signer.address, role: AccountRole.READONLY },
          { address: signer.address, role: AccountRole.READONLY_SIGNER, signer },
        ],
        data: le32(9),
      },
    ]);
    assert.equal(r.signed, 1, `${withRent ? "old" : "v5"} layout: ${r.verdict?.code} ${r.verdict?.reasons[0]}`);
  }
});

for (const [name, layout] of [
  ["v5 Authorize [stake, authority]", (stake: Address, signer: Acc) => [{ address: stake, role: AccountRole.WRITABLE }, signer]],
  ["old Authorize [stake, clock, authority]", (stake: Address, signer: Acc) => [{ address: stake, role: AccountRole.WRITABLE }, { address: CLOCK, role: AccountRole.READONLY }, signer]],
] as const) {
  test(`${name} handing the withdraw authority away is refused locally`, async () => {
    const r = await run((signer, stake, attacker) => [
      { programAddress: address(STAKE_PROGRAM), accounts: layout(stake.address, { address: signer.address, role: AccountRole.READONLY_SIGNER, signer }) as Acc[], data: cat(le32(1), enc.encode(attacker.address), le32(1)) },
    ]);
    assert.deepEqual([r.signed, r.verdict?.action, r.verdict?.code], [0, "block", "local_danger"]);
  });
}

test("v5 AuthorizeChecked [stake, authority, new authority] to someone else is refused locally", async () => {
  const r = await run((signer, stake, attacker) => [
    {
      programAddress: address(STAKE_PROGRAM),
      accounts: [
        { address: stake.address, role: AccountRole.WRITABLE },
        { address: signer.address, role: AccountRole.READONLY_SIGNER, signer },
        { address: attacker.address, role: AccountRole.READONLY_SIGNER, signer: attacker },
      ],
      data: cat(le32(10), le32(1)),
    },
  ]);
  assert.deepEqual([r.signed, r.verdict?.action, r.verdict?.code], [0, "block", "local_danger"]);
});

test("Withdraw to the attacker in both layouts: the recipient is checked and blocked", async () => {
  for (const old of [false, true]) {
    const r = await run((signer, stake, attacker) => [
      {
        programAddress: address(STAKE_PROGRAM),
        accounts: [
          { address: stake.address, role: AccountRole.WRITABLE },
          { address: attacker.address, role: AccountRole.WRITABLE },
          ...(old ? [{ address: CLOCK, role: AccountRole.READONLY }, { address: HISTORY, role: AccountRole.READONLY }] : []),
          { address: signer.address, role: AccountRole.READONLY_SIGNER, signer },
        ],
        data: cat(le32(4), le64(SOL_100)),
      },
    ]);
    assert.deepEqual([r.signed, r.verdict?.action], [0, "block"], old ? "old layout" : "v5 layout");
    assert.ok(r.api.seen.some((q) => q.wallet === r.attacker));
  }
});
