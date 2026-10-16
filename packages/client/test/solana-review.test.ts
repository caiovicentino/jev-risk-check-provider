// The SDK review of 2026-10-16, Solana (finding 3): the lamports a transaction moves are checked
// against whoever controls the receiving account (its owner program, the withdraw authority a
// Stake Initialize sets, the owner an InitializeAccount sets, a nonce authority, a seed base),
// never against a fresh address the dApp supplies. Stubs only: throwaway keys, no network.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  AccountRole,
  address,
  appendTransactionMessageInstructions,
  blockhash,
  createAddressWithSeed,
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
import { STAKE_PROGRAM, SYSTEM_PROGRAM, TOKEN_PROGRAM } from "../src/solana.js";
import { boundProvider } from "./helpers.js";

const LOW = { tier: "low" as const, score: 90, categories: [] };
const BLOCK = { tier: "critical" as const, score: 2, categories: ["known_scam_address"] };

describe("Solana lamports are checked against whoever controls the receiving account", () => {
  const enc = getAddressEncoder();
  const le32 = (n: number) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
  const le64 = (n: bigint) => Uint8Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));
  const cat = (...parts: ArrayLike<number>[]) => Uint8Array.from(parts.flatMap((p) => Array.from(p)));
  const RENT = address("SysvarRent111111111111111111111111111111111");
  const RECENT_BLOCKHASHES = address("SysvarRecentB1ockHashes11111111111111111111");
  const NATIVE_MINT = address("So11111111111111111111111111111111111111112");
  const SOL_100 = 100_000_000_000n;
  type Ix = { programAddress: Address; accounts: Array<{ address: Address; role: AccountRole; signer?: KeyPairSigner }>; data: Uint8Array };

  const createAccount = (payer: KeyPairSigner, fresh: KeyPairSigner, lamports: bigint, space: bigint, owner: string): Ix => ({
    programAddress: address(SYSTEM_PROGRAM),
    accounts: [
      { address: payer.address, role: AccountRole.WRITABLE_SIGNER, signer: payer },
      { address: fresh.address, role: AccountRole.WRITABLE_SIGNER, signer: fresh },
    ],
    data: cat(le32(0), le64(lamports), le64(space), enc.encode(address(owner))),
  });

  /** Signs `build(...)` with a guarded fee payer; the attacker is blocked, every other address is low risk. */
  async function run(build: (payer: KeyPairSigner, fresh: KeyPairSigner, attacker: Address) => Ix[] | Promise<Ix[]>) {
    const attacker = (await generateKeyPairSigner()).address;
    const api = boundProvider((r) => (r.wallet === attacker ? BLOCK : LOW));
    const base = await generateKeyPairSigner();
    let signed = 0;
    const spy = { ...base, signTransactions: async (txs: Parameters<KeyPairSigner["signTransactions"]>[0]) => (signed++, base.signTransactions(txs)) } as KeyPairSigner;
    const guarded = guardSolanaSigner(spy, { pinnedKeys: false, fetch: api.fetch, solanaRpcUrl: "https://rpc.invalid/" });
    const fresh = await generateKeyPairSigner();
    const instructions = await build(guarded, fresh, attacker);
    const message = pipe(
      createTransactionMessage({ version: 0 }),
      (m) => setTransactionMessageFeePayerSigner(guarded, m),
      (m) => setTransactionMessageLifetimeUsingBlockhash({ blockhash: blockhash(fresh.address), lastValidBlockHeight: 1000n }, m),
      (m) => appendTransactionMessageInstructions(instructions as Parameters<typeof appendTransactionMessageInstructions>[0], m),
    );
    let verdict: GuardVerdict | undefined;
    try {
      await signTransactionMessageWithSigners(message);
    } catch (err) {
      assert.ok(err instanceof X402CheckBlockedError, String(err));
      verdict = err.verdict;
    }
    return { api, signed, verdict, attacker, fresh };
  }

  test("100 SOL into a new account owned by a blocked program: the program is checked, and blocks it", async () => {
    const r = await run((payer, fresh, attacker) => [createAccount(payer, fresh, SOL_100, 0n, attacker)]);
    assert.equal(r.verdict?.action, "block");
    assert.deepEqual(r.api.seen.map((x) => [x.wallet, x.interaction?.type]), [[r.attacker, "contract_call"]]);
    assert.equal(r.signed, 0);
  });

  test("100 SOL into a stake account whose Initialize names a blocked withdrawer: the withdrawer is checked", async () => {
    const r = await run((payer, fresh, attacker) => [
      createAccount(payer, fresh, SOL_100, 200n, STAKE_PROGRAM),
      {
        programAddress: address(STAKE_PROGRAM),
        accounts: [
          { address: fresh.address, role: AccountRole.WRITABLE },
          { address: RENT, role: AccountRole.READONLY },
        ],
        data: cat(le32(0), enc.encode(attacker), enc.encode(attacker), le64(0n), le64(0n), new Uint8Array(32)),
      },
    ]);
    assert.equal(r.verdict?.action, "block");
    assert.equal(r.api.seen[0]?.wallet, r.attacker);
    assert.equal(r.api.seen[0]?.payment?.amount, SOL_100.toString());
  });

  test("a stake account the transaction does not initialize is refused: anyone could set its withdrawer", async () => {
    const r = await run((payer, fresh) => [createAccount(payer, fresh, SOL_100, 200n, STAKE_PROGRAM)]);
    assert.deepEqual([r.verdict?.action, r.verdict?.code], ["not_verified", "unreadable_instruction"]);
    assert.equal(r.api.seen.length, 0);
  });

  test("100 SOL into a new wSOL account that InitializeAccount3 gives to a blocked owner: the owner is checked", async () => {
    const r = await run((payer, fresh, attacker) => [
      createAccount(payer, fresh, SOL_100, 165n, TOKEN_PROGRAM),
      {
        programAddress: address(TOKEN_PROGRAM),
        accounts: [
          { address: fresh.address, role: AccountRole.WRITABLE },
          { address: NATIVE_MINT, role: AccountRole.READONLY },
        ],
        data: cat([18], enc.encode(attacker)),
      },
    ]);
    assert.equal(r.verdict?.action, "block");
    assert.equal(r.api.seen[0]?.wallet, r.attacker);
  });

  test("a new nonce account whose authority is blocked: the authority is checked", async () => {
    const r = await run((payer, fresh, attacker) => [
      createAccount(payer, fresh, SOL_100, 80n, SYSTEM_PROGRAM),
      {
        programAddress: address(SYSTEM_PROGRAM),
        accounts: [
          { address: fresh.address, role: AccountRole.WRITABLE },
          { address: RECENT_BLOCKHASHES, role: AccountRole.READONLY },
          { address: RENT, role: AccountRole.READONLY },
        ],
        data: cat(le32(6), enc.encode(attacker)),
      },
    ]);
    assert.equal(r.verdict?.action, "block");
    assert.equal(r.api.seen[0]?.wallet, r.attacker);
  });

  test("a transfer to an account the transaction then assigns to a blocked program: the program is checked", async () => {
    const r = await run((payer, fresh, attacker) => [
      {
        programAddress: address(SYSTEM_PROGRAM),
        accounts: [
          { address: payer.address, role: AccountRole.WRITABLE_SIGNER, signer: payer },
          { address: fresh.address, role: AccountRole.WRITABLE },
        ],
        data: cat(le32(2), le64(SOL_100)),
      },
      { programAddress: address(SYSTEM_PROGRAM), accounts: [{ address: fresh.address, role: AccountRole.WRITABLE_SIGNER, signer: fresh }], data: cat(le32(1), enc.encode(attacker)) },
    ]);
    assert.equal(r.verdict?.action, "block");
    assert.equal(r.api.seen[0]?.wallet, r.attacker);
  });

  test("a seed-derived system account is checked against its base", async () => {
    const r = await run(async (payer, fresh, attacker) => {
      const seed = "vault";
      const created = await createAddressWithSeed({ baseAddress: attacker, programAddress: address(SYSTEM_PROGRAM), seed });
      return [
        {
          programAddress: address(SYSTEM_PROGRAM),
          accounts: [
            { address: payer.address, role: AccountRole.WRITABLE_SIGNER, signer: payer },
            { address: created, role: AccountRole.WRITABLE },
            { address: fresh.address, role: AccountRole.READONLY_SIGNER, signer: fresh },
          ],
          data: cat(le32(3), enc.encode(attacker), le64(BigInt(seed.length)), new TextEncoder().encode(seed), le64(SOL_100), le64(0n), enc.encode(address(SYSTEM_PROGRAM))),
        },
      ];
    });
    assert.equal(r.verdict?.action, "block");
    assert.equal(r.api.seen[0]?.wallet, r.attacker);
  });

  test("a new mint keeps its rent: nothing to check; more than its rent is refused", async () => {
    const mintRent = (128n + 82n) * 6960n;
    const initMint = (fresh: KeyPairSigner, authority: Address): Ix => ({
      programAddress: address(TOKEN_PROGRAM),
      accounts: [{ address: fresh.address, role: AccountRole.WRITABLE }],
      data: cat([20, 6], enc.encode(authority), [0]),
    });
    const ok = await run((payer, fresh) => [createAccount(payer, fresh, mintRent, 82n, TOKEN_PROGRAM), initMint(fresh, payer.address)]);
    assert.equal(ok.verdict, undefined);
    assert.equal(ok.signed, 1);
    assert.equal(ok.api.seen.length, 0);
    const excess = await run((payer, fresh) => [createAccount(payer, fresh, SOL_100, 82n, TOKEN_PROGRAM), initMint(fresh, payer.address)]);
    assert.deepEqual([excess.verdict?.action, excess.verdict?.code], ["not_verified", "unreadable_instruction"]);
  });

  test("the signer's own stake account (it is the withdrawer) has nothing to check", async () => {
    const r = await run((payer, fresh) => [
      createAccount(payer, fresh, SOL_100, 200n, STAKE_PROGRAM),
      {
        programAddress: address(STAKE_PROGRAM),
        accounts: [
          { address: fresh.address, role: AccountRole.WRITABLE },
          { address: RENT, role: AccountRole.READONLY },
        ],
        data: cat(le32(0), enc.encode(payer.address), enc.encode(payer.address), le64(0n), le64(0n), new Uint8Array(32)),
      },
    ]);
    assert.equal(r.verdict, undefined);
    assert.equal(r.signed, 1);
    assert.equal(r.api.seen.length, 0);
  });
});
