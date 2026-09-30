// The Solana guard's rules from the 2026-09-30 audit: Stake authority and withdrawals, the
// priority-fee cap, MintTo, AssignWithSeed, native programs it cannot read, durable nonces,
// Sign-In With Solana origin mismatches, RPC agreement and unintercepted signing members.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  AccountRole,
  address,
  appendTransactionMessageInstructions,
  blockhash,
  createSignableMessage,
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
import { ASSOCIATED_TOKEN_PROGRAM, STAKE_PROGRAM, SYSTEM_PROGRAM, TOKEN_PROGRAM } from "../src/solana.js";
import { boundProvider, json } from "./helpers.js";

const RPC = "https://solana-rpc.test/";
const RPC2 = "https://solana-rpc-2.test/";
const USDC = address("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const COMPUTE_BUDGET = address("ComputeBudget111111111111111111111111111111");
const VOTE = address("Vote111111111111111111111111111111111111111");
const enc = getAddressEncoder();
const LOW = { tier: "low" as const, score: 90, categories: [] };

const le32 = (n: number) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
const le64 = (n: bigint) => Uint8Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));
const cat = (...parts: ArrayLike<number>[]) => Uint8Array.from(parts.flatMap((p) => Array.from(p)));
const fresh = async () => (await generateKeyPairSigner()).address;
type Ix = { programAddress: Address; accounts: Array<{ address: Address; role: AccountRole }>; data: Uint8Array };

function tokenAccount(mint: Address, owner: Address) {
  const data = new Uint8Array(165);
  data.set(enc.encode(mint), 0);
  data.set(enc.encode(owner), 32);
  data[108] = 1;
  return { owner: TOKEN_PROGRAM, data };
}

/** The provider stub plus one or two Solana RPCs answering getMultipleAccounts from `accounts`. */
function world(rpc: Record<string, Map<string, { owner: string; data: Uint8Array } | null>> = { [RPC]: new Map() }) {
  return boundProvider(
    () => LOW,
    (url, init) => {
      const accounts = rpc[url];
      if (!accounts) return undefined;
      const addresses = (JSON.parse(String(init.body)) as { params: [string[]] }).params[0];
      const value = addresses.map((a) => {
        const acc = accounts.get(a);
        return acc ? { owner: acc.owner, data: [Buffer.from(acc.data).toString("base64"), "base64"], lamports: 1, executable: false, rentEpoch: 0 } : null;
      });
      return json(200, { jsonrpc: "2.0", id: 1, result: { context: { slot: 1 }, value } });
    },
  );
}

async function agent() {
  const base = await generateKeyPairSigner();
  const raw: string[] = [];
  const spy = {
    ...base,
    signTransactions: async (txs: Parameters<KeyPairSigner["signTransactions"]>[0]) => (raw.push("tx"), base.signTransactions(txs)),
    signMessages: async (msgs: Parameters<KeyPairSigner["signMessages"]>[0]) => (raw.push("message"), base.signMessages(msgs)),
  } as KeyPairSigner;
  return { base, spy, raw };
}

async function message(feePayer: KeyPairSigner, instructions: Ix[]) {
  const hash = blockhash(await fresh());
  return pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayerSigner(feePayer, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash({ blockhash: hash, lastValidBlockHeight: 1000n }, m),
    (m) => appendTransactionMessageInstructions(instructions as Parameters<typeof appendTransactionMessageInstructions>[0], m),
  );
}

async function refused(p: Promise<unknown>): Promise<GuardVerdict> {
  try {
    await p;
  } catch (err) {
    assert.ok(err instanceof X402CheckBlockedError, `expected X402CheckBlockedError, got ${String(err)}`);
    return err.verdict;
  }
  assert.fail("expected a refusal");
}

const stake = (op: number, accounts: Array<{ address: Address; role: AccountRole }>, data: Uint8Array = new Uint8Array()) => ({ programAddress: address(STAKE_PROGRAM), accounts, data: cat(le32(op), data) });
const transfer = (from: Address, to: Address, lamports: bigint): Ix => ({
  programAddress: address(SYSTEM_PROGRAM),
  accounts: [
    { address: from, role: AccountRole.WRITABLE_SIGNER },
    { address: to, role: AccountRole.WRITABLE },
  ],
  data: cat(le32(2), le64(lamports)),
});

describe("Solana guard: native programs", () => {
  test("Stake: handing the withdrawer authority away is refused locally; a withdrawal checks its recipient", async () => {
    const a = await agent();
    const [stakeAccount, thief, recipient] = [await fresh(), await fresh(), await fresh()];
    const w = world();
    const guarded = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC });
    const clock = address("SysvarC1ock11111111111111111111111111111111");
    const history = address("SysvarStakeHistory1111111111111111111111111");
    const handOver = stake(1, [{ address: stakeAccount, role: AccountRole.WRITABLE }, { address: clock, role: AccountRole.READONLY }, { address: a.base.address, role: AccountRole.READONLY_SIGNER }], cat(enc.encode(thief), le32(1)));
    const v = await refused(signTransactionMessageWithSigners(await message(guarded, [handOver])));
    assert.equal(v.code, "local_danger");
    assert.match(v.reasons[0] ?? "", /Stake Authorize hands the withdrawer authority/);
    const withdraw = stake(4, [{ address: stakeAccount, role: AccountRole.WRITABLE }, { address: recipient, role: AccountRole.WRITABLE }, { address: clock, role: AccountRole.READONLY }, { address: history, role: AccountRole.READONLY }, { address: a.base.address, role: AccountRole.READONLY_SIGNER }], le64(5_000_000_000n));
    await signTransactionMessageWithSigners(await message(guarded, [withdraw]));
    assert.deepEqual([w.seen[0]?.wallet, w.seen[0]?.interaction?.type, w.seen[0]?.payment?.amount], [recipient, "native_transfer", "5000000000"]);
    const vote = await refused(signTransactionMessageWithSigners(await message(guarded, [{ programAddress: VOTE, accounts: [{ address: await fresh(), role: AccountRole.WRITABLE }, { address: a.base.address, role: AccountRole.READONLY_SIGNER }], data: le32(3) }])));
    assert.equal(vote.code, "unreadable_instruction");
    assert.deepEqual(a.raw, ["tx"]);
  });

  test("MintTo with the signer's mint authority is checked against the destination's owner; AssignWithSeed by the base is refused", async () => {
    const a = await agent();
    const [mint, dest, owner] = [await fresh(), await fresh(), await fresh()];
    const w = world({ [RPC]: new Map([[dest, tokenAccount(mint, owner)]]) });
    const guarded = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC });
    const mintTo: Ix = {
      programAddress: address(TOKEN_PROGRAM),
      accounts: [
        { address: mint, role: AccountRole.WRITABLE },
        { address: dest, role: AccountRole.WRITABLE },
        { address: a.base.address, role: AccountRole.READONLY_SIGNER },
      ],
      data: cat([7], le64(10n ** 15n)),
    };
    await signTransactionMessageWithSigners(await message(guarded, [mintTo]));
    assert.deepEqual([w.seen[0]?.wallet, w.seen[0]?.payment?.asset, w.seen[0]?.payment?.amount], [owner, mint, "1000000000000000"]);

    const seed = new TextEncoder().encode("vault");
    const derived = await fresh();
    const assignWithSeed: Ix = {
      programAddress: address(SYSTEM_PROGRAM),
      accounts: [
        { address: derived, role: AccountRole.WRITABLE },
        { address: a.base.address, role: AccountRole.READONLY_SIGNER },
      ],
      data: cat(le32(10), enc.encode(a.base.address), le64(BigInt(seed.length)), seed, enc.encode(await fresh())),
    };
    const v = await refused(signTransactionMessageWithSigners(await message(guarded, [assignWithSeed])));
    assert.match(v.reasons[0] ?? "", /AssignWithSeed hands the signer's seed-derived account/);
  });
});

describe("Solana guard: fees, nonces, messages, RPCs and members", () => {
  test("a priority fee above the cap is refused when the signer pays the fees", async () => {
    const a = await agent();
    const w = world();
    const guarded = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC });
    const limit: Ix = { programAddress: COMPUTE_BUDGET, accounts: [], data: cat([2], le32(1_400_000)) };
    const price: Ix = { programAddress: COMPUTE_BUDGET, accounts: [], data: cat([3], le64(10n ** 9n)) };
    const v = await refused(signTransactionMessageWithSigners(await message(guarded, [limit, price])));
    assert.equal(v.code, "fee_cap");
    assert.equal(w.seen.length, 0);
    // A normal priority fee passes.
    const normal: Ix = { programAddress: COMPUTE_BUDGET, accounts: [], data: cat([3], le64(1_000n)) };
    await signTransactionMessageWithSigners(await message(guarded, [limit, normal, transfer(a.base.address, await fresh(), 1n)]));
    assert.equal(w.seen.length, 1);
  });

  test("a durable nonce turns an allow into a warn: signed only if onWarn approves", async () => {
    const a = await agent();
    const w = world();
    const nonce = await fresh();
    const advance: Ix = {
      programAddress: address(SYSTEM_PROGRAM),
      accounts: [
        { address: nonce, role: AccountRole.WRITABLE },
        { address: address("SysvarRecentB1ockHashes11111111111111111111"), role: AccountRole.READONLY },
        { address: a.base.address, role: AccountRole.READONLY_SIGNER },
      ],
      data: le32(4),
    };
    const ixs = [advance, transfer(a.base.address, await fresh(), 1n)];
    const v = await refused(signTransactionMessageWithSigners(await message(guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC }), ixs)));
    assert.equal(v.code, "warn_declined");
    assert.match(v.reasons[0] ?? "", /durable nonce/);
    await signTransactionMessageWithSigners(await message(guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC, onWarn: () => true }), ixs));
    assert.deepEqual(a.raw, ["tx"]);
  });

  test("Sign-In With Solana from a different origin is refused; a matching one checks the site", async () => {
    const a = await agent();
    const w = world();
    const siws = (domain: string) => createSignableMessage(`${domain} wants you to sign in with your Solana account:\n${a.base.address}\n\nNonce: 7`);
    const phished = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, origin: "https://app-example.xyz" });
    const v = await refused(phished.signMessages([siws("app.example.com")]));
    assert.match(v.reasons[0] ?? "", /signs in to app\.example\.com, but the request comes from app-example\.xyz/);
    await guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, origin: "https://app.example.com" }).signMessages([siws("https://app.example.com")]);
    assert.equal(w.seen[0]?.domain, "app.example.com");
  });

  test("with several RPCs, they must agree on a receiving token account's owner", async () => {
    const a = await agent();
    const [mine, theirs, owner, other] = [await fresh(), await fresh(), await fresh(), await fresh()];
    const ix: Ix = {
      programAddress: address(TOKEN_PROGRAM),
      accounts: [
        { address: mine, role: AccountRole.WRITABLE },
        { address: theirs, role: AccountRole.WRITABLE },
        { address: a.base.address, role: AccountRole.READONLY_SIGNER },
      ],
      data: cat([3], le64(5n)),
    };
    const liar = world({ [RPC]: new Map([[theirs, tokenAccount(USDC, owner)]]), [RPC2]: new Map([[theirs, tokenAccount(USDC, other)]]) });
    const v = await refused(signTransactionMessageWithSigners(await message(guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: liar.fetch, solanaRpcUrl: RPC, solanaRpcUrls: [RPC2] }), [ix])));
    assert.match(v.reasons[0] ?? "", /RPC endpoints disagree/);
    const honest = world({ [RPC]: new Map([[theirs, tokenAccount(USDC, owner)]]), [RPC2]: new Map([[theirs, tokenAccount(USDC, owner)]]) });
    await signTransactionMessageWithSigners(await message(guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: honest.fetch, solanaRpcUrl: RPC, solanaRpcUrls: [RPC2] }), [ix]));
    assert.equal(honest.seen[0]?.wallet, owner);
    void ASSOCIATED_TOKEN_PROGRAM;
  });

  test("signing members the guard does not intercept refuse", async () => {
    const a = await agent();
    let sent = 0;
    const wallet = { ...a.spy, signAndSendTransaction: async () => (sent++, "sig") };
    const guarded = guardSolanaSigner(wallet, { pinnedKeys: false, fetch: world().fetch });
    const v = await refused(guarded.signAndSendTransaction());
    assert.equal(v.code, "unguarded_method");
    assert.equal(sent, 0);
  });
});
