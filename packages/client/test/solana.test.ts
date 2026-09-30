// The Solana signing guard (guardSolanaSigner): real @solana/kit signers and compiled
// transactions, a stub provider signing attestations bound as the real one binds them, and a
// stub Solana RPC for address lookup tables and token accounts.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  AccountRole,
  address,
  appendTransactionMessageInstructions,
  blockhash,
  compileTransaction,
  compressTransactionMessageUsingAddressLookupTables,
  createSignableMessage,
  createTransactionMessage,
  generateKeyPairSigner,
  getAddressEncoder,
  pipe,
  setTransactionMessageFeePayer,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  verifySignature,
  type Address,
  type KeyPairSigner,
} from "@solana/kit";
import { guardSolanaSigner, X402CheckBlockedError, type GuardVerdict } from "../src/guard.js";
import { requestHash } from "../src/request-hash.js";
import { normalizeHost, toCaip2 } from "../src/normalize.js";
import {
  ADDRESS_LOOKUP_TABLE_PROGRAM,
  ASSOCIATED_TOKEN_PROGRAM,
  base58Decode,
  base58Encode,
  decodeSolanaMessage,
  SOLANA_MAINNET,
  SYSTEM_PROGRAM,
  TOKEN_2022_PROGRAM,
  TOKEN_PROGRAM,
} from "../src/solana.js";
import type { RiskCheckRequest } from "../src/types.js";
import { claims, DID_URL, didDocument, json, mockFetch, providerStyleSigner } from "./helpers.js";

const RPC = "https://solana-rpc.test/";
const USDC = address("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const JUPITER = address("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
const U64_MAX = (1n << 64n) - 1n;
const enc = getAddressEncoder();

type Verdict = { tier: "low" | "medium" | "high" | "critical"; score: number; categories: string[] };
const LOW: Verdict = { tier: "low", score: 90, categories: [] };
const BLOCK: Verdict = { tier: "critical", score: 8, categories: ["approval_to_eoa", "unlimited_approval"] };

const le32 = (n: number) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
const le64 = (n: bigint) => Uint8Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));
const cat = (...parts: ArrayLike<number>[]) => Uint8Array.from(parts.flatMap((p) => Array.from(p)));
const fresh = async () => (await generateKeyPairSigner()).address;
/** @solana/kit brands its byte arrays; the decoder takes plain bytes. */
const bytesOf = (t: { messageBytes: unknown }) => t.messageBytes as unknown as Uint8Array;
/** Compiled transactions, as a signer's batch (kit brands them with size and lifetime). */
const batch = (...txs: unknown[]) => txs as unknown as Parameters<KeyPairSigner["signTransactions"]>[0];

const ix = {
  transfer: (from: Address, to: Address, lamports: bigint) => ({
    programAddress: address(SYSTEM_PROGRAM),
    accounts: [
      { address: from, role: AccountRole.WRITABLE_SIGNER },
      { address: to, role: AccountRole.WRITABLE },
    ],
    data: cat(le32(2), le64(lamports)),
  }),
  assign: (account: Address, owner: Address) => ({ programAddress: address(SYSTEM_PROGRAM), accounts: [{ address: account, role: AccountRole.WRITABLE_SIGNER }], data: cat(le32(1), enc.encode(owner)) }),
  authorizeNonce: (nonce: Address, authority: Address, next: Address) => ({
    programAddress: address(SYSTEM_PROGRAM),
    accounts: [
      { address: nonce, role: AccountRole.WRITABLE },
      { address: authority, role: AccountRole.READONLY_SIGNER },
    ],
    data: cat(le32(7), enc.encode(next)),
  }),
  createAta: (payer: Address, ata: Address, owner: Address, mint: Address) => ({
    programAddress: address(ASSOCIATED_TOKEN_PROGRAM),
    accounts: [
      { address: payer, role: AccountRole.WRITABLE_SIGNER },
      { address: ata, role: AccountRole.WRITABLE },
      { address: owner, role: AccountRole.READONLY },
      { address: mint, role: AccountRole.READONLY },
      { address: address(SYSTEM_PROGRAM), role: AccountRole.READONLY },
      { address: address(TOKEN_PROGRAM), role: AccountRole.READONLY },
    ],
    data: Uint8Array.of(1),
  }),
  transferChecked: (source: Address, mint: Address, destination: Address, authority: Address, amount: bigint) => ({
    programAddress: address(TOKEN_PROGRAM),
    accounts: [
      { address: source, role: AccountRole.WRITABLE },
      { address: mint, role: AccountRole.READONLY },
      { address: destination, role: AccountRole.WRITABLE },
      { address: authority, role: AccountRole.READONLY_SIGNER },
    ],
    data: cat([12], le64(amount), [6]),
  }),
  tokenTransfer: (source: Address, destination: Address, authority: Address, amount: bigint) => ({
    programAddress: address(TOKEN_PROGRAM),
    accounts: [
      { address: source, role: AccountRole.WRITABLE },
      { address: destination, role: AccountRole.WRITABLE },
      { address: authority, role: AccountRole.READONLY_SIGNER },
    ],
    data: cat([3], le64(amount)),
  }),
  approve: (source: Address, delegate: Address, owner: Address, amount: bigint) => ({
    programAddress: address(TOKEN_PROGRAM),
    accounts: [
      { address: source, role: AccountRole.WRITABLE },
      { address: delegate, role: AccountRole.READONLY },
      { address: owner, role: AccountRole.READONLY_SIGNER },
    ],
    data: cat([4], le64(amount)),
  }),
  setOwner: (account: Address, current: Address, next: Address) => ({
    programAddress: address(TOKEN_PROGRAM),
    accounts: [
      { address: account, role: AccountRole.WRITABLE },
      { address: current, role: AccountRole.READONLY_SIGNER },
    ],
    data: cat([6, 2, 1], enc.encode(next)),
  }),
  call: (program: Address, accounts: Array<{ address: Address; role: AccountRole }>, data = Uint8Array.of(0xe5, 1, 2)) => ({ programAddress: program, accounts, data }),
};

type Rpc = Map<string, { owner: string; data: Uint8Array } | null>;

function tokenAccount(mint: Address, owner: Address, program = TOKEN_PROGRAM) {
  const data = new Uint8Array(165);
  data.set(enc.encode(mint), 0);
  data.set(enc.encode(owner), 32);
  data[108] = 1;
  return { owner: program, data };
}

function lookupTable(addresses: Address[]) {
  const data = new Uint8Array(56 + 32 * addresses.length);
  data[0] = 1;
  addresses.forEach((a, i) => data.set(enc.encode(a), 56 + 32 * i));
  return { owner: ADDRESS_LOOKUP_TABLE_PROGRAM, data };
}

/** The provider (attestations bound like the real one's) and a Solana RPC, behind one fetch. */
function world(decide: (request: RiskCheckRequest) => Verdict, rpc: Rpc = new Map(), opts: { rpcDown?: boolean } = {}) {
  const signer = providerStyleSigner();
  const seen: RiskCheckRequest[] = [];
  const rpcCalls: string[][] = [];
  const sign = async (request: RiskCheckRequest) => {
    seen.push(request);
    const v = decide(request);
    const network = request.chain ? toCaip2(request.chain) : undefined;
    const c = claims({
      sub: request.wallet,
      score: v.score,
      tier: v.tier,
      categories: v.categories,
      request_hash: await requestHash(request),
      checks: {
        sanctions: { list: "ofac-sdn", as_of: "2026-09-23", status: "not_listed" },
        ...(network ? { onchain: { status: "ok", network, activity: "some" } } : {}),
        model: "jev-wallet-risk/v6",
        ...(request.domain ? { domain: { host: normalizeHost(request.domain), registrable: normalizeHost(request.domain), official: false } } : {}),
      },
    });
    if (request.interaction) c.interaction = request.interaction.type;
    else delete c.interaction;
    if (request.payment) c.payment = request.payment;
    return { checked: true, score: v.score, tier: v.tier, categories: v.categories, jws: signer.sign(c), checked_at: new Date().toISOString(), expires_at: new Date((c.exp as number) * 1000).toISOString() };
  };
  const { fetch } = mockFetch(async (url, init) => {
    if (url === DID_URL) return json(200, didDocument(signer.publicJwk));
    if (url === RPC) {
      if (opts.rpcDown) return json(503, { error: "unavailable" });
      const addresses = (JSON.parse(String(init.body)) as { params: [string[]] }).params[0];
      rpcCalls.push(addresses);
      const value = addresses.map((a) => {
        const account = rpc.get(a);
        return account ? { owner: account.owner, data: [Buffer.from(account.data).toString("base64"), "base64"], lamports: 2039280, executable: false, rentEpoch: 0 } : null;
      });
      return json(200, { jsonrpc: "2.0", id: 1, result: { context: { slot: 1 }, value } });
    }
    const body = JSON.parse(String(init.body ?? "{}")) as RiskCheckRequest & { requests?: RiskCheckRequest[] };
    if (url.endsWith("/v1/risk-check/batch")) return json(200, { results: await Promise.all((body.requests ?? []).map(sign)) });
    if (url.endsWith("/v1/risk-check")) return json(200, await sign(body));
    return json(404, { error: "not_found" });
  });
  return { fetch, seen, rpcCalls };
}

/** A real key pair signer whose raw signing calls are counted. */
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

async function message(feePayer: KeyPairSigner, instructions: ReadonlyArray<ReturnType<(typeof ix)[keyof typeof ix]>>) {
  const hash = blockhash(await fresh());
  return pipe(
    createTransactionMessage({ version: 0 }),
    (m) => setTransactionMessageFeePayerSigner(feePayer, m),
    (m) => setTransactionMessageLifetimeUsingBlockhash({ blockhash: hash, lastValidBlockHeight: 1000n }, m),
    (m) => appendTransactionMessageInstructions(instructions as Parameters<typeof appendTransactionMessageInstructions>[0], m),
  );
}

async function refusal(p: Promise<unknown>): Promise<GuardVerdict> {
  try {
    await p;
  } catch (err) {
    assert.ok(err instanceof X402CheckBlockedError, `expected X402CheckBlockedError, got ${String(err)}`);
    return err.verdict;
  }
  assert.fail("the signature should have been refused");
}

describe("the Solana wire format", () => {
  test("base58 round-trips, with leading zeros", () => {
    for (const bytes of [new Uint8Array(32), Uint8Array.of(0, 0, 1, 2, 255), crypto.getRandomValues(new Uint8Array(32))]) {
      assert.deepEqual(base58Decode(base58Encode(bytes)), bytes);
    }
    assert.equal(base58Encode(enc.encode(USDC) as Uint8Array), USDC);
    assert.equal(base58Decode("0OIl"), null);
  });

  test("a compiled v0 message decodes exactly; any tampering is refused", async () => {
    const a = await agent();
    const bob = await fresh();
    const compiled = compileTransaction(await message(a.base, [ix.transfer(a.base.address, bob, 5n)]));
    const m = decodeSolanaMessage(bytesOf(compiled));
    assert.equal(m.version, 0);
    assert.deepEqual(m.staticAccounts, [a.base.address, bob, SYSTEM_PROGRAM]);
    assert.equal(m.instructions.length, 1);
    const bytes = bytesOf(compiled);
    assert.throws(() => decodeSolanaMessage(cat(bytes, [0])), /trailing bytes/);
    assert.throws(() => decodeSolanaMessage(bytes.slice(0, -1)), /truncated/);
    assert.throws(() => decodeSolanaMessage(cat([0x81], bytes.slice(1))), /message version 1/);
    const badProgram = bytes.slice();
    badProgram[1 + 3 + 1 + 32 * 3 + 32 + 1] = 9; // the instruction's program index
    assert.throws(() => decodeSolanaMessage(badProgram), /program index out of range/);
  });
});

describe("guardSolanaSigner: transactions", () => {
  test("a SOL transfer: the recipient is checked with the amount bound, then the key signs a valid signature", async () => {
    const a = await agent();
    const bob = await fresh();
    const w = world(() => LOW);
    const guarded = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC });
    const signed = await signTransactionMessageWithSigners(await message(guarded, [ix.transfer(a.base.address, bob, 1_500_000_000n)]));
    const signature = signed.signatures[a.base.address];
    assert.ok(signature, "signed");
    assert.equal(await verifySignature(a.base.keyPair.publicKey, signature, signed.messageBytes), true);
    assert.deepEqual(a.raw, ["tx"]);
    assert.equal(w.seen.length, 1);
    assert.equal(w.seen[0]?.wallet, bob);
    assert.equal(w.seen[0]?.chain, SOLANA_MAINNET);
    assert.deepEqual(w.seen[0]?.interaction, { type: "native_transfer" });
    assert.deepEqual(w.seen[0]?.payment, { network: SOLANA_MAINNET, pay_to: bob, asset: "native", amount: "1500000000" });
    assert.match(w.seen[0]?.context ?? "", /the signer sends 1500000000 lamports to .* \(System transfer\)/);
    assert.deepEqual(w.rpcCalls, [], "nothing to resolve: no RPC call");
  });

  test("USDC to a token account the transaction creates: the owner comes from the ATA instruction, not an RPC", async () => {
    const a = await agent();
    const [bob, mine, bobs] = [await fresh(), await fresh(), await fresh()];
    const w = world(() => LOW);
    const guarded = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC });
    await signTransactionMessageWithSigners(await message(guarded, [ix.createAta(a.base.address, bobs, bob, USDC), ix.transferChecked(mine, USDC, bobs, a.base.address, 2_500_000n)]));
    assert.deepEqual(a.raw, ["tx"]);
    assert.equal(w.seen[0]?.wallet, bob, "the owner, not the token account");
    assert.deepEqual(w.seen[0]?.interaction, { type: "token_transfer" });
    assert.deepEqual(w.seen[0]?.payment, { network: SOLANA_MAINNET, pay_to: bob, amount: "2500000", asset: USDC });
    assert.deepEqual(w.rpcCalls, []);
  });

  test("a transfer to an existing token account: its owner and mint are read on-chain", async () => {
    const a = await agent();
    const [bob, mine, bobs] = [await fresh(), await fresh(), await fresh()];
    const w = world(() => LOW, new Map([[bobs, tokenAccount(USDC, bob, TOKEN_2022_PROGRAM)]]));
    const guarded = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC });
    await signTransactionMessageWithSigners(await message(guarded, [ix.tokenTransfer(mine, bobs, a.base.address, 42n)]));
    assert.deepEqual(w.rpcCalls, [[bobs]]);
    assert.deepEqual([w.seen[0]?.wallet, w.seen[0]?.payment?.asset, w.seen[0]?.payment?.amount], [bob, USDC, "42"]);
  });

  test("a receiving token account whose owner cannot be established: not_verified, nothing signed", async () => {
    for (const [rpc, opts, why] of [
      [new Map(), {}, /does not exist, and the transaction does not create it/],
      [new Map(), { rpcDown: true }, /Solana RPC answered HTTP 503/],
    ] as const) {
      const a = await agent();
      const [mine, target] = [await fresh(), await fresh()];
      const w = world(() => LOW, rpc as Rpc, opts);
      const guarded = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC });
      const v = await refusal(signTransactionMessageWithSigners(await message(guarded, [ix.tokenTransfer(mine, target, a.base.address, 1n)])));
      assert.equal(v.action, "not_verified");
      assert.match(v.reasons.join(" "), why);
      assert.deepEqual(a.raw, []);
      assert.equal(w.seen.length, 0);
    }
  });

  test("the account or its control handed over: blocked locally, no check, nothing signed", async () => {
    const [drainerProgram, drainer] = [await fresh(), await fresh()];
    const cases: Array<[(me: Address) => Promise<ReturnType<(typeof ix)[keyof typeof ix]>>, RegExp]> = [
      [async (me) => ix.assign(me, drainerProgram), /System Assign hands the signer's own account to program/],
      [async (me) => ix.setOwner(await fresh(), me, drainer), /SPL Token SetAuthority hands the account owner authority of .* to /],
      [async (me) => ix.authorizeNonce(await fresh(), me, drainer), /hands the authority of nonce account/],
    ];
    for (const [make, why] of cases) {
      const a = await agent();
      const w = world(() => LOW);
      const guarded = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC });
      const v = await refusal(signTransactionMessageWithSigners(await message(guarded, [await make(a.base.address)])));
      assert.equal(v.action, "block");
      assert.equal(v.code, "local_danger");
      assert.match(v.reasons[0] ?? "", why);
      assert.deepEqual(a.raw, []);
      assert.equal(w.seen.length, 0, "no check is bought for a proven drain");
    }
  });

  test("an unlimited SPL approval: the delegate is checked as an unlimited token approval, and blocked", async () => {
    const a = await agent();
    const [delegate, mine] = [await fresh(), await fresh()];
    const w = world((r) => (r.interaction?.type === "token_approval" && r.interaction.unlimited ? BLOCK : LOW));
    const guarded = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC });
    const v = await refusal(signTransactionMessageWithSigners(await message(guarded, [ix.approve(mine, delegate, a.base.address, U64_MAX)])));
    assert.equal(v.action, "block");
    assert.equal(w.seen[0]?.wallet, delegate);
    assert.deepEqual(w.seen[0]?.interaction, { type: "token_approval", unlimited: true });
    assert.deepEqual(a.raw, []);
  });

  test("v0 with an address lookup table: the recipient loaded from the table is the one checked", async () => {
    const a = await agent();
    const [bob, filler, table] = [await fresh(), await fresh(), await fresh()];
    const w = world(() => LOW, new Map([[table, lookupTable([filler, bob])]]));
    const guarded = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC });
    const compressed = compressTransactionMessageUsingAddressLookupTables(await message(guarded, [ix.transfer(a.base.address, bob, 7n)]), { [table]: [filler, bob] });
    const compiled = compileTransaction(compressed);
    assert.equal(decodeSolanaMessage(bytesOf(compiled)).lookups.length, 1, "the recipient is loaded from the table");
    await signTransactionMessageWithSigners(compressed);
    assert.deepEqual(w.rpcCalls, [[table]]);
    assert.equal(w.seen[0]?.wallet, bob);

    const b = await agent();
    const unresolved = world(() => LOW, new Map([[table, null]]));
    const again = guardSolanaSigner(b.spy, { pinnedKeys: false, fetch: unresolved.fetch, solanaRpcUrl: RPC });
    const v = await refusal(signTransactionMessageWithSigners(compressTransactionMessageUsingAddressLookupTables(await message(again, [ix.transfer(b.base.address, bob, 7n)]), { [table]: [filler, bob] })));
    assert.equal(v.action, "not_verified");
    assert.match(v.reasons[0] ?? "", /address lookup tables could not be resolved/);
    assert.deepEqual(b.raw, []);
  });

  test("a program that receives the signer's authority is checked as a contract call", async () => {
    const a = await agent();
    const w = world(() => LOW);
    const guarded = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC });
    await signTransactionMessageWithSigners(await message(guarded, [ix.call(JUPITER, [{ address: a.base.address, role: AccountRole.WRITABLE_SIGNER }, { address: await fresh(), role: AccountRole.WRITABLE }])]));
    assert.deepEqual([w.seen[0]?.wallet, w.seen[0]?.interaction?.type], [JUPITER, "contract_call"]);
  });

  test("a token instruction the guard cannot read, signed by the signer: not_verified", async () => {
    const a = await agent();
    const w = world(() => LOW);
    const guarded = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC });
    const unknown = { programAddress: address(TOKEN_2022_PROGRAM), accounts: [{ address: await fresh(), role: AccountRole.WRITABLE }, { address: a.base.address, role: AccountRole.READONLY_SIGNER }], data: Uint8Array.of(27, 0) };
    const v = await refusal(signTransactionMessageWithSigners(await message(guarded, [unknown])));
    assert.equal(v.action, "not_verified");
    assert.equal(v.code, "unreadable_instruction");
    assert.match(v.reasons[0] ?? "", /Token-2022 instruction 27/);
  });

  test("between the signer's own token accounts nothing is checked; more than 5 counterparties is refused", async () => {
    const a = await agent();
    const [mine, other] = [await fresh(), await fresh()];
    const w = world(() => LOW);
    const guarded = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC });
    await signTransactionMessageWithSigners(await message(guarded, [ix.createAta(a.base.address, other, a.base.address, USDC), ix.transferChecked(mine, USDC, other, a.base.address, 9n)]));
    assert.equal(w.seen.length, 0);

    const b = await agent();
    const spread = await Promise.all(Array.from({ length: 6 }, fresh));
    const many = guardSolanaSigner(b.spy, { pinnedKeys: false, fetch: world(() => LOW).fetch, solanaRpcUrl: RPC });
    const v = await refusal(signTransactionMessageWithSigners(await message(many, spread.map((to) => ix.transfer(b.base.address, to, 1n)))));
    assert.equal(v.action, "not_verified");
    assert.match(v.reasons[0] ?? "", /6 counterparties in one transaction; at most 5 are checked/);
  });

  test("one refused transaction refuses the whole batch", async () => {
    const a = await agent();
    const bob = await fresh();
    const w = world(() => LOW);
    const guarded = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC });
    const good = compileTransaction(await message(a.base, [ix.transfer(a.base.address, bob, 1n)]));
    const bad = compileTransaction(await message(a.base, [ix.assign(a.base.address, await fresh())]));
    await refusal(guarded.signTransactions(batch(good, bad)));
    assert.deepEqual(a.raw, []);
  });

  test("a transaction the signer does not have to sign: its signature would authorize nothing, so nothing is checked", async () => {
    const a = await agent();
    const payer = await generateKeyPairSigner();
    const w = world(() => LOW);
    const guarded = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC });
    const hash = blockhash(await fresh());
    const m = pipe(
      createTransactionMessage({ version: 0 }),
      (x) => setTransactionMessageFeePayer(payer.address, x),
      (x) => setTransactionMessageLifetimeUsingBlockhash({ blockhash: hash, lastValidBlockHeight: 1n }, x),
      (x) => appendTransactionMessageInstructions([ix.transfer(payer.address, a.base.address, 1n)], x),
    );
    // The guard lets it through; @solana/kit's own signer then refuses to sign for a non-signer.
    await assert.rejects(guarded.signTransactions(batch(compileTransaction(m))), /not a signer/);
    assert.deepEqual(a.raw, ["tx"]);
    assert.equal(w.seen.length, 0);
  });
});

describe("guardSolanaSigner: messages", () => {
  test("a transaction disguised as a message is refused; plain text signs without a check; Sign-In With Solana checks the site", async () => {
    const a = await agent();
    const w = world(() => LOW);
    const guarded = guardSolanaSigner(a.spy, { pinnedKeys: false, fetch: w.fetch, solanaRpcUrl: RPC });
    const tx = compileTransaction(await message(a.base, [ix.transfer(a.base.address, await fresh(), 10n ** 9n)]));
    const v = await refusal(guarded.signMessages([createSignableMessage(bytesOf(tx))]));
    assert.equal(v.code, "local_danger");
    assert.match(v.reasons[0] ?? "", /serialized Solana transaction/);
    assert.deepEqual(a.raw, []);

    await guarded.signMessages([createSignableMessage("hello from an agent")]);
    assert.equal(w.seen.length, 0);

    await guarded.signMessages([createSignableMessage(`app.example.com wants you to sign in with your Solana account:\n${a.base.address}\n\nNonce: 42`)]);
    assert.equal(w.seen.length, 1);
    assert.deepEqual([w.seen[0]?.wallet, w.seen[0]?.domain, w.seen[0]?.interaction?.type], [a.base.address, "app.example.com", "message_signature"]);
    assert.deepEqual(a.raw, ["message", "message"]);
  });
});
