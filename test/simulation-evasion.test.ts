// Regression tests for the 2026-09-30 audit finding pcore-1: a drainer could switch the
// simulation's drain rules off with a fake inflow (a Transfer event it emits itself), with dust
// of a real asset, or by padding the logs past the analysis cap.
import { test } from "node:test";
import assert from "node:assert";
import { comesBack, createSimulator, decodeLogs, MAX_LOGS, netMovements } from "../src/simulation.js";

const USER = "0x1111111111111111111111111111111111111111";
const DRAINER = "0x2222222222222222222222222222222222222222";
const HIDDEN = "0x3333333333333333333333333333333333333333";
const ROUTER = "0x4444444444444444444444444444444444444444";
const FAKE_TOKEN = "0x5555555555555555555555555555555555555555";
const SELLER = "0x6666666666666666666666666666666666666666";
const NFT = "0x7777777777777777777777777777777777777777";
const NATIVE = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const t = (a: string) => `0x${a.slice(2).padStart(64, "0")}`;
const amt = (n: bigint) => `0x${n.toString(16).padStart(64, "0")}`;
const transfer = (token: string, from: string, to: string, n: bigint) => ({ address: token, topics: [TRANSFER, t(from), t(to)], data: amt(n) });
const nft = (token: string, from: string, to: string, id: number) => ({ address: token, topics: [TRANSFER, t(from), t(to), t(`0x${id.toString(16)}`)], data: "0x" });
const ETH = 10n ** 18n;

/** Code: the drainer, the router, the tokens and the NFT are contracts; the rest are plain wallets. */
function rpcStub(logs: object[]) {
  const contracts = [DRAINER, ROUTER, FAKE_TOKEN, NFT, USDC, WETH];
  return (async (_url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    if (Array.isArray(body)) return new Response(JSON.stringify(body.map((b: { id: number; params: string[] }) => ({ id: b.id, result: contracts.includes(String(b.params[0])) ? "0x6080" : "0x" }))));
    return new Response(JSON.stringify({ result: [{ calls: [{ status: "0x1", logs }] }] }));
  }) as unknown as typeof fetch;
}

const run = async (logs: object[], to = DRAINER) => (await createSimulator({ fetchImpl: rpcStub(logs) })({ from: USER, to, value: "0x1bc16d674ec80000" }, "eip155:1", { declared: [{ address: to }] })).findings ?? [];

test("a fake Transfer the drainer emits itself does not count as something coming back", async () => {
  const drain = [transfer(NATIVE, USER, DRAINER, 2n * ETH), transfer(NATIVE, DRAINER, HIDDEN, 2n * ETH)];
  assert.ok((await run(drain)).includes("outflow_to_undisclosed_eoa"));
  const faked = [...drain, transfer(DRAINER, DRAINER, USER, 1000n)];
  assert.ok((await run(faked)).includes("outflow_to_undisclosed_eoa"), "the drainer's own token is not a return");
});

test("dust of a real asset coming back is still nothing", async () => {
  const dust = [transfer(NATIVE, USER, DRAINER, 2n * ETH), transfer(NATIVE, DRAINER, HIDDEN, 2n * ETH), transfer(USDC, ROUTER, USER, 1n)];
  assert.ok((await run(dust)).includes("outflow_to_undisclosed_eoa"));
});

test("a token of unknown value from a separate contract while a hidden wallet takes most of the value: review, not clear", async () => {
  const separate = [transfer(NATIVE, USER, DRAINER, 2n * ETH), transfer(NATIVE, DRAINER, HIDDEN, 2n * ETH), transfer(FAKE_TOKEN, FAKE_TOKEN, USER, 10n ** 21n)];
  const findings = await run(separate);
  assert.ok(findings.includes("undisclosed_recipient_unvalued_return"), findings.join(","));
  assert.ok(!findings.includes("outflow_to_undisclosed_eoa"));
});

test("real value coming back keeps swaps and purchases clean", async () => {
  // USDC -> WETH through a router (pools are contracts): value comes back.
  const swap = [transfer(USDC, USER, ROUTER, 1_000_000_000n), transfer(WETH, ROUTER, USER, 3n * 10n ** 17n)];
  assert.deepEqual(await run(swap, ROUTER), []);
  // An NFT bought from a named seller.
  const purchase = createSimulator({ fetchImpl: rpcStub([transfer(NATIVE, USER, ROUTER, ETH), transfer(NATIVE, ROUTER, SELLER, ETH), nft(NFT, SELLER, USER, 7)]) });
  assert.deepEqual((await purchase({ from: USER, to: ROUTER, value: "0xde0b6b3a7640000" }, "eip155:1", { declared: [{ address: ROUTER }, { address: SELLER }] })).findings, []);
});

test("logs padded past the cap hide the real transfer: simulation_truncated", async () => {
  const padding = Array.from({ length: MAX_LOGS + 1 }, () => ({ address: FAKE_TOKEN, topics: ["0x01"], data: "0x" }));
  const findings = await run([...padding, transfer(NATIVE, USER, DRAINER, ETH), transfer(NATIVE, DRAINER, HIDDEN, ETH)]);
  assert.ok(findings.includes("simulation_truncated"), findings.join(","));
});

test("comesBack: value, unvalued and nothing", () => {
  const flows = (logs: object[]) => netMovements(decodeLogs(logs as never).flows, USER);
  const a = flows([transfer(USDC, USER, ROUTER, 100_000_000n), transfer(WETH, ROUTER, USER, 10n ** 16n)]);
  assert.equal(comesBack(a.inflows, a.outflows, "eip155:1", ROUTER, a.beneficiaries), "value");
  const b = flows([transfer(USDC, USER, ROUTER, 100_000_000n), transfer(FAKE_TOKEN, ROUTER, USER, 5n)]);
  assert.equal(comesBack(b.inflows, b.outflows, "eip155:1", ROUTER, b.beneficiaries), "unvalued");
  const c = flows([transfer(USDC, USER, DRAINER, 100_000_000n), transfer(DRAINER, DRAINER, USER, 5n)]);
  assert.equal(comesBack(c.inflows, c.outflows, "eip155:1", DRAINER, c.beneficiaries), "nothing");
});
