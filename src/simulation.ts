// Transaction simulation (EVM): what will this transaction actually do to the
// sender's assets? Uses the standard `eth_simulateV1` JSON-RPC method with
// `traceTransfers` (native transfers appear as synthetic ERC-20-style logs from
// 0xeeee…eeee), then reduces every Transfer/Approval-style log to net flows.
//
// Output is evidence (asset movements, approvals granted, findings); the provider
// turns findings into deterministic caps. Failures degrade to "unavailable", and a
// result that could not be completed (unclassified recipients, truncated logs) says
// so with the `simulation_incomplete` finding: it is never read as clear.
import { endpointsFor, rpcWithFallback, RPC_ENDPOINTS, SIMULATION_ENDPOINTS } from "./rpc.js";
import type { ContractIntel } from "./contract-intel.js";
import { codeFacts, fingerprintsOf, isContractCode, resolveIndirection, verificationTarget, type CodeFacts } from "./code-fingerprint.js";

export type TransactionInput = { from: string; to?: string | undefined; value?: string | undefined; data?: string | undefined };

export type AssetMovement = {
  standard: "native" | "erc20" | "erc721" | "erc1155";
  asset: string;
  amount?: string;
  token_id?: string;
  counterparty: string;
  counterparty_is_contract?: boolean;
};

export type ApprovalGrant = {
  standard: "erc20" | "erc721" | "erc721-all" | "permit2";
  asset: string;
  spender: string;
  amount?: string;
  unlimited?: boolean;
  spender_is_contract?: boolean;
};

export type CodeMatch = { address: string; role: "called" | "recipient" | "spender"; sources: string[] };

export type SimulationEvidence = {
  status: "ok" | "reverted" | "unavailable" | "unsupported";
  network?: string;
  outflows?: AssetMovement[];
  inflows?: AssetMovement[];
  approvals?: ApprovalGrant[];
  findings?: string[];
  /** Contracts in the transaction whose logic code (or delegate/implementation code) matches a listed drainer's. */
  code_matches?: CodeMatch[];
  /** Whether any contract in scope (called, recipients, spenders) had fingerprintable logic code. */
  code_checked?: boolean;
  /** Source verification of the called contract, when it forwarded assets to an undisclosed wallet. */
  forwarder_verified?: boolean;
  /** Why the result is incomplete (`simulation_incomplete`): e.g. "unclassified", "logs_truncated". */
  limits?: string[];
  /**
   * The block whose state the transaction was simulated on (the chain head at the time; since
   * provider 0.6.1). eth_simulateV1 builds the simulated block on top of it.
   */
  at_block?: number;
};

/** The state block of an eth_simulateV1 result: the simulated block's parent. */
function stateBlockOf(number: unknown): number | undefined {
  if (typeof number !== "string" || !/^0x[0-9a-fA-F]{1,16}$/.test(number)) return undefined;
  const n = Number.parseInt(number, 16);
  return Number.isSafeInteger(n) && n >= 1 ? n - 1 : undefined;
}

/**
 * What the user knowingly intends to give: an address, optionally scoped to one asset
 * ("native" or a token address) and a maximum amount in base units. Flows beyond the
 * scope are not covered, so a named payee cannot receive a different asset, or more,
 * without a finding.
 */
export type Declared = {
  address: string;
  asset?: string | undefined;
  max?: string | undefined;
  /**
   * An intended payee (payment `pay_to`, an explicit transfer recipient). Assets a payee
   * receives are what the user meant to give, even when the payee is a contract (a Safe,
   * a smart wallet). A bare subject is named but not a payee: a contract subject that
   * keeps assets with nothing in return is still checked.
   */
  payee?: boolean | undefined;
};

export type SimulationContext = {
  declared: Declared[];
  /** Code-fingerprint lookup: the feeds that list this fingerprint (empty = none). */
  codeMatch?: ((fingerprint: string) => string[]) | undefined;
};

export type Simulator = (tx: TransactionInput, network: string | undefined, context: SimulationContext) => Promise<SimulationEvidence>;

/** Chains with a simulation endpoint (primary URL; fallbacks in src/rpc.ts). */
export const SIMULATION_RPC: Record<string, string> = Object.fromEntries(Object.entries(SIMULATION_ENDPOINTS).map(([network, urls]) => [network, urls[0] as string]));

// Bounds: a hostile contract can emit megabytes of logs inside the gas budget.
export const MAX_RESPONSE_BYTES = 4_000_000;
export const MAX_LOGS = 3_000;
export const MAX_FLOWS = 5_000;
/** Addresses classified per transaction (called contract, recipients, spenders), largest first. */
export const MAX_PROBE = 40;
const PROBE_BATCH = 10; // some public RPCs cap JSON-RPC batches at 10 calls
// A plausible sender balance (value + 0.1 ETH), not an implausible one a contract could test for.
const BALANCE_HEADROOM = 10n ** 17n;

const NATIVE = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

/** Assets whose value is known per network: [decimals, class]. Anything else is of unknown value. */
type ValueClass = "usd" | "eth" | "btc" | "other";
const VALUE_BOUNDS: Record<ValueClass, [number, number]> = { usd: [0.9, 1.1], eth: [100, 50_000], btc: [5_000, 1_000_000], other: [0.001, 10_000] };
const KNOWN_VALUE: Record<string, { native: ValueClass; tokens: Record<string, [number, ValueClass]> }> = {
  "eip155:1": {
    native: "eth",
    tokens: {
      "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": [18, "eth"], // WETH
      "0xae7ab96520de3a18e5e111b5eaab095312d7fe84": [18, "eth"], // stETH
      "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0": [18, "eth"], // wstETH
      "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": [6, "usd"], // USDC
      "0xdac17f958d2ee523a2206206994597c13d831ec7": [6, "usd"], // USDT
      "0x6b175474e89094c44da98b954eedeac495271d0f": [18, "usd"], // DAI
      "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": [8, "btc"], // WBTC
    },
  },
  "eip155:8453": {
    native: "eth",
    tokens: {
      "0x4200000000000000000000000000000000000006": [18, "eth"], // WETH
      "0x2ae3f1ec7f1f5012cfeab0185bfc7aa3cf0dec22": [18, "eth"], // cbETH
      "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": [6, "usd"], // USDC
      "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca": [6, "usd"], // USDbC
      "0x50c5725949a6f0c72e6c4a641f24049a917db0cb": [18, "usd"], // DAI
      "0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf": [8, "btc"], // cbBTC
    },
  },
  "eip155:137": {
    native: "other",
    tokens: {
      "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270": [18, "other"], // WPOL
      "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619": [18, "eth"], // WETH
      "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359": [6, "usd"], // USDC
      "0x2791bca1f2de4661ed88a30c99a7a9449aa84174": [6, "usd"], // USDC.e
      "0xc2132d05d31c914a87c6611c10748aeb04b58e8f": [6, "usd"], // USDT
    },
  },
  "eip155:42161": {
    native: "eth",
    tokens: {
      "0x82af49447d8a07e3bd95bd0d56f35241523fbab1": [18, "eth"], // WETH
      "0xaf88d065e77c8cc2239327c5edb3a432268e5831": [6, "usd"], // USDC
      "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8": [6, "usd"], // USDC.e
      "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9": [6, "usd"], // USDT
      "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1": [18, "usd"], // DAI
    },
  },
  "eip155:10": {
    native: "eth",
    tokens: {
      "0x4200000000000000000000000000000000000006": [18, "eth"], // WETH
      "0x0b2c639c533813f4aa9d7837caf62653d097ff85": [6, "usd"], // USDC
      "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58": [6, "usd"], // USDT
      "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1": [18, "usd"], // DAI
    },
  },
  "eip155:56": {
    native: "other",
    tokens: {
      "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": [18, "other"], // WBNB
      "0x55d398326f99059ff775485246999027b3197955": [18, "usd"], // USDT (18 decimals on BSC)
      "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": [18, "usd"], // USDC
      "0xe9e7cea3dedca5984780bafc599bd69add087d56": [18, "usd"], // BUSD
    },
  },
};
/** A hidden recipient taking at least this share of an asset the sender lost is a drain even when an unvalued token comes back. */
const MAJORITY_SHARE_NUM = 1n;
const MAJORITY_SHARE_DEN = 2n;
const ZERO = "0x0000000000000000000000000000000000000000";
const PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3";
const T = {
  transfer: "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
  approval: "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
  approvalForAll: "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31",
  transferSingle: "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62",
  transferBatch: "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb",
  permit2Approval: "0xda9fa7c1b00402c17d0161b249b1ab8bbec047c5a52207b9c112deffd817036b",
  permit2Permit: "0xc6a377bfc4eb120024a8ac08eef205be16b817020812c73223e81d1bdb9708ec",
  wethDeposit: "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c",
  wethWithdrawal: "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65",
};
const UNLIMITED_MIN = 2n ** 128n; // ≥ 2^128 is effectively unlimited for any real token supply

type Log = { address: string; topics: string[]; data: string };
type Flow = { standard: AssetMovement["standard"]; asset: string; token_id?: string; from: string; to: string; amount: bigint };

const HEX = /^[0-9a-fA-F]*$/;
const topicAddr = (t: string | undefined): string => `0x${(t ?? "").slice(-40)}`.toLowerCase();
const word = (data: string, i: number): bigint => {
  const hex = data.slice(2 + i * 64, 2 + (i + 1) * 64);
  return hex && HEX.test(hex) ? BigInt(`0x${hex}`) : 0n;
};

/** Decodes Transfer/Approval-family logs into raw flows and approval grants (at most `maxFlows` flows). Exported for tests. */
export function decodeLogs(logs: Log[], maxFlows = MAX_FLOWS): { flows: Flow[]; approvals: Array<ApprovalGrant & { owner: string }>; truncated: boolean } {
  const flows: Flow[] = [];
  const approvals: Array<ApprovalGrant & { owner: string }> = [];
  let truncated = false;
  const push = (f: Flow): boolean => {
    if (flows.length >= maxFlows) return !(truncated = true);
    flows.push(f);
    return true;
  };
  for (const l of logs) {
    if (!l || typeof l.address !== "string" || !Array.isArray(l.topics) || typeof l.data !== "string" || !l.topics.every((t) => typeof t === "string")) continue;
    const address = l.address.toLowerCase();
    const [t0, t1, t2, t3] = l.topics.map((t) => t.toLowerCase());
    if (t0 === T.transfer && l.topics.length === 3) {
      push({ standard: address === NATIVE ? "native" : "erc20", asset: address === NATIVE ? "native" : address, from: topicAddr(t1), to: topicAddr(t2), amount: word(l.data, 0) });
    } else if (t0 === T.transfer && l.topics.length === 4) {
      push({ standard: "erc721", asset: address, token_id: HEX.test((t3 as string).slice(2)) ? BigInt(t3 as string).toString() : "0", from: topicAddr(t1), to: topicAddr(t2), amount: 1n });
    } else if (t0 === T.transferSingle) {
      push({ standard: "erc1155", asset: address, token_id: word(l.data, 0).toString(), from: topicAddr(t2), to: topicAddr(t3), amount: word(l.data, 1) });
    } else if (t0 === T.transferBatch) {
      const words = Math.floor((l.data.length - 2) / 64);
      const idsOff = Number(word(l.data, 0) / 32n);
      const valsOff = Number(word(l.data, 1) / 32n);
      const n = Number(word(l.data, idsOff));
      // Every entry the data actually contains, under the global flow cap.
      const count = Math.max(0, Math.min(n, words - idsOff - 1, words - valsOff - 1));
      for (let i = 0; i < count; i++) {
        if (!push({ standard: "erc1155", asset: address, token_id: word(l.data, idsOff + 1 + i).toString(), from: topicAddr(t2), to: topicAddr(t3), amount: word(l.data, valsOff + 1 + i) })) break;
      }
      if (n > count) truncated = true;
    } else if (t0 === T.wethDeposit && l.topics.length === 2) {
      push({ standard: "erc20", asset: address, from: address, to: topicAddr(t1), amount: word(l.data, 0) });
    } else if (t0 === T.wethWithdrawal && l.topics.length === 2) {
      push({ standard: "erc20", asset: address, from: topicAddr(t1), to: address, amount: word(l.data, 0) });
    } else if (t0 === T.approval && l.topics.length === 3) {
      const amount = word(l.data, 0);
      if (amount > 0n) approvals.push({ standard: "erc20", asset: address, owner: topicAddr(t1), spender: topicAddr(t2), amount: amount.toString(), unlimited: amount >= UNLIMITED_MIN });
    } else if (t0 === T.approval && l.topics.length === 4) {
      const spender = topicAddr(t2);
      if (spender !== ZERO) approvals.push({ standard: "erc721", asset: address, owner: topicAddr(t1), spender, amount: HEX.test((t3 as string).slice(2)) ? BigInt(t3 as string).toString() : "0" });
    } else if (t0 === T.approvalForAll && l.topics.length === 3) {
      if (word(l.data, 0) !== 0n) approvals.push({ standard: "erc721-all", asset: address, owner: topicAddr(t1), spender: topicAddr(t2), unlimited: true });
    } else if ((t0 === T.permit2Approval || t0 === T.permit2Permit) && address === PERMIT2 && l.topics.length === 4) {
      const amount = word(l.data, 0);
      if (amount > 0n) approvals.push({ standard: "permit2", asset: topicAddr(t2), owner: topicAddr(t1), spender: topicAddr(t3), amount: amount.toString(), unlimited: amount >= 2n ** 159n });
    }
  }
  return { flows, approvals, truncated };
}

type Movements = { outflows: Flow[]; inflows: Flow[]; beneficiaries: Map<string, Flow[]> };

/**
 * Net flows relative to the sender, in linear time. Beneficiaries are addresses
 * (other than the sender) that end up with a net gain of an asset the sender lost —
 * so assets routed through the called contract and forwarded elsewhere are attributed
 * to their final recipient.
 */
export function netMovements(flows: Flow[], sender: string): Movements {
  const net = new Map<string, { sample: Flow; deltas: Map<string, bigint> }>(); // asset key -> address -> delta
  for (const f of flows) {
    const k = `${f.asset}|${f.token_id ?? ""}`;
    let entry = net.get(k);
    if (!entry) net.set(k, (entry = { sample: f, deltas: new Map() }));
    entry.deltas.set(f.from, (entry.deltas.get(f.from) ?? 0n) - f.amount);
    entry.deltas.set(f.to, (entry.deltas.get(f.to) ?? 0n) + f.amount);
  }
  const outflows: Flow[] = [];
  const inflows: Flow[] = [];
  const beneficiaries = new Map<string, Flow[]>();
  for (const { sample, deltas } of net.values()) {
    const mine = deltas.get(sender) ?? 0n;
    if (mine === 0n) continue;
    if (mine > 0n) {
      inflows.push({ ...sample, from: "", to: sender, amount: mine });
      continue;
    }
    outflows.push({ ...sample, from: sender, to: "", amount: -mine });
    for (const [addr, d] of deltas) {
      if (addr === sender || d <= 0n || addr === ZERO) continue;
      const list = beneficiaries.get(addr) ?? [];
      list.push({ ...sample, from: sender, to: addr, amount: d });
      beneficiaries.set(addr, list);
    }
  }
  return { outflows, inflows, beneficiaries };
}

/** USD bounds [min, max] of an amount of a known-value asset on a network, or null (unknown value). */
function usdBounds(asset: string, amount: bigint, network: string | undefined): [number, number] | null {
  const known = network ? KNOWN_VALUE[network] : undefined;
  if (!known) return null;
  const entry: [number, ValueClass] | undefined = asset === "native" ? [18, known.native] : known.tokens[asset];
  if (!entry) return null;
  const units = Number(amount) / 10 ** entry[0];
  const [lo, hi] = VALUE_BOUNDS[entry[1]];
  return [units * lo, units * hi];
}

/**
 * What comes back to the sender: "value" (a known-value asset worth at least 1% of the
 * known-value assets it lost), "unvalued" (only tokens or NFTs of unknown value), or "nothing"
 * (no inflow, dust, or tokens emitted by the called contract or a recipient itself).
 */
export function comesBack(inflows: Flow[], outflows: Flow[], network: string | undefined, to: string | undefined, beneficiaries: Map<string, Flow[]>): "value" | "unvalued" | "nothing" {
  const real = inflows.filter((f) => f.asset === "native" || (f.asset !== to && !beneficiaries.has(f.asset)));
  if (real.length === 0) return "nothing";
  const valued = real.map((f) => usdBounds(f.asset, f.amount, network)).filter((b): b is [number, number] => b !== null);
  const lost = outflows.map((f) => usdBounds(f.asset, f.amount, network)).filter((b): b is [number, number] => b !== null);
  if (valued.length > 0) {
    const outMin = lost.reduce((sum, [lo]) => sum + lo, 0);
    const inMax = valued.reduce((sum, [, hi]) => sum + hi, 0);
    if (lost.length === 0 || inMax >= outMin * 0.01) return "value";
  }
  return real.length > valued.length ? "unvalued" : "nothing";
}

/**
 * Recipients that are explicit arguments of the top-level call (the wallet shows
 * them to the user): ERC-20 transfer/transferFrom, ERC-721/1155 safeTransferFrom,
 * with the amount when the standard carries one. They are declared only for the
 * called token itself, so an ordinary token transfer is not a "hidden" outflow, while
 * a contract that merely borrows the `transfer` selector gains nothing.
 */
export function explicitTransfers(data: string | undefined): Array<{ recipient: string; amount?: bigint }> {
  if (!data || data.length < 10) return [];
  const sel = data.slice(0, 10).toLowerCase();
  const arg = (i: number): string | null => {
    const hex = data.slice(10 + i * 64, 10 + (i + 1) * 64);
    return hex.length === 64 && HEX.test(hex) ? hex : null;
  };
  const addr = (i: number) => {
    const hex = arg(i);
    return hex ? `0x${hex.slice(24)}`.toLowerCase() : null;
  };
  const amount = (i: number) => {
    const hex = arg(i);
    return hex ? BigInt(`0x${hex}`) : undefined;
  };
  const one = (to: string | null, value?: bigint) => (to ? [{ recipient: to, ...(value !== undefined ? { amount: value } : {}) }] : []);
  if (sel === "0xa9059cbb") return one(addr(0), amount(1)); // transfer(to, amount)
  if (sel === "0x23b872dd") return one(addr(1), amount(2)); // transferFrom(from, to, amount|tokenId)
  if (sel === "0x42842e0e" || sel === "0xb88d4fde" || sel === "0xf242432a" || sel === "0x2eb2c2d6") return one(addr(1)); // NFT / 1155 transfers
  return [];
}

/** Back-compat helper: the explicit recipients only. */
export function explicitRecipients(data: string | undefined): string[] {
  return explicitTransfers(data).map((t) => t.recipient);
}

const normAsset = (asset: string | undefined): string | undefined => {
  if (!asset) return undefined;
  const a = asset.toLowerCase();
  return a === "native" || a === NATIVE || a === ZERO ? "native" : a;
};

/** The declared scope for one beneficiary: never named (hidden), or whether every flow is within what was named. */
function coverage(address: string, flows: Flow[], declared: Declared[]): "hidden" | "covered" | "exceeds" {
  const all = declared.filter((d) => d.address === address);
  if (!all.length) return "hidden";
  // A payee scope (payment, explicit transfer in the calldata) is more specific than the
  // bare naming of the subject: when one exists, it alone decides what the address may get.
  const payee = all.filter((d) => d.payee === true);
  const mine = payee.length ? payee : all;
  const totals = new Map<string, { total: bigint; nft: boolean }>();
  for (const f of flows) {
    const t = totals.get(f.asset) ?? { total: 0n, nft: false };
    totals.set(f.asset, { total: t.total + f.amount, nft: t.nft || f.standard === "erc721" });
  }
  for (const [asset, { total, nft }] of totals) {
    const ok = mine.some((d) => {
      if (d.asset !== undefined && normAsset(d.asset) !== asset) return false;
      // An ERC-721 call's third argument is a token id, not an amount.
      if (d.max === undefined || nft) return true;
      try {
        return total <= BigInt(d.max);
      } catch {
        return false;
      }
    });
    if (!ok) return "exceeds";
  }
  return "covered";
}

async function readCapped(res: Response, maxBytes: number): Promise<string> {
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared > maxBytes) throw new Error("rpc response too large");
  if (!res.body) return res.text();
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel();
      throw new Error("rpc response too large");
    }
    chunks.push(value);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.byteLength;
  }
  return new TextDecoder().decode(out);
}

export function createSimulator(opts: { rpc?: Record<string, string>; timeoutMs?: number; fetchImpl?: typeof fetch; contractIntel?: ContractIntel | null } = {}): Simulator {
  const timeoutMs = opts.timeoutMs ?? 2500;
  const rawFetch = opts.fetchImpl ?? ((input: string | URL | Request, init?: RequestInit) => fetch(input, init));
  // Every RPC answer is read under a byte cap before it is parsed.
  const doFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const res = await rawFetch(input, init);
    const text = await readCapped(res, MAX_RESPONSE_BYTES);
    return new Response(text, { status: res.status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;

  // Code of the called contract, recipients and spenders (plus one level of 7702/proxy
  // indirection): contract vs plain wallet, and fingerprints for drainer-kit matching.
  const probeCode = async (addresses: string[], network: string): Promise<Map<string, CodeFacts>> => {
    const out = new Map<string, CodeFacts>();
    const urls = endpointsFor(network, RPC_ENDPOINTS);
    if (urls.length === 0 || addresses.length === 0) return out;
    const budget = Math.min(timeoutMs, 1500);
    const call = async (requests: Array<{ method: string; params: unknown[] }>): Promise<unknown[]> => {
      const results: unknown[] = [];
      for (let i = 0; i < requests.length; i += PROBE_BATCH) {
        const chunk = requests.slice(i, i + PROBE_BATCH);
        const batch = chunk.map((r, k) => ({ jsonrpc: "2.0", id: k + 1, ...r }));
        const complete = (json: unknown) => Array.isArray(json) && json.length === chunk.length && json.every((r: { result?: unknown }) => typeof r?.result === "string");
        const res = (await rpcWithFallback(urls, batch, budget, doFetch, complete)) as Array<{ id: number; result: string }>;
        const byId = new Map(res.map((r) => [r.id, r.result]));
        chunk.forEach((_, k) => results.push(byId.get(k + 1)));
      }
      return results;
    };
    const codes = await Promise.all(
      Array.from({ length: Math.ceil(addresses.length / PROBE_BATCH) }, (_, b) => addresses.slice(b * PROBE_BATCH, (b + 1) * PROBE_BATCH)).map((chunk) =>
        call(chunk.map((a) => ({ method: "eth_getCode", params: [a, "latest"] }))).then(
          (r) => r.map((c, i) => [chunk[i] as string, c] as const),
          () => [] as Array<readonly [string, unknown]>,
        ),
      ),
    );
    for (const [a, c] of codes.flat()) if (typeof c === "string") out.set(a, codeFacts(c));
    await resolveIndirection(out, call).catch(() => undefined);
    return out;
  };

  const matchCodes = (facts: Map<string, CodeFacts>, roles: Map<string, CodeMatch["role"]>, context: SimulationContext): { matches: CodeMatch[]; checked: boolean } => {
    const matches: CodeMatch[] = [];
    let checked = false;
    for (const [address, f] of facts) {
      const fps = fingerprintsOf(f);
      if (!fps.length) continue;
      checked = true;
      const sources = [...new Set(fps.flatMap((fp) => context.codeMatch?.(fp) ?? []))];
      if (sources.length) matches.push({ address, role: roles.get(address) ?? "recipient", sources });
    }
    return { matches, checked };
  };

  return async (tx, network, context) => {
    if (!network || !network.startsWith("eip155:")) return { status: "unsupported", ...(network ? { network } : {}) };
    const urls = endpointsFor(network, SIMULATION_ENDPOINTS, opts.rpc);
    if (urls.length === 0) return { status: "unsupported", network };
    const from = tx.from.toLowerCase();
    const to = tx.to?.toLowerCase();
    const value = tx.value ? BigInt(tx.value) : 0n;
    const call = {
      from,
      ...(to ? { to } : {}),
      ...(value > 0n ? { value: `0x${value.toString(16)}` } : {}),
      ...(tx.data && tx.data !== "0x" ? { input: tx.data } : {}),
      gas: "0x1c9c380",
    };
    let result: { number?: string; calls?: Array<{ status?: string; logs?: Log[] }> } | undefined;
    try {
      const body = {
        jsonrpc: "2.0",
        id: 1,
        method: "eth_simulateV1",
        // Balance override: the question is what the transaction does, not whether the
        // sender can currently afford it.
        params: [{ blockStateCalls: [{ stateOverrides: { [from]: { balance: `0x${(value + BALANCE_HEADROOM).toString(16)}` } }, calls: [call] }], traceTransfers: true, validation: false }, "latest"],
      };
      const res = (await rpcWithFallback(urls, body, timeoutMs, doFetch, (json) => Array.isArray((json as { result?: unknown }).result))) as { result?: Array<{ number?: string; calls?: Array<{ status?: string; logs?: Log[] }> }>; error?: unknown };
      if (res.error || !Array.isArray(res.result)) return { status: "unavailable", network };
      result = res.result[0];
    } catch {
      return { status: "unavailable", network };
    }
    const c = result?.calls?.[0];
    if (!c) return { status: "unavailable", network };
    const atBlock = stateBlockOf(result?.number);
    const anchor = atBlock !== undefined ? { at_block: atBlock } : {};
    if (c.status !== "0x1") {
      // Still worth knowing whether the called contract is a known drainer kit.
      let codes = new Map<string, CodeFacts>();
      if (to && context.codeMatch) codes = await probeCode([to], network).catch(() => new Map<string, CodeFacts>());
      const { matches, checked } = matchCodes(codes, new Map(to ? [[to, "called" as const]] : []), context);
      return {
        status: "reverted",
        network,
        findings: ["simulation_reverted", ...(matches.length ? ["known_drainer_code"] : [])],
        ...(matches.length ? { code_matches: matches } : {}),
        ...(context.codeMatch ? { code_checked: checked } : {}),
        ...anchor,
      };
    }

    const limits: string[] = [];
    let logs = Array.isArray(c.logs) ? c.logs : [];
    if (logs.length > MAX_LOGS) {
      logs = logs.slice(0, MAX_LOGS);
      limits.push("logs_truncated");
    }
    const { flows, approvals, truncated } = decodeLogs(logs);
    if (truncated) limits.push("flows_truncated");
    // Padding the logs (or the flows) past the cap pushes the real transfer out of view: never read as a warn only.
    const truncatedView = limits.includes("logs_truncated") || limits.includes("flows_truncated");
    const mine = approvals.filter((a) => a.owner === from);
    const { outflows, inflows, beneficiaries } = netMovements(flows, from);

    // Declared scope: what the caller named (subject, payee with asset and amount) and
    // explicit transfer recipients for the called token. For wallets (not for contracts
    // that keep funds), the native value sent to `to` is named by the transaction itself.
    const declared: Declared[] = [
      // Library callers may still pass bare addresses (the pre-0.3 shape).
      ...context.declared.map((d) => (typeof d === "string" ? { address: (d as string).toLowerCase() } : { ...d, address: d.address.toLowerCase() })),
      ...(to ? explicitTransfers(tx.data).map((t) => ({ address: t.recipient, asset: to, payee: true, ...(t.amount !== undefined ? { max: t.amount.toString() } : {}) })) : []),
      ...(to ? [{ address: to, asset: "native", max: value.toString() }] : []),
    ];
    const payees = declared.filter((d) => d.payee === true);

    // Classify every recipient and spender (largest amount first), plus the called contract.
    const roles = new Map<string, CodeMatch["role"]>();
    for (const a of mine) roles.set(a.spender, "spender");
    for (const b of beneficiaries.keys()) roles.set(b, "recipient");
    if (to) roles.set(to, "called");
    const byAmount = [...beneficiaries.entries()].sort((x, y) => {
      const sx = x[1].reduce((s, f) => s + f.amount, 0n);
      const sy = y[1].reduce((s, f) => s + f.amount, 0n);
      return sx > sy ? -1 : sx < sy ? 1 : 0;
    });
    const wanted = [...new Set([...(to ? [to] : []), ...mine.map((a) => a.spender), ...byAmount.map(([a]) => a)])];
    const probe = wanted.slice(0, MAX_PROBE);
    let facts = new Map<string, CodeFacts>();
    try {
      facts = await probeCode(probe, network);
    } catch {
      facts = new Map();
    }
    const unclassified = wanted.filter((a) => !facts.has(a) && (beneficiaries.has(a) || mine.some((g) => g.spender === a)));
    if (unclassified.length) limits.push("unclassified");
    const isEoa = (a: string) => facts.has(a) && !isContractCode(facts.get(a) as CodeFacts);
    const isContract = (a: string) => facts.has(a) && isContractCode(facts.get(a) as CodeFacts);
    const { matches, checked } = matchCodes(facts, roles, context);

    const findings: string[] = [];
    const scopes = new Map([...beneficiaries.entries()].map(([a, fl]) => [a, coverage(a, fl, declared)] as const));
    const back = comesBack(inflows, outflows, network, to, beneficiaries);
    // Hidden recipient: assets leave the sender, nothing of value comes back, and a plain wallet
    // the sender never named ends up with them (drainer "claim"/"verify" pattern, including
    // value forwarded through the called contract). A token the called contract or a recipient
    // emits itself, or dust of a known asset, is not something coming back.
    const hiddenEoa = [...beneficiaries.keys()].filter((a) => isEoa(a) && scopes.get(a) === "hidden");
    if (outflows.length > 0 && back === "nothing" && hiddenEoa.length > 0) findings.push("outflow_to_undisclosed_eoa");
    // Only a token of unknown value comes back while a hidden wallet takes most of an asset: review.
    const majority = hiddenEoa.some((a) =>
      (beneficiaries.get(a) ?? []).some((f) => {
        const lost = outflows.find((o) => o.asset === f.asset && (o.token_id ?? "") === (f.token_id ?? ""));
        return lost !== undefined && f.amount * MAJORITY_SHARE_DEN >= lost.amount * MAJORITY_SHARE_NUM;
      }),
    );
    if (outflows.length > 0 && back === "unvalued" && majority) findings.push("undisclosed_recipient_unvalued_return");
    // A payee (payment, explicit transfer) receives a different asset than declared, or more.
    // Judged against payee scopes only: the native value sent to a router is not a payment.
    if ([...beneficiaries.entries()].some(([a, fl]) => coverage(a, fl, payees) === "exceeds")) findings.push("outflow_exceeds_declared");
    let forwarderVerified: boolean | undefined;
    if (findings.includes("outflow_to_undisclosed_eoa") && to && isContract(to) && opts.contractIntel) {
      forwarderVerified = (await opts.contractIntel(verificationTarget(to, facts.get(to)), network).catch(() => ({}) as { verified?: boolean })).verified;
    }
    // Assets parked with nothing in return in a contract (or a delegated account) the user
    // did not name: legitimate sinks (bridges, pools, WETH, staking) are source-verified;
    // drainer contracts that hold stolen funds for later withdrawal usually are not.
    if (outflows.length > 0 && back === "nothing" && hiddenEoa.length === 0 && opts.contractIntel) {
      const sinks = byAmount
        .map(([a]) => a)
        .filter((a) => coverage(a, beneficiaries.get(a) as Flow[], payees) !== "covered" && (isContract(a) || facts.get(a)?.kind === "delegated"))
        .slice(0, 3);
      // A delegated account or an exact forwarding proxy (Safe, EIP-1167, minimal EIP-1967)
      // is judged by the code it runs: fresh Safes are unverified on explorers, their singleton is not.
      const intel = await Promise.all(
        sinks.map(async (a) => {
          const own = await (opts.contractIntel as ContractIntel)(verificationTarget(a, facts.get(a)), network).catch(() => ({ unavailable: true }) as { verified?: boolean; unavailable?: boolean });
          if (own.verified !== false || verificationTarget(a, facts.get(a)) === a) return own;
          return (opts.contractIntel as ContractIntel)(a, network).catch(() => ({ unavailable: true }) as { verified?: boolean; unavailable?: boolean });
        }),
      );
      if (intel.some((r) => r.verified === false)) findings.push("outflow_to_unverified_contract");
      // A sink whose verification could not be read is unknown: the result is incomplete, not clear.
      else if (intel.some((r) => (r as { unavailable?: boolean }).unavailable === true)) limits.push("verification_unavailable");
    }
    if (mine.some((a) => isEoa(a.spender))) findings.push("approval_to_eoa");
    if (mine.some((a) => a.unlimited)) findings.push("unlimited_approval");
    if (matches.length) findings.push("known_drainer_code");
    if (limits.length) findings.push("simulation_incomplete");
    if (truncatedView) findings.push("simulation_truncated");

    const movement = (f: Flow, counterparty: string): AssetMovement => ({
      standard: f.standard,
      asset: f.asset,
      ...(f.standard === "erc721" ? {} : { amount: f.amount.toString() }),
      ...(f.token_id !== undefined ? { token_id: f.token_id } : {}),
      counterparty,
      ...(facts.has(counterparty) ? { counterparty_is_contract: isContract(counterparty) } : {}),
    });
    return {
      status: "ok",
      network,
      outflows: byAmount.flatMap(([addr, fl]) => fl.map((f) => movement(f, addr))).slice(0, 20),
      inflows: inflows.map((f) => movement(f, to ?? "")).slice(0, 20),
      approvals: mine.slice(0, 20).map(({ owner: _o, ...a }) => ({ ...a, ...(facts.has(a.spender) ? { spender_is_contract: isContract(a.spender) } : {}) })),
      findings,
      ...(matches.length ? { code_matches: matches } : {}),
      ...(context.codeMatch ? { code_checked: checked } : {}),
      ...(forwarderVerified !== undefined ? { forwarder_verified: forwarderVerified } : {}),
      ...(limits.length ? { limits } : {}),
      ...anchor,
    };
  };
}
