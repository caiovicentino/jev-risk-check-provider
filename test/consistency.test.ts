// Facts copied across the Worker, the published packages and the docs must agree (audit mc-8):
// pay_to, versions and lockfiles, prices in every text a buyer reads, and the client's copies of
// the provider's address and chain rules.
import { test } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { X402CHECK_PAY_TO } from "../packages/client/src/guard.js";
import { buildAccepts, MAINNET_NETWORKS } from "../deploy/protected.js";
import { formatUsd, networkPrice, SIMULATION_PRICE, toMicro } from "../deploy/pricing.js";
import { CREDIT_CHECK_PRICE } from "../deploy/credits.js";
import { PROVIDER_VERSION } from "../src/provider.js";
import { landingPage } from "../src/landing.js";
import { parseSubject } from "../src/address.js";
import { normalizeChain } from "../src/chains.js";
import { parseSubject as clientParseSubject } from "../packages/client/src/subject.js";
import { toCaip2 } from "../packages/client/src/normalize.js";

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const json = (path: string) => JSON.parse(read(path)) as Record<string, any>;
const usd = (n: number) => formatUsd(toMicro(n));

test("pay_to: wrangler.toml, the Worker's defaults, the guard's trusted payees and the Bazaar probe agree", () => {
  const toml = read("deploy/wrangler.toml");
  const evm = /PAY_TO_EVM = "([^"]+)"/.exec(toml)?.[1] as string;
  const sol = /PAY_TO_SOL = "([^"]+)"/.exec(toml)?.[1] as string;
  assert.deepEqual([...X402CHECK_PAY_TO], [evm, sol]);
  for (const a of buildAccepts({})) assert.equal(a.payTo, a.network.startsWith("solana:") ? sol : evm, a.network);
  assert.ok(read("eval/bazaar.ts").includes(evm));
});

test("versions: PROVIDER_VERSION, every package.json, its lockfile, and the MCP server's server.json and VERSION", () => {
  const root = json("package.json");
  assert.equal(PROVIDER_VERSION, root.version);
  for (const dir of [".", "packages/client", "packages/mcp"]) {
    const pkg = json(`${dir}/package.json`);
    const lock = json(`${dir}/package-lock.json`);
    assert.deepEqual([lock.version, lock.packages[""].version], [pkg.version, pkg.version], `${dir}/package-lock.json`);
  }
  const mcp = json("packages/mcp/package.json");
  const server = json("packages/mcp/server.json");
  assert.equal(server.version, mcp.version);
  for (const p of server.packages as Array<{ version: string }>) assert.equal(p.version, mcp.version);
  assert.match(read("packages/mcp/src/version.ts"), new RegExp(`VERSION = "${mcp.version.replace(/\./g, "\\.")}"`));
  // In the repository the MCP server builds against the client next to it; publishing pins a range.
  assert.equal(mcp.dependencies["@x402check/client"], "file:../client");
});

const NETWORK_NAMES: Record<string, string> = { Base: "eip155:8453", Polygon: "eip155:137", Arbitrum: "eip155:42161", Avalanche: "eip155:43114", Monad: "eip155:143", Sei: "eip155:1329", Solana: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" };

test("prices a buyer reads (site, READMEs, MCP texts) are the ones deploy/pricing.ts charges", () => {
  const min = usd(Math.min(...MAINNET_NETWORKS.map(networkPrice)));
  const texts: Record<string, string> = {
    site: landingPage(),
    README: read("README.md"),
    "deploy/README": read("deploy/README.md"),
    "client README": read("packages/client/README.md"),
    "mcp README": read("packages/mcp/README.md"),
    "mcp server": read("packages/mcp/src/server.ts"),
    "mcp methodology": read("packages/mcp/src/methodology.ts"),
    "mcp --help": read("packages/mcp/src/index.ts"),
    "mcp render": read("packages/mcp/src/render.ts"),
    AGENTS: read("AGENTS.md"),
  };
  let seen = 0;
  for (const [name, raw] of Object.entries(texts)) {
    // Fees and margins quoted in the docs ("about $0.0023 on Base") are not prices.
    const text = raw.replace(/<\/?b>|\*\*/g, "").replace(/(?:about|fee of|margin of|costs us) \$\d+\.\d+ on [A-Z][a-z]+/g, "");
    for (const m of text.matchAll(/\$(\d+\.\d+) on ([A-Z][a-z]+)(?: and ([A-Z][a-z]+))?/g)) {
      for (const net of [m[2], m[3]].filter((n): n is string => !!n && n in NETWORK_NAMES)) {
        assert.equal(`$${m[1]}`, usd(networkPrice(NETWORK_NAMES[net] as string)), `${name}: "${m[0]}"`);
        seen++;
      }
    }
    for (const m of text.matchAll(/\b(Base|Polygon|Arbitrum|Avalanche|Monad|Sei|Solana) \$(\d+\.\d+)/g)) {
      assert.equal(`$${m[2]}`, usd(networkPrice(NETWORK_NAMES[m[1] as string] as string)), `${name}: "${m[0]}"`);
      seen++;
    }
    for (const m of text.matchAll(/per call (?:via|with) x402 from \$(\d+\.\d+)/g)) {
      assert.equal(`$${m[1]}`, min, `${name}: "${m[0]}" (the cheapest network)`);
      seen++;
    }
    for (const m of text.matchAll(/\$(\d+\.\d+) (?:a check|per evaluation)/g)) {
      assert.equal(`$${m[1]}`, usd(CREDIT_CHECK_PRICE), `${name}: "${m[0]}"`);
      seen++;
    }
    for (const m of text.matchAll(/\$(\d+\.\d+) (?:with simulation|when a transaction is simulated|with a transaction to simulate)/g)) {
      assert.equal(`$${m[1]}`, usd(SIMULATION_PRICE), `${name}: "${m[0]}"`);
      seen++;
    }
  }
  assert.ok(seen >= 20, `only ${seen} price statements found: the patterns no longer match the texts`);
});

test("the client parses addresses and chains as the provider does", () => {
  const subjects = [
    "0x1111111111111111111111111111111111111111",
    "0xbF88b1F49B5e8Ec386289341c4a5ee00bB0E0178",
    "0xBF88B1F49B5E8EC386289341C4A5EE00BB0E0178",
    "eip155:8453:0xbF88b1F49B5e8Ec386289341c4a5ee00bB0E0178",
    "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
    "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    "BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ",
    "bc1QAR0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW",
    "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
    "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
    "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
    "41a614f803b6fd780986a42c78ec9c7f77e6ded13c",
    "not an address",
    "",
    "0x123",
  ];
  for (const s of subjects) {
    const a = parseSubject(s);
    const b = clientParseSubject(s);
    assert.deepEqual(b && { canonical: b.canonical, caip2: b.caip2 }, a && { canonical: a.canonical, caip2: a.caip2 }, s);
  }
  const chains = ["base", "Base", "eip155:8453", "ethereum", "eip155:1", "polygon", "arbitrum", "optimism", "bsc", "avalanche", "sei", "monad", "solana", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "base-sepolia", "bitcoin", "tron", "foo", ""];
  for (const c of chains) assert.equal(toCaip2(c), normalizeChain(c)?.caip2 ?? null, c);
  // One deliberate difference: the client canonicalizes a zero-padded chain id before sending; the provider refuses it.
  assert.deepEqual([toCaip2("eip155:08453"), normalizeChain("eip155:08453")], ["eip155:8453", null]);
});
