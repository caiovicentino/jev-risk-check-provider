// Facts copied across the Worker, the published packages and the docs must agree (audit mc-8):
// pay_to, versions and lockfiles, prices in every text a buyer reads, and the client's copies of
// the provider's address and chain rules.
import { test } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { getDefaultAsset } from "@x402/evm";
import { X402_PERMIT2_PROXIES, X402CHECK_PAY_TO, X402CHECK_PAYMENT_ASSETS } from "../packages/client/src/guard.js";
import { NEVER_FLAG_EVM } from "../src/never-flag.js";
import { buildAccepts, MAINNET_NETWORKS, openApi } from "../deploy/protected.js";
import { llmsTxt } from "../deploy/discovery.js";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { ExactSvmScheme } from "@x402/svm/exact/server";
import { formatUsd, networkPrice, SIMULATION_PRICE, toMicro } from "../deploy/pricing.js";
import { CREDIT_CHECK_PRICE } from "../deploy/credits.js";
import { PROVIDER_VERSION } from "../src/provider.js";
import { landingPage } from "../src/landing.js";
import { parseSubject } from "../src/address.js";
import { normalizeChain } from "../src/chains.js";
import { parseSubject as clientParseSubject } from "../packages/client/src/subject.js";
import { toCaip2 } from "../packages/client/src/normalize.js";

/** A string as a literal inside a RegExp. */
const escapeRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

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

test("never-flag (src/never-flag.ts): our pay_to, x402's Permit2 proxies and the asset each EVM network is charged in", () => {
  const evm = /PAY_TO_EVM = "([^"]+)"/.exec(read("deploy/wrangler.toml"))?.[1] as string;
  assert.ok(NEVER_FLAG_EVM.has(evm.toLowerCase()), "pay_to");
  for (const proxy of X402_PERMIT2_PROXIES) assert.ok(NEVER_FLAG_EVM.has(proxy.toLowerCase()), proxy);
  for (const network of MAINNET_NETWORKS) if (network.startsWith("eip155:")) assert.ok(NEVER_FLAG_EVM.has(getDefaultAsset(network).asset.toLowerCase()), network);
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
  assert.match(read("packages/mcp/src/version.ts"), new RegExp(`VERSION = "${escapeRegExp(mcp.version)}"`));
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
    "llms.txt": llmsTxt(openApi({})),
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
    // A CAIP-10 chain must be able to hold its address.
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:0xbF88b1F49B5e8Ec386289341c4a5ee00bB0E0178",
    "eip155:1:9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
    "eip155:8453:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    "bip122:000000000019d6689c085ae165831e93:0xbF88b1F49B5e8Ec386289341c4a5ee00bB0E0178",
    "tron:0x2b6653dc:TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW",
    "bip122:000000000019d6689c085ae165831e93:1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
  ];
  for (const s of subjects) {
    const a = parseSubject(s);
    const b = clientParseSubject(s);
    assert.deepEqual(b && { canonical: b.canonical, caip2: b.caip2 }, a && { canonical: a.canonical, caip2: a.caip2 }, s);
  }
  const chains = ["base", "Base", "eip155:8453", "ethereum", "eip155:1", "polygon", "arbitrum", "optimism", "bsc", "avalanche", "sei", "monad", "solana", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", "base-sepolia", "bitcoin", "tron", "bip122:000000000019d6689c085ae165831e93", "tron:0x2b6653dc", "solana:mainnet", "foo:bar", "cosmos:cosmoshub-4", "eip155:0", "foo", ""];
  for (const c of chains) assert.equal(toCaip2(c), normalizeChain(c)?.caip2 ?? null, c);
  // Deliberate differences: the client canonicalizes a zero-padded chain id before sending (the
  // provider refuses it), and leaves checksums (EIP-55, base58check) to the provider, which refuses
  // a bad one with a 422 before any charge.
  assert.deepEqual([toCaip2("eip155:08453"), normalizeChain("eip155:08453")], ["eip155:8453", null]);
  const badChecksum = "0xBf88b1F49B5e8Ec386289341c4a5ee00bB0E0178";
  assert.deepEqual([clientParseSubject(badChecksum)?.canonical, parseSubject(badChecksum)], [badChecksum.toLowerCase(), null]);
});

test("docs agree with the code and with each other (audit docev-11)", async () => {
  const minor = PROVIDER_VERSION.split(".").slice(0, 2).join(".");
  // The evidence document and the MCP server's methodology text name the running API version.
  assert.match(read("docs/EVIDENCE.md").split("\n")[0] as string, new RegExp(`v${escapeRegExp(minor)}\\b`), "EVIDENCE.md's title names the current version");
  const { API_VERSION, METHODOLOGY } = await import("../packages/mcp/src/methodology.js");
  assert.equal(API_VERSION, minor, "packages/mcp/src/methodology.ts API_VERSION");
  assert.doesNotMatch(METHODOLOGY, /API v0\.[0-4]\b/);
  // Every MCP tool is listed where the README lists them.
  for (const tool of ["x402check_check", "x402check_pay", "x402check_verify_attestation", "x402check_methodology"]) {
    assert.ok(read("README.md").includes(`\`${tool}\``), `README.md lists ${tool}`);
    assert.ok(read("packages/mcp/README.md").includes(`\`${tool}\``), `packages/mcp/README.md lists ${tool}`);
  }
  // One figure for unlisted phishing domains caught without a feed: 0–4 of 60.
  for (const path of ["README.md", "docs/EVIDENCE.md", "docs/METHODOLOGY.md", "packages/mcp/README.md", "packages/mcp/src/methodology.ts"]) {
    assert.doesNotMatch(read(path), /0[–-]3 of 60|0[–-]3\/60/, `${path}: the unlisted-phishing figure is 0–4 of 60`);
  }
  // The client README documents the credit methods and the guard's key pinning.
  const client = read("packages/client/README.md");
  for (const name of ["buyCredits", "creditBalance", "creditToken", "pinnedKeys", "trustedPayeeMaxAmount"]) assert.ok(client.includes(name), `packages/client/README.md documents ${name}`);
});

test("the guard exempts payments to x402check only in the asset the challenge asks for, on every network", async () => {
  // The schemes price each offered network in its default asset: that is what the challenge asks for.
  const evm = new ExactEvmScheme() as unknown as { parsePrice(price: string, network: string): Promise<{ asset: string }> };
  const svm = new ExactSvmScheme() as unknown as { parsePrice(price: string, network: string): Promise<{ asset: string }> };
  const offered: Record<string, string> = {};
  for (const o of buildAccepts({})) {
    const network = String(o.network);
    offered[network] = (await (network.startsWith("solana:") ? svm : evm).parsePrice("$0.001", network)).asset;
  }
  assert.deepEqual(offered, X402CHECK_PAYMENT_ASSETS);
});
