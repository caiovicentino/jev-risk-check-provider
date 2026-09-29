# x402check — pre-payment risk checks for x402 agents and wallets

**LIVE**: [https://x402check.xyz](https://x402check.xyz) · `did:web:x402check.xyz` · $0.001 per evaluation, paid with x402 · [discovery](https://x402check.xyz/.well-known/risk-check.json) · [DID document](https://x402check.xyz/.well-known/did.json) · [JWKS](https://x402check.xyz/.well-known/jwks.json)

x402check is an x402 `risk-check` provider (wire format of [x402 PR #2422](https://github.com/x402-foundation/x402/pull/2422)). You call it before an agent or a wallet pays or signs, and it checks the counterparty. It combines provider-verified evidence with a typed model:

- the **OFAC SDN** list, refreshed daily;
- curated **phishing and drainer feeds**;
- **transaction simulation**: where the assets actually go, and which approvals are granted;
- **drainer-kit code fingerprints**, which recognize redeployed drainer contracts before their address is listed;
- **look-alike domain** analysis;
- **on-chain facts** about the counterparty, such as whether an approval is being granted to a plain wallet;
- a typed model (TypeSafe **Jev**) that reads the content the agent acted on for **injected instructions**.

Every verdict is an **ES256 attestation**. It states which checks the provider actually ran and which fields the caller merely asserted.

> **Scope, stated plainly.** x402check catches what the chain, the lists, and the content in front of it reveal. It does **not** see laundering patterns or other transaction-graph behaviour, and it cannot flag an unknown drainer address that is simply sent funds. A clean verdict means "none of these checks fired", not "safe". Measured limits are in [docs/EVIDENCE.md](docs/EVIDENCE.md).

[![x402check demo](https://i.ytimg.com/vi/MCOWk7nh5r8/hqdefault.jpg)](https://youtu.be/MCOWk7nh5r8)

<sub>The demo video predates v0.2.0: its evidence slide shows v5 corpus numbers that [EVIDENCE.md](docs/EVIDENCE.md) supersedes.</sub>

## What it checks

| Check | Source | Effect on the verdict |
|---|---|---|
| Sanctioned address | Official OFAC SDN XML: 1,056 digital-currency addresses, dated snapshot | score **0 / critical**, deterministic, no model call |
| Known phishing domain | MetaMask eth-phishing-detect (~100k hosts, embedded) | capped at **20** (critical) |
| Known drainer / scam address | ScamSniffer (EVM, runtime KV, 7-day publication lag) | capped at **20** |
| Community-flagged domain | ScamSniffer domain list | capped at **40** only when our own domain analysis corroborates it |
| Look-alike domain | public-suffix aware: leet, IDN homoglyphs, typosquats, brand + lure word, official domain reused as a subdomain | "strong" impersonation → capped at **40** |
| Approval granted to a plain wallet | on-chain `eth_getCode` / activity (EVM), account data (Solana) | permits and approvals to an EOA → capped at **55**; **40** if the address has no activity |
| Hidden recipient | simulation of `transaction` (`eth_simulateV1` + `traceTransfers`) | assets leave, nothing comes back, and a wallet the user never named ends up with them → **40** (**75**, review, when a source-verified contract such as a bridge forwarded them) |
| Payee gets more than declared | simulation + `payment` / the explicit transfer in the calldata | the named payee receives a different asset, or more, than declared → **40** |
| Assets parked in an unverified contract | simulation + Blockscout source verification | nothing in return, contract source not verified → **55** |
| Drainer-kit code | logic-code fingerprints of contracts listed by Forta (embedded) and ScamSniffer (runtime) | the subject, or a contract in the simulated transaction, runs a listed drainer's code → **30** |
| Unverified spender | Blockscout source verification | approval or permit to an unverified contract → **75** and at least `medium` (review) |
| Injected / manipulated intent | Jev typed questions over `context` (what the agent acted on) | model penalties and caps |
| New address | on-chain activity | informational `new_address` category |

Caller-supplied `screening` and `authorization` fields are recorded as `asserted` in the attestation and **can never lower the score**. Prose claims such as "already screened" are unverified by construction.

## Quickstart

```bash
curl -X POST https://x402check.xyz/v1/risk-check \
  -H "Content-Type: application/json" \
  -d '{
    "wallet": "0x7a3e8f0c2b1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f",
    "chain": "eip155:1",
    "domain": "https://app.example-dapp.org",
    "context": "Permit2 signature: unlimited USDC allowance to this spender",
    "interaction": { "type": "permit_signature", "unlimited": true },
    "payment": { "network": "eip155:1", "asset": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "pay_to": "0x7a3e8f0c2b1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f" }
  }'
```

```json
{
  "checked": true,
  "score": 40,
  "tier": "high",
  "categories": ["intent_risk", "behavioral", "approval_to_eoa", "new_address"],
  "provider": "did:web:x402check.xyz",
  "evidence": {
    "sanctions": { "list": "ofac-sdn", "as_of": "2026-09-23", "status": "not_listed" },
    "domain": { "host": "app.example-dapp.org", "registrable": "example-dapp.org", "official": false, "impersonation": "none", "signals": [] },
    "onchain": { "status": "ok", "network": "eip155:1", "is_contract": false, "activity": "none", "tx_count": 0 },
    "feeds": [{ "source": "metamask-phishing-detect", "kind": "domain", "as_of": "2026-09-29", "status": "clear" }, "…"],
    "model": "jev-wallet-risk/v6"
  },
  "jws": "eyJhbGciOiJFUzI1NiIsInR5cCI6InJpc2stY2hlY2srand0Ii…",
  "jwks_url": "https://x402check.xyz/.well-known/jwks.json",
  "checked_at": "…", "expires_at": "…"
}
```

To also check **what a transaction will do**, send it as `transaction`. The provider simulates it against the latest block and reports the net asset movements, the approvals granted, and any findings:

```bash
curl -X POST https://x402check.xyz/v1/risk-check -H "Content-Type: application/json" -d '{
  "wallet": "0x…called contract or decoded counterparty…", "chain": "eip155:1",
  "transaction": { "from": "0x…user…", "to": "0x…contract…", "value": "0x2386f26fc10000", "data": "0x…" }
}'
# evidence.simulation → { "status": "ok", "outflows": [{ "standard": "native", "amount": "10000000000000000",
#   "counterparty": "0x…", "counterparty_is_contract": false }], "inflows": [], "approvals": [],
#   "findings": ["outflow_to_undisclosed_eoa"] }   → score capped at 40
```

## Request fields

| Field | Required | Rules |
|---|---|---|
| `wallet` | yes | the subject address: EVM `0x…`, base58 (Solana/Tron/BTC…), bech32, cashaddr, or CAIP-10. Anything else → `422 {error, field:"wallet"}` |
| `chain` | no | alias (`ethereum`, `base`, `solana`, …) or CAIP-2 (`eip155:8453`); enables on-chain facts on supported mainnets |
| `domain` | no | hostname or http(s) URL (normalized server-side); the site the payment or signature is for |
| `context` | no | ≤ 4096 chars: what the agent acted on (tool output, page text, instruction). Untrusted by design |
| `interaction` | no | `{type, unlimited?}`; `type` ∈ `native_transfer`, `token_transfer`, `token_approval`, `nft_approval`, `permit_signature`, `order_signature`, `message_signature`, `contract_call` |
| `payment` | no | binds the attestation to a payment: `{network, pay_to, amount (base units), asset, resource}` |
| `aud` | no | ≤ 256 chars; copied into the attestation, never shown to the model |
| `transaction` | no | EVM `{from, to?, value?, data?}` to simulate; needs an `eip155` chain. `value` is decimal or 0x-hex; `data` is 0x-hex, ≤ 49,152 chars. Simulated on Ethereum, Base, Polygon, Arbitrum, Optimism and BSC |
| `screening`, `authorization` | no | caller assertions, recorded as `asserted` (can only raise risk) |

Batch: `POST /v1/risk-check/batch` with `{"requests": [...]}` (≤ 25). It is all-or-nothing: an invalid item returns `422` with its `index`.

## Attestation

A compact JWS (`alg: ES256`, `typ: risk-check+jwt`, `kid: jev-attest-v1`), TTL 1 h. Claims:

| Claim | Meaning |
|---|---|
| `iss`, `sub`, `iat`, `exp`, `jti` | issuer `did:web:x402check.xyz`, the subject wallet, times, unique id |
| `score`, `tier`, `categories` | the verdict and the findings behind it |
| `checks` | **what the provider verified**: `sanctions` (list, date, status), `domain` (impersonation), `onchain` (status, network, activity), `feeds` (`source@date:status`, including code-fingerprint sets), `simulation` (status, network, findings), `model` (question set, or `skipped`) |
| `interaction` | the interaction type the verdict covers |
| `asserted` | what the caller **claimed** (screening / pre-authorization): not verified |
| `payment`, `interaction`, `aud` | what the verdict was issued for |
| `input_hash` | SHA-256 over the canonical normalized inputs, sources and question set |
| `request_hash` | SHA-256 over the request fields exactly as sent (RFC 8785): recompute it to prove nothing was dropped or altered in transit |

Verify it by **pinning the issuer**. Never trust a key URL carried by a response or an intermediary:

```bash
npx tsx scripts/verify-attest.ts <jws> --issuer did:web:x402check.xyz [--aud <url>] [--sub <wallet>]
```

The verifier resolves the key from the issuer's `did:web` document and checks `alg`, `typ`, `iss`, `exp` and `iat` (plus `aud` and `sub` when given).

## Wallet integration

Check the **real counterparty**. For `approve`, a Permit2 signature or a Seaport order, that is the spender, operator or recipient decoded from the calldata or typed data, not the token contract. Send the interaction type too. The MetaMask Snap in `snap/` is a complete reference decoder.

```js
const res = await fetch("https://x402check.xyz/v1/risk-check", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    wallet: spenderOrRecipient,              // decoded counterparty
    chain: `eip155:${chainId}`,
    domain: location.origin,                 // the requesting site
    context: "Permit2: unlimited USDC allowance to spender 0x…",
    interaction: { type: "permit_signature", unlimited: true },
  }),
});
if (res.status !== 200) return showNotVerified(res.status);   // 402 = not paid (every check is paid via x402)
const v = await res.json();
if (!v.checked) return showNotVerified();                     // fail-closed, never an all-clear
if (v.tier === "high" || v.tier === "critical") warnOrBlock(v);
```

| Tier | UX |
|---|---|
| `low` | no warning; optional "checked" badge |
| `medium` | amber: "Some signals suggest caution" |
| `high` | red: "We recommend you do not proceed" |
| `critical` | hard block with override; show the categories and evidence |

## Payments

Every evaluation is paid; there is no free tier.

- **Price:** $0.001 per evaluation ($0.002 on Solana). A batch of *n* is billed *n*.
- **Settlement:** USDC via x402 v2 (`PAYMENT-SIGNATURE`), **mainnet only**: Base, Polygon, Arbitrum, Avalanche, Monad, Sei and Solana. The facilitator is Dexter (gas-sponsored), with PayAI as fallback. The x402 "exact" scheme is gasless for the payer, so USDC alone is enough.
- **An unpaid request** gets `402` with the accepted options in `PAYMENT-REQUIRED`. Any x402 client pays and retries.
- **Invalid input** is rejected (`422`/`413`) before anything is priced.
- **Release after settlement:** the attestation is returned only once the payment settles. If the evaluation cannot be produced, nothing is settled (`503`, no charge).

```ts
import { createClient } from "@x402check/client";
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

const payer = new x402Client();
payer.register("eip155:*", new ExactEvmScheme(privateKeyToAccount(process.env.PAYER_KEY as `0x${string}`)));
payer.setSpendControls({ maxAmountPerPayment: "$0.05" }); // a batch of 25 costs $0.025
const x402check = createClient({ fetch: wrapFetchWithPayment(fetch, payer) });
const verdict = await x402check.check({ wallet: "0x…", chain: "base" });
```

## Architecture

```
request ─► validate (422 names the field) ─► quota / x402 (per item) ─► Provider
                                                                         │
      deterministic, provider-side ──────────────────────────────────────┤
        OFAC SDN screen ── listed? ──► score 0 · critical (no model call)│
        domain analysis (PSL, homoglyph, typosquat, lure)                │
        threat feeds (MetaMask + OFAC refreshed daily, ScamSniffer KV)   │
        on-chain facts + code fingerprints (JSON-RPC)                    │
        transaction simulation (eth_simulateV1) + contract verification  │
      model ─ Jev typed questions over provider checks + context ────────┤
      code  ─ weights, deterministic caps, tiers (src/scoring.ts) ───────┤
                                                                         ▼
                          ES256 attestation: checks · asserted · payment · jti
```

Source layout:

- `src/`: provider, validation, enrichment, scoring and JWS.
- `deploy/`: the Cloudflare Worker (quota Durable Object, paywall, feeds). See [deploy/README.md](deploy/README.md).
- `snap/`: the MetaMask Snap.
- `eval/`: evaluation layers.
- `scripts/`: data refresh and the verifier.

## Evidence (v0.3.0)

| What | Result |
|---|---|
| OFAC SDN addresses (external labels) | 24/24 critical |
| MetaMask-listed phishing domains · ScamSniffer drainer addresses | 40/40 · 30/30 |
| Drainer **permits**, drainer feed switched off (approval-to-EOA rule) | **27/30** |
| **Simulation:** real drainer transactions that still move assets at the latest block | **18/25 flagged** (72%), all as hidden recipients |
| **Simulation:** real transactions to 19 well-known contracts | **0/84** flagged |
| **Code fingerprints:** listed drainer contracts matched by earlier kits' code, at creation time | **43/100** |
| **Code fingerprints:** legitimate contracts (latest blocks + CoinGecko tokens), following delegations and proxies | **0/9,625** matched |
| Plain **transfers** to unlisted drainers | **0/30**: not detectable from the address alone |
| Unlisted phishing domains without a feed | 0–4/60 across four samples: feeds do the heavy lifting |
| Well-known contracts and top dApp domains | 0 false positives (0/22, 0/40) |
| Tranco top 200k, deterministic rules | 22 capped (0.011%): 20 on MetaMask's own list, 2 crypto look-alikes |
| Risky cases with an **attacker-written** context | 20/100 (only look-alike domains) |
| Injected instructions passed as raw agent content | 40/40 |

Full methodology, confidence intervals and what each number does *not* show: [docs/EVIDENCE.md](docs/EVIDENCE.md). How each verdict is formed, with every cap: [docs/METHODOLOGY.md](docs/METHODOLOGY.md). Earlier evidence documents are kept as historical records with correction notes.

## Run locally

```bash
npm install
npm test                           # provider unit tests
npm run typecheck                  # root + deploy + scripts + snap
AI_GATEWAY_API_KEY=... npm start   # :8787 (or TYPESAFE_API_KEY=...)
curl localhost:8787/.well-known/risk-check.json
npm run eval:suite -- --seed 200   # full evaluation (~$0.15 of model calls)
```

Worker: `npm run dev:worker`, or `wrangler dev --local` in `deploy/`. See [deploy/README.md](deploy/README.md) for secrets, feeds, deploy and rollback.

## For agents: SDK and MCP server

- **[`@x402check/client`](packages/client)** is a typed TypeScript client with zero runtime dependencies. It runs on Node ≥ 20, browsers, Cloudflare Workers, Deno and Bun.
  - `verifyAttestation` checks the signature against the issuer's `did:web` key and binds it to the request you made, including `request_hash`.
  - `interpret` applies the fail-closed policy. Its verdicts come from the **signed** claims only, never from the unsigned body.
- **[`@x402check/mcp`](packages/mcp)** is an MCP server for any agent (Claude Code, Claude Desktop, other MCP clients), with the tools `x402check_check`, `x402check_verify_attestation` and `x402check_methodology`.
  - Every verdict is verified before the agent sees an action.
  - It pays each check itself via x402 (USDC on Base, gasless for the payer), with a per-payment cap and a total budget.

```bash
# once published to npm; use a dedicated wallet with a small USDC balance on Base
claude mcp add x402check -e X402CHECK_PAYER_KEY=0x… -e X402CHECK_BUDGET_USD=1 -- npx -y @x402check/mcp
```

Both packages are ready to publish, but not yet published.

## MetaMask Snap (preview)

`snap/` has `onTransaction` / `onSignature` insights that decode the request locally and show the real counterparty, the amounts (including UNLIMITED approvals) and local danger findings.

**Checks are paid per call and a Snap cannot pay yet.** So 0.3.0 sends **nothing** to x402check.xyz and has no network permission. Every insight says "NOT verified by x402check" and never shows an all-clear.

The paid mode is complete and tested behind a single flag (`src/config.ts`), ready for when wallet-side payment exists. It checks the counterparty, simulates the transaction ("You send 1.5 ETH → 0x… (wallet)"), and renders the signed verdict with its evidence and warnings for hidden recipients and known drainer code.

Supported decoding:

- calldata: ERC-20 approve / transfer, Permit2, EIP-2612, setApprovalForAll, NFT transfers;
- typed data: v1, v3 and v4, including Permit2 and Seaport;
- `personal_sign` messages, decoded to text.

On install and on update it shows a disclosure that states exactly what happens. In this version nothing is sent. It stores only which disclosure you have seen.

```bash
cd snap && npm install && npm test          # builds, then 322 tests (285 run; paid-mode scenarios also run in Node) incl. the built bundle in SES
npx mm-snap serve                           # then wallet_requestSnaps "local:http://localhost:8062" in MetaMask Flask
```

The Snap is **not yet published to npm nor allowlisted by MetaMask**, so there is no one-click install in regular MetaMask yet.

## Data sources and licenses

Code is MIT. Data sources:

- OFAC SDN (U.S. Treasury);
- MetaMask eth-phishing-detect (DBAD-1.2, embedded as a derived hash set, attributed);
- ScamSniffer scam-database (GPL-3.0, runtime only: never committed or bundled);
- Forta labelled datasets (MIT, derived code fingerprints);
- Blockscout and public JSON-RPC endpoints.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). OFAC and MetaMask are refreshed daily by `.github/workflows/feeds.yml` and swapped in at runtime after verification. [`/status`](https://x402check.xyz/status) shows the versions in use. Manual refresh: `npm run ofac:update`, `npm run feeds:update`.

## Roadmap

1. Shadow real x402 facilitator traffic, moving the evidence from curated corpora to live flows.
2. Fresher address intelligence: real-time drainer feeds and funding-source analytics for plain transfers; EIP-7702 sweeper detection.
3. Valuation-aware simulation rules (price data), closing the "return a dust asset" evasion.
4. Publish the Snap and request MetaMask allowlisting.
5. KMS/HSM custody for the attestation key; key rotation with overlapping `kid`s.
6. Kora `decision_provider` integration (issue #682); AP2 `RiskPayload` once upstream stabilizes.
