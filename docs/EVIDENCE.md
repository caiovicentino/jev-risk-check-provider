# Evidence — x402check v0.2.0

All numbers come from commit `6caf5a4`:

- the consolidated suite (`npm run eval:suite -- --seed 200`, 2026-09-29, question set `jev-wallet-risk/v6`, backend Vercel AI Gateway `typesafe-ai/jev`, ~$0.15 of model calls, 261 s);
- the production deployment `https://x402check.xyz`. `security:v2` ran on Worker `76bc1051`, and the other production suites on `2c3937fa`, which differs only in the Solana on-chain RPC default and the 2 s lookup ceiling.

Machine-readable reports are in `eval/evidence/*-report.json`. They are tracked in git; the raw per-call logs are not. Every rate carries a Wilson 95% interval.

v0.2.0 follows an independent review. Its findings changed how the earlier (v5) evidence reads, so this document leads with measurements whose labels this project did **not** author. v5 numbers are kept as historical records in `EVIDENCE-SCALE.md`, `EVIDENCE-REDTEAM.md` and `EVIDENCE-SECURITY.md`, with correction notes.

## 1. Externally grounded labels (`eval/grounded.ts`)

Positives and negatives come from third-party sources. Held-out layers use a sampling seed never inspected during development: seeds 0–99 were looked at while tuning the domain heuristics, so the canonical run uses seed 200.

| Layer | Source of truth | Result | Rate (95% CI) |
|---|---|---|---|
| A · sanctioned addresses | OFAC SDN list (ETH, SOL, TRX, XBT) | 24/24 critical | 100% (86–100%) |
| B · feed coverage: phishing domains | MetaMask eth-phishing-detect | 40/40 flagged | 100% (91–100%) |
| B · feed coverage: drainer addresses | ScamSniffer | 30/30 flagged | 100% (89–100%) |
| B · feed coverage: ScamSniffer-only domains | ScamSniffer (not in MetaMask) | 60/60 flagged | 100% (94–100%) |
| **C · held-out: drainer permits, feed OFF** | ScamSniffer addresses, feed disabled | **27/30** | **90% (74–97%)** |
| **C · held-out: plain transfer to drainer, feed OFF** | same addresses, `native_transfer` | **0/30** | **0% (0–11%)** |
| **C · held-out: unlisted phishing domain** | ScamSniffer-only domains, MetaMask feed only | **0/60** | **0% (0–6%)** |
| D · legit contracts and wallets (22) | Uniswap, Permit2, 1inch, Aave, Seaport, USDC/USDT/WETH, Jupiter, Raydium… | 22/22 passed, 0 high/critical | 100% (85–100%) |
| D · top dApp domains (40) | curated list (app.uniswap.org, jup.ag, wallet.coinbase.com…) | 40/40 passed, 0 high/critical | 100% (91–100%) |
| D · Tranco top 200k (deterministic only) | popularity list, no model calls | 5 capped / 199,999 | 0.003% (0.001–0.006%) |

What this supports:

- **Feeds and the OFAC screen do the detection of known bad actors.** The deterministic caps are independent of model sampling.
- **The approval-to-EOA rule generalizes.** 27/30 drainer spenders are plain wallets; the 3 misses are drainer *contracts*.
- **Unknown drainers receiving a plain transfer are not detectable** from the address alone (0/30).
- **Look-alike analysis plus the model does not replace a phishing feed.** It caught 0–3 of 60 unlisted phishing domains across two fresh samples; those domains mostly do not imitate a known brand.
- **False-positive pressure is low.** On the Tranco top 200k, the 5 capped hosts are `temporary.site` and `tornadoeth.cash` (MetaMask list) and `ss:07789dc83cb686a1`, `ss:a227373b500b8020` and one IDN host (ScamSniffer, corroborated). Most are genuine abuse.

## 2. Attacker-realistic context (`eval/realistic.ts`)

The same risky scale cases were run with three kinds of context: the self-describing context of the legacy corpus, the benign context an attacker would send, and no context. A fourth variant uses raw injected content, as an agent-side gate would pass it.

| Category (n=20 each) | described | attacker-written benign | no context | raw agent content |
|---|---|---|---|---|
| impersonation (look-alike domain) | 20/20 | **20/20** | **20/20** | — |
| injection | 20/20 | 0/20 | 0/20 | **40/40** |
| laundering | 20/20 | 0/20 | 0/20 | — |
| sanctions (described, not listed) | 20/20 | 0/20 | 0/20 | — |
| abuse | 20/20 | 0/20 | 0/20 | — |

Reading: the model detects risk that is **present in the content it is given**. That covers a look-alike domain, and injected instructions when the agent passes the content it acted on. It does not infer laundering, sanctions exposure or abuse from an address, because nothing in the request carries that information. Those categories need data (feeds, on-chain analytics), not prose.

## 3. Regression corpora (described scenarios — upper bounds, not real-world rates)

| Layer | n | Accuracy (95% CI) | FN | FP | Notes |
|---|---|---|---|---|---|
| synthetic (mock model) | 53 | 100% (93–100%) | 0 | 0 | plumbing only |
| shadow, production regime → gate | 53 | 100% (93–100%) | 0 | 0 | no caller screening; review share **0.0%**; gate **READY** |
| shadow, legacy label-derived screening | 53 | 100% | 0 | 0 | comparison only (label leaked into input); review 9.4% |
| scale (7 categories × 60) | 420 | 100% (99.1–100%) | 0 | 0 | stability 91% unanimous tier (24×5) |
| red-team v6 corpus | 1,439 (+1 unchecked) | 99.2% (98.6–99.6%) | 2 | 9 | 60 prose-only clearance claims held in the block band |
| benchmark: provider | 225 | 99.6% (97.5–99.9%) | 0 | 1 | same described-scenario sample |
| benchmark: gpt-4.1-mini chat judge | 225 | 98.7% (96.2–99.5%) | 1 | 2 | one-line prompt; **intervals overlap: no significant difference** |

- The switch-over gate runs in the production regime: no caller `screening`, and the provider's own OFAC screen and feeds in the state. The v5 gate reached READY only in a "screening-integrated" simulation that derived the caller's screening field from the label. Unscreened, it failed at a 26% review share.
- The 53 "human-verified" labels were applied by the project owner to cases the project authored. They confirm that the authored intent was captured. They are not an independent ground truth.
- The v5 claim that the provider beats the chat judge on accuracy and cost did not survive the corrected corpus. Accuracy is within noise, and cost per decision is similar ($0.0152 vs $0.0135 on this sample). The provider's differentiators are typed, signable outputs and deterministic evidence, not accuracy.

## 4. Production (`https://x402check.xyz`)

| Suite | Result |
|---|---|
| `npm run prod` — 53 cases against the live endpoint | **53/53** correct, **53/53** attestations verified (issuer pinned, `exp` checked), 0 mismatches |
| `npm run security:v2` — v0.2.0 fixes | **12/12 PASS**: see the list below |
| `npm run security` — v5 probe suite | **20/20 PASS** (422s now name the offending field) |
| `npm run security:full` — 56 probes | **54 PASS · 0 FAIL · 2 SKIP**. The concurrency probe was skipped for lack of free allowance on the test IP after the other runs; it passes against the same code locally (below). |

The 12 `security:v2` probes:

- discovery lists no testnets;
- the 402 challenge offers mainnets only;
- a 25-item batch is priced 25× the unit on all 7 networks;
- malformed input gets 422 or 413 with the field named;
- the free tier is charged per item and invalid input is free;
- `/healthz` is edge-cached;
- an OFAC-listed address gets 0/critical with the model skipped;
- a MetaMask-listed domain gets 20/critical;
- a self-asserted "clean" gets 30/high;
- a permit to a fresh EOA gets 40/high, while one to the Universal Router gets 85/low;
- signed `checks`/`payment`/`aud`/`jti`;
- **two IPv6 source addresses in one /64 share the quota**.

Per-key counter atomicity: 25 concurrent requests from one client id, run on workerd with the production code and a fresh Durable Object, received remaining values 24…0, all distinct and consecutive. The next 5 fell back to the IP allowance.

Not re-exercised: a real paid settlement. Both payer wallets are unfunded (0 USDC). The paywall was verified up to the 402 challenge: prices, networks, and settle-before-release in unit tests with a fake facilitator.

## 5. What each number does NOT show

- Real x402 facilitator traffic has not been shadowed yet. All model-in-the-loop corpora are synthetic or curated.
- ScamSniffer's public data lags 7 days. MetaMask's list is refreshed only when `npm run feeds:update` is run and deployed.
- OFAC screening covers direct listing only; it does not detect funds received from listed addresses.
- The MetaMask Snap was exercised in the official SES execution environment (snaps-jest), not in the MetaMask extension. It is not published or allowlisted.

## Reproduce

```bash
npm test                                     # 63 unit tests
npm --prefix snap test                       # 90 Snap tests (built bundle in SES)
npm run eval:suite -- --seed 200             # needs AI_GATEWAY_API_KEY or TYPESAFE_API_KEY
TRANCO_LIST=top-1m.txt npm run eval:grounded -- --seed 200 --tranco-n 200000
npm run security:v2 && npm run prod          # against production (free tier: 25/day)
```

Historical meta-evaluations (`audit-report.json`, `crosslabel-report.json`, 2026-09-27) used the same model family to judge its own verdicts. They measure framing stability, not correctness, and are kept for the record.
