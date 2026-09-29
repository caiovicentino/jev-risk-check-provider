# Evidence — x402check v0.3.0

All numbers were measured on 2026-09-29 on the v0.3.0 code:

- the consolidated suite (`npm run eval:suite -- --seed 200`: question set `jev-wallet-risk/v6`, backend Vercel AI Gateway `typesafe-ai/jev`, $0.145 of model calls, 260 s), at the release commit;
- the grounded layers with the Tranco scan (`TRANCO_LIST=top-1m.csv npm run eval:grounded -- --seed 200 --tranco-n 200000`, Tranco list of 2026-09-28);
- two new layers that make no model calls, `eval/simulation.ts` and `eval/code-fingerprint.ts`;
- local workerd runs of the production Worker, and production probes (§7).

Machine-readable reports are in `eval/evidence/*-report.json`. They are tracked in git; the raw per-call logs are not. Every rate carries a Wilson 95% interval. The rulebook these numbers measure is [`METHODOLOGY.md`](METHODOLOGY.md).

**New in v0.3:**

- transaction simulation;
- drainer-kit code fingerprints;
- contract-verification signals;
- a daily runtime refresh of OFAC and MetaMask;
- `/status`;
- the TypeScript SDK and the MCP server.

Sections 2 and 3 measure the new layers. The v0.2 layers were re-run: the numbers below are from this run, and the differences from v0.2 are noted.

## 1. Externally grounded labels (`eval/grounded.ts`)

Positives and negatives come from third-party sources. Held-out layers use a sampling seed never inspected during development. Seeds 0–99 were looked at while tuning the domain heuristics, so the canonical run uses seed 200.

| Layer | Source of truth | Result | Rate (95% CI) |
|---|---|---|---|
| A · sanctioned addresses | OFAC SDN list (ETH, SOL, TRX, XBT) | 24/24 critical | 100% (86–100%) |
| B · feed coverage: phishing domains | MetaMask eth-phishing-detect | 40/40 flagged | 100% (91–100%) |
| B · feed coverage: drainer addresses | ScamSniffer | 30/30 flagged | 100% (89–100%) |
| B · feed coverage: ScamSniffer-only domains | ScamSniffer (not in MetaMask) | 60/60 flagged | 100% (94–100%) |
| **C · held-out: drainer permits, feed OFF** | ScamSniffer addresses, feed disabled | **27/30** | **90% (74–97%)** |
| **C · held-out: plain transfer to drainer, feed OFF** | same addresses, `native_transfer` | **0/30** | **0% (0–11%)** |
| **C · held-out: unlisted phishing domain** | ScamSniffer-only domains, MetaMask feed only | **4/60** (0/60 and 1/60 in earlier v0.3 samples) | **6.7% (2.6–15.9%)** |
| D · legit contracts and wallets (22) | Uniswap, Permit2, 1inch, Aave, Seaport, USDC/USDT/WETH, Jupiter, Raydium… | 22/22 passed, 0 high/critical | 100% (85–100%) |
| D · top dApp domains (40) | curated list (app.uniswap.org, jup.ag, wallet.coinbase.com…) | 40/40 passed, 0 high/critical | 100% (91–100%) |
| D · Tranco top 200k (deterministic only) | popularity list, no model calls | 22 capped / 199,996 | 0.011% (0.007–0.017%) |

What this supports:

- **Feeds and the OFAC screen do the detection of known bad actors.** The deterministic caps are independent of model sampling.
- **The approval-to-EOA rule generalizes.** 27/30 drainer spenders are plain wallets; the 3 misses are drainer *contracts*.
- **Unknown drainers receiving a plain transfer are not detectable** from the address alone (0/30).
- **Look-alike analysis plus the model does not replace a phishing feed.** Across four fresh samples of 60 unlisted phishing domains it caught 0–4; those domains mostly do not imitate a known brand.
- **Labels drift within a day.** MetaMask removed about 200 entries on 2026-09-29. A label cache from that morning scored one "miss" against the refreshed embedded list: a host MetaMask itself had delisted. With refreshed labels the layer is 40/40. Label snapshots are now refreshed before a canonical run.
- **False-positive pressure is low.** The Tranco figure rose from 5 (v0.2, older Tranco snapshot) to 22 capped hosts:
  - 20 are on MetaMask's own list, which is refreshed daily now: `temporary.site`, `happymod.net`, `vanced.to` and other APK-mod, casino and DNS-tool sites;
  - 2 are strong look-alikes of crypto brands: `layerzro.ru` and `bitget.com.vn`.

  Popular does not mean benign. The figure is an upper bound on false positives.

## 2. Transaction simulation (`eval/simulation.ts`, new)

**Positives** are real transactions that victims sent to ScamSniffer-listed drainer contracts on Ethereum. **Negatives** are recent real user transactions to 19 well-known contracts:

- routers and aggregators: Uniswap UR and SwapRouter02, 1inch, MetaMask Swaps, Pendle;
- lending, staking and pools: Aave, Lido, Balancer, Curve, WETH;
- NFT and naming: Seaport 1.5/1.6, Blur, ENS, Uniswap positions;
- bridges and tokens: Across, and USDC/USDT transfers.

Each is replayed with `eth_simulateV1` at the latest block. The declared counterparty is the called contract, which is all a wallet can say about a call it cannot decode. No model calls are made. Code fingerprints are deliberately not applied, because the drainer contracts come from the list the runtime fingerprints are built from (§3 measures them held out).

| | Transactions | Reverted at latest | Simulated | Flagged | Rate (95% CI) | When assets move |
|---|---|---|---|---|---|---|
| Drainer interactions (20 contracts) | 56 | 23 | 33 | **18** | **54.5% (38.0–70.2%)** | **18/25 = 72.0% (52.4–85.7%)** |
| Legitimate interactions (19 contracts) | 228 | 144 | 84 | **0** | **0.0% (0.0–4.4%)** | 0/49 = 0.0% (0.0–7.3%) |

Reading:

- **Every detection is the hidden-recipient rule.** Assets left the victim, nothing came back, and a wallet the victim never named ended up with them. This holds even when the drainer contract itself is on no list.
- **The 15 misses are of three kinds:**
  - 8 replays move nothing at the latest block: the victim's approvals were already spent or the balance drained. A historical replay needs archive state, which the free public RPCs refuse.
  - 3 send ETH straight to an EIP-7702 delegated drainer account that is itself the called address. The address feed covers this one: it is listed.
  - 4 park ETH in source-verified "SecurityUpdates" contracts. The code-fingerprint layer (§3) targets exactly this kit.
- **No false positives.** Swaps, marketplace fills, bridge deposits, staking and withdrawal requests, ENS registrations and token transfers were not flagged. Recipients named in a `transfer`/`transferFrom` call count as declared for that token only.
- **The high revert rate is expected when replaying at the latest block:** filled orders, expired deadlines, spent signatures. Reverts are reported, never counted as detections.
- **Known evasion.** A drainer that returns any asset to the victim defeats the "nothing comes back" condition. Valuation-based rules need price data (roadmap).

## 3. Drainer-kit code fingerprints (`eval/code-fingerprint.ts`, new)

A fingerprint is the SHA-256 of a contract's runtime code without the compiler-metadata trailer. It is computed for logic code only: token, NFT, delegating (DELEGATECALL/CALLCODE) and <100-byte code is never fingerprinted. The set embedded in the Worker comes from Forta's MIT-licensed 2023 phishing labels, giving 46 fingerprints. The runtime set comes from ScamSniffer-listed addresses on 7 EVM chains, giving 52 fingerprints; it is GPL data, so it lives in KV and is never committed.

| Measurement (Ethereum, 100 ScamSniffer-listed contracts) | Result | Rate (95% CI) |
|---|---|---|
| Cross-source: Forta 2023 fingerprints only | 15/100 | 15.0% (9.3–23.3%) |
| **Temporal: contracts created earlier (listed set) or Forta** | **43/100** | **43.0% (33.7–52.8%)** |
| Leave-one-out within ScamSniffer (upper bound) | 51/100 | 51.0% (41.3–60.6%) |
| **False positives: contracts called in the latest 300 blocks + CoinGecko tokens** | **0/2,018 fingerprintable** (0/9,625 contracts) | 0.00% (0.00–0.19%) |

Reading:

- **Most drainer contracts are redeployments of a few kits.** "SecurityUpdates" alone accounts for 13 listed contracts. A continuously updated fingerprint set would have recognized 43% of listed contracts *when they were created*, before their own address could be listed.
- **Fingerprints generalize across deployments, not across eras.** The 2023 set catches 15% of today's listed contracts.
- **The exclusions are what make the signal safe.** Before they were added, 27 legitimate contracts collided with listed fingerprints, including the SHIB token: lists contain fake-token clones whose code is identical to the real token's.
- **After the exclusions, 0 of 9,625 contracts collided.** The scan followed EIP-7702 delegations, proxies and hard-coded links, exactly as runtime matching does:
  - 2,018 contracts were fingerprintable, 1,327 of them only through a delegate or implementation;
  - the corpus also included 3,385 tokens, 4,065 delegating contracts and 1,055 delegated accounts.
- **The temporal split assumes an earlier-created contract was already listed** when the later one appeared. Listing lag would lower the figure. The leave-one-out figure is an upper bound.
- **A match caps the score at 30 (high).** It is not treated as proof: the verdict states which set matched.

## 4. Attacker-realistic context (`eval/realistic.ts`)

The same risky scale cases were run with three kinds of context: the self-describing context of the legacy corpus, the benign context an attacker would send, and no context. A fourth variant uses raw injected content, as an agent-side gate would pass it.

| Category (n=20 each) | described | attacker-written benign | no context | raw agent content |
|---|---|---|---|---|
| impersonation (look-alike domain) | 20/20 | **20/20** | **20/20** | — |
| injection | 20/20 | 0/20 | 0/20 | **40/40** |
| laundering | 20/20 | 0/20 | 0/20 | — |
| sanctions (described, not listed) | 20/20 | 0/20 | 0/20 | — |
| abuse | 20/20 | 0/20 | 0/20 | — |

Reading: the model detects risk that is **present in the content it is given**. That covers a look-alike domain, and injected instructions when the agent passes the content it acted on. It does not infer laundering, sanctions exposure or abuse from an address, because nothing in the request carries that information. Those categories need data (feeds, on-chain analytics), not prose. The v0.3 run reproduces v0.2 exactly.

## 5. Regression corpora (described scenarios: upper bounds, not real-world rates)

| Layer | n | Accuracy (95% CI) | FN | FP | Notes |
|---|---|---|---|---|---|
| synthetic (mock model) | 53 | 100% (93–100%) | 0 | 0 | plumbing only |
| shadow, production regime → gate | 53 | 100% (93–100%) | 0 | 0 | no caller screening; review share **0.0%**; gate **READY** |
| shadow, legacy label-derived screening | 53 | 100% | 0 | 0 | comparison only (label leaked into input); review 9.4% |
| scale (7 categories × 60) | 420 | 100% (99.1–100%) | 0 | 0 | 1 unchecked; stability 91% unanimous tier (24×5) |
| red-team v6 corpus | 1,440 | 99.2% (98.6–99.6%) | 3 | 8 | 60 prose-only clearance claims held in the block band |
| benchmark: provider | 225 | 98.2% (95.5–99.3%) | 0 | 4 | same described-scenario sample |
| benchmark: gpt-4.1-mini chat judge | 225 | 99.1% (96.8–99.8%) | 0 | 2 | one-line prompt; **within noise of the provider** |

- The switch-over gate runs in the production regime: no caller `screening`, and the provider's own OFAC screen and feeds in the state.
- The 53 "human-verified" labels were applied by the project owner to cases the project authored. They confirm that the authored intent was captured. They are not an independent ground truth.
- **These rows are from the final run at the release commit.** An earlier run the same day gave 99.1%/FP 12 (red-team), 99.1% vs 99.6% (benchmark) and 96% stability. The model layer varies by about one point run to run, and the deterministic layers do not.
- On described scenarios, a one-line chat judge performs as well as the provider ($0.0135 vs $0.0152 on this sample). The provider's differentiators are the layers a prompt cannot reproduce: provider-verified evidence (lists, simulation, code), typed and signed outputs, and deterministic caps.

## 6. What each number does NOT show

- Real x402 facilitator traffic has not been shadowed yet. All model-in-the-loop corpora are synthetic or curated.
- ScamSniffer's public data lags 7 days. OFAC and MetaMask are refreshed daily by `.github/workflows/feeds.yml`. Before v0.3 they changed only with a deploy.
- The simulation replays at the latest block. It says nothing about transactions whose preconditions no longer hold, and it is measured on Ethereum only; Base, Polygon, Arbitrum, Optimism and BSC use the same code path.
- OFAC screening covers direct listing only; it does not detect funds received from listed addresses.
- The MetaMask Snap was exercised in the official SES execution environment (snaps-jest), not in the MetaMask extension. It is not published or allowlisted.

## 7. Production (`https://x402check.xyz`)

**`security-v3` against production (Worker `fbc0a6dc`): 8/8 PASS.** The run happened before the free tier was removed later the same day, so the evaluations did not need a payment:

- discovery v0.3.0 and `/status`;
- three 422 validations;
- a Forta-fingerprinted drainer contract, on no address list, capped at **30** with a verified attestation;
- a real drainer transaction replayed to **20**: a hidden recipient, whose address is also ScamSniffer-listed, with the finding signed in `checks.simulation`;
- a WETH wrap left at **94/low**.

The same probes passed on workerd with the production code before the deploy.

**`security-v2` after the paid-only deploy: 6 PASS · 0 FAIL · 5 SKIP.**

- **PASS:**
  - discovery;
  - mainnet-only 402 options;
  - batch pricing (25 × unit on all 7 networks);
  - validation before payment;
  - **no free evaluations**: an unpaid request gets 402 and no attestation, and legacy free-tier headers are ignored;
  - health.
- **SKIP:** the five probes that need a verdict. They pay per evaluation, and no funded payer was configured.

**No free tier (v0.3):** every evaluation is paid. The probes that need a verdict now pay through `eval/paid-fetch.ts` and wait on a funded payer key. Until then they report SKIP, never PASS. An unpaid request is verified to get 402 with the accepted options.

The v0.2 production record (53/53 cases, 53 attestations verified; `security:v2` 12/12, `security` 20/20, `security:full` 54 PASS / 0 FAIL / 2 SKIP) was measured on Worker `76bc1051`/`2c3937fa` and is kept in the corresponding reports.

## 8. Reviews

**v0.3 adversarial review: 11 reproduced findings, all fixed.** An independent reviewer attacked the new code. It reported only findings it had reproduced, 5 of them high severity. Each fix has a regression test in `test/review-v03.test.ts`, and the reviewer's repro scripts no longer reproduce.

- *(high)* **A named payee covered any asset and any amount.** A Snap request for `transfer(X, 1)` whose transaction actually moved 1e24 of another token to X scored 100/low.
  - Fix: payees are scoped to `payment.asset` and `payment.amount`, and explicit calldata recipients to the called token and amount. A payee scope overrides the bare naming of the subject, and anything beyond it is `outflow_exceeds_declared` (40).
- *(high)* **The code lookup failed open.** A rate-limited `eth_getCode` batch, or a recipient beyond the 7 then classified, made a drain look clean.
  - Fix: every recipient and spender is classified, up to 40, with a fallback RPC. Anything unclassified is `simulation_incomplete` (75 and review).
- *(high)* **False positives on bridges and batch senders.** Relay deposits went 12/12 and Disperse payouts 7/7 to "hidden recipient" at 40.
  - Fix: when a source-verified contract forwards to the recipient, the cap is 75 with review instead of 40.
- *(high)* **Paying a Safe or smart-wallet payee was capped at 55,** because fresh proxies are unverified on explorers.
  - Fix: payees are excluded from the "unverified sink" rule, and exact forwarding proxies are judged by their implementation.
- *(high)* **CPU amplification.** Net-movement accounting was quadratic, and logs and responses were unbounded: 500 TransferBatch logs took about 11 s.
  - Fix: linear accounting, caps on response size, logs and flows, and "incomplete" when a cap is hit. The same input now takes milliseconds.
- *(medium)* **CAIP-10 payees did not match the declared set.** Fix: canonical addresses.
- *(medium)* **The feed refresh authenticated nothing.** A self-consistent publish could replace the OFAC rows.
  - Fix: an Ed25519-signed manifest with the publisher key pinned in the Worker, sane dates, shrink checks against the list in use, and a bounded allowlist.
  - The workflow was hardened too: build with a read-only token, no persisted credentials and no install scripts, then sign and publish in a separate job that runs no dependency code.
- *(medium)* **Drainer code behind a 7702 delegation or a proxy was never fingerprinted.** Fix: one level of indirection is followed, with a build-time guard for widely used implementations.
- *(low)* TransferBatch entries after the 64th were dropped. "Not verified" was cached for 24 h. A cold isolate screened with the older embedded OFAC list.
  - Fixes: all entries are decoded under a global cap, the negative cache lasts 10 minutes, and a cold isolate briefly waits for the first verified refresh.

**SDK and MCP server review:** 1 critical and 15 other findings, all fixed but one documented residual.

- The critical one: the verdict was read from the unsigned response body, so a proxy could turn BLOCK into ALLOW. Verdicts are now read from the signed claims only, bound to the request.
- The review also led to two provider changes:
  - `request_hash`, a client-recomputable binding of the exact request;
  - fail-closed review floors when on-chain facts or the simulation are unavailable.

**v0.2:** v0.2.0 followed an independent review. A second adversarial review then confirmed and fixed 9 backend and 9 Snap findings. Each is a regression test (`test/review-regressions.test.ts`, and the Snap suite). The details are in the v0.2 record of this file in git history (`git show v0.2.0:docs/EVIDENCE.md`).

## Reproduce

```bash
npm test                                     # provider unit tests
npm --prefix snap test                       # Snap tests (built bundle in SES)
npm run eval:suite -- --seed 200             # needs AI_GATEWAY_API_KEY or TYPESAFE_API_KEY
TRANCO_LIST=top-1m.csv npm run eval:grounded -- --seed 200 --tranco-n 200000
npm run eval:simulation -- --drainers 400 --per-contract 3 --legit-per-contract 12 --seed 11
npm run eval:code                            # needs .cache ScamSniffer list (eval:grounded caches it)
PAID=1 npm run security:v3 && PAID=1 npm run security:v2   # against production: every evaluation is paid (funded payer key)
```

Historical meta-evaluations (`audit-report.json`, `crosslabel-report.json`, 2026-09-27) used the same model family to judge its own verdicts. They measure framing stability, not correctness, and are kept for the record.
