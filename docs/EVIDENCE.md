# Evidence — x402check v0.6 (v0.3.0–v0.6.2)

**v0.6.0** is the audit release (2026-09-30). It closes paths around the rules rather than adding new ones, and it re-measures the signing guard. It was measured in production on v0.6.0 (Worker commit `7d1e3ab`) on 2026-09-30 (UTC); see the next section.

**v0.5** changes how checks are paid, not how they are made. It adds per-network prices, facilitator routing by compatibility and cost, and prepaid credits. **v0.5.1** adds Coinbase CDP as a facilitator. Both were measured in production on 2026-09-30 (UTC) by `eval/security-v5.ts`, with `eval/security-v2.ts` re-run (§7).

**Dates.** The signing guard, `x402check_pay`, the Bazaar payee sample, the Solana guard, the Bazaar listing and x402scan were measured on 2026-09-30, and the guard and the payee sample were re-measured on v0.6.0 the same day. Everything else was measured on 2026-09-29.

**v0.4** adds the kit watch and the first shadow of a facilitator's real traffic (§0); it was measured on the v0.4.0 code without model calls:

- the kit watch backfill (`scripts/hunt-kits.ts`, the same code the Worker cron runs);
- `eval/kit-watch.ts`: precision on held-out legitimate code, template recall, the poisoner audit and the forwarder audit;
- `scripts/payai-shadow.ts`: seven days of PayAI-settled payments on Base;
- `eval/security-v4.ts`: paid production probes.

The v0.3 layers (§1–§5) were measured on the v0.3.0 code:

- the consolidated suite (`npm run eval:suite -- --seed 200`: question set `jev-wallet-risk/v6`, backend Vercel AI Gateway `typesafe-ai/jev`, $0.145 of model calls, 260 s), at the release commit;
- the grounded layers with the Tranco scan (`TRANCO_LIST=top-1m.csv npm run eval:grounded -- --seed 200 --tranco-n 200000`, Tranco list of 2026-09-28);
- two layers that make no model calls, `eval/simulation.ts` and `eval/code-fingerprint.ts`;
- local workerd runs of the production Worker, and production probes (§7).

Machine-readable reports are in `eval/evidence/*-report.json`. They are tracked in git; the raw per-call logs are not, and neither is the kit-watch watchlist (it is the provider's private data). An address or domain that only ScamSniffer lists (GPL-3.0) appears in a report as `ss:<16 hex>`, the first 16 hex digits of its SHA-256 (`eval/redact.ts`). Every rate carries a Wilson 95% interval. Wilson intervals assume independent samples; where a sample takes several transactions from one contract, the contract-level figure is given too. A number that was measured but is not in a tracked report says so. The rulebook these numbers measure is [`METHODOLOGY.md`](METHODOLOGY.md).

## v0.6.0 in production (new)

The Worker at commit `7d1e3ab`, deployed with `scripts/deploy.sh` after CI passed. Every probe below was paid by the probe payer to our own `pay_to`, or from its prepaid credits.

| Probe | Result |
|---|---|
| **Single-use payments** (`eval/replay.ts`, `replay-report.json`): one check paid per call on Base, and the same `PAYMENT-SIGNATURE` sent twice more at the same moment, so all three verify before anything settles | **PASS.** One copy was evaluated and settled; the other two got `409 payment_already_used`. A copy sent after settlement also got 409. Before v0.6.0, all three would have been evaluated. |
| **`npm run security:v5`** (`security-v5-report.json`): prices, routes, per-call and credit payments | **11/11 PASS.** Both settlements (a per-call check and a $0.10 credit pack) went through Coinbase CDP, the Base route. |
| **The model canary's three cases**, sent once from credits through the full production pipeline | injected instruction: **critical** (7); drain request: **critical** (0); a configured payment: **low** (95). This was a one-off run, not a tracked report. The cron's own canary result is in `/status` → `model`. |
| **`x402check_pay`**, the MCP server 0.3.0 build (`eval/mcp-pay.ts`, `mcp-pay-report.json`) | One real payment settled on Base in 4.8 s, **to x402check's own `pay_to`, a trusted payee that is not checked**. No secret in the output or on stderr. |
| **Bazaar payees, seed 402** (`eval/pay-guard.ts`, `pay-guard-report.json`) | **25/25 allowed** (see below) |
| **`scripts/verify-attest.ts`** on a fresh production attestation | Valid when bound to the exact request (`--request`, `--max-age 300`, key pinned). With another request: `request_mismatch`. With another pin: `key_not_pinned`. Ad hoc, not a tracked report. |
| **HTTP** | Plain HTTP: a page gets 301 to HTTPS, an API call 403. HSTS, `nosniff`, `Referrer-Policy`; a CSP on the site, whose fonts, video and live counter still load with no violation. |
| **x402scan's requirements** | An unpaid POST with no body gets 402, and `HEAD /favicon.ico` 200. |

**Latency.** From credits a check took 0.5–0.8 s (664 and 538 ms in `security:v5`, 0.6–0.7 s for two of the canary's calls; its first call, just after the deploy, took 2.8 s). Paid per call, a check took **4.7 s** end to end in this run (402, payment, evaluation, settlement). Earlier single samples: 2.7 s through PayAI (v0.5.0), 3.7 s through CDP (v0.5.1). These are single samples; no p95 is published yet.

## Guarded x402 payments (`@x402check/mcp` 0.2.0, new)

`x402check_pay` is a tool of the MCP server. It fetches an x402 resource and pays for it only after x402check clears the exact option about to be signed: the payee, network, asset, amount and the resource's site. The check runs inside the x402 client's `onBeforePaymentCreation` hook, and its attestation is verified and bound to that request. A `warn` is paid only if the user approves it in the client (MCP elicitation). Nothing else can approve it.

**A real payment through the tool, in production** (`eval/mcp-pay.ts`, `mcp-pay-report.json`):
- the built server (`packages/mcp/dist/index.js`; 0.2.0 at first, 0.3.0 in the report now) was driven over stdio with plain JSON-RPC, as an MCP client drives it;
- the tool bought a paid x402check call ($0.0035), with our own `pay_to` as the payee, so no third party was paid;
- **settled on Base** by the facilitator, with the receipt, the result and the verdict returned in 3.6 s (0.2.0) and 4.8 s (0.3.0);
- no secret appeared in the output or on stderr (the key and the credit token were checked for);
- **x402check's own `pay_to` is a trusted payee that is not checked**, so this run proves the payment path only. The check path is measured next, on real merchants' payees. The full path (check, then pay a third party) has not been run with a real payment.

**Real x402 merchants** (`eval/pay-guard.ts`, `pay-guard-report.json`). Method:
- 25 distinct payees were drawn at random (seed 402) from the Coinbase x402 Bazaar, the public catalog (19,735 resources, 8 pages read), from 83 Base USDC payees;
- each was checked against production (v0.6.0) exactly as the tool checks a payment before signing it;
- nothing was paid to them: only the checks were bought, from prepaid credits ($0.025).

| Verdict | Payees |
|---|---|
| `allow` (the tool would pay) | **25/25 (100%, 95% CI 86.7–100%)** |
| `warn`, `block`, `not_verified` | 0 |

- 12 payees carried the "new address" note (no or little on-chain history) and were still allowed: a fresh merchant wallet alone does not stop an agent. Each check took 0.5–1.0 s.
- Listed merchants are not known to be benign, so this is not a false-positive rate. It is how often an autonomous agent would be stopped on the catalog's merchants, and why.
- **Correction.** The first run (v0.5.5, 2026-09-30) was published as "seed 402, 24/25 allowed". A parser bug in the eval scripts read the Node binary's path when a flag was absent, so that sample was drawn with seed 0, not 402 (fixed in `eval/flags.ts`). The run above is the first with the published seed.

**Tests:** `packages/mcp/test/pay.test.ts`, 16 tests. They cover:
- every outcome, and the user's decision through elicitation (approve, decline, cancel);
- that a `block` is never put to the user;
- per-call checks paid by the same wallet as the resource;
- `max_usd`, the cap and the budget refusing before any check is bought;
- time limits, and URL and header refusals.

## Solana signing guard (`@x402check/client` 0.3.0, new)

`guardSolanaSigner()` wraps a `@solana/kit` signer. Every transaction is decoded, including v0 lookup tables and the owners of receiving token accounts, and its counterparties are checked before the key signs.

**Real inputs** (`eval/solana-guard.ts`, `solana-guard-report.json`). The inputs used the real Solana mainnet RPC and production checks from prepaid credits. Nothing was sent to the network and no funds moved. **One case is a real x402 payment; the other three were constructed by the eval, with the expected decision set by the project.** 4/4 decided as expected (95% CI 51.0–100%): this shows the paths work, not a rate.

| Case | Decision | How |
|---|---|---|
| A real x402 payment on Solana: production's 402, built by the official x402 SVM client (`@x402/svm` `ExactSvmScheme`) with the guarded signer | **allow, signed** (1.9 s) | The payee's token account was resolved on mainnet to its owner, x402check's `pay_to`, checked in production as a `token_transfer` with the amount and mint bound, and the attestation was verified. |
| A System `Assign` of the wallet to an unknown program (the owner-change drain) | **block**, locally | No check was needed. |
| An unlimited SPL approval to a fresh wallet | **block** (0.6 s) | Production found an approval to a plain wallet with no history. |
| A SOL transfer disguised as a message to sign | **block**, locally | The bytes are a transaction message. |

**Tests:** `packages/client/test/solana.test.ts`, 15 tests on real `@solana/kit` signers and compiled transactions. They cover:
- signatures that verify after an allow, and nothing signed after a refusal;
- ATA-created and on-chain token-account owners, and lookup tables (resolved or not);
- local drains, unreadable instructions, batches, messages and Sign-In With Solana.

## Signing guard (`@x402check/client` 0.2.0; re-measured with 0.4.0)

`guardAccount()` wraps the account an agent signs with. A signature request is decoded (the real counterparty inside the calldata or typed data), checked, and its attestation verified and bound to that exact request. Only then does the key sign; otherwise the guard throws.

**Real mainnet transactions** (`eval/guard.ts`, `guard-report.json`, re-run on the v0.6.0 code on 2026-09-30). The cases are the exact transactions of the `eval/simulation.ts` run of 2026-09-29:
- 56 transactions that victims sent to 20 ScamSniffer-listed drainer contracts;
- 228 recent transactions to well-known contracts (30 distinct counterparties).

Each was re-fetched and handed to the guard as the signature request an agent's account would make. The **real provider** ran in process: simulation on public mainnet RPCs at the latest block, OFAC, the MetaMask list, Forta code fingerprints, on-chain facts and contract verification. **The ScamSniffer feed was off** (the drainer contracts come from it) and the model was neutral, so every refusal below comes from what the transaction does, not from a list. The guard pinned the in-process provider's key, so every attestation was verified as in production.

| Transactions | Refused (the key never signs) | Signed |
|---|---|---|
| Drainer transactions that still move the victim's assets (25, from 11 contracts) | **22/25 (88%, 95% CI 70.0–95.8%)**; by contract **10/11 (62.3–98.4%)** | 3, all from one contract |
| Drainer transactions that execute but moved nothing in the simulation run (already drained) | 0/8 | 8 (nothing left to lose) |
| Drainer transactions that revert at the latest block, or were not simulated | 0/23 | 23 (they cannot execute) |
| Legitimate transactions that move assets | **0/49 (0.0–7.3%)** | 49 |
| Legitimate transactions that execute (simulated OK in the simulation run) | **0/84 (0.0–4.4%)** | 84 |
| All legitimate transactions (144 of them revert at the latest block) | **1/228 (0.4%, 0.1–2.4%)**, as `not_verified` | 227 |

- **Why it refused the drainers:**
  - 18 transactions were refused by the simulation: the assets end with a wallet the signer never named;
  - 4 by drainer code (Forta fingerprints, an independent source). Simulation alone had missed these 4 (18/25 in `simulation-report.json`).
- **The 3 misses** are the three transactions of one contract, and they simulate cleanly: nothing in what they do at the latest block looks like a drain.
- **The one legitimate refusal** is a transaction whose calldata is too large to simulate (it also reverted in the simulation run). Since v0.6.0 the guard refuses such a transaction (`not_simulated`) rather than sign it on an address check alone.
- **Denominators.** A reverting transaction cannot trigger the simulation rules, so the legitimate rate is stated on the 49 that move assets and the 84 that execute. The drainer and legitimate samples take up to 3 transactions per contract; the Wilson intervals treat transactions as independent, so the contract-level figure is the more conservative one (legitimate: 0 of 30 counterparties refused, 0.0–11.4%).

**In production** (`eval/guard-production.ts`, `guard-production-report.json`):
- the guard against `https://x402check.xyz`, paid from prepaid credits ($0.005 per simulated check), agreed with the in-process guard on **4/4** transactions: 2 drainers blocked, 2 legitimate allowed, in 0.6–2.3 s;
- **both legitimate transactions revert at the latest block** (`simulation_reverted`), so production has not yet exercised a legitimate transaction that executes;
- there, the drainers also hit the ScamSniffer list (`known_scam_address`) and the kit watch (`compromised_wallet`).

**Unit and end-to-end tests:**
- `packages/client/test/guard.test.ts`, 13 tests, including refusal on no credits, an unreachable provider, an attestation bound to another request, and a forged signature;
- `test/guard-e2e.test.ts`, the guard against the real provider's attestations.

## 0. Kit watch and a facilitator shadow (v0.4, new)

### What the watch saw

A **backfill** (`scripts/hunt-kits.ts`, the same code as the production cron, run before the cron was deployed) read every block of the windows below. None of what it flagged was on ScamSniffer's list at measurement time. That list publishes with a 7-day delay, so an overlap of 0 was expected by construction: **the watch's lead time over the public lists is not yet measured**, and ScamSniffer is the only list compared.

| | Ethereum, 24 h (7,200 blocks) | Base, 6 h (10,800 blocks) |
|---|---|---|
| EIP-7702 authorizations read † | 37,843 | 15,912 |
| Delegates classified † | 196 | 95 |
| Contracts created at the top level † | 1,254 | 1,712 |
| **Look-alikes delegated to the poisoning executor** | **6,232** | 0 |
| Wallets delegated to a labelled sweeper family | 16 | 12 |
| Wallets delegated to a forwarder (behaviour, no label) | 559 | 204 |
| Destinations of forwarders (plain wallets only) ‡ | 24 | 10 |
| New contracts in an old drainer-kit family † | **0** of 1,254 | **0** of 1,712 |
| Flagged addresses on ScamSniffer's list (published with a 7-day delay) | **0** of 6,831 | **0** of 226 |

† From the backfill's logs (`.cache/intel/hunt-*.log`, not tracked); `kit-watch-report.json` records the flagged addresses by kind, the families and the ScamSniffer overlap.
‡ Since v0.6.0 a forwarder's destinations are no longer recorded: whoever deploys a forwarder chooses them, so they prove nothing about the destination (METHODOLOGY §2).

Reading:

- **Drainer infrastructure has moved to EIP-7702.** Not one new contract matched a drainer-kit family (the kits of 2017–2023). Tens of thousands of delegations a day did, however, go to address-poisoning executors and to sweepers.
- **The poisoning executor is a single public template.** Wintermute exposed and verified it ("Poisoner": `executeBatch` gated on `tx.origin`). One operator delegated 6,232 fresh look-alike wallets to it in a day.
- 22 forwarder families were learned from behaviour alone. Two of them are known by their delegate's address, because their code is too small to fingerprint.

### Precision

**Poisoner family.** The delegate's verified source obeys only its operator (a `tx.origin` check). So a wallet that delegates to it is controlled by the operator while it stays delegated, whether or not it is a look-alike.

- **Audit:** 40 authorities were sampled (seed 7). For each, up to 8 counterparties' latest 50 token transfers and 50 transactions were read, looking for a *different* address sharing the authority's first 3 and last 4 hex digits: the real payee it imitates. By chance this happens about once in 250 million pairs.
- **Result:** **27/37 confirmed look-alikes = 73.0% (95% CI 57.0–84.6%)**. 3 had no activity yet.
- This is a lower bound: the victim's matching payment can be older than what was read. A first version of the audit read only token transfers and missed payments in native ETH (5/28). That miss was in the audit, not the watch.

**Forwarders (behaviour).**
- Of the 34 destinations, none carries an exchange or service label on Blockscout, one is flagged as a scam, and none is on ScamSniffer's list.
- An auto-forwarding delegation is recorded as a fact ("whatever this wallet receives is passed on to X"), not as proof of theft. It caps at 40 (`auto_forwarding_wallet`); only labelled sweeper families cap at 20.

**Code families and the production code sets, on code legitimate users run.** This measurement found a false positive that had been live since v0.3.

- **Corpus:** held-out verified contracts (Blockscout pages 41–80, 2,000 per chain, never used to build anything) plus the contracts called in the latest blocks.

| Held-out corpus | Fingerprintable | Kit families, before the gate | after the gate | Production code sets (Forta + ScamSniffer) |
|---|---|---|---|---|
| Ethereum (2,000 verified + 5,808 callees) | 2,500 | 16 = 0.6% (0.4–1.0%) | 1 = 0.04% (0.007–0.23%) | 1 = 0.04% (0.007–0.23%) |
| Base (2,000 verified + 5,311 callees) | 2,957 | 0 (0–0.13%) | 0 (0–0.13%) | 0 (0–0.13%) |

- **What collided:** lists label a single deposit address or wallet as phishing because it received phishing proceeds, but its code is a legitimate fleet's. Forta's dataset does this for:
  - Luno's deposit forwarder (11 labelled);
  - a Poloniex deposit contract;
  - BitGo's `Forwarder` (eth-multisig-v2);
  - the Mist/Ethereum Wallet multisig.
- **Consequence in production:** the v0.3 Forta set flagged **every deposit address of those fleets** as drainer code (cap 30). The v0.3 figure "0/9,625" was measured on the latest callees and CoinGecko tokens, a corpus that happened to contain none of them.
- **Fix (v0.4):**
  1. A **collision gate** (`scripts/legit-corpus.ts`): a fingerprint in legitimate use never enters a code set or a kit family. The gate corpus is the verified contracts of pages 1–40, CoinGecko tokens and callees, disjoint from the held-out pages above.
  2. The four fleets are guarded explicitly.
  3. Forta contracts created **before 2021** no longer seed a set. All four collisions came from them, and dropping them costs no recall (40/82 before and after).
  4. Families that come only from an address hard-coded in a listed contract are dropped, because that target is whatever the contract calls. Uniswap's V2 router entered this way.
- **After the fix:**
  - the embedded Forta set went from 46 to 27 fingerprints; the ScamSniffer set is unchanged (52);
  - the kit registry shrank (109 families to 85, measured locally and not in a tracked report). `kit-watch-report.json` records the registry the watch runs: 124 families (94 drainer kits, 7 sweepers, 1 poisoner and 22 forwarder families learned from behaviour);
  - the paid production probes (§7) confirm that a Luno deposit address and a BitGo forwarder now score low.
- **Second held-out run (pages 81–120 and fresh callees, after these rules):**
  - **Ethereum: 1 match among 1,737 fingerprintable contracts** (the report's raw figure: 0.058%, 0.010–0.325%). On our own review, it is a real `SecurityUpdates` drainer. Its verified source has a payable `SecurityUpdate()` and an owner-only `withdraw`, and victims paid into it in 2023. It is on no public list we use, and it entered the "legitimate" corpus because it was re-verified on Blockscout that day.
  - **Base: 0 matches among 2,935.**
  - **False positives, counting that review: 0/1,737 on Ethereum (0.00–0.22%) and 0/2,935 on Base (0.00–0.13%).** The review is ours, not an external label, and the report records the raw match.
  - A corpus of verified and called contracts is not guaranteed clean: every match is reviewed before it is counted either way.

**Template fingerprints: a negative result.**
- Zeroing immutables and hard-coded addresses did not recognize a single additional listed drainer contract: 40/82 = 48.8% (38.3–59.4%) with exact fingerprints, and the same with templates. The listed kits differ by more than their operator's address.
- Templates are kept for the poisoner family, whose deployments differ only by an immutable (the operator).

### PayAI shadow (`scripts/payai-shadow.ts`)

- **Method:** PayAI publishes its EVM settlement signers (x402 v2 `/supported`). Every transaction they sent on Base from 2026-09-22 to 2026-09-29 was read from Blockscout, and the ERC-20 Transfer logs of their receipts are the payments.
- **Checks replayed:** x402check's deterministic layers, on every payee and payer: OFAC, ScamSniffer addresses, the kit watch, and the code each address runs, with a forwarding probe on every delegated payee. No model calls.

| | |
|---|---|
| Settlement transactions (2 of 15 published signers active on Base) | 3,487 |
| USDC payments | 3,132 · $709.48 · median $0.01 · p99 $3.77 |
| Payees / payers | 207 / 226 (24 payees and 20 payers are EIP-7702-delegated EOAs) |
| Top 10 payees' share of payments | 59% |
| **Flagged payees / payers** | **0 / 0** |
| Cost of checking every payment at $0.001 | $3.13 for the week |

Reading: PayAI's Base traffic in that week was small and clean by every deterministic layer. The shadow measures the base rate a facilitator would pay to rule out the rare bad payee. It does not measure a detection.

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
| False positives: contracts called in the latest 300 blocks + CoinGecko tokens | 0/2,018 fingerprintable (0/9,625 contracts) | 0.00% (0.00–0.19%) — **superseded in v0.4, see below** |

Reading:

- **Most drainer contracts are redeployments of a few kits.** "SecurityUpdates" alone accounted for 13 listed contracts (counted during development; not in a tracked report). A continuously updated fingerprint set would have recognized 43% of listed contracts *when they were created*, before their own address could be listed.
- **Fingerprints generalize across deployments, not across eras.** The 2023 set catches 15% of today's listed contracts.
- **The exclusions are what make the signal safe.** Before they were added, 27 legitimate contracts collided with listed fingerprints, including the SHIB token: lists contain fake-token clones whose code is identical to the real token's. (That count is from development and is not in a tracked report; the report records the result with the exclusions.)
- **After the exclusions, 0 of 9,625 contracts collided.** The scan followed EIP-7702 delegations, proxies and hard-coded links, exactly as runtime matching does:
  - 2,018 contracts were fingerprintable, 1,327 of them only through a delegate or implementation;
  - the corpus also included 3,385 tokens, 4,065 delegating contracts and 1,055 delegated accounts.
- **The temporal split assumes an earlier-created contract was already listed** when the later one appeared. Listing lag would lower the figure. The leave-one-out figure is an upper bound.
- **A match caps the score at 30 (high).** It is not treated as proof: the verdict states which set matched.
- **Correction (v0.4).** The false-positive corpus above held no exchange deposit contracts. On held-out verified contracts, the Forta set matched the deposit fleets of Luno, Poloniex and BitGo, and the Mist multisig. Forta labels single deposit addresses of those fleets as phishing. v0.4 gates every code set against legitimate code and drops pre-2021 Forta contracts (§0).

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

- Real x402 facilitator traffic has been shadowed for one facilitator and one week, from public data and with the deterministic layers only (§0): 3,132 payments, none flagged. All model-in-the-loop corpora are synthetic or curated.
- The kit watch's volumes are one 24 h backfill on Ethereum and six hours on Base, not a day of the live cron. Its lead time over the public lists needs weeks of listings to measure: no flagged address was on ScamSniffer's list at measurement time, which that list's 7-day delay guarantees. Only ScamSniffer was compared.
- The guard's samples take up to 3 transactions per contract, so transaction-level intervals overstate the precision; contract-level figures are given next to them.
- ScamSniffer's public data lags 7 days. OFAC and MetaMask are refreshed daily by `.github/workflows/feeds.yml`. Before v0.3 they changed only with a deploy.
- The simulation replays at the latest block. It says nothing about transactions whose preconditions no longer hold, and it is measured on Ethereum only; Base, Polygon, Arbitrum, Optimism and BSC use the same code path.
- OFAC screening covers direct listing only; it does not detect funds received from listed addresses.
- The MetaMask Snap was exercised in the official SES execution environment (snaps-jest), not in the MetaMask extension. It is not published or allowlisted.

## 7. Production (`https://x402check.xyz`)

**Every evaluation below was paid.** Each was either settled on-chain in USDC on Base through x402, or (v0.5) paid from prepaid credits bought that way. The settlement transactions are in the `security-v5`, `bazaar`, `replay` and `mcp-pay` reports. `prod-report.json` (v0.3) does not record them.

- `prod` ran on Worker `d230e4a5`: the paid-only v0.3 code with EVM settlement through PayAI.
- `security:v2` and `security:v3` ran on v0.3.2 (`3045ce10`), which adds simulation pricing.
- `security:v5` ran on v0.5.0 (`d9030314`): per-network prices, routing and prepaid credits. `security:v2` was re-run there: 12/12 PASS, with its 6 evaluations settled at the v0.5 prices.
- `security:v5` ran again on v0.5.1 (`08c5a2f6`), with Coinbase CDP configured. It adds two probes:
  - the facilitators' health, from `/status`;
  - which facilitator settled each payment, found by matching the transaction's sender on Base against the signers each facilitator publishes.

| Suite | Result | Paid evaluations |
|---|---|---|
| `npm run prod`: 53 described cases against the live endpoint | **53/53** correct, **53/53** attestations verified (issuer pinned, `exp` checked), 0 mismatches | 53 |
| `npm run security:v2`: v0.2 fixes, "no free evaluations", simulation pricing (v0.3.2) | **12/12 PASS** | 6 |
| `npm run security:v3`: v0.3 features (v0.3.2: two simulated evaluations settled at $0.005) | **8/8 PASS** | 3 |
| `npm run security:v4`: v0.4 kit watch and collision gate (Worker `5f8e17f0`) | **7/7 PASS** | 5 |
| `npm run security:v5`: v0.5 prices, routing and prepaid credits (Worker `d9030314`, `security-v5-v0.5.0-report.json`) | **9/9 PASS** | 1 per call ($0.0035), then 2 from a $0.10 credit pack (one settlement) |
| `npm run security:v5` on v0.5.1, settling through Coinbase CDP (Worker `08c5a2f6`) | **11/11 PASS** | 1 per call ($0.0035), then 2 from a $0.10 credit pack. Both settlements were sent by CDP signers |
| `npm run security:v5` on v0.6.0 (commit `7d1e3ab`) | **11/11 PASS** | the same probes; per call 4,716 ms end to end, from credits 664 and 538 ms |
| `eval/replay.ts` on v0.6.0: three copies of one payment at once | **PASS** | one evaluated and settled; two `409 payment_already_used`; a later copy 409 |
| `eval/replay.ts` on v0.6.2 (commit `c4a5f33`): four spellings of one payment at once (the original, an exact copy, every JSON key reversed, the nonce's hex upper-cased plus an extra field) | **PASS** | one evaluated and settled on Base (`0x6d7f4ac8…`): the re-spelled copy, which CDP accepted; the other three `409 payment_already_used`; a later copy 402 (the facilitator saw the nonce used). On v0.6.1 each spelling was its own claim (security review F1) |

The `security:v5` probes cover:
- **the price table:** the discovery document and the 402 carry the seven per-network prices, and none mismatches. Base is offered through EIP-3009, so any wallet can pay it gaslessly;
- **the routes:** `/status` → `payments` states each network's facilitator, transfer method, fee and margin (below). None is below its facilitator's floor;
- **a per-call check on Base:** $0.0035, **2,709 ms** end to end (402, payment, evaluation, settlement);
- **credits:**
  - a **$0.10 pack** was bought with one settlement;
  - **two checks** were paid from it, at $0.001 each, in **800 ms and 636 ms**, with no payment round trip and no settlement. The balance went $0.099 → $0.098;
  - a batch that costs more than the balance ($0.125) was refused with 402 `insufficient_credits`, and the balance was untouched;
  - a malformed token got 401, and an unknown one 402. Neither ever produced an unpaid evaluation.

The token appears in the report only as a SHA-256 prefix.

**v0.6.2: the 2026-10-02 evaluation, checked in production** (commit `c4a5f33`).
- **Single use by what the payer signed:** the replay row above. One authorization sent four ways was evaluated and settled once.
- **Credits:** a request with a misspelled field (`contxt`) was refused with 422 and charged nothing; a real check from credits took 1,024 ms and was charged $0.001 (balance $0.008 → $0.007), with the kit watch's coverage anchor signed.
- **Unpaid requests:** a body that would be refused, a POST with no body and `POST /v1/credits` with no body each got the 402 challenge (the first with `request_error` naming the field); a malformed bearer got 401; preflights and 405s carry the security headers and `Allow`; `jwks.json` publishes only public members.
- **Kit watch:** right after the deploy, both chains `ok` with lag 0, gaps 0 and no reads pending.

**v0.5.3: listed in the x402 Bazaar** (`eval/bazaar.ts`, `bazaar-report.json`).
- **Payments:** a per-call check and a one-item batch were paid through CDP, and each payment carried the `bazaar` discovery extension (method POST). The transactions are in the report.
- **Listing:** CDP's public discovery catalog, 19,196 resources at the time, lists both `https://x402check.xyz/v1/risk-check` and `/v1/risk-check/batch`. Each entry has:
  - service name `x402check` and 5 tags;
  - the icon;
  - the JSON Schema of the body and a callable example;
  - the price on all 7 networks.
- **The first listing** came from the first CDP-settled payment that carried the extension, at 14:33 UTC.
- **Before the Bazaar declaration:** outside our own probes, no agent had called the paid endpoints. Cloudflare analytics for the prior 24 hours showed 14 distinct outside clients hitting them, all with a browser GET (405) or an unauthenticated credits GET (401).

**v0.5.4: listed on x402scan.**
- **Registration:** `registerFromOrigin` read `https://x402check.xyz/openapi.json`, probed each endpoint and registered 3 of 3, with none failed.
- **Validation:** `@agentcash/discovery discover` reports 3 paid x402 routes and no warnings. Those routes cost $0.001–$0.009 for a check, $0.001–$0.225 for a batch, and $0.10–$100 for credits.
- **Before this fix,** the probe got a 422: it sends a POST with no body, and we validated before pricing. A missing favicon check also failed, because HEAD returned 404.

**v0.5.1: Coinbase CDP settles Base, Polygon and Arbitrum.**
- **Settlements:** the per-call check and the credit pack were settled by CDP signers `0xa32ccda9…` and `0x59b7ebc6…`, both published in CDP's `/supported`. They moved 0.0035 and 0.10 USDC from the probe payer to our `pay_to` (transactions in `security-v5-report.json`).
- **Speed:**
  - The per-call check took **3,713 ms** end to end, against 2,709 ms through PayAI in the v0.5.0 run. That is one sample each, not a benchmark.
  - The two checks from credits took 716 ms and 513 ms.
- **Margin:** CDP costs $0.001 per settlement after 1,000 free a month. Base's per-call margin rises from 32% to **69%**. Polygon's rises to 85% and Arbitrum's to 88%.

Routes and margins in production on v0.5.1. They come from `/status`, with PayAI's fees read from its live `/pricing`. Every margin also deducts the model's ~$0.00007.

| Network | Price per call | Facilitator (transfer) | Settlement fee to us | Margin |
|---|---|---|---|---|
| Base | $0.0035 | Coinbase CDP (EIP-3009) | $0.001 (first 1,000 a month free) | $0.00243 (69%); 32% through PayAI in v0.5.0 |
| Polygon | $0.007 | Coinbase CDP (EIP-3009) | $0.001 | $0.00593 (85%) |
| Arbitrum | $0.009 | Coinbase CDP (EIP-3009) | $0.001 | $0.00793 (88%) |
| Avalanche | $0.001 | PayAI (EIP-3009) | $0.0001 | $0.00083 (83%) |
| Sei | $0.002 | PayAI (EIP-3009) | $0.00077 | $0.00116 (58%) |
| Monad | $0.001 | Dexter (Permit2), the only one offering it | $0 (floor $0.00027) | $0.00093 (93%) |
| Solana | $0.002 | Dexter | $0 (floor $0.0013) | $0.00193 (96.5%) |
| **Prepaid credits** | **$0.001 per check** | one settlement per pack | one fee per pack ($0.001 on Base via CDP) | 92% on a $0.10 pack, 93% from $1 |

**Found and corrected in v0.5, by reading the facilitators' terms and paying for real:**
- **The v0.4 unit economics were wrong.**
  - The "~93% margin" counted only the model call.
  - Since 2026-09-21, PayAI bills the receiving merchant each settlement's gas + 30%, separately from the price: $0.00231 on Base. So a $0.001 check paid per call on Base cost more to settle than it earned.
  - v0.5 prices each network above its route's cost. The $0.001 price moves to prepaid credits, where one settlement pays for up to 100,000 checks.
- **Dexter's EVM route is Permit2.**
  - Its fee is zero, but a payer must first grant Permit2 an allowance, and a plain key-only wallet, such as the MCP server's payer, cannot pay through it.
  - Routing now prefers the facilitator every wallet can pay through (EIP-3009), then the lower fee, then the configured order.

The `security:v4` probes cover:
- a poisoning look-alike from the watchlist, observed on Ethereum and evaluated on Base, capped at **20/critical**. `address_poisoning` is signed as `x402check-kit-watch@<scan time>:hit`;
- a wallet delegated to a labelled sweeper, capped at **20**. It is found both by the watchlist and by its current code;
- a Luno deposit address and a BitGo forwarder, now **low**, with the code feeds clear. v0.3 capped both at 30: this is the false positive fixed by the gate;
- a well-known wallet with the kit watch `clear`;
- `/status` reporting the watch's coverage (blocks behind, per chain) without a single address in it.

The watchlist subjects are named in the report only by a SHA-256 prefix.

The `security:v3` probes cover:
- a Forta-fingerprinted drainer contract, on no address list, capped at **30**;
- a real drainer transaction replayed to **20** (hidden recipient, signed in `checks.simulation`);
- a WETH wrap at **88/low**;
- three 422s, discovery and `/status`.

The `security:v2` probes cover:
- OFAC listing → 0/critical with the model skipped;
- MetaMask-listed domain → 20;
- self-asserted "clean" → 30;
- permit to a fresh EOA → 40, and to the Universal Router → 84;
- signed evidence, `payment` and `aud`;
- mainnet-only 402 options, 25 × pricing for a batch, validation before payment;
- an unpaid request gets 402 and no attestation.

**Found and fixed by paying for real:** the paid validation exposed a production failure that the free tier had hidden.
- Dexter, then the first facilitator, publishes gas-cost floors per network. On 2026-09-29 they were $0.0015 on Base, $0.0031 on Polygon, $0.0039 on Avalanche and $0.0061 on Arbitrum, all above the $0.001 price. So it refused **every EVM payment** (`policy:amount_below_floor`).
- EVM payments now settle through PayAI, which verified and settled $0.001 on Base. Solana ($0.002, above a $0.0013 floor) and Monad ($0.0003 floor) stay on Dexter.
- `/status` now reports, per network, the facilitator, its published floor and whether the price clears it. A floor rising above the price can no longer fail silently.

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
npx tsx scripts/kit-catalog.ts && npx tsx scripts/legit-corpus.ts && npx tsx scripts/kit-registry.ts
npx tsx scripts/hunt-kits.ts --chain eip155:1 --hours 24 && npx tsx scripts/hunt-kits.ts --chain eip155:8453 --hours 6
npm run eval:kit-watch -- --sample 40 && npm run eval:kit-watch -- --second-holdout
npx tsx scripts/payai-shadow.ts --days 7
npx tsx eval/guard.ts                        # the signing guard on the simulation run's real transactions (in process, no money)
npx tsx scripts/redact-evidence.ts --check   # no ScamSniffer-only entry in the committed reports
# ↓ against production: every evaluation is paid (funded payer key and credit token in ~/.config/paysol)
PAY_NETWORK=eip155:8453 npm run security:v5    # spends $0.1035: one per-call check and a $0.10 credit pack; reports who settled each
PAY_NETWORK=eip155:8453 npx tsx eval/replay.ts # single-use payments: $0.0035 (three copies of one payment, one settles)
PAY=none npx tsx eval/bazaar.ts              # the Bazaar listing, read-only; without PAY=none it pays two checks ($0.007)
npx tsx eval/mcp-pay.ts                      # one real payment through x402check_pay, to x402check's own pay_to, a trusted payee not checked ($0.0035)
npx tsx eval/pay-guard.ts --n 25 --seed 402  # 25 Bazaar payees checked from prepaid credits ($0.025); nothing paid to them
npx tsx eval/guard-production.ts             # the guard against production, from prepaid credits (~$0.02)
npx tsx eval/solana-guard.ts                 # the Solana guard on a real x402 payment and constructed drain patterns ($0.002 of checks; nothing sent)
npx tsx scripts/verify-attest.ts <jws> --request '<the exact body>' --max-age 300   # verify one attestation, bound to its request
PAY_NETWORK=eip155:8453 npm run security:v2 && PAY_NETWORK=eip155:8453 npm run prod
# security:v3 and security:v4 are historical suites: against another version they stop before paying.
```

Historical meta-evaluations (`audit-report.json`, `crosslabel-report.json`, 2026-09-27) used the same model family to judge its own verdicts. They measure framing stability, not correctness, and are kept for the record.
