# Changelog

Each release's full notes and evidence are on the [releases page](https://github.com/caiovicentino/jev-risk-check-provider/releases). Measurements are in [docs/EVIDENCE.md](docs/EVIDENCE.md), and every verdict rule is in [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## v0.5.2 — 2026-09-30

- **Coinbase CDP is active in production.**
  - Base, Polygon and Arbitrum now settle through CDP. On Base, the per-call margin went from 32% to **69%**.
  - PayAI keeps Avalanche and Sei, and stays the fallback for every EVM network.
- **`/status` → `facilitators` lists the settlement signers each facilitator publishes.** CDP's list needs our key to read, so `/status` is where anyone can check on-chain which facilitator settled a payment.
- **Measured in production** (Worker `08c5a2f6`, `docs/EVIDENCE.md` §7):
  - `security:v5` passed **11/11**;
  - the per-call check and the $0.10 credit pack were both settled by CDP signers, matched against CDP's published list;
  - `eval/security-v5.ts` attributes each settlement through `/status`.
- **Site:** a "v0.5.1" news row; the settlement row names each network's facilitator.

## v0.5.1 — 2026-09-30

- **Coinbase CDP as a facilitator** (`deploy/cdp.ts`), active once the owner's CDP Secret API Key is set as the Worker secrets `CDP_API_KEY_ID` and `CDP_API_KEY_SECRET`.
  - **Authentication:** every call carries the JWT that `@coinbase/x402` would build: ES256 or EdDSA, bound to the endpoint, valid 120 s, with a fresh nonce. It is made with WebCrypto, so the Worker needs no SDK.
  - **Key formats:** the portal's Ed25519 keys, and EC keys in PKCS#8 or SEC1 PEM.
  - **Routing:** CDP costs $0.001 per settlement after 1,000 free a month, against PayAI's gas + 30%. It takes the networks where it is cheapest: Base, Polygon and Arbitrum. On Base, the margin at $0.0035 rises from 32% to 69%.
  - **Fallback:** a key CDP rejects drops it from routing, and PayAI takes those networks back.
  - **`/status` → `facilitators`:** whether each configured facilitator answers, and the mainnets it offers. Only an HTTP status is shown, never a key.
- **Site:**
  - the hero states the kit watch and the prices, and the attestation card matches the current claims;
  - a "what's new" strip;
  - a **live kit-watch counter** built from `/status` aggregates. The watchlist stays private;
  - the integration example buys credits and then checks with the token;
  - a new social preview (`og.png?v=0.5`) with the kit watch and the current prices;
  - the top bar no longer overflows on phones.

## v0.5.0 — 2026-09-30

- **Prepaid credits:**
  - `POST /v1/credits {"amount_usd": 1}` is paid once via x402 ($0.10–$100) and returns a token (`x402c_…`).
  - With `Authorization: Bearer <token>`, every check costs **$0.001** ($0.005 simulated), with no 402 round trip and no on-chain settlement per call.
  - Balances live in a Durable Object (`CreditLedger`), so a debit is atomic and can never overdraw. A settlement credits once, however often its response is replayed. A check that produces no verdict is refunded.
  - `GET /v1/credits` returns the balance.
  - The SDK (`creditToken`, `buyCredits`, `creditBalance`) and the MCP server (`X402CHECK_CREDIT_TOKEN`) support credits.
  - Still no free tier: credits are prepaid.
- **Per-call prices by payment network**, each above the cost of settling it. Base **$0.0035**, Solana $0.002, Sei $0.002, Avalanche $0.001, Monad $0.001, Polygon $0.007, Arbitrum $0.009. A simulated item costs $0.005, or the network's price when that is higher.
- **Fix (economics): the flat $0.001 lost money on EVM networks.** Since 2026-09-21 PayAI bills the receiving merchant gas + 30% per settlement (Base ≈ $0.0023), so a $0.001 check on Base cost us about $0.0014. The earlier "~93% margin" counted only the model call.
- **Facilitator routing by compatibility and cost:**
  - Each network settles through a facilitator that accepts the price and that every payer can pay through. PayAI's EIP-3009 is gasless for any wallet; Dexter's EVM route needs a Permit2 allowance, and our own payer wallet had none.
  - Among those, the router takes the facilitator cheapest to us, from PayAI's live fee table and Dexter's floors.
  - `/status` → `payments` shows each route's facilitator, transfer method, fee and margin.
- The discovery document publishes `amounts_by_network` and the `credits` terms.
- **Measured in production** (Worker `d9030314`, `docs/EVIDENCE.md` §7):
  - `security:v5` **9/9 PASS**: the price table, the routes and margins, a per-call check on Base, a $0.10 pack, checks from credits, refusals;
  - `security:v2` **12/12 PASS**, re-run on v0.5;
  - a per-call check on Base took **2.7 s** end to end (402, payment, evaluation, settlement), and a check from credits **0.64–0.80 s**.

## v0.4.0 — 2026-09-29

- **Kit watch: our own intelligence on drainer infrastructure.** A Worker cron reads every new Ethereum and Base block, once a minute (`src/kit-watch.ts`, `deploy/kit-watch.ts`).
  - **EIP-7702 delegations.** Each delegate is classified once:
    - an **address-poisoning executor** (the "Poisoner" that Wintermute exposed, or any deployment of its template);
    - a **sweeper** that ScamSniffer-listed wallets delegate to;
    - by **behaviour**: 0.01 ETH is sent (simulated) to a wallet that delegates to it, and a delegate that passes it on is a **forwarder**.

    Every wallet that delegates to one of these is recorded, and so is where a forwarder sends what it receives (plain wallets only).
  - **New contracts** are matched against drainer-kit families by exact or **template** fingerprint. The template zeroes immutables and hard-coded addresses, so a redeployment that changes only the operator's wallet is still recognized.
  - **At evaluation time:** the subject, and the recipients, spenders and called contract of a simulated transaction, are checked against the watchlist; the code the subject runs now is checked against the families.
  - **Caps and categories:**
    - look-alike → **20**, `address_poisoning`;
    - wallet delegated to a labelled sweeper → **20**, `compromised_wallet`;
    - kit contract, kit deployer or labelled sweeper destination → **30**, `known_drainer_code` / `drainer_operator`;
    - forwarder with no label (or its destination) → **40**, `auto_forwarding_wallet` / `drainer_operator`.
  - Signed as `x402check-kit-watch@<scan time>:<status>` in `checks.feeds`; details in `evidence.kit_watch`.
- **Backfill (same code as the cron):**
  - **Ethereum, 24 h:** 6,831 addresses flagged, **none of them on ScamSniffer's public list**: 6,232 poisoning look-alikes, 575 wallets delegated to sweepers or forwarders, 24 destinations. Of 1,254 new contracts, 0 matched an old drainer-kit family.
  - **Base, 6 h:** 226 addresses flagged; no poisoner activity. Of 1,712 new contracts, 0 matched an old kit.
  - Poisoner audit: 27 of 37 sampled look-alikes were confirmed by a victim's history (a lower bound). The executor obeys only its operator, so every delegated wallet is operator-controlled anyway.
  - Negative result: template fingerprints recognized no additional listed drainer (40/82 either way).
  - Details and the audit methods are in `docs/EVIDENCE.md` §0.
- **Fix: a false positive in production since v0.3.** Forta labels single deposit addresses of exchange fleets as phishing, because they received phishing proceeds: Luno's deposit forwarder, a Poloniex deposit contract, BitGo's `Forwarder` and the Mist multisig. Their code is the fleet's standard contract, so the v0.3 code set flagged **every deposit address of those fleets** as drainer code (cap 30). The v0.3 figure "0/9,625" came from a corpus that contained none of them.
  - Every code set and kit family now passes a **collision gate** against code in legitimate use (`scripts/legit-corpus.ts`).
  - The four fleets are guarded explicitly.
  - Forta contracts from before 2021 no longer seed a set. All four collisions came from them, and dropping them costs no recall.
  - On held-out legitimate code, before the fix: 16/2,500 on Ethereum.
  - After the fix, on a second held-out set: 0 false positives among 1,737 (Ethereum) and 2,935 (Base) contracts. Its only match was a real `SecurityUpdates` drainer on no public list.
  - The embedded Forta set went from 46 to 27 fingerprints. Confirmed in production: a Luno deposit address and a BitGo forwarder now score low.
- **Fix, found while building the catalog:** the delegates of ScamSniffer-listed EIP-7702 wallets were never fingerprinted. Only the listed addresses' own code was, so a wallet delegated to a known sweeper was not caught by code. 7 sweeper families that forward what they receive now seed the watch.
- **Operations:** the cron needs Workers Paid. It uses about 250 ms of CPU per run, and the Free plan's 10 ms ends in `exceededCpu`; evaluations are unaffected. `limits.cpu_ms` is set in `wrangler.toml`.
- **PayAI shadow (public data):** 7 days of PayAI-settled payments on Base were replayed through the deterministic layers: 3,132 payments, 207 payees and 226 payers, with 0 flagged. Checking every payment would have cost $3.13. The report is `eval/evidence/payai-shadow-report.json`.
- `/status` → `data.kit_watch` reports coverage (lag, gaps) and counts per kind, never addresses. The discovery document lists the `kit_watch` signal.
- The block scan runs on its own RPC endpoints (`SCAN_ENDPOINTS`), so its volume (~20 GB a day) cannot rate-limit a paid evaluation.
- **SDK:** it knows the four new categories and validates `evidence.kit_watch` before display. The labelled kinds block whatever the tier.

## v0.3.2 — 2026-09-29

- **Differentiated pricing.** An evaluation whose transaction is simulated costs $0.005 on every network. Other evaluations stay at $0.001 ($0.002 on Solana).
  - The simulation price applies only when the simulation actually runs: a supported chain, with simulation enabled.
  - A batch is billed per item.
  - The discovery document states both prices (`amount`, `amount_with_transaction`).
- **Validated in production:** the 402 challenges for a simulated item and a mixed batch are checked. Two simulated evaluations settled at 0.005 USDC each on Base.

## v0.3.1 — 2026-09-29

- **Fix: EVM payments were refused.** Dexter publishes gas-cost floors per network, and they were above the $0.001 price on Base, Polygon, Arbitrum and Avalanche. EVM payments now settle through PayAI; Solana and Monad stay on Dexter.
- `/status` → `payments` reports each network's facilitator, its published floor and whether the price clears it.
- Production probe reports record x402 settlement receipts (tx hashes).
- **Paid validation in production:**
  - `prod`: 53/53 correct and 53/53 attestations verified;
  - `security:v2`: 11/11;
  - `security:v3`: 8/8.

## v0.3.0 — 2026-09-29

- **Transaction simulation.** `eth_simulateV1` runs on Ethereum, Base, Polygon, Arbitrum, Optimism and BSC. It reports net asset movements and the approvals granted, and adds these findings:

  | Finding | Cap |
  |---|---|
  | Hidden recipient | 40; 75 with review through a verified forwarder |
  | Payee receives more than declared | 40 |
  | Assets parked in an unverified contract | 55 |
  | Approval to a plain wallet | 55 |
  | Incomplete simulation | 75 with review |

  - **Measured:** 18/25 real drainer interactions that still move assets were flagged, and 0/84 legitimate transactions.
- **Drainer-kit code fingerprints.** Metadata-stripped logic code is compared with contracts listed by Forta (embedded) and ScamSniffer (runtime), following EIP-7702 delegations and proxies.
  - **Measured:** 43/100 listed contracts recognized at creation, with 0 collisions among 9,625 legitimate contracts.
- **Contract verification** (Blockscout, proxy-aware) and **per-chain fallback RPCs**.
- **`request_hash`:** a client-recomputable binding of the exact request.
- **Fail-closed review floors** when on-chain facts or the simulation are unavailable. `checked: false` responses carry a `reason`.
- **Daily OFAC and MetaMask refresh without a redeploy,** from an Ed25519-signed manifest. `GET /status` shows data freshness.
- **No free tier:** every evaluation is paid per call via x402.
- **Packages:** `@x402check/client` (SDK) and `@x402check/mcp` (an MCP server that pays per check). Neither is published to npm yet.
- **Snap 0.3.0:** the simulation UI is kept behind a flag. The Snap cannot pay yet, so this version sends nothing and has no network permission.
- **Review:** all 11 findings of an independent adversarial review are fixed (`test/review-v03.test.ts`).
- **Docs:** `docs/METHODOLOGY.md` is new.

## v0.2.0 — 2026-09-29

- **Rebuild around provider-verified evidence:**
  - OFAC SDN screening, with the same key caught across encodings;
  - MetaMask and ScamSniffer feeds;
  - public-suffix-aware look-alike analysis;
  - the approval-to-plain-wallet rule.
- **Attestation:** `checks` and `asserted` are kept separate; `payment`, `interaction` and `jti` bind the verdict; `input_hash` uses RFC 8785 canonical JSON.
- **Evaluation with external labels and held-out seeds,** replacing the v0.1 numbers measured on self-describing corpora.
- **Snap 0.2.0:** it decodes the real counterparty and interaction type.

## v0.1 — 2026-09-27

- **First x402 `risk-check` provider:** TypeSafe Jev typed questions, ES256 attestations and `did:web:x402check.xyz`.
- **Evaluation corpora:** shadow, scale, red-team and chat-judge benchmark. They were later found to describe their own risk; see v0.2.0.
