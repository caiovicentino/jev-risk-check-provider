# x402check — strategy

## Mission

Be the risk agency that agents and wallets can trust **because every verdict can be checked**. Each verdict comes with its evidence, its sources and their dates, and its measured error rates. Nothing rests on reputation alone.

## Position

AI agents and wallets move money after a decision that happens in software, and nobody reviews it. Today's controls answer only part of the question:

- **Allowlists and spend caps** check structure, not intent.
- **Compliance vendors** screen addresses, but they are closed and built for exchanges, not for a payment an agent is about to sign.
- **Wallet security vendors** simulate transactions, but their verdicts cannot be verified and their accuracy is not published.

x402check brings these together at the moment before a payment or signature. It answers three questions:

1. Who is the counterparty?
2. What will this transaction or signature actually do?
3. Was the agent manipulated into doing it?

Every answer comes back as a signed attestation that a merchant, a facilitator, an auditor or the user can check independently.

## Principles (non-negotiable)

1. **Evidence before verdicts.** Deterministic, provider-verified facts go first: lists, simulation, on-chain state. The model is used only where it has signal, which is content the agent acted on.
2. **Claims are not evidence.** Anything the caller asserts is recorded as `asserted` and can never lower risk.
3. **Every verdict is scoped and signed.** The attestation records the checks that ran, their sources and dates, the payment and interaction it covers, and a unique id.
4. **Measured, published limits.** Every claim cites a reproducible evaluation. Labels come from sources we did not write. Held-out samples have never been seen during development, and negative results are published too.
5. **Fail-closed and honest UX.** If a check cannot run, the answer is "not verified", never "all clear".

## Architecture of a verdict

| Layer | Question | Sources (today → next) |
|---|---|---|
| Counterparty intelligence | Is this address or site known to be bad? | OFAC SDN (same-key cross-encoding, refreshed daily), MetaMask phishing list (refreshed daily), ScamSniffer, look-alike analysis, contract verification (Blockscout), drainer-kit code fingerprints (gated against legitimate code), **the kit watch: our own block-by-block record of EIP-7702 poisoners, sweepers and forwarders, and new drainer-kit deployments** → funding-source analytics, lead time over the public lists |
| Interaction intelligence | What will this do to the user's assets? | decoding of calldata and typed data (Snap), approval-to-EOA rule, **transaction simulation (`eth_simulateV1`): net asset movements, approvals granted, value forwarded to undisclosed wallets or parked in unverified contracts** → historical replay for evaluation (archive state) |
| Content intelligence | Was the agent manipulated? | Jev typed questions over the content the agent acted on |
| Attestation and transparency | Can anyone verify this verdict? | ES256 JWS, `did:web`, JCS input hash, `checks`/`asserted`, public rulebook (`METHODOLOGY.md`), live data freshness (`/status`) → public verdict transparency log |

## Business model

Every evaluation is paid; there is no free tier. The unit economics are set by what settling a payment costs, not by the model.

- **Prepaid credits (the product we steer to):** one x402 payment buys a balance ($0.10–$100). Each check then costs **$0.001**, or $0.005 when a transaction is simulated, with no payment round trip.
  - Our cost per check is one model call, about $0.00007, plus a share of one settlement: on a $1 pack settled through CDP, about $0.000001 per check.
  - Margin: **about 93%**.
- **Per call:** x402 exact, priced by payment network so that each price clears the cost of its route. Margins are measured live (`/status` → `payments`):
  - **Base: $0.0035, 69%** through Coinbase CDP ($0.001 per settlement after 1,000 free a month). Through PayAI, which bills gas + 30% (about $0.0023), it was 32%.
  - Solana: $0.002, 96%. Dexter sponsors the gas.
  - Avalanche: $0.001, 83%.
  - Sei: $0.002, 58%.
  - Polygon: $0.007, 85% (CDP).
  - Arbitrum: $0.009, 88% (CDP).
  - Monad: $0.001, 93%.
- **Why settlement dominates:** every x402 exact payment is an on-chain transaction.
  - PayAI's EIP-3009 route, which any wallet can pay without gas, costs us gas + 30% per settlement (since 2026-09-21).
  - Dexter's route is free to us, but on EVM networks it settles only through Permit2, which most payers cannot use without an on-chain approval. Routing therefore prefers what every payer can pay, then what is cheapest.
  - A single price of $0.001 per call would lose about $0.0014 per check on Base. The earlier "~93% margin" counted only the model cost; this corrects it.
- **The price is also the anti-abuse control:** nothing is evaluated without payment. A per-call attestation is released only after the payment settles, and a payment buys one evaluation: a copy of it is refused (v0.6.0). A check paid from credits is refunded when no verdict is produced. Unpaid requests to paid routes are rate-limited per IP.
- **Operational risk:** facilitators change fees and floors. PayAI switched to cost-plus on 2026-09-21. The router re-routes every 10 minutes from PayAI's live fee table, Dexter's floors and CDP's reachability. `/status` shows every route's margin and whether each facilitator answers, so a change is visible the day it happens.
- **Three facilitators, no single point of failure.** CDP (Base, Polygon, Arbitrum), PayAI (Avalanche, Sei, and a fallback for every EVM network) and Dexter (Solana, Monad).
  - If CDP rejects our key or goes down, PayAI takes its networks back, at a lower margin.
  - PayAI's lifetime free allowance (1,000 credits per receiving wallet) now covers only its small Avalanche and Sei fees.

## Distribution

The same API reaches everyone who moves value: x402 facilitators and resource servers (the `risk-check` extension), wallets (the MetaMask Snap and plain HTTP), and AI agents (an MCP server and a TypeScript SDK).

## Roadmap

- **v0.3 (shipped)**
  - Transaction simulation with asset-flow rules, measured on real drainer transactions.
  - Drainer-kit code fingerprints, measured held out (cross-source and temporal).
  - Contract verification signal.
  - OFAC and MetaMask refreshed daily without a redeploy (verified runtime swap).
  - MCP server and SDK for agents.
  - Public rulebook (`METHODOLOGY.md`) and a live data-status endpoint (`/status`).
  - CI on every push.
- **v0.4 (shipped)**
  - **The kit watch.** Our own intelligence: every Ethereum and Base block is read. It covers EIP-7702 poisoners (look-alikes), sweepers and forwarders (compromised wallets), and drainer-kit deployments. A 24 h backfill on Ethereum flagged 6,831 addresses, none of them on ScamSniffer's list; that list publishes with a 7-day delay, so the lead time is not yet measured. It closes the 0/30 gap for those two kinds of wallet.
  - **A collision gate on every code set.** It found and fixed a v0.3 false positive: exchange deposit fleets that a list labels as phishing.
  - **A shadow of real facilitator traffic.** Seven days of PayAI-settled payments on Base were replayed from public data.
- **v0.5 (shipped)**
  - Prepaid credits, per-network prices, and facilitator routing across Coinbase CDP, PayAI and Dexter.
  - Listings: the x402 Bazaar, x402scan (`/openapi.json`) and the MCP Registry.
  - **The signing guard** (`@x402check/client/guard`): an agent's key signs only after a verified allow bound to the exact request. EVM first, then Solana signers.
  - **Guarded x402 payments** (`x402check_pay` in the MCP server): the payee is checked right before signing, and a `warn` goes to the user.
- **v0.6 (shipped): the audit release**
  - A full multi-agent audit (security, payments, operations, supply chain, evidence); every finding code can fix, fixed.
  - Single-use payments, payer screening, a checked attestation key with overlapping-`kid` rotation, HTTPS only, rate limits, logs and settlement records.
  - A model canary (the gateway's alias has no pinned revision) and an automated ScamSniffer refresh into KV.
  - Gated deploys (`scripts/deploy.sh`), pinned tooling, SHA-pinned CI and Dependabot.
  - Evidence restated with clear denominators and corrections.
- **Next**
  - Guard phase 3: custody-level enforcement (a co-signer, a smart-account module that checks the attestation on-chain, the Kora fee-payer gate).
  - A paid `x402check_pay` run against a third-party resource: so far the one real payment went to x402check itself.
  - The kit watch's lead time over the public lists; factory (CREATE2) deployments; more chains.
  - A continuous facilitator shadow: a weekly report, and an inline, log-only integration.
  - Agent-framework integrations (AgentKit, Vercel AI SDK, ElizaOS).
  - A Snap that pays from credits; then publish it and seek allowlisting.
  - KMS custody for the attestation key; AP2 `RiskPayload`.
  - A published latency distribution (p50/p95, credits and per call).
- **Later**
  - A public verdict transparency log (Merkle).
  - Weekly threat reports generated from feed deltas.
  - SLAs for paid tiers.

## North-star metrics

Published in `docs/EVIDENCE.md` unless noted.

- **Recall on held-out, externally labelled threats**, by class (sanctioned, known phishing, drainer interactions, unknown drainers).
- **False-positive rate** on well-known contracts, top dApps and the Tranco top 200k.
- **Latency.** Not yet published as a distribution: single samples so far give 0.5–0.8 s from credits and 2.7–4.7 s per call, where the on-chain settlement dominates. The earlier target, p95 under 3 s, holds for checks paid from credits; per call it cannot, because of the settlement.
- **Data freshness**: age of every list at verdict time (live in `/status`).
- **Integrations** live: facilitators, wallets and agent frameworks.

## What we will not do

- Sell a model score without the evidence behind it.
- Claim coverage we have not measured.
- Treat a caller's word as verification.
- Present a sanctions screen as a compliance program: it covers direct listing only.
