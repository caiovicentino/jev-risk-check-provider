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
| Counterparty intelligence | Is this address or site known to be bad? | OFAC SDN (same-key cross-encoding, refreshed daily), MetaMask phishing list (refreshed daily), ScamSniffer, look-alike analysis, contract verification (Blockscout), **drainer-kit code fingerprints** → 7702 sweeper detection, funding-source analytics |
| Interaction intelligence | What will this do to the user's assets? | decoding of calldata and typed data (Snap), approval-to-EOA rule, **transaction simulation (`eth_simulateV1`): net asset movements, approvals granted, value forwarded to undisclosed wallets or parked in unverified contracts** → historical replay for evaluation (archive state) |
| Content intelligence | Was the agent manipulated? | Jev typed questions over the content the agent acted on |
| Attestation and transparency | Can anyone verify this verdict? | ES256 JWS, `did:web`, JCS input hash, `checks`/`asserted`, public rulebook (`METHODOLOGY.md`), live data freshness (`/status`) → public verdict transparency log |

## Business model

Every evaluation is paid per call via x402: $0.001 in USDC, $0.002 on Solana, with a batch billed per item. There is no free tier.

- The price is the product: an agent or wallet pays for a signed, evidence-backed verdict at the moment it matters.
- The price is also the anti-abuse control: nothing is evaluated without settlement, and the attestation is released only after the payment settles.
- Partners get the same per-call economics through x402. Volume pricing is on the roadmap, not a free tier.
- **Operational risk:** facilitators can set gas-cost floors above the price. Routing picks a facilitator that settles at our price, and `/status` exposes each network's floor so a rising floor is visible immediately.

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
- **v0.4**
  - Shadow real facilitator traffic.
  - Real-time drainer intelligence for plain transfers, the measured 0/30 gap.
  - EIP-7702 sweeper detection: 30 of the 2,530 ScamSniffer-listed addresses are delegated accounts.
  - Automated ScamSniffer refresh into KV.
  - KMS custody and key rotation.
  - Publish the Snap and seek allowlisting.
  - AP2 `RiskPayload`.
- **v0.5**
  - A public verdict transparency log (Merkle).
  - Weekly threat reports generated from feed deltas.
  - SLAs for paid tiers.

## North-star metrics (all published in `docs/EVIDENCE.md`)

- **Recall on held-out, externally labelled threats**, by class (sanctioned, known phishing, drainer interactions, unknown drainers).
- **False-positive rate** on well-known contracts, top dApps and the Tranco top 200k.
- **p95 latency**, which must stay under 3 s.
- **Data freshness**: age of every list at verdict time.
- **Integrations** live: facilitators, wallets and agent frameworks.

## What we will not do

- Sell a model score without the evidence behind it.
- Claim coverage we have not measured.
- Treat a caller's word as verification.
- Present a sanctions screen as a compliance program: it covers direct listing only.
