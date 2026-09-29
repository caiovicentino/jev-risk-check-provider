# Colosseum submission — portal answers (paste-ready)

## Product name

x402check

## Brief description

x402check is a pre-payment risk check for AI agents and wallets on x402. Before an agent pays or a user signs, it checks the counterparty with evidence the provider verifies itself:

- the official **OFAC SDN** list;
- **MetaMask's phishing list** and **ScamSniffer's drainer addresses**;
- **look-alike domain** analysis;
- **on-chain facts**, for example an approval or permit being granted to a plain wallet instead of a contract, the classic drainer pattern.

A typed model (TypeSafe's Jev) reads the content the agent acted on for injected instructions. Caller-asserted mitigations are recorded but can never lower the score. Every verdict is an ES256 attestation, verifiable against `did:web:x402check.xyz`, that states which checks actually ran. It ships as an x402 `risk-check` provider (live on mainnet) plus an open-source MetaMask Snap that decodes the real counterparty of approvals, Permit2 and Seaport signatures.

## Blockchains and tools integrated

- **Solana** (primary; mainnet + devnet USDC settlement live; Solana Foundation Kora paymaster integration proposed — issue #682)
- **x402** (Linux Foundation standard; conformant to the `risk-check` extension spec, proposal #3597) — **USDC settlement live across 10 networks**: Base, Solana, Polygon, Arbitrum, Avalanche, Monad, Sei (mainnet) + Base Sepolia, Arbitrum Sepolia, Solana Devnet
- **Production deployment live**: Cloudflare Workers + dedicated domain (x402check.xyz), free-tier accounting (public `/healthz` counter), DID `did:web:x402check.xyz`
- **TypeSafe AI Jev** via Vercel AI Gateway (also TypeSafe direct API)
- ES256/JWS attestations (RFC 7515) via node:crypto; x402 SDKs for payments; OFAC SDN, MetaMask eth-phishing-detect and ScamSniffer data (see THIRD_PARTY_NOTICES.md)
- TypeScript, Node 22, Cloudflare Workers deploy-ready (fetch-handler architecture)

## Teammates

Solo founder: Caio Vicentino (@0xCVYH) — solo developer; previous work includes open-source interpretability infrastructure (openinterp.org) and the jev-shield agent-security tool (LLM-injection defense with Jev).

## Location

Brazil (remote; GMT-3)

## Pre-existing development disclosure (required by Colosseum rules)

Work completed before the hackathon window (disclosed per Colosseum eligibility rules):

- The `jev-risk-check-provider` core (wire format, scoring, JWS attestations, demo) and its evidence suite were built before the hackathon start (Sep 14). Repository history and commit dates document this transparently: github.com/caiovicentino/jev-risk-check-provider (commits 40bb5e4 → aa25bb1, dated 2026-09-27).
- Upstream engagement (x402 issue #3597, PR comments #2300/#2422, Kora issue #682, awesome-jev PR #293) also predates the window and is disclosed here.

Work completed **during** the hackathon window (what we're asking judges to evaluate, per the rules):

1. **Live public deployment** — `https://x402check.xyz`, live on 2026-09-28: `did:web:x402check.xyz` identity (DID document + stable JWKS, round-trip verified), x402 paywall with free tier (25/day) and **mainnet USDC settlement (Base + Solana, plus Polygon, Arbitrum, Avalanche, Monad, Sei)** via the Dexter facilitator (gas-sponsored, zero facilitator fee), and a public landing page with integration docs.
2. Real-facilitator traffic shadowing (moving the evidence base from synthetic corpora to live x402 facilitator traffic).
3. Human-verified labels completing the repository's switch-over gate (≥50 verified checks).
4. Kora `decision_provider` integration advancing through the accepted-issue process.
5. Go-to-market execution: distribution (directory listings, X engagement, x402 community), demand conversations with facilitator operators, and this submission's positioning work.

## Go-to-market strategy

**Wedge**: the x402 facilitator ecosystem. Facilitators (PayAI, Corbits, Coinbase, and the ~22K seller ecosystem) face the charge-then-deny problem the `risk-check` extension solves; we are the first provider with signed-intent verdicts they can plug in via one discovery URL. Solana carries ~70% of x402 monthly volume — the facilitator layer here is concentrated and reachable.

**Distribution** (live): x402-foundation proposal + PR engagement (issues/PRs linked above), Solana Foundation Kora proposal, Jev ecosystem directories (awesome-jev PR #293; jev.directory submission queued), X (@0xCVYH, 3.4k crypto/AI-following audience).

**Monetization**: open-source provider (MIT) + paid tiers on the evidence layer — compliance-grade signed decision logs for PSPs and financial institutions (the segment paying for agent-payment infrastructure today: Fireblocks-style buyers), and volume-based API pricing for hosted risk-check above free tier. Land in the open ecosystem, monetize the audit trail.

**Evidence to date** (docs/EVIDENCE.md, externally grounded labels):

- OFAC-listed addresses: 24/24 critical.
- Drainer permits with the drainer feed switched off: 27/30.
- 0 false positives on well-known contracts and top dApps.
- 5 of the Tranco top 200k domains capped.
- Production: 53/53 checks correct with 53/53 attestations verified; 12/12 v0.2.0 security probes.
- Published limits: plain transfers to unreported drainers are not detectable from the address alone, and unlisted phishing sites are mostly caught by feeds, not heuristics.
- Upstream: the x402 trust-provider extension author named the payer-intent slot in PR #2300, and there is active maintainer engagement.

## Why we win this market (the insight)

Red-teaming our own system taught the transferable lesson: **a model that reads a payment description can only catch what the description reveals, and an attacker writes the description.** Our v5 evaluation scored 99–100% on corpora whose text described the risk. With an attacker-written context, the same cases dropped to 20%, and only look-alike domains were still caught.

So x402check puts provider-verified evidence first (sanctions list, curated feeds, on-chain facts, domain analysis) and uses the model where it actually has signal: injected instructions in the content an agent acted on, which it caught 40/40. Caller claims ("already screened") are recorded as claims and never lower risk. That turns a demo into an auditable control, and the attestation says exactly which checks backed each verdict.
