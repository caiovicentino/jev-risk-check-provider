# Colosseum submission — portal answers (paste-ready)

## Product name

x402check

## Brief description

x402check is the signed-intent layer for agent payments. AI agents increasingly pay with wallets, but the industry's controls — spend caps, allowlists, signed mandates — check transaction *structure*, never *intent*: whether the payment corresponds to what the user authorized, or whether the payment context carries a prompt injection. x402check evaluates intent with a typed-decision model (TypeSafe's Jev, a System One model), enforces evidence policy in deterministic code, and issues every verdict as an ES256-signed attestation verifiable against a public JWKS. It ships as an x402 `risk-check` provider (conformant to the live extension proposal) plus an agent-side counterparty gate, both demonstrated end-to-end on Solana.

## Blockchains and tools integrated

- **Solana** (primary; mainnet + devnet USDC settlement live; Solana Foundation Kora paymaster integration proposed — issue #682)
- **x402** (Linux Foundation standard; conformant to the `risk-check` extension spec, proposal #3597) — **USDC settlement live across 10 networks**: Base, Solana, Polygon, Arbitrum, Avalanche, Monad, Sei (mainnet) + Base Sepolia, Arbitrum Sepolia, Solana Devnet
- **Production deployment live**: Cloudflare Workers + dedicated domain (x402check.xyz), free-tier accounting (public `/healthz` counter), DID `did:web:x402check.xyz`
- **TypeSafe AI Jev** via Vercel AI Gateway (also TypeSafe direct API)
- ES256/JWS attestations (RFC 7515), node:crypto only — zero runtime dependencies beyond the AI SDK
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

**Demand validation to date**: 2,200+ provider decisions across independent evaluation layers with zero false positives on benign traffic; **53/53 production checks against the live public endpoint with every attestation verified against the public JWKS; 20/20 security probes passed** (injection resistance, quota-integrity, payment-protocol hygiene); upstream recognition: the x402 trust-provider extension author publicly named the payer-intent slot ("jev's payer-intent scoring") in PR #2300; active maintainer engagement on the x402 spec discussions; inbound interest pending the public deployment (measured: directory listing click-through, facilitator sandbox signups — targets set for the window).

## Why we win this market (the insight)

Red-teaming our own system produced a transferable principle: **claims of legitimacy require structured evidence; prose claims are unverified by default.** Chat-model judges trust prose ("already screened, proceeding as usual" — 27/27 approved by GPT-4.1-mini in our cross-rater study); x402check holds them as unverified claims by design. This distinction maps directly onto AP2's "verifiable intent, not inferred action" — and it's the difference between a demo and an auditable control system.
