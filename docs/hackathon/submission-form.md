# Colosseum submission — portal answers (paste-ready)

Updated 2026-10-06 for v0.6.4. Every number below is in docs/EVIDENCE.md or AGENTS.md §5.

## Project name

x402check

## Brief description (≤ 500 characters, public)

x402check checks the counterparty before an AI agent or wallet pays with x402. It screens OFAC sanctions, phishing and drainer lists, its own live watch of drainer infrastructure, a simulation of the transaction and the content the agent acted on, then returns a signed verdict anyone can verify. Its signing guard decodes Solana and EVM transactions and refuses drains before the key signs. Live on mainnet (Solana + 6 EVM chains), paid per check via x402. Open source.

## Project website (public)

https://x402check.xyz/

## Repository

https://github.com/caiovicentino/jev-risk-check-provider (MIT)

## Blockchains and tools integrated

- **Solana**
  - x402 payments settle on Solana mainnet (USDC, through the Dexter facilitator).
  - The SDK's Solana signing guard (`guardSolanaSigner` in `@x402check/client`) decodes each transaction locally (legacy and v0, with address lookup tables), refuses owner-change drains before the key signs, and checks recipients, delegates and called programs. 4/4 on real inputs.
  - Payers are screened against the OFAC SDN list, including Solana addresses, and a Solana payment must come from the payer's own token account.
  - A shadow analysis of PayAI's Solana settlements (20,925 transactions in a week, 0 OFAC hits in a seeded sample) is published in docs/EVIDENCE.md.
  - Proposed: the Kora fee-payer gate (solana-foundation/kora#682).
- **x402**
  - An x402 `risk-check` provider: every check is paid per call (from $0.001; $0.0035 on Base) or from prepaid credits ($0.001).
  - Payments accepted on Solana, Base, Polygon, Arbitrum, Avalanche, Monad and Sei, routed across Coinbase CDP, PayAI and Dexter.
  - Listed in the x402 Bazaar (Coinbase) and on x402scan.
  - A trust-provider adapter for the proposed x402 trust-provider extension (x402-foundation/x402#2300).
- **Ethereum and Base:** a kit watch that scans every block for EIP-7702 delegations to poisoners and sweepers and for drainer-kit deployments, and transaction simulation (`eth_simulateV1`).
- **Attestations:** ES256 JWS verifiable against `did:web:x402check.xyz`, with a freshness anchor per evidence item: the OFAC release and the SHA-256 of its SDN.XML, the kit watch's coverage, the simulated block.
- **Agents:** an MCP server (`@x402check/mcp`, on npm and the MCP Registry) whose `x402check_pay` pays an x402 resource only after the payee is cleared, and a TypeScript SDK (`@x402check/client`) with an attestation verifier and a signing guard.
- **Stack:** Cloudflare Workers, Durable Objects and KV; TypeSafe AI's Jev model for injected-instruction analysis; TypeScript.

## Teammates

Solo founder: Caio Vicentino (@0xCVYH), solo developer; previous work includes open-source interpretability infrastructure (openinterp.org) and the jev-shield agent-security tool.

## Location

Brazil (remote; GMT-3)

## Pre-existing development disclosure (required by Colosseum rules)

The repository's history documents everything; its first commit (40bb5e4, 2026-09-27) imported the provider core: the wire format, scoring, JWS attestations and the evaluation suite. Upstream engagement (x402 issue #3597, PR comments on #2300 and #2422, Kora issue #682) began alongside it.

Built since, in public, with the commit history as the record:

1. **Production on mainnet** at `https://x402check.xyz` (v0.6.4): paid checks only, per-network prices, prepaid credits, facilitator routing across CDP, PayAI and Dexter, single-use payments, payer screening.
2. **The kit watch:** our own index of drainer infrastructure on Ethereum and Base, scanned every minute, with signed coverage.
3. **The signing guard** for EVM and Solana, and the MCP server with guarded payments.
4. **Freshness anchors** in every attestation, adopted as the shape of the x402 trust-provider discussion.
5. **Three independent security reviews and two full evaluations**, every finding fixed and published, plus a public shadow analysis of a facilitator's real traffic.

## Go-to-market strategy

**Where the money moves:** x402 payments go through facilitators, agent frameworks and catalogs. x402check sits in the payment path in three ways:
- a provider that sellers and facilitators query before settling (the trust-provider extension, #2300);
- a guard that agents run before signing (SDK, MCP server);
- a listed service in the Bazaar and on x402scan.

**Pricing:** every check is paid; there is no free tier. A check costs $0.001 from credits or from $0.001 per call. The margin includes the settlement fee: 69% per call on Base at list price, 98% today inside CDP's free monthly allowance.

**Where we are, honestly:**
- The first outside payments came from two paying monitors ($0.014), not yet from customers.
- The market is early: PayAI settles about $1,450 a week, mostly sub-cent repeat payers.
- We are building the trust layer now, while the spec is still being written.

**Distribution:** x402 Bazaar, x402scan, npm, the MCP Registry, the x402 spec threads (#2300, #3597), and proposals to PayAI (PayAINetwork/docs#98), Kora (#682) and AgentPay (romudille-bit/agentpay#9).

## Evidence (docs/EVIDENCE.md)

- **OFAC-listed addresses:** 24/24 critical. Every listed address the API accepts screens as listed, including the entries OFAC labels with the wrong currency.
- **Drainer permits with the drainer feed switched off:** 27/30.
- **Signing guard on real mainnet transactions:** it refused 22 of 33 drainer transactions that still execute, and none of 84 legitimate ones that simulate.
- **Production regression suite:** 11/11 on v0.6.3. Single use was proven with four spellings of one payment: one evaluation, one settlement.
- **External validation on x402#2300:** two independent participants reproduced our OFAC digest and called our screening method "the only correct read".
- **Published limits:** a plain transfer to a drainer nobody has reported is not detectable from the address alone, and unlisted phishing sites are mostly caught by feeds, not heuristics.

## Why we win this market (the insight)

Red-teaming our own system taught the transferable lesson: **a model that reads a payment description can only catch what the description reveals, and an attacker writes the description.** Our v5 evaluation scored 99–100% on corpora whose text described the risk. With an attacker-written context, the same cases dropped to 20%, and only look-alike domains were still caught.

So x402check puts provider-verified evidence first (the sanctions list, curated feeds, our own kit watch, on-chain facts, simulation) and uses the model where it has signal: injected instructions in the content an agent acted on, which it caught 40/40. Caller claims ("already screened") are recorded as claims and never lower risk. Every verdict is signed and says exactly which checks backed it, with the version of each source, so a relying party can recompute it.
