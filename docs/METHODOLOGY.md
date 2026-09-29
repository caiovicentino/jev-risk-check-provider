# How x402check forms a verdict

This is the complete rulebook for turning a request into a signed verdict: the evidence the provider collects, the rules applied to that evidence, and how the result is attested. Strategy and principles are in [`STRATEGY.md`](STRATEGY.md). Measured accuracy, with confidence intervals, is in [`EVIDENCE.md`](EVIDENCE.md).

## 1. Inputs

| Field | Meaning | Trust |
|---|---|---|
| `wallet` | The counterparty (the subject), as an EVM, Solana, Bitcoin-family or Tron address, optionally in CAIP-10 form | the subject of the verdict |
| `chain` | CAIP-2 or alias (`base`, `solana`…) | must agree with CAIP-10 and `payment.network` (else 422) |
| `domain` | The site or origin involved | analysed by the provider |
| `context` | Content the agent acted on (page text, tool output, instructions) | input to the model; never trusted as a claim |
| `payment` | The x402 payment being made (`pay_to`, `amount`, `asset`, `network`) | bound into the attestation |
| `interaction` | `token_approval`, `nft_approval`, `permit_signature`, `native_transfer`… | decides which rules apply |
| `transaction` | EVM `{from, to, value, data}` to simulate (needs an `eip155` chain) | simulated by the provider |
| `screening`, `authorization` | The caller's own screening result or pre-authorization | **asserted**: recorded, can only raise risk |

## 2. Evidence, in order

Evidence is collected by the provider itself. Nothing the caller asserts counts as evidence.

1. **OFAC SDN screen** (`src/sanctions.ts`). Exact match on the canonical address, then on the 20-byte hash it encodes, so the same key in another encoding matches (BCH legacy ↔ cashaddr, BTC P2PKH ↔ P2WPKH, TRX ↔ EVM). Checksums are enforced. A listing is final: score 0, tier critical, and no model call. Scope: direct listing only.
2. **Domain analysis** (`src/domain-analysis.ts`). Public-suffix-aware parsing, punycode and homoglyph detection, typosquats of brands (7 or more characters), brand plus lure keyword, and an official domain used as a subdomain of another site.
3. **Threat feeds** (`src/threat-intel.ts`):
   - MetaMask eth-phishing-detect domains, matched on the host and its parents down to the registrable domain, with MetaMask's own allowlist applied;
   - ScamSniffer domains (exact host) and EVM addresses.
4. **On-chain facts** (`src/onchain.ts`). Whether the subject is a contract, its nonce and balance ("unused address"), and its code classification. EIP-7702 delegated accounts are EOAs. Every chain has a primary and a fallback public RPC under one time budget (`src/rpc.ts`).
5. **Drainer-kit code fingerprints** (`src/code-fingerprint.ts`).
   - **What is classified:** the subject's runtime code, and in a simulated transaction the called contract, recipients and spenders.
   - **What gets a fingerprint:** only *logic* code, as the SHA-256 of the bytecode with the compiler-metadata trailer removed. Token, NFT, delegating (DELEGATECALL/CALLCODE) and very small (<100-byte) code is never fingerprinted itself, because countless legitimate contracts share it (a fake-token clone has exactly the real token's code).
   - **Indirection:** matching follows one level of it, to the code an address actually runs: an EIP-7702 delegate, an EIP-1167, Safe or EIP-1967 proxy implementation, or an address hard-coded in delegating code.
   - **Reference sets:** fingerprints are compared with those of contracts listed by Forta's labelled datasets (embedded) and ScamSniffer (runtime).
   - **Guard:** any listed fingerprint identical to a widely used implementation is dropped at build time. These include the MetaMask 7702 delegator, the Safe singletons, Coinbase Smart Wallet, the 4337 EntryPoints, Permit2 and Multicall3.
6. **Transaction simulation** (`src/simulation.ts`). The transaction is replayed with `eth_simulateV1` and `traceTransfers` on Ethereum, Base, Polygon, Arbitrum, Optimism or BSC, against the latest block.
   - **Sender balance:** it is set to the value plus 0.1 ETH. The question is what the transaction does, not whether the sender can afford it, and a plausible balance gives a contract nothing to detect.
   - **Asset movements:** Transfer, Approval, ApprovalForAll, ERC-1155, WETH and Permit2 logs are reduced to net movements, in linear time and under caps on response size, logs and flows. Value routed through the called contract is attributed to its final recipient.
   - **Classification:** every recipient and spender is classified as a contract or a plain wallet, largest first, up to 40.
   - **What the user named:**
     - the payee (`payment.pay_to`), limited to `payment.asset` and `payment.amount` when those are machine-checkable;
     - a recipient named in the top-level call (`transfer`, `transferFrom`, `safeTransferFrom`), for the called token and amount only;
     - the subject, for any asset, unless a payee scope names it more precisely;
     - the native value sent to the called address.
7. **Contract verification** (`src/contract-intel.ts`).
   - **Source:** Blockscout source-verification status. "Not verified" is cached for 10 minutes; "verified" for 24 hours.
   - **When:** only when the user grants a contract control over assets, when assets are parked in a contract, or when a contract forwards them to an undisclosed wallet.
   - **Proxies and delegated accounts:** an exact forwarding proxy (Safe, EIP-1167, minimal EIP-1967) and a delegated account are judged by the code they run, because fresh Safes are unverified on explorers while their singleton is verified.
8. **Model** (TypeSafe Jev, question set `jev-wallet-risk/v6`). Typed questions over the state: the provider's checks, the caller's assertions labelled as such, and the content the agent acted on. The model is the only layer that reads `context`, and it is where manipulation such as injected instructions is detected.

Every external lookup is time-boxed and fails to "unavailable", which is stated in the evidence. A failed lookup is never read as "clear": where a verdict depends on it, the tier is raised to at least medium (§3). A `checked: false` response carries a `reason` code.

## 3. Rules

The score runs from 0 to 100, where higher is safer. It starts from the model's typed answers. Deterministic evidence then **caps** it: the lowest applicable cap wins, whatever the model said.

| Evidence | Rule | Cap / effect | Category |
|---|---|---|---|
| OFAC SDN | subject listed (exact or same key) | **0**, critical, model skipped | `sanctioned_address` |
| MetaMask phishing list | domain listed | **20** | `phishing_domain` |
| ScamSniffer addresses | subject listed | **20** | `known_scam_address` |
| Drainer code fingerprint | subject, or a contract in the simulated transaction, runs a listed drainer's logic code | **30** | `known_drainer_code` |
| Caller assertion | `screening: "flagged"` | **30** | `compliance_risk` |
| Simulation | assets leave the sender, nothing comes back, and an undisclosed plain wallet ends up with them | **40**; **75** and review when a source-verified contract forwarded them (bridges, batch senders) | `outflow_to_undisclosed_eoa` |
| Simulation | a named payee receives a different asset, or more, than declared | **40** | `outflow_exceeds_declared` |
| Domain analysis | strong impersonation | **40** | `impersonation` |
| ScamSniffer domains | host listed **and** corroborated by domain analysis | **40** | `phishing_domain` |
| Interaction | approval or permit to a plain wallet with no history | **40** | `approval_to_eoa` |
| Interaction or simulation | approval or permit to a plain wallet | **55** | `approval_to_eoa` |
| Simulation | assets parked with nothing in return in a contract whose source is **not verified** | **55** | `outflow_to_unverified_contract` |
| Contract verification | approval, permit or simulated approval to an unverified contract | **75** and at least medium tier (review) | `unverified_contract` |
| Simulation | not every recipient or spender could be classified, or a size cap was hit | **75** and review | `simulation_incomplete` |
| Fail-closed | an approval or permit whose spender could not be classified (on-chain lookup failed), or a transaction whose simulation failed transiently | at least medium tier (review) | `onchain_unavailable`, `simulation_unavailable` |
| ScamSniffer domains | host listed, not corroborated | none (evidence only) | `community_flagged_domain` |
| Simulation | unlimited approval; revert | none (evidence only) | `unlimited_approval`, `simulation_reverted` |
| Caller assertion | `screening: "clean"`, `pre_authorized` | **none: can never lower risk** | — |
| Model | known threat ≥ 0.85 / sanctions concern ≥ 0.85 / guard bypass ≥ 0.8 / fraud class ≥ 0.8 / abuse class ≥ 0.8 / low-confidence trust | 20 / 30 / 30 / 40 / 55 / 55 | per signal |

Tiers: **low** ≥ 80; **medium** 60–79 only when a signal is elevated, otherwise low; **high** 30–59; **critical** < 30. The block and allow decision belongs to the relying party. Evaluation corpora treat high and critical as "block".

## 4. The attestation

Each verdict is an ES256 JWS (`typ: risk-check+jwt`, `kid: jev-attest-v1`) issued by `did:web:<host>` and valid for one hour. It carries:

- `sub`, `score`, `tier` and `categories`;
- `checks`: what the provider verified, with list dates and statuses, e.g. `metamask-phishing-detect@2026-09-29:clear`, `forta-phishing-code@2023-01-26:hit`, the on-chain status, and the simulation status and findings;
- `asserted`: what the caller claimed, kept separate from `checks`;
- `payment` and `interaction`: what the verdict covers;
- `input_hash`: SHA-256 of the RFC 8785 (JCS) canonical normalized request, the list versions and the question set;
- `request_hash`: SHA-256 of the RFC 8785 canonical request fields **exactly as the caller sent them**. Any client can recompute it, so an intermediary that drops `context` or flips `interaction.unlimited` is detected (the SDK checks it);
- `jti`, `iat` and `exp`.

Anyone can verify it with the published JWKS (`scripts/verify-attest.ts` is a reference verifier). A verdict does not apply to a different payment or transaction: the hash would not match.

## 5. Data sources and freshness

| Source | License | In the Worker | Refresh |
|---|---|---|---|
| OFAC SDN digital currency addresses | U.S. public data | embedded snapshot | daily workflow → `feeds` branch, Ed25519-signed manifest (publisher key pinned in the Worker) → runtime swap after signature, date, SHA-256, count and shrink checks |
| MetaMask eth-phishing-detect | DBAD-1.2 | embedded hash set | same as OFAC |
| ScamSniffer domains, addresses, code fingerprints | GPL-3.0 | operator KV only, never committed | `scripts/update-threat-feeds.ts --scamsniffer --upload`; the public data lags 7 days |
| Forta labelled datasets (phishing contracts) | MIT | embedded fingerprint set | static 2023 dataset |
| On-chain state, simulation | — | public JSON-RPC with a fallback endpoint per chain (simulation: Ethereum, Base, Polygon, Arbitrum, Optimism, BSC; on-chain facts also Avalanche and Solana) | live |
| Contract verification | — | Blockscout API v2 | live, cached 24 h |

`GET /status` reports the list versions verdicts are using right now, their age, and the last refresh attempt.

## 6. How we measure

- **External labels.** Positives and negatives come from lists we did not write: OFAC, MetaMask, ScamSniffer, Forta, Tranco, and well-known contracts.
- **Held out.** Sampling seeds that were inspected during development are never used for reported numbers. Cross-source and temporal splits are used where a list could leak into its own test.
- **Uncertainty.** Every rate carries a Wilson 95% interval.
- **Reproducible.** Scripts are in `eval/`, and machine-readable reports in `eval/evidence/*-report.json`.
- **Negative results are published**, including dead ends (§7).

## 7. Known limits and negative results

- **A plain transfer to an unknown drainer wallet is not detectable** from the address alone: 0/30 on held-out drainer addresses with feeds off. Only feeds catch these, and they lag.
- **Unlisted phishing domains that imitate no brand** are mostly missed: 0–3 of 60 held out. A feed is required.
- **Code fingerprints generalize across kits, not across sources.** Fingerprints from Forta's 2023 labels match 15% of the contracts ScamSniffer lists today. A continuously updated set matches 43% of contracts at creation time. See `EVIDENCE.md`.
- **Simulation runs against the latest block.** A replay that reverts or moves nothing today (spent approvals, drained balances) says nothing about the past. Historical replays need archive state, which the free public RPCs refuse.
- **Simulation cannot see intent.** A drainer contract that keeps the funds itself and is source-verified is only caught by the code-fingerprint layer or by a feed.
- **Domain age is not used.** We measured it with RDAP and dropped it: 30 of 40 sampled listed phishing domains no longer had a registration record (RDAP 404). For most real phishing, age could not be established at all.
- **OFAC screening covers direct listing only.** It says nothing about funds received from listed addresses, and x402check is not a compliance program.
