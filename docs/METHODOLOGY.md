# How x402check forms a verdict

This is the complete rulebook for turning a request into a signed verdict: the evidence the provider collects, the rules applied to that evidence, and how the result is attested. Strategy and principles are in [`STRATEGY.md`](STRATEGY.md). Measured accuracy, with confidence intervals, is in [`EVIDENCE.md`](EVIDENCE.md).

## 1. Inputs

| Field | Meaning | Trust |
|---|---|---|
| `wallet` | The counterparty (the subject), as an EVM, Solana, Bitcoin-family or Tron address, optionally in CAIP-10 form | the subject of the verdict |
| `chain` | A known CAIP-2 id or alias (`base`, `solana`…) | must agree with CAIP-10 and `payment.network` (else 422); an unknown id is refused, never half-checked |
| `domain` | The site or origin involved | analysed by the provider |
| `context` | Content the agent acted on (page text, tool output, instructions) | input to the model; never trusted as a claim. Private keys, seed phrases and credit tokens are redacted before the model sees it |
| `payment` | The x402 payment being made (`pay_to`, `amount`, `asset`, `network`) | bound into the attestation |
| `interaction` | `token_approval`, `nft_approval`, `permit_signature`, `native_transfer`… | decides which rules apply |
| `transaction` | EVM `{from, to, value, data}` to simulate (needs an `eip155` chain) | simulated by the provider |
| `screening`, `authorization` | The caller's own screening result or pre-authorization | **asserted**: recorded, can only raise risk |

Any other field is refused (422 naming it): a misspelled `context` must not leave its content unanalysed while the verdict answers a different request. A mixed-case EVM `wallet` must carry a valid EIP-55 checksum.

## 2. Evidence, in order

Evidence is collected by the provider itself. Nothing the caller asserts counts as evidence.

1. **OFAC SDN screen** (`src/sanctions.ts`). Exact match on the canonical address, then on the 20-byte hash it encodes, so the same key in another encoding matches (BCH legacy ↔ cashaddr, BTC P2PKH ↔ P2WPKH, TRX ↔ EVM). Checksums are enforced. A listing is final: score 0, tier critical, and no model call. Scope: direct listing only.
2. **Domain analysis** (`src/domain-analysis.ts`). Public-suffix-aware parsing, punycode and homoglyph detection, typosquats of brands (7 or more characters), brand plus lure keyword, and an official domain used as a subdomain of another site.
3. **Threat feeds** (`src/threat-intel.ts`):
   - MetaMask eth-phishing-detect domains, matched on the host and its parents down to the registrable domain, with MetaMask's own allowlist applied;
   - ScamSniffer domains (exact host) and EVM addresses, rebuilt into KV by the Worker's cron twice a day.
   - A feed entry counts only as a bare host: one with userinfo, a port, a path, a query or a fragment (`x@coinbase.com`, `coinbase.com:443`) is dropped, never reduced to the host it wraps. Addresses x402check never flags (`src/never-flag.ts`: its own `pay_to`, Permit2 and x402's Permit2 proxies, the asset x402 charges in on each EVM network, and the major tokens the simulator values) are left out of the ScamSniffer address set and of the code fingerprints built from it.
4. **On-chain facts** (`src/onchain.ts`). Whether the subject is a contract, its nonce and balance ("unused address"), and its code classification. EIP-7702 delegated accounts are EOAs. Every chain has a primary and a fallback public RPC under one time budget (`src/rpc.ts`).
5. **Drainer-kit code fingerprints** (`src/code-fingerprint.ts`).
   - **What is classified:** the subject's runtime code, and in a simulated transaction the called contract, recipients and spenders.
   - **What gets a fingerprint:** only *logic* code, as the SHA-256 of the bytecode with the compiler-metadata trailer removed. Token, NFT, delegating (DELEGATECALL/CALLCODE) and very small (<100-byte) code is never fingerprinted itself, because countless legitimate contracts share it (a fake-token clone has exactly the real token's code).
   - **Indirection:** matching follows one level of it, to the code an address actually runs: an EIP-7702 delegate, an EIP-1167, Safe or EIP-1967 proxy implementation, or an address hard-coded in delegating code.
   - **Reference sets:** fingerprints are compared with those of contracts listed by Forta's labelled datasets (embedded, contracts created since 2021) and ScamSniffer (runtime).
   - **Guard:** a listed fingerprint is dropped at build time if it is identical to a widely used implementation:
     - the MetaMask 7702 delegator, the Safe singletons, Coinbase Smart Wallet, the 4337 EntryPoints, Permit2 and Multicall3;
     - exchange deposit fleets that lists label as phishing because single deposit addresses received phishing proceeds: Luno, Poloniex, BitGo's `Forwarder`, and the Mist multisig.
   - **Collision gate:** a listed fingerprint is also dropped if it matches code in legitimate use (`scripts/legit-corpus.ts`): recently verified contracts, CoinGecko tokens and the contracts real users call.
6. **Kit watch** (`src/kit-watch.ts`, `deploy/kit-watch.ts`). This is the provider's own record of drainer infrastructure. A cron reads every new Ethereum and Base block, once a minute.
   - **EIP-7702 delegations.** Each authorization in a type-4 transaction names a delegate, and the scan classifies each delegate once:
     - **Labelled families:** an address-poisoning executor (a publicly exposed "Poisoner", or any deployment of its template), or a sweeper that ScamSniffer-listed wallets delegate to and that forwards what they receive.
     - **Behaviour:** the scan sends 0.01 ETH (simulated) to a wallet that delegates to it. A delegate that passes at least half of it on in the same call is a **forwarder**.
       - The forwarder's logic code becomes a learned family, so its redeployments are known on sight.
       - Code with no logic fingerprint (tiny forwarders, proxies) is known by the delegate's address instead.
     - **What is recorded:** every wallet that delegates to a poisoner, sweeper or forwarder, while the delegation is in effect. Since v0.6.0, where a forwarder sends what it receives is **not** recorded: whoever deploys a forwarder chooses its destinations, so recording them would let anyone mark an arbitrary wallet (a merchant's `pay_to`, say) as drainer infrastructure. A forwarding verdict is generalized to other wallets only when the delegate's code is small (at most 1,024 bytes), and a failed `eth_getCode` is never cached as a verdict.
   - **New contracts.** Every contract created at the top level is fingerprinted, following proxies. It is matched against the drainer-kit families by exact fingerprint or by **template fingerprint**: the logic code with every PUSH20/PUSH32 immediate zeroed, so redeployments that differ only in immutables or in a hard-coded operator address share it. A match records the contract and its deployer.
   - **At evaluation time:**
     - The subject is looked up in the watchlist, and so are the recipients, spenders and called contract of a simulated transaction.
     - The code the subject runs now is matched against the families. A wallet that delegates to a known poisoner, sweeper or forwarder is therefore caught even if the scan never saw the delegation.
     - EOA entries hold on every EVM chain, because the same key controls the address. Contract entries hold only on the chain where they were seen.
   - **Guard:** the guarded implementations and the collision gate (item 5) apply to the families too, by exact and by template fingerprint. A fingerprint that comes only from an address hard-coded in a listed contract never seeds a family, because it names what the contract calls.
   - **Private:** the watchlist and the families live in the operator's KV. `/status` reports coverage (blocks behind the chain head, gaps, code reads waiting for a retry) and counts, never addresses.
7. **Transaction simulation** (`src/simulation.ts`). The transaction is replayed with `eth_simulateV1` and `traceTransfers` on Ethereum, Base, Polygon, Arbitrum, Optimism or BSC, against the latest block.
   - **Sender balance:** it is set to the value plus 0.1 ETH. The question is what the transaction does, not whether the sender can afford it, and a plausible balance gives a contract nothing to detect.
   - **Asset movements:** Transfer, Approval, ApprovalForAll, ERC-1155, WETH and Permit2 logs are reduced to net movements, in linear time and under caps on response size, logs and flows. Value routed through the called contract is attributed to its final recipient.
   - **Classification:** every recipient and spender is classified as a contract or a plain wallet, largest first, up to 40.
   - **What counts as coming back:** only value. A token issued by the called contract, or by a wallet that received the sender's assets, is not a return (a drainer can emit Transfer events for its own token), and neither is a known asset worth less than 1% of what left. A token of unknown value from a separate contract, while an undisclosed wallet takes the value, is a review item (`undisclosed_recipient_unvalued_return`), never a clear.
   - **Truncation:** logs beyond the analysis cap make the result `simulation_truncated`, which caps like a hidden recipient: padding a transaction with logs cannot hide the transfer after them.
   - **What the user named:**
     - the payee (`payment.pay_to`), limited to `payment.asset` and `payment.amount` when those are machine-checkable;
     - a recipient named in the top-level call (`transfer`, `transferFrom`, `safeTransferFrom`), for the called token and amount only;
     - the subject, for any asset, unless a payee scope names it more precisely;
     - the native value sent to the called address.
8. **Contract verification** (`src/contract-intel.ts`).
   - **Source:** Blockscout source-verification status. "Not verified" is cached for 10 minutes; "verified" for 24 hours.
   - **When:** only when the user grants a contract control over assets, when assets are parked in a contract, or when a contract forwards them to an undisclosed wallet.
   - **Proxies and delegated accounts:** an exact forwarding proxy (Safe, EIP-1167, minimal EIP-1967) and a delegated account are judged by the code they run, because fresh Safes are unverified on explorers while their singleton is verified.
9. **Model** (TypeSafe Jev, question set `jev-wallet-risk/v6`). Typed questions over the state: the provider's checks, the caller's assertions labelled as such, and the content the agent acted on. The model is the only layer that reads `context`, and it is where manipulation such as injected instructions is detected.
   - **Which model answered.** The id the backend reports is signed in `checks.model_id`. Through the Vercel AI Gateway that id is the alias `typesafe-ai/jev`: the gateway exposes no revision, so the vendor can change the model behind it.
   - **Drift canary.** Twice a day the Worker's cron runs fixed cases through the live model with the real scoring (an injected instruction and a drain request must not come back low; a configured payment must stay low). `/status` → `model` shows the last result; a failure is logged.
   - **Deadline.** The model call has an 8 s total budget, retries included. Past it the check is `checked: false`, with no charge.

Every external lookup is time-boxed and fails to "unavailable", which is stated in the evidence. A failed lookup is never read as "clear": where a verdict depends on it, the tier is raised to at least medium (§3). A `checked: false` response carries a `reason` code.

## 3. Rules

The score runs from 0 to 100, where higher is safer. It starts from the model's typed answers. Deterministic evidence then **caps** it: the lowest applicable cap wins, whatever the model said.

| Evidence | Rule | Cap / effect | Category |
|---|---|---|---|
| OFAC SDN | subject listed (exact or same key) | **0**, critical, model skipped | `sanctioned_address` |
| MetaMask phishing list | domain listed | **20** | `phishing_domain` |
| ScamSniffer addresses | subject listed | **20** | `known_scam_address` |
| Kit watch | the subject, or a counterparty in the simulated transaction, is a look-alike delegated to an address-poisoning executor | **20** | `address_poisoning` |
| Kit watch | a wallet delegated to a labelled sweeper family (its key is compromised) | **20** | `compromised_wallet` |
| Kit watch | a contract in a drainer-kit family (exact or template), or the deployer of one | **30** | `known_drainer_code`, `drainer_operator` |
| Drainer code fingerprint | subject, or a contract in the simulated transaction, runs a listed drainer's logic code | **30** | `known_drainer_code` |
| Caller assertion | `screening: "flagged"` | **30** | `compliance_risk` |
| Simulation | assets leave the sender, nothing of value comes back, and an undisclosed plain wallet ends up with them | **40**; **75** and review when a source-verified contract forwarded them (bridges, batch senders) | `outflow_to_undisclosed_eoa` |
| Simulation | logs beyond the analysis cap: what follows them cannot be read | **40** | `simulation_truncated` |
| Simulation | a named payee receives a different asset, or more, than declared | **40** | `outflow_exceeds_declared` |
| Domain analysis | strong impersonation | **40** | `impersonation` |
| Kit watch | a wallet delegated to code that forwards what it receives, with no label | **40** | `auto_forwarding_wallet` |
| ScamSniffer domains | host listed **and** corroborated by domain analysis | **40** | `phishing_domain` |
| Interaction | approval or permit to a plain wallet with no history | **40** | `approval_to_eoa` |
| Interaction or simulation | approval or permit to a plain wallet | **55** | `approval_to_eoa` |
| Simulation | assets parked with nothing in return in a contract whose source is **not verified** | **55** | `outflow_to_unverified_contract` |
| Simulation | an undisclosed wallet takes most of the value, and what comes back is a token of unknown value from a separate contract | **55** and review | `undisclosed_recipient_unvalued_return` |
| Contract verification | approval, permit or simulated approval to an unverified contract | **75** and at least medium tier (review) | `unverified_contract` |
| Simulation | not every recipient or spender could be classified, or a size cap was hit | **75** and review | `simulation_incomplete` |
| Fail-closed | an approval or permit whose spender could not be classified (on-chain lookup failed); a transaction whose simulation failed transiently; a contract whose source verification could not be read; a kit-watch lookup that failed; an EVM grant with no chain named | at least medium tier (review) | `onchain_unavailable`, `simulation_unavailable`, `contract_verification_unavailable`, `kit_watch_unavailable`, `chain_unknown` |
| ScamSniffer domains | host listed, not corroborated | none (evidence only) | `community_flagged_domain` |
| Kit watch | an address recorded before v0.6.0 as a forwarder's destination | none (evidence only) | `forwarding_destination` |
| Simulation | unlimited approval; revert | none (evidence only) | `unlimited_approval`, `simulation_reverted` |
| Caller assertion | `screening: "clean"`, `pre_authorized` | **none: can never lower risk** | — |
| Model | known threat ≥ 0.85 / sanctions concern ≥ 0.85 / guard bypass ≥ 0.8 / fraud class ≥ 0.8 / abuse class ≥ 0.8 / low-confidence trust | 20 / 30 / 30 / 40 / 55 / 55 | per signal |

Tiers: **low** ≥ 80; **medium** 60–79 only when a signal is elevated, otherwise low; **high** 30–59; **critical** < 30. The block and allow decision belongs to the relying party. Evaluation corpora treat high and critical as "block".

## 4. The attestation

Each verdict is an ES256 JWS (`typ: risk-check+jwt`, with the `kid` the DID document publishes, today `jev-attest-v1`) issued by `did:web:<host>` and valid for one hour. It carries:

- `sub`, `score`, `tier` and `categories`;
- `checks`: what the provider verified, with list dates and statuses, e.g. `metamask-phishing-detect@2026-09-29:clear`, `forta-phishing-code@2023-01-26:hit`, the on-chain status, the simulation status and findings, the kit watch's clocks, the question set (`model`) and the model id the backend reported (`model_id`). Each item carries its freshness anchor (§5);
- `asserted`: what the caller claimed, kept separate from `checks`;
- `payment` and `interaction`: what the verdict covers;
- `input_hash`: SHA-256 of the RFC 8785 (JCS) canonical normalized request, the list versions and the question set;
- `request_hash`: SHA-256 of the RFC 8785 canonical request fields **exactly as the caller sent them**. Any client can recompute it, so an intermediary that drops `context` or flips `interaction.unlimited` is detected (the SDK checks it);
- `jti`, `iat` and `exp`.

Anyone can verify it with the published JWKS. **A verdict does not apply to a different request, payment or transaction only when the verifier compares `request_hash`.** These do:
- the SDK's `verifyAttestation(jws, { request })` (`@x402check/client`), and `interpret` on its result;
- the signing guard (`@x402check/client/guard`), and the MCP server's `x402check_check` and `x402check_pay`, on every check they make;
- the MCP server's `x402check_verify_attestation` when it is given the checked `request` (since `@x402check/mcp` 0.3.0; it also takes `max_age_seconds`); handed a JWS alone, it binds only `aud` and `sub`;
- `scripts/verify-attest.ts --request '<body>'`, the reference CLI (it adds `--max-age` and payment bindings).

A verifier that checks only the signature accepts a genuine verdict issued for something else, for its full hour.

**Keys.** The SDK, the guard and the MCP server pin x402check's key by its RFC 7638 thumbprint (`X402CHECK_KEY_THUMBPRINTS`): a DID document serving another key is refused (`key_not_pinned`). A rotation publishes the next key in the DID document before it signs (`JEV_ATTEST_NEXT_PUBLIC_JWK`). If the provider's own key fails its load-time check, paid routes refuse all work, with no charge, rather than sign with a key nobody can verify.

**What is sold, and to whom.** Each x402 payment is used once: it is claimed when it verifies, so a copy gets `409` instead of a second evaluation. A paying wallet on the OFAC SDN list is refused (`403 payer_sanctioned`).

## 5. Data sources and freshness

| Source | License | In the Worker | Refresh |
|---|---|---|---|
| OFAC SDN digital currency addresses | U.S. public data | embedded snapshot | daily workflow → a guard against the published manifest (`scripts/feeds-guard.mjs`: no signature when OFAC addresses shrink by more than 5% or grow by more than 50%, MetaMask entries move by more than 20%, or a date goes backwards or runs more than a day ahead) → `feeds` branch, Ed25519-signed manifest (publisher key pinned in the Worker) → runtime swap after signature, date, SHA-256, count and shrink checks |
| MetaMask eth-phishing-detect | DBAD-1.2 | embedded hash set | same as OFAC |
| ScamSniffer domains, addresses, code fingerprints | GPL-3.0 | operator KV only, never committed | domains and addresses: the Worker's cron, twice a day (`deploy/scamsniffer-refresh.ts`), both lists read at the upstream commit it resolves first; a refresh in which a list halves, or grows by more than 50% or by more than 100,000 domains or 2,000 addresses, is refused and the previous sets stay; code fingerprints: `scripts/update-threat-feeds.ts --scamsniffer --upload`. The public data lags 7 days; `/status` marks the feed stale after 3 days without a refresh |
| Forta labelled datasets (phishing contracts created since 2021) | MIT | embedded fingerprint set | static 2023 dataset |
| Kit watch (x402check's own scan of Ethereum and Base) | the provider's own data; the seeded families are partly derived from ScamSniffer (GPL-3.0) | operator KV only | every minute (Worker cron); families seeded by `scripts/kit-catalog.ts` and `scripts/kit-registry.ts --upload`, backfill with `scripts/hunt-kits.ts` |
| On-chain state, simulation | — | public JSON-RPC with a fallback endpoint per chain (simulation: Ethereum, Base, Polygon, Arbitrum, Optimism, BSC; on-chain facts also Avalanche and Solana) | live |
| Contract verification | — | Blockscout API v2 | live, cached 24 h |

`GET /status` reports the list versions verdicts are using right now, their age, and the last refresh attempt.

### Freshness anchors (since 0.6.1)

Each signed evidence item carries the anchor of its kind, so a relying party can tell how fresh the evidence was, and recompute what can be recomputed, without trusting the provider's word:

| Evidence (`checks`) | Anchor | How a relying party uses it |
|---|---|---|
| `sanctions` | `as_of` (OFAC's publish date) and `digest`, the SHA-256 of OFAC's SDN.XML | Fetch the SDN.XML release of that date, check its SHA-256, and recompute the screen for the subject. The digest is signed only when the list in use carries it; it is never borrowed from another list. |
| `feeds` | `source@as_of:status` per list | The list version consulted (MetaMask's, Forta's and ScamSniffer's dates). |
| `kit_watch` | `as_of` (the scan clock: the watch's last update) and, per chain: `complete_through`, the last block the scan read (the coverage clock); `gaps`, every hole ever recorded below it, each block range skipped after an outage and each code read abandoned after a day of retries (the real count, since 0.6.2; only when there are any); `pending` (since 0.6.2), the code reads from blocks already scanned that failed on every endpoint and are queued for a retry (only when there are any) | Compare `complete_through` with the block the payment or delegation happened in: activity after it was not covered. Coverage up to it is unbroken only when `gaps` and `pending` are absent; `pending` clears as the retries succeed. The watchlist itself stays private. |
| `simulation` | `at_block`, the block whose state the transaction was simulated on | Re-run `eth_simulateV1` against that block. A transaction sent much later can behave differently. |

Fail closed: an anchor a policy requires and the verdict lacks, or one that is too old for it, does not count as a fresh clear. The provider applies the same rule to itself: a lookup that failed raises a review floor (§3), and `/status` marks a stale feed.

## 6. How we measure

- **External labels.** Positives and negatives come from lists we did not write: OFAC, MetaMask, ScamSniffer, Forta, Tranco, and well-known contracts.
- **Held out.** Sampling seeds that were inspected during development are never used for reported numbers. Cross-source and temporal splits are used where a list could leak into its own test.
- **Uncertainty.** Every rate carries a Wilson 95% interval.
- **Reproducible.** Scripts are in `eval/`, and machine-readable reports in `eval/evidence/*-report.json`.
- **Negative results are published**, including dead ends (§7).

## 7. Known limits and negative results

- **A plain transfer to an unknown drainer wallet is not detectable** from the address alone: 0/30 on held-out drainer addresses with feeds off. Only feeds catch these, and they lag. The kit watch closes this gap for two kinds of wallet only: look-alikes that delegate to a poisoner, and wallets that delegate to a sweeper or forwarder (§2, item 6).
- **Unlisted phishing domains that imitate no brand** are mostly missed: 0–4 of 60 held out across four samples. A feed is required.
- **Code fingerprints generalize across deployments of a kit, not across eras.** A continuously updated set would have recognized 40 of 82 listed contracts at creation time (v0.4, Ethereum and Base). No new contract in the scanned windows matched an old kit: today's drainer infrastructure is mostly EIP-7702 delegations, which the kit watch covers. See `EVIDENCE.md`.
- **Lists label wallets, not only drainers.** A deposit address that received phishing proceeds gets listed, and its code is an exchange's standard contract. The collision gate and the fleet guards exist because of this; a fleet that is neither verified nor called recently can still slip through until the gate corpus includes it.
- **Simulation runs against the latest block.** A replay that reverts or moves nothing today (spent approvals, drained balances) says nothing about the past. Historical replays need archive state, which the free public RPCs refuse.
- **Simulation cannot see intent.** A drainer contract that keeps the funds itself and is source-verified is only caught by the code-fingerprint layer or by a feed.
- **Domain age is not used.** We measured it with RDAP and dropped it: 30 of 40 sampled listed phishing domains no longer had a registration record (RDAP 404). For most real phishing, age could not be established at all.
- **Kit watch coverage.**
  - Only contracts created at the top level are seen. Factory deployments (CREATE/CREATE2 inside another contract) are missed. Of the listed kit contracts whose creation is known, 7 of 162 were deployed through a factory (counted during development; not in a tracked report).
  - EIP-7702 delegations are watched on Ethereum and Base only.
  - A code read that no endpoint answers is queued and retried on later runs, then evaluated with its original block (`pending`). After a day, or when more than 500 reads wait, it is abandoned and counted in `gaps`. A proxy whose implementation slot cannot be read is not retried: it is judged by its own code only.
  - A forwarder is recognized by native-ETH behaviour. A sweeper that moves only tokens is missed, and so is one probed before it is initialized, until a later probe.
  - The old drainer-kit families (2017–2023) did not redeploy in the scanned windows. What the watch finds today is EIP-7702 infrastructure; see `EVIDENCE.md`.
- **Behaviour is not intent.** A wallet that forwards everything it receives could belong to a legitimate forwarding setup. Without a label, it caps at 40, not 20. Where it forwards to proves nothing about the destination, so destinations are not flagged.
- **The model can change underneath.** The gateway serves an alias with no pinned revision. The canary catches a drift on its fixed cases, not on every input.
- **OFAC screening covers direct listing only.** It says nothing about funds received from listed addresses, and x402check is not a compliance program.
