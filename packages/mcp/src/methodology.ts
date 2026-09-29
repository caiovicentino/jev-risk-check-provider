export const EVIDENCE_URL: string = "https://github.com/caiovicentino/jev-risk-check-provider/blob/main/docs/EVIDENCE.md";
export const METHODOLOGY_URL: string = "https://github.com/caiovicentino/jev-risk-check-provider/blob/main/docs/METHODOLOGY.md";

/** Static summary served by the `x402check_methodology` tool. Numbers mirror docs/EVIDENCE.md (v0.3.0). */
export const METHODOLOGY: string = `x402check: what is checked, and the published limits (API v0.3)

Provider-verified evidence (deterministic, independent of the model):
- Sanctions: OFAC SDN digital-currency addresses, refreshed daily, including the same key in another encoding. A listed address scores 0 (critical) with no model call. Direct listing only.
- Threat feeds: MetaMask eth-phishing-detect (domains, refreshed daily); ScamSniffer drainer addresses and phishing domains (about 7 days publication lag).
- Look-alike domains: public-suffix aware analysis (leet, IDN homoglyphs, typosquats, brand plus lure word).
- On-chain facts: contract or plain wallet (EOA), activity, contract source verification. An approval or permit granted to an EOA is capped at high risk (the classic drainer pattern); one granted to a contract with unverified source is raised to review.
- Transaction simulation (eth_simulateV1 on Ethereum, Base, Polygon, Arbitrum, Optimism and BSC; not Avalanche): asset outflows, inflows and approvals. It flags:
  - hidden recipients: assets leave the sender, nothing comes back, and a plain wallet the sender did not name ends up with them (outflow_to_undisclosed_eoa). Through a source-verified forwarder, such as a bridge or batch sender, this is a review item instead;
  - exceeds-declared: a named payee receives a different asset, or more, than the declared payment or transfer (outflow_exceeds_declared);
  - unverified sinks: assets end up in a contract whose source is not verified (outflow_to_unverified_contract);
  - approvals to EOAs, unlimited approvals, and reverts.
- Drainer-kit code fingerprints: the logic code of the subject and of the contracts a simulated transaction touches (called contract, recipients, spenders), following one level of EIP-7702 delegation or proxy, is compared with fingerprints of listed drainer contracts (Forta, ScamSniffer). A match caps the score at 30 (known_drainer_code).
Model: TypeSafe Jev typed questions over "context" (the content the agent acted on), for injected or manipulated instructions.

Fail-closed review floors: a check that should have run but failed transiently raises the verdict to at least review (medium), never to clear. This covers the on-chain lookup for an approval (onchain_unavailable), the simulation of a sent transaction (simulation_unavailable), and an incomplete simulation whose recipients or spenders could not be classified or whose logs were truncated (simulation_incomplete). An unsupported chain is a stated coverage gap.

Every verdict is an ES256 attestation signed by did:web:x402check.xyz. It lists what the provider verified ("checks") separately from what the caller asserted ("asserted"). Caller assertions are never evidence and can never lower risk. It also signs request_hash: a SHA-256 over the RFC 8785 canonical request exactly as sent. This server recomputes it on every check, so a request altered or stripped in transit (context included) is rejected as not_verified.

Published limits (measured):
- Unknown drainers receiving a plain transfer are NOT detectable from the address alone (0/30 held-out drainer addresses with the feed off). Simulating the transaction is what catches a drain in flight.
- Unlisted phishing domains are mostly NOT caught without a feed (0 to 3 of 60).
- The simulation replays at the latest block and is measured on Ethereum only. A drainer that returns any asset to the victim defeats the hidden-recipient rule.
- Sanctions screening is direct OFAC listing only: funds received from listed addresses are not detected, and it is not a compliance program.
- Laundering and other transaction-graph behaviour are not analyzed.
- A clean verdict means "none of these checks fired", not "safe".

Measured results (v0.3.0, externally labelled): OFAC addresses 24/24 critical; feed-listed phishing domains 40/40 and drainer addresses 30/30; drainer permits with the drainer feed switched off 27/30; real drainer transactions on Ethereum 18/25 flagged when assets move (72%), against 0/84 legitimate transactions to 19 well-known contracts; drainer-kit fingerprints recognize 43/100 listed contracts at creation from earlier deployments (15/100 cross-source from Forta 2023), with 0 collisions among 9,625 legitimate contracts (following 7702 delegations and proxies); 0 high or critical on 22 well-known contracts and 40 top dApp domains.

Policy for agents: call x402check_check BEFORE sending funds, signing approvals, permits or orders, or paying an x402 invoice. Pass the transaction when you have it.
- allow: proceed (still not a guarantee of safety)
- warn: get explicit confirmation from the user first
- block: do not proceed
- not_verified: the check did not complete or could not be verified. STOP; it is never an all-clear.

Price: $0.001 per evaluation ($0.002 on Solana), paid per call with x402 (USDC); there is no free tier. This server pays from its configured payer (X402CHECK_PAYER_KEY), within its per-payment cap and budget.

Evidence: ${EVIDENCE_URL}
Methodology: ${METHODOLOGY_URL}
Discovery: https://x402check.xyz/.well-known/risk-check.json
Issuer DID document: https://x402check.xyz/.well-known/did.json`;
