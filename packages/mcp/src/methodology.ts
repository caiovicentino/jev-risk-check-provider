export const EVIDENCE_URL: string = "https://github.com/caiovicentino/jev-risk-check-provider/blob/main/docs/EVIDENCE.md";
export const METHODOLOGY_URL: string = "https://github.com/caiovicentino/jev-risk-check-provider/blob/main/docs/METHODOLOGY.md";

/** Static summary served by the `x402check_methodology` tool. Numbers mirror docs/EVIDENCE.md (v0.4.0). */
export const METHODOLOGY: string = `x402check: what is checked, and the published limits (API v0.4)

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
- Drainer-kit code fingerprints: the logic code of the subject and of the contracts a simulated transaction touches (called contract, recipients, spenders), following one level of EIP-7702 delegation or proxy, is compared with fingerprints of listed drainer contracts (Forta since 2021, ScamSniffer), gated against code in legitimate use. A match caps the score at 30 (known_drainer_code).
- Kit watch (x402check's own intelligence): every Ethereum and Base block is read as it is produced. Wallets that delegate (EIP-7702) to an address-poisoning executor are look-alikes their operator controls (address_poisoning, capped at 20). Wallets that delegate to a labelled sweeper are compromised (compromised_wallet, 20). A wallet whose delegate forwards whatever it receives is auto_forwarding_wallet (40). Deployers of drainer-kit code and the wallets collecting what sweepers forward are drainer_operator (30; 40 when the forwarder has no label). The subject and the counterparties of a simulated transaction are looked up; the list itself is private.
Model: TypeSafe Jev typed questions over "context" (the content the agent acted on), for injected or manipulated instructions.

Fail-closed review floors: a check that should have run but failed transiently raises the verdict to at least review (medium), never to clear. This covers the on-chain lookup for an approval (onchain_unavailable), the simulation of a sent transaction (simulation_unavailable), and an incomplete simulation whose recipients or spenders could not be classified or whose logs were truncated (simulation_incomplete). An unsupported chain is a stated coverage gap.

Every verdict is an ES256 attestation signed by did:web:x402check.xyz, with a key this server pins (RFC 7638 thumbprint): a DID document serving any other key is rejected as not_verified. It lists what the provider verified ("checks") separately from what the caller asserted ("asserted"). Caller assertions are never evidence and can never lower risk. It also signs request_hash: a SHA-256 over the RFC 8785 canonical request exactly as sent. This server recomputes it on every check, so a request altered or stripped in transit (context included) is rejected as not_verified.

Published limits (measured):
- Unknown drainers receiving a plain transfer are NOT detectable from the address alone (0/30 held-out drainer addresses with the feed off), unless the kit watch has seen the wallet as a poisoning look-alike or a compromised wallet. Simulating the transaction is what catches a drain in flight.
- Unlisted phishing domains are mostly NOT caught without a feed (0 to 4 of 60).
- The simulation replays at the latest block and is measured on Ethereum only. A drainer that returns any asset to the victim defeats the hidden-recipient rule.
- Sanctions screening is direct OFAC listing only: funds received from listed addresses are not detected, and it is not a compliance program.
- Laundering and other transaction-graph behaviour are not analyzed.
- A clean verdict means "none of these checks fired", not "safe".

Measured results (v0.4.0, externally labelled): OFAC addresses 24/24 critical; feed-listed phishing domains 40/40 and drainer addresses 30/30; drainer permits with the drainer feed switched off 27/30; real drainer transactions on Ethereum 18/25 flagged when assets move (72%), against 0/84 legitimate transactions to 19 well-known contracts; drainer-kit fingerprints recognize 40/82 listed contracts at creation from earlier deployments; on held-out legitimate code the gated code sets have 0 false positives among 1,737 fingerprintable contracts on Ethereum and 2,935 on Base (their one match was a real, unlisted drainer; v0.3's sets had matched the deposit contracts of Luno, Poloniex and BitGo, which a list labels as phishing: fixed); the kit watch flagged 6,831 addresses on Ethereum in 24 hours, none of them on ScamSniffer's public list, and 27 of 37 sampled poisoning look-alikes were confirmed by a victim's history; 0 high or critical on 22 well-known contracts and 40 top dApp domains.

Paying x402 resources (x402check_pay, this server): the resource is requested; on a 402, the option this server would pay (USDC on EVM, Base first) is checked right before it is signed: the payee, network, asset, amount and the resource's site, with the agent's context and the 402's own description. The attestation is verified and bound to that request. Only a verified allow signs. A warn is paid only if the user approves it in the client (MCP elicitation). Block and not_verified sign nothing. x402check's own pay_to is paid without a check only on x402check's own site; named by any other site, it is checked like any payee. One payment per call, within the per-payment cap and the budget; max_usd can only lower them. Https URLs on public hosts only (a host name that resolves to a private address is refused), x402 version 2 challenges only, authorizations valid at most 15 minutes, and redirects are not followed. A call the client cancels signs nothing. Measured: one real payment through the tool settled on Base in production, to x402check's own pay_to (a trusted payee, so that payment was not checked; the check path is measured by the Bazaar sample); 24 of 25 payees of real x402 merchants sampled from the Coinbase x402 Bazaar were allowed (96%, 95% CI 80.5-99.3%), and the one warning was a model finding on a prediction-market URL. Fresh merchant wallets with no history are allowed with a note.

Policy for agents: call x402check_check BEFORE sending funds, signing approvals, permits or orders, or paying an x402 invoice. Pass the transaction when you have it. To pay for an x402 resource, use x402check_pay; when it refuses, do not pay that payee any other way.
- allow: proceed (still not a guarantee of safety)
- warn: get explicit confirmation from the user first
- block: do not proceed
- not_verified: the check did not complete or could not be verified. STOP; it is never an all-clear.

Price: $0.001 per evaluation from prepaid credits (one x402 payment buys a balance: POST /v1/credits), or per call via x402 in USDC at the payment network's price ($0.0035 on Base, $0.002 on Solana; the 402 challenge lists them all); $0.005 when a transaction is simulated. There is no free tier. This server pays for checks from its prepaid credits (X402CHECK_CREDIT_TOKEN) or its configured payer (X402CHECK_PAYER_KEY), and for the resources x402check_pay clears from the payer, within its per-payment cap and budget (X402CHECK_BUDGET_USD bounds the payer and, separately, what this process spends from credits).

Evidence: ${EVIDENCE_URL}
Methodology: ${METHODOLOGY_URL}
Discovery: https://x402check.xyz/.well-known/risk-check.json
Issuer DID document: https://x402check.xyz/.well-known/did.json`;
