# Changelog

Each release's full notes and evidence are on the [releases page](https://github.com/caiovicentino/jev-risk-check-provider/releases). Measurements are in [docs/EVIDENCE.md](docs/EVIDENCE.md), and every verdict rule is in [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## Unreleased (v0.6.2)

From a full evaluation on 2026-10-02 (a security review of everything since the 2026-09-30 audit, an operations and cost review, and a black-box run against production):

- **A payment is used once, by what its payer signed (security review F1, high):** the single-use claim was keyed on the payload's JSON spelling, so re-encoding one authorization (key order, hex case, an extra field, base64 padding) made it several payments: each verified and evaluated, and, with a facilitator that confirms duplicates, several verdicts or credit packs for one payment. The claim is now keyed on the payment itself: EIP-3009 network, asset, payer and nonce; Permit2 network, owner and nonce; the Solana message bytes. One settlement transaction also pays for one verdict or pack only, even if a facilitator confirms it twice.
- **Only x402 v2 payments reach verification (F2):** x402 core reads the payment through the adapter, which now hands over only a v2 `PAYMENT-SIGNATURE` (never `X-PAYMENT`). A payload whose payment or payer cannot be identified is refused (402 `payment_unrecognized`) instead of skipping the claim or the payer's screen (a Solana transaction format the decoder does not read yet, such as v1 messages, is refused rather than sold unscreened).
- **Payments that cannot settle are not evaluated (F3):**
  - An authorization must stay valid for 60 s more (it must settle after the evaluation) and for at most 24 hours (the life of its claim): otherwise a 402 before any work.
  - A payer may have 8 payments in flight at once (429 `payer_busy`), and 5 settlement refusals within an hour hold its payments back (429 `payer_settlement_failures`). Our facilitators' own failures (timeouts, unexpected errors) never count against a payer.
  - Every POST to a paid route is rate-limited per IP: unpaid traffic at 60 a minute as before, traffic with a well-formed credential (an x402 v2 payment or a `Bearer x402c_…` token) at 300 a minute (`PAID_LIMITER`). The mere presence of a header no longer skips the limit.
- **A settled credit pack always returns its token (F4):** if the ledger and the retry queue both fail, the response is still a 202 with the token and a reference (the pending credit is logged by the token's hash for reconciliation). Every credit carries a reference, so a retry never credits twice, and settle-then-credit runs to completion if the buyer disconnects.
- **Only public key members are published (F6):** `jwks.json` and `did.json` carry `kty`, `crv`, `x`, `y`, `kid`, `alg` and `use` only. A configured key carrying private material is refused: the current key reports misconfigured, a next key is not published.
- **Strict requests:** an unknown field (`contxt`, `Context`) is a 422 naming it, instead of being dropped with its content unanalysed. A mixed-case EVM address must carry a valid EIP-55 checksum. A chain id must be a known one: an EVM chain id, a known Solana cluster, a Bitcoin-family genesis or TRON (`solana:mainnet` and `foo:bar` are refused).
- **Unpaid, every body gets the challenge:** an unpaid POST to a paid route always answers with the one-item 402 challenge, and a body that would be refused says why in `request_error`. Monitors and catalogs posting placeholder bodies now see a payable endpoint; nothing invalid is ever charged, and with a payment or a token an invalid body is still a 422 before any payment work. `POST /v1/credits` without an amount is the $1 pack.
- **Headers:** every response carries CORS and the security headers, 429s and preflights included; a 405 on `/v1/credits` says `Allow: GET, POST`; the site's CSP admits Cloudflare's cookieless analytics beacon.
- **Docs:** the discovery documents state the measured latency (0.7–2 s from credits, about 4 s per call) and that `intent_risk` and `behavioral` are evaluated families present in every verdict.
- `scripts/deploy.sh` installs without dependency install scripts.
- **Feeds supply chain (security review F7):**
  - A feed entry must be a bare host. An entry with userinfo, a port, a path, a query or a fragment (`x@coinbase.com`, `coinbase.com:443`) is dropped instead of being reduced to the host it wraps. On the current lists this drops one ScamSniffer entry and no MetaMask entry.
  - The ScamSniffer refresh resolves the upstream commit first and reads both lists at that SHA, so the recorded commit is the data's. When GitHub does not answer, it reads `main` and records the fetch date and no commit.
  - A refresh in which a list grows by more than 50%, or by more than 100,000 domains or 2,000 addresses, is refused like one in which it halves, and logged.
  - Addresses x402check never flags are left out of the community address sets (`src/never-flag.ts`): its own `pay_to`, Permit2 and x402's Permit2 proxies, the asset x402 charges in on each EVM network, and the major tokens the simulator values. The manual build also leaves them out of the code fingerprints.
  - The manual MetaMask and ScamSniffer builds read their lists at the resolved commit too.
  - The feeds workflow refuses to sign a manifest that changed implausibly since the published one (`scripts/feeds-guard.mjs`, plain node, checked out from the run's commit). The bounds: OFAC addresses −5% or +50%, MetaMask entries ±20%, no date going backwards or more than a day ahead, and a published manifest to compare with. A manual run with `override` publishes after review.

## `@x402check/client` 0.5.0 and `@x402check/mcp` 0.3.1 — 2026-10-02

- **The guard exempts payments to x402check only in USDC (client, security review F5):** the trusted-payee cap (250000 atomic units, $0.25 of USDC) applied to any asset; for an 8-decimal token it was not $0.25. Only the asset x402check's challenge asks for on each network (`X402CHECK_PAYMENT_ASSETS`) is exempt now.
- **Chain ids as the provider accepts them (client):** `toCaip2` returns null for a namespace or cluster the provider refuses (`solana:mainnet`, `foo:bar`), so the trust provider leaves such a chain out instead of failing the check.
- **Sellers can screen the payer before settling (client):** `x402checkTrustProvider()` implements a provider for the proposed x402 trust-provider extension (x402-foundation/x402#2300). It maps a verified, request-bound verdict on the payer's wallet to PASS / FAIL / UNCERTAIN, never PASS for anything it cannot verify, and returns the attestation as `evidence_uri`. A check that did not complete reports why (`not_checked:<reason>`).
- **Freshness anchors in the types (client):** `checks.sanctions.digest`, `checks.kit_watch` (`complete_through`, `gaps`) and `checks.simulation.at_block`, signed since provider 0.6.1; all optional, older attestations still verify.
- **`x402check_verify_attestation` and check results show the anchors (MCP):** the OFAC release digest and the per-chain block maps, each value only in its expected format.

## v0.6.1 — 2026-10-01: freshness anchors

Every signed evidence item now carries the freshness anchor of its kind, the shape discussed in x402-foundation/x402#2300 (each evidence kind brings its own clock instead of one watermark for all). All new fields are optional and additive: verifiers keep accepting older attestations.

- **`checks.sanctions.digest`:** the SHA-256 of OFAC's SDN.XML the screen ran against (`sha256:<hex>`), next to its publish date. A relying party can fetch that release, check the digest and recompute the screen. The feeds manifest now carries the digest too (`ofac.xml_sha256`); a refreshed list whose manifest and snapshot disagree on it is refused, and a list without one signs no digest.
- **`checks.kit_watch`:** `as_of` (the scan clock), the status, and `complete_through`, per chain the last block the scan completed (the coverage clock), with `gaps` when outages made it skip ranges. Only aggregates: the watchlist stays private.
- **`checks.simulation.at_block`:** the block whose state the transaction was simulated on, read from the `eth_simulateV1` result (no extra call).
- METHODOLOGY §5 explains what each anchor lets a relying party check, and the fail-closed rule.
- The MCP server shows the new fields in `x402check_verify_attestation` (next MCP release).

## v0.6.0 — 2026-09-30: the audit release

A full multi-agent audit (security, payments, operations, supply chain, evidence) found no critical issue and 11 high ones. This release fixes every finding that code can fix; the rest are owner settings (see the release notes).

- **Payments are single-use.** Each x402 payment is claimed once, after it verifies (a `PaymentClaim` Durable Object per payload): a copy gets 409 `payment_already_used` instead of a second evaluation, settlement or credit token. A claim store that cannot be reached refuses the payment (503, no charge).
- **The payer is screened.** A wallet on the OFAC SDN list gets 403 `payer_sanctioned`, per call and for credit packs.
- **The attestation key is checked at load.** Both secrets must be present, the private key must match the published JWK, and a canary must sign and verify. Otherwise paid routes refuse all work with no charge (503 `attestation_key_unavailable`) and `/healthz` answers 503. A next key can be published ahead of a rotation (`JEV_ATTEST_NEXT_PUBLIC_JWK`), and the discovery document names the live kid.
- **Payments survive a facilitator outage.** `/supported` has 5 s, verify and settle 30 s; a failed stack build is never cached; a network whose facilitator is down leaves the 402 challenge; identity documents and the site never wait for the payment stack. Monad's option says `assetTransferMethod: "permit2"`, the only method its facilitator settles. Only x402 v2 payloads are processed. Solana blockhashes come from publicnode.
- **Credits.** A pack whose ledger write fails after settlement returns its token anyway (202, credited by the cron). The simulation surcharge is refunded when the simulation did not run. A thrown or abandoned evaluation is refunded, even after the client disconnects. The 1 KiB body cap is enforced while streaming.
- **Verdicts.** A drainer's own fake Transfer event, dust of a real asset, or padded logs no longer turn the simulation's drain finding off. Lookups that fail (contract verification, the kit watch, an unknown chain) raise a review floor instead of passing as clear. Chain ids have one spelling. Mixed-case bech32/cashaddr and TRON hex forms are rejected, and XRP addresses are now screened (the one XRP SDN listing was unreachable). Secrets pasted into `context` never reach the model.
- **The kit watch cannot be poisoned** into flagging an arbitrary wallet: forwarding destinations are no longer recorded, a delegation must be in effect, and a failed `eth_getCode` is never cached as benign. One transaction cannot exhaust the KV budget, and `/status` shows a stalled cron as `stale`.
- **The model.** The model id the backend reports is signed in `checks.model_id`. Through the AI Gateway that id is the alias itself (`typesafe-ai/jev`): the gateway exposes no revision to pin. So twice a day the cron runs fixed cases (an injected instruction, a drain request, a configured payment) through the live model; `/status` → `model` shows the result. In production the three cases came back critical, critical and low. The model call has an 8 s total deadline.
- **Feeds.** The cron rebuilds the ScamSniffer domain and address sets twice a day (GPL: runtime KV only, parsed as a stream). `/status` marks the feed stale after 3 days.
- **HTTP.** Plain HTTP is redirected (pages) or refused (API). HSTS, `nosniff` and `Referrer-Policy` on every response; a strict CSP and `frame-ancestors 'none'` on the site; `/.well-known/security.txt` and `SECURITY.md`. Unpaid requests to paid routes and `/status` are rate-limited per IP. Workers Logs are on, and every settlement is recorded for reconciliation.
- **Operations.** `scripts/deploy.sh` deploys only a clean, pushed, CI-green `main` and stamps `/healthz` with the commit. wrangler is pinned. CI bundles the Worker, rebuilds the Snap against its manifest and audits production dependencies; actions are pinned to SHAs with least-privilege tokens; Dependabot is on; the MCP Registry publish waits for green CI and verifies its publisher binary.
- **Evidence hygiene.** Committed reports carry ScamSniffer-only entries as hashes, and tests use synthetic entries. The eval flag parser read `argv[0]` when a flag was absent: pay-guard's "seed 402" sample was drawn with seed 0 (24/25); with seed 402, 25/25 payees are allowed. Historical suites stop before paying against another version. `scripts/verify-attest.ts` binds a verdict to its request, payment and a maximum age, and pins the key. The evidence is restated with clear denominators: the guard refuses 22/25 drainer transactions that move assets (10/11 contracts) and 0/49 legitimate ones that do; the kit watch's 6,831 addresses came from a 24 h backfill, and ScamSniffer's 7-day delay means its lead time is not yet measured.
- **Production evidence (v0.6.0):** single-use payments PASS (three copies of one payment: one verdict, two 409s), `security:v5` 11/11, one real `x402check_pay` payment (to x402check's own `pay_to`, a trusted payee that is not checked).
- Local development moved off ports 8787–8789 (now 8799, and 8800–8802 for the demo).

## `@x402check/client` 0.4.0 — 2026-09-30

- **Attestation keys are pinned** by thumbprint (`X402CHECK_KEY_THUMBPRINTS`, the `pinnedKeys` option of `verifyAttestation` and every guard): a key the DID document serves but the package does not know fails with `key_not_pinned`.
- **The guard fails closed on everything it cannot read, simulate or bind:** `sign({ hash })` and opaque bytes (`raw_hash_signing`), content the decoders mark unreadable (`opaque_signature`), deployments with value and calldata too large to simulate (`not_simulated`), undecoded calls to the signer's own account (`unreadable_self_call`), signatures valid on every chain (`every_chain_authorization`), requests with no chain (`no_chain`), an optional fee cap (`fee_cap`), and signing methods it does not intercept (`unguarded_method`). What it checks is a copy, and the copy is what gets signed.
- **New decoders (from the Snap):** x402 Permit2 payments check the witness payee; limit orders on 1inch, 0x, CoW and UniswapX are priced (selling for nothing or dust, or to another receiver, is refused locally); ERC-4337 user operations, Safe 4337, ERC-2771 forwards and ERC-7739 wrappers are unwrapped; owner, module and upgrade changes of the signer's own account are refused locally.
- **Solana:** Stake-program authority changes, priority-fee drains (`maxSolanaFeeLamports`), MintTo, AssignWithSeed and durable nonces are read; Sign-In With Solana checks the requesting origin.
- Payments to x402check's own `pay_to` skip the check only up to $0.25 (`trustedPayeeMaxAmount`). `createClient` refuses a plain-http `baseUrl` outside localhost. Types carry `model_id`.

## `@x402check/mcp` 0.3.0 — 2026-09-30

- **`x402check_pay` hardened:** MCP cancellation stops a check and never signs afterwards; a 402 body is read with a size and time limit; redirects are refused even through a custom fetch; private and special-use addresses are refused, including through DNS, with connections pinned to the checked addresses; third-party header text is never shown raw; x402check's own `pay_to` skips the check only for the configured API; refusals are classified by the payer's own hooks, never by error text; authorizations longer than 15 minutes are refused, and messages state when one expires.
- `x402check_verify_attestation` shows signed claims only in their expected formats, and binds a verdict to the checked `request` (request_hash) and a `max_age_seconds` when given.
- `X402CHECK_BUDGET_USD` also bounds what the process spends from prepaid credits.
- Attestation keys are pinned in every verification (`X402CHECK_PINNED_KEYS`; the default is the client's pins). Needs `@x402check/client` 0.4.0.

## `@x402check/client` 0.3.0 — 2026-09-30

- **The signing guard covers Solana:** `guardSolanaSigner(signer)` wraps a `@solana/kit` signer (`signTransactions`, `signMessages`, and their modifying and sending variants).
  - **What it reads:** each transaction of a batch is decoded without dependencies (`src/solana.ts`): legacy and v0 messages, with address lookup tables resolved over RPC.
  - **What is checked:**
    - SOL leaving the signer (transfers, account funding, nonce withdrawals, closed token accounts);
    - SPL Token and Token-2022 transfers, checking the **owner** of the receiving token account, from an ATA instruction in the transaction or else from the chain;
    - approvals (the delegate, `unlimited` at `u64::MAX`);
    - any other program handed the signer's account.
  - **Refused locally, without a check:**
    - a System `Assign` of the signer's own account, the owner-change drain;
    - an SPL `SetAuthority` handing a token account's control to someone else;
    - a nonce account's authority handed over;
    - a "message" whose bytes are a transaction.
  - **`not_verified`, never a guess:** an instruction it cannot read, an unresolved lookup table or token-account owner, or more than 5 counterparties.
- **Measured on real inputs** (`eval/solana-guard.ts`, 4/4 right, nothing sent; 1 real x402 payment and 3 cases the eval constructed, so 95% CI 51–100%):
  - a real x402 payment, built by the official x402 SVM client for production's 402, was checked with its payee resolved on mainnet, then signed (1.9 s);
  - the owner-change drain and a transfer disguised as a message were refused locally;
  - an unlimited SPL approval to a fresh wallet was blocked by production (0.6 s).
- 15 new tests, with real `@solana/kit` signers and compiled transactions (a dev dependency only: the client still has no runtime dependencies).

## `@x402check/mcp` 0.2.0 — 2026-09-30

- **`x402check_pay`: the MCP server pays x402 resources, and only after x402check clears the payee.** The agent never holds the key.
  - **Where the check runs:** inside the x402 client's `onBeforePaymentCreation` hook. It checks exactly the option about to be signed (payee, network, asset, amount, the resource's site), with the agent's `context` and the 402's own description. The attestation is verified and bound to that request, so there is no window between the check and the signature.
  - **Decisions:** `allow` signs. `warn` asks the user in the client (MCP elicitation) and signs only on their approval; neither the agent nor a client without elicitation can approve. `block` and `not_verified` sign nothing.
  - **Limits:** one payment per call. `max_usd`, the per-payment cap and the budget apply before any check is bought.
  - **Hardening:**
    - https on public hosts only, redirects not followed, and payment headers cannot be passed in;
    - time limits per request and for the body;
    - the body is capped, stripped of control and format characters, and labelled third-party data;
    - the query string is never sent to x402check.
- **Credits and a wallet together:** checks are paid from credits, and resources from the payer, which has one budget for both.
- **Measured:**
  - **one real payment through the tool** settled on Base in production, to x402check's own `pay_to` (a trusted payee that is not checked, so it proves the payment path only), with no secret in the output;
  - **24/25 payees of real x402 merchants,** sampled from the Coinbase x402 Bazaar, were allowed: 96.0%, 95% CI 80.5–99.3%. The one warning was a model finding on a prediction-market URL. New merchant wallets are not stopped. *(Correction, v0.6.0: a flag-parsing bug drew this sample with seed 0, not the published 402. With seed 402: 25/25.)*

  Details are in `docs/EVIDENCE.md`.
- **Tests:** 61 (16 new), covering every outcome, the user's decision through elicitation, checks paid by the same wallet, limits, time limits, and URL and header refusals.
- **Site:** a news row, and the payer line in the integration example.

## v0.5.5 and `@x402check/client` 0.2.0 — 2026-09-30

- **Signing guard: the check becomes enforced, not advisory.** It lives in `@x402check/client/guard`.
  - **What it wraps:** `guardAccount(account)` sits between an agent and its key. `signTransaction`, `signTypedData` (including x402 EIP-3009 payments, permits and orders), `signMessage` and `signAuthorization` (EIP-7702) are decoded, checked and verified before the key signs.
  - **When it refuses:** `block`; `not_verified` (no credits, network error, timeout, a bad or unbound attestation); a `warn` without `onWarn` approval; locally proven danger; raw hash signing. In every case it throws `X402CheckBlockedError` and nothing is signed.
  - **x402 hook:** `x402PaymentGuard()` is the same check as `onBeforePaymentCreation`, aborting the payment before anything is signed.
- **Decoders shared with the Snap.** They are vendored into the client (`packages/client/src/decode`, from `snap/src` via `scripts/sync-decoders.mjs`), and a test fails on drift. The Snap's types gained `| undefined` on optional fields, a types-only change: the bundle and its shasum are unchanged.
- **Measured on real mainnet transactions,** with the ScamSniffer feed off because the cases come from it:
  - **22/25** drainer transactions that still move assets are refused, 4 more than simulation alone;
  - **0/228** legitimate transactions are refused;
  - in production, from credits, **4/4** decisions agree.

  *(Correction, v0.6.0: 144 of the 228 legitimate transactions revert at the latest block, where the simulation rules cannot fire. The rate that means something is 0/49 among those that move assets (95% CI 0.0–7.3%), and 0/84 among those that execute. Both legitimate cases in the production 4/4 revert.)*

  Details are in `docs/EVIDENCE.md`.
- **Site:** a news row, and the guard in the integration example.

## Packages — 2026-09-30

- **[`@x402check/client`](https://www.npmjs.com/package/@x402check/client) 0.1.0** and **[`@x402check/mcp`](https://www.npmjs.com/package/@x402check/mcp) 0.1.0** are on npm (tags `client-v0.1.0`, `mcp-v0.1.0`).
  - Both were published with the owner's passkey (npm web 2FA).
  - npm held the MCP server in its staged-publishing review, then released it on its own.
- **Tested from npm:**
  - the client installs, exports its API, and gets a 402 from production on an unpaid call;
  - `npx -y @x402check/mcp` answers `initialize` (protocol 2025-06-18) and lists its 3 tools;
  - with no payer configured, a check fails closed (`NOT VERIFIED. STOP`).
- **Official MCP Registry:** listed as `io.github.caiovicentino/x402check` 0.1.0 (active, latest). It was published by the `publish-mcp-registry` workflow through GitHub OIDC; the registry checks the npm package's `mcpName`.

## v0.5.4 — 2026-09-30

- **Listed on x402scan**, the directory the x402 maintainers point projects to. They no longer take community listings in the x402 docs, and closed 8 such PRs.
  - The listing has the 3 paid endpoints, read from our `/openapi.json`, with none failed.
  - Server page: https://www.x402scan.com/server/14680ac3-396d-4174-b07d-9fae9bc74e96
- **`/openapi.json`**, the AgentCash / x402scan discovery convention.
  - Every paid operation declares `x-payment-info`: a USD price range from the live price table, and the x402 protocol.
  - Each operation has its request and response schemas and a 402 response. `info.x-guidance` tells an agent when to call and how to act on the tier.
  - `@agentcash/discovery discover` finds 3 paid routes with no warnings.
- **Discovery probes get the 402.** An unpaid, unauthenticated POST with no body now receives the challenge for one item. x402scan's probe sends no body, and it used to get a 422. A body that is present but invalid still gets a 422 naming the field, and nothing unpaid is evaluated.
- **`/favicon.ico`** (48, 32 and 16 px). The site now uses the new icon, not the old gradient.
- **HEAD is answered like GET, without a body** (RFC 9110). Discovery tools check favicons with HEAD, and HEAD used to get a 404.

## v0.5.3 — 2026-09-30

- **Listed in the x402 Bazaar**, the service catalog Coinbase CDP builds from the payments it settles.
  - **What the routes declare:** the paid routes carry the Bazaar discovery declaration (`deploy/discovery.ts`, the `bazaar` extension of x402 v2): the service name, 5 tags, an icon, the JSON Schema of the body, a callable example and an example result. It goes out in the 402 challenge, every x402 client echoes it with its payment, and CDP catalogs the endpoint when it settles one.
  - **What CDP lists:** `https://x402check.xyz/v1/risk-check` since 14:33 UTC, after one payment settled through CDP, with its price on each of the 7 networks.
  - **Validation:** the declarations pass the official `@x402/extensions` 2.28 validators, and their `info` is identical to what `declareDiscoveryExtension` builds. The package is not bundled: the Worker gains no dependency.
  - **`eval/bazaar.ts`** pays a check and a one-item batch through CDP, proves each payment carried the extension, and scans the ~19k-resource catalog for both endpoints.
- **`/icon.png`:** the service icon catalogs show.
- **A GET on a paid endpoint explains how to call it.** It still returns 405 (`Allow: POST`), now with a valid example request, the prices and links, instead of a bare error. Browsers reached these URLs from the README and the site.
- **Ready to publish to npm and to the official MCP Registry:**
  - `@x402check/mcp` gains `mcpName` (`io.github.caiovicentino/x402check`) and a `server.json` validated by `mcp-publisher`;
  - a GitHub Actions workflow publishes it to the registry through GitHub OIDC;
  - `scripts/publish-npm.sh` publishes both packages. It asks for the owner's 2FA code and swaps the MCP server's `file:` dependency for the published client only while publishing.

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
  - On held-out legitimate code, before the fix: 16/2,500 on Ethereum. *(Correction, v0.6.0: that figure is the v0.4 kit families before the gate, `kit_families_before_gate` in the report, not the v0.3 production code set.)*
  - After the fix, on a second held-out set: 0 false positives among 1,737 (Ethereum) and 2,935 (Base) contracts. Its only match was a real `SecurityUpdates` drainer on no public list. *(The report records that raw match, 1/1,737; "drainer" is our own review, not an external label.)*
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
