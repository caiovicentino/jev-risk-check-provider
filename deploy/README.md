# Deploy — Cloudflare Worker with did:web identity

**Live:** `https://x402check.xyz` — `did:web:x402check.xyz`

| Route | What |
|---|---|
| `POST /v1/risk-check` | single evaluation: from prepaid credits (`Authorization: Bearer x402c_…`, $0.001), or paid per call with x402 at the payment network's price ($0.0035 on Base; $0.005 when a `transaction` is simulated) |
| `POST /v1/risk-check/batch` | up to 25 evaluations, billed per item |
| `POST /v1/credits` / `GET /v1/credits` | buy or top up prepaid credits ($0.10–$100, one x402 payment) / read a token's balance |
| `GET /.well-known/risk-check.json` | discovery: pricing networks, data sources, attestation claims |
| `GET /.well-known/jwks.json`, `/.well-known/did.json` | attestation keys (the current `kid`, today `jev-attest-v1`, plus the next one during a rotation), `did:web` document |
| `GET /.well-known/security.txt` | how to report a vulnerability (RFC 9116) |
| `GET /healthz` | version, deployed commit, and attestation-key health: 503 while the key cannot sign verifiable attestations |
| `GET /status` | data freshness and payments. It shows the OFAC, MetaMask, ScamSniffer and Forta list versions verdicts are using now, their age, and the last runtime-refresh attempt. It also shows each payment network's facilitator, transfer method, fee, floor and margin, the credit terms, the attestation key (`kid`, thumbprint, self-check) and the last model canary. Edge-cached 60 s |

Plain HTTP is never served: a page gets a 301 to HTTPS and an API call a 403, before its body or token is read. Every response carries HSTS, `nosniff` and a `Referrer-Policy`; the site also has a strict CSP.

## Layout

- `worker.ts` — entry point: routing, CORS, `/healthz`, `/status`, embedded MetaMask and Forta sets (`.bin` Data modules)
- `fresh-feeds.ts` — runtime refresh of OFAC and MetaMask from the `feeds` branch (checksums, counts, no large shrink), in the background
- `protected.ts` — the paid flow: validate → price (per item and network) → verify payment → screen the payer → claim the payment → evaluate → settle → release; facilitator routing by compatibility and cost, `/status` payment routes, and the attestation key's load-time check
- `payment-claims.ts` — `PaymentClaim` Durable Object: each x402 payment is claimed once (binding `PAYMENT_CLAIMS`, migration `v4`)
- `http-util.ts` — body cap while streaming, settlement receipts and records, the payer's OFAC screen
- `model-canary.ts` — fixed cases through the live model, twice a day (cron), shown in `/status` → `model`
- `scamsniffer-refresh.ts` — ScamSniffer domain and address sets rebuilt into KV twice a day (cron), parsed as a stream
- `pricing.ts` — prices by payment network, the simulation price, micro-dollar arithmetic
- `credits.ts` — prepaid credits: the `CreditLedger` Durable Object (one per token), purchase, balance and spending
- `cdp.ts` — the Coinbase CDP facilitator: a JWT per call, signed with WebCrypto from the Worker secrets
- `discovery.ts` — discovery metadata for the paid routes:
  - the x402 Bazaar declaration: service name, tags, icon, input schema, a callable example and an example result;
  - the `/openapi.json` document that x402scan and AgentCash read.
- `feeds.ts` — ScamSniffer blobs (domains, addresses, drainer-code fingerprints) read from KV at runtime (GPL-3.0 data: never bundled or committed)
- `runtime.ts` — minimal Workers types, so `deploy/` type-checks with the rest of the repo (`npm run typecheck`)

## Request flow (protected routes)

1. **Validate first.** Read the body (≤ 64 KiB), parse it, validate it (`src/validate.ts`): an unknown field, a mixed-case EVM address with a bad EIP-55 checksum or an unknown chain id is invalid too. With a payment or a credit token, invalid input gets `422 {error, field[, index]}` or `413` before any payment work. Unpaid, it gets the one-item `402` challenge with the reason in `request_error` (monitors and catalogs see a payable endpoint). Invalid input is never charged.
2. **Every evaluation is paid; there is no free tier.**
   - **Price:** the x402 price is unit × units, 1 unit per evaluation, so a batch of *n* costs *n*. `adapter.getBody()` exposes the validated body to the SDK's dynamic price.
   - **Unpaid request:** it gets the `402` challenge with the accepted options.
   - **Paid request:** verify → admit (`admitPayment` in `http-util.ts`) → evaluate → **settle** → release. If the evaluation cannot be produced, nothing is settled (`503`, no charge). If settlement fails, the response is `402 payment_settlement_failed`, no attestation is returned, and the claim is released so the payer can retry.
   - **Only x402 v2** payloads are processed: the adapter hands x402 core only a v2 `PAYMENT-SIGNATURE` (never `X-PAYMENT`); anything else gets the v2 challenge.
   - **Admission**, before any work:
     - the payer must be readable (`402 payment_unrecognized` otherwise) and not on the OFAC SDN list (`403 payer_sanctioned`);
     - the authorization must stay valid for 60 s more and at most 24 h (`402 authorization_expires_too_soon` / `authorization_valid_too_long`);
     - the payer may have 8 payments in flight (`429 payer_busy`), and 5 settlement refusals in an hour hold it back (`429 payer_settlement_failures`; facilitator timeouts and errors never count);
     - **single use:** the payment is claimed once by what its payer signed (EIP-3009: network, asset, payer, nonce; Permit2: network, owner, nonce; Solana: the message bytes), however the JSON is spelled. A copy gets `409 payment_already_used`; a claim store that cannot be reached refuses the payment (`503`, no charge).
   - **One transaction, one purchase:** after settlement the transaction is claimed too; a facilitator confirming one transaction for two payments releases nothing the second time (`402 payment_settlement_reused`).
   - **The attestation key:** on x402check.xyz, a missing or mismatched key pair makes every paid route answer `503 attestation_key_unavailable` (no charge).
   - Every settlement is recorded in KV (`st:<network>:<tx>`, 400 days) for reconciliation against the chain.
3. **Facilitator routing** (`paymentRouting` in `protected.ts`, recomputed every 10 minutes). For each network the router picks, in order:
   1. a facilitator that accepts our price (Dexter refuses payments below its floor);
   2. one that does not cost more than the price (the settlement fee plus one model call). A network whose every route would lose money is not offered: it leaves the 402 challenge, and comes back on its own once a route clears its cost (Avalanche left on 2026-10-15, when PayAI's fee there reached $0.0057 against a $0.001 price, below Dexter's floor);
   3. one every payer can pay through: EIP-3009 (PayAI, Coinbase CDP) over Dexter's EVM Permit2, which needs an on-chain allowance most wallets lack;
   4. the one cheapest to us. PayAI charges from its live fee table (gas + 30% per settlement; a failed lookup reuses the last table read). Dexter charges nothing. Coinbase CDP charges $0.001 per settlement after 1,000 free a month, and routing always uses the paid rate.

   The resource server gets each facilitator scoped to its networks, first. `/status` shows two things:
   - `payments`: the facilitator, transfer method, fee, floor and margin of every route, and whether the network is offered (`offered`; when not, `reason`);
   - `facilitators`: whether each configured facilitator answers, and the mainnets it offers. Only an HTTP status is shown, never a key.

   **Coinbase CDP** is used only when both `CDP_API_KEY_ID` and `CDP_API_KEY_SECRET` are set (see below).
   - Every call carries a JWT signed with that key (`deploy/cdp.ts`, WebCrypto, 120 s).
   - CDP settles Base, Polygon, Arbitrum, Monad and Solana.
   - A key CDP rejects drops it from routing, and PayAI takes those networks back.
4. **Pricing** (`deploy/pricing.ts`, in micro-dollars):
   - per network: Base $0.0035, Solana $0.002, Sei $0.002, Avalanche $0.001, Monad $0.001, Polygon $0.007, Arbitrum $0.009;
   - an item whose `transaction` will be simulated costs $0.005, or the network's price if higher. That applies on a supported simulation chain, with `SIMULATION` not off;
   - a batch is the sum of its items;
   - the discovery document states `amounts_by_network`, `amount_with_transaction` and the `credits` terms.
5. **Prepaid credits** (`deploy/credits.ts`, Durable Object binding `CREDITS`, migration `v3`):
   - **Purchase:** a pack costs its face value on every network. After settlement the token's ledger is credited, keyed by the settlement's transaction, so it is credited once. If the ledger cannot be written, the buyer still gets the token (`202`, `status: "pending"`) and the cron applies the queued credit (`pc:*` in KV, holding the token's SHA-256, never the token).
   - **Checks:** a check with the token debits the ledger atomically, runs, and is refunded when no verdict is produced, including when the evaluation throws or the client disconnects (the refund runs in `waitUntil`). The simulation surcharge is refunded when the simulation did not run. There is no 402 and no settlement.
   - **Storage:** the token is shown once. Only its SHA-256, the ledger's name, is stored.
6. **Mainnets only by default:** Base, Polygon, Arbitrum, Avalanche, Monad, Sei and Solana. `ENABLE_TESTNETS="true"` adds Base Sepolia, Arbitrum Sepolia and Solana Devnet on a local host only; on x402check.xyz it is ignored and logged, because testnet USDC is free.
7. **Outages:** a facilitator's `/supported` has 3 s (under the stack's 4 s wait for the routing table; a failure is remembered for 30 s) and verify/settle 30 s. A network whose facilitator is down leaves the 402 challenge. A stack build that fails is routed again once from fresh answers, and is never cached. If the payment stack still cannot build a challenge or read a payment, the answer is `503 payment_unavailable` with `Retry-After`, never a 500, and nothing is charged. Identity documents and the site never wait for the payment stack.
8. **Rate limits:** every POST to a paid route, and every balance read, is limited per IP (approximately: Cloudflare's rate-limit binding counts per location and lets a short burst through). Unpaid requests (and ones whose credential is malformed), and `/status`, get 60 a minute (`UNPAID_LIMITER`); requests with a well-formed credential (an x402 v2 payment or a `Bearer x402c_…` token) get 300 a minute (`PAID_LIMITER`). Every response, 429s and preflights included, carries CORS and the security headers.

## Secrets and variables

```bash
cd deploy
wrangler secret put AI_GATEWAY_API_KEY          # or TYPESAFE_API_KEY
wrangler secret put JEV_ATTEST_PRIVATE_KEY      # PEM: SEC1 "EC PRIVATE KEY" or PKCS#8 (escaped \n newlines are accepted)
wrangler secret put JEV_ATTEST_PUBLIC_JWK       # the matching public JWK (kty/crv/x/y/kid/alg/use)
# only during a rotation (AGENTS.md §3.12): the next public JWK, published in jwks.json and did.json before it signs
wrangler secret put JEV_ATTEST_NEXT_PUBLIC_JWK
# optional: settle through Coinbase CDP (portal.cdp.coinbase.com → API Keys → Secret API key, Ed25519, no IP allowlist)
wrangler secret put CDP_API_KEY_ID              # the key's id
wrangler secret put CDP_API_KEY_SECRET          # its secret: base64 Ed25519, or an EC key in PEM
```

The public JWK must be derived from the private PEM. A new key needs a **new** `kid` (for example `jev-attest-v2`); replace `KID` below:

```bash
node -e 'const c=require("crypto");const k=c.createPublicKey(require("fs").readFileSync("jev-attest.pem","utf8")).export({format:"jwk"});console.log(JSON.stringify({kty:"EC",crv:"P-256",x:k.x,y:k.y,kid:"KID",alg:"ES256",use:"sig"}))'
```

Keep the PEM outside the repository with `chmod 600`. At load the Worker checks that both secrets are present, that the private key matches the public JWK, and that a canary attestation signs and verifies. On x402check.xyz a failure makes paid routes refuse all work with no charge, and `/healthz` answers 503 with `/status` → `attestation.reason`. Only a local host falls back to an ephemeral key. The SDK and the MCP server pin the key by thumbprint, so a rotation follows AGENTS.md §3.12: pin the new thumbprint in a client release first.

Optional variables:

| Variable | Effect |
|---|---|
| `ENABLE_TESTNETS` | `"true"` adds testnet payments (staging only) |
| `ONCHAIN` | `"off"` disables provider-side JSON-RPC lookups |
| `RPC_URLS` | JSON `{caip2: url}` overriding the public RPCs in `src/onchain.ts` |
| `SOL_RPC_URL_MAINNET` | Solana RPC for on-chain facts and for x402 Solana payment requirements (default for the latter: publicnode; `api.mainnet-beta.solana.com` refuses Worker egress) |
| `GIT_COMMIT` | set by `scripts/deploy.sh`; shown in `/healthz` |
| `SIMULATION` | `"off"` disables transaction simulation (`eth_simulateV1`) |
| `SIMULATION_RPC_URLS` | JSON `{caip2: url}` overriding the simulation RPCs (they must serve `eth_simulateV1`) |
| `CONTRACT_INTEL` | `"off"` disables contract-verification lookups (Blockscout) |
| `FEEDS_URL` | base URL of the published feeds for runtime refresh (default: this repository's `feeds` branch); `"off"` keeps the embedded snapshot |
| `KIT_WATCH` | `"off"` disables the kit watch: the block-scanning cron and its evaluation-time lookups |

## Threat feeds

```bash
npm run ofac:update                                  # OFAC SDN → src/data/ofac-sdn.ts (commit it)
npm run feeds:update                                 # MetaMask list → src/data/*.bin + threat-feeds.ts (commit it)
npx tsx scripts/update-threat-feeds.ts --forta       # + Forta drainer-code fingerprints → src/data (static dataset)
npx tsx scripts/update-threat-feeds.ts --scamsniffer --upload   # ScamSniffer domains, addresses and code fingerprints → KV (binding RATE), 4 writes; the cron refreshes domains and addresses on its own
```

- OFAC and MetaMask are embedded **and** refreshed at runtime. `.github/workflows/feeds.yml` rebuilds them daily with a read-only token and no install scripts. A separate job signs the manifest with Ed25519 and publishes it to the `feeds` branch; the key is the `FEEDS_SIGNING_KEY` secret of the `feeds` environment.
- That job takes only the five expected regular files out of the build artifact, into a fresh directory: a `.git`, a symlink or any other entry fails the run. Git then runs only there, with no system or global config, `core.fsmonitor` off and hooks disabled.
- Before signing, it compares the new release with the published one (`scripts/feeds-guard.mjs`: plain node, checked out from the run's commit, never taken from the build artifact). It signs nothing when:
  - OFAC addresses shrink by more than 5% or grow by more than 50%;
  - **any published OFAC address is missing from the new list** (a delisting; counts only are printed);
  - MetaMask entries move by more than 20% either way;
  - a date goes backwards, or runs more than a day ahead;
  - no published manifest or OFAC snapshot can be read, or a snapshot is not the one its manifest names.

  The run then fails with `feeds guard` errors and the Worker keeps its lists. After reviewing the change, `gh workflow run feeds.yml -f override=true` publishes it anyway.
- The Worker pins the public key (`FEEDS_PUBLIC_KEY` in `fresh-feeds.ts`) and checks hourly, in the background, OFAC before MetaMask. It swaps in data only if all of these hold:
  - the signature is valid;
  - the data is newer and dated no later than tomorrow;
  - it matches the manifest's SHA-256 and entry counts;
  - it has not shrunk sharply against the list in use.

  Otherwise it keeps the current list. `/status` shows which version is in use.
- **OFAC on new isolates.** The last verified OFAC release is kept in KV (`feed:ofac:v1`: the signed manifest, its signature and the snapshot, re-verified with the pinned key on every load), written once per release and only forward. A new isolate applies it with one KV read before anything else. A paid request on a cold isolate waits up to 2.5 s for a current list; past that it goes ahead on the list it has (the attestation states its date), logs `a paid check went ahead on the … OFAC list` once, and the isolate stops waiting.
- **MetaMask on new isolates (since v0.6.10).** The last verified MetaMask list is kept the same way (`feed:metamask:v1`: the signed manifest, its signature, the list as base64 and its JSON, re-verified on every load: checksums, entry count, shrink bound), written once per list and only forward. Before it, a new isolate checked domains against the list embedded at deploy until its own refresh finished; on 2026-10-15 that list was 16 days older than the published one. A paid request on a cold isolate waits for this read within the same 2.5 s as OFAC. `/status` → `data.metamask_phishing.origin` says `kv`, `refreshed` or `embedded`.
- **The embedded snapshot** is what a brand-new isolate holds until then: `npx tsx scripts/sync-embedded-feeds.ts` refreshes `src/data/ofac-sdn.ts` from the published release (verified as the Worker verifies it), and `scripts/deploy.sh` refuses to deploy an older one.
- **To rotate the publisher key,** generate a new Ed25519 key, store the PKCS#8 PEM with `gh secret set FEEDS_SIGNING_KEY --env feeds` (the environment only main may use), put the raw public key (base64url) in `FEEDS_PUBLIC_KEY`, deploy, then run the workflow (`gh workflow run feeds.yml`) so the branch carries a manifest signed with the new key. Until it does, the Worker keeps its current lists. Last rotated 2026-09-30.
- ScamSniffer lives only in KV and is picked up within an hour. The Worker's cron rebuilds the domain and address sets at 05:37 and 17:37 UTC (`scamsniffer-refresh.ts`). It resolves the upstream commit first and reads both lists at that SHA; when GitHub does not answer, it reads `main` and records the fetch date and no commit. A list that halves, or grows by more than 50% or by more than 100,000 domains or 2,000 addresses since the last refresh, is refused: the previous sets stay and Workers Logs show `scamsniffer refresh kept the previous data: <reason>`. Addresses x402check never flags (`src/never-flag.ts`) are left out and counted in the meta's `never_flag_dropped`. The code set keeps its own date, `code_as_of`. `/status` marks the feed stale after 3 days without a refresh. The code fingerprints come from the listed addresses' runtime code on 7 EVM chains (about 2 minutes via publicnode), with the manual upload above.
- Every attestation states the date and status of each list it consulted (`checks.sanctions`, `checks.feeds`).

## Kit watch

The Worker's cron (`[triggers]` in `wrangler.toml`, every minute) reads the new blocks of Ethereum and Base and keeps the watchlist in KV (`deploy/kit-watch.ts`). All keys start with `kw:`, and none of them is public.

```bash
npx tsx scripts/kit-catalog.ts                              # listed drainer contracts → .cache/intel/kit-catalog.json (~5 min)
npx tsx scripts/kit-registry.ts --upload                    # families (drainer kits, sweepers, poisoners) → KV kw:registry
npx tsx scripts/hunt-kits.ts --chain eip155:1 --hours 24    # backfill (same code as the cron) → .cache/intel/
npx tsx scripts/hunt-kits.ts --chain eip155:1 --retry       # segments the backfill could not fetch
npx tsx scripts/hunt-kits.ts --chain eip155:1 --upload-all  # watchlist, delegate verdicts, learned families, cursor → KV
```

- **Each run:**
  - it reads everything it needs in one round of KV reads (the lease, the stats, the families, each chain's delegates and queue): a cron placed far from Cloudflare's KV and the RPCs pays ~0.3 s per round, and runs from Taipei took up to 83 s;
  - it holds the lease (`kw:lease`, its start time) for the whole run and releases it in the stats it writes last, so a run that finds the lease held skips, and a run that died holds it at most 5 minutes;
  - it first retries what earlier runs could not evaluate (`kw:pending:<chain>`), with its original block, chosen by cost in queue order: anything whose delegate has since settled (nothing left to do), a threat's authorizations up to the run's evaluation budget, and at most 100 reads (creations, delegates still to classify);
  - it scans from `kw:cursor:<chain>` to the head, minus a few confirmations: up to 15 Ethereum blocks and 90 Base blocks per run, in segments of 10; each chain's block batch starts where the last run's measurement left it. A segment whose blocks no endpoint serves ends the run's scan there: the segments before it are kept, the next run resumes with it (never skipped), and the chain's `error` says what each endpoint answered;
  - authorizations to a delegate whose verdict leaves nothing to evaluate (a revocation, or a delegate judged not a threat with no re-probe due) are only counted (`settled_authorizations` in `/status`): a flood of benign batch delegations costs nothing and leaves no gap. A segment keeps at most 5,000 others for evaluation;
  - a threat's authorizations (each a signature recovery, a code read and at most one entry) are evaluated up to the run's budget, 400 on Ethereum and 200 on Base, shared by the queue and the new blocks; the rest wait in the queue, in order;
  - it writes new entries (`kw:a:<address>`, one-year TTL; the current ones are read in bulk, 100 keys per KV operation, and only a new or stronger entry is written), the delegate verdicts and the families it learned.
- **Deferred work:** a code read that no endpoint answers, a delegate the scan could not probe (the probe budget spent, the simulation down) and a threat's authorizations past the run's evaluation budget are queued in `kw:pending:<chain>` (one KV value per chain, at most 10,000 items, written at most once a run), keyed by the whole signed tuple. An item a day old, or pushed out of a full queue, is abandoned and counted as a gap. Attestations sign what waits as `checks.kit_watch.pending`.
- **KV writes:** at most 450 watch entries per run on Ethereum and 250 on Base (with the bulk reads, the run's own reads and writes, the credits retry and the ScamSniffer refresh, the invocation stays under ~870 of its 1,000 KV operations), and 25,000 a UTC day across both chains. The last 5,000 of the day's budget go only to kit contracts and labelled delegations, and the most severe kinds are always written first. An entry the caps leave out is a gap.
- **Coverage:** every hole is counted in the stats (`gaps_total`) and moves `unbroken_since` past its block: a skipped range, an abandoned item, more than 5,000 authorizations to evaluate in a segment (1,000 before v0.6.6, when authorizations to settled delegates counted too), an entry the caps left out. Stats from before v0.6.4 were migrated once: the 9,884 (Ethereum) and 2,090 (Base) code reads dropped before v0.6.2 count as gaps, and unbroken coverage starts with the first block v0.6.4 scanned.
- **Lag:** a chain more than 6 hours behind skips ahead, and the gap is recorded. `/status` → `data.kit_watch` shows per chain the lag, the gaps (every hole ever recorded), `unbroken_since`, `pending_reads`, the day's `writes_today` and `dropped_today`, and the counts per kind. A chain with 50 or more queued items is `degraded`.
- **RPCs:** blocks and the head come from `SCAN_ENDPOINTS` (`src/rpc.ts`): BlastAPI, Tenderly, MEV Blocker, 1RPC, Flashbots and MeowRPC for Ethereum; Tenderly, 1RPC, BlastAPI, MeowRPC and dRPC for Base. Each batch starts at the next of them, so no public endpoint takes the whole volume (the Base endpoints rate-limited the cron's shared egress with HTTP 429 on 2026-10-15), and one that answers 429 is not asked again in that run. The endpoints that serve paid evaluations (publicnode, and Base's official RPC) are only the last fallback, so the scan's ~20 GB a day cannot rate-limit a check. Each request asks for about 2 MB of block JSON (the batch follows the size of the blocks just fetched; a batch no endpoint serves in time is split in half, down to single blocks, and stays that small for the run), and each batch is dropped once its creations and authorizations are taken, to keep the cron's peak memory under the isolate's 128 MB (batches of 10 full blocks reached 231 MB on 2026-10-01). Code reads go to `READ_ENDPOINTS`, BlastAPI first; each endpoint gets only what the ones before it left unanswered, and one that fails is tried last for the rest of the run.
- **Refreshing the families:** re-run the catalog and the registry when ScamSniffer or Forta change. Families learned from behaviour (`kw:learned`) are kept.

## Deploy, validate, roll back

```bash
npm test && npm run typecheck
X402CHECK_BASE=http://localhost:8799 npm run security:v2      # against `wrangler dev --local --port 8799`
git push origin main                                           # then wait for CI on that commit
scripts/deploy.sh                                              # refuses unless the tree is clean, HEAD is main on GitHub and CI passed
export PAY_NETWORK=eip155:8453                                 # pay the probes in USDC on Base
npm run security:v5 && npx tsx eval/replay.ts                  # against production (~$0.11, every evaluation paid)
PAY=none npx tsx eval/bazaar.ts                                # the Bazaar listing, read-only
npx wrangler rollback                                          # previous version, if anything regresses
```

Then check `/healthz` (version, commit, `attestation_key: "ok"`) and `/status` (routes, facilitators, kit watch lag 0 and gaps 0). `security:v3` and `security:v4` are historical suites: against another version they stop before paying.

Every evaluation is paid, so the production suites need a funded payer. They read the key from `~/.config/paysol/payer-evm.key` (Base USDC; the x402 exact scheme is gasless for the payer), or `payer-sol.b58` for Solana. The `security:v5`, `replay`, `bazaar` and `mcp-pay` reports record the settlement transactions. Without a payer, the probes that need a verdict are reported as SKIP, never as PASS.
