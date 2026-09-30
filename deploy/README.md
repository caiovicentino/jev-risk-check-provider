# Deploy — Cloudflare Worker with did:web identity

**Live:** `https://x402check.xyz` — `did:web:x402check.xyz`

| Route | What |
|---|---|
| `POST /v1/risk-check` | single evaluation: from prepaid credits (`Authorization: Bearer x402c_…`, $0.001), or paid per call with x402 at the payment network's price ($0.0035 on Base; $0.005 when a `transaction` is simulated) |
| `POST /v1/risk-check/batch` | up to 25 evaluations, billed per item |
| `POST /v1/credits` / `GET /v1/credits` | buy or top up prepaid credits ($0.10–$100, one x402 payment) / read a token's balance |
| `GET /.well-known/risk-check.json` | discovery: pricing networks, data sources, attestation claims |
| `GET /.well-known/jwks.json`, `/.well-known/did.json` | attestation key (`kid jev-attest-v1`), `did:web` document |
| `GET /healthz` | liveness and version |
| `GET /status` | data freshness and payments. It shows the OFAC, MetaMask, ScamSniffer and Forta list versions verdicts are using now, their age, and the last runtime-refresh attempt. It also shows each payment network's facilitator, transfer method, fee, floor and margin, and the credit terms. Edge-cached 60 s |

## Layout

- `worker.ts` — entry point: routing, CORS, `/healthz`, `/status`, embedded MetaMask and Forta sets (`.bin` Data modules)
- `fresh-feeds.ts` — runtime refresh of OFAC and MetaMask from the `feeds` branch (checksums, counts, no large shrink), in the background
- `protected.ts` — the paid flow: validate → price (per item and network) → verify payment → evaluate → settle → release; facilitator routing by compatibility and cost, and `/status` payment routes
- `pricing.ts` — prices by payment network, the simulation price, micro-dollar arithmetic
- `credits.ts` — prepaid credits: the `CreditLedger` Durable Object (one per token), purchase, balance and spending
- `cdp.ts` — the Coinbase CDP facilitator: a JWT per call, signed with WebCrypto from the Worker secrets
- `discovery.ts` — x402 Bazaar discovery metadata for the paid routes: service name, tags, icon, input schema, a callable example and an example result
- `feeds.ts` — ScamSniffer blobs (domains, addresses, drainer-code fingerprints) read from KV at runtime (GPL-3.0 data: never bundled or committed)
- `runtime.ts` — minimal Workers types, so `deploy/` type-checks with the rest of the repo (`npm run typecheck`)

## Request flow (protected routes)

1. **Validate first.** Read the body (≤ 64 KiB), parse it, validate it (`src/validate.ts`). Invalid input gets `422 {error, field[, index]}` or `413` and is never priced.
2. **Every evaluation is paid; there is no free tier.**
   - **Price:** the x402 price is unit × units, 1 unit per evaluation, so a batch of *n* costs *n*. `adapter.getBody()` exposes the validated body to the SDK's dynamic price.
   - **Unpaid request:** it gets the `402` challenge with the accepted options.
   - **Paid request:** verify → evaluate → **settle** → release. If the evaluation cannot be produced, nothing is settled (`503`, no charge). If settlement fails, the response is `402 payment_settlement_failed` and no attestation is returned.
3. **Facilitator routing** (`paymentRouting` in `protected.ts`, recomputed every 10 minutes). For each network the router picks, in order:
   1. a facilitator that accepts our price (Dexter refuses payments below its floor);
   2. one every payer can pay through: EIP-3009 (PayAI, Coinbase CDP) over Dexter's EVM Permit2, which needs an on-chain allowance most wallets lack;
   3. the one cheapest to us. PayAI charges from its live fee table (gas + 30% per settlement). Dexter charges nothing. Coinbase CDP charges $0.001 per settlement after 1,000 free a month, and routing always uses the paid rate.

   The resource server gets each facilitator scoped to its networks, first. `/status` shows two things:
   - `payments`: the facilitator, transfer method, fee, floor and margin of every route;
   - `facilitators`: whether each configured facilitator answers, and the mainnets it offers. Only an HTTP status is shown, never a key.

   **Coinbase CDP** is used only when both `CDP_API_KEY_ID` and `CDP_API_KEY_SECRET` are set (see below).
   - Every call carries a JWT signed with that key (`deploy/cdp.ts`, WebCrypto, 120 s).
   - CDP settles Base, Polygon, Arbitrum and Solana.
   - A key CDP rejects drops it from routing, and PayAI takes those networks back.
4. **Pricing** (`deploy/pricing.ts`, in micro-dollars):
   - per network: Base $0.0035, Solana $0.002, Sei $0.002, Avalanche $0.001, Monad $0.001, Polygon $0.007, Arbitrum $0.009;
   - an item whose `transaction` will be simulated costs $0.005, or the network's price if higher. That applies on a supported simulation chain, with `SIMULATION` not off;
   - a batch is the sum of its items;
   - the discovery document states `amounts_by_network`, `amount_with_transaction` and the `credits` terms.
5. **Prepaid credits** (`deploy/credits.ts`, Durable Object binding `CREDITS`, migration `v3`):
   - **Purchase:** a pack costs its face value on every network. After settlement the token's ledger is credited, keyed by the settlement's transaction, so it is credited once.
   - **Checks:** a check with the token debits the ledger atomically, runs, and is refunded when no verdict is produced. There is no 402 and no settlement.
   - **Storage:** the token is shown once. Only its SHA-256, the ledger's name, is stored.
6. **Mainnets only by default:** Base, Polygon, Arbitrum, Avalanche, Monad, Sei and Solana. `ENABLE_TESTNETS="true"` adds Base Sepolia, Arbitrum Sepolia and Solana Devnet. **Never enable it in production**: testnet USDC is free.

## Secrets and variables

```bash
cd deploy
wrangler secret put AI_GATEWAY_API_KEY          # or TYPESAFE_API_KEY
wrangler secret put JEV_ATTEST_PRIVATE_KEY      # PEM: SEC1 "EC PRIVATE KEY" or PKCS#8 — keep it stable
wrangler secret put JEV_ATTEST_PUBLIC_JWK       # the matching public JWK (kty/crv/x/y/kid/alg/use)
# optional: settle through Coinbase CDP (portal.cdp.coinbase.com → API Keys → Secret API key, Ed25519, no IP allowlist)
wrangler secret put CDP_API_KEY_ID              # the key's id
wrangler secret put CDP_API_KEY_SECRET          # its secret: base64 Ed25519, or an EC key in PEM
```

The public JWK must be derived from the private PEM:

```bash
node -e 'const c=require("crypto");const k=c.createPublicKey(require("fs").readFileSync("jev-attest.pem","utf8")).export({format:"jwk"});console.log(JSON.stringify({kty:"EC",crv:"P-256",x:k.x,y:k.y,kid:"jev-attest-v1",alg:"ES256",use:"sig"}))'
```

Keep the PEM outside the repository with `chmod 600`. Without the secret, the Worker falls back to an ephemeral key, which is demo-only: attestations stop verifying across isolates.

Optional variables:

| Variable | Effect |
|---|---|
| `ENABLE_TESTNETS` | `"true"` adds testnet payments (staging only) |
| `ONCHAIN` | `"off"` disables provider-side JSON-RPC lookups |
| `RPC_URLS` | JSON `{caip2: url}` overriding the public RPCs in `src/onchain.ts` |
| `SOL_RPC_URL_MAINNET` | Solana RPC for on-chain facts and x402 Solana settlement |
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
npx tsx scripts/update-threat-feeds.ts --scamsniffer --upload   # ScamSniffer domains, addresses and code fingerprints → KV (binding RATE), 4 writes
```

- OFAC and MetaMask are embedded **and** refreshed at runtime. `.github/workflows/feeds.yml` rebuilds them daily with a read-only token and no install scripts. A separate job signs the manifest with Ed25519 and publishes it to the `feeds` branch; the key is in the `FEEDS_SIGNING_KEY` repository secret.
- The Worker pins the public key (`FEEDS_PUBLIC_KEY` in `fresh-feeds.ts`) and checks hourly, in the background. A cold isolate waits up to 400 ms. It swaps in data only if all of these hold:
  - the signature is valid;
  - the data is newer and dated no later than tomorrow;
  - it matches the manifest's SHA-256 and entry counts;
  - it has not shrunk sharply against the list in use.

  Otherwise it keeps the current list. `/status` shows which version is in use.
- **To rotate the publisher key,** generate a new Ed25519 key, store the PKCS#8 PEM with `gh secret set FEEDS_SIGNING_KEY`, put the raw public key (base64url) in `FEEDS_PUBLIC_KEY`, and deploy.
- ScamSniffer lives only in KV and is picked up within an hour. Refresh it daily; the public data already lags 7 days. The code fingerprints come from the listed addresses' runtime code on 7 EVM chains (about 2 minutes via publicnode).
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
  - it scans from `kw:cursor:<chain>` to the head, minus a few confirmations: up to 15 Ethereum blocks and 90 Base blocks per run, in segments of 10;
  - it writes new entries (`kw:a:<address>`, one-year TTL), the delegate verdicts and the families it learned;
  - it takes a 30-second lease (`kw:lease`), so overlapping runs skip.
- **Lag:** a chain more than 6 hours behind skips ahead, and the gap is recorded. `/status` → `data.kit_watch` shows the lag, the gaps and the counts per kind.
- **RPCs:** blocks come from `SCAN_ENDPOINTS` (`src/rpc.ts`): the BlastAPI and Tenderly public gateways for Ethereum, and Base's official RPC. The endpoints that serve paid evaluations are only the last fallback, so the scan's ~20 GB a day cannot rate-limit a check.
- **Refreshing the families:** re-run the catalog and the registry when ScamSniffer or Forta change. Families learned from behaviour (`kw:learned`) are kept.

## Deploy, validate, roll back

```bash
npm test && npm run typecheck
X402CHECK_BASE=http://localhost:8799 npm run security:v2      # against `wrangler dev --local --port 8799`
cd deploy && wrangler deploy
export PAY_NETWORK=eip155:8453                                 # pay the probes in USDC on Base
npm run security:v3 && npm run security:v2 && npm run prod     # against production (~$0.07, every evaluation paid)
wrangler rollback                                              # previous version, if anything regresses
```

Every evaluation is paid, so the production suites need a funded payer. They read the key from `~/.config/paysol/payer-evm.key` (Base USDC; the x402 exact scheme is gasless for the payer), or `payer-sol.b58` for Solana. Each report records the settlement tx hashes. Without a payer, the probes that need a verdict are reported as SKIP, never as PASS.
