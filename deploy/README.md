# Deploy — Cloudflare Worker with did:web identity

**Live:** `https://x402check.xyz` — `did:web:x402check.xyz`

| Route | What |
|---|---|
| `POST /v1/risk-check` | single evaluation. Free tier, then x402 |
| `POST /v1/risk-check/batch` | up to 25 evaluations. Billed and counted per item |
| `GET /.well-known/risk-check.json` | discovery: pricing networks, data sources, attestation claims |
| `GET /.well-known/jwks.json`, `/.well-known/did.json` | attestation key (`kid jev-attest-v1`), `did:web` document |
| `GET /healthz` | liveness + `freeEvalsToday`. Edge-cached 60 s so it cannot hammer the quota Durable Object |

## Layout

- `worker.ts` — entry point: routing, CORS, `/healthz`, embedded MetaMask feed (a `.bin` Data module), `RateCounter` export
- `protected.ts` — paid and free-tier flow: validate → quota → pay → evaluate → settle → release
- `counter.ts` — `RateCounter` Durable Object (SQLite). Atomic per-key daily counters with a cost per request; admission budgets for new client ids
- `feeds.ts` — ScamSniffer blobs read from KV at runtime (GPL-3.0 data: never bundled or committed)
- `runtime.ts` — minimal Workers types, so `deploy/` type-checks with the rest of the repo (`npm run typecheck`)

## Request flow (protected routes)

1. **Validate first.** Read the body (≤ 64 KiB), parse it, validate it (`src/validate.ts`). Invalid input gets `422 {error, field[, index]}` or `413` and costs no free slot and no payment.
2. **Free tier.** Units = 1 per evaluation, so a batch of *n* costs *n*.
   - With `X-Risk-Check-Client`, the id is charged against its own daily allowance. The first sighting of an id must also fit the per-/64 (10/day) and global (1000/day) new-client budgets.
   - If the id is refused or exhausted, the IP allowance is used instead, so draining the global budget cannot lock real users out.
   - IP keys use the full IPv4 address. IPv6 keys use the **/64**.
   - Response headers: `X-Risk-Check-Free: true` and `X-Risk-Check-Free-Remaining`.
3. **Paid.** The x402 price is unit × units (`adapter.getBody()` exposes the validated body to the SDK's dynamic price). Flow: verify → evaluate → **settle** → release. If settlement fails the response is `402 payment_settlement_failed` and no attestation is returned.
4. **Mainnets only by default:** Base, Polygon, Arbitrum, Avalanche, Monad, Sei ($0.001) and Solana ($0.002). `ENABLE_TESTNETS="true"` adds Base Sepolia, Arbitrum Sepolia and Solana Devnet. **Never enable it in production**: testnet USDC is free.

## Secrets and variables

```bash
cd deploy
wrangler secret put AI_GATEWAY_API_KEY          # or TYPESAFE_API_KEY
wrangler secret put JEV_ATTEST_PRIVATE_KEY      # PEM: SEC1 "EC PRIVATE KEY" or PKCS#8 — keep it stable
wrangler secret put JEV_ATTEST_PUBLIC_JWK       # the matching public JWK (kty/crv/x/y/kid/alg/use)
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
| `FREE_TIER_DAILY` | free evaluations per caller per day (default 25) |

## Threat feeds

```bash
npm run ofac:update                                  # OFAC SDN → src/data/ofac-sdn.ts (commit it)
npm run feeds:update                                 # MetaMask list → src/data/*.bin + threat-feeds.ts (commit it)
npx tsx scripts/update-threat-feeds.ts --scamsniffer --upload   # ScamSniffer → KV (binding RATE), 3 writes
```

- OFAC and MetaMask are embedded, so a data refresh ships with a deploy.
- ScamSniffer lives only in KV and is picked up within an hour. Refresh it daily; the public data already lags 7 days.
- Every attestation states the date and status of each list it consulted (`checks.sanctions`, `checks.feeds`).

## Deploy, validate, roll back

```bash
npm test && npm run typecheck
X402CHECK_BASE=http://localhost:8799 npm run security:v2      # against `wrangler dev --local --port 8799`
cd deploy && wrangler deploy
npm run security:v2 && npm run prod                            # against production
wrangler rollback                                              # previous version, if anything regresses
```

Add `IPV6_A=<addr> IPV6_B=<addr in the same /64>` to `npm run security:v2` to prove the /64 quota aggregation from a real IPv6 host.
