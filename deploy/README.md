# Deploy — public provider with did:web identity

## Status

**LIVE** (2026-09-28): `https://x402check.xyz` — `did:web:x402check.xyz`

- `POST /v1/risk-check` — x402-protected (see below), free tier via `X-Risk-Check-Free`
- `POST /v1/risk-check/batch` — batch endpoint, same pricing
- `GET /.well-known/jwks.json` — stable EC P-256 key (kid `jev-attest-v1`)
- `GET /.well-known/did.json` — DID document (`did:web:x402check.xyz`, QUORUM-resolvable)
- `GET /.well-known/risk-check.json` — discovery document
- Paywall: `@x402/core` v2 SDK, accepts Base Sepolia USDC + Solana Devnet USDC via the x402.org testnet facilitator; mainnet facilitators (CDP for EVM, Kora for Solana) are an env-gated upgrade (`X402_FACILITATOR_URL` + networks).

## Steps to go live (once authenticated)

```bash
npm i -g wrangler
wrangler login            # or: export CLOUDFLARE_API_TOKEN=...

# secrets (never committed)
wrangler secret put AI_GATEWAY_API_KEY          # or TYPESAFE_API_KEY
wrangler secret put JEV_ATTEST_PRIVATE_KEY      # PEM (sec1 EC P-256) — reuse the SAME key across deploys so JWKS stays stable
wrangler secret put JEV_ATTEST_PUBLIC_JWK       # the matching public JWK (kty/crv/x/y/kid/alg/use) — MUST match the private PEM

NOTE: the public JWK must be derived from the private PEM at key-creation time:

    openssl ec -in jev-attest.pem -pubout  # then export the JWK via node:crypto
    # NEVER publish a generated-at-runtime publicJwk next to a stored private PEM:
    # the published key and the signing key must be the same key pair.

wrangler deploy --config deploy/wrangler.toml
```

Then:

1. Point `PROVIDER_HOST` (in `deploy/wrangler.toml` `[vars]`) at your real domain.
2. Route `/.well-known/jwks.json` on that domain (worker route or reverse proxy).
3. The provider DID becomes `did:web:<your-domain>` — anyone can verify attestations against the published JWKS.
4. Publish the discovery URL in `PaymentRequired.extensions["risk-check"].info.risk_check_url` of any x402 resource server.

## Key management note (important)

`loadKeyPair` in `deploy/worker.ts` imports `JEV_ATTEST_PRIVATE_KEY` from the Worker secret when present; without it, it generates an ephemeral key (demo-only — attestations become unverifiable across isolate restarts). For production:

- generate once: `openssl ecparam -genkey -name prime256v1 -noout -out jev-attest.pem`
- store as a Worker secret; the JWKS is then stable and `did:web` verification works from anywhere.

## Alternative hosts

The same handler runs anywhere with a fetch handler (Deno Deploy, Bun, Node behind a reverse proxy). No framework, no dependencies beyond the `ai` SDK.
