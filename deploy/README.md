# Deploy — public provider with did:web identity

## Status

The provider is deploy-ready (`src/handler.ts` is a framework-free fetch handler used by both the Node server and the Cloudflare Worker). Deployment is blocked only on credentials: no valid `CLOUDFLARE_API_TOKEN` / `wrangler login` on this machine (checked 2026-09-27 — token expired, refresh requires interactive login).

## Steps to go live (once authenticated)

```bash
npm i -g wrangler
wrangler login            # or: export CLOUDFLARE_API_TOKEN=...

# secrets (never committed)
wrangler secret put AI_GATEWAY_API_KEY          # or TYPESAFE_API_KEY
wrangler secret put JEV_ATTEST_PRIVATE_KEY      # PEM (sec1 EC P-256) — reuse the SAME key across deploys so JWKS stays stable

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
