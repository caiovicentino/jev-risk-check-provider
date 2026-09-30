# Security policy

x402check checks a counterparty before an AI agent or a wallet pays, and signs every
verdict. If you find a way to break that, please tell us privately first.

## Report a vulnerability privately

Use GitHub's private vulnerability reporting on this repository:
**[Report a vulnerability](https://github.com/caiovicentino/jev-risk-check-provider/security/advisories/new)**
(the Security tab, then Advisories). The report stays private between you and the
maintainer until a fix is published.

<!-- Maintainers: the link above works only while "Private vulnerability reporting" is
enabled in Settings > Code security. -->

If that page does not offer the form, open a public issue that asks for a private contact,
and put no details in it.

A useful report says:

- which component and version: `curl https://x402check.xyz/healthz` for the service, the
  npm version for a package;
- how to reproduce it (the request, transaction or message, and what came back);
- the impact: who loses what, and under which conditions.

Never send a private key, a seed phrase or a full credit token (`x402c_…`). If a token
matters, send the first 12 hex characters of its SHA-256.

There is no bug bounty. We credit reporters in the published advisory, unless you prefer
not to be named.

## Scope

In scope:

- **The service at https://x402check.xyz** (one Cloudflare Worker): paid checks
  (`/v1/risk-check`, `/v1/risk-check/batch`), prepaid credits (`/v1/credits`), payment
  verification and settlement, attestations, the identity documents
  (`/.well-known/did.json`, `/.well-known/jwks.json`), the discovery documents and `/status`.
- **`@x402check/client`** on npm: the attestation verifier and the signing guard
  (`@x402check/client/guard`: `guardAccount`, `guardSolanaSigner`, `x402PaymentGuard`).
  Anything that makes a guarded key sign what it should have refused, or makes a forged
  or unbound verdict verify.
- **`@x402check/mcp`** on npm, the MCP server (including `x402check_pay`), and its MCP
  Registry entry `io.github.caiovicentino/x402check`.
- **The MetaMask Snap** in `snap/` (a preview; it is not published).
- **This repository's pipeline**: the GitHub Actions workflows and the signed feeds on the
  `feeds` branch.

A missed detection (a drainer that is not flagged yet) is welcome as a normal issue. A way
to make a dangerous request come back `allow`, or to make the guard sign it anyway, is a
vulnerability: report it privately.

Not in scope, and not this project: the unscoped npm package `x402check`, the site
x402check.com, and any npm package named `x402check-mcp` or `x402check-snap`. Our only
npm packages are `@x402check/client` and `@x402check/mcp`. Report issues in the
facilitators (Coinbase CDP, PayAI, Dexter), the x402 libraries (`@x402/*`), MetaMask,
Cloudflare, npm or GitHub to those projects.

## Rules for testing

- Use only wallets, funds and credits that are yours. Never spend, move or lock anyone
  else's funds, and never use someone else's credit token.
- Every check is paid. Pay for your tests with your own wallet or credits, and keep a
  proof of concept to a few calls. If you find a way to get verdicts without paying, stop
  at the smallest proof and report it.
- No load tests, denial of service, floods or high-volume scanning of x402check.xyz, its
  payment facilitators or the RPC providers it uses.
- Do not get real third-party addresses flagged in production (for example with on-chain
  transactions meant to poison the kit watch). Use addresses you control, or describe the
  technique.
- No social engineering, phishing or spam, and no access to data that is not yours.
- Give us a reasonable time to ship a fix before you disclose anything publicly.

## Trust anchor: the attestation key

Every verdict is an ES256 JWS signed by x402check's attestation key. That key is published
in the DID document of `did:web:x402check.xyz`, served at
https://x402check.xyz/.well-known/did.json (the same key is in `/.well-known/jwks.json`).
This DID document is the trust anchor: `verifyAttestation` in `@x402check/client` and
`scripts/verify-attest.ts` resolve the key only from the DID document of the issuer you
expect (by default `did:web:x402check.xyz`), never from a key, URL or header carried by a
response or by the token.

So these are the most severe reports:

- `verifyAttestation` accepting a JWS that this key did not sign or, when you pass the
  request, one issued for a different request;
- anything that lets someone change what that DID document serves: the domain, its DNS or
  TLS certificates, the hosting account or deploy access.
