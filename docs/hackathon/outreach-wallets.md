# Wallet outreach kit — x402check pre-payment gate

Goal: get one wallet to integrate the counterparty check (pre-payment gate) as a design partner.

One-paragraph pitch (EN), reusable anywhere:

> x402check is a live, x402-native risk gate: before a user signs a transfer, the wallet calls `POST https://x402check.xyz/v1/risk-check` with the counterparty address (and optional domain/context) and gets back a signed verdict — score, tier, and an ES256 attestation verifiable against a public JWKS (`did:web:x402check.xyz`). CORS is open, no signup, 100 free checks/day per caller, batch up to 25 addresses per call. It catches what blocklists miss: injected intent, homoglyph domains, fresh-wallet laundering patterns, social engineering contexts. Fail-closed by design — if the check cannot run, the wallet holds the transaction. Integration is ~15 lines; the demo video shows the real flow with a real on-chain settlement.

## Links to include

- Live: https://x402check.xyz
- Demo video (real wallet, real settlement): https://youtu.be/MCOWk7nh5r8
- Discovery: https://x402check.xyz/.well-known/risk-check.json
- DID / JWKS: https://x402check.xyz/.well-known/did.json
- Wallet integration section: https://github.com/caiovicentino/jev-risk-check-provider#wallet-integration
- Verify a verdict: `npx tsx scripts/verify-attest.ts <jws>`

## Snippet (the whole integration)

```js
const res = await fetch("https://x402check.xyz/v1/risk-check", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    wallet: destinationAddress,
    chain: "solana",
    domain: destinationDomainIfAny,
    context: "user sends 50 USDC to this address",
  }),
});
const v = await res.json();
if (!v.checked) holdTransaction();                    // fail-closed
else if (v.tier === "high" || v.tier === "critical") warnOrBlock(v);
```

Tier copy: low → badge, medium → caution, high → warning, critical → block with override.

## Targets and angles

| Wallet | Angle |
|---|---|
| Phantom (Solana+EVM) | biggest retail surface; injection/social-engineering scams hit their users daily |
| Solflare (Solana) | Solana-native; memo/signal integration matches their dev-first brand |
| Backpack (xNFT) | app-rich flows; pre-send gate inside xNFT contexts |
| Rabby (EVM) | already does pre-tx simulations; risk-check is the intent layer they lack |
| MetaMask Snaps | x402check as a Snap — clean packaging for their approval flow |
| Wallets shipping x402 | any wallet in the x402 ecosystem: we gate the agent's own spends |

## DM drafts (EN)

Short (X/Twitter DM, first contact):
> Hi — we built x402check, a live risk gate for wallet/x402 payments: one call before the user signs, signed verdict back (ES256, verifiable DID:web), 100 free checks/day, no signup. It catches injected intent, homoglyph domains and fresh-wallet laundering that blocklists miss. 15-line integration: github.com/caiovicentino/jev-risk-check-provider#wallet-integration — 2min video with a real mainnet settlement: youtu.be/MCOWk7nh5r8. Would love feedback from your security team.

Longer (email/partnerships):
> Subject: Pre-payment intent gate for [Wallet] — live, signed verdicts, free tier
>
> We run x402check (x402check.xyz), a live payer-intent risk provider for the x402 ecosystem — proposed as the reference provider for the risk-check extension at the x402 Foundation (issue #3597; the extension author named our slot in PR #2300). Before a user signs a transfer, the wallet asks one question: is the payer's intent legitimate? The verdict is a typed score with tiering and an ES256 attestation anyone can verify against did:web:x402check.xyz — no trust in us required.
>
> It is already settling real USDC on Solana and six EVM mainnets via x402 (gas sponsored by the Dexter facilitator), with a free tier of 100 checks/day per caller — enough for end-user traffic at no cost. CORS is open, so the integration is a fetch call from any browser context; batch endpoint scans up to 25 counterparties per call. A 2-minute demo with a real on-chain settlement: youtu.be/MCOWk7nh5r8.
>
> We would like [Wallet] as our first wallet design partner: free tier indefinitely for the pilot, co-marketing of the attestation badge, and priority support for signals your fraud team wants (we ship new signal types in days, not quarters). Repo with full evidence trail: github.com/caiovicentino/jev-risk-check-provider.

## Follow-up cadence

- Day 0: DM + email
- Day 4: one-line bump with one new proof point (e.g., "0 false negatives in the final 1,500-case red-team iteration")
- Day 10: final nudge with the Colosseum prize deadline as natural urgency; then park
