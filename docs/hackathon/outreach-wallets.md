# Wallet outreach kit — x402check pre-payment gate

Goal: get one wallet to integrate the counterparty check (pre-payment gate) as a design partner.

One-paragraph pitch (EN), reusable anywhere:

> x402check is a live, x402-native risk gate. Before a user signs, the wallet sends the decoded counterparty to `POST https://x402check.xyz/v1/risk-check`: the spender of an approval or permit, the recipient of a transfer. It also sends the site and the interaction type. It gets back a signed verdict: score, tier, the evidence behind it, and an ES256 attestation verifiable against `did:web:x402check.xyz`.
>
> The checks are the official OFAC SDN list, MetaMask's phishing list, ScamSniffer's drainer addresses, look-alike domain analysis, and on-chain facts. The on-chain facts include "this approval grants a plain wallet, not a contract, control of your tokens", which caught 27/30 drainer permits even with the drainer list switched off.
>
> CORS is open, there is no signup, and each caller gets 25 free checks a day. It is fail-closed: if the check cannot run, the wallet shows "not verified", never an all-clear.
>
> Limits are published: a plain transfer to a drainer nobody has reported yet is not detectable from the address alone.

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
    wallet: decodedCounterparty,               // spender / operator / recipient — not the token contract
    chain: `eip155:${chainId}`,
    domain: requestingSiteOrigin,
    context: "Permit2: unlimited USDC allowance to spender 0x…",
    interaction: { type: "permit_signature", unlimited: true },
  }),
});
if (res.status !== 200) showNotVerified(res.status);   // 402 = free checks used up
const v = await res.json();
if (!v.checked) showNotVerified();                     // fail-closed
else if (v.tier === "high" || v.tier === "critical") warnOrBlock(v);
```

Tier copy: low → badge, medium → caution, high → warning, critical → block with override. The MetaMask Snap in the repo (`snap/`) is a complete reference decoder for approvals, Permit2, EIP-2612 and Seaport.

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
> Hi — we built x402check, a live pre-signing risk gate: one call with the decoded counterparty, signed verdict back (ES256, did:web). It combines OFAC, MetaMask's phishing list and ScamSniffer's drainer addresses with on-chain checks (e.g. approvals to plain wallets: 27/30 drainer permits caught with the drainer list switched off). 25 free checks/day, no signup, open-source MetaMask Snap as reference. github.com/caiovicentino/jev-risk-check-provider#wallet-integration — would love feedback from your security team.

Longer (email/partnerships):
> Subject: Pre-payment intent gate for [Wallet] — live, signed verdicts, free tier
>
> We run x402check (x402check.xyz), a live payer-intent risk provider for the x402 ecosystem — proposed as the reference provider for the risk-check extension at the x402 Foundation (issue #3597; the extension author named our slot in PR #2300). Before a user signs, the wallet checks the real counterparty; the verdict is a typed score with tiering, the evidence behind it, and an ES256 attestation anyone can verify against did:web:x402check.xyz — no trust in us required.
>
> The API settles real USDC on Solana and six EVM mainnets via x402 (gas sponsored by the Dexter facilitator), with a free tier of 25 checks/day per caller. CORS is open, so the integration is a fetch call from any browser context; the batch endpoint scans up to 25 counterparties per call (billed per item). Every verdict lists the checks behind it (OFAC SDN, MetaMask and ScamSniffer feeds, on-chain facts, domain analysis), and the published evaluation says what it does not catch. A 2-minute demo with a real on-chain settlement: youtu.be/MCOWk7nh5r8.
>
> We would like [Wallet] as our first wallet design partner: free tier indefinitely for the pilot, co-marketing of the attestation badge, and priority support for signals your fraud team wants (we ship new signal types in days, not quarters). Repo with full evidence trail: github.com/caiovicentino/jev-risk-check-provider.

## Follow-up cadence

- Day 0: DM + email
- Day 4: one-line bump with one new proof point (e.g., "27/30 drainer permits caught with the drainer list switched off; 0 false positives on top dApps")
- Day 10: final nudge with the Colosseum prize deadline as natural urgency; then park
