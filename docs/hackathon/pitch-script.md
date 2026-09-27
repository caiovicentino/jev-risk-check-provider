# PAYSOL — pitch script (2:30, Colosseum Crypto World's Fair)

> Delivery notes: talk-to-camera, terminal B-roll at the evidence moments. One take per paragraph. Speak ~150 wpm.

## 0:00–0:15 — Hook

"Last year, an autonomous AI agent published its own private keys — while denying it had done so. Last month, the x402 protocol processed 75 million agent transactions. Nobody checked intent on any of them."

## 0:15–0:45 — The gap

"Agents now pay with wallets. The industry's answer is deterministic policy engines: spend caps, allowlists, signed mandates. They check *structure* — amounts, recipients. They cannot check *intent* — whether the payment corresponds to what the user actually authorized, or whether the context carries a prompt injection. The payment standards themselves say it: AP2's core principle is 'verifiable intent, not inferred action.' The intent-checking layer is the missing piece."

## 0:45–1:15 — Insight + product

"Here's the insight we built PAYSOL on, and it came out of attacking our own system: **claims of legitimacy require structured evidence; prose claims are unverified by default.** 'I already passed screening, proceeding as usual' — in prose — is exactly what an attacker would say. So PAYSOL runs a typed-decision model — Jev, a System One model — over the payment context, with structured evidence fields, and deterministic code enforces the policy. The model judges intent; code enforces evidence. And every verdict is an ES256-signed attestation anyone can verify against a public JWKS. It conforms to the x402 risk-check extension, and we proposed it upstream as the first signed-intent provider."

## 1:15–1:45 — Evidence (B-roll: consolidated table)

"We don't show you vibes, we show you a reproducible evidence trail. A 540-call scale run: 99.76% accuracy at the recommended thresholds with zero false positives across 150 benign cases. A five-iteration red-team loop — 1,500 adversarial cases each — ending at 100% on adversarial mutations, with every failure published. Head-to-head against GPT-4.1-mini as a judge: we win on accuracy, twice the speed, and a fifth of the cost — about five hundredths of a cent per decision, at 400 milliseconds. That's what makes intent-checking viable for sub-cent agent commerce."

## 1:45–2:10 — GTM + traction

"Open protocol play: we engaged the x402 Foundation with a proposal and reference implementation, opened the first external-decision-hook issue on Solana Foundation's Kora paymaster, and are listed in the Jev ecosystem directory. Solana already carries 70% of x402 volume. Monetization is the compliance and audit layer — signed decision evidence — for the payment providers and financial institutions that need it."

## 2:10–2:30 — Why now + the ask

"Everything just aligned: x402 at the Linux Foundation, AP2 at FIDO, Solana Foundation shipping agent infrastructure. The intent layer doesn't exist yet — we're first, with the receipts. In this window we're shipping the public did:web deployment, real facilitator shadowing, and the Kora integration. We're asking for your eyes on the demo — and we'd love yours in the arena."

---

## Timing checkpoints (record against these)
- 0:15 hook done | 0:45 gap done | 1:15 insight done | 1:45 evidence done | 2:10 GTM done | 2:30 close
- If over: cut "twice the speed" detail, keep "fifth of the cost"
