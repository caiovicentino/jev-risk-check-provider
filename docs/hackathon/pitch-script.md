# x402check — pitch script (2:30, Colosseum Crypto World's Fair)

> Delivery notes: talk-to-camera, terminal B-roll at the evidence moments. One take per paragraph. Speak ~150 wpm.

## 0:00–0:15 — Hook

"Last year, an autonomous AI agent published its own private keys — while denying it had done so. Agents now pay with wallets on x402, the open payment standard for agentic HTTP commerce — and nobody checked intent on any of those payments."

## 0:15–0:45 — The gap

"Agents now pay with wallets. The industry's answer is deterministic policy engines: spend caps, allowlists, signed mandates. They check *structure* — amounts, recipients. They cannot check *intent* — whether the payment corresponds to what the user actually authorized, or whether the context carries a prompt injection. The payment standards themselves say it: AP2's core principle is 'verifiable intent, not inferred action.' The intent-checking layer is the missing piece."

## 0:45–1:15 — Insight + product

"Here's what we learned by attacking our own system: a model reading a payment description only catches risk the description reveals — and an attacker never describes the attack. So x402check leads with **evidence the provider checks itself**: the official OFAC SDN list, MetaMask's phishing list and ScamSniffer's drainer addresses, look-alike domain analysis, and on-chain facts — like an approval being granted to a plain wallet instead of a contract, the classic drainer pattern. A typed model, Jev, then reads the content the agent actually acted on for injected instructions. Caller claims like 'already screened' are recorded as claims and can never lower the score. Every verdict is an ES256 attestation that says which checks actually ran."

## 1:15–1:45 — Evidence (B-roll: EVIDENCE.md tables)

"We measure against labels we didn't write. Every OFAC-sanctioned address we sampled: critical. Drainer permit signatures with the drainer list switched off: 27 of 30 caught by the approval-to-wallet rule. Zero false positives on well-known contracts and top dApps, and 5 hits in the top 200,000 websites. And we publish the limits: a plain transfer to a drainer nobody has reported yet is not detectable from the address alone — that's what real-time feeds are for. About half a second, a tenth of a cent, signed."

## 1:45–2:10 — GTM + traction

"Open protocol play: we engaged the x402 Foundation with a proposal and reference implementation, opened the first external-decision-hook issue on Solana Foundation's Kora paymaster, and are listed in the Jev ecosystem directory. Solana already carries 70% of x402 volume. Monetization is the compliance and audit layer — signed decision evidence — for the payment providers and financial institutions that need it."

## 2:10–2:30 — Why now + the ask

"Everything just aligned: x402 is a Linux Foundation project, AP2 is gaining agent-payment traction, and Solana Foundation is shipping agent infrastructure. The intent layer doesn't exist yet — we're first, with the receipts. In this window we're shipping the public did:web deployment, real facilitator shadowing, and the Kora integration. We're asking for your eyes on the demo — and we'd love yours in the arena."

---

## Timing checkpoints (record against these)
- 0:15 hook done | 0:45 gap done | 1:15 insight done | 1:45 evidence done | 2:10 GTM done | 2:30 close
- If over: cut the Tranco line, keep the limits sentence
