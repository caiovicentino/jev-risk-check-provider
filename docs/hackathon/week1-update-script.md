# Builder update — Week 1 (1-minute video script)

> Weekly updates are one-minute videos highlighting progress + notable challenges. Record raw, over the terminal — authenticity beats polish here.

## 0:00–0:10 — Who/what

"PAYSOL — the signed-intent layer for agent payments. Agents pay with wallets; we gate each payment with a typed-decision model and a signed, verifiable verdict."

## 0:10–0:30 — Week 1 progress (show on screen)

Terminal: `curl -s https://x402check.xyz/healthz` then `npm run eval:suite` tail — the consolidated table with the production and security rows.

"Status at week one: the product is LIVE at x402check.xyz — mainnet USDC settlement on Base and Solana, DID identity, paywall with a free tier. Two thousand two hundred live model decisions; 53 of 53 human-verified production checks; 20 of 20 security probes. Zero false positives on legitimate traffic across every layer."

## 0:30–0:50 — Upstream traction (show the GitHub issues/PRs)

Browser tabs: x402 issue #3597, Kora issue #682, awesome-jev PR #293.

"We engaged the standards where our users are: a reference-provider proposal at the x402 Foundation, the first external decision-hook issue on Solana Foundation's Kora paymaster, and a listing in the Jev ecosystem directory."

## 0:50–1:00 — This week's focus + challenge (honest)

"Next: first real facilitator traffic in shadow mode, and the payment path end-to-end with real integrators. The hard part is making signed verdicts verifiable from anywhere with stable keys — and now anyone can verify one with two curls."

---

## Recording checklist
- [ ] Fresh `npm run eval:suite --quick` run right before recording (real numbers)
- [ ] Have the three upstream links open in tabs
- [ ] 60s hard cap — if over, cut the challenge line
- [ ] Post via Colosseum dashboard → Builder updates
