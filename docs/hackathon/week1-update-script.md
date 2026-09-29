# Builder update — Week 1 (1-minute video script)

> Weekly updates are one-minute videos highlighting progress + notable challenges. Record raw, over the terminal — authenticity beats polish here.

## 0:00–0:10 — Who/what

"x402check — a pre-payment risk check for agents and wallets: sanctions list, phishing and drainer feeds, on-chain facts and injected-instruction detection, every verdict signed with the checks behind it."

## 0:10–0:30 — Week 1 progress (show on screen)

Terminal: `curl -s https://x402check.xyz/healthz` then `npm run eval:suite` tail — the consolidated table with the production and security rows.

"Status: LIVE at x402check.xyz — mainnet USDC settlement, DID identity, free tier. We re-evaluated against labels we didn't write: every sampled OFAC address critical, 27 of 30 drainer permits caught with the drainer list switched off, zero false positives on top contracts and dApps — and we published what it can't catch."

## 0:30–0:50 — Upstream traction (show the GitHub issues/PRs)

Browser tabs: x402 issue #3597, Kora issue #682, awesome-jev PR #293.

"We engaged the standards where our users are: a reference-provider proposal at the x402 Foundation, the first external decision-hook issue on Solana Foundation's Kora paymaster, and a listing in the Jev ecosystem directory."

## 0:50–1:00 — This week's focus + challenge (honest)

"Hard lesson this week: our first evaluation scored 99% because the test cases described their own risk — an attacker never does. Next: real facilitator traffic in shadow mode and real-time drainer feeds."

---

## Recording checklist
- [ ] Fresh `npm run eval:suite --quick` run right before recording (real numbers)
- [ ] Have the three upstream links open in tabs
- [ ] 60s hard cap — if over, cut the challenge line
- [ ] Post via Colosseum dashboard → Builder updates
