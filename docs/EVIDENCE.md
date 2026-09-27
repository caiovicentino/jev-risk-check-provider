# Evidence — consolidated master document

All numbers below come from a single `npm run eval:suite` execution (2026-09-27, question-set `jev-wallet-risk/v5`, backend: Vercel AI Gateway `typesafe-ai/jev`). Reproduce with the same command; corpora are seeded and deterministic.

## Consolidated table (one suite run)

| Layer | n | Accuracy | FN | FP | p50 | p95 | Cost |
|---|---|---|---|---|---|---|---|
| synthetic (offline plumbing) | 24 | 100.0% | 0 | 0 | — | — | $0 |
| shadow (fixed regression) | 24 | 100.0% | 0 | 0 | 374ms | 532ms | $0.0013 |
| scale (7 categories × 60 + 24×5 stability) | 420 | 99.8% | 1 | 0 | 381ms | 528ms | $0.0286 |
| red-team (adversarial v5) | 1,419 | 99.7% | 0 | 4 | 419ms | 634ms | $0.0805 |
| benchmark: gpt-4.1-mini as judge | 293 | 99.3% | 0 | 2 | 743ms | 1104ms | $0.0174 |
| benchmark: JEV provider | 293 | **100.0%** | 0 | 0 | 419ms | 590ms | $0.0157 |

**Totals: 2,180 provider decisions in one suite run · $0.11 · 170s.** Zero false positives on benign traffic across every live layer (4/315 FP on the adversarial FP-probe family only — the documented SLA-urgency boundary).

## What each layer proves

1. **synthetic** — pipeline integrity without API access (mock JEV): scoring math, JWS, wire format, gate derivation.
2. **shadow** — the fixed labeled regression set against the live model; feeds the scoreboard (`npm run board`).
3. **scale** — distribution-level evidence: risky mean 36.8 vs safe mean 90.5; threshold sweep says min_score 65–75 buys 4 fewer FNs at 0 FP cost; **stability 83% unanimous tier across 24×5 repeats, 100% majority decision agreement** — the threshold is robust to sampling variance.
4. **red-team** — the hardening story, not just the final number: five question-set versions driven by failure data (docs/EVIDENCE-REDTEAM.md). Adversarial mutations and distributed/encoded attacks: 100%. The design principle that emerged: claims of legitimacy require structured evidence (`screening`, `authorization`); prose claims are unverified by default — and 81 prose-only clearance claims were correctly held in the block band as a separate dual-use class.
5. **benchmark** — same 293-case sample through `gpt-4.1-mini` as a chat judge: JEV wins on accuracy (100% vs 99.3%), latency (~2x), cost, and — decisive for this spec — outputs **typed, calibrated, ES256-signable verdicts** the chat judge cannot produce.

## Key numbers for the x402 issue (one-liners)

- 99.76% accuracy at min_score 65–75 with **0 false positives** across 540+ benign/ambiguous cases
- 100% adversarial accuracy after a published 5-iteration red-team loop; 1.3% FP on legitimate-lookalike patterns
- ~$0.00005/decision, p50 ~400ms at concurrency 10-12 — compatible with x402 sub-cent micropayments
- Every verdict is a compact JWS (ES256) verifiable against a public JWKS: `iss`, `sub`, `score`, `tier`, `iat`, `exp`, `aud`, `input_hash`
- Fail-closed: no key or model error → `{"checked": false}` — never a fabricated score

## Honest limitations

- Labels are authored by the builder, not human-verified — the switch-over gate stays NOT READY (0/50) until `npm run verify` sessions complete. The interactive session exists and takes ~10 minutes for the fixed set.
- Single backend so far (gateway); the direct TypeSafe API returns native calibrated confidence and needs its own scale run.
- Synthetic corpora exercise the question set's coverage, not real-world distribution. The next evidence tier is real facilitator traffic in shadow mode.
- JEV sampling is non-deterministic (±3 points p95 on repeated calls) — all thresholds carry margin, and the logs accumulate runs for longitudinal statistics.

## Evidence files

- `eval/evidence/consolidated-report.json` — this run, machine-readable
- `eval/evidence/scale-report.json`, `eval/evidence/redteam-report.json`, `eval/evidence/benchmark-report.json` — per-layer detail
- `eval/evidence/shadow-log.jsonl`, `scale-log.jsonl`, `redteam-log.jsonl` — raw per-call logs (append-only across runs)
- `docs/EVIDENCE-SCALE.md`, `docs/EVIDENCE-REDTEAM.md` — methodology and iteration stories
- `docs/DISTRIBUTION.md` — ready-to-post drafts that reference these numbers

## Meta-eval: JEV as independent judge (`npm run eval:audit`)

The provider's own model evaluates its verdicts through two differently-framed arms — this measures inter-rater reliability across framings and anchoring resistance, not just accuracy:

| Arm | Design | Result (167 cases, 3 calls each) |
|---|---|---|
| Provider | full question-set battery | 100% vs authored labels |
| **Blind judge** | single independent classification framing, verdict NOT shown | **98.7%** accuracy, 10 honest `uncertain` answers, 0 errors |
| Blind ↔ provider agreement | two independent framings of the same judgment | **98.8%** (2 disagreements, both at documented boundaries) |
| **Anchored judge** | sees the verdict, judges whether it is correct | **100% agreement** after probability gating (P(wrong) ≥ 0.6); raw argmax showed 5.2% false-flag rate from sampling noise |

Two transferable findings: (1) the AI SDK's `evaluate` validation requires `choice` = argmax of probabilities and JEV occasionally samples out-of-sync distributions — production adapters must tolerate this (our provider already fails closed); (2) judge "flags" must be probability-gated, not argmax-read — a 74/25 split would otherwise be reported as a disagreement. Both are exactly the failure modes the LLM-as-judge literature predicts (position/order bias, sampling instability), handled here with typed probabilities rather than prompt patching.
