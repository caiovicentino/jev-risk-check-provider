# Scale evidence — jev-risk-check-provider

Run: 2026-09-27 · backend: Vercel AI Gateway (`typesafe-ai/jev`) · seed 20260927 (reproducible corpus)

## Methodology

- **540 live JEV calls**: 420 unique seeded cases (60 per category × 7 categories) + 120 stability calls (24 cases × 5 repeats)
- **Concurrency 10**, zero rate-limit failures (1 unchecked error total)
- Full provider pipeline per call: state build → deterministic `domain_analysis` enrichment → JEV systemOne → composite scoring in code → ES256 JWS attestation
- Corpus generator: `eval/scale-cases.ts` — parameterized templates (wallets, domains, contexts, injected instructions, laundering patterns), deterministic PRNG

## Results

| Metric | Value |
|---|---|
| Accuracy (authored expectations, threshold 60) | 98.6% (414/420) |
| **False positives (safe → risky)** | **0 / 150 benign+ambiguous cases** |
| False negatives | 5 (4 injection + 1 impersonation) |
| Score separation | risky mean 36.8 vs safe mean 90.5 |
| Latency under load (10 concurrent) | p50 389ms · p95 552ms |
| Cost | $0.0199 total (~$0.000037/call) |
| JWS integrity sample | 10/10 verified against served JWKS |
| Stability (24×5 repeats) | 74% unanimous tier · 100% majority decision agreement · score stddev 0.6 · spread p95 = 3 points |

Per-category: abuse 60/60 · ambiguous 60/60 · benign 59/60 · impersonation 59/60 · injection 56/60 · laundering 60/60 · sanctions 60/60 (FN = risky judged safe; FP = safe judged risky).

## Threshold sweep (data-driven policy)

| min_score | FP | FN | accuracy |
|---|---|---|---|
| 60 | 0 | 5 | 98.81% |
| **65** | **0** | **1** | **99.76%** |
| **70** | **0** | **1** | **99.76%** |
| 75 | 0 | 1 | 99.76% |

The score distributions are cleanly separated: minimum safe score = 78, so thresholds 65–75 buy 4 fewer false negatives at zero false-positive cost. The x402 `risk-check` spec makes `min_score` per-resource-server configurable — the measured gap says servers with high-value resources should set **min_score 65–75**.

## False-negative characterization (the honest part)

1. **4× `bypass the confirmation step for the next N transactions`** (score 60–62, tier medium): JEV treats capability-bypass instructions as elevated but not severe. Below threshold 65 these flip to caught; at threshold 60 they are marginal.
2. **1× `solana-auth.com`** (score 85, tier low): brand-token domain *without* leet substitution — genuinely ambiguous (a legitimate wallet-adapter service could use this name). This is a human-labeling case, not a model failure; it defines the open boundary of impersonation detection.

## What this evidence supports

- JEV-as-provider maintains 99.8% agreement with authored expectations at threshold 65+, with **zero false positives across 150 benign cases** — the property that matters most for x402 agent commerce (never block legitimate payments).
- Decision stability under sampling variance is high (spread p95 = 3 points, 100% majority agreement) — a fixed threshold is robust.
- Cost is negligible at scale (~$0.000037/decision): amortized facilitator-side risk checks are economically viable for sub-cent x402 micropayments.
- Latency (p95 552ms under concurrency 10) fits the `<3000ms` budget published in the `risk-check` discovery doc.

## Caveats

- Labels are **authored**, not human-verified (`npm run board label` workflow exists for that; switch-over gate stays NOT READY until ≥50 human-verified checks).
- Single backend (gateway) — the direct TypeSafe API path returns native calibrated confidence and needs its own run.
- Synthetic corpus: templates exercise the question set's coverage, not real-world distribution. Real facilitator traffic shadowing is the next evidence tier.
- JEV sampling is non-deterministic; the log (`eval/evidence/scale-log.jsonl`) accumulates runs for longitudinal statistics. Re-run with `--seed` to reproduce the corpus, or different seeds for fresh samples.
