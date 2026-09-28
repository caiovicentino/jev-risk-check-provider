# Evidence — consolidated master document

All numbers below come from a single `npm run eval:suite` execution (2026-09-28, question-set `jev-wallet-risk/v5` with signal-driven review tiers (v5.1), backend: Vercel AI Gateway `typesafe-ai/jev`). Reproduce with the same command; corpora are seeded and deterministic. The deployed provider at `https://x402check.xyz` is additionally evaluated in production (layer 6) and probed by a security suite (layer 7).

## Consolidated table (one suite run)

| Layer | n | Accuracy | FN | FP | p50 | p95 | Cost |
|---|---|---|---|---|---|---|---|
| synthetic (offline plumbing) | 53 | 100.0% | 0 | 0 | — | — | $0 |
| shadow (live, screening-integrated) | 53 | 100.0% | 0 | 0 | 388ms | 592ms | $0.0028 |
| scale (7 categories × 60 + 24×5 stability) | 420 | 99.8% | 1 | 0 | 390ms | 575ms | $0.0286 |
| red-team (adversarial v5) | 1,419 | 99.7% | 0 | 4 | 387ms | 526ms | $0.0805 |
| benchmark: gpt-4.1-mini as judge | 293 | 99.3% | 0 | 2 | 819ms | 1090ms | $0.0174 |
| benchmark: JEV provider | 293 | **100.0%** | 0 | 0 | 396ms | 572ms | $0.0157 |
| **production (live x402check.xyz)** | 53 | **100.0%** | 0 | 0 | 385ms | 640ms | $0 (free tier) |
| **security suite (live endpoint)** | 20 probes | 100% pass | — | — | — | — | $0 |

**Totals: 2,238 provider decisions in one suite run · $0.11 · 174s — plus 53 live production checks (JWS 53/53 verified against the public JWKS) and a 20-probe security suite (20/20 PASS).** Zero false positives on benign traffic across every live layer (4 FP on the adversarial FP-probe family only — the documented SLA-urgency boundary).

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

- Review routing (tier `medium`) measures the screening-integrated deployment mode (1.9% review share). Unscreened traffic — no `screening` field — pays the documented fail-closed cost: ~26% of safe decisions route to review. The block threshold is identical in both modes.
- Single backend so far (gateway); the direct TypeSafe API returns native calibrated confidence and needs its own scale run.
- Synthetic corpora exercise the question set's coverage, not real-world distribution. The next evidence tier is real facilitator traffic in shadow mode.
- JEV sampling is non-deterministic (±3 points p95 on repeated calls) — all thresholds carry margin, and the logs accumulate runs for longitudinal statistics.

## Evidence files

- `eval/evidence/consolidated-report.json` — this run, machine-readable
- `eval/evidence/scale-report.json`, `eval/evidence/redteam-report.json`, `eval/evidence/benchmark-report.json` — per-layer detail
- `eval/evidence/shadow-log.jsonl`, `scale-log.jsonl`, `redteam-log.jsonl` — raw per-call logs (append-only across runs)
- `eval/evidence/prod-report.json` + `prod-log.jsonl` — production eval against the live endpoint (`npm run prod`), JWS verified per response
- `eval/evidence/security-report.json` + `docs/EVIDENCE-SECURITY.md` — security probe suite against the live endpoint (`npm run security`)
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

## Switch-over gate: READY (`npm run board report`)

The gate requires 50+ human-verified checks, ≥5 verified risky cases, 0 dismissed-real, 0 JEV false-confirms, and ≤20% review share.

- **Suite expanded 24 → 53 cases** via a deterministic rule (documented in `eval/cases.ts`): first 16 benign cases by (context, domain) uniqueness, first 2 of each risky category, first 3 ambiguous — drawn from the same seeded scale corpus (seed 20260927). No score-peeking: selection depends only on corpus order.
- **Human labels: 53/53 verified `real`, 100% agreement** with authored labels, applied by the project owner in two labeling sessions (24 + 29).
- **Gate result: READY** — 53 verified checks, 25 risky-real, 0 dismissed-real, 0 false-confirms, review share 2%.

### Review-routing semantics (policy change, v5.1)

The gate's review-share criterion exposed a real policy gap: the `medium` tier was triggered by score proximity alone, routing score-noise benign traffic (~28%) to human review. Tier routing is now **signal-driven** (`src/scoring.ts`): a safe decision routes to review only when there is a positive reason to look — an intent signal ≥ 0.3 (JEV's honest "no screening data" noise sits at 0.2–0.3 on benign-class cases) or an uncertain risk class (`unclassifiable`/`automated_abuse`/`fraud_signal` at probability ≥ 0.5, which is what keeps genuinely ambiguous cases in review). The **block threshold is untouched** (score-only); the safety decision is identical across the change.

### Screening-integrated simulation

Shadow runs support `--screening integrated`: benign/ambiguous requests get `screening: {sanctions: "clean"}`, risky requests get `"flagged"` — simulating an integrator that actually runs screening (an honest integrator cannot return clean on a sanctioned counterparty). Results on the 53-case suite: **53/53 correct, review share 1.9%** screened vs **26.4%** unscreened. Review load is a function of screening coverage; the fail-closed cost of not screening is the 26%, by design.

Note: a screening-`clean` field submitted against a context that asserts a sanctions listing flips that case to safe (51 → 78) — correct under the integrator-trust threat model (the integrator's screening result overrides stale prose), and the attacker-controlled-input surface for `screening`/`authorization` is the integrator, not the paying client, whose prose remains untrusted.
