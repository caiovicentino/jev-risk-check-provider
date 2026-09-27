# jev-risk-check-provider

An x402 `risk-check` provider that scores agent counterparties with **Jev** — TypeSafe AI's System One model for typed decisions — and issues **ES256-signed attestations** that facilitators and resource servers can verify independently.

Fully aligned with the `risk-check` extension spec proposed in
[x402 PR #2422](https://github.com/x402-foundation/x402/pull/2422): discovery at `/.well-known/risk-check.json`, scoring at `POST /v1/risk-check` (+ `/batch`), and `RiskCheckResult` payloads with compact JWS attestations verified against `/.well-known/jwks.json`.

## Why

Agents pay with wallets they never see keys for. The x402 ecosystem gates settlement with deterministic policy engines, but nothing evaluates **intent**: whether a payment corresponds to what the user actually authorized, or whether the payer context carries injection / fraud patterns. This provider fills that layer with typed, calibrated Jev decisions — and because the verdict is signed, downstream verification does not have to trust the provider.

## Architecture

```
Agent ──x402──> Facilitator ──risk-check──> jev-risk-check-provider
                                              │
                                              ├─ Jev systemOne call (Noul ×4, Choice, Score)
                                              │    state = wallet, chain, domain, operation context
                                              │    answers = calibrated probabilities + confidence
                                              ├─ code-controlled composite scoring (weights in code)
                                              └─ ES256 JWS attestation (iss/sub/score/tier/iat/exp/aud/input_hash)
```

Design follows the Jev pattern: **atomic questions, composed in code**. Each risk dimension is a separate typed question evaluated in parallel against the same state (one API call per payer); the composite score, caps, and tier mapping are deterministic code, not prompts.

| Jev question | Type | Signal |
|---|---|---|
| `known_threat` | Noul | malicious-actor profile |
| `sanctions_concern` | Noul | sanctions / high-crime indicators |
| `laundering_pattern` | Noul | mixing, peel chain, structuring |
| `risky_domain` | Noul | impersonation / phishing domain |
| `risk_class` | Choice | benign · automated_abuse · fraud_signal · unclassifiable |
| `trust` | Score | 0–4 rubric |

Mapping to the x402 score scale (0 = highest risk, 100 = safest): weighted penalties subtracted from 100, trust bonus applied; hard caps (known threat ≥ 0.85 → ≤ 20; sanctions ≥ 0.85 → ≤ 30; trust confidence < 0.5 → ≤ 55); tiers `low ≥ 80`, `medium ≥ 60`, `high ≥ 30`, else `critical`.

## Fail-closed behavior

- No `TYPESAFE_API_KEY` or any Jev error → `{"checked": false}` (never a fabricated score).
- Every attestation carries `input_hash` (sha256 of canonical scoring inputs + question-set version) and `exp` (1h) per the spec.
- `aud` claim binds the attestation to the resource URL when provided.

## Run

```bash
npm install
npm test
TYPESAFE_API_KEY=... npm start          # :8787
curl localhost:8787/.well-known/risk-check.json
curl -X POST localhost:8787/v1/risk-check \
  -d '{"wallet":"9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM","chain":"solana","context":"agent pays $0.05 for API access"}'
```

## Evaluation

Two backends, same provider logic: `TYPESAFE_API_KEY` → TypeSafe direct (`/v1/systemone`), or `AI_GATEWAY_API_KEY` → Vercel AI Gateway (`experimental_evaluate`, model `typesafe-ai/jev`, matching the jev-shield setup).

Two modes, same pipeline:

- `npm run eval:synthetic` — full offline pipeline validation with a mock JEV backend (fixture answers per case). Validates plumbing, scoring math, log format, and gate derivation without any API access.
- `npm run shadow` — live shadow run against the real TypeSafe API (`TYPESAFE_API_KEY` or `AI_GATEWAY_API_KEY` required). Never enforces; records verdicts next to expectations.

### First live run (2026-09-27, Vercel AI Gateway)

| Metric | Value |
|---|---|
| Accuracy vs authored expectations | 24/24 (100%) after 2 fixes from run 1 |
| Run 1 (before fixes) | 18/24 (75%) |
| Baseline (deterministic keyword rules) | 18/24 |
| Latency | p50 426ms · p95 607ms |
| Cost | ~$0.0009 for 24 decisions (~$0.000037/case) |

Two defects found and fixed using run-1 data: (1) gateway `score` answers carry no calibrated confidence — treating `max(probability)` as confidence falsely capped 4 benign cases at 55; gateway score answers are now marked `noCalibration` and the confidence cap only applies to calibrated answers. (2) JEV could not detect leet-substitution lookalike domains from raw state; the provider now enriches state with deterministic `domain_analysis` (leet normalization, brand-token match, suspicious TLD) before the call — deterministic code first, Jev second.

**Caveat**: expected labels are authored, not human-verified. The switch-over gate stays NOT READY (0/50 verified) until labels are checked via `npm run board label`. JEV sampling is non-deterministic — conclusions need accumulated runs, which the log is designed for.

## Scale evidence

`npm run eval:scale` runs a seeded corpus (60/category × 7) plus a stability matrix (24×5 repeats) with concurrent JEV calls. Full methodology and results: `docs/EVIDENCE-SCALE.md`. Headline: 98.6% at threshold 60, **99.76% at threshold 65–75 with zero false positives across 150 benign cases**, p95 552ms at concurrency 10, ~$0.000037/call, JWS sample 10/10, stability spread p95 = 3 points.

```bash
npm run board todo      # unlabeled cases, disagreements first
npm run board label <case_id> real|fp   # human-verified label
npm run board report    # accuracy per category, cost, switch-over gate
```

Switch-over gate (documented, derived from the log so threshold changes need no re-sweep): READY requires ≥50 verified checks, ≥5 verified real-risky cases with 0 dismissed, JEV false confirms ≤ baseline false flags, review share ≤20%. NOT READY until then — shadow only, no enforcement.

## Shadow mode

`npm run shadow` replays labeled cases through the provider (Jev enabled, no enforcement) and appends evidence to `eval/evidence/shadow-log.jsonl`: per-case verdicts, latency, token usage, estimated cost ($0.042/MTok input, output free), disagreements, and the switch-over gate. Threshold and question-set are versioned; changing them re-baselines the log.

## Honest limitations (v0)

- Scoring runs on Jev-evaluated context only — no on-chain graph, address-cluster, or threat-feed enrichment yet (planned: Helius webhook enrichment, Solana program allowlist signals).
- No sanctions feed integration; `sanctions_concern` is a Jev judgment, not a screened list. Do not use as a compliance control.
- Attestation keys are in-process (`jev-attest-v1`); production needs KMS/HSM-backed keys and published JWKS under a real domain (`did:web`).
- Batch endpoint parallelizes rather than amortizing a single Jev call; caching per payer (per spec facilitator guidance) is not implemented server-side yet.

## Red-team, benchmark, demo, deploy

- **Red-team loop** (`npm run eval:redteam`): 1,500 adversarial cases (synonym mutations, authority spoofing, encoded payloads, distributed malice) + legitimate-lookalike FP probe + prose-only-claim dual-use class. Five hardening iterations (v1→v5) — see `docs/EVIDENCE-REDTEAM.md`. Final: 100% adversarial accuracy, 1.3% FP. The reusable design principle: **claims of legitimacy require structured evidence** (`screening`, `authorization` fields); prose claims are unverified by default.
- **Benchmark** (`npm run eval:benchmark`): same sample through a chat LLM judge (`gpt-4.1-mini` via AI Gateway) — JEV provider 100% @ p50 394ms / $0.0157 vs chat judge 99.3% @ p50 727ms / $0.0174 (approx. pricing). JEV additionally outputs typed, calibrated, signable verdicts.
- **End-to-end demo** (`npm run demo`): three live scenarios — (A) legitimate agent pays, attestation JWS verified independently against JWKS; (B) compromised agent (injected guard-bypass) rejected by facilitator at score 0/critical; (C) agent-side counterparty gate: agent refuses to pay an impersonated recipient at score 8/critical before signing anything.
- **Deploy** (`deploy/`): fetch-handler refactor (`src/handler.ts`) runs unchanged on Node and Cloudflare Workers; `wrangler.toml` + secret setup for a public `did:web:` provider with stable JWKS.
- **Distribution drafts**: `docs/DISTRIBUTION.md` — comment for x402 PR #2300, issue draft for x402-foundation, directory entries, X post, Kora issue (issue-first per house rules).

## Human verification

`npm run verify` — interactive labeling session (disagreements first) that feeds the switch-over gate. The gate goes READY at ≥50 human-verified checks with 0 dismissed real-risky cases.

## Roadmap

1. Human labels → switch-over gate READY (`npm run verify`).
2. x402 upstream: issue + docs-catalog PR (drafts ready in `docs/DISTRIBUTION.md`).
3. Public deployment with real `did:web:` identity (`deploy/`).
4. Kora `decision_provider` proposal (issue-first, after x402 traction).
5. AP2 `RiskPayload` implementation once #165/#187 stabilize.
6. Real facilitator traffic shadowing (the evidence tier above synthetic corpora).

See `docs/PR-PLAN.md` and `docs/EVIDENCE-SCALE.md`, `docs/EVIDENCE-REDTEAM.md` for the full evidence trail.
