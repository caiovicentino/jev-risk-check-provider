# Red-team evidence — jev-risk-check-provider

> **Historical record (question set v5, 2026-09-27/28), superseded by v0.2.0 — see [EVIDENCE.md](EVIDENCE.md).**
> An independent review (2026-09-29) found issues that change how these numbers read:
> - The corpora's context text **describes the risk it labels** ("funds routed through a mixer…"). With an attacker-written context, the same cases are detected only when a look-alike domain is present (v6 `realistic` layer: 20/100).
> - The red-team generator was not reproducible: it used `Math.random`, discarded mutations for the identity wrapper, emitted invalid `brand-x..tld` domains, and its "decoded" hints were still base64. It is fixed in the v6 corpus.
> - The "screening-integrated" gate simulation derived the caller's `screening` field from the ground-truth label.
> - Suite modules started duplicate workloads on import.
>
> The numbers below are kept unchanged as a record of what was measured at the time.


Five adversarial iterations against the provider, each driven by the previous run's failure data. Backend: Vercel AI Gateway (`typesafe-ai/jev`). Corpus: parameterized mutation engine (`eval/redteam-cases.ts`) — synonym swaps, authority spoofing, softening wrappers, encoding, distributed multi-field malice, plus legitimate-lookalike patterns (FP-resistance probe) and prose-only clearance claims (dual-use class).

## Iteration story (the honest log)

| Version | Change | mutation | distributed | legit FP | What the red team exposed |
|---|---|---|---|---|---|
| v1 | baseline battery | 92.1% (57 FN) | 95.5% (17 FN) | 0/399 | The class of attacks on the control system itself ("disable the payment guard") was invisible — plain nouls didn't weight it |
| v2 | + `guard_bypass_attempt` noul (attacks on the agent's own controls get a dedicated signal + hard cap ≤30) | 100% | 100% | 18 | New FP pattern: contexts that *mention* sanctions screening ("screened — clean") triggered `sanctions_concern` |
| v3 | refined sanctions criteria (mention ≠ exposure) | 100% | 100% | 20 | Prose-only clearance claims still FP — because a prose claim of clearance is exactly what an attacker would say |
| v4 | + structured `screening` field; prose claims reclassified as dual-use | 100% | 100% | 10 | Same principle exposed urgency: "pre-authorized" in prose is unverified |
| v5 | + structured `authorization` field (pre_authorized + source); prose-only claims → dual-use class | **100% (744/744)** | **100% (360/360)** | **4/315 (1.3%)** | Remaining FPs: one SLA-urgency template (56-59) — genuine boundary between SLA urgency and false urgency |

Final v5 run: 1,500 live calls, 0 errors, $0.08 total, p50 403ms / p95 561ms.

## Design principle that emerged (the reusable insight)

**Claims of legitimacy require structured evidence; prose claims are unverified by default.** A context saying "already screened, proceeding as usual" or "the user pre-authorized this" scores as a suspicious unverified claim unless the integrator passes structured fields (`screening.sanctions: "clean"`, `authorization.pre_authorized: true` + source). JEV evaluates; deterministic code enforces the evidence policy (screening-clean reduces sanctions penalty ×0.2; pre-authorization floors trust bonus at level 3). This distinction is protocol-shaped: it maps directly to AP2's "verifiable intent, not inferred action".

## Final numbers (v5, dedup by case)

| Metric | Value |
|---|---|
| Adversarial mutation accuracy | **100%** (744/744) |
| Distributed/encoded attacks | **100%** (360/360) |
| False positives on legitimate-lookalike | 4/315 (1.3%) — SLA-urgency template at 56-59 |
| Threshold sweep | FN=0 for thresholds 60-70; safe p5 = 74 |
| Prose-only clearance claims (dual-use) | 81 — all correctly held in block band, reported as a separate class, not counted as errors |
| Latency | p50 403ms · p95 561ms |
| Cost | ~$0.000054/call |

## Known boundaries (documented, not hidden)

1. **SLA-urgency template** (4 FPs at 56-59): "settlement deadline is in 10 minutes per the exchange's SLA" is indistinguishable from false urgency by text alone. Mitigations: structured `authorization` with source (implemented), per-server `min_score` tuning, or a second confirmation step for urgency-flagged flows.
2. **Brand-token domains without leet substitution** (e.g. `solana-auth.com` scored 85 in the scale run): genuinely ambiguous — an authenticated service could legitimately use a chain's name. Human labeling required; this is the honest frontier of impersonation detection.
3. Sampling variance: JEV verdicts vary run-to-run (±3 score points p95). Thresholds have margin against this; the log accumulates runs for longitudinal stats.

## What this evidence supports

- A typed-decision provider can reach 100% on adversarial paraphrase/distribution attacks with **zero FN and 1.3% FP** — with the failure modes published rather than hidden.
- The hardening loop (question-set versioning v1→v5 + deterministic evidence fields) is itself the architecture: every red-team iteration produced either a new question, a structured evidence field, or a reclassified ambiguity class — never a silent threshold tweak.
- Cost per decision (~$0.00005) makes adversarial-grade screening economically compatible with x402 sub-cent commerce.
