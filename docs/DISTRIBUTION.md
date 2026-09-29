# Distribution drafts — ready to post

> **Superseded pricing.** Since v0.3 there is no free tier. Every evaluation is paid per call via x402: $0.001, $0.002 on Solana, and $0.005 when a transaction is simulated. Drafts that mention free checks are out of date.
>
> **Superseded numbers.** Drafts 1–5 below quote the v5 evaluation (2026-09-27/28). An independent review found those corpora described their own risk, so v5 accuracy does not carry over to real traffic (see docs/EVIDENCE.md). If any draft was already posted, post draft 0 as a follow-up.

## 0. Correction / update comment (for x402 issue #3597 and PR #2300 threads)

> Update on the `jev-risk-check-provider` / x402check numbers I shared earlier: an independent review showed our v5 corpora described the risk in the text being scored ("funds routed through a mixer…"), so the 99–100% figures measured reading, not detection. With an attacker-written context the same cases fall to 20% (only look-alike domains survive). v0.2.0 (live at x402check.xyz) now leads with provider-verified evidence — OFAC SDN screening, MetaMask/ScamSniffer feeds, on-chain facts (approval granted to an EOA), public-suffix-aware domain analysis — and the model is used for injected instructions in content the agent acted on (40/40). Attestations now carry a `checks` claim (what the provider verified) separate from `asserted` (what the caller claimed). New evidence uses external labels: OFAC 24/24 critical; drainer permits 27/30 with the drainer feed held out; 0 FP on well-known contracts/dApps; limits published (plain transfers to unreported drainers: 0/30). Details: docs/EVIDENCE.md. Apologies for the earlier overstatement.

Historical drafts (v5 numbers — do not repost without updating):

## 1. Comment for x402 PR #2300 (trust-provider extension — 39 comments, active)

> We've been building a reference provider for exactly this hook and have scale + adversarial evidence now. Our `jev-risk-check-provider` (TypeSafe Jev System One model + ES256-signed attestations, aligned with #2422's wire format) runs a v5 question-set: after a 5-iteration red-team loop (1,500 adversarial cases — synonym swaps, authority spoofing, encoded payloads, distributed malice), we're at 100% on adversarial mutations, 0 FN at thresholds 60-70, and 1.3% FP on legitimate-lookalike patterns. Stability across sampling: spread p95 = 3 points, 100% majority decision agreement over 24×5 repeats. Cost ~$0.00005/decision, p50 ~400ms.
>
> Two design notes that may matter for the extension spec itself:
> 1. **Claims of legitimacy require structured evidence.** Prose like "already screened, proceeding as usual" scores as an unverified claim (correctly — that's what an attacker would say). We added structured `screening` / `authorization` fields to the provider contract; deterministic code enforces the evidence policy, Jev evaluates intent. Worth considering whether the extension should standardize such evidence fields.
> 2. **Attacks on the control system deserve their own signal.** "Disable the payment guard" was invisible to generic risk nouls; a dedicated `guard_bypass_attempt` question fixed 74 FNs at zero FP cost.
>
> Repo with reproducible corpus (seeded), shadow-mode scoreboard, and threshold-sweep methodology: [link when public]. Happy to contribute a Jev backend adapter for this extension if the direction is welcome.

## 2. Issue draft for x402-foundation/x402 (proposal, issue-first per house rules)

**Title:** `risk-check`: JEV as first signed-intent reference provider (typed-decision model + JWS)

**Body:**
- Context: builds on #2422's `risk-check` extension and #2300's trust-provider hook. We implemented a full provider: TypeSafe Jev (System One model for typed decisions) + ES256 JWS attestations exactly per the #2422 claims schema (iss/sub/score/tier/iat/exp/aud/input_hash).
- Evidence (all reproducible, seeded corpora, logs in repo):
  - Scale: 540 live calls, 98.6% @ min_score 60; **99.76% @ 65-75 with 0 FP across 150 benign cases**; latency p95 552ms @ concurrency 10; cost ~$0.000037/call.
  - Red-team: 5 iterations against our own provider (1,500 adversarial cases): 100% adversarial accuracy, 1.3% FP, error taxonomy published (SLA-urgency boundary, brand-token-no-leet domains).
  - Benchmark: same 293-case sample vs `gpt-4.1-mini` as chat judge — JEV 100% @ p50 394ms / $0.0157 vs chat 99.3% @ p50 727ms / $0.0174 (approx. pricing), and JEV outputs are typed + calibrated + signable (chat judge outputs are neither).
  - Fail-closed: no key or JEV error → `{"checked": false}`; facilitators reject when `required: true` per spec.
- Ask: (a) feedback on whether signed-intent providers fit the extension's provider-agnostic model; (b) interest in a docs-catalog entry (we'll follow PR #3079's pattern, docs-only, signed commits, AI-disclosure).

## 3. Directory submissions

**jev.directory / awesomejev.com entry:**

> **jev-risk-check-provider** — Agent payments: an x402 `risk-check` provider that scores agent counterparties with Jev (typed Noul/Choice/Score questions → code-controlled composite score → ES256-signed attestation). 540-call scale evidence + 1,500-case adversarial red-team loop, fail-closed, shadow-first scoreboard with human-label gate. Categories: Verification & Guardrails / Finance & Trading.

## 4. X post draft

> Agents pay with wallets, but nothing checks intent before money moves.
>
> We built an open x402 `risk-check` provider where a System One model (Jev) judges each counterparty — and every verdict is a signed ES256 attestation anyone can verify.
>
> 540 live calls → 99.76% acc @ 0 false positives. 1,500-case red-team → 100% on adversarial mutations. ~$0.00005/decision, ~400ms.
>
> The hard-won lesson: "already screened, proceeding as usual" in prose = unverified claim. Claims of legitimacy need structured evidence. Code enforces the policy; the model judges intent.
>
> Issue-first PR coming to x402-foundation. #x402 #AIagents #Jev

## 5. Kora issue draft (solana-foundation/kora — issue-first, wait for `accepted` label)

**Title:** `decision_provider` config: external pre-signing risk gate for fee-payer co-signing

**Body:**
- Motivation: Kora co-signs as fee payer after validating program/token/account allowlists. Structural validation can't catch intent-level risk (impersonated recipients, injected instructions, laundering patterns). This adds an optional HTTP hook: before co-signing, Kora POSTs the tx summary (programs, recipients, amounts) to a configured `decision_provider` endpoint and requires a signed decision (`allow`/`deny` + attestation) — fail-closed, off by default.
- Reference implementation exists: `jev-risk-check-provider` (x402 `risk-check` wire-compatible, ES256 attestations, 1,500-case adversarial evidence, p50 ~400ms, ~$0.00005/decision).
- Compatibility: pure config addition; no behavior change when unset; works alongside existing `allowed_programs`/`sponsor_only_programs` rules (defense in depth, not replacement).
- Happy to adjust the hook shape to whatever fits Kora's config patterns.
