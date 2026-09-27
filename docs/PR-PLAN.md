# Upstream PR plan — validated 2026-09-27

Everything below was verified against live sources this session. The x402 `risk-check` wire format is from the actual PR #2422 diff (spec + TS + Go types). The Kora issue-first gate is from solana-foundation/kora PR #678 (merged 2026-09-21). TypeSafe API shape is from docs.typesafe.ai (`POST /v1/systemone`, `state` + `questions`, `jev-latest` → `jev-1.13.0`).

## Validated interfaces we conform to

- `RiskCheckDiscovery` / `RiskCheckExtensionInfo` / `RiskCheckResult` — x402 PR #2422 (`specs/extensions/risk-check.md`, `typescript/packages/core/src/types/risk-check.ts`)
- JWS claims required by the spec: `iss`, `sub` (payer wallet), `score`, `tier`, `iat`, `exp`; recommended `aud`, `categories`, `input_hash` — all implemented
- TypeSafe API: `POST https://api.typesafe.ai/v1/systemone`, Bearer auth, questions `noul|choice|score`, errors 401/422/429/529 with backoff on 429/529

## Phase 0 — done (this repo)

- Provider service, zero runtime deps, fail-closed, shadow harness, 20 passing tests
- Open item: run `npm run shadow` with a real `TYPESAFE_API_KEY` to collect latency/accuracy evidence

## Phase 1 — proposal issues (NOT PRs first)

1. x402-foundation/x402: issue proposing "JEV as first signed-intent reference provider for `risk-check`" — reference PR #2422 as the interface, link our repo + shadow evidence. Comment with data in the active discussions (#2300 trust-provider has 39 comments).
2. solana-foundation/kora: issue proposing a `decision_provider` config (HTTP hook consulted before fee-payer co-signing, fail-closed, off by default). Wait for the maintainer `accepted` label before writing any PR (PRs without it are auto-closed since #678).

## Phase 2 — small PRs, one at a time

3. x402 docs-only PR: add our provider to the third-party extensions catalog (pattern: PR #3079, Agent Guild). Signed commits + AI-assistance disclosure required.
4. Optional: JEV backend adapter for the `trust-provider` extension (PR #2300) — only after engagement.
5. Kora PR (after `accepted` label): config field + validation + tests, minimal diff.

## House rules (observed in both repos)

- Issue-first everywhere; proposals get reviewed before code
- Signed commits; x402 requires AI-assistance disclosure (PRs have added it retroactively — do it up front)
- x402: `specs/extensions/*.md` + types in `typescript/packages/core/src/types/` + Go parity when touching SDK
- Kora: `needs-issue` label auto-closes; commit signing enforced via review bot (#678)
- Community is allergic to bulk AI-generated repos (see awesome-jev curation warnings) — keep the diff small, evidence-backed, and human-reviewable

## Kill criteria

- If `risk-check` (#2422) is rejected or reshaped, re-target whatever interface survives; the provider logic (Jev scoring + JWS) is interface-independent.
- If Kora declines external decision hooks, ship the provider as facilitator-side middleware only and revisit Solana-native enforcement later.
