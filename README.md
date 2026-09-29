# x402check — signed-intent risk checks for x402 agent commerce

**LIVE**: [https://x402check.xyz](https://x402check.xyz) · `did:web:x402check.xyz` · 100 free evaluations/day · [discovery](https://x402check.xyz/.well-known/risk-check.json) · [DID document](https://x402check.xyz/.well-known/did.json) · [JWKS](https://x402check.xyz/.well-known/jwks.json)

x402check is an x402 `risk-check` provider that scores agent counterparties with **Jev** — TypeSafe AI's System One model for typed decisions — and issues **ES256-signed attestations** that facilitators and resource servers can verify independently. The verdict answers one question before settlement: **is the paying agent's intent legitimate?**

Aligned with the `risk-check` extension spec proposed in
[x402 PR #2422](https://github.com/x402-foundation/x402/pull/2422): discovery at `/.well-known/risk-check.json`, scoring at `POST /v1/risk-check` (+ `/batch`), and `RiskCheckResult` payloads with compact JWS attestations verified against `/.well-known/jwks.json`.

## What it protects

| Side | Protected from |
|---|---|
| Agent's user | hijacked intent (prompt injection → drain), impersonation, sanctions exposure, becoming a laundering mule |
| Seller / resource server | malicious agent payments (charge-then-deny), abuse traffic, compliance exposure |
| Facilitator | all of the above, once for every merchant |

Between "the agent decided to pay" and "the payment settles" there is one instant where intent can be checked. x402check lives in that instant — and proves every verdict with a signature, not a promise.

[![x402check demo](https://i.ytimg.com/vi/MCOWk7nh5r8/hqdefault.jpg)](https://youtu.be/MCOWk7nh5r8)

## Payments (live, mainnet)

`POST /v1/risk-check` is x402-protected: **100 free evaluations/day** per caller, then **$0.001 per evaluation** settled in USDC via x402 across **7 mainnets** — Base, Solana, Polygon, Arbitrum, Avalanche, Monad, Sei — plus Base Sepolia, Arbitrum Sepolia and Solana Devnet testnets (Dexter facilitator, gas-sponsored, zero facilitator fee; buyer funds move buyer → provider wallet directly, the facilitator never holds them).

## Quickstart

```bash
curl -X POST https://x402check.xyz/v1/risk-check \
  -H "Content-Type: application/json" \
  -d '{"wallet":"7Xf2...pvFh","chain":"solana","domain":"api.merchant-labs.com","context":"agent pays $0.05 voucher for a pricing API call","screening":{"sanctions":"clean"}}'
```

```json
{
  "checked": true,
  "score": 99,
  "tier": "low",
  "provider": "did:web:x402check.xyz",
  "jws": "eyJhbGciOiJFUzI1Ni...",
  "jwks_url": "https://x402check.xyz/.well-known/jwks.json",
  "checked_at": "...", "expires_at": "..."
}
```

## Wallet integration

Wallets and wallet apps can gate any outgoing payment the same way — check the counterparty **before** the user signs. CORS is open; the snippet below runs in any browser context (extensions, dApps, web wallets):

```js
const res = await fetch("https://x402check.xyz/v1/risk-check", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    wallet: destinationAddress,            // counterparty wallet
    chain: "solana",                       // or "base", "polygon", ...
    domain: destinationDomainIfAny,        // optional: site the payment is for
    context: "user sends 50 USDC to this address",
  }),
});
const v = await res.json();
if (!v.checked) {
  // fail-closed: hold the transaction, show "check unavailable"
} else if (v.tier === "high" || v.tier === "critical") {
  // block or require explicit user override; display v.jws for audit
}
```

Suggested user-facing copy per tier:

| Tier | Wallet UX |
|---|---|
| `low` | no warning; show attestation badge (verified, signed) |
| `medium` | amber caution: "Some signals suggest caution. Review before signing." |
| `high` | red warning: "High risk detected. We recommend you do not proceed." |
| `critical` | hard block with override; show categories from the verdict |

Batch scan of counterparties in one call: `POST /v1/risk-check/batch` with `{"requests": [...]}` (max 25). Any verdict can be verified without trusting the provider: `npx tsx scripts/verify-attest.ts <jws>` prints `valid: true` against the live JWKS. The free tier (100/day per caller) covers end-user traffic; heavy integrations pay per check over x402 in the same wallets they already manage.

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

Two defects found and fixed using run-1 data: (1) gateway `score` answers carry no calibrated confidence — the confidence cap only applies to calibrated answers; (2) JEV could not detect leet-substitution lookalike domains from raw state — the provider enriches state with deterministic `domain_analysis` (leet normalization, brand-token match, suspicious TLD) before the call — deterministic code first, Jev second.

## Scale evidence

`npm run eval:suite` runs the consolidated five-layer suite (synthetic, shadow, scale, red-team, benchmark) in one command — full numbers in `docs/EVIDENCE.md`. Latest consolidated run (v5 question set, signal-driven review tiers): **2,238 decisions, synthetic/shadow 100%, scale 99.8%, red-team 99.7% (0 FN), benchmark 100% vs chat-judge 99.3%, human-labeled gate READY (53 verified checks)** — plus **production eval 53/53 against the live endpoint with all attestations verified against the public JWKS** (`npm run prod`) and a **20/20-pass security probe suite** (`npm run security`).

```bash
npm run board todo      # unlabeled cases, disagreements first
npm run board label <case_id> real|fp   # human-verified label
npm run board report    # accuracy per category, cost, switch-over gate
```

**Switch-over gate: READY** (53 human-verified checks, 0 dismissed-real, 0 false-confirms, 2% review share in the screening-integrated mode; unscreened traffic pays a documented ~26% review cost — the fail-closed trade-off, block threshold identical in both modes).

## Shadow mode

`npm run shadow` replays labeled cases through the provider (Jev enabled, no enforcement) and appends evidence to `eval/evidence/shadow-log.jsonl`: per-case verdicts, latency, token usage, estimated cost ($0.042/MTok input, output free), disagreements, and the switch-over gate. Threshold and question-set are versioned; changing them re-baselines the log.

## Honest limitations

- Scoring runs on Jev-evaluated context only — no on-chain graph, address-cluster, or threat-feed enrichment yet (planned: Helius webhook enrichment, Solana program allowlist signals).
- No sanctions feed integration; `sanctions_concern` is a Jev judgment, not a screened list. Do not use as a compliance control.
- Attestation keys are Worker secrets (stable `jev-attest-v1`); KMS/HSM-backed key custody is the next hardening step.
- Batch endpoint parallelizes rather than amortizing a single Jev call; caching per payer (per spec facilitator guidance) is not implemented server-side yet.

## Red-team, benchmark, demo, production, security

- **Red-team loop** (`npm run eval:redteam`): 1,500 adversarial cases (synonym mutations, authority spoofing, encoded payloads, distributed malice) + legitimate-lookalike FP probe + prose-only-claim dual-use class. Five hardening iterations (v1→v5) — see `docs/EVIDENCE-REDTEAM.md`. Final: 100% adversarial accuracy, 1.3% FP. The reusable design principle: **claims of legitimacy require structured evidence** (`screening`, `authorization` fields); prose claims are unverified by default.
- **Benchmark** (`npm run eval:benchmark`): same sample through a chat LLM judge (`gpt-4.1-mini` via AI Gateway) — JEV provider 100% @ p50 394ms / $0.0157 vs chat judge 99.3% @ p50 727ms / $0.0174 (approx. pricing). JEV additionally outputs typed, calibrated, signable verdicts.
- **End-to-end demo** (`npm run demo`): three live scenarios — (A) legitimate agent pays, attestation JWS verified independently against JWKS; (B) compromised agent (injected guard-bypass) rejected by facilitator at score 0/critical; (C) agent-side counterparty gate: agent refuses to pay an impersonated recipient at score 8/critical before signing anything.
- **Deploy** (`deploy/`): live at `https://x402check.xyz` — `did:web:x402check.xyz`, x402 paywall (SDK v2, multi-network), free tier + KV accounting; `deploy/README.md` documents the full setup.
- **Distribution drafts**: `docs/DISTRIBUTION.md` — comment for x402 PR #2300, issue draft for x402-foundation, directory entries, X post, Kora issue (issue-first per house rules).

## Human verification

`npm run verify` — labeling session (`--sheet` prints the full review set; `--answers <string>` applies r/f/s per case). **Status: DONE** — 53/53 human-verified, gate READY.

## Roadmap

Done:
1. ~~Human labels → gate READY~~ ✅ 53 verified checks, 0 dismissed-real, 0 false-confirms.
2. ~~Public deployment with real `did:web:` identity~~ ✅ live at x402check.xyz.
3. ~~x402 upstream: reference-provider proposal~~ ✅ issue #3597 + comments on PRs #2300/#2422.

Next:
4. Real facilitator traffic in shadow mode — evidence moves from synthetic corpora to live x402 flows.
5. Kora `decision_provider` integration (issue #682).
6. CDP facilitator option for key-based mainnet settlement; KMS/HSM key custody.
7. Payments beyond USDC (multi-asset) and remaining x402 networks as facilitator coverage lands.
8. AP2 `RiskPayload` implementation once upstream stabilizes.

See `docs/EVIDENCE.md` (consolidated master) and `docs/EVIDENCE-SCALE.md`, `docs/EVIDENCE-REDTEAM.md`, `docs/EVIDENCE-SECURITY.md` for the full evidence trail.
