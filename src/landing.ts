const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>x402check — payer-intent risk checks for x402 agent commerce</title>
<meta name="description" content="Signed, typed payer-intent risk checks for x402 payments. Block malicious agents before settlement — $0.001/evaluation, first 100/day free.">
<style>
  :root {
    --bg: #0a0b10; --panel: #12141c; --border: #232735; --text: #e8eaf2;
    --muted: #9aa1b5; --accent: #14f195; --accent2: #9945ff; --warn: #f5a623;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg); color: var(--text); font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    line-height: 1.6; -webkit-font-smoothing: antialiased;
  }
  .wrap { max-width: 980px; margin: 0 auto; padding: 0 24px; }
  header { padding: 40px 0 24px; }
  .brand { display: flex; align-items: center; gap: 12px; font-weight: 700; font-size: 20px; letter-spacing: -0.02em; }
  .brand .dot { width: 34px; height: 34px; border-radius: 9px; background: linear-gradient(135deg, var(--accent2), var(--accent)); display: inline-flex; align-items: center; justify-content: center; font-weight: 800; color: #0a0b10; }
  nav { display: flex; gap: 24px; margin-left: auto; font-size: 14px; }
  nav a { color: var(--muted); text-decoration: none; }
  nav a:hover { color: var(--text); }
  h1 { font-size: clamp(30px, 5vw, 46px); line-height: 1.15; letter-spacing: -0.03em; margin: 32px 0 16px; }
  h1 .grad { background: linear-gradient(90deg, var(--accent2), var(--accent)); -webkit-background-clip: text; background-clip: text; color: transparent; }
  .sub { color: var(--muted); font-size: 18px; max-width: 640px; margin-bottom: 28px; }
  .badges { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 8px; }
  .badge { font-size: 12.5px; padding: 5px 11px; border-radius: 999px; border: 1px solid var(--border); background: var(--panel); color: var(--muted); }
  .badge.ok { color: var(--accent); border-color: rgba(20,241,149,.35); }
  h2 { font-size: 22px; letter-spacing: -0.02em; margin: 48px 0 16px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 20px; }
  .card h3 { font-size: 15.5px; margin-bottom: 8px; }
  .card p { color: var(--muted); font-size: 14px; }
  .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
  .metric { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 16px; }
  .metric b { display: block; font-size: 24px; letter-spacing: -0.02em; }
  .metric span { color: var(--muted); font-size: 12.5px; }
  pre {
    background: #0d0f16; border: 1px solid var(--border); border-radius: 12px; padding: 18px;
    overflow-x: auto; font-size: 13px; line-height: 1.55; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  pre .c { color: #6b7280; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 600; font-size: 13px; }
  .note { border-left: 3px solid var(--warn); background: rgba(245,166,35,.06); padding: 12px 16px; border-radius: 0 10px 10px 0; color: var(--muted); font-size: 14px; margin-top: 16px; }
  .cta { display: inline-block; margin-top: 8px; padding: 10px 18px; border-radius: 10px; font-size: 14px; font-weight: 600; text-decoration: none; }
  .cta.primary { background: linear-gradient(90deg, var(--accent2), var(--accent)); color: #0a0b10; }
  .cta.ghost { border: 1px solid var(--border); color: var(--text); }
  footer { margin: 64px 0 40px; padding-top: 24px; border-top: 1px solid var(--border); color: var(--muted); font-size: 13.5px; display: flex; flex-wrap: wrap; gap: 16px; }
  footer a { color: var(--muted); text-decoration: none; }
  footer a:hover { color: var(--text); }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand"><span class="dot">x</span> x402check <nav>
      <a href="https://github.com/caiovicentino/jev-risk-check-provider">GitHub</a>
      <a href="/.well-known/risk-check.json">Discovery</a>
      <a href="/.well-known/jwks.json">JWKS</a>
      <a href="https://github.com/x402-foundation/x402/issues/3597">Proposal</a>
    </nav></div>
    <h1>Payer-intent risk checks<br>for <span class="grad">x402 agent commerce</span></h1>
    <p class="sub">Before your resource server settles an agent's payment, ask one question: <b>is the paying agent's intent legitimate?</b> x402check answers it with a typed-decision model (TypeSafe Jev System One) and a signed, verifiable attestation — in ~400&nbsp;ms, for $0.001.</p>
    <div class="badges">
      <span class="badge ok">switch-over gate: READY</span>
      <span class="badge ok">0 false negatives</span>
      <span class="badge">fail-closed</span>
      <span class="badge">MIT</span>
    </div>
    <div>
      <a class="cta primary" href="#integrate">Integrate in 5 minutes</a>
      <a class="cta ghost" href="https://github.com/caiovicentino/jev-risk-check-provider">Read the evidence</a>
    </div>
  </header>

  <h2>What it checks</h2>
  <div class="cards">
    <div class="card"><h3>Prompt injection &amp; guard bypass</h3><p>Injected instructions, drain contracts, "disable the payment guard" attempts, skill-file injections routed through trusted channels.</p></div>
    <div class="card"><h3>Impersonation &amp; social engineering</h3><p>Homoglyph domains (coinbase-wa11et, jup1ter-audit), fake auditors, urgency pressure, wallet-restore scams.</p></div>
    <div class="card"><h3>Laundering &amp; sanctions</h3><p>Peel chains, mixers, structuring under reporting limits, sanctions-screened counterparties, no-KYC clusters.</p></div>
    <div class="card"><h3>Abuse patterns</h3><p>Fresh-wallet bulk payments, coupon farming rotations, sybil campaigns — at x402 micropayment scale.</p></div>
  </div>

  <h2>Why it is different</h2>
  <div class="cards">
    <div class="card"><h3>Typed decisions, not prose</h3><p>A per-layer model (Jev) answers typed questions — Noul probabilities, choices, calibrated scores — not free-text verdicts. Deterministic code composes the score; the model never re-interprets its own policy.</p></div>
    <div class="card"><h3>Signed attestations</h3><p>Every verdict ships as an ES256 JWS from <code>did:web:x402check.xyz</code> — verifiable by anyone against the public JWKS, composable into QUORUM aggregation.</p></div>
    <div class="card"><h3>Structured evidence beats prose</h3><p>"Already screened, proceed" is scored as an unverified claim — exactly what an attacker would say. Only structured <code>screening</code>/<code>authorization</code> fields change policy. Prose is never trusted.</p></div>
    <div class="card"><h3>Fail-closed by construction</h3><p>JEV unreachable → <code>checked: false</code>, settlement does not proceed. Low-confidence answers are capped, not averaged. Uncertainty routes to review, never to silent allow.</p></div>
  </div>

  <h2>Evidence</h2>
  <div class="metrics">
    <div class="metric"><b>53/53</b><span>human-verified checks, 100% agreement</span></div>
    <div class="metric"><b>99.8%</b><span>accuracy on 540 live scale calls</span></div>
    <div class="metric"><b>0</b><span>false negatives (7,500+ adversarial cases)</span></div>
    <div class="metric"><b>98.8%</b><span>inter-rater reliability (blind vs anchored)</span></div>
    <div class="metric"><b>~400ms</b><span>p50 latency</span></div>
    <div class="metric"><b>$0.001</b><span>per evaluation (cost: $0.000037)</span></div>
  </div>
  <p class="note" style="border-color: var(--border); background: var(--panel);">Full methodology — scale runs, 5-iteration red-team loop, benchmark vs chat judge, meta-eval — in <a href="https://github.com/caiovicentino/jev-risk-check-provider/blob/main/docs/EVIDENCE.md" style="color:var(--accent)">docs/EVIDENCE.md</a>. Seeded corpora are reproducible.</p>

  <h2 id="integrate">Integrate</h2>
  <pre>
<span class="c"># 1. Evaluate — free tier (first 100/day, no payment needed)</span>
curl -X POST https://x402check.xyz/v1/risk-check \\
  -H "Content-Type: application/json" \\
  -d '{
    "wallet": "7Xf2...pvFh",
    "chain": "solana",
    "domain": "api.merchant-labs.com",
    "context": "agent pays $0.05 voucher for a pricing API call",
    "screening": { "sanctions": "clean" },
    "authorization": { "pre_authorized": true, "source": "user-dashboard" }
  }'

<span class="c"># 2. Response — decision + signed attestation (TTL 1h)</span>
{
  "checked": true,
  "score": 99,               <span class="c">// 0-100; block if below your min_score</span>
  "tier": "low",             <span class="c">// low | medium | high | critical</span>
  "provider": "did:web:x402check.xyz",
  "jws": "eyJhbGciOiJFUzI1Ni...", <span class="c">// ES256, verifiable vs /.well-known/jwks.json</span>
  "checked_at": "...", "expires_at": "..."
}

<span class="c"># 3. Verify the attestation (any client)</span>
curl https://x402check.xyz/.well-known/jwks.json
<span class="c"># verify the JWS (ES256, ieee-p1363) — iss must be did:web:x402check.xyz</span>

<span class="c"># 4. Beyond the free tier: pay with x402</span>
<span class="c"># The endpoint speaks the x402 protocol — a request past quota returns 402</span>
<span class="c"># with accepts for Base USDC and Solana USDC. Pay with any x402 client.</span>
  </pre>

  <h2>Pricing &amp; identity</h2>
  <table>
    <tr><th></th><th></th></tr>
    <tr><td>Free tier</td><td>100 evaluations/day per caller (demo-friendly)</td></tr>
    <tr><td>Paid</td><td>$0.001 per evaluation via x402 (Base Sepolia USDC, Solana Devnet USDC today; mainnet networks next)</td></tr>
    <tr><td>Identity</td><td><code>did:web:x402check.xyz</code> — <a href="/.well-known/did.json" style="color:var(--accent)">DID document</a>, attestations verify against <a href="/.well-known/jwks.json" style="color:var(--accent)">public JWKS</a></td></tr>
    <tr><td>Engine</td><td>TypeSafe Jev System One (typed-decision model) + deterministic scoring in open-source code</td></tr>
  </table>
  <p class="note">Payments are on <b>testnet</b> networks today (free facilitator, real protocol flow). Mainnet facilitators (Base, Solana via Kora) land next — the same attestation and API, real settlement.</p>

  <footer>
    <span>MIT — <a href="https://github.com/caiovicentino/jev-risk-check-provider">caiovicentino/jev-risk-check-provider</a></span>
    <span><a href="https://github.com/x402-foundation/x402/issues/3597">x402 #3597</a></span>
    <span><a href="https://github.com/x402-foundation/x402/pull/2300">trust-provider extension PR #2300</a></span>
    <span>x402check is a third-party reference provider for the x402 protocol</span>
  </footer>
</div>
</body>
</html>`;

export function landingPage(): string {
  return PAGE;
}
