const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>x402check — payer-intent risk checks for x402</title>
<meta name="description" content="Signed, typed payer-intent risk checks for x402 agent payments. Fail-closed, verifiable, $0.001 per evaluation.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --paper: #fcfcfa; --ink: #16181d; --muted: #5d6472; --faint: #8b90a0;
    --line: #e4e4de; --panel: #f4f4ee; --code: #f7f7f3;
    --green: #0b6e4f; --red: #a13224;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }
  body {
    background: var(--paper); color: var(--ink);
    font: 16px/1.65 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    -webkit-font-smoothing: antialiased; text-rendering: optimizeLegibility;
  }
  .mono { font-family: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, monospace; }
  .wrap { max-width: 1060px; margin: 0 auto; padding: 0 28px; }

  /* top bar */
  .top { display: flex; align-items: baseline; gap: 28px; padding: 22px 0; border-bottom: 1px solid var(--line); }
  .mark { font-family: "IBM Plex Mono", monospace; font-weight: 500; font-size: 15px; }
  .mark span { color: var(--green); }
  .top nav { margin-left: auto; display: flex; gap: 22px; font-size: 13.5px; }
  .top a { color: var(--muted); text-decoration: none; }
  .top a:hover { color: var(--ink); }

  /* hero */
  .hero { display: grid; grid-template-columns: 1.15fr 0.85fr; gap: 56px; padding: 72px 0 64px; align-items: start; }
  .kicker { font-family: "IBM Plex Mono", monospace; font-size: 12px; letter-spacing: 0.08em; color: var(--faint); text-transform: uppercase; margin-bottom: 20px; }
  h1 { font-family: "Space Grotesk", ui-sans-serif, system-ui, sans-serif; font-weight: 500; font-size: clamp(34px, 4.6vw, 52px); line-height: 1.08; letter-spacing: -0.025em; margin-bottom: 20px; }
  .lede { color: var(--muted); font-size: 17.5px; max-width: 30em; margin-bottom: 30px; }
  .lede b { color: var(--ink); font-weight: 600; }
  .cta-row { display: flex; gap: 12px; flex-wrap: wrap; }
  .cta { font-family: "IBM Plex Mono", monospace; font-size: 13.5px; padding: 11px 18px; text-decoration: none; border: 1px solid var(--ink); border-radius: 3px; }
  .cta.solid { background: var(--ink); color: var(--paper); }
  .cta.solid:hover { background: #2a2d35; }
  .cta.line { color: var(--ink); }
  .cta.line:hover { border-color: var(--green); color: var(--green); }

  /* attestation document */
  .doc { border: 1px solid var(--ink); border-radius: 4px; background: #fff; box-shadow: 4px 4px 0 rgba(22,24,29,0.06); }
  .doc-head { display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; border-bottom: 1px solid var(--line); }
  .doc-head .t { font-family: "IBM Plex Mono", monospace; font-size: 12px; letter-spacing: 0.06em; text-transform: uppercase; color: var(--faint); }
  .doc-head .stamp { font-family: "IBM Plex Mono", monospace; font-size: 11px; color: var(--green); border: 1px solid var(--green); padding: 2px 8px; border-radius: 2px; letter-spacing: 0.05em; }
  .doc-body { padding: 14px 16px; font-family: "IBM Plex Mono", monospace; font-size: 12.5px; line-height: 1.7; }
  .doc-body .row { display: flex; gap: 14px; }
  .doc-body .k { width: 110px; color: var(--faint); flex-shrink: 0; }
  .doc-body .v { color: var(--ink); word-break: break-all; }
  .doc-body .v.ok { color: var(--green); }
  .doc-foot { padding: 10px 16px; border-top: 1px dashed var(--line); font-family: "IBM Plex Mono", monospace; font-size: 11px; color: var(--faint); }

  /* sections */
  section { border-top: 1px solid var(--line); padding: 52px 0; }
  .sec-head { display: flex; align-items: baseline; gap: 18px; margin-bottom: 30px; }
  .sec-no { font-family: "IBM Plex Mono", monospace; font-size: 13px; color: var(--faint); }
  h2 { font-family: "Space Grotesk", sans-serif; font-weight: 500; font-size: 26px; letter-spacing: -0.02em; }
  .cols { display: grid; grid-template-columns: repeat(2, 1fr); gap: 0 48px; }
  .item { padding: 18px 0; border-top: 1px solid var(--line); }
  .item h3 { font-family: "IBM Plex Mono", monospace; font-weight: 500; font-size: 14px; margin-bottom: 6px; }
  .item h3 em { color: var(--green); font-style: normal; }
  .item p { color: var(--muted); font-size: 14.5px; }

  /* metrics ledger */
  .ledger { border: 1px solid var(--line); border-radius: 4px; overflow: hidden; }
  .ledger-row { display: grid; grid-template-columns: repeat(6, 1fr); }
  .ledger-cell { padding: 20px 18px; border-right: 1px solid var(--line); }
  .ledger-cell:last-child { border-right: none; }
  .ledger-cell b { font-family: "IBM Plex Mono", monospace; font-weight: 500; font-size: 22px; display: block; margin-bottom: 4px; }
  .ledger-cell b.ok { color: var(--green); }
  .ledger-cell span { color: var(--faint); font-size: 12px; line-height: 1.5; display: block; }

  /* code */
  pre { background: var(--code); border: 1px solid var(--line); border-radius: 4px; padding: 18px 20px; overflow-x: auto;
        font-family: "IBM Plex Mono", monospace; font-size: 13px; line-height: 1.6; }
  pre .cm { color: var(--faint); }
  pre .g { color: var(--green); }

  /* table */
  table { width: 100%; border-collapse: collapse; font-size: 14.5px; }
  th { font-family: "IBM Plex Mono", monospace; font-size: 12px; font-weight: 500; letter-spacing: 0.06em; text-transform: uppercase; color: var(--faint); text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--ink); }
  td { padding: 12px 14px; border-bottom: 1px solid var(--line); vertical-align: top; }
  td:first-child { color: var(--muted); width: 160px; }

  .note { border: 1px solid var(--line); border-left: 3px solid var(--ink); background: var(--panel); padding: 14px 18px; font-size: 14px; color: var(--muted); margin-top: 22px; max-width: 780px; }
  .note b { color: var(--ink); font-weight: 600; }

  footer { border-top: 1px solid var(--ink); padding: 26px 0 44px; display: flex; flex-wrap: wrap; gap: 8px 28px; font-family: "IBM Plex Mono", monospace; font-size: 12.5px; color: var(--faint); }
  footer a { color: var(--muted); text-decoration: none; }
  footer a:hover { color: var(--green); }

  @media (max-width: 860px) {
    .hero { grid-template-columns: 1fr; gap: 40px; padding: 48px 0; }
    .cols { grid-template-columns: 1fr; }
    .ledger-row { grid-template-columns: repeat(3, 1fr); }
    .ledger-cell:nth-child(3n) { border-right: none; }
    .ledger-cell:nth-child(-n+3) { border-bottom: 1px solid var(--line); }
  }
</style>
</head>
<body>
<div class="wrap">

  <div class="top">
    <div class="mark">x402check<span>.</span>xyz</div>
    <nav>
      <a href="#evidence">Evidence</a>
      <a href="#integrate">Integration</a>
      <a href="/.well-known/risk-check.json">Discovery</a>
      <a href="https://github.com/caiovicentino/jev-risk-check-provider">Source</a>
    </nav>
  </div>

  <div class="hero">
    <div>
      <div class="kicker">x402 trust-provider &middot; risk-check extension &middot; reference implementation</div>
      <h1>One question before you settle an agent's payment: is the payer's intent legitimate?</h1>
      <p class="lede">x402check answers it with a <b>typed decision</b> from a calibrated decision model, scored by deterministic code, and returned as a <b>signed attestation</b> anyone can verify. ~400&nbsp;ms, $0.001, fail-closed.</p>
      <div class="cta-row">
        <a class="cta solid" href="#integrate">Integrate in 5 minutes</a>
        <a class="cta line" href="https://github.com/caiovicentino/jev-risk-check-provider/blob/main/docs/EVIDENCE.md">Read the evidence</a>
      </div>
    </div>
    <div class="doc">
      <div class="doc-head"><span class="t">Attestation</span><span class="stamp">VERIFIED</span></div>
      <div class="doc-body">
        <div class="row"><span class="k">alg</span><span class="v">ES256</span></div>
        <div class="row"><span class="k">typ</span><span class="v">risk-check+jwt</span></div>
        <div class="row"><span class="k">kid</span><span class="v">jev-attest-v1</span></div>
        <div class="row"><span class="k">iss</span><span class="v">did:web:x402check.xyz</span></div>
        <div class="row"><span class="k">score</span><span class="v ok">94</span></div>
        <div class="row"><span class="k">tier</span><span class="v">low</span></div>
        <div class="row"><span class="k">input_hash</span><span class="v">894df5fe0e6667f2...</span></div>
      </div>
      <div class="doc-foot">signature: MEUCIQ&amp;hellip; (64 bytes, r||s) &middot; verifiable against /.well-known/jwks.json &middot; TTL 1h</div>
    </div>
  </div>

  <section id="what">
    <div class="sec-head"><span class="sec-no">01</span><h2>What it answers</h2></div>
    <div class="cols">
      <div class="item"><h3><em>Injection</em> &middot; guard bypass</h3>
        <p>Injected instructions in context, tool outputs asking the agent to sign unknown spends, skill-file payloads routed through trusted channels, and direct attempts to disable the payment guard.</p></div>
      <div class="item"><h3><em>Impersonation</em> &middot; social engineering</h3>
        <p>Homoglyph domains (coinbase-wa11et, jup1ter-audit), purchased audit certificates, wallet-restore helper scams, deadline pressure on treasury movements.</p></div>
      <div class="item"><h3><em>Laundering</em> &middot; sanctions</h3>
        <p>Peel chains, mixer hops, structuring under reporting thresholds, counterparties on screening lists, no-KYC exchange clusters.</p></div>
      <div class="item"><h3><em>Abuse</em> &middot; scale patterns</h3>
        <p>Fresh wallets issuing thousands of identical sub-cent payments, coupon-farming wallet rotation, sybil campaigns — the failure modes specific to micropayment commerce.</p></div>
    </div>
  </section>

  <section id="how">
    <div class="sec-head"><span class="sec-no">02</span><h2>How it works</h2></div>
    <div class="cols">
      <div class="item"><h3>Typed decisions, not prose</h3>
        <p>A decision model (TypeSafe Jev, System One) answers typed questions — probabilities, choices, calibrated scores. Deterministic code composes them into one number. The model never re-interprets its own policy.</p></div>
      <div class="item"><h3>Structured evidence over claims</h3>
        <p>"Already screened, proceeding" is scored as an unverified claim — which is what an attacker would say. Only structured <span class="mono" style="font-size:13px">screening</span> and <span class="mono" style="font-size:13px">authorization</span> fields move policy; prose never does.</p></div>
      <div class="item"><h3>Signed, verifiable verdicts</h3>
        <p>Every decision ships as an ES256 JWS from <span class="mono" style="font-size:13px">did:web:x402check.xyz</span>. Any resource server — or QUORUM aggregator — can verify it against the public JWKS without trusting us.</p></div>
      <div class="item"><h3>Fail-closed by construction</h3>
        <p>Model unreachable → <span class="mono" style="font-size:13px">checked: false</span>, settlement does not proceed. Low-confidence answers are capped, uncertainty routes to review — never to a silent allow.</p></div>
    </div>
  </section>

  <section id="evidence">
    <div class="sec-head"><span class="sec-no">03</span><h2>Evidence, not claims</h2></div>
    <div class="ledger">
      <div class="ledger-row">
        <div class="ledger-cell"><b class="ok">53/53</b><span>human-verified checks, 100% agreement with authored labels</span></div>
        <div class="ledger-cell"><b class="ok">99.8%</b><span>accuracy on 540 live calls, threshold sweep 65–75</span></div>
        <div class="ledger-cell"><b class="ok">0</b><span>false negatives over 7,500+ adversarial cases</span></div>
        <div class="ledger-cell"><b>98.8%</b><span>inter-rater reliability, blind vs anchored framing</span></div>
        <div class="ledger-cell"><b>~400ms</b><span>p50 latency, gateway backend</span></div>
        <div class="ledger-cell"><b>$0.001</b><span>per evaluation (marginal cost $0.000037)</span></div>
      </div>
    </div>
    <p class="note">Methodology is public and reproducible: 5-iteration red-team loop (1,500 adversarial cases per iteration), benchmark against a chat-judge baseline, meta-eval with probability gating, and a human-verified switch-over gate. <a href="https://github.com/caiovicentino/jev-risk-check-provider/blob/main/docs/EVIDENCE.md">docs/EVIDENCE.md</a></p>
  </section>

  <section id="integrate">
    <div class="sec-head"><span class="sec-no">04</span><h2>Integration</h2></div>
    <pre>
<span class="cm"># Evaluate — the first 100 calls per day are free, no payment needed</span>
curl -X POST https://x402check.xyz/v1/risk-check \\
  -H <span class="g">"Content-Type: application/json"</span> \\
  -d '{
    "wallet": "7Xf2...pvFh",
    "chain": "solana",
    "domain": "api.merchant-labs.com",
    "context": "agent pays $0.05 voucher for a pricing API call",
    "screening":     { "sanctions": "clean" },
    "authorization": { "pre_authorized": true, "source": "user-dashboard" }
  }'

<span class="cm"># Response — the decision plus its signed attestation</span>
{
  "checked": true,
  "score": 99,                <span class="cm">// 0–100 · block below your min_score (we suggest 65)</span>
  "tier": "low",              <span class="cm">// low · medium (review) · high · critical</span>
  "provider": "did:web:x402check.xyz",
  "jws": "eyJhbGciOiJFUzI1Ni...", <span class="cm">// ES256 attestation, TTL 1h</span>
  "checked_at": "...", "expires_at": "..."
}

<span class="cm"># Verify the attestation with any JWS library — signature is r||s (ieee-p1363)</span>
curl https://x402check.xyz/.well-known/jwks.json

<span class="cm"># Past the free tier, the endpoint speaks x402: a 402 response carries the</span>
<span class="cm"># payment options (Base USDC, Solana USDC). Pay with any x402 client.</span>
    </pre>
  </section>

  <section id="pricing">
    <div class="sec-head"><span class="sec-no">05</span><h2>Pricing &amp; identity</h2></div>
    <table>
      <tr><th></th><th></th></tr>
      <tr><td>Free tier</td><td>100 evaluations per day, per caller — enough for an integration build-out</td></tr>
      <tr><td>Paid</td><td>$0.001 per evaluation, settled with x402 — <b>Base USDC and Solana USDC on mainnet</b> (gas sponsored, zero facilitator fee), plus testnets</td></tr>
      <tr><td>Identity</td><td><span class="mono" style="font-size:13.5px">did:web:x402check.xyz</span> — <a href="/.well-known/did.json">DID document</a> &middot; <a href="/.well-known/jwks.json">public JWKS</a></td></tr>
      <tr><td>Engine</td><td>TypeSafe Jev System One for intent; deterministic scoring in open-source code (MIT)</td></tr>
<tr><td>Networks</td><td>Accepts USDC settlement across the x402 networks: EVM chains (Base, Polygon, Arbitrum, Avalanche, Monad, Sei) and Solana, mainnet + testnet</td></tr>
    </table>
<p class="note"><b>Payment networks live:</b> Base, Solana, Polygon, Arbitrum, Avalanche, Monad and Sei on mainnet — plus Base Sepolia, Arbitrum Sepolia and Solana Devnet testnets — all settling USDC via x402 with any client (agent wallets, SDKs). The facilitator verifies the buyer's signed authorization and submits the transfer onchain; buyer funds move directly to the provider wallet, and the facilitator never holds them.</p>
  </section>

  <footer>
    <span>MIT License</span>
    <a href="https://github.com/caiovicentino/jev-risk-check-provider">caiovicentino/jev-risk-check-provider</a>
    <a href="https://github.com/x402-foundation/x402/issues/3597">x402 #3597</a>
    <a href="https://github.com/x402-foundation/x402/pull/2300">PR #2300</a>
    <span>x402check is a third-party reference provider for the x402 protocol — not affiliated with the x402 Foundation</span>
  </footer>

</div>
</body>
</html>`;

export function landingPage(): string {
  return PAGE;
}
