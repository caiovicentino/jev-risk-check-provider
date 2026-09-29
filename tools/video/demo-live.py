#!/usr/bin/env python3
"""Live-money demo: real wallet, real x402 settlement, real on-chain proof.
All terminal output and screenshots come from actual production events."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from render import (anim_title, anim_metrics, anim_terminal, anim_browser, build_video,
                    c, g, warn, dim, TERM_FG, OUT)

TX = "5U57horHinfpJ8ibqbuhiBvHty47rSD2BtrZknjvXJcKNWBvo9yvxzKXgvEEPaTAi5msCKeFqA3zMsnjBiKA6pxT"
SOLSCAN = f"https://solscan.io/tx/{TX}"
EXPLORER = f"https://explorer.solana.com/tx/{TX}"

FREE_LINES = [
    dim("$ curl -i -X POST https://x402check.xyz/v1/risk-check \\"),
    dim('    -H "content-type: application/json" \\'),
    dim('    -d \'{"wallet":"7Xf2...LmBh","chain":"solana","context":...}\''),
    ("",),
    g("HTTP/2 200"),
    g("x-risk-check-free: true"),
    ("",),
    ('{ "checked": true, "score": 100, "tier": "low",',),
    ('  "provider": "did:web:x402check.xyz",',),
    ('  "jws": "eyJhbGciOiJFUzI1NiIsInR5cCI6InJpc2stY2hlY2srand0Iiwia...',),
    ('   ....MCd3wTzGuUT-lqA9BWlGbMr6vQDef-Oy5Zy3RAcurS1VXp44bZi...",',),
    ('  "jwks_url": "https://x402check.xyz/.well-known/jwks.json" }',),
]

PAID_LINES = [
    dim("$ PAY_NETWORK=solana:mainnet X402CHECK_PAID=1 npx tsx scripts/x402-pay.ts"),
    ("",),
    ("payer: SOL FxV8erYgrfrHnTvgc7ZWN565ATATZe8LSxoWb7xw2mAX",),
    dim("POST https://x402check.xyz/v1/risk-check | network: solana | PAID"),
    ("",),
    g('SETTLED: {"success":true, "network":"solana:5eykt...Kvdp",'),
    g('          "payer":"FxV8erYgrfrHnTvgc...2mAX"}'),
    g(f"PROOF: https://solscan.io/tx/{TX[:28]}"),
    g(f"             {TX[28:]}"),
    ("",),
    ('{ "checked": true, "score": 99, "tier": "low",',),
    ('  "provider": "did:web:x402check.xyz",',),
    ('  "jws": "eyJhbGciOiJFUzI1NiIsInR5cCI6InJpc2stY2hlY2srand0Iiwia...',),
    ('  "jwks_url": "https://x402check.xyz/.well-known/jwks.json",',),
    ('  "expires_at": "2026-09-29T03:17:21.000Z" }',),
]

VERIFY_LINES = [
    dim("$ npx tsx scripts/verify-attest.ts <jws-from-response>"),
    ("",),
    g('{ "valid": true, "alg": "ES256", "kid": "jev-attest-v1",'),
    g('  "iss": "did:web:x402check.xyz",'),
    g('  "sub": "7Xf2KrLzVqRT7pWruvFh4m6cBYuYEuNoXcRMKnvsLmBh",'),
    g('  "score": 99, "tier": "low",'),
    g('  "input_hash": "350df00fd52184f8a0d2f6809d44a788699461aab82fc8d5badf837fa6db73f5" }'),
    ("",),
    dim("verified against the live JWKS at x402check.xyz"),
]


def norm(lines):
    out = []
    for t in lines:
        st, col = t[0], (t[1] if len(t) > 1 and isinstance(t[1], tuple) else TERM_FG)
        if st == "": continue
        out.append((st, col))
    return out

def seg(draw, narration):
    return {"draw": draw, "narration": narration}

def f_demo():
    segs = []
    segs.append(seg(
        anim_title("x402check · live demo · solana mainnet",
                   ["A real wallet pays", "for a real risk check"],
                   "Every number in this video comes from production. Nothing mocked."),
        "This is not a mock. We fund a real wallet with real U S D C, call x402check, and the settlement lands on Solana mainnet. Every number you see is from production."))
    segs.append(seg(
        anim_browser(os.path.join(OUT, "shot-landing.png"), "x402check.xyz", dark=False, zoom=1.14),
        "The product is live at x402check dot xyz. A public discovery document, a resolvable D I D, and the public key set anyone can verify our verdicts against."))
    segs.append(seg(
        anim_terminal(norm(FREE_LINES), note="free tier: 25 evaluations/day, no signup"),
        "First, the free tier. Twenty-five evaluations a day, no signup. The response header says free, and the verdict arrives as a signed attestation."))
    segs.append(seg(
        anim_terminal(norm(PAID_LINES), note="real settlement: 0.002 USDC on Solana mainnet"),
        "Now the paid path. Our payer wallet asks for the check, opting to pay. The x402 client receives the payment required response, signs the transfer, and the Dexter facilitator settles it. The verdict comes back: score ninety nine, tier low, signed."))
    segs.append(seg(
        anim_browser(os.path.join(OUT, "shot-explorer.png"), EXPLORER, dark=True, zoom=1.10),
        "And there it is on chain. Solana Explorer — the same record is on Solscan. Status: success. Finalized. That signature is the settlement we just made."))
    segs.append(seg(
        anim_browser(os.path.join(OUT, "shot-explorer-tokens.png"), EXPLORER, dark=True, zoom=1.08),
        "The token transfer: zero point zero zero two U S D C from the payer to the provider treasury. And the network fee was paid by the Dexter facilitator — gas sponsored. The facilitator never touches the funds; they move buyer to provider directly. The memo even carries the attestation's input hash."))
    segs.append(seg(
        anim_terminal(norm(VERIFY_LINES), note="anyone can verify any verdict against the public JWKS"),
        "And the verdict is independently verifiable. One command: the J W S checks against the public J W K S. Real wallet, real payment, real settlement, signed verdict."))
    segs.append(seg(
        anim_metrics([
            ("0.002 USDC", "settled on Solana mainnet, tx confirmed and finalized"),
            ("0.000010001 SOL", "network fee — paid by the Dexter facilitator, zero to us"),
            ("1 command", "npx tsx scripts/verify-attest.ts <jws> → valid: true"),
        ], note="x402check — signed intent for agent payments"),
        "Real wallet, real payment, real settlement, and a signed verdict anyone can check. x402check: signed intent for agent payments."))
    return segs

if __name__ == "__main__":
    build_video("demo-live", f_demo())
