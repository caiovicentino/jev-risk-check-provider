# @x402check/mcp

An MCP server that lets any AI agent check a counterparty **before money moves**, with [x402check](https://x402check.xyz). It is a stdio server built on the official [`@modelcontextprotocol/sdk`](https://github.com/modelcontextprotocol/typescript-sdk).

Each check screens the counterparty against the OFAC SDN list, phishing and drainer feeds, look-alike domains and on-chain facts. It can also simulate the transaction (API v0.3), and a typed model reads the content the agent acted on. The server verifies every verdict's ES256 attestation against `did:web:x402check.xyz` before the agent sees an action.

| Tool | What it does |
|---|---|
| `x402check_check` | Risk-checks a counterparty. It returns an action (`allow`, `warn`, `block` or `not_verified`), the findings, the evidence, the attestation `jti` and the full structured result. |
| `x402check_verify_attestation` | Verifies an x402check attestation (`{ jws, aud?, sub? }`) before relying on it. |
| `x402check_methodology` | Explains what is checked and the published, measured limits. |

## Install

### Claude Code

```bash
claude mcp add x402check -- npx -y @x402check/mcp

# optional: a stable id for this install gets its own daily free allowance
claude mcp add x402check -e X402CHECK_CLIENT_ID=$(uuidgen) -- npx -y @x402check/mcp
```

### Claude Desktop

Add the server to `claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "x402check": {
      "command": "npx",
      "args": ["-y", "@x402check/mcp"],
      "env": { "X402CHECK_CLIENT_ID": "a-stable-random-id-for-this-install" }
    }
  }
}
```

### Any other MCP client

Run `npx -y @x402check/mcp`, or `x402check-mcp` after `npm install -g @x402check/mcp`, as a stdio server. The server needs Node ≥ 20.

### From a local checkout (no npm publish needed)

```bash
# from the repository root; the server depends on the client via file:../client, so build the client first
npm --prefix packages/client ci && npm --prefix packages/client run build
npm --prefix packages/mcp ci && npm --prefix packages/mcp run build
node packages/mcp/dist/index.js --help
```

Then register the built entry point with an **absolute** path. Quote it if it contains spaces.

```bash
claude mcp add x402check -- node "/absolute/path/to/repo/packages/mcp/dist/index.js"
```

```json
{
  "mcpServers": {
    "x402check": { "command": "node", "args": ["/absolute/path/to/repo/packages/mcp/dist/index.js"] }
  }
}
```

## Configuration

| Variable | Default | |
|---|---|---|
| `X402CHECK_BASE_URL` | `https://x402check.xyz` | API origin, for example a staging or local provider |
| `X402CHECK_CLIENT_ID` | none | Sent as `X-Risk-Check-Client`. A stable random id (1–64 printable ASCII characters) gives this install its own 25 checks per day; otherwise the IP's allowance is shared. |
| `X402CHECK_ISSUER` | `did:web:x402check.xyz` | The attestation issuer this server trusts. It is the trust anchor, so it is operator configuration only and never a tool argument. |
| `X402CHECK_TIMEOUT_MS` | `10000` | per API call |

## How an agent should use it

The server's instructions and the tool description tell the agent the following:

- Call `x402check_check` **before** it sends funds, signs a token approval, permit or order, or pays an x402 invoice.
- Check the **real counterparty**: the recipient, spender, operator or `pay_to`, not the token contract.
- Pass the chain, the site, and the content it acted on (`context`), verbatim.
- Pass `transaction` (EVM `from`, `to`, `value`, `data`) to have the transaction simulated.
- Then follow the action:

| Action | Meaning | Agent behaviour |
|---|---|---|
| `allow` | No check fired. | Proceed. This is still not a guarantee of safety. |
| `warn` | Risk signals are present. | Get explicit confirmation from the user. |
| `block` | High or critical risk. | Do **not** proceed. |
| `not_verified` | The check did not complete or its attestation did not verify. Causes include 402 (free tier used up), 422, 503, a network error or timeout, `checked: false` (with its reason), and a bad, missing or mismatched attestation. | **STOP.** This is never an all-clear. |

The tool does not accept caller assertions (`screening`, `authorization`), because claims such as "already screened" are not evidence.

### What the agent reads

```text
x402check: BLOCK. Do not proceed.
Checked 0x7a3e8f0c2b1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f on base for permit_signature (unlimited) from https://app-uniswap.org
Why:
- Drainer pattern: assets leave the sender, nothing comes back, and a plain wallet (EOA) the sender did not name ends up with them: erc20 0x8335…2913 250000000 → 0x9999…9999 (EOA)
- Drainer pattern: an approval or permit grants a plain wallet (EOA) control over the user's assets: permit2 0x8335…2913 UNLIMITED to 0x7a3e…6e7f (EOA)
- Unlimited allowance: permit2 0x8335…2913 UNLIMITED to 0x7a3e…6e7f (EOA)
- Risk tier critical, score 10/100 (higher is safer)
Evidence: OFAC SDN not listed (list as of 2026-09-23) · on-chain: plain wallet (EOA), no history on eip155:8453 · domain app-uniswap.org: impersonation strong of uniswap · feeds: scamsniffer-addresses clear · model jev-wallet-risk/v6
Simulation (eip155:8453): ok · amounts in base units
- sends: erc20 0x8335…2913 250000000 → 0x9999…9999 (EOA)
- receives: none
- approves: permit2 0x8335…2913 UNLIMITED to 0x7a3e…6e7f (EOA)
- findings: outflow_to_undisclosed_eoa, approval_to_eoa, unlimited_approval
Attestation: signature verified against did:web:x402check.xyz · jti 7d0f3a52-1c4b-4e8a-9f6d-2b3c4d5e6f70 · expires 2026-09-29T18:00:55.000Z
Free checks left today: 3
Policy: allow → proceed · warn → ask the user first · block or not_verified → STOP.
```

The tool also returns `structuredContent`, which conforms to the tool's `outputSchema`, and the same JSON in a second text block. It holds these fields:

- `action`, `reasons`;
- `tier`, `score`, `categories` and `jti`, present only when the verdict is trusted;
- `attestation`: `{ verified, failures, issuer, expires_at }`;
- `usage`: `{ free, free_remaining }`;
- `error`: `{ code, status, message, field?, index?, retry_after?, payment_required? }`;
- `result`: the API result, with its `jws`. Its evidence is normalized, so values not in their expected format are dropped.

A failed call (402, 422, 413, 503, network error or timeout) also sets `isError: true`.

## Security properties

- **Attestations are always verified, and bound to the call.** The server checks the ES256 signature with the key in the pinned issuer's `did:web` document, never with a `jwks_url` or a header key.
  - The server recomputes the signed `request_hash` over the exact request it sent. Any field altered or dropped in transit is detected, `context` (the injected content) and `interaction.unlimited` included.
  - The attestation must also match the call's wallet, audience, interaction type, payment, analyzed domain and chain, and whether a transaction was simulated.
  - It must have been issued within the last 5 minutes (plus 5 minutes of clock skew), so an older attestation for the same address cannot be replayed.
  - The verdict comes from the signed claims. A response body whose tier, score or categories differ from them is rejected.
  - A missing or invalid attestation turns any verdict into `not_verified`.
- **Fail-closed.** Every error path, and `checked: false`, becomes `not_verified`. So does any output that could not be represented safely.
- **Response data cannot steer the agent.** The signature does not cover evidence, so every evidence value shown must match its expected format: digits, addresses, enums, dates, hostnames or identifiers. Anything else, such as instruction-like text planted in a field, is dropped. The same applies to error details and categories. All strings are also stripped of control, bidi, zero-width, tag and line-separator characters, so nothing can forge a line or hide text.
- **stdout carries MCP messages only.** Diagnostics go to stderr, and an invalid configuration exits non-zero at startup.

## Limits

x402check reports what the lists, the chain, the simulation and the content in front of it reveal. It cannot flag an unknown drainer that is simply sent funds (0/30 in the held-out evaluation), and it mostly misses unlisted phishing domains when no feed has them (0–3 of 60). Sanctions screening covers direct OFAC listing only. `x402check_methodology` returns the full list, and [docs/EVIDENCE.md](https://github.com/caiovicentino/jev-risk-check-provider/blob/main/docs/EVIDENCE.md) has the measurements.

## Programmatic use

The package also exports the server factory, so you can connect it to another transport:

```ts
import { createX402CheckServer, configFromEnv } from "@x402check/mcp";
const server = createX402CheckServer({ ...configFromEnv(), clientId: "my-install" });
await server.connect(transport); // e.g. a Streamable HTTP or in-memory transport from @modelcontextprotocol/sdk
```

## Development

```bash
(cd ../client && npm ci)   # the linked client's dev dependencies
npm ci
npm run build       # builds ../client first, then this package
npm test            # builds, then runs in-process tests over linked in-memory transports and a stdio test of dist/index.js
npm run typecheck   # also builds ../client first (its types come from ../client/dist)
```

In this repository, `@x402check/client` is a `file:../client` dependency. The published package depends on the npm release instead, such as `"@x402check/client": "^0.1.0"`. A `prepublishOnly` guard refuses to publish while any dependency still points at a local path.

MIT © Caio Vicentino
