# @x402check/ai-sdk

[x402check](https://x402check.xyz) for the [Vercel AI SDK](https://ai-sdk.dev) 7: screen the counterparty **before a tool moves money**.

- **`x402checkApproval`** is a `toolApproval` policy for `generateText` and `streamText`. Before a tool that sends funds, approves a spender or pays an invoice runs, x402check checks the address its input names, and the verdict becomes the approval:

  | x402check | the tool call |
  |---|---|
  | `allow` | **approved**: it runs |
  | `warn` | **user-approval**: it waits for a human (or `denied`, with `onWarn: "denied"`) |
  | `block` | **denied** |
  | `not_verified` (the check failed, or its signature did not verify) | **denied** |

  For a tool that runs on the server (it has an `execute`), the model cannot skip the check: the AI SDK asks the policy before it executes the tool, and again when an approval is replayed. The tool's own `needsApproval` still applies, and the stricter answer wins. [Limits](#limits) lists what a tool-approval policy cannot hold back.
- **`x402checkTool`** gives the model a risk-check tool to call on its own, for counterparties it is still choosing.

Every verdict is an ES256 attestation signed by `did:web:x402check.xyz`. It is verified against the exact request it answers, with x402check's key pinned, before anything is approved. The check screens:
- the OFAC SDN list;
- phishing and drainer lists, and x402check's own watch of drainer infrastructure on Ethereum and Base;
- look-alike domains;
- the content the agent acted on, for injected instructions.

Every check is paid: **$0.001 from prepaid credits**, or per call with x402. There is no free tier.

```bash
npm install @x402check/ai-sdk ai
```

It needs `ai` 7.0.153 or later and Node.js 22.12 or later.

## Enforce: a tool-approval policy

```ts
import { generateText, tool } from "ai";
import { z } from "zod";
import { x402checkApproval } from "@x402check/ai-sdk";

const tools = {
  sendUsdc: tool({
    description: "Send USDC on Base",
    inputSchema: z.object({ to: z.string(), amount: z.string() }),
    execute: async ({ to, amount }) => wallet.sendUsdc(to, amount),
  }),
  getWeather, // not listed below: never checked, never charged
};

const result = await generateText({
  model,
  tools,
  prompt,
  toolApproval: x402checkApproval<typeof tools>({
    creditToken: process.env.X402CHECK_CREDIT_TOKEN, // x402c_…
    tools: {
      // Who receives value or rights: the recipient, spender, operator or payee.
      sendUsdc: (input) => ({ wallet: input.to, chain: "base", interaction: { type: "token_transfer" } }),
    },
  }),
});
```

- **What a mapper returns:** a `RiskCheckRequest` from `@x402check/client`, an array of them (checked in one batch, and the worst verdict decides), or `undefined` to leave that call unchecked.
- **A `warn`** ends the step with a `tool-approval-request` whose `reason` lists x402check's reasons: show it to the user and answer with `addToolApprovalResponse` (or a `tool-approval-response` message). On the replay the policy runs again. A verdict from the last five minutes for the same call is reused, so the replay is not charged twice.
- **`onVerdict`** receives every screened call, for audit logs, together with the signed attestations.
- **Fail closed:** a timeout, an outage, a missing or invalid signature, an attestation for another request, or a mapper that throws all deny the call.

### Limits

A `toolApproval` policy decides only what the AI SDK itself executes:
- **A tool without `execute`** runs in the client, for example a browser wallet in `useChat`'s `onToolCall`. The AI SDK hands the call to the client before it asks any policy, so an approval cannot hold it back.
  - A listed tool without `execute` is denied, with a reason that says why, so the misuse shows.
  - Check such a payment where it runs, before the wallet signs: for example, a server route that calls `createScreener`. Better still, keep value-moving tools on the server.
- **A provider-executed tool** runs at the model provider before the policy is asked.
- **With `generateText`, `result.toolCalls` also lists denied calls.** If you execute calls yourself, read the `tool-approval-response` parts first.

### What is sent

Each check carries the counterparty and, as `context`, the content the agent acted on:
- the latest user message and the tool results after it;
- the call itself (the tool's name and input).

That `context` is what the injection check reads. Pass `context: (messages) => …` to choose the text yourself, or `context: false` to send none (the injection check then has nothing to read).

## Advise: a tool for the model

```ts
import { x402checkTool } from "@x402check/ai-sdk";

const tools = { x402check: x402checkTool({ creditToken }), ...yourTools };
```

The model calls it with `address`, `chain` and optionally `domain`, `interaction` and `context`. It gets back `action`, `tier`, `reasons`, the `instruction` to follow, and the attestation. A model can ignore advice, so enforce with `x402checkApproval` on the tools that move value.

## Paying for checks

- **Prepaid credits** (recommended): $0.001 a check. Buy a token once with `createClient().buyCredits(amountUsd)` from `@x402check/client`, paying it with any x402 client. Then pass `creditToken`.
- **Per call:** pass `fetch`, an x402-paying fetch such as `wrapFetchWithPayment` from `@x402/fetch`. It costs $0.0035 on Base and $0.002 on Solana.

If your agent also pays x402 resources itself, add `x402PaymentGuard` from `@x402check/client/guard` to that x402 client. If it signs with a viem account, wrap the account with `guardAccount`. The key then signs only after a verified allow.

## Options

`client`, `creditToken`, `fetch`, `baseUrl`, `timeoutMs` (default 10 s), `issuer`, and `pinnedKeys` (`false` only for tests against a local issuer) work as in `@x402check/client`. `createScreener(options)` exposes the check, verify and interpret step on its own.

## License

MIT
