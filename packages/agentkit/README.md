# @x402check/agentkit

[x402check](https://x402check.xyz) for [Coinbase AgentKit](https://github.com/coinbase/agentkit) (TypeScript): screen every counterparty **before the agent's key signs**.

- **`guardWalletProvider(wallet, options)`** returns the same EVM wallet provider with x402check between it and every signature. Before anything is signed or sent, the guard decodes it and checks the counterparty, then verifies the signed verdict. Anything but a verified `allow` throws `X402CheckBlockedError`, and nothing is signed. It covers:
  - AgentKit's **x402 payments** (`x402ActionProvider` signs EIP-3009 and Permit2 typed data through `toSigner()`);
  - ERC-20 and native **transfers**, **approvals**, contract calls and messages.
- **`x402checkActionProvider(options)`** gives the agent one action, `X402checkActionProvider_check_counterparty`. The agent can check an address, the site and the content it acted on **before** it decides to pay, and gets back what to do.

Every verdict is an ES256 attestation signed by `did:web:x402check.xyz`. It is verified against the exact request it answers, with x402check's key pinned, before the key signs. The check screens:
- the OFAC SDN list;
- phishing and drainer lists, and x402check's own watch of drainer infrastructure on Ethereum and Base;
- look-alike domains;
- a simulation of the transaction;
- the content the agent acted on, for injected instructions.

Every check is paid: **$0.001 from prepaid credits** ($0.005 for a simulated transaction), or per call with x402. There is no free tier.

```bash
npm install @x402check/agentkit @coinbase/agentkit
```

## Quickstart

```ts
import { AgentKit, CdpEvmWalletProvider, erc20ActionProvider, x402ActionProvider } from "@coinbase/agentkit";
import { guardWalletProvider, x402checkActionProvider } from "@x402check/agentkit";

const creditToken = process.env.X402CHECK_CREDIT_TOKEN; // x402c_…

const wallet = guardWalletProvider(await CdpEvmWalletProvider.configureWithWallet({ /* … */ }), {
  creditToken,
  onWarn: async (verdict) => askTheUser(verdict.reasons), // default: a warn refuses
});

const agentkit = await AgentKit.from({
  walletProvider: wallet,
  actionProviders: [x402ActionProvider(), erc20ActionProvider(), x402checkActionProvider({ creditToken })],
});
// getLangChainTools(agentkit), getVercelAITools(agentkit) and getMcpTools(agentkit) work as usual.
```

When the agent pays an x402 resource, transfers tokens or approves a spender, the guard checks the payee, recipient or spender first:
- **allow:** it signs;
- **warn:** it signs only if `onWarn` returns true;
- **block or not_verified:** it throws, and the action reports the refusal to the agent.

## What is guarded

| Wallet member | Guarded as |
|---|---|
| `signTypedData` (x402 EIP-3009 / Permit2, permits, orders) | typed data, decoded: payee, spender, amount and asset are bound |
| `signTransaction`, `sendTransaction`, `nativeTransfer` | a transaction, simulated before signing; `sendTransaction` sends the checked copy |
| `signMessage` | a message, decoded and checked; a message of opaque bytes is refused like a raw hash |
| `sign(hash)` | refused: a raw hash could authorize anything (`allowRawHashSigning: true` lets it through, unchecked) |
| `toSigner()` (and `toEip1193Provider()` where AgentKit has it) | built on the guarded methods above |
| any other member whose name signs or sends (`swap…`, `transfer…`, `execute…`) | refused (`passthrough: ["name"]` lets it through, unchecked) |

**Not covered:** work a wallet's backend does on its own, without the wallet provider's signing methods. A CDP server wallet's swaps through `getClient()`, for example, sign inside CDP.

**Solana:** this release guards EVM wallets. For a Solana signer, wrap it with `guardSolanaSigner` from `@x402check/client/guard`.

## Options

`guardWalletProvider` takes the options of `guardAccount` in `@x402check/client/guard`:
- **how checks are paid:** `creditToken` or `fetch`;
- **what a warn does, and an audit hook:** `onWarn` (default: refuse) and `onVerdict`;
- **the content the agent acted on:** `context`, checked for injected instructions;
- **limits:** `origin`, `maxFeeWei`, `passthrough` and `allowRawHashSigning`.

The chain comes from the wallet's network.

`x402checkActionProvider` takes `creditToken`, `fetch`, `baseUrl`, `timeoutMs`, `issuer` and `pinnedKeys`.

## Paying for checks

- **Prepaid credits** (recommended): $0.001 a check. Buy a token once with `createClient().buyCredits(amountUsd)` from `@x402check/client`, paying it with any x402 client, then pass `creditToken`.
- **Per call:** pass `fetch`, an x402-paying fetch such as `wrapFetchWithPayment` from `@x402/fetch`. It costs $0.0035 on Base. Payments to x402check's own `pay_to` are not checked, so paying for a check never triggers another check.

## Compatibility

- `@coinbase/agentkit` from 0.10.4 to below 0.12.
- The action's schema is built with the zod that AgentKit itself loads, so it works with AgentKit's LangChain, Vercel AI SDK and MCP extensions.
- The provider overrides `getActions`, so it uses no decorators.
- Node.js 22 or later.

## License

MIT
