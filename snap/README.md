# x402check-snap

A MetaMask Snap that decodes every transaction and signature locally, before you sign. It shows the real counterparty (the spender, operator or recipient inside the calldata or typed data, not the token contract), the amounts, including UNLIMITED approvals, and local danger findings.

**Version 0.3.0 sends nothing and has no network permission.** [x402check](https://x402check.xyz) evaluations are paid per call through x402, and a Snap cannot pay yet. So every insight says "NOT verified by x402check" and never shows an all-clear.

The paid mode is built and tested behind one flag (`src/config.ts`). It checks the counterparty, simulates the transaction ("You send 1.5 ETH → 0x… (wallet)") and renders the signed verdict. It will ship when wallet-side payment exists.

## What it decodes

- **Calldata:** ERC-20 approve and transfer, Permit2, EIP-2612, setApprovalForAll, NFT transfers, and wrappers (multicall, Safe, Universal Router, ERC-7579/4337, 7702 self-calls).
- **Typed data:** v1, v3 and v4, including Permit2, Seaport and UniswapX.
- **`personal_sign` messages,** decoded to text.

## Build and test

```bash
npm install
npm test          # builds the bundle, then runs 322 tests (285 against the built bundle in SES; the paid-mode scenarios run in Node)
npx mm-snap serve # then wallet_requestSnaps "local:http://localhost:8062" in MetaMask Flask
```

This Snap is not yet published to npm or allowlisted by MetaMask. The main project README is at [the repository root](https://github.com/caiovicentino/jev-risk-check-provider#metamask-snap-preview). The license is MIT.
