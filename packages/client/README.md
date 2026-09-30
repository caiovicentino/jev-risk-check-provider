# @x402check/client

Typed client and attestation verifier for [x402check](https://x402check.xyz). x402check is a pre-payment risk check for AI agents, wallets and x402 payments. You call it before money moves, and it checks the counterparty against:

- the OFAC SDN list;
- phishing and drainer feeds;
- look-alike domain analysis;
- on-chain facts, such as an approval granted to a plain wallet;
- a simulation of the transaction (API v0.3);
- a typed model that reads the content the agent acted on.

Every verdict is an ES256 attestation signed by `did:web:x402check.xyz`. Every evaluation is paid with [x402](#paying-x402): **$0.001 from prepaid credits**, or per call at the payment network's price ($0.0035 on Base, $0.002 on Solana). A request whose `transaction` is simulated costs $0.005. There is no free tier.

- **Zero runtime dependencies.** ESM with bundled `.d.ts` types.
- **Runs anywhere WebCrypto and `fetch` exist:** Node ≥ 20, browsers, Cloudflare Workers, Deno and Bun.
- **`check` and `checkBatch`** return typed results and throw typed errors (`X402CheckError`).
- **`verifyAttestation`** checks the signature with the key in the issuer's `did:web` document, never with a URL taken from a response.
- **`interpret`** applies the **fail-closed** policy that wallets and agents should follow.
- **`guardAccount`** (`@x402check/client/guard`) puts x402check **between an agent and its key**. A transaction, permit, order, x402 payment or EIP-7702 delegation is signed only after a verified allow; otherwise it throws. See [Signing guard](#signing-guard-block-before-the-key-signs).

```bash
npm install @x402check/client
```

## Quickstart: agents

Call the check **before** the agent sends funds, signs an approval, permit or order, or pays an x402 invoice. Then follow the action it returns.

```ts
import { createClient, interpret, verifyAttestation, type Interpretation } from "@x402check/client";

const x402check = createClient({ fetch: payingFetch, timeoutMs: 30_000 }); // an x402-paying fetch, see "Paying (x402)"

async function guardPayment(p: { payTo: string; network: string; amount: string; asset: string; resource: string; actedOn: string }) {
  let verdict: Interpretation;
  try {
    const request = {
      wallet: p.payTo,                          // the REAL counterparty
      chain: p.network,                         // "base" or "eip155:8453"
      domain: p.resource,                       // the site being paid
      context: p.actedOn,                       // the content that led the agent here, verbatim
      interaction: { type: "token_transfer" as const },
      payment: { network: p.network, pay_to: p.payTo, amount: p.amount, asset: p.asset, resource: p.resource },
    };
    const result = await x402check.check(request);
    // Verify the signature against the pinned issuer, bound to THIS request and issued just now.
    const verification = await verifyAttestation(result.jws, { request, maxAgeSeconds: 300 });
    verdict = interpret(result, { verification });
  } catch (err) {
    verdict = interpret(err); // any failure → not_verified
  }

  switch (verdict.action) {
    case "allow":
      return; // proceed
    case "warn":
      return askTheUser(verdict.reasons); // explicit human confirmation
    default:
      // "block" or "not_verified": STOP
      throw new Error(`payment stopped (${verdict.action}): ${verdict.reasons.join("; ")}`);
  }
}
```

## Quickstart: wallets

Check the address that **receives value or rights**, not the token contract. For `approve`, Permit2 or a Seaport order, that is the spender, operator or recipient decoded from the calldata or typed data. Pass the transaction too, and the provider simulates it (API v0.3, EVM only).

```ts
const request = {
  wallet: spender,                                   // decoded from calldata / typed data
  chain: `eip155:${chainId}`,
  domain: origin,                                    // the requesting site
  interaction: { type: "token_approval" as const, unlimited: true },
  transaction: { from: account, to: tx.to, value: tx.value, data: tx.data },
};
const result = await x402check.check(request);
const verification = await verifyAttestation(result.jws, { request, maxAgeSeconds: 300 });
const { action, reasons } = interpret(result, { verification });
```

| Action | Tier | UX |
|---|---|---|
| `allow` | `low` | No warning. An optional "checked" badge is fine. Never say "safe". |
| `warn` | `medium` | Amber: review before confirming. |
| `block` | `high`, `critical` | Red: recommend not proceeding. Show the reasons and the evidence. |
| `not_verified` | no verdict | The check did not run or cannot be trusted. **Never show it as an all-clear.** |

`reasons` lists the most important finding first. The drainer signals lead:

- `outflow_to_undisclosed_eoa`: assets leave the sender, nothing comes back, and a plain wallet the sender did not name ends up with them.
- `approval_to_eoa`: a plain wallet is granted control over the user's assets.

The simulated flows are rendered in the same reason.

## Signing guard: block before the key signs

Calling `check` and obeying the answer is advisory: an agent that is tricked, for example by injected instructions, can skip it. The guard enforces the check in code. It wraps the account the agent signs with, and **the key signs only after a verified allow for that exact signature request.**

```ts
import { guardAccount, x402PaymentGuard } from "@x402check/client/guard";
import { privateKeyToAccount } from "viem/accounts";

const account = guardAccount(privateKeyToAccount(process.env.AGENT_KEY as `0x${string}`), {
  creditToken: process.env.X402CHECK_CREDIT_TOKEN, // $0.001 a check ($0.005 simulated); see Paying
  onWarn: async (verdict) => askTheUser(verdict),   // optional: without it, a warn is refused
  onVerdict: (verdict) => auditLog(verdict),         // optional: every decision, signed or refused
});

// Use it wherever the agent signs: a wallet client, an x402 client, an agent framework.
const wallet = createWalletClient({ account, chain: base, transport: http() });
await wallet.sendTransaction(tx); // throws X402CheckBlockedError before signing if refused
```

**Every signature, decoded first.** The guard intercepts `signTransaction`, `signTypedData`, `signMessage` and `signAuthorization`, and finds the real counterparty with the same decoders as the x402check MetaMask Snap:

- **A transaction:** the recipient of a transfer, the spender of an approval, or the operator of an NFT approval, including inside multicall, Safe and Universal Router wrappers. The transaction itself is sent for **simulation** at the latest block.
- **Typed data:** the spender of an EIP-2612 permit or a Permit2 signature, and the recipients of a Seaport order.
- **An x402 payment on EVM** (an EIP-3009 `TransferWithAuthorization`): the payee, bound as `payment` together with the amount and the asset.
- **An EIP-7702 delegation:** the delegate contract, which would gain full control of the account.
- **A message:** the addresses and hosts it names, or else the signer itself.

**The decision:**

| Result | What happens |
|---|---|
| `allow`, verified and bound | The key signs. |
| `warn` | The key signs only if `onWarn` returns true. Without `onWarn`, the signature is refused. |
| `block` | Refused: `X402CheckBlockedError`, with `verdict.reasons`. |
| Anything else: no credits (402), network error, timeout, `checked: false`, a signature that does not verify, or an attestation bound to another request (`request_hash`) | Refused (`not_verified`). **A missing check never means yes.** |
| Danger the decoder proves locally (e.g. a `delegatecall`) | Refused before any call. |
| `sign({ hash })`, an opaque 32-byte value | Refused unless `allowRawHashSigning: true`. Some smart-account flows need it, and with it those signatures go unchecked. |

- **Payments to x402check's own `pay_to` are not checked** (`trustedPayees`), so paying for a check never recurses.
- **Pay for the checks from prepaid credits.** Do not use a per-call payer that signs with the guarded account.

**x402 buyers that do not wrap the account** can use the client hook instead. It checks the payee before the payment is created, and aborts it otherwise:

```ts
const client = new x402Client();
client.register("eip155:*", new ExactEvmScheme(signer));
client.onBeforePaymentCreation(x402PaymentGuard({ creditToken: process.env.X402CHECK_CREDIT_TOKEN }));
```

**Limits:**
- The guard enforces what the checks detect. A plain transfer to a brand-new, unlisted drainer wallet still passes, unless our kit watch has already recorded that wallet.
- It protects against a misled agent, not against code that reaches the key another way. For that, custody-level enforcement (a co-signer) is planned.
- EVM only for now. Solana signers are next.

## The fail-closed policy (`interpret`)

| Input | Action |
|---|---|
| `tier: "low"` | `allow` |
| `tier: "medium"` | `warn` |
| `tier: "high"` or `"critical"` | `block` |
| a sanctions listing, known scam address, known phishing domain, known drainer code, or a simulated overpayment to a named payee (`outflow_exceeds_declared`), whatever the tier | `block` |
| a check that did not fully run (`onchain_unavailable`, `simulation_unavailable`, `simulation_incomplete`) or `unverified_contract` on a `low` tier | at least `warn`, never an unremarked `allow` |
| `checked: false` (the `reason` is stated: `invalid_subject`, `model_unavailable`, …) | `not_verified` |
| a 402: the call was not paid, or the payment failed | `not_verified`, `code: "payment_required"`, `next`: configure an x402 payer |
| any thrown error: 402, 422, 413, 503, network error, timeout | `not_verified` |
| a malformed verdict, or one past `expires_at` | `not_verified` |
| `options.verification` given and not `valid` | `not_verified` |
| `options.verification` valid, but the body's `tier`, `score` or `categories` differ from the signed claims | `not_verified` |

"Not verified" is never an all-clear. A clean verdict means *none of the checks fired*, not that the counterparty is safe. The published limits are in [docs/EVIDENCE.md](https://github.com/caiovicentino/jev-risk-check-provider/blob/main/docs/EVIDENCE.md). For example, an unknown drainer that is simply sent funds is not detectable from its address alone.

Caller-asserted fields (`screening`, `authorization`) are recorded in the attestation as `asserted` and **never lower risk**. Do not treat them as evidence.

## Verifying an attestation

A relying party, such as a merchant, facilitator or auditor, verifies the `jws` it was handed. Verification pins the **issuer**:

1. The key is resolved from `https://x402check.xyz/.well-known/did.json`, the `did:web` document.
2. The key must be referenced by `assertionMethod`, and the document's `id` must equal the issuer.
3. The token's `jwks_url` and any `jku`, `jwk` or `x5u` header are **never** used.

```ts
import { verifyAttestation } from "@x402check/client";

const v = await verifyAttestation(jws, {
  aud: "https://api.merchant.example/resource", // require this audience
  sub: payTo,                                   // require this subject
});
if (!v.valid) throw new Error(`attestation rejected: ${v.failures.join(", ")}`);
v.claims.tier;   // "low" | "medium" | "high" | "critical"
v.claims.checks; // what the provider verified (sanctions, domain, on-chain, feeds, simulation, model)
v.claims.jti;    // unique id of this verdict
```

The verifier checks the following:

- `alg` is `ES256`. `none`, `HS256` and every other algorithm are rejected before any key is fetched.
- `typ` is `risk-check+jwt`.
- The signature is valid over the 64-byte P1363 signature, using WebCrypto.
- `kid` is in `assertionMethod`.
- `iss` equals the issuer.
- `exp` is still in the future, with no leeway. `iat` and `nbf` may be at most 5 minutes ahead.
- `aud` and `sub` match, when given.

Subjects are compared with the provider's rules:

- EVM, bech32 and cashaddr are case-insensitive. A CAIP-10 prefix and `bitcoincash:` are stripped.
- Base58 (Solana, Tron, BTC legacy) is **case-sensitive**.

`sameSubject(a, b)` exposes the same comparison.

`verifyAttestation` never throws. It returns `{ valid, failures, claims, header, issuer, verificationMethod? }`. The `claims` field is the decoded payload and is **untrusted unless `valid` is true**. The failure codes are:

| Code | Meaning |
|---|---|
| `missing_attestation` | there is no `jws` to verify |
| `malformed_jws` | the input is not a well-formed compact JWS |
| `alg_not_es256` | the header algorithm is not `ES256` |
| `unexpected_typ` | the header `typ` is not `risk-check+jwt` |
| `unsupported_header` | the header uses `crit` or `b64` |
| `missing_kid` | the header has no `kid` |
| `unsupported_issuer` | the expected issuer is not a `did:web` DID |
| `did_resolution_failed` | the DID document could not be fetched or parsed |
| `did_document_id_mismatch` | the DID document's `id` is not the issuer |
| `unknown_kid` | no verification method in the DID document matches `kid` |
| `kid_not_in_assertion_method` | the key exists but is not referenced by `assertionMethod` |
| `unsupported_key` | the key is not a usable EC P-256 signing key |
| `webcrypto_unavailable` | `crypto.subtle` is missing in this runtime |
| `signature_invalid` | the signature does not verify |
| `issuer_mismatch` | `iss` is not the expected issuer |
| `missing_exp` / `expired` | `exp` is absent, or has passed |
| `missing_iat` / `iat_in_future` | `iat` is absent, or more than 5 minutes ahead |
| `not_yet_valid` | `nbf` is more than 5 minutes ahead |
| `invalid_claims` | `sub`, `score` or `tier` is missing or of the wrong type |
| `audience_mismatch` | `aud` does not match the required audience |
| `subject_mismatch` | `sub` is not the required subject |
| `invalid_time` | the `now` option is not a valid time |

### Binding to the request you made

When you verify a check **you just made**, pass the request as well. Anything between you and the API could otherwise strip the fields that raise risk, such as the domain or the transaction, and relay a genuine, fresh verdict for the weaker request. It could also replay an older attestation for the same address, such as a low verdict for a plain transfer presented for a permit.

```ts
const v = await verifyAttestation(result.jws, { request, maxAgeSeconds: 300 });
```

`request` is the object you passed to `check()`, or the item for a batch. It is bound in two ways:

- **`request_hash` (v0.3 providers).** The provider signs a SHA-256 over the RFC 8785 canonical JSON of the request fields exactly as it received them. The client recomputes it with WebCrypto over the JSON round-trip of your request, which is what traveled. Every field is then bound, `context` and `interaction.unlimited` included: an intermediary that strips the injected content before forwarding is caught (`request_mismatch`). An older provider that does not sign the claim skips this check; `requestHash(request)` computes the value.
- **Structural bindings (always).** `request` binds the wallet (`sub`), `aud`, the `interaction` type and `payment`. It also binds the analyzed domain (`checks.domain.host`), the chain whose on-chain facts were used (`checks.onchain.network`), and whether a transaction was simulated (`checks.simulation`). A field absent from the request must be absent from the claims.

Two exceptions apply to the structural bindings:

- `payment.network` and `chain` aliases are normalized like the API does (`toCaip2`). An alias this client does not know is not compared.
- A deterministic sanctions verdict (`checks.model: "skipped"`) simulates nothing, so a missing simulation is accepted there.

`maxAgeSeconds` rejects attestations issued earlier than that. The 5-minute skew allowance is added on top.

The same bindings are available one by one: `sub`, `aud` (`null` means none allowed), `interaction` (`null` means none allowed) and `payment` (`null` means none allowed). They add these failure codes:

| Code | Meaning |
|---|---|
| `interaction_mismatch` | the `interaction` claim is not the expected one |
| `payment_mismatch` | the `payment` claim does not carry the expected payment fields |
| `domain_mismatch` | the signed domain is not the request's domain |
| `chain_mismatch` | the signed on-chain network is not the request's chain |
| `transaction_mismatch` | a transaction was sent but nothing was simulated, or the reverse |
| `request_mismatch` | the signed `request_hash` is not the hash of the request you sent: a field was altered or dropped |
| `stale` | issued longer ago than `maxAgeSeconds` plus the skew allowance |

Always pass the verification to `interpret(result, { verification })`. The response body is unsigned, so a body that disagrees with its signed claims is treated as `not_verified`.

### Displaying evidence

The signature does not cover `evidence`. Before you show evidence to a user, or to a model that may follow instructions it reads, pass it through `normalizeEvidence(result.evidence)`. Every value must match the format the provider emits (digits, addresses, enums, dates, hostnames, identifiers), and anything else is dropped, so free text planted in an evidence field never reaches the display. `interpret()` already does this for its `reasons`, and strips control, bidi, zero-width and tag characters (`sanitizeText`).

DID documents are cached in memory for 5 minutes, per `fetch` implementation. Concurrent verifications share one request, and failures are not cached. For key rotation, an unknown `kid` refreshes a cached document at most once every 30 seconds; `clearDidCache()` drops everything. Pass `issuer` to verify attestations from another `did:web` provider.

## API

### `createClient(options?)`

| Option | Default | |
|---|---|---|
| `baseUrl` | `https://x402check.xyz` | API origin |
| `fetch` | `globalThis.fetch` | any fetch-compatible function |
| `timeoutMs` | `10000` | per request, body included; it also bounds a `fetch` that ignores `AbortSignal` |

The client has four methods. Each also accepts `{ signal }` as a last argument.

- **`check(request)`** resolves to a `RiskCheckResult`, possibly `checked: false`.
- **`checkBatch(requests)`** resolves to `RiskCheckResult[]` in request order. A batch takes at most 25 requests, and validation is all-or-nothing.
- **`checkWithInfo(request)`** and **`checkBatchWithInfo(requests)`** also return `info`: `{ status, paymentResponse }`. `paymentResponse` is the decoded x402 settlement receipt (`{ success, transaction, network, payer }`) of a paid call.

A request has the following fields. `wallet` is required.

| Field | Content |
|---|---|
| `wallet` | EVM `0x…`, base58, bech32, cashaddr or CAIP-10 |
| `chain` | alias or CAIP-2 |
| `domain` | hostname or URL |
| `context` | at most 4096 characters |
| `aud` | at most 256 characters |
| `interaction` | `{ type, unlimited? }` |
| `payment` | `{ network, pay_to, amount (base units), asset, resource }` |
| `transaction` | `{ from, to?, value?, data? }`, EVM only (v0.3) |
| `screening`, `authorization` | caller assertions, recorded as `asserted`; they never lower risk |

A `RiskCheckResult` has these fields:

- `checked`, `score` (0–100, higher is safer), `tier`, `categories`;
- `reason`, with `checked: false`: `invalid_subject`, `model_unconfigured`, `model_malformed_answers` or `model_unavailable`;
- `jws`, `provider`, `checked_at`, `expires_at`;
- `evidence`:
  - `sanctions`, `domain`, `onchain` (including `verified` and `code` for contracts) and `feeds`;
  - `simulation`: `{ status, network, outflows, inflows, approvals, findings, code_matches, code_checked, forwarder_verified, limits }`;
  - `model`.

Simulation findings include:

- `outflow_to_undisclosed_eoa`, the hidden recipient. Through a source-verified forwarder (`forwarder_verified`), such as a bridge, it is a review item.
- `outflow_exceeds_declared`: a named payee gets a different asset, or more.
- `outflow_to_unverified_contract`, `approval_to_eoa`, `unlimited_approval` and `known_drainer_code`.
- `simulation_incomplete`, with `limits` saying why. It is never read as clear.

Simulation runs on Ethereum, Base, Polygon, Arbitrum, Optimism and BSC.

In the simulation evidence, an outflow's `counterparty` is the **final beneficiary**. An inflow's `counterparty` is the called contract. An `ApprovalGrant.standard` of `"erc721"` is a single-token approval, and its `amount` carries the token id.

### Errors: `X402CheckError`

| `code` | `status` | Fields |
|---|---|---|
| `invalid_request` | 422 | `field`; `index` for a batch |
| `payment_required` | 402 | `paymentRequired`, the decoded x402 `PAYMENT-REQUIRED` challenge with `accepts`; `paymentError` after a failed settlement |
| `too_large` | 413 | body over 64 KiB, or more than 25 batch items |
| `evaluation_unavailable` | 503 | `retryAfter` |
| `http_error` | other | `retryAfter` when present |
| `invalid_response` | 200 | the body is not a well-formed result |
| `network_error`, `timeout`, `aborted` | 0 | `cause` |

### Other exports

- `interpret(resultOrError, { verification?, now? })` returns `{ action, reasons, tier?, score? }`. With `not_verified` it adds `code` (e.g. `payment_required`) and `next`, the step to take.
- `describeCategory(category)` and `describeFailureReason(reason)` return human-readable text.
- `requestHash(request)`, `canonicalJson(value)` and `REQUEST_HASH_FIELDS` compute the signed `request_hash`, identical to the provider's.
- `sameSubject(a, b)` and `parseSubject(address)` implement the canonical address rules.
- `toCaip2(chain)` and `normalizeHost(domain)` mirror the API's input normalization.
- `normalizeEvidence(evidence)`, `sanitizeText(text)` and `isSafeId(id)` prepare response data for display.
- `INTERACTION_TYPES` and `RISK_TIERS` are the enumerations, and every wire type is exported.

## Paying (x402)

Every evaluation is paid; there is no free tier. There are two ways:

- **Prepaid credits (cheapest, fastest):** `buyCredits(amountUsd)` pays once via x402, for a pack of $0.10 to $100. It returns a token (`x402c_…`, shown once).
  - With `createClient({ creditToken })`, every check costs **$0.001**, or $0.005 when a transaction is simulated. It is debited from the balance with no 402 round trip and no on-chain settlement.
  - `info.credits` gives each call's charge and the balance left. An empty balance rejects with `code: "insufficient_credits"`, and a check that produces no verdict is refunded.
- **Per call:** the payment network's price: Base $0.0035, Solana $0.002, Sei $0.002, Avalanche $0.001, Monad $0.001, Polygon $0.007, Arbitrum $0.009. A simulated item costs $0.005, or the network's price if higher. A batch of *n* costs *n* items.

```ts
const { token } = await createClient({ fetch: wrapFetchWithPayment(fetch, payer) }).buyCredits(1); // $1.00, one settlement
const x402check = createClient({ creditToken: token }); // keep the token secret
const { result, info } = await x402check.checkWithInfo({ wallet: "0x…", chain: "base" });
info.credits; // { chargedUsd: "$0.001", balanceUsd: "$0.999" }
```

Without payment, the API answers `402`, and the client rejects with an `X402CheckError`: `code: "payment_required"`, with the decoded challenge in `paymentRequired.accepts`. `interpret()` turns that into `not_verified` with the next step to configure a payer.

The client stays dependency-free and takes any fetch. To pay, pass an x402-paying fetch from the x402 SDK:

```bash
npm install @x402/fetch@2.27 @x402/evm@2.27 viem
```

```ts
import { createClient } from "@x402check/client";
import { wrapFetchWithPayment, x402Client } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

const payer = new x402Client()
  .register("eip155:*", new ExactEvmScheme(privateKeyToAccount(process.env.PAYER_KEY as `0x${string}`)))
  .setSpendControls({ maxAmountPerPayment: "$1" }); // a credit pack, or refuse anything above $1 per call

const x402check = createClient({ fetch: wrapFetchWithPayment(fetch, payer), timeoutMs: 30_000 });
const { result, info } = await x402check.checkWithInfo({ wallet: "0x…", chain: "base" });
info.paymentResponse; // { success: true, transaction: "0x…", network: "eip155:8453", payer: "0x…" }
```

Things to know:

- **The payment is gasless for the payer.** The x402 "exact" scheme signs a USDC transfer authorization (EIP-3009), and the facilitator settles it on-chain.
- **Use a dedicated wallet with a small USDC balance.** The key signs payments without asking; spend controls cap each payment, not the total.
- **Settlement happens before release.** The provider releases the result only after settlement, which is why a paid call needs a longer `timeoutMs`.
- **Other networks work the same way.** For Solana, register `ExactSvmScheme` from `@x402/svm` for `solana:*` instead.

## Browsers

The client itself sends only `Content-Type` and `Accept`. An x402-paying fetch adds `PAYMENT-SIGNATURE`, which the API allows cross-origin and whose `PAYMENT-RESPONSE` receipt it exposes. The client never reads `jwks_url`.

In browsers, `retryAfter` on a 503 is currently always `undefined`, because the API does not expose `Retry-After` to cross-origin callers. Retry with your own backoff.

## Development

```bash
npm ci
npm run build      # tsc → dist/ (ESM + .d.ts)
npm test           # node --test via tsx: mocked fetch, real ES256 signatures made with WebCrypto
npm run typecheck  # sources and tests
```

MIT © Caio Vicentino
