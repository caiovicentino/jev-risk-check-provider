# Changelog

Each release's full notes and evidence are on the [releases page](https://github.com/caiovicentino/jev-risk-check-provider/releases). Measurements are in [docs/EVIDENCE.md](docs/EVIDENCE.md), and every verdict rule is in [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## Unreleased

- **The MCP's lockfile:** zod 4.6.7 (GHSA-mrhx-c7xc-m3w5), body-parser 2.4.0 (GHSA-27r3-jxmh-p828) and fast-uri 3.1.9. The published 0.3.3 pins the earlier versions in its shrinkwrap. Over stdio the server never starts the SDK's express server, and every input it validates is size-bounded.
- **The Worker's lockfile:** zod 4.6.7.
- **Development tooling:** the root `overrides` hold undici at 7.30.1 (GHSA-xjj6-f33q-929c, high). Before this, miniflare, wrangler's local runtime, pinned 7.29.1. The Snap's tooling moves to fast-uri 3.1.9 and body-parser 2.4.0.
- **CI:** the production dependency audit is `scripts/audit-gate.mjs`. It fails on any high or critical finding, except an advisory accepted for exact install paths with a reason and a review date. That covers the zod 3 copies that `@x402/core` and `@x402/evm` require, since no zod 3 release fixes this advisory.
- **The audit gate, hardened (2026-10-25 review):**
  - It audits even when run through a symlinked path: its main-module guard compares real paths. Before, it exited 0 without auditing.
  - An acceptance names the versions installed at its paths, read from the lockfile.
  - A moderate or low advisory never needs an acceptance, even on an accepted path.
  - A cycle among covered packages passes.
  - It runs `npm audit --offline=false` (2026-10-26 review): an offline npm returns an empty report with no error.
  - It reads only npm's report format 2 (2026-10-27 review). A report in any other format, such as a future npm's, has no `vulnerabilities` to read; before, the gate passed it.

## v0.6.21 — 2026-10-31: forwarding verdicts from before v0.6.0 follow its rule

The 2026-10-31 maintenance run investigated a new coverage hole on Base: 713 authorizations, in one 20-second segment at 19:15 UTC on 2026-10-30. About 10,400 EIP-7702 authorizations arrived in 25 blocks, to three delegates. What it found is larger than the hole.

- **Old forwarding verdicts flagged every account on large code.** Since v0.6.0, forwarding seen on one account generalizes to every account on the same delegate only when the delegate is a small forwarder (at most 1,024 bytes of code): a proxy or a larger contract can forward for one account and not for others. Verdicts reached before that rule recorded no code, and the scan kept flagging every account that delegated to them. A learned family from that time did the same on sight, and at evaluation time it matched any wallet delegated to its code.
  - Production held 84 such verdicts, of 104 forwarder verdicts in all: 44 on Ethereum and 40 on Base. Their code, read on 2026-10-31: 79 are larger than 1,024 bytes (75 logic contracts, 2 proxies, 2 NFT contracts), and 5 are small forwarders. The commit message says 104 by mistake.
  - In a sample of 3,000 watch entries, 805 of the 1,104 `forwarding_delegation` entries came from those verdicts. One of the delegates in the 2026-10-30 flood was one of them (6,027 bytes), with 4,000 authorizations.
  - **In production (deployed 2026-10-31, commit `349e044`):** the first cron runs settled all 84. 79 became "not forwarding" (41 on Ethereum, 38 on Base), and 44 of the 45 learned families now carry their code, 14 of which generalize. A new sample of 2,875 entries holds 1,051 forwarding entries: 728 no longer count, 320 do (their delegate generalizes), and 3 are probed accounts' own.
  - Such an entry capped a verdict at 40 (`auto_forwarding_wallet`) for a wallet the rule says nothing about.
- **The fix:**
  - Each cron run settles up to 50 such verdicts by reading the delegate's code. A small forwarder keeps its verdict, now with its code recorded. Any other code becomes "not forwarding" and is re-probed as usual, so a probe that sees forwarding flags only the probed account. An unreadable delegate keeps its old verdict, which flags no one.
  - The scan settles one the same way when its authorizations appear. A forwarder family is known on sight only for code that the rule covers; other code is probed like any new delegate.
  - At evaluation time, a forwarding entry recorded for every account on a delegate counts only while that delegate's verdict generalizes. Nothing is deleted: entries from verdicts settled as "not forwarding" stop counting. The probed account's own entry (`fwd-acct-`) always counts.
  - Learned families record their code. Older families take it from a settled verdict on logic code, and until then they match no one by code. The wallet's delegate verdict is still consulted then.
  - What this gives up: the one to three accounts an old probe actually saw forwarding were never recorded apart from the rest, so they stop counting too. Each settled delegate is re-probed after six hours, as usual, and a probe that sees an account forward records that account's own entry.
- **The review of this release** found four issues, each fixed before its deploy:
  - The probed account's own entry was never written over an old shared one of the same rank, so a re-probe that saw an account forward could leave it unflagged. Now the account's own entry replaces a shared one, and so does an entry from another delegate (an account delegates to one at a time).
  - A read of no code, a 7702 designator or a malformed answer could settle a verdict and give a family the wrong code. Deployed code cannot vanish (EIP-6780), so such a read waits for another.
  - New entries could be invisible for up to six minutes, until an isolate's cached copy of the verdicts expired. A verdict missing from a copy more than a minute old is now read again.
  - A failed read of the verdicts failed the whole lookup. Now the entries are kept, as before this release.
- **Fewer holes in floods.** A delegate already judged "not forwarding", whose re-probe is due but can flag only the probed account, now keeps only the four authorizations the probe reads. Before, its authorizations counted against the per-scan bound of 5,000. In the 2026-10-30 flood, one such delegate had 3,201 authorizations.

## `@x402check/mcp` 0.3.3 — 2026-10-23 (on npm; tag `mcp-v0.3.3`)

These changes follow the security releases of 2026-10-21: Node.js 22.23.4, 24.22.1 and 26.12.1, Brotli 1.2.1, and, on 2026-10-15, undici 6.29.1.

`x402check_pay` fetches resources from servers it does not know, in the process that holds the payer key. Three changes protect that fetch:
- **Brotli from a resource is never decoded (CVE-2026-111497, high).** The Brotli decoder writes out of bounds on a crafted stream, which permits remote code execution. Node.js bundles that decoder before 22.23.4, 24.22.1 and 26.12.1, and fetch runs it on any response marked `Content-Encoding: br`.
  - The resource fetch now asks for gzip or deflate only. A response in any other coding is refused from its headers, before fetch creates a decoder: `refused`, `unrequested_encoding`, nothing paid.
  - A response to the paid request in such a coding is not read either. Its receipt goes unread with it, so the outcome is `failed` and `payment_unconfirmed`, and the message says why.
  - This holds on any Node.js version, for the resources this server fetches itself. Two things are not covered:
    - a custom `fetch` (`ServerConfig.fetch`, for embedding), which must refuse such codings itself;
    - x402check's own API and DID document, fetched with Node.js's fetch over TLS from x402check.xyz. These are decoded as the installed Node.js decodes them, so run a patched release.
  - Tests:
    - `test/net.test.ts` runs a real server answering in br, a mixed coding and zstd, and counts the Brotli decoders fetch creates: none;
    - `test/pay-security.test.ts` runs both cases end to end;
    - an independent review tried obs-fold, duplicate headers, 1xx and 101, redirects, connection reuse and smuggled responses, and found no bypass.
- **undici 6.29.0 → 6.29.1.** A malicious server could crash the process in two ways: more than five content codings with the connection closed early (CVE-2026-109869, high), or a TLS 1.2 renegotiation to another certificate (CVE-2026-87018, high).
  - The DNS pinning that keeps resource connections on public addresses is not affected by CVE-2026-109383, the TLS options undici's `Agent` dropped: the pinning passes its `lookup` through `connect`, which kept it.
- **Node.js 22 or later** (`engines`). Node.js 20 reached its end of life on 2026-04-30 and gets no security releases. The README asks for the line's latest security release.

The lockfile also moves `ip-address` to 10.7.4, used through the MCP SDK's `express-rate-limit`. 10.7.2 was open to a moderate denial of service, a quadratic match of IPv6 zone identifiers.

## `@x402check/client` 0.5.3 and `@x402check/mcp` 0.3.2 — 2026-10-18 (on npm; tags `client-v0.5.3`, `mcp-v0.3.2`; client 0.5.0 deprecated with a security notice)

0.5.1 and 0.5.2 were never published: their fixes ship in 0.5.3, with the follow-ups of the review's third and fourth rounds.

Daily maintenance reviews found these, and all are fixed here:
- the review of 0.5.0 (2026-10-17): two critical issues in the client, three high, one medium and several low (`packages/client/test/guard-0617.test.ts`, `solana-custodian-signers.test.ts`, `solana-nonce-signers.test.ts`, `solana-legit-flows.test.ts`);
- the review of this release itself, before its publish (2026-10-18, four rounds): two high, three medium and four low (`guard-0618.test.ts`), then the follow-ups below (`guard-052.test.ts`, `guard-053.test.ts`).

Client 0.5.0 and older should not be used.

**Client (signing guard), the review's fourth round (2026-10-18): Across read on every chain it serves:**
- **Low: Across deposits whose tokens the decoders did not both know.** A deposit's two amounts were compared only when the decoders' token registry knew both tokens under one symbol. Otherwise it got a warning, so a deposit that paid out 1 unit was signed with a stub provider, and the relayer that fills it keeps the input. Two cases did this: a destination missing from the registry (WETH from Base to WETH on Linea), and an output token with another symbol (USDC to USDT). The fixes:
  - The registry now holds the tokens Across routes on each chain it serves: 52 entries. 19 chains are new to it: Linea, zkSync Era, Unichain, Blast, Scroll, World Chain, Ink, Mode, Zora, Lisk, Soneium, Monad, Lens, HyperEVM, Tempo, MegaETH, Robinhood Chain, Arc and Plasma. Optimism gains its bridged USDC, BNB Chain its ETH, and Base USDbC and USDT.
  - The addresses come from Across (`@across-protocol/constants` 3.1.129 and its live routes API). Each was read on-chain through a free public RPC: the chain id, the code, `symbol()` and `decimals()`. `snap/src/util.ts` names the RPC used for each chain.
  - US-dollar stablecoins (USDC and its bridged forms, USDT and USDT0, DAI, Blast's USDB) are compared at $1 each, and WETH and bridged ETH 1:1, with decimals normalized. A deposit that pays out less than half is refused (`local_danger`). Across's fees are under 1%, so legitimate deposits sign, including those with mixed decimals (BNB Chain's USDC and USDT have 18).
  - Two known tokens of different assets (WETH to USDC) are never priced, and their warning now says so. In production, the simulation reads every Across deposit as `cross_chain`, a review, so such a deposit is signed only if `onWarn` approves.
  - Tokens still outside the registry keep the warning: WBTC, Across's USDG, pathUSD and USDH, and Tron.
- **Low: Across speed-ups signed off-chain.** Across's SpokePool takes the depositor's EIP-712 signature of `UpdateDepositDetails` (`speedUpV3Deposit`, `speedUpDeposit`, `fillRelayWithUpdatedDeposit`; domain `ACROSS-V2` `1.0.0`). That signature rewrites what a pending deposit pays on the other chain and to whom, but does not name the deposit's input. A new amount of 1 wei to a clean recipient therefore hands the deposit to whoever fills it. The guard read it as a plain message and signed it: the address form after checking only the recipient, and the bytes32 form after checking only the signer. The typed-data decoder now recognizes the type and refuses it as unreadable (`opaque_signature`) in both forms of the SpokePool:
  - `UpdateDepositDetails(uint32 depositId,uint256 originChainId,uint256 updatedOutputAmount,address updatedRecipient,bytes updatedMessage)` (`UPDATE_V3_DEPOSIT_DETAILS_HASH`, contracts v3.0.0);
  - `UpdateDepositDetails(uint256 depositId,uint256 originChainId,uint256 updatedOutputAmount,bytes32 updatedRecipient,bytes updatedMessage)` (`UPDATE_BYTES32_DEPOSIT_DETAILS_HASH`, contracts v4.1.5 and master). The deployed SpokePools on Ethereum, Base and Arbitrum return its hash.
  - Note: the registry also feeds the order economics (Permit2 and UniswapX orders, Seaport, ERC-20 orders). There, an order that pays out less than $1 of a known stablecoin, or less than 0.001 of a known ETH, is "only dust" (`local_danger`), and that now holds for the newly known tokens as it already held for USDC. An order selling 100 units of a token for 0.50 USDT on Base was signed by 0.5.2 and is refused by 0.5.3. Larger amounts are unaffected.

**Client (signing guard), the review's third round (2026-10-18):**
- **Four more bridges whose recipient on the other chain is only in calldata.** The guard checked only the bridge contract, so a transfer through one of them to an attacker on the other chain was signed on the bridge's check alone (since v0.6.20 the Worker's simulation reads them as `cross_chain`, a review). Their recipients there, refund recipients included, are now read and checked along with the bridge:
  - Polygon's unified bridge (zkEVM, Agglayer): `bridgeAsset` and `bridgeMessage`. The `permitData` of `bridgeAsset` is a permit the bridge uses on this chain, so it is not unread. The metadata of `bridgeMessage` is run by its recipient on the other chain, so it is.
  - Celer cBridge: `send` and `sendNative`.
  - Gnosis Chain: the OmniBridge's `relayTokens(token, receiver, value)` and `relayTokensAndCall`, its WETH router's two `wrapAndRelayTokens`, and the xDAI bridge's `relayTokens(receiver, amount)`. That last selector is also the OmniBridge's `relayTokens(token, value)`, which pays the sender itself. Its first word is checked either way: at worst a token is checked for nothing, and a receiver is never left unchecked.
  - zkSync Era: the Bridgehub's `requestL2TransactionDirect`, whose one argument is a tuple, and the Era diamond's legacy `requestL2Transaction`. Their refund recipient receives what the deposit leaves over on L2, or all of it when the L2 call fails. Calldata or factory dependencies (code deployed on L2) make the request unread. `requestL2TransactionTwoBridges` is unread as a whole, because its recipient is inside the calldata it hands a second bridge.
  - Each selector was computed with viem's `toFunctionSelector` from the canonical signature, and each was found in the deployed code: the dispatcher of each bridge's implementation on Ethereum, the OmniBridge's on Gnosis Chain too, and the zkSync Era diamond's `facetAddress`.
- **Across: what a deposit pays on the other chain.** The decoder read who receives an Across deposit, but not how much. A deposit to the signer that paid out 1 wei was signed, and the relayer that fills such a deposit is repaid all of it. `depositV3`, `depositV3Now`, `deposit` and `depositNow` now show both amounts in the summary:
  - A deposit that pays out nothing for a nonzero input is refused before any check (`local_danger`).
  - When both tokens are in the decoders' registry with the same symbol, the amounts are compared after scaling by each chain's decimals (USDC and USDT have 18 on BNB Chain). A deposit that pays out less than half of its input is refused (`local_danger`). Across's fees are far below half, so a legitimate deposit is not refused.
  - Otherwise, a warning names both amounts.
- **A bridge selector sent to the signer's own account** was read as a bridge transfer and signed on its recipient's check. The account runs its own code there, not a bridge's, so the call is now read like any other call to the account. At the top level it is refused as `unreadable_self_call`.

**Client (signing guard), before the publish (2026-10-18 review):**
- **High: a string field given as bytes.** viem signs a string-typed field given as a `Uint8Array`, a byte array or a bigint as its bytes, which is the same hash as the text. The guard read it as no address, so a Hyperliquid `usdSend` to an attacker written that way was signed. A string field given as anything but a string now makes the request malformed (`malformed`). A string longer than the decoders read is unread.
- **High: bridges other than the OP Stack's withdrawals.** A deposit from Ethereum to an L2 (the OP Stack's L1StandardBridge and OptimismPortal, Arbitrum's Inbox and gateway routers) or a transfer through Across or Circle CCTP names its recipient on the other chain only in calldata, so only the bridge was checked.
  - Their recipients, refund addresses included, are now read and checked, along with the bridge.
  - A recipient that is not an EVM address, or calldata or a deployment run on the other chain, makes the request unread.
  - The Worker reads any transfer through a bridge or message layer it knows as incomplete (v0.6.19).
- **Medium: a serializer that rewrites the transaction it is handed** passed the read-back. viem hands the serializer the very object it signs, and the read-back compared against that same object. It now compares against a copy taken before the call.
- **Medium: a serializer that returns a native promise with its own `then`** passed the read-back too. The checked bytes went to the check while the `then` gave viem a drain to sign. Found by the review's second round. What the promise resolves to is now awaited and verified, and only that value reaches viem.
- **Medium (a regression in the unpublished 0.5.1): viem before 2.37.11 hashes a serializer's return value without awaiting it.** With those versions, the read-back made every transaction fail on chains that have their own serializer (Base, OP, Celo, zkSync). A synchronous serializer now stays synchronous, and a thenable is adopted as a native promise.
- **Low:**
  - A Permit2 witness payee was exempt from its check when the order named it as its swapper, as an address or now as a string. Only the signing account is exempt, and outputs paid to another swapper no longer count as the signer's.
  - Generic typed data checked its verifying contract only when the message named no other address, so a memo holding a clean address spared a flagged verifying contract. The verifying contract is now always checked.
  - A Multicall3 selector sent with no value did not name the contract called, which can be any contract answering that selector. It is now checked.
  - A list of more than 64 numbers in generic typed data was read as unread content. Only content that can hold calldata is marked unread past the reading limits.
  - A string longer than 2048 characters is read as before, and an address padded with whitespace past that point is still read as the payee.
  - `scripts/publish-npm.sh` resumes with the MCP when the client is already on the registry.

**Client (signing guard), from the review of 0.5.0 (2026-10-17):**
- **Critical: Solana authorities are judged as the programs judge them.** The Stake program checks a withdrawal's or an authority change's signature against every signer it collects, the lockup custodian's slot included, and the System program accepts a nonce authority's signature from any account of the instruction. The guard looked at one position: with the victim's key in the custodian slot (or anywhere in a nonce instruction), a stake withdrawal to an attacker or the hand-over of a stake or nonce authority was signed unchecked. The signer's presence now counts, in both Stake layouts.
- **Critical: a typed-data number written as `true` or `[1]`** (viem hashes it as 1) was read as missing, which disarmed the local rules (a SafeTx `operation: true` was read as a CALL and signed as a DELEGATECALL). A field the decoders cannot read as its declared type now makes the request malformed (`malformed`), and so does a fixed-size bytes field they cannot read.
- **High: withdrawals to L1.** A withdrawal through Arbitrum's ArbSys behind Multicall3 was signed with only Multicall3 checked: Multicall3 batches (aggregate, aggregate3, aggregate3Value and relatives) are now decoded call by call. A withdrawal through the OP Stack's L2StandardBridge or L2ToL1MessagePasser on Base names its L1 recipient only in calldata: that recipient is now read and checked.
- **High: typed data read only in part.** The search for calldata payloads stopped at 10 levels and at the 64th item of a list, silently: content past those limits now makes the request unreadable. A payee written as a string field (Hyperliquid's `usdSend`, `withdraw3`) is now checked.
- **Medium: a serializer passed with the call is read back.** The bytes a viem account signs are what its serializer writes, so a caller's serializer could sign a transaction the guard never saw. Its unsigned output must now be the transaction that was checked (legacy, EIP-2930 or EIP-1559), or nothing is signed; the OP Stack's serializer on Base passes.
- **Low:** list fields must be arrays (an `authorizationList` given as a `Set` slipped past the EIP-7702 rule); viem's `sendTransactionSync` and `eth_fillTransaction` options (`timeout`, `_capabilities`) are dropped like `account` and `chain`; a transaction that names no counterparty is refused as `no_counterparty`, not `not_simulated`; a domain with no declared `EIP712Domain` is typed exactly as viem types it, so a `chainId` written as a string is not read as a chain viem never signs.

**MCP:**
- **A payment counts as accepted only on a receipt that says `success: true`.** A 2xx with no receipt, an unreadable one, or one that says anything else is reported as unconfirmed (`payment_unconfirmed`), and no new authorization goes to that payee and site until the earlier one expires (up to 15 minutes).
- **Concurrent calls to one payee and site:** the second is refused before it buys an x402check check, instead of after.
- **Publishing:** `check-publish --tarball` refuses any tarball entry that is not a regular file (a symlink or hard link named like a module), and `scripts/publish-npm.sh` reads the tarball's name from `npm pack --json` and resolves the client from the registry when it pins the tree.

## v0.6.20 — 2026-10-18: a verdict paid for reaches its payer on a resend

Since v0.6.18, a client that leaves during its evaluation is charged, because its verdict was produced. That closed the free-evaluation loop. But an honest client that times out paid for a verdict it never received, and a resend of the same payment was refused: 409, or 402 from the facilitator, whose verify sees the nonce already used. The 2026-10-18 review suggested keeping that verdict.

- **The verdict is kept.** It is stored with the payment's claim for a day (up to 100 KB). The same payment resent for the same request (same route, same body) receives it as it was produced, with `X-Payment-Delivery: resent` and its settlement receipt. Nothing is evaluated or charged again, and the settlement record then says `delivered: "resent"`.
- **No cost on other paths.** The kept verdict is looked up only for a payment that was refused or already used, never on the way of a new one. Any other request with that payment is refused as before.
- **The review of this release** found four low issues, fixed before its deploy:
  - A resend that arrives while the abandoned check still runs gets `409 payment_in_progress` with `Retry-After: 5`, not "sign a new one", which would charge the client twice.
  - The kept verdict also comes back past an authorization about to expire or a busy payer.
  - Past the facilitator's refusal the payer is screened again, and the record says `delivered: "resent_unverified"`.
  - A client that leaves while its settlement is recorded is caught too, so its verdict is kept.
- **Credit purchases are unchanged.** A new credit token lost the same way is not kept, because that would store the token itself; it stays the owner's to make right.
- **`eval/disconnect.ts`** now expects one payment to buy one verdict that reaches the payer, whenever the client leaves.
- **More bridges read as incomplete.** The review's second round found four more bridges whose simulation came back clear: Polygon's unified bridge, Celer cBridge, Gnosis Chain's AMB (OmniBridge) and zkSync Era's Bridgehub. Their events now also make it `cross_chain`, each confirmed in live logs. The list cannot be complete: a bridge the simulation does not know is still read as an ordinary contract.

## v0.6.19 — 2026-10-18: a transfer to another chain is never read as clear

The 2026-10-18 maintenance review found that the rule from v0.6.18 covered only withdrawals from an L2 to L1. A deposit from Ethereum to an L2, or a transfer to someone else through a third-party bridge, came back from the simulation `ok` with no finding: the funds sink into the bridge, and the recipient on the other chain is never visible to the simulation. Now any event from a bridge or message layer the simulation knows makes the simulation incomplete (`cross_chain`, review):
- deposits from Ethereum through the OP Stack's portal and Arbitrum's bridge;
- Across, Circle CCTP (v1 and v2), LayerZero, Wormhole, Hyperlane, Linea, Scroll, Polygon PoS and Starknet.

Events are matched whichever contract emits them, and each was confirmed in live logs on Ethereum or Base. A bridge the simulation does not know is still read as an ordinary contract (`docs/METHODOLOGY.md`). The signing guard (client 0.5.3) reads and checks the recipients of the bridges its decoders know.

## v0.6.18 — 2026-10-17: a produced verdict is paid, and withdrawals to L1 are never read as clear

The daily maintenance run's review of v0.6.17 and of the SDK fixes found one medium issue in the Worker and one high issue that the provider shares with the SDK; both are fixed here (`test/payments-hardening.test.ts`, `test/simulation.test.ts`).
- **Medium: an abandoned check was still free.** v0.6.17 counted an abandoned evaluation against the payer, but released the payment: up to 8 in flight before the hold was read, a 25-item batch counting once, and the same authorization reusable. That came to about 300 item evaluations an hour per wallet holding a batch's price that never moved. A client gone during its evaluation is now charged like one that stayed: the verdict was produced, the payment settles, and the settlement is recorded `undelivered`. A client gone before its check starts is still not evaluated and not charged. An honest client whose timeouts used to count as refusals is no longer held back.
- **High: a withdrawal to L1 looked clear in the simulation.** Value sent to L1 through Arbitrum's ArbSys or the OP Stack's messenger, bridge or message passer leaves for an address the simulation never sees, also when another contract (Multicall3) makes the call. An event from one of these contracts now makes the simulation incomplete (`l1_withdrawal`: at least a review, never a clear result).

## v0.6.17 — 2026-10-16: an abandoned check is never a free one

The daily maintenance run's independent review of v0.6.15 and v0.6.16 found one high issue and five low ones; all are fixed here (`test/payments-hardening.test.ts`, `test/discovery-routes.test.ts`, `test/review-1016-prod.test.ts`, `test/fresh-feeds-coldwait.test.ts`).

- **High: an abandoned check was a free evaluation, without limit.** v0.6.16 finished every abandoned request's work and then let the payment be used again: a per-call client that disconnected during its evaluation got its claim released with nothing counted, and a credits caller got its debit back. One signed authorization, or a $0.10 pack, could be abandoned again and again, each time costing an evaluation (a 25-item batch: 25 model calls) and paying nothing. The client never received a verdict, so it was an attack on cost and availability, not a free service. Now:
  - **per call:** a client gone during its evaluation is still not charged, and the payment can be sent again, but it counts against the payer like a refused settlement: after 5 in an hour, the payer is held back (`429`);
  - **credits:** once the verdict is produced it is charged, even if the caller left;
  - **both:** a client already gone when its check would start costs nothing and is not evaluated (`499`).
- **A per-call payment that settles after its client left** is recorded `undelivered`, like a credit pack, and the daily check lists it.
- **Discovery follows the challenge's fallback:** with every facilitator down on a new isolate, the 402 offers every network not known to lose money, and `/.well-known/risk-check.json` listed none. It now lists what the 402 offers, and an isolate that only serves discovery refreshes its routing table in the background.
- **`/status` no longer ends a new isolate's wait for current lists:** when its own wait ran out, the paid checks after it stopped waiting.
- **Every bounded text field counts characters** (`payment.resource`, `domain`, `authorization.source`), as the published schemas do; v0.6.15 had done it for `context` and `aud` only.
- **`eval/disconnect.ts --credits`** sends the probe credits' token to production only.

## `@x402check/client` 0.5.0 and `@x402check/mcp` 0.3.1 — 2026-10-16 (on npm; tags `client-v0.5.0`, `mcp-v0.3.1`; client 0.4.0 and older are deprecated with a security notice)

The SDK and MCP review of 2026-10-16 found eight issues (three high: a contract creation with value signed unchecked, counterparties past the third left unchecked, and Solana lamports checked against a fresh address instead of the account's controller; one medium; four low); all are fixed here, each with a regression test that fails without its fix (`packages/client/test/guard-review.test.ts`, `solana-review.test.ts`, `packages/mcp/test/payer-review.test.ts`, `snap/test/unit/truncation.test.ts`).

**The daily maintenance review (2026-10-16),** a second independent look before publishing, found two critical issues, four high, four medium and four low. Most predate this release and are in the published client 0.4.0 too; all are fixed here (`packages/client/test/guard-maintenance.test.ts`, `solana-stake-v5.test.ts`, and the C1 block of `guard-review.test.ts`):
- **Critical: a drainer's permit plus one junk type was signed unchecked.** A typed-data type nothing references is not part of the signature (viem ignores it), but the decoders called the whole request malformed and the guard found "nothing to check". The decoders now read only the types the signature hashes, and the guard never signs a request they call malformed (`malformed`).
- **Critical: Solana stake instructions in the Stake v5 layouts** (SIMD-0490, on mainnet since 2026-06-18: the sysvar accounts are optional) were read with the old positions: a v5 `Authorize` or `AuthorizeChecked` handing the withdraw authority away, a v5 `Withdraw` to an attacker, or a v5 `InitializeChecked` naming an attacker's withdrawer was signed unchecked. Both layouts are read now, as the program tells them apart, and an authority the program accepts from any signer is judged by the signer's presence.
- **High:** a chain's own serializer could sign fields the guard never read (only the standard serializer's fields are accepted now; viem's attached `account` and `chain` objects are dropped, which also fixes `walletClient.sendTransaction`, refused before as uncopyable); typed data past the reading budget (an order hidden at the end of a Seaport bulk listing) was signed with a warning (now unreadable); a call to a precompile or system contract (Arbitrum's ArbSys withdrawing ETH to an L1 address) inside a Safe transaction was signed with nothing checked; generic typed data checked only its first address, and a zkSync-style transaction signed as typed data checked none.
- **Medium and low:** the fee cap now uses the larger of `maxFeePerGas` and `gasPrice`; a transaction that moves value or calls code but names no checkable counterparty is not signed; a type-4 transaction's delegations, which the simulation does not apply, are refused; SPL `InitializeAccount2/3` and `InitializeMintCloseAuthority` are read as the token program reads them (extra bytes ignored).
- **MCP:** the no-second-authorization rule could be bypassed (another path or network for the same payee, parallel calls, a success receipt saying `success: false`): it now keys on the payee and the resource's origin, is recorded before signing, and is cleared only by an accepted payment; a response that does not accept a sent payment (a 3xx, a 2xx whose receipt says `success: false`) is reported as unconfirmed (`payment_unconfirmed`), never as paid; the published tarball now carries its `npm-shrinkwrap.json`, and `check-publish --tarball` verifies the packed tarball itself (lockfile v3, every entry resolved to its own registry tarball with a sha512 integrity, no unexpected install scripts). `scripts/publish-npm.sh` follows the same steps.

**Client (signing guard):**
- **What is checked is what is signed.** The EVM guard normalizes a transaction as viem serializes it, and that copy is checked and signed:
  - `to` absent, `""` or `"0x"` is a contract creation, so a creation that carries value is refused however it is spelled;
  - amounts are read with BigInt semantics and signed as bigints, and `input` is signed as `data`;
  - a missing `chainId` takes `options.chainId`, never a legacy signature valid on every chain;
  - anything viem would read differently is refused (`invalid_transaction`);
  - `maxFeeWei` applies to the signed copy, blob gas included.
- **Every counterparty is checked, or nothing is signed:** in batches of 25, up to 50 (more is `too_many_counterparties`). A batch the decoders do not read in full is refused as opaque: MultiSend, multicall, ERC-7579 or `executeBatch` past 32 calls or with leftover bytes, Universal Router plans, a Seaport bulk listing past 64 orders.
- **A transaction is signed on its simulation.** Its verified attestation must say `checks.simulation.status: "ok"`. A simulated revert is not verified (`simulation_reverted`): what it would do is unknown, and a drain can be written to revert in simulation and succeed on-chain. Anything else is `not_simulated`. **This changes behaviour:** a transaction with a counterparty on a chain the provider does not simulate (Avalanche, Monad, Sei, any EVM chain but Ethereum, Base, Polygon, Arbitrum, Optimism and BSC) is no longer signed. x402 payments signed as typed data are unaffected.
- **Solana: SOL is checked against whoever controls the account it funds.** For an account the transaction creates or assigns, that is the stake withdrawer, the token-account owner, the nonce authority or the seed base, and otherwise the owner program, checked as a contract call. Refused as not verified: uninitialized stake or token accounts, mints or multisigs funded beyond rent, and Vote, loader, lookup-table and Config accounts. Refused locally: a stake lockup under another custodian, and `AllocateWithSeed` of a signer-derived account.
- **Typed data:** an unrecognized struct that grants a spender, delegatee or operator an amount (Aave's `DelegationWithSig`, for one) is checked as a permit, unlimited from 2^255.
- **API:** `GuardCheck.claims`; the decoders keep every candidate; `buildRiskCheckBodies(decoded, origin, limit)`.
- **Not changed (known limits):** a Solana transfer to an existing program-owned account is checked by the account's address; generic typed data with no known role field checks only its first address.

**MCP:**
- **x402check's own checks are paid only to x402check's `pay_to`, at most $0.01 each** (`untrusted_check_payee`, `over_check_price`), so a hijacked API origin cannot collect more; `PayerOptions.checkPayees` and `maxCheckPaymentUsd` override it.
- **No second authorization while one can settle:** `x402check_pay` signs nothing new to a payee for a resource while an earlier authorization the resource did not accept can still be settled (`authorization_outstanding`).
- **Build:** `@x402/core` is pinned at 2.28.0, and the published package carries an `npm-shrinkwrap.json` that pins its whole installed tree from the registry (the server holds a payer key). `scripts/check-publish.mjs` builds the package and refuses a tarball holding anything but `package.json`, `README.md`, `LICENSE`, the shrinkwrap and a `dist/` built from `src/`, or a shrinkwrap with a package not pinned to the registry with an integrity hash.

**Prepared on 2026-10-02:**
- **The guard exempts payments to x402check only in USDC (client, security review F5):** the trusted-payee cap (250000 atomic units, $0.25 of USDC) applied to any asset; for an 8-decimal token it was not $0.25. Only the asset x402check's challenge asks for on each network (`X402CHECK_PAYMENT_ASSETS`) is exempt now.
- **Chain ids as the provider accepts them (client):** `toCaip2` returns null for a namespace or cluster the provider refuses (`solana:mainnet`, `foo:bar`), so the trust provider leaves such a chain out instead of failing the check.
- **Sellers can screen the payer before settling (client):** `x402checkTrustProvider()` implements a provider for the proposed x402 trust-provider extension (x402-foundation/x402#2300). It maps a verified, request-bound verdict on the payer's wallet to PASS / FAIL / UNCERTAIN, never PASS for anything it cannot verify, and returns the attestation as `evidence_uri`. A check that did not complete reports why (`not_checked:<reason>`).
- **Freshness anchors in the types (client):** `checks.sanctions.digest`, `checks.kit_watch` (`complete_through`, `gaps`) and `checks.simulation.at_block`, signed since provider 0.6.1; all optional, older attestations still verify.
- **`x402check_verify_attestation` and check results show the anchors (MCP):** the OFAC release digest and the per-chain block maps, each value only in its expected format.

## v0.6.16 — 2026-10-16: a client that leaves never strands its payment

A paid production probe of v0.6.15 (`eval/disconnect.ts`) abandoned a paid request 1.5 s after it left. The resend of the same payment got `409 payment_already_used`, and nothing had been charged. The runtime cancels whatever a request has not handed to `waitUntil`. Admission ran before the hand-off, so a client gone during it left its payment claimed for a day: no money moved, but the signed payment could not be used. Abandoned after 300 ms, during the payment's verification, the same probe passed.

- **Per call:** admission (the payer's slot and the payment's claim) now runs inside the work handed to `waitUntil`, so a claim taken is always released or marked settled.
- **Credits:** the debit runs inside it too, and a caller gone before the verdict is ready gets the debit back (499), as a per-call payment is not settled.
- **Buying credits:** a buyer gone before settlement is not charged (499) and can send the same payment again. Before, the pack settled and its new token reached nobody. A buyer who leaves during the settlement itself still loses the new token, since the money has moved by then. The settlement record marks it `undelivered`, and the daily check lists it for the owner.
- **Each 499 is logged** (`client left before settlement`, `client left before its verdict`, `buyer left before settlement`), so Workers Logs show how often clients leave.

## v0.6.15 — 2026-10-16: the production reviews

Three independent reviews ran overnight: payments, a black-box run against production (nothing paid), and operations with the docs. They found one medium issue in payments, one in the feeds workflow, and several low ones. All are fixed here; `test/review-1016-prod.test.ts`, `test/payments-hardening.test.ts` and `test/feeds-guard.test.ts` keep them fixed.

- **Medium: every Cloudflare Worker shared one rate-limit bucket.** A request from a Worker on another zone reaches us from one Cloudflare address, so one such caller could use up the limit of every other. The limiters now count a client by its address, an IPv6 client by its /64, and another zone's Worker by the zone Cloudflare names in `CF-Worker`.
- **Medium: the feeds guard could miss a delisting.** It compared the OFAC address sets only when the count and date checks had passed. A day with a large MetaMask change and one OFAC delisting printed only the MetaMask reason, and a person who overrode it signed the delisting unseen. Every check now runs and every reason is printed. The override also never signs a malformed build: a new manifest with a missing field, or a snapshot that is not the one its manifest names, fails even with it.
- **A client that disconnects before settlement is not charged.** The check is evaluated, and if the client is gone by then, nothing is settled (499) and the same payment can be sent again. Once settlement starts, it runs to completion and is recorded, even if the client leaves (`waitUntil`, and the `enable_request_signal` flag).
- **Routes and discovery agree.** A facilitator whose per-settlement fee could not be read is no longer offered at an unknown cost (`reason: "fee_unknown"`): a new isolate during a PayAI pricing outage had offered Avalanche at a loss. `/.well-known/risk-check.json` lists only the networks the 402 challenge offers; on a new isolate it waits up to 2 s for the first routing table.
- **Request bodies mean one thing.** A body that is not valid UTF-8, or one that repeats a key within an object, is refused (422, or the 402's `request_error` when unpaid). Text lengths count code points, as the published JSON Schema `maxLength` does, so an emoji counts once.
- **Smaller fixes:**
  - an unpaid challenge reuses a Solana blockhash for 15 s instead of asking the public RPC on every request;
  - a known resource asked with the wrong method gets 405 with `Allow`, not 404;
  - `/status` waits for a new isolate's current lists, as a paid check does, so it reports what a verdict would use;
  - `/status` → `scamsniffer.as_of_source` says whether the lists were read at the upstream commit or, when GitHub's API did not answer, at `main` (also logged);
  - `scripts/deploy.sh` names its configuration (`--config wrangler.toml`): an ignored `wrangler.json` or `.wrangler/deploy/config.json` redirect can no longer choose what is deployed;
  - the daily check sends the probe credits' token only to production.
- **Docs:** twenty statements that had drifted from the code were corrected (limits, logs, queue sizes, counts, prices, latencies); the site's pricing names the simulated price as "$0.005 or the network's price if higher".

## v0.6.14 — 2026-10-16: the provider core's review

An independent review of the provider core found two high, three medium and three low issues. Each was reproduced in process and is fixed here; `test/review-1016-core.test.ts` keeps them fixed.

- **High: a listed site hidden by a lenient spelling of its URL.** `https:/evil.com/pay`, `https:\\evil.com`, `http:/\evil.com` and `http:evil.com` all reach `evil.com` in browsers and in `fetch`. Our normalizer read them as the host `https`, so a domain on the MetaMask list came out clear (low, 100). The Worker and the SDK (`@x402check/client`) now parse any http(s) URL first, as browsers do, and treat other schemes (`ftp:`, `javascript:`) as no site.
- **High: verification caps an attacker could fill with decoys.**
  - Simulation checked the source verification of only the three sinks with the largest raw amounts. Anyone can emit a Transfer of a made-up token with any amount, so decoys took every slot. Up to 8 sinks are now checked, known value first, and more is `simulation_incomplete`.
  - Only the first two simulated spenders were checked. Now up to 6 are, in any order, and more is `contract_verification_unavailable`.
  - The kit watch read 16 of the up to 41 counterparties a simulation names, and signed the rest as clear. It now reads up to 100 in one KV operation and refuses more.
- **Medium: `payment` fields that skipped or bypassed checks.**
  - `payment.network` named the verdict's chain without the family check `chain` has, so an EVM wallet "paid on Solana" skipped the chain-keyed checks.
  - A `payment.pay_to` other than `wallet` was signed into the attestation but never screened.

  Both are now refused (422). The SDK already sent `pay_to` equal to `wallet`.
- **Medium: a community list that could not be read raised no floor.** When the ScamSniffer sets failed to load from KV, the verdict said "unavailable" and still came out low. An applicable list that cannot be read is now `feeds_unavailable`, at least medium (review). That means a domain list when a domain was given, and an address list for an EVM subject.
- **Low:**
  - A kit-watch hit no longer also carries the community lists' `known_scam_address` category.
  - The watch signs the coverage clock of every watched chain, Polygon and other chains included, since their EOA entries apply everywhere.
  - The model is told that caller assertions (`screening`, `pre_authorized`) never raise trust, as docs/METHODOLOGY.md always said. Before, it was told that a structured pre-authorization made urgency or a larger amount normal.

## v0.6.13 — 2026-10-16: fixes from the overnight review

An independent review of v0.6.5–v0.6.12 found one medium issue and five low ones; all are fixed here.

- **The MetaMask list from KV could be taken back (medium).** A new isolate's network refresh copied the feeds state before its downloads and wrote that copy back afterwards. When the KV read applied the list in between, the copy erased it, and the isolate fell back to the list embedded at deploy for up to an hour. A stale CDN manifest could do the same to a newer list from KV. The refresh now builds its result from the state as it is when it writes, and a list only moves forward (`test/fresh-feeds-metamask-race.test.ts`).
- **PayAI's fee table survives a failed lookup.** Routing builds its facilitator list anew on every refresh, so v0.6.5's "last table read" fallback never had a table to fall back on. The cache now lives at module scope, per facilitator URL. A failed lookup also makes the routing table retry within a minute instead of ten.
- **More room under the KV limit.** The cron's one invocation also retries queued credits and refreshes ScamSniffer, so the watch's per-run caps are now 450 writes and 400 evaluations on Ethereum, 250 and 200 on Base. The worst case for the invocation is about 870 operations of the 1,000 allowed.
- **A delegate that had no code is classified again.** Its "not a threat" verdict now expires after a day instead of 30, since code can still be deployed at its address with CREATE2. A drainer family deployed at an address that had another verdict replaces that verdict.
- **The Ethereum scan uses more endpoints.** It rotates over BlastAPI, Tenderly, MEV Blocker, 1RPC, Flashbots and MeowRPC. publicnode, which serves evaluations, comes last, and the head is read from the same rotation. The Ethereum endpoints had also been answering the cron with HTTP 429 now and then.
- **The daily check:**
  - re-reads a settlement whose payer could not be read, so an RPC that fails today cannot hide a payment for good;
  - blanks control and bidi characters in text it quotes from others;
  - samples other isolates before calling OFAC stale, not only MetaMask.

## v0.6.12 — 2026-10-16: a facilitator outage no longer breaks the 402 challenge

Two monitors (CarbonMonitor and lumiere's prober) got a 500 from `POST /v1/risk-check/batch` on 2026-10-15. Cloudflare's analytics show both. The cause, reproduced locally: when a facilitator's `/supported` hung, the routing table came late (the stack waits 4 s, each facilitator had 5 s), so the stack was built with every network. x402 then refused to build a challenge that offers a network no reachable facilitator supports. Every unpaid probe and paid request on that isolate got a 500 until the facilitator answered again.

- A facilitator's `/supported` now has 3 s, under the stack's 4 s wait, and a failure is remembered for 30 s. Routing leaves the hung facilitator's networks out, and the stack build reuses that answer instead of waiting again.
- When the routing table is late anyway, the stack uses the last table the isolate computed, not every network. That also keeps a network known to lose money out of the challenge.
- A stack build that fails is routed again once, from fresh answers.
- If the payment stack still cannot build a challenge or read a payment, the answer is `503 payment_unavailable` with `Retry-After: 10` (`/v1/credits` too), never a 500. Nothing is charged.
- `test/stack-resilience.test.ts`: with one facilitator hung, the unpaid challenge is a 402 that lists only the networks the others serve.

## v0.6.11 — 2026-10-16: dependency updates

Dependabot's monthly PRs #22–#24 could not pass CI: their regenerated root lockfile left out `utf-8-validate`, so `npm ci` refused it. The same updates are applied here with a consistent lockfile, at the versions Dependabot proposed (each public for at least 7 days; newer patches published in the last days are not taken).

- Runtime: `@x402/core`, `@x402/evm`, `@x402/fetch` and `@x402/svm` 2.28.0; `viem` 2.57.4; `ai` 7.0.136; `tldts` 7.4.18. The MCP server's pins move with them (`@x402/evm`, `@x402/fetch` 2.28.0, `viem` 2.57.4).
- `@noble/curves` 2.4.0 (it was 1.9.1). The Solana associated-token-account check (`deploy/svm-ata.ts`) now decodes points with `ed25519.Point.fromBytes`. It matched `@solana/spl-token` on 400 random owners and mints across both token programs, and `test/svm-ata.test.ts` pins four of them. curves 2 uses `@noble/hashes` 2.4.0, the version the Worker already pins (viem and `@x402/svm` still bring their own 1.x copies).
- Development: `@types/node` 22.20.5 in the root, the packages and the Snap. CI actions: `actions/setup-node` 7.1.0 and `actions/upload-artifact` 7.0.2 (#21).
- The signing-guard evaluation (`eval/guard.ts`, free) gives the same verdicts as the committed report: 22 of 33 drainer transactions refused, 0 of 84 legitimate ones.

## v0.6.10 — 2026-10-16: current phishing lists on new isolates, and a daily maintenance routine

- **The MetaMask phishing list on new isolates.** The Worker refreshes the published feeds in the background, per isolate. A new isolate checked domains against the list embedded at deploy until its own refresh finished, and with little traffic most checks run on new isolates. On 2026-10-15 that embedded list was 16 days older than the published one (100,604 entries against 106,105). The last verified list is now kept in KV (`feed:metamask:v1`), like OFAC since v0.6.4: a new isolate applies it with one read, re-verified (signature with the pinned key, checksums, entry count, shrink bound), and a paid request on a cold isolate waits for it within the same 2.5 s. `/status` → `data.metamask_phishing.origin` says `kv`, `refreshed` or `embedded`.
- **Daily maintenance** (`docs/MAINTENANCE.md`, `scripts/daily-check.ts`). The lead agent runs a daily routine from a Claude Code session cron:
  - a read-only check of production (against the last run), the unpaid black box, GitHub, the deployed commit, the feeds, money and npm;
  - the four suites, and a review of new code;
  - free evaluations weekly, and the paid suite when the probe payer is funded;
  - fixes within the runbooks.

  The check found the stale MetaMask list on its first run.
- Maintenance runs keep their evaluation reports out of `eval/evidence` (`EVAL_OUT_DIR`). A listing-only Bazaar run (`PAY=none`) no longer overwrites the committed report.

## v0.6.9 — 2026-10-15: no retries into a rate limit

While Base caught up after v0.6.8, every Base endpoint answered some requests with HTTP 429. Each batch still asked every endpoint in turn, including ones that had just refused, which only prolonged their limits.

- An endpoint that answers 429 is not asked for blocks again in the same run.
- When every endpoint is limited, the scan stops at once with the segments it completed, and the next run resumes. A batch is split only after other failures (too large, or cut off by the timeout), not after a rate limit.

## v0.6.8 — 2026-10-15: the Base scan spreads its load

With v0.6.7's diagnostics, the Base failures turned out to be rate limits: from 22:11 UTC all three Base scan endpoints answered the cron with HTTP 429. The scan downloads about 15 GB of Base blocks a day, and Cloudflare's egress is shared. Base's official RPC took that volume first, although it also serves paid evaluations as their fallback.

- The Base scan now spreads its blocks over five public endpoints that serve no evaluation (Tenderly, 1RPC, BlastAPI, MeowRPC, dRPC), starting each batch at the next one, within each endpoint's batch limit. Base's official RPC and publicnode, which serve paid evaluations, are only the last fallback.
- Ethereum's scan alternates between BlastAPI and Tenderly the same way; publicnode stays the last fallback.

## v0.6.7 — 2026-10-15: a slow block fetch no longer stalls a chain

From 21:50 UTC on 2026-10-15 the kit watch's Base scan stopped moving. Every run failed with `blocks … unavailable`: no endpoint answered a 7-block request (about 2.4 MB) within the cron's time budget, although all three answered it in about a second from outside Cloudflare. One failed request discarded the whole run, so the cursor never advanced, and the same request failed again a minute later.

- A batch that no endpoint serves is split in half, down to single blocks, and stays at most that size for the rest of the run. The next run starts at the size that worked.
- A segment whose blocks still cannot be fetched ends the run's scan there. The segments before it are kept (cursor, entries, queue, stats), and the next run resumes with that segment, so nothing is skipped.
- The chain's `error` in `/status` states what each endpoint answered (an HTTP status, a timeout, an incomplete batch), by host name only.

## v0.6.6 — 2026-10-15: the kit watch keeps up with floods of delegations

From 2026-10-03 to 2026-10-15 the kit watch counted about 153,000 holes on Ethereum: every 10-block segment kept at most 1,000 EIP-7702 authorizations and dropped the rest unevaluated. On Base, 7,204 queued items were abandoned: a threat's authorizations past 100 per scan waited in a queue of 500. Much of what a flood carries needs no work: in a sample of 3,000 Ethereum blocks on 2026-10-15, 48% of the 20,653 authorizations went to delegates already judged not a threat, and 43% to one address-poisoning executor. (That run was not saved. `eval/kit-watch-floods.ts` re-measured on 2026-10-16, with the report in `eval/evidence/kit-watch-floods-report.json`: 38.6% settled, 39.1% to the poisoning executor, 22.2% to forwarders; see `docs/EVIDENCE.md` §0.)

- Authorizations to a delegate whose verdict leaves nothing to evaluate (a revocation, or a delegate judged not a threat with no re-probe due) are counted, never kept (`settled_authorizations` in `/status`): they no longer crowd out the rest or become holes. A segment keeps up to 5,000 others.
- A threat's authorizations are evaluated up to a budget per run (450 on Ethereum, 250 on Base), shared by the queue and the new blocks. The rest wait in the queue, in order, instead of being dropped.
- The queue holds 10,000 items and is retried by cost: items whose delegate has since settled at no cost, a threat's authorizations within the budget, and at most 100 reads. An RPC outage cannot make one run retry thousands of reads.
- Current watch entries are read in bulk (100 keys per KV operation), and only a new or stronger one is written: at most 500 a run on Ethereum and 300 on Base, within the invocation's KV limit.
- The holes already counted stay in `gaps` (every hole ever recorded), and `unbroken_since` shows where unbroken coverage restarts.

## v0.6.5 — 2026-10-15: no route at a loss

- **Routing never offers a route that costs more than its price.** On 2026-10-15 PayAI's fee on Avalanche had risen to $0.00574 per settlement against a $0.001 price (a margin of −481%), and Coinbase CDP had begun settling Monad at $0.001 against a $0.001 price (−7% with the model call). Routing ranked a facilitator any wallet can pay through above cost, so both networks were offered at a loss; no payment was made on either. A route known to lose money is now never chosen while another clears its cost, and a network with no such route is not offered:
  - Monad moves to Dexter (free, through Permit2);
  - Avalanche leaves the 402 challenge (its price is below Dexter's $0.0034 floor there) and comes back on its own once a route clears its cost.
- `/status` → `payments` shows `offered` per network and, for one that is not offered, the `reason` (`unprofitable`, `below_floor` or `no_facilitator`).
- A failed PayAI fee lookup reuses the last table read rather than leaving the fee unknown. With every facilitator down, the challenge still never lists a network known to lose money.

Prices are unchanged.

## v0.6.4 — 2026-10-03: the second evaluation

From a second full evaluation on 2026-10-03 (an independent security review of everything in v0.6.2–v0.6.3, a black-box run against production, and an operations review):

- **One scheme payload per payment, the one its route takes (security review H1, high):** a facilitator verifies the EIP-3009 authorization, the Permit2 authorization or the Solana transaction and ignores anything else in the payload, but admission read an `authorization` object first. A decoy one next to a real Permit2 or Solana payment could pass an SDN-listed payer, give one payment many evaluations, or lock another wallet out for an hour. A payment must now carry exactly one of them, matching its route (Solana: `transaction`; a Permit2 route: `permit2Authorization`; any other EVM route: `authorization`), and payer, identity and validity are read from it alone; anything else is a 402 `payment_unrecognized` before any work.
- **The payer screen cannot be skipped by spelling (M1):** an EVM payer is screened lowercase, so a wrong EIP-55 checksum (which a Permit2 facilitator accepts) never turns a listed address into an unscreened one; an unreadable payer is refused.
- **A Solana payment must come from the payer's own token account (L4):** a delegate spending someone else's account would have been screened instead of the owner of the funds. The transfer's source must be the authority's associated token account (derived locally, no RPC).
- **Only the payer's own refusals count against the payer (L3):** insufficient funds, a bad or reused signature or nonce, an expired or premature authorization, a wrong value or recipient, a missing Permit2 allowance. A pending or failed transaction, RPC trouble or an unknown reason never does.
- **The chain must be able to hold the address (black-box):** a CAIP-10 id, `wallet` + `chain`, or `payment.network` + `pay_to` from different families (an EVM address on Solana, a Solana address on Base) was accepted and the chain-keyed checks were silently skipped. It is a 422 now, and the SDK's subject comparison treats two namespaces as different subjects.
- **Strictness:** `transaction.from`/`to` need a valid EIP-55 checksum when mixed-case; `eip155:0` is refused; a string with a lone surrogate is refused (no client could recompute `request_hash`); `payment.amount` must fit in uint256; a batch carries `requests` only.
- **HTTP:** the `Bearer` scheme is case-insensitive (RFC 9110); balance reads are rate-limited; `/status` and `/healthz` answer 405 to other methods; verdicts and balances are `no-store`, the identity documents cacheable for 5 minutes, `/` varies by `Accept`, and a 500 carries the security headers too. A challenge no longer waits on a slow Solana RPC for its blockhash (at most 800 ms), and its `resource` never echoes the query string.
- **Proxy evidence:** USDC's proxy keeps its implementation in the ZeppelinOS slot, which is now read, and text embedded in bytecode is never taken for a linked address.
- **One run at a time, held for the whole run:** the cron now runs from Taipei after the 10-02 deploy, and a run took up to 83 s, so the 30-second lease lapsed mid-run (32 overlapping runs, each overwriting the other's stats, queue and delegates). A run now holds the lease from its start until the stats it writes last record its release (no extra KV write); a run that finds it held skips, and a run that died holds it at most 5 minutes. Each run reads what it needs in one round of KV reads instead of a dozen sequential ones, reads and writes watch entries 50 at a time, and each chain's block batch carries over from its last run.
- **An honest coverage clock:** `checks.kit_watch` signs `unbroken_since` per chain, the first block of the current unbroken coverage (every hole moves it past its block). `gaps` now also counts the 9,884 (Ethereum) and 2,090 (Base) code reads that failed before v0.6.2 and were dropped, never re-read: until now attestations signed `complete_through` with no gaps. Unbroken coverage starts with the first block v0.6.4 scans.
- **Nothing dropped silently:** a delegate the scan could not probe (its probe budget spent, the simulation down) and authorizations past 100 per delegate are queued for a later run instead of being skipped; more than 1,000 authorizations in a 10-block segment, and watch entries the write caps leave out, are counted as gaps; a queued item is counted as recovered only when a run actually evaluated it.
- **A decoy cannot hide a delegation (security review M2):** authorizations were deduplicated by `(r, s)` alone, so a tuple reusing a real authorization's signature values for another delegate, placed first, hid the real delegation. They are now keyed by the whole signed tuple (chain id, delegate, nonce, parity, r, s), in the scan and in the queue.
- **Types and display (client, MCP):** `kit_watch.unbroken_since` in the evidence and attestation types; `x402check_verify_attestation` shows it as a per-chain block number.
- **New isolates screen against a current OFAC list:** a new isolate used the snapshot embedded at deploy until its background refresh landed, and a paid request waited at most 400 ms for it while the refresh fetched MetaMask's 800 KB first, so cold isolates routinely checked against an older OFAC release. The last verified release is now kept in KV (signed manifest, signature and snapshot, re-verified with the pinned key on every load) and applied with one read; the refresh does OFAC before MetaMask and writes KV once per release, only forward; a paid request on a cold isolate waits up to 2.5 s for a current list, then goes ahead on the list it has (the attestation states its date), says so once and stops waiting.
- **The embedded OFAC snapshot follows the published release:** `scripts/sync-embedded-feeds.ts` refreshes `src/data/ofac-sdn.ts` from the `feeds` branch, verified as the Worker verifies it, and `scripts/deploy.sh` refuses to deploy an older snapshot. The embedded list is now the 2026-10-02 release (1,063 addresses).
- **Feeds publish job (security review L2):** only the five expected regular files leave the build artifact, into a fresh directory, and git runs there with no inherited config, `core.fsmonitor` off and hooks disabled (a planted `.git/config` used to run its fsmonitor during `git add -A`, in the job that holds the signing key).
- **The feeds guard refuses any OFAC delisting:** it compared counts only, so a build that dropped one sanctioned address and added a junk one passed. It now diffs the address sets (each snapshot checked against its manifest's SHA-256) and refuses a missing address until a person reviews it and publishes with `override`; it prints counts only.
- **Discovery files:** `/llms.txt` (built from the OpenAPI document, so its prices and fields cannot drift), `/.well-known/x402` (x402scan's compatibility format) and `/sitemap.xml`. The OpenAPI and Bazaar request schemas say `additionalProperties: false`, as the API enforces, and the site states the measured latency (0.7–2 s from credits, 3–6 s per call).
- **Discovery documents:** the request schema is strict like the validator (`additionalProperties: false`, `wallet` up to 160), lists every status the routes return, and no longer says categories always start with the evaluated families (a sanctions hit carries its own alone). Rate limits are documented as approximate (Cloudflare counts per location).

## v0.6.3 — 2026-10-02

- **A credit pack still needs its amount:** v0.6.2 answered `POST /v1/credits` without an amount with the $1 pack's 402. The credit pack is deliberately not a listed Bazaar service, so that challenge carries no discovery schemas, and AgentCash flagged the route (`SCHEMA_INPUT_MISSING`, `SCHEMA_OUTPUT_MISSING`). Without an amount it is a 422 again; the check routes keep answering every unpaid body with their challenge. AgentCash reports 3 paid routes and no warnings, and x402scan re-registered 3 of 3.
- **The first CodeQL findings (code scanning is on since 2026-10-02):** `didWebDocumentUrl` (client) decodes every `%3A` and accepts only a host with at most one numeric port; the OFAC script decodes `&amp;` last; tests escape regex metacharacters fully. Two alerts were false positives and are dismissed with the reason.
- **CI:** `actions/checkout` 7.0.1, `setup-node` 7.0.0, `upload-artifact` 7.0.1 and `download-artifact` 8.0.1 (pins verified against the release tags); a manual feeds run passed the new guard with them. Dependabot skips the majors that need planned migrations (TypeScript 7, undici, `@solana/kit`, the Snap's MetaMask toolchain and Jest).

## v0.6.2 — 2026-10-02: the evaluation release

Deployed from commit `c4a5f33` and checked in production (docs/EVIDENCE.md §7): one payment sent four ways was evaluated and settled once. From a full evaluation on 2026-10-02 (a security review of everything since the 2026-09-30 audit, an operations and cost review, and a black-box run against production):

- **A payment is used once, by what its payer signed (security review F1, high):** the single-use claim was keyed on the payload's JSON spelling, so re-encoding one authorization (key order, hex case, an extra field, base64 padding) made it several payments: each verified and evaluated, and, with a facilitator that confirms duplicates, several verdicts or credit packs for one payment. The claim is now keyed on the payment itself: EIP-3009 network, asset, payer and nonce; Permit2 network, owner and nonce; the Solana message bytes. One settlement transaction also pays for one verdict or pack only, even if a facilitator confirms it twice.
- **Only x402 v2 payments reach verification (F2):** x402 core reads the payment through the adapter, which now hands over only a v2 `PAYMENT-SIGNATURE` (never `X-PAYMENT`). A payload whose payment or payer cannot be identified is refused (402 `payment_unrecognized`) instead of skipping the claim or the payer's screen (a Solana transaction format the decoder does not read yet, such as v1 messages, is refused rather than sold unscreened).
- **Payments that cannot settle are not evaluated (F3):**
  - An authorization must stay valid for 60 s more (it must settle after the evaluation) and for at most 24 hours (the life of its claim): otherwise a 402 before any work.
  - A payer may have 8 payments in flight at once (429 `payer_busy`), and 5 settlement refusals within an hour hold its payments back (429 `payer_settlement_failures`). Our facilitators' own failures (timeouts, unexpected errors) never count against a payer.
  - Every POST to a paid route is rate-limited per IP: unpaid traffic at 60 a minute as before, traffic with a well-formed credential (an x402 v2 payment or a `Bearer x402c_…` token) at 300 a minute (`PAID_LIMITER`). The mere presence of a header no longer skips the limit.
- **A settled credit pack always returns its token (F4):** if the ledger and the retry queue both fail, the response is still a 202 with the token and a reference (the pending credit is logged by the token's hash for reconciliation). Every credit carries a reference, so a retry never credits twice, and settle-then-credit runs to completion if the buyer disconnects.
- **Only public key members are published (F6):** `jwks.json` and `did.json` carry `kty`, `crv`, `x`, `y`, `kid`, `alg` and `use` only. A configured key carrying private material is refused: the current key reports misconfigured, a next key is not published.
- **Strict requests:** an unknown field (`contxt`, `Context`) is a 422 naming it, instead of being dropped with its content unanalysed. A mixed-case EVM address must carry a valid EIP-55 checksum. A chain id must be a known one: an EVM chain id, a known Solana cluster, a Bitcoin-family genesis or TRON (`solana:mainnet` and `foo:bar` are refused).
- **Unpaid, every body gets the challenge:** an unpaid POST to a paid route always answers with the one-item 402 challenge, and a body that would be refused says why in `request_error`. Monitors and catalogs posting placeholder bodies now see a payable endpoint; nothing invalid is ever charged, and with a payment or a token an invalid body is still a 422 before any payment work. `POST /v1/credits` without an amount is the $1 pack (reverted in v0.6.3).
- **Headers:** every response carries CORS and the security headers, 429s and preflights included; a 405 on `/v1/credits` says `Allow: GET, POST`; the site's CSP admits Cloudflare's cookieless analytics beacon.
- **Docs:** the discovery documents state the measured latency (0.7–2 s from credits, about 4 s per call) and that `intent_risk` and `behavioral` are evaluated families present in every verdict.
- `scripts/deploy.sh` installs without dependency install scripts.
- **The kit watch no longer loses code reads (provider):** a read that one endpoint leaves unanswered (a per-item 429, a refused batch) goes to the next, healthiest first, within a bounded number of requests. A read that still fails is queued in KV (one value per chain, at most 500, written at most once a run), retried before new work on later runs, and evaluated with its original block, transaction and time. After a day it is abandoned and counted as a hole.
- **An honest coverage clock (provider):** `checks.kit_watch` signs `pending`, the reads still queued per chain, next to `complete_through`, and `gaps` is now the real count of holes (it was capped at 10). `/status` shows `pending_reads` per chain and marks a chain `degraded` from 50 queued reads.
- **Bounded KV writes and memory in the cron (provider):** watch-entry writes have a daily budget of 25,000 across both chains, its last 5,000 kept for kit contracts and labelled delegations (`/status` → `writes_today`, `dropped_today`). Blocks are fetched in batches sized to about 2 MB of JSON, and each batch's bodies are dropped once processed.
- **Simulation keeps its fallback (provider):** the code reads behind a simulation went to each endpoint as one batch of 10, which dRPC's keyless tier refuses (it takes 3), so on Ethereum and Polygon a primary outage left no working fallback and the simulation came back incomplete (review). Each endpoint now gets only the reads still unanswered, in batches it accepts.
- **Types and display (client, MCP):** `kit_watch.pending` in the attestation and evidence types; `x402check_verify_attestation` shows it, as a per-chain count only.
- **Feeds supply chain (security review F7):**
  - A feed entry must be a bare host. An entry with userinfo, a port, a path, a query or a fragment (`x@coinbase.com`, `coinbase.com:443`) is dropped instead of being reduced to the host it wraps. On the current lists this drops one ScamSniffer entry and no MetaMask entry.
  - The ScamSniffer refresh resolves the upstream commit first and reads both lists at that SHA, so the recorded commit is the data's. When GitHub does not answer, it reads `main` and records the fetch date and no commit.
  - A refresh in which a list grows by more than 50%, or by more than 100,000 domains or 2,000 addresses, is refused like one in which it halves, and logged.
  - Addresses x402check never flags are left out of the community address sets (`src/never-flag.ts`): its own `pay_to`, Permit2 and x402's Permit2 proxies, the asset x402 charges in on each EVM network, and the major tokens the simulator values. The manual build also leaves them out of the code fingerprints.
  - The manual MetaMask and ScamSniffer builds read their lists at the resolved commit too.
  - The feeds workflow refuses to sign a manifest that changed implausibly since the published one (`scripts/feeds-guard.mjs`, plain node, checked out from the run's commit). The bounds: OFAC addresses −5% or +50%, MetaMask entries ±20%, no date going backwards or more than a day ahead, and a published manifest to compare with. A manual run with `override` publishes after review.

## v0.6.1 — 2026-10-01: freshness anchors

Every signed evidence item now carries the freshness anchor of its kind, the shape discussed in x402-foundation/x402#2300 (each evidence kind brings its own clock instead of one watermark for all). All new fields are optional and additive: verifiers keep accepting older attestations.

- **`checks.sanctions.digest`:** the SHA-256 of OFAC's SDN.XML the screen ran against (`sha256:<hex>`), next to its publish date. A relying party can fetch that release, check the digest and recompute the screen. The feeds manifest now carries the digest too (`ofac.xml_sha256`); a refreshed list whose manifest and snapshot disagree on it is refused, and a list without one signs no digest.
- **`checks.kit_watch`:** `as_of` (the scan clock), the status, and `complete_through`, per chain the last block the scan completed (the coverage clock), with `gaps` when outages made it skip ranges. Only aggregates: the watchlist stays private.
- **`checks.simulation.at_block`:** the block whose state the transaction was simulated on, read from the `eth_simulateV1` result (no extra call).
- METHODOLOGY §5 explains what each anchor lets a relying party check, and the fail-closed rule.
- The MCP server shows the new fields in `x402check_verify_attestation` (next MCP release).

## v0.6.0 — 2026-09-30: the audit release

A full multi-agent audit (security, payments, operations, supply chain, evidence) found no critical issue and 11 high ones. This release fixes every finding that code can fix; the rest are owner settings (see the release notes).

- **Payments are single-use.** Each x402 payment is claimed once, after it verifies (a `PaymentClaim` Durable Object per payload): a copy gets 409 `payment_already_used` instead of a second evaluation, settlement or credit token. A claim store that cannot be reached refuses the payment (503, no charge).
- **The payer is screened.** A wallet on the OFAC SDN list gets 403 `payer_sanctioned`, per call and for credit packs.
- **The attestation key is checked at load.** Both secrets must be present, the private key must match the published JWK, and a canary must sign and verify. Otherwise paid routes refuse all work with no charge (503 `attestation_key_unavailable`) and `/healthz` answers 503. A next key can be published ahead of a rotation (`JEV_ATTEST_NEXT_PUBLIC_JWK`), and the discovery document names the live kid.
- **Payments survive a facilitator outage.** `/supported` has 5 s, verify and settle 30 s; a failed stack build is never cached; a network whose facilitator is down leaves the 402 challenge; identity documents and the site never wait for the payment stack. Monad's option says `assetTransferMethod: "permit2"`, the only method its facilitator settles. Only x402 v2 payloads are processed. Solana blockhashes come from publicnode.
- **Credits.** A pack whose ledger write fails after settlement returns its token anyway (202, credited by the cron). The simulation surcharge is refunded when the simulation did not run. A thrown or abandoned evaluation is refunded, even after the client disconnects. The 1 KiB body cap is enforced while streaming.
- **Verdicts.** A drainer's own fake Transfer event, dust of a real asset, or padded logs no longer turn the simulation's drain finding off. Lookups that fail (contract verification, the kit watch, an unknown chain) raise a review floor instead of passing as clear. Chain ids have one spelling. Mixed-case bech32/cashaddr and TRON hex forms are rejected, and XRP addresses are now screened (the one XRP SDN listing was unreachable). Secrets pasted into `context` never reach the model.
- **The kit watch cannot be poisoned** into flagging an arbitrary wallet: forwarding destinations are no longer recorded, a delegation must be in effect, and a failed `eth_getCode` is never cached as benign. One transaction cannot exhaust the KV budget, and `/status` shows a stalled cron as `stale`.
- **The model.** The model id the backend reports is signed in `checks.model_id`. Through the AI Gateway that id is the alias itself (`typesafe-ai/jev`): the gateway exposes no revision to pin. So twice a day the cron runs fixed cases (an injected instruction, a drain request, a configured payment) through the live model; `/status` → `model` shows the result. In production the three cases came back critical, critical and low. The model call has an 8 s total deadline.
- **Feeds.** The cron rebuilds the ScamSniffer domain and address sets twice a day (GPL: runtime KV only, parsed as a stream). `/status` marks the feed stale after 3 days.
- **HTTP.** Plain HTTP is redirected (pages) or refused (API). HSTS, `nosniff` and `Referrer-Policy` on every response; a strict CSP and `frame-ancestors 'none'` on the site; `/.well-known/security.txt` and `SECURITY.md`. Unpaid requests to paid routes and `/status` are rate-limited per IP. Workers Logs are on, and every settlement is recorded for reconciliation.
- **Operations.** `scripts/deploy.sh` deploys only a clean, pushed, CI-green `main` and stamps `/healthz` with the commit. wrangler is pinned. CI bundles the Worker, rebuilds the Snap against its manifest and audits production dependencies; actions are pinned to SHAs with least-privilege tokens; Dependabot is on; the MCP Registry publish waits for green CI and verifies its publisher binary.
- **Evidence hygiene.** Committed reports carry ScamSniffer-only entries as hashes, and tests use synthetic entries. The eval flag parser read `argv[0]` when a flag was absent: pay-guard's "seed 402" sample was drawn with seed 0 (24/25); with seed 402, 25/25 payees are allowed. Historical suites stop before paying against another version. `scripts/verify-attest.ts` binds a verdict to its request, payment and a maximum age, and pins the key. The evidence is restated with clear denominators: the guard refuses 22/25 drainer transactions that move assets (10/11 contracts) and 0/49 legitimate ones that do; the kit watch's 6,831 addresses came from a 24 h backfill, and ScamSniffer's 7-day delay means its lead time is not yet measured.
- **Production evidence (v0.6.0):** single-use payments PASS (three copies of one payment: one verdict, two 409s), `security:v5` 11/11, one real `x402check_pay` payment (to x402check's own `pay_to`, a trusted payee that is not checked).
- Local development moved off ports 8787–8789 (now 8799, and 8800–8802 for the demo).

## `@x402check/client` 0.4.0 — 2026-09-30

- **Attestation keys are pinned** by thumbprint (`X402CHECK_KEY_THUMBPRINTS`, the `pinnedKeys` option of `verifyAttestation` and every guard): a key the DID document serves but the package does not know fails with `key_not_pinned`.
- **The guard fails closed on everything it cannot read, simulate or bind:** `sign({ hash })` and opaque bytes (`raw_hash_signing`), content the decoders mark unreadable (`opaque_signature`), deployments with value and calldata too large to simulate (`not_simulated`), undecoded calls to the signer's own account (`unreadable_self_call`), signatures valid on every chain (`every_chain_authorization`), requests with no chain (`no_chain`), an optional fee cap (`fee_cap`), and signing methods it does not intercept (`unguarded_method`). What it checks is a copy, and the copy is what gets signed.
- **New decoders (from the Snap):** x402 Permit2 payments check the witness payee; limit orders on 1inch, 0x, CoW and UniswapX are priced (selling for nothing or dust, or to another receiver, is refused locally); ERC-4337 user operations, Safe 4337, ERC-2771 forwards and ERC-7739 wrappers are unwrapped; owner, module and upgrade changes of the signer's own account are refused locally.
- **Solana:** Stake-program authority changes, priority-fee drains (`maxSolanaFeeLamports`), MintTo, AssignWithSeed and durable nonces are read; Sign-In With Solana checks the requesting origin.
- Payments to x402check's own `pay_to` skip the check only up to $0.25 (`trustedPayeeMaxAmount`). `createClient` refuses a plain-http `baseUrl` outside localhost. Types carry `model_id`.

## `@x402check/mcp` 0.3.0 — 2026-09-30

- **`x402check_pay` hardened:** MCP cancellation stops a check and never signs afterwards; a 402 body is read with a size and time limit; redirects are refused even through a custom fetch; private and special-use addresses are refused, including through DNS, with connections pinned to the checked addresses; third-party header text is never shown raw; x402check's own `pay_to` skips the check only for the configured API; refusals are classified by the payer's own hooks, never by error text; authorizations longer than 15 minutes are refused, and messages state when one expires.
- `x402check_verify_attestation` shows signed claims only in their expected formats, and binds a verdict to the checked `request` (request_hash) and a `max_age_seconds` when given.
- `X402CHECK_BUDGET_USD` also bounds what the process spends from prepaid credits.
- Attestation keys are pinned in every verification (`X402CHECK_PINNED_KEYS`; the default is the client's pins). Needs `@x402check/client` 0.4.0.

## `@x402check/client` 0.3.0 — 2026-09-30

- **The signing guard covers Solana:** `guardSolanaSigner(signer)` wraps a `@solana/kit` signer (`signTransactions`, `signMessages`, and their modifying and sending variants).
  - **What it reads:** each transaction of a batch is decoded without dependencies (`src/solana.ts`): legacy and v0 messages, with address lookup tables resolved over RPC.
  - **What is checked:**
    - SOL leaving the signer (transfers, account funding, nonce withdrawals, closed token accounts);
    - SPL Token and Token-2022 transfers, checking the **owner** of the receiving token account, from an ATA instruction in the transaction or else from the chain;
    - approvals (the delegate, `unlimited` at `u64::MAX`);
    - any other program handed the signer's account.
  - **Refused locally, without a check:**
    - a System `Assign` of the signer's own account, the owner-change drain;
    - an SPL `SetAuthority` handing a token account's control to someone else;
    - a nonce account's authority handed over;
    - a "message" whose bytes are a transaction.
  - **`not_verified`, never a guess:** an instruction it cannot read, an unresolved lookup table or token-account owner, or more than 5 counterparties.
- **Measured on real inputs** (`eval/solana-guard.ts`, 4/4 right, nothing sent; 1 real x402 payment and 3 cases the eval constructed, so 95% CI 51–100%):
  - a real x402 payment, built by the official x402 SVM client for production's 402, was checked with its payee resolved on mainnet, then signed (1.9 s);
  - the owner-change drain and a transfer disguised as a message were refused locally;
  - an unlimited SPL approval to a fresh wallet was blocked by production (0.6 s).
- 15 new tests, with real `@solana/kit` signers and compiled transactions (a dev dependency only: the client still has no runtime dependencies).

## `@x402check/mcp` 0.2.0 — 2026-09-30

- **`x402check_pay`: the MCP server pays x402 resources, and only after x402check clears the payee.** The agent never holds the key.
  - **Where the check runs:** inside the x402 client's `onBeforePaymentCreation` hook. It checks exactly the option about to be signed (payee, network, asset, amount, the resource's site), with the agent's `context` and the 402's own description. The attestation is verified and bound to that request, so there is no window between the check and the signature.
  - **Decisions:** `allow` signs. `warn` asks the user in the client (MCP elicitation) and signs only on their approval; neither the agent nor a client without elicitation can approve. `block` and `not_verified` sign nothing.
  - **Limits:** one payment per call. `max_usd`, the per-payment cap and the budget apply before any check is bought.
  - **Hardening:**
    - https on public hosts only, redirects not followed, and payment headers cannot be passed in;
    - time limits per request and for the body;
    - the body is capped, stripped of control and format characters, and labelled third-party data;
    - the query string is never sent to x402check.
- **Credits and a wallet together:** checks are paid from credits, and resources from the payer, which has one budget for both.
- **Measured:**
  - **one real payment through the tool** settled on Base in production, to x402check's own `pay_to` (a trusted payee that is not checked, so it proves the payment path only), with no secret in the output;
  - **24/25 payees of real x402 merchants,** sampled from the Coinbase x402 Bazaar, were allowed: 96.0%, 95% CI 80.5–99.3%. The one warning was a model finding on a prediction-market URL. New merchant wallets are not stopped. *(Correction, v0.6.0: a flag-parsing bug drew this sample with seed 0, not the published 402. With seed 402: 25/25.)*

  Details are in `docs/EVIDENCE.md`.
- **Tests:** 61 (16 new), covering every outcome, the user's decision through elicitation, checks paid by the same wallet, limits, time limits, and URL and header refusals.
- **Site:** a news row, and the payer line in the integration example.

## v0.5.5 and `@x402check/client` 0.2.0 — 2026-09-30

- **Signing guard: the check becomes enforced, not advisory.** It lives in `@x402check/client/guard`.
  - **What it wraps:** `guardAccount(account)` sits between an agent and its key. `signTransaction`, `signTypedData` (including x402 EIP-3009 payments, permits and orders), `signMessage` and `signAuthorization` (EIP-7702) are decoded, checked and verified before the key signs.
  - **When it refuses:** `block`; `not_verified` (no credits, network error, timeout, a bad or unbound attestation); a `warn` without `onWarn` approval; locally proven danger; raw hash signing. In every case it throws `X402CheckBlockedError` and nothing is signed.
  - **x402 hook:** `x402PaymentGuard()` is the same check as `onBeforePaymentCreation`, aborting the payment before anything is signed.
- **Decoders shared with the Snap.** They are vendored into the client (`packages/client/src/decode`, from `snap/src` via `scripts/sync-decoders.mjs`), and a test fails on drift. The Snap's types gained `| undefined` on optional fields, a types-only change: the bundle and its shasum are unchanged.
- **Measured on real mainnet transactions,** with the ScamSniffer feed off because the cases come from it:
  - **22/25** drainer transactions that still move assets are refused, 4 more than simulation alone;
  - **0/228** legitimate transactions are refused;
  - in production, from credits, **4/4** decisions agree.

  *(Correction, v0.6.0: 144 of the 228 legitimate transactions revert at the latest block, where the simulation rules cannot fire. The rate that means something is 0/49 among those that move assets (95% CI 0.0–7.3%), and 0/84 among those that execute. Both legitimate cases in the production 4/4 revert.)*

  Details are in `docs/EVIDENCE.md`.
- **Site:** a news row, and the guard in the integration example.

## Packages — 2026-09-30

- **[`@x402check/client`](https://www.npmjs.com/package/@x402check/client) 0.1.0** and **[`@x402check/mcp`](https://www.npmjs.com/package/@x402check/mcp) 0.1.0** are on npm (tags `client-v0.1.0`, `mcp-v0.1.0`).
  - Both were published with the owner's passkey (npm web 2FA).
  - npm held the MCP server in its staged-publishing review, then released it on its own.
- **Tested from npm:**
  - the client installs, exports its API, and gets a 402 from production on an unpaid call;
  - `npx -y @x402check/mcp` answers `initialize` (protocol 2025-06-18) and lists its 3 tools;
  - with no payer configured, a check fails closed (`NOT VERIFIED. STOP`).
- **Official MCP Registry:** listed as `io.github.caiovicentino/x402check` 0.1.0 (active, latest). It was published by the `publish-mcp-registry` workflow through GitHub OIDC; the registry checks the npm package's `mcpName`.

## v0.5.4 — 2026-09-30

- **Listed on x402scan**, the directory the x402 maintainers point projects to. They no longer take community listings in the x402 docs, and closed 8 such PRs.
  - The listing has the 3 paid endpoints, read from our `/openapi.json`, with none failed.
  - Server page: https://www.x402scan.com/server/14680ac3-396d-4174-b07d-9fae9bc74e96
- **`/openapi.json`**, the AgentCash / x402scan discovery convention.
  - Every paid operation declares `x-payment-info`: a USD price range from the live price table, and the x402 protocol.
  - Each operation has its request and response schemas and a 402 response. `info.x-guidance` tells an agent when to call and how to act on the tier.
  - `@agentcash/discovery discover` finds 3 paid routes with no warnings.
- **Discovery probes get the 402.** An unpaid, unauthenticated POST with no body now receives the challenge for one item. x402scan's probe sends no body, and it used to get a 422. A body that is present but invalid still gets a 422 naming the field, and nothing unpaid is evaluated.
- **`/favicon.ico`** (48, 32 and 16 px). The site now uses the new icon, not the old gradient.
- **HEAD is answered like GET, without a body** (RFC 9110). Discovery tools check favicons with HEAD, and HEAD used to get a 404.

## v0.5.3 — 2026-09-30

- **Listed in the x402 Bazaar**, the service catalog Coinbase CDP builds from the payments it settles.
  - **What the routes declare:** the paid routes carry the Bazaar discovery declaration (`deploy/discovery.ts`, the `bazaar` extension of x402 v2): the service name, 5 tags, an icon, the JSON Schema of the body, a callable example and an example result. It goes out in the 402 challenge, every x402 client echoes it with its payment, and CDP catalogs the endpoint when it settles one.
  - **What CDP lists:** `https://x402check.xyz/v1/risk-check` since 14:33 UTC, after one payment settled through CDP, with its price on each of the 7 networks.
  - **Validation:** the declarations pass the official `@x402/extensions` 2.28 validators, and their `info` is identical to what `declareDiscoveryExtension` builds. The package is not bundled: the Worker gains no dependency.
  - **`eval/bazaar.ts`** pays a check and a one-item batch through CDP, proves each payment carried the extension, and scans the ~19k-resource catalog for both endpoints.
- **`/icon.png`:** the service icon catalogs show.
- **A GET on a paid endpoint explains how to call it.** It still returns 405 (`Allow: POST`), now with a valid example request, the prices and links, instead of a bare error. Browsers reached these URLs from the README and the site.
- **Ready to publish to npm and to the official MCP Registry:**
  - `@x402check/mcp` gains `mcpName` (`io.github.caiovicentino/x402check`) and a `server.json` validated by `mcp-publisher`;
  - a GitHub Actions workflow publishes it to the registry through GitHub OIDC;
  - `scripts/publish-npm.sh` publishes both packages. It asks for the owner's 2FA code and swaps the MCP server's `file:` dependency for the published client only while publishing.

## v0.5.2 — 2026-09-30

- **Coinbase CDP is active in production.**
  - Base, Polygon and Arbitrum now settle through CDP. On Base, the per-call margin went from 32% to **69%**.
  - PayAI keeps Avalanche and Sei, and stays the fallback for every EVM network.
- **`/status` → `facilitators` lists the settlement signers each facilitator publishes.** CDP's list needs our key to read, so `/status` is where anyone can check on-chain which facilitator settled a payment.
- **Measured in production** (Worker `08c5a2f6`, `docs/EVIDENCE.md` §7):
  - `security:v5` passed **11/11**;
  - the per-call check and the $0.10 credit pack were both settled by CDP signers, matched against CDP's published list;
  - `eval/security-v5.ts` attributes each settlement through `/status`.
- **Site:** a "v0.5.1" news row; the settlement row names each network's facilitator.

## v0.5.1 — 2026-09-30

- **Coinbase CDP as a facilitator** (`deploy/cdp.ts`), active once the owner's CDP Secret API Key is set as the Worker secrets `CDP_API_KEY_ID` and `CDP_API_KEY_SECRET`.
  - **Authentication:** every call carries the JWT that `@coinbase/x402` would build: ES256 or EdDSA, bound to the endpoint, valid 120 s, with a fresh nonce. It is made with WebCrypto, so the Worker needs no SDK.
  - **Key formats:** the portal's Ed25519 keys, and EC keys in PKCS#8 or SEC1 PEM.
  - **Routing:** CDP costs $0.001 per settlement after 1,000 free a month, against PayAI's gas + 30%. It takes the networks where it is cheapest: Base, Polygon and Arbitrum. On Base, the margin at $0.0035 rises from 32% to 69%.
  - **Fallback:** a key CDP rejects drops it from routing, and PayAI takes those networks back.
  - **`/status` → `facilitators`:** whether each configured facilitator answers, and the mainnets it offers. Only an HTTP status is shown, never a key.
- **Site:**
  - the hero states the kit watch and the prices, and the attestation card matches the current claims;
  - a "what's new" strip;
  - a **live kit-watch counter** built from `/status` aggregates. The watchlist stays private;
  - the integration example buys credits and then checks with the token;
  - a new social preview (`og.png?v=0.5`) with the kit watch and the current prices;
  - the top bar no longer overflows on phones.

## v0.5.0 — 2026-09-30

- **Prepaid credits:**
  - `POST /v1/credits {"amount_usd": 1}` is paid once via x402 ($0.10–$100) and returns a token (`x402c_…`).
  - With `Authorization: Bearer <token>`, every check costs **$0.001** ($0.005 simulated), with no 402 round trip and no on-chain settlement per call.
  - Balances live in a Durable Object (`CreditLedger`), so a debit is atomic and can never overdraw. A settlement credits once, however often its response is replayed. A check that produces no verdict is refunded.
  - `GET /v1/credits` returns the balance.
  - The SDK (`creditToken`, `buyCredits`, `creditBalance`) and the MCP server (`X402CHECK_CREDIT_TOKEN`) support credits.
  - Still no free tier: credits are prepaid.
- **Per-call prices by payment network**, each above the cost of settling it. Base **$0.0035**, Solana $0.002, Sei $0.002, Avalanche $0.001, Monad $0.001, Polygon $0.007, Arbitrum $0.009. A simulated item costs $0.005, or the network's price when that is higher.
- **Fix (economics): the flat $0.001 lost money on EVM networks.** Since 2026-09-21 PayAI bills the receiving merchant gas + 30% per settlement (Base ≈ $0.0023), so a $0.001 check on Base cost us about $0.0014. The earlier "~93% margin" counted only the model call.
- **Facilitator routing by compatibility and cost:**
  - Each network settles through a facilitator that accepts the price and that every payer can pay through. PayAI's EIP-3009 is gasless for any wallet; Dexter's EVM route needs a Permit2 allowance, and our own payer wallet had none.
  - Among those, the router takes the facilitator cheapest to us, from PayAI's live fee table and Dexter's floors.
  - `/status` → `payments` shows each route's facilitator, transfer method, fee and margin.
- The discovery document publishes `amounts_by_network` and the `credits` terms.
- **Measured in production** (Worker `d9030314`, `docs/EVIDENCE.md` §7):
  - `security:v5` **9/9 PASS**: the price table, the routes and margins, a per-call check on Base, a $0.10 pack, checks from credits, refusals;
  - `security:v2` **12/12 PASS**, re-run on v0.5;
  - a per-call check on Base took **2.7 s** end to end (402, payment, evaluation, settlement), and a check from credits **0.64–0.80 s**.

## v0.4.0 — 2026-09-29

- **Kit watch: our own intelligence on drainer infrastructure.** A Worker cron reads every new Ethereum and Base block, once a minute (`src/kit-watch.ts`, `deploy/kit-watch.ts`).
  - **EIP-7702 delegations.** Each delegate is classified once:
    - an **address-poisoning executor** (the "Poisoner" that Wintermute exposed, or any deployment of its template);
    - a **sweeper** that ScamSniffer-listed wallets delegate to;
    - by **behaviour**: 0.01 ETH is sent (simulated) to a wallet that delegates to it, and a delegate that passes it on is a **forwarder**.

    Every wallet that delegates to one of these is recorded, and so is where a forwarder sends what it receives (plain wallets only).
  - **New contracts** are matched against drainer-kit families by exact or **template** fingerprint. The template zeroes immutables and hard-coded addresses, so a redeployment that changes only the operator's wallet is still recognized.
  - **At evaluation time:** the subject, and the recipients, spenders and called contract of a simulated transaction, are checked against the watchlist; the code the subject runs now is checked against the families.
  - **Caps and categories:**
    - look-alike → **20**, `address_poisoning`;
    - wallet delegated to a labelled sweeper → **20**, `compromised_wallet`;
    - kit contract, kit deployer or labelled sweeper destination → **30**, `known_drainer_code` / `drainer_operator`;
    - forwarder with no label (or its destination) → **40**, `auto_forwarding_wallet` / `drainer_operator`.
  - Signed as `x402check-kit-watch@<scan time>:<status>` in `checks.feeds`; details in `evidence.kit_watch`.
- **Backfill (same code as the cron):**
  - **Ethereum, 24 h:** 6,831 addresses flagged, **none of them on ScamSniffer's public list**: 6,232 poisoning look-alikes, 575 wallets delegated to sweepers or forwarders, 24 destinations. Of 1,254 new contracts, 0 matched an old drainer-kit family.
  - **Base, 6 h:** 226 addresses flagged; no poisoner activity. Of 1,712 new contracts, 0 matched an old kit.
  - Poisoner audit: 27 of 37 sampled look-alikes were confirmed by a victim's history (a lower bound). The executor obeys only its operator, so every delegated wallet is operator-controlled anyway.
  - Negative result: template fingerprints recognized no additional listed drainer (40/82 either way).
  - Details and the audit methods are in `docs/EVIDENCE.md` §0.
- **Fix: a false positive in production since v0.3.** Forta labels single deposit addresses of exchange fleets as phishing, because they received phishing proceeds: Luno's deposit forwarder, a Poloniex deposit contract, BitGo's `Forwarder` and the Mist multisig. Their code is the fleet's standard contract, so the v0.3 code set flagged **every deposit address of those fleets** as drainer code (cap 30). The v0.3 figure "0/9,625" came from a corpus that contained none of them.
  - Every code set and kit family now passes a **collision gate** against code in legitimate use (`scripts/legit-corpus.ts`).
  - The four fleets are guarded explicitly.
  - Forta contracts from before 2021 no longer seed a set. All four collisions came from them, and dropping them costs no recall.
  - On held-out legitimate code, before the fix: 16/2,500 on Ethereum. *(Correction, v0.6.0: that figure is the v0.4 kit families before the gate, `kit_families_before_gate` in the report, not the v0.3 production code set.)*
  - After the fix, on a second held-out set: 0 false positives among 1,737 (Ethereum) and 2,935 (Base) contracts. Its only match was a real `SecurityUpdates` drainer on no public list. *(The report records that raw match, 1/1,737; "drainer" is our own review, not an external label.)*
  - The embedded Forta set went from 46 to 27 fingerprints. Confirmed in production: a Luno deposit address and a BitGo forwarder now score low.
- **Fix, found while building the catalog:** the delegates of ScamSniffer-listed EIP-7702 wallets were never fingerprinted. Only the listed addresses' own code was, so a wallet delegated to a known sweeper was not caught by code. 7 sweeper families that forward what they receive now seed the watch.
- **Operations:** the cron needs Workers Paid. It uses about 250 ms of CPU per run, and the Free plan's 10 ms ends in `exceededCpu`; evaluations are unaffected. `limits.cpu_ms` is set in `wrangler.toml`.
- **PayAI shadow (public data):** 7 days of PayAI-settled payments on Base were replayed through the deterministic layers: 3,132 payments, 207 payees and 226 payers, with 0 flagged. Checking every payment would have cost $3.13. The report is `eval/evidence/payai-shadow-report.json`.
- `/status` → `data.kit_watch` reports coverage (lag, gaps) and counts per kind, never addresses. The discovery document lists the `kit_watch` signal.
- The block scan runs on its own RPC endpoints (`SCAN_ENDPOINTS`), so its volume (~20 GB a day) cannot rate-limit a paid evaluation.
- **SDK:** it knows the four new categories and validates `evidence.kit_watch` before display. The labelled kinds block whatever the tier.

## v0.3.2 — 2026-09-29

- **Differentiated pricing.** An evaluation whose transaction is simulated costs $0.005 on every network. Other evaluations stay at $0.001 ($0.002 on Solana).
  - The simulation price applies only when the simulation actually runs: a supported chain, with simulation enabled.
  - A batch is billed per item.
  - The discovery document states both prices (`amount`, `amount_with_transaction`).
- **Validated in production:** the 402 challenges for a simulated item and a mixed batch are checked. Two simulated evaluations settled at 0.005 USDC each on Base.

## v0.3.1 — 2026-09-29

- **Fix: EVM payments were refused.** Dexter publishes gas-cost floors per network, and they were above the $0.001 price on Base, Polygon, Arbitrum and Avalanche. EVM payments now settle through PayAI; Solana and Monad stay on Dexter.
- `/status` → `payments` reports each network's facilitator, its published floor and whether the price clears it.
- Production probe reports record x402 settlement receipts (tx hashes).
- **Paid validation in production:**
  - `prod`: 53/53 correct and 53/53 attestations verified;
  - `security:v2`: 11/11;
  - `security:v3`: 8/8.

## v0.3.0 — 2026-09-29

- **Transaction simulation.** `eth_simulateV1` runs on Ethereum, Base, Polygon, Arbitrum, Optimism and BSC. It reports net asset movements and the approvals granted, and adds these findings:

  | Finding | Cap |
  |---|---|
  | Hidden recipient | 40; 75 with review through a verified forwarder |
  | Payee receives more than declared | 40 |
  | Assets parked in an unverified contract | 55 |
  | Approval to a plain wallet | 55 |
  | Incomplete simulation | 75 with review |

  - **Measured:** 18/25 real drainer interactions that still move assets were flagged, and 0/84 legitimate transactions.
- **Drainer-kit code fingerprints.** Metadata-stripped logic code is compared with contracts listed by Forta (embedded) and ScamSniffer (runtime), following EIP-7702 delegations and proxies.
  - **Measured:** 43/100 listed contracts recognized at creation, with 0 collisions among 9,625 legitimate contracts.
- **Contract verification** (Blockscout, proxy-aware) and **per-chain fallback RPCs**.
- **`request_hash`:** a client-recomputable binding of the exact request.
- **Fail-closed review floors** when on-chain facts or the simulation are unavailable. `checked: false` responses carry a `reason`.
- **Daily OFAC and MetaMask refresh without a redeploy,** from an Ed25519-signed manifest. `GET /status` shows data freshness.
- **No free tier:** every evaluation is paid per call via x402.
- **Packages:** `@x402check/client` (SDK) and `@x402check/mcp` (an MCP server that pays per check). Neither is published to npm yet.
- **Snap 0.3.0:** the simulation UI is kept behind a flag. The Snap cannot pay yet, so this version sends nothing and has no network permission.
- **Review:** all 11 findings of an independent adversarial review are fixed (`test/review-v03.test.ts`).
- **Docs:** `docs/METHODOLOGY.md` is new.

## v0.2.0 — 2026-09-29

- **Rebuild around provider-verified evidence:**
  - OFAC SDN screening, with the same key caught across encodings;
  - MetaMask and ScamSniffer feeds;
  - public-suffix-aware look-alike analysis;
  - the approval-to-plain-wallet rule.
- **Attestation:** `checks` and `asserted` are kept separate; `payment`, `interaction` and `jti` bind the verdict; `input_hash` uses RFC 8785 canonical JSON.
- **Evaluation with external labels and held-out seeds,** replacing the v0.1 numbers measured on self-describing corpora.
- **Snap 0.2.0:** it decodes the real counterparty and interaction type.

## v0.1 — 2026-09-27

- **First x402 `risk-check` provider:** TypeSafe Jev typed questions, ES256 attestations and `did:web:x402check.xyz`.
- **Evaluation corpora:** shadow, scale, red-team and chat-judge benchmark. They were later found to describe their own risk; see v0.2.0.
