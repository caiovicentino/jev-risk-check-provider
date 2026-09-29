/**
 * EIP-712 typed-data decoders. They only ever read the canonical view built by
 * eip712.ts (declared fields, values normalized exactly as MetaMask signs
 * them), so an undeclared decoy key or an exotic encoding cannot change what
 * the Snap reports.
 */
import type { AddressVisit, CanonStruct, CanonValue, Canonical, TypedTypes } from "./eip712";
import {
  baseType,
  canonAddressValue,
  canonBigInt,
  canonicalizeTypedData,
  collectAddressFields,
  fieldType,
  isCanonStruct,
  isStrictHexString,
} from "./eip712";
import { decodeCallAction, dedupe } from "./tx";
import type { Candidate, Decoded, Interaction, Role } from "./util";
import {
  PERMIT2_ADDRESS,
  RANK,
  UNLIMITED_UINT160,
  UNLIMITED_UINT256,
  capText,
  cleanText,
  describeAllowance,
  hasOwn,
  interaction,
  isIgnorableAddress,
  isRecord,
  knownToken,
  nativeAmount,
  normalizeAddress,
  normalizeChainId,
  payment,
  quote,
  selectCandidates,
  tokenAmount,
  tokenLabel,
  unixDate,
  withCandidates,
} from "./util";

/** Typed data given as a JSON string larger than this is not parsed. */
const MAX_JSON = 1024 * 1024;
/** Orders decoded from a bulk-listing tree. */
const MAX_TREE_ORDERS = 64;
/** Tokens treated like native ETH for pricing (Blur Pool). */
const ETH_LIKE = new Set(["0x0000000000a39bb272e79075ade125fd351887ac"]);

type Ctx = {
  canon: Canonical;
  types: TypedTypes;
  method: string;
  signer?: string;
  chain?: string;
  verifyingContract?: string;
  domainName?: string;
  primaryType: string;
  message: CanonStruct;
  warnings: string[];
  danger: string[];
};

// ---------------------------------------------------------------------------
// Small accessors over canonical values
// ---------------------------------------------------------------------------

function declared(ctx: Ctx, struct: string, field: string): string | undefined {
  return fieldType(ctx.types, struct, field);
}

function addr(struct: CanonStruct | null | undefined, field: string): string | undefined {
  return struct ? canonAddressValue(struct[field]) : undefined;
}

function num(struct: CanonStruct | null | undefined, field: string): bigint | undefined {
  return struct ? canonBigInt(struct[field]) : undefined;
}

function structs(value: CanonValue): CanonStruct[] {
  if (Array.isArray(value)) return value.filter((item): item is CanonStruct => isCanonStruct(item));
  return isCanonStruct(value) ? [value] : [];
}

function minOf(a: bigint | undefined, b: bigint | undefined): bigint | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return a < b ? a : b;
}

function maxOf(a: bigint | undefined, b: bigint | undefined): bigint | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return a > b ? a : b;
}

function domainLabel(ctx: Ctx): string {
  const parts = [ctx.domainName ? quote(ctx.domainName, 40) : "unnamed domain"];
  if (ctx.verifyingContract) parts.push(`verifying contract ${ctx.verifyingContract}`);
  return parts.join(", ");
}

/** Is `amount` of `token` ("native" or address) provably almost nothing? */
function isDust(chain: string | undefined, token: string | undefined, amount: bigint): boolean {
  if (token === "native" || (token && ETH_LIKE.has(token))) return amount < 10n ** 15n;
  const info = knownToken(chain, token);
  if (info?.wrappedNative) return amount < 10n ** 15n;
  if (info?.stable) return amount < 10n ** BigInt(info.decimals);
  if (info) return amount < 10n ** BigInt(Math.max(0, info.decimals - 3));
  return amount < 1000n;
}

function isKnownValueToken(chain: string | undefined, token: string | undefined): boolean {
  return token === "native" || (token !== undefined && (ETH_LIKE.has(token) || knownToken(chain, token) !== undefined));
}

function priceText(chain: string | undefined, token: string | undefined, amount: bigint): string {
  if (token === "native" || !token || token === `0x${"0".repeat(40)}` || ETH_LIKE.has(token)) return nativeAmount(amount, chain);
  return tokenAmount(amount, chain, token);
}

function done(
  ctx: Ctx,
  base: Omit<Decoded, "counterparty" | "role" | "reason" | "interaction" | "payment" | "others" | "warnings" | "danger" | "chain"> & {
    interaction?: Interaction;
  },
  candidates: Candidate[],
): Decoded {
  const selected = selectCandidates(candidates, []);
  const primary = selected[0];
  return withCandidates(
    {
      ...base,
      chain: ctx.chain,
      unlimited: base.unlimited ?? primary?.unlimited,
      amountLabel: base.amountLabel ?? primary?.amountLabel,
      warnings: dedupe(ctx.warnings),
      danger: dedupe(ctx.danger),
    },
    selected,
  );
}

function signerFallback(ctx: Ctx, action: string, summary: string, kind: Interaction): Decoded {
  if (!ctx.signer) {
    return withCandidates(
      {
        action,
        chain: ctx.chain,
        summary,
        warnings: dedupe(ctx.warnings),
        danger: dedupe(ctx.danger),
        interaction: kind,
        localNote:
          "The request names no counterparty and the signing account is unknown, so there is nothing to check. Nothing was sent to x402check.",
      },
      [],
    );
  }
  return withCandidates(
    { action, chain: ctx.chain, summary, warnings: dedupe(ctx.warnings), danger: dedupe(ctx.danger) },
    [{ address: ctx.signer, role: "signer", interaction: kind, rank: RANK.signer }],
  );
}

/** A required address could not be decoded: fail closed, do not claim anything. */
function unresolved(ctx: Ctx, action: string, field: string): Decoded {
  const path = `message.${field}`;
  const unsignable = ctx.canon.unsignable.some((entry) => entry.startsWith(path));
  if (unsignable) {
    return withCandidates(
      {
        action,
        chain: ctx.chain,
        summary: `${action} whose "${field}" field is not a valid address, so MetaMask cannot sign it as-is.`,
        warnings: dedupe(ctx.warnings),
        danger: dedupe(ctx.danger),
        localNote: `This signature request is malformed (its "${field}" field is invalid), so it cannot be signed as-is and was not checked.`,
      },
      [],
    );
  }
  ctx.danger.push(`the "${field}" address of this ${action} could not be decoded; do not sign it`);
  return withCandidates(
    {
      action,
      chain: ctx.chain,
      summary: `${action} whose "${field}" address could not be decoded by x402check.`,
      warnings: dedupe(ctx.warnings),
      danger: dedupe(ctx.danger),
      localNote: `x402check could not decode the "${field}" address of this request, so it could not be checked. Do NOT sign it.`,
    },
    [],
  );
}

// ---------------------------------------------------------------------------
// Permits
// ---------------------------------------------------------------------------

function decodePermit(ctx: Ctx): Decoded | undefined {
  if (declared(ctx, "Permit", "spender") !== "address") return undefined;
  const spender = addr(ctx.message, "spender");
  if (!spender) return unresolved(ctx, "permit", "spender");
  const token = ctx.verifyingContract;
  const tokenText = tokenLabel(ctx.chain, token);

  if (declared(ctx, "Permit", "allowed") === "bool") {
    // DAI-style permit. eth-sig-util signs bool as JavaScript truthiness, so
    // only a real `false` (or other falsy value) revokes; a missing or invalid
    // value fails closed as allowed.
    const allowed = ctx.message.allowed !== false;
    const expiry = unixDate(num(ctx.message, "expiry"));
    return done(
      ctx,
      {
        action: allowed ? "DAI-style permit" : "DAI-style permit (revoke)",
        unlimited: allowed,
        amountLabel: allowed ? "UNLIMITED" : "0 (revokes allowance)",
        summary: `DAI-style permit signature (${domainLabel(ctx)}): ${
          allowed ? `grants spender ${spender} an UNLIMITED allowance on ${tokenText}` : `revokes the allowance of spender ${spender}`
        }${expiry ? `, expiry ${expiry}` : ""}.`,
      },
      [
        {
          address: spender,
          role: "spender",
          interaction: allowed ? interaction("permit_signature", true) : interaction("message_signature"),
          rank: allowed ? RANK.unlimitedApproval : RANK.revoke,
          unlimited: allowed,
          ...(allowed ? { payment: payment({ network: ctx.chain, pay_to: spender, amount: ((1n << 256n) - 1n).toString(), asset: token }) } : {}),
        },
      ],
    );
  }

  const valueType = declared(ctx, "Permit", "value");
  if (valueType?.startsWith("uint")) {
    const amount = num(ctx.message, "value");
    const allowance = describeAllowance(amount, UNLIMITED_UINT256, ctx.warnings);
    const deadline = unixDate(num(ctx.message, "deadline"));
    const grantsNothing = amount === 0n;
    return done(
      ctx,
      {
        action: "EIP-2612 permit",
        unlimited: allowance.unlimited,
        amountLabel: allowance.label,
        summary: `EIP-2612 permit signature (${domainLabel(ctx)}): grants spender ${spender} ${allowance.phrase} on ${tokenText}${
          deadline ? `, deadline ${deadline}` : ""
        }.`,
      },
      [
        {
          address: spender,
          role: "spender",
          interaction: grantsNothing ? interaction("message_signature") : interaction("permit_signature", allowance.unlimited),
          rank: grantsNothing ? RANK.revoke : allowance.unlimited ? RANK.unlimitedApproval : RANK.approval,
          unlimited: allowance.unlimited,
          amountLabel: allowance.label,
          payment: payment({ network: ctx.chain, pay_to: spender, amount: amount?.toString(), asset: token }),
        },
      ],
    );
  }

  if (declared(ctx, "Permit", "tokenId")) {
    const tokenId = num(ctx.message, "tokenId");
    return done(
      ctx,
      {
        action: "NFT permit (ERC-4494)",
        amountLabel: `NFT #${tokenId?.toString() ?? "?"}`,
        summary: `NFT permit signature (${domainLabel(ctx)}): approves spender ${spender} for NFT #${tokenId?.toString() ?? "?"} of ${token ?? "an unknown collection"}.`,
      },
      [{ address: spender, role: "spender", interaction: interaction("permit_signature"), rank: RANK.approval }],
    );
  }
  return undefined;
}

type TokenAmount = { token?: string; amount?: bigint; expiration?: bigint };

function checkPermit2Domain(ctx: Ctx): void {
  if (ctx.verifyingContract !== PERMIT2_ADDRESS) {
    ctx.warnings.push(
      ctx.verifyingContract
        ? `Permit2-style message whose verifying contract ${ctx.verifyingContract} is not the canonical Permit2 contract`
        : "Permit2-style message without a declared verifying contract",
    );
  }
}

function permitInteraction(amounts: (bigint | undefined)[], unlimited: boolean): Interaction {
  const grantsNothing = amounts.length > 0 && amounts.every((amount) => amount === 0n);
  return grantsNothing ? interaction("message_signature") : interaction("permit_signature", unlimited);
}

function tokenPayment(ctx: Ctx, spender: string, entries: TokenAmount[]) {
  if (entries.length === 1) {
    const [entry] = entries as [TokenAmount];
    return payment({ network: ctx.chain, pay_to: spender, amount: entry.amount?.toString(), asset: entry.token });
  }
  return payment({ network: ctx.chain, pay_to: spender });
}

function decodePermit2Allowance(ctx: Ctx, batch: boolean): Decoded | undefined {
  if (declared(ctx, ctx.primaryType, "spender") !== "address") return undefined;
  const spender = addr(ctx.message, "spender");
  if (!spender) return unresolved(ctx, `Permit2 ${ctx.primaryType}`, "spender");
  const entries: TokenAmount[] = structs(ctx.message.details).map((detail) => ({
    token: addr(detail, "token"),
    amount: num(detail, "amount"),
    expiration: num(detail, "expiration"),
  }));
  if (entries.length === 0) entries.push({});
  checkPermit2Domain(ctx);
  const described = entries.map((entry) => {
    const allowance = describeAllowance(entry.amount, UNLIMITED_UINT160, ctx.warnings);
    const expiry = entry.expiration !== undefined ? `, expiring ${unixDate(entry.expiration)}` : "";
    return { allowance, text: `${allowance.phrase} on ${tokenLabel(ctx.chain, entry.token)}${expiry}` };
  });
  const unlimited = described.some((item) => item.allowance.unlimited);
  const sigDeadline = unixDate(num(ctx.message, "sigDeadline"));
  const shown = described.slice(0, 3).map((item) => item.text);
  if (described.length > 3) shown.push(`and ${described.length - 3} more tokens`);
  const amountLabel = unlimited ? "UNLIMITED" : entries.length === 1 ? described[0]?.allowance.label : `${entries.length} tokens`;
  return done(
    ctx,
    {
      action: batch ? "Permit2 PermitBatch" : "Permit2 PermitSingle",
      unlimited,
      amountLabel,
      summary: `Permit2 ${batch ? "PermitBatch" : "PermitSingle"} signature (${domainLabel(ctx)}): grants spender ${spender} ${shown.join("; ")}${
        sigDeadline ? `; signature valid until ${sigDeadline}` : ""
      }.`,
    },
    [
      {
        address: spender,
        role: "spender",
        interaction: permitInteraction(entries.map((entry) => entry.amount), unlimited),
        rank: unlimited ? RANK.unlimitedApproval : RANK.approval,
        unlimited,
        amountLabel,
        payment: tokenPayment(ctx, spender, entries),
      },
    ],
  );
}

type Output = { token?: string; amount?: bigint; recipient: string };

/** Structs with an address `recipient` (and usually `token`) inside a witness. */
function collectOutputs(types: TypedTypes, type: string, value: CanonValue, out: Output[], depth = 0): void {
  if (depth > 12 || out.length > 32) return;
  if (type.endsWith("]")) {
    if (Array.isArray(value)) {
      const itemType = type.slice(0, type.lastIndexOf("["));
      for (const item of value) collectOutputs(types, itemType, item, out, depth + 1);
    }
    return;
  }
  const fields = types[type];
  if (!fields || !isCanonStruct(value)) return;
  const recipient = fieldType(types, type, "recipient") === "address" ? canonAddressValue(value.recipient) : undefined;
  if (recipient) {
    out.push({
      recipient,
      token: fieldType(types, type, "token") === "address" ? canonAddressValue(value.token) : undefined,
      amount: minOf(canonBigInt(value.startAmount), canonBigInt(value.endAmount)) ?? canonBigInt(value.amount),
    });
  }
  for (const field of fields) collectOutputs(types, field.type, value[field.name], out, depth + 1);
}

function decodePermit2Transfer(ctx: Ctx): Decoded | undefined {
  if (declared(ctx, ctx.primaryType, "spender") !== "address") return undefined;
  const spender = addr(ctx.message, "spender");
  if (!spender) return unresolved(ctx, `Permit2 ${ctx.primaryType}`, "spender");
  const entries: TokenAmount[] = structs(ctx.message.permitted).map((item) => ({
    token: addr(item, "token"),
    amount: num(item, "amount"),
  }));
  if (entries.length === 0) entries.push({});
  checkPermit2Domain(ctx);
  const described = entries.map((entry) => {
    const allowance = describeAllowance(entry.amount, UNLIMITED_UINT160, ctx.warnings);
    const amount =
      entry.amount === undefined
        ? "an UNKNOWN amount (treated as unlimited)"
        : allowance.unlimited
          ? "an UNLIMITED amount"
          : `up to ${tokenAmount(entry.amount, ctx.chain, entry.token)}`;
    return { allowance, text: entry.amount === undefined || allowance.unlimited ? `${amount} of ${tokenLabel(ctx.chain, entry.token)}` : amount };
  });
  const unlimited = described.some((item) => item.allowance.unlimited);
  const deadline = unixDate(num(ctx.message, "deadline"));
  const shown = described.slice(0, 3).map((item) => item.text);
  if (described.length > 3) shown.push(`and ${described.length - 3} more tokens`);
  const amountLabel = unlimited ? "UNLIMITED" : entries.length === 1 ? described[0]?.allowance.label : `${entries.length} tokens`;

  const candidates: Candidate[] = [
    {
      address: spender,
      role: "spender",
      interaction: permitInteraction(entries.map((entry) => entry.amount), unlimited),
      rank: unlimited ? RANK.unlimitedApproval : RANK.approval,
      unlimited,
      amountLabel,
      payment: tokenPayment(ctx, spender, entries),
    },
  ];
  let witnessText = "";
  const witnessType = declared(ctx, ctx.primaryType, "witness");
  if (witnessType) {
    const outputs: Output[] = [];
    collectOutputs(ctx.types, witnessType, ctx.message.witness, outputs);
    const visits: AddressVisit[] = [];
    collectAddressFields(ctx.types, witnessType, ctx.message.witness, "witness", visits);
    for (const visit of visits) {
      if (visit.key === "swapper" && ctx.signer && visit.address !== ctx.signer) {
        ctx.warnings.push(`the order's swapper ${visit.address} is not the signing account`);
      }
    }
    const foreign = outputs.filter((output) => output.recipient !== ctx.signer && !isIgnorableAddress(output.recipient));
    for (const output of foreign) {
      const what = output.amount !== undefined ? tokenAmount(output.amount, ctx.chain, output.token) : tokenLabel(ctx.chain, output.token);
      ctx.warnings.push(`an order output of ${what} goes to ${output.recipient}, not to you`);
      candidates.push({
        address: output.recipient,
        role: "recipient",
        interaction: interaction("token_transfer"),
        rank: RANK.orderOutput,
        reason: `receives an order output of ${what}`,
        amountLabel: what,
        payment: payment({ network: ctx.chain, pay_to: output.recipient, amount: output.amount?.toString(), asset: output.token }),
      });
    }
    const listed = outputs
      .slice(0, 3)
      .map((output) => `${output.amount !== undefined ? tokenAmount(output.amount, ctx.chain, output.token) : tokenLabel(ctx.chain, output.token)} to ${output.recipient === ctx.signer ? "you" : output.recipient}`);
    witnessText = ` Order (${capText(baseType(witnessType) ?? "witness", 40)}) outputs: ${listed.join("; ") || "none decoded"}.`;
  }
  return done(
    ctx,
    {
      action: `Permit2 ${ctx.primaryType}`,
      unlimited,
      amountLabel,
      summary: `Permit2 ${ctx.primaryType} signature (${domainLabel(ctx)}): lets spender ${spender} transfer ${shown.join("; ")} out of the signer's wallet${
        deadline ? `, deadline ${deadline}` : ""
      }.${witnessText}`,
    },
    candidates,
  );
}

// ---------------------------------------------------------------------------
// Marketplace orders
// ---------------------------------------------------------------------------

type SeaItem = { itemType: number; token?: string; id?: bigint; start?: bigint; end?: bigint; recipient?: string };

function seaItems(value: CanonValue): SeaItem[] {
  return structs(value).map((item) => {
    const itemType = num(item, "itemType");
    return {
      itemType: itemType === undefined || itemType > 5n ? -1 : Number(itemType),
      token: addr(item, "token"),
      id: num(item, "identifierOrCriteria"),
      start: num(item, "startAmount"),
      end: num(item, "endAmount"),
      recipient: addr(item, "recipient"),
    };
  });
}

function describeSeaItem(item: SeaItem, chain: string | undefined, useMin: boolean): string {
  const amount = (useMin ? minOf(item.start, item.end) : maxOf(item.start, item.end)) ?? 0n;
  const token = item.token ?? "(unknown token)";
  switch (item.itemType) {
    case 0:
      return nativeAmount(amount, chain);
    case 1:
      return tokenAmount(amount, chain, item.token);
    case 2:
      return `NFT ${token} #${item.id?.toString() ?? "?"}`;
    case 3:
      return `${amount.toString()} x ERC-1155 ${token} #${item.id?.toString() ?? "?"}`;
    case 4:
    case 5:
      return `any item of collection ${token} (criteria)`;
    default:
      return "an unrecognized item";
  }
}

function describeItems(items: SeaItem[], chain: string | undefined, useMin: boolean): string {
  const shown = items.slice(0, 3).map((item) => describeSeaItem(item, chain, useMin));
  if (items.length > 3) shown.push(`and ${items.length - 3} more`);
  return shown.join(", ");
}

type OrderAnalysis = { summary: string; candidates: Candidate[]; empty: boolean };

function analyzeSeaportOrder(ctx: Ctx, order: CanonStruct): OrderAnalysis {
  const offerer = addr(order, "offerer");
  const offer = seaItems(order.offer);
  const consideration = seaItems(order.consideration);
  if (offer.length === 0 && consideration.length === 0) return { summary: "", candidates: [], empty: true };
  if (!offerer) {
    ctx.danger.push("the order's offerer could not be decoded");
    return { summary: "Seaport order with an undecodable offerer.", candidates: [], empty: false };
  }
  if (ctx.signer && offerer !== ctx.signer) ctx.warnings.push(`the order's offerer ${offerer} is not the signing account`);
  const toOfferer = consideration.filter((item) => item.recipient === offerer);
  const toOthers = consideration.filter((item) => item.recipient && item.recipient !== offerer);
  const offersValue = offer.some((item) => item.itemType >= 2 || (maxOf(item.start, item.end) ?? 0n) > 0n);
  const receivesNft = toOfferer.some((item) => item.itemType >= 2);
  const fungible = toOfferer
    .filter((item) => item.itemType === 0 || item.itemType === 1)
    .map((item) => ({ token: item.itemType === 0 ? "native" : item.token, amount: minOf(item.start, item.end) ?? 0n }));
  if (offersValue && !receivesNft) {
    if (fungible.length === 0) {
      ctx.danger.push("the offerer receives NOTHING in return for the offered items");
    } else if (fungible.every((entry) => isDust(ctx.chain, entry.token, entry.amount))) {
      ctx.danger.push(
        `the offerer receives only ${describeItems(toOfferer, ctx.chain, true)} (at the lowest point of the price) for the offered items (typical of NFT drainer listings)`,
      );
    } else if (fungible.every((entry) => !isKnownValueToken(ctx.chain, entry.token))) {
      ctx.warnings.push("the offerer is paid only in unknown token(s) that may be worthless");
    }
  }
  if (toOfferer.some((item) => item.start !== undefined && item.end !== undefined && item.start !== item.end)) {
    ctx.warnings.push(
      `the price changes over time: from ${describeItems(toOfferer, ctx.chain, false)} down to ${describeItems(toOfferer, ctx.chain, true)}`,
    );
  }
  if (consideration.some((item) => item.recipient && isIgnorableAddress(item.recipient))) {
    ctx.warnings.push("part of the consideration goes to the zero/burn address");
  }
  const candidates: Candidate[] = toOthers
    .filter((item) => item.recipient && !isIgnorableAddress(item.recipient))
    .map((item) => ({ item, native: item.itemType === 0 ? (minOf(item.start, item.end) ?? 0n) : -1n }))
    .sort((a, b) => (b.native > a.native ? 1 : b.native < a.native ? -1 : 0))
    .map(({ item }) => ({
      address: item.recipient as string,
      role: "recipient" as Role,
      interaction: interaction("order_signature"),
      rank: RANK.transfer,
      reason: `receives ${describeSeaItem(item, ctx.chain, true)} from the sale`,
      ...(item.itemType === 0 || item.itemType === 1
        ? {
            payment: payment({
              network: ctx.chain,
              pay_to: item.recipient,
              amount: minOf(item.start, item.end)?.toString(),
              asset: item.itemType === 0 ? "native" : item.token,
            }),
          }
        : {}),
    }));
  const others = [...new Set(toOthers.map((item) => item.recipient as string))].filter((address) => !isIgnorableAddress(address));
  return {
    summary: `offerer ${offerer} offers ${offer.length > 0 ? describeItems(offer, ctx.chain, false) : "nothing"}; the offerer receives ${
      toOfferer.length > 0 ? describeItems(toOfferer, ctx.chain, true) : "NOTHING"
    }; other consideration recipients: ${others.length > 0 ? others.slice(0, 3).join(", ") : "none"}`,
    candidates,
    empty: false,
  };
}

function flattenTree(value: CanonValue, out: CanonStruct[], depth = 0): void {
  if (out.length >= MAX_TREE_ORDERS || depth > 30) return;
  if (Array.isArray(value)) {
    for (const item of value) flattenTree(item, out, depth + 1);
    return;
  }
  if (isCanonStruct(value)) out.push(value);
}

function verifyingCandidate(ctx: Ctx, kind: Interaction): Candidate[] {
  return ctx.verifyingContract
    ? [{ address: ctx.verifyingContract, role: "contract", interaction: kind, rank: RANK.verifyingContract }]
    : [];
}

function orderResult(ctx: Ctx, action: string, summary: string, candidates: Candidate[]): Decoded {
  const kind = interaction("order_signature");
  const all = candidates.length > 0 ? candidates : verifyingCandidate(ctx, kind);
  if (all.length === 0) return signerFallback(ctx, action, `${summary} No counterparty address in message; subject is the signer.`, kind);
  const noThirdParty = candidates.length === 0 ? " No third-party recipient in the order; subject is the marketplace contract." : "";
  return done(ctx, { action, summary: `${summary}${noThirdParty}` }, all);
}

function decodeSeaport(ctx: Ctx): Decoded | undefined {
  if (declared(ctx, "OrderComponents", "offerer") !== "address") return undefined;
  if (ctx.primaryType === "OrderComponents") {
    const analysis = analyzeSeaportOrder(ctx, ctx.message);
    return orderResult(ctx, "Seaport order", `Seaport order signature (${domainLabel(ctx)}): ${analysis.summary || "empty order"}.`, analysis.candidates);
  }
  // BulkOrder: a Merkle tree (nested fixed arrays) of OrderComponents.
  if (baseType(declared(ctx, ctx.primaryType, "tree")) !== "OrderComponents") return undefined;
  const orders: CanonStruct[] = [];
  flattenTree(ctx.message.tree, orders);
  const analyses = orders.map((order) => analyzeSeaportOrder(ctx, order)).filter((analysis) => !analysis.empty);
  if (orders.length >= MAX_TREE_ORDERS) ctx.warnings.push(`the bulk listing is large; only the first ${MAX_TREE_ORDERS} orders were inspected`);
  const parts = analyses.slice(0, 3).map((analysis, index) => `order ${index + 1}: ${analysis.summary}`);
  return orderResult(
    ctx,
    "Seaport bulk listing",
    `Seaport bulk listing signature (${domainLabel(ctx)}) covering ${analyses.length} order(s)${parts.length > 0 ? `: ${parts.join("; ")}` : ""}.`,
    analyses.flatMap((analysis) => analysis.candidates),
  );
}

function decodeBlur(ctx: Ctx): Decoded | undefined {
  if (ctx.primaryType === "Root" && declared(ctx, "Root", "root")?.startsWith("bytes")) {
    ctx.warnings.push(
      "blind bulk-listing signature: it signs only a Merkle root, so neither you nor x402check can see which listings (or prices) it authorizes",
    );
    return orderResult(ctx, "Blur bulk listing (blind root)", `Blur bulk-listing signature (${domainLabel(ctx)}) over an opaque Merkle root of orders.`, []);
  }
  if (ctx.primaryType !== "Order") return undefined;
  if (declared(ctx, "Order", "trader") !== "address" || !declared(ctx, "Order", "price") || !declared(ctx, "Order", "side")) {
    return undefined;
  }
  const trader = addr(ctx.message, "trader");
  const side = num(ctx.message, "side");
  const price = num(ctx.message, "price");
  const currency = addr(ctx.message, "paymentToken");
  const collection = addr(ctx.message, "collection");
  const tokenId = num(ctx.message, "tokenId");
  if (ctx.signer && trader && trader !== ctx.signer) ctx.warnings.push(`the order's trader ${trader} is not the signing account`);
  const selling = side === 1n;
  const priceLabel = price === undefined ? "an unknown price" : priceText(ctx.chain, currency, price);
  if (selling && (price === undefined || isDust(ctx.chain, currency && !isIgnorableAddress(currency) ? currency : "native", price))) {
    ctx.danger.push(`the order lists ${collection ?? "an NFT"} #${tokenId?.toString() ?? "?"} for only ${priceLabel} (typical of NFT drainer listings)`);
  }
  const fees = structs(ctx.message.fees).map((fee) => ({ rate: num(fee, "rate") ?? 0n, recipient: addr(fee, "recipient") }));
  const totalRate = fees.reduce((sum, fee) => sum + fee.rate, 0n);
  if (totalRate > 5000n) ctx.warnings.push(`fees send ${Number(totalRate) / 100}% of the sale price to other addresses`);
  const candidates: Candidate[] = fees
    .filter((fee) => fee.recipient && fee.recipient !== ctx.signer && !isIgnorableAddress(fee.recipient))
    .sort((a, b) => (b.rate > a.rate ? 1 : -1))
    .map((fee) => ({
      address: fee.recipient as string,
      role: "recipient" as Role,
      interaction: interaction("order_signature"),
      rank: RANK.transfer,
      reason: `receives a ${Number(fee.rate) / 100}% fee`,
    }));
  return orderResult(
    ctx,
    selling ? "Blur listing" : "Blur order",
    `Blur order signature (${domainLabel(ctx)}): ${selling ? "sells" : "buys"} ${collection ?? "an NFT"} #${tokenId?.toString() ?? "?"} for ${priceLabel}${
      fees.length > 0 ? `, fees ${Number(totalRate) / 100}%` : ""
    }.`,
    candidates,
  );
}

function analyzeMaker(ctx: Ctx, maker: CanonStruct): string {
  const quoteType = num(maker, "quoteType");
  const price = num(maker, "price");
  const currency = addr(maker, "currency");
  const collection = addr(maker, "collection");
  const signerField = addr(maker, "signer");
  if (ctx.signer && signerField && signerField !== ctx.signer) ctx.warnings.push(`the order's signer field ${signerField} is not the signing account`);
  const selling = quoteType === 1n;
  const priceLabel = price === undefined ? "an unknown price" : priceText(ctx.chain, currency, price);
  if (selling && (price === undefined || isDust(ctx.chain, currency && !isIgnorableAddress(currency) ? currency : "native", price))) {
    ctx.danger.push(`the order lists ${collection ?? "NFTs"} for only ${priceLabel} (typical of NFT drainer listings)`);
  }
  return `${selling ? "ask (sell)" : "bid (buy)"} for ${collection ?? "an NFT collection"} at ${priceLabel}`;
}

function decodeLooksRare(ctx: Ctx): Decoded | undefined {
  if (declared(ctx, "Maker", "quoteType") === undefined || declared(ctx, "Maker", "price") === undefined) return undefined;
  if (ctx.primaryType === "Maker") {
    return orderResult(ctx, "LooksRare order", `LooksRare order signature (${domainLabel(ctx)}): ${analyzeMaker(ctx, ctx.message)}.`, []);
  }
  if (baseType(declared(ctx, ctx.primaryType, "tree")) !== "Maker") return undefined;
  const makers: CanonStruct[] = [];
  flattenTree(ctx.message.tree, makers);
  const parts = makers.map((maker) => analyzeMaker(ctx, maker));
  return orderResult(
    ctx,
    "LooksRare batch order",
    `LooksRare batch order signature (${domainLabel(ctx)}) covering ${makers.length} order(s): ${parts.slice(0, 3).join("; ")}.`,
    [],
  );
}

// ---------------------------------------------------------------------------
// Safe transactions
// ---------------------------------------------------------------------------

function decodeSafeTx(ctx: Ctx): Decoded | undefined {
  if (ctx.primaryType !== "SafeTx" || declared(ctx, "SafeTx", "to") !== "address" || declared(ctx, "SafeTx", "data") !== "bytes") {
    return undefined;
  }
  const to = addr(ctx.message, "to");
  if (!to) return unresolved(ctx, "Safe transaction", "to");
  const value = num(ctx.message, "value") ?? 0n;
  const rawData = ctx.message.data;
  const operation = num(ctx.message, "operation") ?? 0n;
  const data = typeof rawData === "string" && isStrictHexString(`${rawData}0`) ? rawData.slice(2) : rawData === "0x" ? "" : undefined;
  if (data === undefined) ctx.warnings.push("the Safe transaction's data could not be decoded");
  const action = decodeCallAction(
    { sender: ctx.verifyingContract, to, value, data: data ?? "", delegate: operation === 1n },
    ctx.chain,
    ctx.signer,
  );
  ctx.warnings.push(...action.warnings);
  ctx.danger.push(...action.danger);
  const gasPrice = num(ctx.message, "gasPrice") ?? 0n;
  const refundReceiver = addr(ctx.message, "refundReceiver");
  if (gasPrice > 0n && refundReceiver && !isIgnorableAddress(refundReceiver)) ctx.warnings.push(`the Safe pays gas refunds to ${refundReceiver}`);
  const candidates = action.candidates.length > 0 ? action.candidates : [{ address: to, role: "contract" as Role, interaction: interaction("contract_call"), rank: RANK.contract }];
  return done(
    ctx,
    {
      action: `Safe transaction: ${action.label}`,
      summary: `Safe transaction signature (SafeTx for Safe ${ctx.verifyingContract ?? "(unknown)"}, ${operation === 1n ? "DELEGATECALL" : "CALL"} to ${to}): ${action.summary}`,
    },
    candidates,
  );
}

// ---------------------------------------------------------------------------
// Generic typed data
// ---------------------------------------------------------------------------

const PERMIT_TYPES = new Set([
  "Permit",
  "PermitSingle",
  "PermitBatch",
  "PermitTransferFrom",
  "PermitBatchTransferFrom",
  "PermitWitnessTransferFrom",
  "PermitBatchWitnessTransferFrom",
]);

/**
 * Marketplace orders: Seaport OrderComponents / BulkOrder, Blur/0x/Rarible
 * orders ("Order", "MakerOrder", "ERC721Order"...), LooksRare v2 "Maker" and
 * Blur bulk-listing "Root".
 *
 * @param primaryType - The EIP-712 primary type.
 * @param domainName - The EIP-712 domain name.
 * @returns Whether the typed data is a marketplace order.
 */
export function isOrderType(primaryType: string, domainName?: string): boolean {
  return /order/iu.test(primaryType) || primaryType === "Maker" || (primaryType === "Root" && /blur/iu.test(domainName ?? ""));
}

const KEY_RANKS: Record<string, { rank: number; role: Role }> = {
  spender: { rank: RANK.approval, role: "spender" },
  operator: { rank: RANK.approval, role: "operator" },
  delegate: { rank: RANK.approval, role: "delegate" },
  to: { rank: RANK.transfer, role: "recipient" },
  recipient: { rank: RANK.transfer, role: "recipient" },
  receiver: { rank: RANK.transfer, role: "recipient" },
  taker: { rank: RANK.transfer, role: "counterparty" },
};

/** Field names come from the (untrusted) types: own-property lookups only. */
function keyRank(key: string): { rank: number; role: Role } | undefined {
  const lower = key.toLowerCase();
  return hasOwn(KEY_RANKS, lower) ? KEY_RANKS[lower] : undefined;
}

function decodeGeneric(ctx: Ctx): Decoded {
  const kind = PERMIT_TYPES.has(ctx.primaryType)
    ? interaction("permit_signature")
    : isOrderType(ctx.primaryType, ctx.domainName)
      ? interaction("order_signature")
      : interaction("message_signature");
  const visits: AddressVisit[] = [];
  collectAddressFields(ctx.types, ctx.primaryType, ctx.message, "", visits);
  const skip = new Set([ctx.signer, ctx.verifyingContract].filter(Boolean));
  const usable = visits.filter((visit) => !skip.has(visit.address) && !isIgnorableAddress(visit.address));
  const head = `EIP-712 signature (${ctx.method}, ${domainLabel(ctx)}, primary type ${quote(ctx.primaryType || "unknown", 40)})`;
  const details = scalarFields(ctx, 6).join("; ");
  const action = `Typed data: ${capText(ctx.primaryType || "unknown", 40)}`;
  const preferred = usable.filter((visit) => keyRank(visit.key) !== undefined);
  const chosen = preferred.length > 0 ? preferred : usable.slice(0, 1);
  if (chosen.length > 0) {
    const candidates: Candidate[] = chosen.map((visit, index) => {
      const info = keyRank(visit.key);
      return {
        address: visit.address,
        role: info?.role ?? "counterparty",
        interaction: kind,
        rank: (info?.rank ?? RANK.contract) - index * 0.001,
        reason: `named in field "${capText(visit.path, 60)}"`,
      };
    });
    const first = chosen[0] as { path: string; address: string };
    return done(
      ctx,
      {
        action,
        summary: `${head}: counterparty taken from field "${capText(first.path, 60)}" = ${first.address}.${details ? ` Fields: ${details}.` : ""}`,
      },
      candidates,
    );
  }
  if (ctx.verifyingContract && ctx.verifyingContract !== ctx.signer) {
    return done(
      ctx,
      { action, summary: `${head}: no counterparty address in the message; subject is the verifying contract.${details ? ` Fields: ${details}.` : ""}` },
      verifyingCandidate(ctx, kind),
    );
  }
  return signerFallback(ctx, action, `${head}: no counterparty address in message; subject is the signer.${details ? ` Fields: ${details}.` : ""}`, kind);
}

/** A few declared scalar fields as "path=value", for context. */
function scalarFields(ctx: Ctx, limit: number): string[] {
  const out: string[] = [];
  const walk = (type: string, value: CanonValue, path: string, depth: number) => {
    if (out.length >= limit || depth > 4) return;
    const fields = ctx.types[type];
    if (fields && isCanonStruct(value)) {
      for (const field of fields) walk(field.type, value[field.name], path ? `${path}.${field.name}` : field.name, depth + 1);
      return;
    }
    if (Array.isArray(value)) {
      out.push(`${path}=[${value.length} items]`);
      return;
    }
    if (typeof value === "bigint" || typeof value === "boolean") out.push(`${path}=${value.toString()}`);
    else if (typeof value === "string") out.push(`${path}=${capText(cleanText(value, 256).text, 48)}`);
  };
  walk(ctx.primaryType, ctx.message, "", 0);
  return out;
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

function parseTypedDataInput(data: unknown): unknown {
  if (typeof data === "string") {
    if (data.length > MAX_JSON) return { tooLarge: data.length };
    try {
      return JSON.parse(data) as unknown;
    } catch {
      return undefined;
    }
  }
  return data;
}

function malformed(signer: string | undefined, method: string, reason: string): Decoded {
  return withCandidates(
    {
      action: "Malformed typed data",
      summary: `Typed-data signature (${method}) that cannot be signed as-is: ${reason}.`,
      warnings: [],
      danger: [],
      interaction: interaction("message_signature"),
      localNote: `This signature request is malformed (${reason}), so MetaMask cannot sign it as-is. x402check did not check it.`,
    },
    signer ? [] : [],
  );
}

/**
 * Decodes eth_signTypedData (v1 array) and v3/v4 (object, or its JSON string)
 * using only what MetaMask actually signs.
 *
 * @param data - The `signature.data` value.
 * @param signerAddress - The signing account (`signature.from`).
 * @param method - The signature method, for the summary.
 * @returns The decoded request.
 */
export function decodeTypedData(data: unknown, signerAddress?: unknown, method = "eth_signTypedData_v4"): Decoded {
  const signer = normalizeAddress(typeof signerAddress === "string" ? signerAddress.toLowerCase() : signerAddress);
  const parsed = parseTypedDataInput(data);
  if (Array.isArray(parsed)) return decodeTypedDataV1(parsed, signer);
  if (isRecord(parsed) && typeof parsed.tooLarge === "number") {
    const warnings = [`the typed data is very large (${parsed.tooLarge} characters) and was not decoded`];
    return withCandidates(
      {
        action: "Typed data (too large)",
        summary: `Typed-data signature (${method}) of ${parsed.tooLarge} characters, too large to decode; no counterparty address could be read; subject is the signer.`,
        warnings,
        danger: [],
        ...(signer ? {} : { localNote: "The typed data is too large to decode and the signer is unknown; nothing was sent to x402check." }),
      },
      signer ? [{ address: signer, role: "signer", interaction: interaction("message_signature"), rank: RANK.signer }] : [],
    );
  }
  const canon = canonicalizeTypedData(parsed);
  if ("error" in canon) return malformed(signer, method, canon.error);

  const domainName = typeof canon.domain.name === "string" ? canon.domain.name : undefined;
  const ctx: Ctx = {
    canon,
    types: canon.types,
    method,
    signer,
    chain: typeof canon.domain.chainId === "bigint" ? normalizeChainId(canon.domain.chainId) : undefined,
    verifyingContract: canonAddressValue(canon.domain.verifyingContract),
    domainName,
    primaryType: canon.primaryType,
    message: canon.message,
    warnings: [],
    danger: [],
  };
  for (const note of canon.unusual.slice(0, 4)) ctx.warnings.push(note);
  if (canon.unsignable.length > 0) {
    ctx.warnings.push(`MetaMask cannot sign this request as-is: invalid field(s) ${canon.unsignable.slice(0, 3).join(", ")}`);
  }
  if (canon.unresolved.length > 0) {
    ctx.danger.push(`x402check could not decode field(s) ${canon.unresolved.slice(0, 3).join(", ")}; do not sign unless you trust the site`);
  }
  if (canon.truncated) ctx.warnings.push("the typed data is too large to inspect completely");

  let decoded: Decoded | undefined;
  switch (ctx.primaryType) {
    case "Permit":
      decoded = decodePermit(ctx);
      break;
    case "PermitSingle":
      decoded = decodePermit2Allowance(ctx, false);
      break;
    case "PermitBatch":
      decoded = decodePermit2Allowance(ctx, true);
      break;
    case "PermitTransferFrom":
    case "PermitBatchTransferFrom":
    case "PermitWitnessTransferFrom":
    case "PermitBatchWitnessTransferFrom":
      decoded = decodePermit2Transfer(ctx);
      break;
    case "SafeTx":
      decoded = decodeSafeTx(ctx);
      break;
    default:
      decoded = decodeSeaport(ctx) ?? decodeBlur(ctx) ?? decodeLooksRare(ctx);
  }
  return decoded ?? decodeGeneric(ctx);
}

/** eth_signTypedData (v1): address values must be strict hex to be signable. */
function v1Address(value: unknown): string | undefined {
  if (typeof value !== "string" || !isStrictHexString(value)) return undefined;
  let hex = value.slice(2).toLowerCase();
  if (hex.length % 2 === 1) hex = `0${hex}`;
  return hex.length <= 40 ? `0x${hex.padStart(40, "0")}` : undefined;
}

function decodeTypedDataV1(entries: unknown[], signer?: string): Decoded {
  const fields = entries
    .slice(0, 64)
    .filter(isRecord)
    .map((entry) => ({
      type: typeof entry.type === "string" ? entry.type : "",
      name: typeof entry.name === "string" ? entry.name : "",
      value: entry.value,
    }));
  const visits = fields
    .filter((field) => field.type === "address")
    .map((field) => ({ key: field.name, address: v1Address(field.value) }))
    .filter((visit): visit is { key: string; address: string } => Boolean(visit.address) && visit.address !== signer && !isIgnorableAddress(visit.address as string));
  const listed = fields
    .slice(0, 6)
    .map((field) => {
      const value = typeof field.value === "object" && field.value !== null ? "[complex]" : cleanText(String(field.value), 256).text;
      return `${capText(cleanText(field.name, 64).text, 24)} (${capText(field.type, 16)}) = ${capText(value, 48)}`;
    })
    .join("; ");
  const head = `Legacy typed-data signature (eth_signTypedData v1) with ${fields.length} field(s): ${listed}`;
  const kind = interaction("message_signature");
  const preferred = visits.find((visit) => keyRank(visit.key) !== undefined) ?? visits[0];
  if (preferred) {
    const info = keyRank(preferred.key);
    return withCandidates(
      {
        action: "Typed data (v1)",
        summary: `${head}. Counterparty taken from field "${capText(preferred.key, 40)}" = ${preferred.address}.`,
        warnings: [],
        danger: [],
      },
      [{ address: preferred.address, role: info?.role ?? "counterparty", interaction: kind, rank: info?.rank ?? RANK.contract }],
    );
  }
  const summary = `${head}. No counterparty address in message; subject is the signer.`;
  if (!signer) {
    return withCandidates(
      {
        action: "Typed data (v1)",
        summary,
        warnings: [],
        danger: [],
        interaction: kind,
        localNote: "The request names no counterparty and the signing account is unknown, so there is nothing to check. Nothing was sent to x402check.",
      },
      [],
    );
  }
  return withCandidates({ action: "Typed data (v1)", summary, warnings: [], danger: [] }, [
    { address: signer, role: "signer", interaction: kind, rank: RANK.signer },
  ]);
}
