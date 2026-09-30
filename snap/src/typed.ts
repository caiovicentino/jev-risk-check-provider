/**
 * EIP-712 typed-data decoders. They only ever read the canonical view built by
 * eip712.ts (declared fields, values normalized exactly as MetaMask signs
 * them), so an undeclared decoy key or an exotic encoding cannot change what
 * the Snap reports.
 *
 * Recognized: permits (EIP-2612, DAI, ERC-4494), Permit2 (allowances and
 * signature transfers with their witness: UniswapX orders, x402 payments),
 * marketplace orders (Seaport, Blur, LooksRare), ERC-20 limit orders (1inch,
 * 0x v4, CoW Protocol), calls signed as typed data (SafeTx, ERC-4337 user
 * operations and Safe 4337 operations, ERC-2771 forward requests, EIP712Base
 * meta-transactions) and ERC-7739 nested signatures. Anything else is decoded
 * generically; when what it signs is a hash or calldata, it is `opaque`.
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
import { decodePersonalSign, isMostlyPrintable } from "./personal";
import type { Action } from "./tx";
import { decodeCallAction, dedupe } from "./tx";
import type { Candidate, Decoded, Interaction, Role } from "./util";
import {
  PERMIT2_ADDRESS,
  RANK,
  UNLIMITED_UINT160,
  UNLIMITED_UINT256,
  ZERO_ADDRESS,
  capText,
  cleanText,
  describeAllowance,
  hasOwn,
  interaction,
  isIgnorableAddress,
  isRecord,
  knownToken,
  nativeAmount,
  nativeSymbol,
  normalizeAddress,
  normalizeChainId,
  opaqueNote,
  opaqueReason,
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
/** ERC-7739 wrappers unwrapped inside each other. */
const MAX_NESTING = 2;
/** Tokens treated like native ETH for pricing (Blur Pool). */
const ETH_LIKE = new Set(["0x0000000000a39bb272e79075ade125fd351887ac"]);
/** The 0xEeee… marker some protocols (CoW Protocol) use for native ETH. */
const NATIVE_MARKER = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
/** x402's Permit2 proxies (exact and upto schemes): the witness `to` is the payee. */
const X402_PROXIES = new Map([
  ["0x402085c248eea27d92e8b30b2c58ed07f9e20001", "the x402 exact-payment Permit2 proxy"],
  ["0x4020a4f3b7b90cca423b9fabcc0ce57c6c240002", "the x402 upto-payment Permit2 proxy"],
]);

type Ctx = {
  canon: Canonical;
  types: TypedTypes;
  method: string;
  signer?: string | undefined;
  chain?: string | undefined;
  verifyingContract?: string | undefined;
  domainName?: string | undefined;
  primaryType: string;
  message: CanonStruct;
  warnings: string[];
  danger: string[];
  /** Why what this signature authorizes cannot be read (Decoded.opaque). */
  opaque: string[];
  /** The parsed typed data as given, to decode ERC-7739 wrapped contents. */
  raw: Record<string, unknown>;
  /** ERC-7739 nesting depth. */
  depth: number;
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

/** Lowercase hex without 0x of a canonical `bytes` value ("" when empty). */
function bytesHex(value: CanonValue): string | undefined {
  if (value === "0x") return "";
  return typeof value === "string" && value.length % 2 === 0 && isStrictHexString(value) ? value.slice(2).toLowerCase() : undefined;
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

/** "native" for the zero address and the 0xEeee… marker, else the token. */
function assetOf(token: string | undefined): string | undefined {
  return token === ZERO_ADDRESS || token === NATIVE_MARKER ? "native" : token;
}

function assetLabel(chain: string | undefined, asset: string | undefined): string {
  return asset === "native" ? nativeSymbol(chain) : tokenLabel(chain, asset);
}

function assetAmount(chain: string | undefined, asset: string | undefined, amount: bigint | undefined): string {
  if (amount === undefined) return `an unknown amount of ${assetLabel(chain, asset)}`;
  if (asset === "native" || (asset !== undefined && ETH_LIKE.has(asset))) return nativeAmount(amount, chain);
  return tokenAmount(amount, chain, asset);
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/** Records that part of what the signature authorizes cannot be read. */
function markOpaque(ctx: Ctx, reason: string): void {
  if (!ctx.opaque.includes(reason)) ctx.opaque.push(reason);
}

/** Warnings (opaque reasons first), danger and the opaque reason of a result. */
function findings(ctx: Ctx): { warnings: string[]; danger: string[]; opaque?: string } {
  const opaque = opaqueReason(ctx.opaque);
  return {
    warnings: dedupe([...ctx.opaque.map(opaqueNote), ...ctx.warnings]),
    danger: dedupe(ctx.danger),
    ...(opaque ? { opaque } : {}),
  };
}

/** Folds a decoded call into the typed-data findings. */
function absorb(ctx: Ctx, action: Action): void {
  ctx.warnings.push(...action.warnings);
  ctx.danger.push(...action.danger);
  for (const reason of action.opaque ?? []) markOpaque(ctx, reason);
}

function done(
  ctx: Ctx,
  base: Omit<Decoded, "counterparty" | "role" | "reason" | "interaction" | "payment" | "others" | "warnings" | "danger" | "chain" | "opaque"> & {
    interaction?: Interaction | undefined;
  },
  candidates: Candidate[],
  exclude: (string | undefined)[] = [],
): Decoded {
  const selected = selectCandidates(candidates, exclude);
  const primary = selected[0];
  return withCandidates(
    {
      ...base,
      chain: ctx.chain,
      unlimited: base.unlimited ?? primary?.unlimited,
      amountLabel: base.amountLabel ?? primary?.amountLabel,
      ...findings(ctx),
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
        ...findings(ctx),
        interaction: kind,
        localNote:
          "The request names no counterparty and the signing account is unknown, so there is nothing to check. Nothing was sent to x402check.",
      },
      [],
    );
  }
  return withCandidates(
    { action, chain: ctx.chain, summary, ...findings(ctx) },
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
        ...findings(ctx),
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
      ...findings(ctx),
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

type TokenAmount = { token?: string | undefined; amount?: bigint | undefined; expiration?: bigint | undefined };

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

type Output = { token?: string | undefined; amount?: bigint | undefined; recipient: string };

/** The least an order output pays: Dutch decay (start/end), a V3 `minAmount`, else `amount`. */
function outputAmount(value: CanonStruct): bigint | undefined {
  return minOf(minOf(canonBigInt(value.startAmount), canonBigInt(value.endAmount)), canonBigInt(value.minAmount)) ?? canonBigInt(value.amount);
}

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
      amount: outputAmount(value),
    });
  }
  for (const field of fields) collectOutputs(types, field.type, value[field.name], out, depth + 1);
}

/** Order witnesses that list what the swapper receives (UniswapX `outputs` / `baseOutputs`). */
function hasOutputList(types: TypedTypes, witnessType: string): boolean {
  return (types[witnessType] ?? []).some((field) => /^(?:base)?outputs$/iu.test(field.name) && field.type.endsWith("]"));
}

/**
 * The economics of an order signed through Permit2 (UniswapX): you give the
 * permitted tokens; what do the outputs pay YOU? Nothing, or only dust, is
 * proven danger (the Seaport rule); outputs in unknown tokens are flagged.
 *
 * @param ctx - Decoding context.
 * @param entries - The permitted tokens and amounts (what you give).
 * @param outputs - The order outputs.
 * @param you - The signer and the order's swapper.
 */
function analyzeOrderOutputs(ctx: Ctx, entries: TokenAmount[], outputs: Output[], you: Set<string>): void {
  if (!entries.some((entry) => entry.amount === undefined || entry.amount > 0n)) return;
  const input = entries
    .slice(0, 2)
    .map((entry) => assetAmount(ctx.chain, entry.token, entry.amount))
    .join(" and ");
  const describe = (list: Output[]) =>
    list
      .slice(0, 3)
      .map((output) => assetAmount(ctx.chain, assetOf(output.token), output.amount))
      .join(", ");
  const mine = outputs.filter((output) => you.has(output.recipient));
  if (mine.length === 0) {
    const others = [...new Set(outputs.map((output) => output.recipient))].filter((address) => !isIgnorableAddress(address));
    ctx.danger.push(
      `you receive NOTHING from this order in exchange for ${input}: ${
        others.length > 0 ? `its outputs go to ${others.slice(0, 3).join(", ")}` : "none of its outputs goes to you"
      }`,
    );
    return;
  }
  const valuable = entries.some((entry) => entry.amount === undefined || !isDust(ctx.chain, entry.token, entry.amount));
  if (valuable && mine.every((output) => output.amount !== undefined && isDust(ctx.chain, assetOf(output.token), output.amount))) {
    ctx.danger.push(`you receive only ${describe(mine)} (at the lowest point of the price) in exchange for ${input} (typical of drainer orders)`);
  } else if (mine.every((output) => !isKnownValueToken(ctx.chain, assetOf(output.token)))) {
    ctx.warnings.push(`you are paid only in token(s) whose value x402check does not know: check that ${describe(mine)} is worth ${input}`);
  }
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
  const proxy = X402_PROXIES.get(spender);

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
    const witness = ctx.message.witness;
    const outputs: Output[] = [];
    collectOutputs(ctx.types, witnessType, witness, outputs);
    const visits: AddressVisit[] = [];
    collectAddressFields(ctx.types, witnessType, witness, "witness", visits);
    let swapper: string | undefined;
    for (const visit of visits) {
      if (visit.key !== "swapper") continue;
      swapper ??= visit.address;
      if (ctx.signer && visit.address !== ctx.signer) ctx.warnings.push(`the order's swapper ${visit.address} is not the signing account`);
    }
    const you = new Set([ctx.signer, swapper].filter((address): address is string => address !== undefined));
    // A witness `to` (x402 exact and upto: Witness{to, validAfter[, facilitator]})
    // is where the permitted tokens are paid: the payee, bound to the permit.
    const payee = fieldType(ctx.types, witnessType, "to") === "address" && isCanonStruct(witness) ? canonAddressValue(witness.to) : undefined;
    const single = entries.length === 1 ? entries[0] : undefined;
    const paid = single ? assetAmount(ctx.chain, single.token, single.amount) : "the permitted tokens";
    if (payee && !you.has(payee) && !isIgnorableAddress(payee)) {
      candidates.push({
        address: payee,
        role: "recipient",
        interaction: interaction("token_transfer"),
        rank: RANK.orderOutput,
        reason: `is paid up to ${paid} (witness "to")`,
        amountLabel: paid,
        payment: single
          ? payment({ network: ctx.chain, pay_to: payee, amount: single.amount?.toString(), asset: single.token })
          : payment({ network: ctx.chain, pay_to: payee }),
      });
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
    if (hasOutputList(ctx.types, witnessType)) analyzeOrderOutputs(ctx, entries, outputs, you);
    if (payee) witnessText += ` Pays up to ${paid} to ${you.has(payee) ? "you" : payee} (witness "to")${proxy ? ": an x402 payment" : ""}.`;
    if (!payee || outputs.length > 0) {
      const listed = outputs
        .slice(0, 3)
        .map((output) => `${output.amount !== undefined ? tokenAmount(output.amount, ctx.chain, output.token) : tokenLabel(ctx.chain, output.token)} to ${output.recipient === ctx.signer ? "you" : output.recipient}`);
      witnessText += ` Order (${capText(baseType(witnessType) ?? "witness", 40)}) outputs: ${listed.join("; ") || "none decoded"}.`;
    }
  }
  return done(
    ctx,
    {
      action: `Permit2 ${ctx.primaryType}`,
      unlimited,
      amountLabel,
      summary: `Permit2 ${ctx.primaryType} signature (${domainLabel(ctx)}): lets spender ${spender}${proxy ? ` (${proxy})` : ""} transfer ${shown.join("; ")} out of the signer's wallet${
        deadline ? `, deadline ${deadline}` : ""
      }.${witnessText}`,
    },
    candidates,
  );
}

// ---------------------------------------------------------------------------
// Marketplace orders
// ---------------------------------------------------------------------------

type SeaItem = { itemType: number; token?: string | undefined; id?: bigint | undefined; start?: bigint | undefined; end?: bigint | undefined; recipient?: string | undefined };

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
    markOpaque(
      ctx,
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
// ERC-20 limit orders: 1inch (v2-v4), 0x v4, CoW Protocol and similar shapes
// ---------------------------------------------------------------------------

const MAKER_TOKEN_FIELDS = ["makerAsset", "makerToken", "sellToken"];
const TAKER_TOKEN_FIELDS = ["takerAsset", "takerToken", "buyToken"];
const MAKER_AMOUNT_FIELDS = ["makingAmount", "makerAmount", "sellAmount"];
const TAKER_AMOUNT_FIELDS = ["takingAmount", "takerAmount", "buyAmount"];
/** 1inch v3 `interactions`, in `offsets` order (eight uint32 end offsets). */
const V3_INTERACTIONS = ["makerAssetData", "takerAssetData", "getMakingAmount", "getTakingAmount", "predicate", "permit", "preInteraction", "postInteraction"];

type FieldKind = "address" | "uint" | "bytes" | "string";

function declaredAs(ctx: Ctx, field: string, kind: FieldKind): boolean {
  const type = declared(ctx, ctx.primaryType, field);
  return kind === "uint" ? type !== undefined && /^uint\d{0,3}$/u.test(type) : type === kind;
}

function firstField(ctx: Ctx, names: string[], kind: FieldKind): string | undefined {
  return names.find((name) => declaredAs(ctx, name, kind));
}

const abiWord = (value: bigint): string => value.toString(16).padStart(64, "0");

function bit(value: bigint, index: number): boolean {
  return ((value >> BigInt(index)) & 1n) === 1n;
}

/** 1inch v4 `makerTraits`: private taker, expiry, Permit2, and whether an (unseen) extension sets the amounts. */
function oneInchV4(ctx: Ctx, protocol: string, notes: string[]): void {
  const traits = num(ctx.message, "makerTraits") ?? 0n;
  const allowedSender = traits & ((1n << 80n) - 1n);
  if (allowedSender !== 0n) notes.push(`private order: only a taker whose address ends in ${allowedSender.toString(16).padStart(20, "0")} may fill it`);
  const expiration = (traits >> 80n) & ((1n << 40n) - 1n);
  if (expiration !== 0n) notes.push(`expires ${unixDate(expiration) ?? "?"}`);
  if (bit(traits, 248)) notes.push("your tokens are pulled through Permit2");
  if (bit(traits, 247)) notes.push("WETH proceeds are unwrapped to ETH");
  if (bit(traits, 252) || bit(traits, 251)) notes.push("it calls pre/post-interaction hooks");
  if (bit(traits, 249)) {
    markOpaque(
      ctx,
      `the ${protocol} has an extension (committed only by a hash in its salt) that can replace the signed amounts with a getter contract's, or add predicates, permits or hooks, so the price shown may not be the price paid`,
    );
  }
}

function splitV3Interactions(hex: string, offsets: bigint): string[] | undefined {
  const parts: string[] = [];
  let start = 0;
  for (let index = 0; index < V3_INTERACTIONS.length; index += 1) {
    const end = Number((offsets >> BigInt(32 * index)) & 0xffffffffn);
    if (end < start || end * 2 > hex.length) return undefined;
    parts.push(hex.slice(start * 2, end * 2));
    start = end;
  }
  return parts;
}

/** 1inch v3 `interactions`: custom amount getters decide the price actually paid. */
function oneInchV3(ctx: Ctx, protocol: string, notes: string[]): void {
  const hex = bytesHex(ctx.message.interactions);
  if (hex === undefined) {
    markOpaque(ctx, `the ${protocol}'s interactions could not be read`);
    return;
  }
  if (hex === "") return;
  const parts = splitV3Interactions(hex, num(ctx.message, "offsets") ?? 0n);
  if (!parts) {
    ctx.warnings.push("the order's interactions do not match its offsets, so it cannot be filled as signed");
    return;
  }
  // A getter of one byte ("x") only forbids partial fills; a longer one calls a contract that returns the amounts.
  if ((parts[2]?.length ?? 0) > 2 || (parts[3]?.length ?? 0) > 2) {
    markOpaque(ctx, `the ${protocol} computes its amounts with a getter contract (getMakingAmount / getTakingAmount), so the price shown may not be the price paid`);
  }
  const used = V3_INTERACTIONS.filter((name, index) => index !== 2 && index !== 3 && (parts[index]?.length ?? 0) > 0);
  if (used.length > 0) notes.push(`it carries ${used.join(", ")} data that x402check does not decode`);
}

/** 1inch v2: only no getter (exact fills) or the standard proportional getter keeps the signed price. */
function oneInchV2(ctx: Ctx, protocol: string, making: bigint | undefined, taking: bigint | undefined, notes: string[]): void {
  const standard = (field: string, selector: string): boolean => {
    if (declared(ctx, ctx.primaryType, field) === undefined) return true;
    const hex = bytesHex(ctx.message[field]);
    return hex === "" || (hex !== undefined && making !== undefined && taking !== undefined && hex === `${selector}${abiWord(making)}${abiWord(taking)}`);
  };
  if (!standard("getMakerAmount", "f4a215c3") || !standard("getTakerAmount", "296637bf")) {
    markOpaque(ctx, `the ${protocol} computes its amounts with custom getter calldata, so the price shown may not be the price paid`);
  }
  const used = ["makerAssetData", "takerAssetData", "predicate", "permit", "interaction"].filter((field) => (bytesHex(ctx.message[field])?.length ?? 0) > 0);
  if (used.length > 0) notes.push(`it carries ${used.join(", ")} data that x402check does not decode`);
}

/** CoW Protocol: kind, fee and balance sources. Returns true for a buy order. */
function cowOrder(ctx: Ctx, makerAsset: string | undefined, notes: string[]): boolean {
  const fee = num(ctx.message, "feeAmount");
  if (fee !== undefined && fee > 0n) notes.push(`plus a fee of ${assetAmount(ctx.chain, makerAsset, fee)}`);
  for (const field of ["sellTokenBalance", "buyTokenBalance"]) {
    const source = ctx.message[field];
    if (typeof source === "string" && source !== "" && source !== "erc20") notes.push(`${field} ${quote(source, 16)}`);
  }
  if (ctx.message.partiallyFillable === true) notes.push("partially fillable");
  return ctx.message.kind === "buy";
}

/**
 * ERC-20 limit orders: 1inch Limit Order Protocol (v2-v4 `Order`), 0x v4
 * (`LimitOrder`, `RfqOrder`, `OtcOrder`), CoW Protocol (`Order`) and orders of
 * the same shape. You give the maker amount; nothing or dust in return is
 * proven danger, as for Seaport. A foreign receiver of the proceeds, a private
 * taker and fee recipients are checked with the amounts they get.
 *
 * @param ctx - Decoding context.
 * @returns The decoded order, or undefined when the shape does not match.
 */
function decodeErc20Order(ctx: Ctx): Decoded | undefined {
  if (!isOrderType(ctx.primaryType)) return undefined;
  const makerTokenField = firstField(ctx, MAKER_TOKEN_FIELDS, "address");
  const takerTokenField = firstField(ctx, TAKER_TOKEN_FIELDS, "address");
  const makerAmountField = firstField(ctx, MAKER_AMOUNT_FIELDS, "uint");
  const takerAmountField = firstField(ctx, TAKER_AMOUNT_FIELDS, "uint");
  if (!makerTokenField || !takerTokenField || !makerAmountField || !takerAmountField) return undefined;
  const m = ctx.message;
  const cow = makerTokenField === "sellToken" && declaredAs(ctx, "kind", "string");
  const protocol = declaredAs(ctx, "makerTraits", "uint")
    ? "1inch limit order (v4)"
    : declaredAs(ctx, "interactions", "bytes")
      ? "1inch limit order (v3)"
      : declaredAs(ctx, "getMakerAmount", "bytes") || declaredAs(ctx, "getTakerAmount", "bytes")
        ? "1inch limit order (v2)"
        : makerTokenField === "makerToken" && /^(?:LimitOrder|RfqOrder|OtcOrder)$/u.test(ctx.primaryType)
          ? `0x v4 ${ctx.primaryType}`
          : cow
            ? "CoW Protocol order"
            : `ERC-20 order (${capText(ctx.primaryType, 40)}, ${ctx.domainName ? quote(ctx.domainName, 40) : "unnamed domain"})`;

  const hasMaker = declaredAs(ctx, "maker", "address");
  const maker = hasMaker ? addr(m, "maker") : ctx.signer;
  if (hasMaker && !maker) return unresolved(ctx, protocol, "maker");
  if (hasMaker && maker && ctx.signer && maker !== ctx.signer) ctx.warnings.push(`the order's maker ${maker} is not the signing account`);
  const you = maker ?? ctx.signer;

  const makerAsset = assetOf(addr(m, makerTokenField));
  const takerAsset = assetOf(addr(m, takerTokenField));
  const makerAmount = num(m, makerAmountField);
  const takerAmount = num(m, takerAmountField);
  const gives = assetAmount(ctx.chain, makerAsset, makerAmount);
  const gets = assetAmount(ctx.chain, takerAsset, takerAmount);

  // The proceeds go to `receiver` (1inch, CoW); the zero address means the maker.
  let receiver = you;
  if (declaredAs(ctx, "receiver", "address")) {
    const named = addr(m, "receiver");
    if (!named) return unresolved(ctx, protocol, "receiver");
    if (!isIgnorableAddress(named)) receiver = named;
  }
  const foreignReceiver = receiver !== undefined && receiver !== you && receiver !== ctx.signer;
  // Only provable when the maker is known.
  const elsewhere = foreignReceiver && you !== undefined;

  const notes: string[] = [];
  const candidates: Candidate[] = [];
  if (foreignReceiver && receiver) {
    candidates.push({
      address: receiver,
      role: "recipient",
      interaction: interaction("order_signature"),
      rank: RANK.orderOutput,
      reason: `receives the order's proceeds (${gets})`,
      amountLabel: gets,
      payment: payment({ network: ctx.chain, pay_to: receiver, amount: takerAmount?.toString(), asset: takerAsset }),
    });
  }
  // A private order: only this taker can fill it, and it receives what you sell.
  for (const field of ["taker", "allowedSender"]) {
    if (!declaredAs(ctx, field, "address")) continue;
    const taker = addr(m, field);
    if (!taker || isIgnorableAddress(taker) || taker === you) continue;
    notes.push(`only ${taker} may fill it`);
    candidates.push({
      address: taker,
      role: "counterparty",
      interaction: interaction("order_signature"),
      rank: RANK.transfer,
      reason: `the only account allowed to fill the order (it receives ${gives})`,
      payment: payment({ network: ctx.chain, pay_to: taker, amount: makerAmount?.toString(), asset: makerAsset }),
    });
  }
  // 0x v4: the taker's fee goes to `feeRecipient`; `sender` / `txOrigin` restrict who submits the fill.
  if (declaredAs(ctx, "feeRecipient", "address")) {
    const feeRecipient = addr(m, "feeRecipient");
    const fee = num(m, "takerTokenFeeAmount");
    if (feeRecipient && !isIgnorableAddress(feeRecipient) && feeRecipient !== you && fee !== undefined && fee > 0n) {
      const feeText = assetAmount(ctx.chain, takerAsset, fee);
      notes.push(`the taker also pays a fee of ${feeText} to ${feeRecipient}`);
      candidates.push({
        address: feeRecipient,
        role: "recipient",
        interaction: interaction("order_signature"),
        rank: RANK.transfer - 1,
        reason: `receives the taker's fee (${feeText})`,
        payment: payment({ network: ctx.chain, pay_to: feeRecipient, amount: fee.toString(), asset: takerAsset }),
      });
    }
  }
  for (const field of ["sender", "txOrigin"]) {
    if (!declaredAs(ctx, field, "address")) continue;
    const who = addr(m, field);
    if (!who || isIgnorableAddress(who) || who === you) continue;
    notes.push(`only ${who} may submit the fill (${field})`);
    candidates.push({ address: who, role: "counterparty", interaction: interaction("order_signature"), rank: RANK.contract, reason: `the only account allowed to submit the fill (${field})` });
  }
  if (protocol.endsWith("(v4)")) oneInchV4(ctx, protocol, notes);
  else if (protocol.endsWith("(v3)")) oneInchV3(ctx, protocol, notes);
  else if (protocol.endsWith("(v2)")) oneInchV2(ctx, protocol, makerAmount, takerAmount, notes);
  const buy = cow && cowOrder(ctx, makerAsset, notes);

  // The price: what you give against what the order pays you.
  if (makerAmount === undefined || makerAmount > 0n) {
    if (elsewhere) {
      ctx.danger.push(`you receive NOTHING from this order: its proceeds (${gets}) go to ${receiver}, while it sells ${gives} of yours`);
    } else if (takerAmount === 0n) {
      ctx.danger.push(`the order sells ${gives} for NOTHING (0 ${assetLabel(ctx.chain, takerAsset)})`);
    } else if (
      takerAmount !== undefined &&
      (makerAmount === undefined || !isDust(ctx.chain, makerAsset, makerAmount)) &&
      isDust(ctx.chain, takerAsset, takerAmount)
    ) {
      ctx.danger.push(`the order sells ${gives} for only ${gets} (typical of drainer orders)`);
    } else if (!isKnownValueToken(ctx.chain, takerAsset)) {
      ctx.warnings.push(`the order pays in ${assetLabel(ctx.chain, takerAsset)}, whose value x402check does not know: check that ${gets} is worth ${gives}`);
    } else if (!isKnownValueToken(ctx.chain, makerAsset)) {
      ctx.warnings.push(`the order sells ${assetLabel(ctx.chain, makerAsset)}, whose value x402check does not know, for ${gets}: check the price`);
    }
  }
  const trade = buy ? `buys ${gets} for at most ${gives}` : `sells ${gives} for ${cow ? "at least " : ""}${gets}`;
  const proceeds = foreignReceiver ? receiver : you !== undefined && you === ctx.signer ? "you" : "the maker";
  return orderResult(
    ctx,
    protocol,
    `${protocol} signature (${domainLabel(ctx)}): ${hasMaker && maker ? `maker ${maker} ` : ""}${trade}; the proceeds go to ${proceeds}${
      notes.length > 0 ? `; ${notes.join("; ")}` : ""
    }.`,
    candidates,
  );
}

// ---------------------------------------------------------------------------
// Calls signed as typed data
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
  if (data === undefined) {
    ctx.warnings.push("the Safe transaction's data could not be decoded");
    markOpaque(ctx, "the Safe transaction's data could not be read");
  }
  const action = decodeCallAction(
    { sender: ctx.verifyingContract, to, value, data: data ?? "", delegate: operation === 1n },
    ctx.chain,
    ctx.signer,
  );
  absorb(ctx, action);
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

/** First 20 bytes of a `bytes` value (the factory of an initCode, the paymaster of paymasterAndData). */
function leadingAddress(value: CanonValue): string | undefined {
  const hex = bytesHex(value);
  return hex !== undefined && hex.length >= 40 ? `0x${hex.slice(0, 40)}` : undefined;
}

/** EntryPoint v0.8 marks the initCode of an EIP-7702 account with this prefix. */
const EIP7702_INITCODE = "0x7702000000000000000000000000000000000000";

/**
 * ERC-4337 user operations (v0.8 PackedUserOperation, UserOperation) and Safe
 * 4337 operations (SafeOp): the EntryPoint calls the account (`sender` /
 * `safe`) with `callData`, so it is decoded as a call the account makes to
 * itself: execute / executeBatch of SimpleAccount, LightAccount, Coinbase Smart
 * Wallet, Kernel, Biconomy, ERC-7579 accounts and the Safe 4337 module. Calldata
 * that is not one of those entry points is opaque.
 *
 * @param ctx - Decoding context.
 * @returns The decoded operation, or undefined when the shape does not match.
 */
function decodeUserOperation(ctx: Ctx): Decoded | undefined {
  const type = ctx.primaryType;
  if (declared(ctx, type, "callData") !== "bytes") return undefined;
  const accountField = declared(ctx, type, "sender") === "address" ? "sender" : declared(ctx, type, "safe") === "address" ? "safe" : undefined;
  if (!accountField) return undefined;
  const kind = accountField === "safe" ? "Safe 4337 operation" : "ERC-4337 user operation";
  const account = addr(ctx.message, accountField);
  if (!account) return unresolved(ctx, kind, accountField);
  const data = bytesHex(ctx.message.callData);
  let action: Action;
  if (data === undefined) {
    markOpaque(ctx, `the ${kind}'s callData could not be read`);
    action = { label: "unreadable call", summary: "its callData could not be read.", candidates: [], warnings: [], danger: [] };
  } else if (data === "") {
    action = { label: "no call", summary: "it makes no call (empty callData).", candidates: [], warnings: [], danger: [] };
  } else {
    action = decodeCallAction({ sender: account, to: account, value: 0n, data }, ctx.chain, ctx.signer);
  }
  absorb(ctx, action);
  const candidates = [...action.candidates];
  const extras: string[] = [];
  const factory = leadingAddress(ctx.message.initCode);
  if (factory === EIP7702_INITCODE) {
    extras.push("the account is an EIP-7702 delegated account");
  } else if (factory && !isIgnorableAddress(factory)) {
    extras.push(`it deploys the account through factory ${factory}`);
    candidates.push({ address: factory, role: "contract", interaction: interaction("contract_call"), rank: RANK.contract - 1, reason: "deploys the account (initCode factory)" });
  }
  const paymaster = leadingAddress(ctx.message.paymasterAndData);
  if (paymaster && !isIgnorableAddress(paymaster)) {
    extras.push(`paymaster ${paymaster} pays the gas`);
    candidates.push({ address: paymaster, role: "contract", interaction: interaction("contract_call"), rank: RANK.contract - 2, reason: "pays the gas (paymaster)" });
  }
  const entryPoint = addr(ctx.message, "entryPoint") ?? ctx.verifyingContract;
  return done(
    ctx,
    {
      action: `${kind}: ${action.label}`,
      summary: `${kind} signature for account ${account}${entryPoint ? ` (EntryPoint ${entryPoint})` : ""}: ${action.summary}${
        extras.length > 0 ? ` Also: ${extras.join("; ")}.` : ""
      }`,
    },
    candidates,
    [account, ctx.signer],
  );
}

/**
 * ERC-2771 forward requests (OpenZeppelin MinimalForwarder / ERC2771Forwarder,
 * GSN, Biconomy): the forwarder calls `to` with `data`, and the target treats
 * `from` as the caller.
 *
 * @param ctx - Decoding context.
 * @returns The decoded request, or undefined when the shape does not match.
 */
function decodeForwardRequest(ctx: Ctx): Decoded | undefined {
  const type = ctx.primaryType;
  if (declared(ctx, type, "from") !== "address" || declared(ctx, type, "to") !== "address" || declared(ctx, type, "data") !== "bytes") return undefined;
  const from = addr(ctx.message, "from");
  if (!from) return unresolved(ctx, "forwarded call", "from");
  const to = addr(ctx.message, "to");
  if (!to) return unresolved(ctx, "forwarded call", "to");
  if (ctx.signer && from !== ctx.signer) ctx.warnings.push(`the request acts for account ${from}, not the signing account`);
  const value = declared(ctx, type, "value")?.startsWith("uint") ? (num(ctx.message, "value") ?? 0n) : 0n;
  const data = bytesHex(ctx.message.data);
  if (data === undefined) markOpaque(ctx, "the forwarded call's data could not be read");
  const action = decodeCallAction({ sender: from, to, value, data: data ?? "" }, ctx.chain, ctx.signer);
  absorb(ctx, action);
  return done(
    ctx,
    {
      action: `Forwarded call (ERC-2771): ${action.label}`,
      summary: `ERC-2771 forward request (${quote(type, 40)}, ${domainLabel(ctx)}): a call from ${from} to ${to}${
        value > 0n ? ` with ${nativeAmount(value, ctx.chain)}` : ""
      }: ${action.summary}`,
    },
    action.candidates,
    [from, ctx.signer],
  );
}

/**
 * EIP712Base meta-transactions (Polygon PoS tokens and contracts):
 * `functionSignature` is calldata the verifying contract executes as `from`.
 * Their domain carries the chain id in `salt`.
 *
 * @param ctx - Decoding context.
 * @returns The decoded meta-transaction, or undefined when the shape does not match.
 */
function decodeMetaTransaction(ctx: Ctx): Decoded | undefined {
  const type = ctx.primaryType;
  if (declared(ctx, type, "functionSignature") !== "bytes" || declared(ctx, type, "from") !== "address") return undefined;
  const from = addr(ctx.message, "from");
  if (!from) return unresolved(ctx, "meta-transaction", "from");
  if (ctx.signer && from !== ctx.signer) ctx.warnings.push(`the meta-transaction acts for account ${from}, not the signing account`);
  const salt = ctx.canon.domain.salt;
  if (!ctx.chain && typeof salt === "string" && isStrictHexString(salt) && salt.length <= 66) ctx.chain = normalizeChainId(BigInt(salt));
  const to = ctx.verifyingContract;
  if (!to) {
    markOpaque(ctx, "the meta-transaction's domain names no verifying contract, so the contract it calls is unknown");
    return done(ctx, { action: "Meta-transaction", summary: `Meta-transaction (${quote(type, 40)}) for ${from} on an unknown contract.` }, []);
  }
  const data = bytesHex(ctx.message.functionSignature);
  if (data === undefined) markOpaque(ctx, "the meta-transaction's functionSignature could not be read");
  const action = decodeCallAction({ sender: from, to, value: 0n, data: data ?? "" }, ctx.chain, ctx.signer);
  absorb(ctx, action);
  return done(
    ctx,
    {
      action: `Meta-transaction: ${action.label}`,
      summary: `Meta-transaction (EIP712Base ${quote(type, 40)}, ${domainLabel(ctx)}): a call from ${from} to ${to}: ${action.summary}`,
    },
    action.candidates,
    [from, ctx.signer],
  );
}

// ---------------------------------------------------------------------------
// ERC-7739 nested signatures (smart accounts: Solady, Coinbase, Kernel...)
// ---------------------------------------------------------------------------

/**
 * TypedDataSign wraps the app's typed data (`contents`, under the app's own
 * domain) for a smart account (the message's name / version / chainId /
 * verifyingContract). The contents are decoded as what they are, for the
 * account: a wrapped permit keeps its permit semantics.
 *
 * @param ctx - Decoding context.
 * @returns The decoded contents, or undefined when the shape does not match.
 */
function decodeTypedDataSign(ctx: Ctx): Decoded | undefined {
  const contentsType = declared(ctx, "TypedDataSign", "contents");
  if (contentsType === undefined) return undefined;
  const account = addr(ctx.message, "verifyingContract");
  const name = ctx.message.name;
  const head = `ERC-7739 nested signature (TypedDataSign) for smart account ${account ?? "(unknown)"}${typeof name === "string" && name ? ` (${quote(name, 40)})` : ""}`;
  const rawMessage = isRecord(ctx.raw.message) ? ctx.raw.message : {};
  if (!hasOwn(ctx.types, contentsType) || ctx.depth >= MAX_NESTING || !isRecord(rawMessage.contents)) {
    markOpaque(ctx, `the contents of this ERC-7739 wrapper (type ${quote(contentsType, 40)}) could not be decoded`);
    return done(ctx, { action: "ERC-7739 nested signature", summary: `${head}: its contents could not be decoded.` }, []);
  }
  const inner = decodeParsed(
    { types: ctx.raw.types, primaryType: contentsType, domain: ctx.raw.domain, message: rawMessage.contents },
    account ?? ctx.signer,
    ctx.method,
    ctx.depth + 1,
  );
  // Notes about the contents come back from the inner decoding, with their own paths.
  const warnings = ctx.warnings.filter((warning) => !warning.includes("message.contents"));
  const danger = ctx.danger.filter((reason) => !reason.includes("message.contents"));
  const accountChain = typeof ctx.message.chainId === "bigint" ? normalizeChainId(ctx.message.chainId) : undefined;
  if (accountChain && ctx.chain && accountChain !== ctx.chain) warnings.push(`the smart account's domain is for ${accountChain}, the app's domain for ${ctx.chain}`);
  const opaque = opaqueReason([...ctx.opaque, ...(inner.opaque ? [inner.opaque] : [])]);
  return {
    ...inner,
    action: `ERC-7739: ${inner.action}`,
    summary: `${head}: ${inner.summary}`,
    warnings: dedupe([...ctx.opaque.map(opaqueNote), ...inner.warnings, ...warnings]),
    danger: dedupe([...danger, ...inner.danger]),
    ...(opaque ? { opaque } : {}),
  };
}

/** "\x19Ethereum Signed Message:\n", hex. */
const PERSONAL_PREFIX = "19457468657265756d205369676e6564204d6573736167653a0a";

/** The message inside an EIP-191 prefixed payload ("\x19Ethereum Signed Message:\n" + length + message). */
function unprefix(hex: string): string | undefined {
  if (!hex.startsWith(PERSONAL_PREFIX)) return undefined;
  let digits = "";
  for (let index = PERSONAL_PREFIX.length; index + 2 <= hex.length && digits.length < 10; index += 2) {
    const code = parseInt(hex.slice(index, index + 2), 16);
    if (code < 0x30 || code > 0x39) break;
    digits += String.fromCharCode(code);
    // The message may itself start with digits: accept the split whose length matches.
    const rest = hex.length - (index + 2);
    if (Number(digits) * 2 === rest) return hex.slice(index + 2);
  }
  return undefined;
}

function isReadableText(hex: string): boolean {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  try {
    return isMostlyPrintable(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return false;
  }
}

/**
 * PersonalSign(bytes prefixed): a smart account's personal_sign (ERC-7739).
 * A text message is decoded like personal_sign; binary data (a hash) is opaque.
 *
 * @param ctx - Decoding context.
 * @returns The decoded message, or undefined when the shape does not match.
 */
function decodeNestedPersonalSign(ctx: Ctx): Decoded | undefined {
  if (declared(ctx, "PersonalSign", "prefixed") !== "bytes") return undefined;
  const account = ctx.verifyingContract;
  const head = `ERC-7739 nested personal message (PersonalSign) for smart account ${account ?? "(unknown)"}`;
  const hex = bytesHex(ctx.message.prefixed);
  const message = hex === undefined ? undefined : unprefix(hex);
  if (message === undefined) {
    markOpaque(ctx, "this ERC-7739 PersonalSign payload is not a readable Ethereum signed message");
    return done(ctx, { action: "ERC-7739 personal message", summary: `${head}: its payload could not be decoded.` }, []);
  }
  if (message.length > 0 && !isReadableText(message)) {
    markOpaque(
      ctx,
      `smart account ${account ?? "(unknown)"} would sign ${message.length / 2} bytes of binary data${message.length === 64 ? " (a 32-byte hash)" : ""} as a personal message, which can authorize anything the account accepts`,
    );
  }
  const inner = decodePersonalSign(`0x${message}`, account ?? ctx.signer);
  const opaque = opaqueReason(ctx.opaque);
  return {
    ...inner,
    action: `ERC-7739: ${inner.action}`,
    chain: inner.chain ?? ctx.chain,
    summary: `${head}: ${inner.summary}`,
    warnings: dedupe([...ctx.opaque.map(opaqueNote), ...inner.warnings, ...ctx.warnings]),
    danger: dedupe([...ctx.danger, ...inner.danger]),
    ...(opaque ? { opaque } : {}),
  };
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

/**
 * A fixed-size bytes field with one of these names carries a hash (of a
 * transaction, a message, an action) that authorizes something; nonces, salts
 * and ids do not. The names are fixed by the contract that verifies the
 * signature, not chosen by whoever asks for it.
 */
const HASH_FIELD_RE = /(?:hash|digest|root|message|msg|payload|contents?|calldata|data|operation|connectionid)$/iu;
/** Fields that are never the payload of a hash wrapper. */
const PLAIN_FIELD_RE = /^(?:nonce|salt|deadline|expiry|expiration|validafter|validbefore|validuntil|timestamp|time|chainid|version|name)$/iu;
const FIXED_BYTES_RE = /^bytes\d{1,2}$/u;

type Payload = { path: string; type: string; size: number };

/** Declared `bytes` values and hash-named fixed bytes, anywhere in the message. */
function collectPayloads(types: TypedTypes, type: string, value: CanonValue, path: string, name: string, out: Payload[], depth = 0): void {
  if (depth > 10 || out.length >= 4) return;
  if (type.endsWith("]")) {
    if (!Array.isArray(value)) return;
    const itemType = type.slice(0, type.lastIndexOf("["));
    for (let index = 0; index < Math.min(value.length, 64); index += 1) {
      collectPayloads(types, itemType, value[index], `${path}[${index}]`, name, out, depth + 1);
    }
    return;
  }
  if (hasOwn(types, type)) {
    if (!isCanonStruct(value)) return;
    for (const field of types[type] ?? []) {
      collectPayloads(types, field.type, value[field.name], path ? `${path}.${field.name}` : field.name, field.name, out, depth + 1);
    }
    return;
  }
  if (typeof value !== "string" || !value.startsWith("0x")) return;
  const size = (value.length - 2) / 2;
  const payload = type === "bytes" ? size > 0 : FIXED_BYTES_RE.test(type) && HASH_FIELD_RE.test(name) && /[1-9a-f]/u.test(value.slice(2));
  if (payload) out.push({ path, type, size });
}

/** A message whose only meaningful content is fixed bytes (`Foo(bytes32 x)`): a hash wrapper. */
function hashWrapper(ctx: Ctx): Payload | undefined {
  const fields = (ctx.types[ctx.primaryType] ?? []).filter((field) => field.type !== "address" && !PLAIN_FIELD_RE.test(field.name));
  const [first] = fields;
  if (!first || !fields.every((field) => FIXED_BYTES_RE.test(field.type))) return undefined;
  const value = ctx.message[first.name];
  return typeof value === "string" && /[1-9a-f]/u.test(value.slice(2)) ? { path: first.name, type: first.type, size: (value.length - 2) / 2 } : undefined;
}

function payloadReason(ctx: Ctx, payloads: Payload[]): string {
  const fields = payloads
    .slice(0, 2)
    .map((payload) => `"${capText(payload.path, 40)}" (${payload.type}, ${payload.size} bytes${payload.size === 32 ? ", likely a hash" : ""})`);
  const subject =
    ctx.primaryType === "SafeMessage"
      ? `this Safe message (SafeMessage for Safe ${ctx.verifyingContract ?? "(unknown)"})`
      : `the typed data ${quote(ctx.primaryType || "unknown", 40)}`;
  return `${subject} signs ${fields.join(" and ")}${payloads.length > 2 ? " and more" : ""}, which x402check cannot read: a hash or calldata can stand for any transaction, permit or order the verifying contract accepts`;
}

function decodeGeneric(ctx: Ctx): Decoded {
  const order = isOrderType(ctx.primaryType, ctx.domainName);
  const kind = PERMIT_TYPES.has(ctx.primaryType)
    ? interaction("permit_signature")
    : order
      ? interaction("order_signature")
      : interaction("message_signature");
  // What an unrecognized type signs is only readable when it is not a hash or calldata.
  const payloads: Payload[] = [];
  collectPayloads(ctx.types, ctx.primaryType, ctx.message, "", "", payloads);
  if (payloads.length === 0) {
    const wrapper = hashWrapper(ctx);
    if (wrapper) payloads.push(wrapper);
  }
  if (payloads.length > 0) markOpaque(ctx, payloadReason(ctx, payloads));
  if (order) {
    ctx.warnings.push("x402check does not know this order format, so it cannot tell what you give and what you receive: check the amounts and tokens");
  }
  const visits: AddressVisit[] = [];
  collectAddressFields(ctx.types, ctx.primaryType, ctx.message, "", visits);
  const skip = new Set([ctx.signer, ctx.verifyingContract].filter(Boolean));
  const usable = visits.filter((visit) => !skip.has(visit.address) && !isIgnorableAddress(visit.address));
  const head = `EIP-712 signature (${ctx.method}, ${domainLabel(ctx)}, primary type ${quote(ctx.primaryType || "unknown", 40)})`;
  const details = scalarFields(ctx, order ? 8 : 6).join("; ");
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

/** Field names that carry the economics of a request (listed first in the context). */
const ECONOMIC_FIELD_RE = /amount|price|value|token|asset|fee|receiver|recipient|taker|maker|sell|buy|input|output/iu;

/** A few declared scalar fields as "path=value", for context; amounts and tokens first. */
function scalarFields(ctx: Ctx, limit: number): string[] {
  const found: { text: string; economic: boolean }[] = [];
  const walk = (type: string, value: CanonValue, path: string, name: string, depth: number) => {
    if (found.length >= 48 || depth > 4) return;
    const fields = ctx.types[type];
    if (fields && isCanonStruct(value)) {
      for (const field of fields) walk(field.type, value[field.name], path ? `${path}.${field.name}` : field.name, field.name, depth + 1);
      return;
    }
    let text: string | undefined;
    if (Array.isArray(value)) text = `${path}=[${value.length} items]`;
    else if (typeof value === "bigint" || typeof value === "boolean") text = `${path}=${value.toString()}`;
    else if (typeof value === "string") text = `${path}=${capText(cleanText(value, 256).text, 48)}`;
    if (text !== undefined) found.push({ text, economic: ECONOMIC_FIELD_RE.test(name) });
  };
  walk(ctx.primaryType, ctx.message, "", "", 0);
  return [...found.filter((field) => field.economic), ...found.filter((field) => !field.economic)].slice(0, limit).map((field) => field.text);
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
  return decodeParsed(parsed, signer, method, 0);
}

/**
 * Decodes parsed v3/v4 typed data (also the contents of an ERC-7739 wrapper).
 *
 * @param parsed - The typed data object.
 * @param signer - The signing account (for wrapped contents: the smart account).
 * @param method - The signature method, for the summary.
 * @param depth - ERC-7739 nesting depth.
 * @returns The decoded request.
 */
function decodeParsed(parsed: unknown, signer: string | undefined, method: string, depth: number): Decoded {
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
    opaque: [],
    raw: isRecord(parsed) ? parsed : {},
    depth,
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
    case "TypedDataSign":
      decoded = decodeTypedDataSign(ctx);
      break;
    case "PersonalSign":
      decoded = decodeNestedPersonalSign(ctx);
      break;
    default:
      decoded =
        decodeSeaport(ctx) ??
        decodeBlur(ctx) ??
        decodeLooksRare(ctx) ??
        decodeErc20Order(ctx) ??
        decodeUserOperation(ctx) ??
        decodeMetaTransaction(ctx) ??
        decodeForwardRequest(ctx);
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
  // A bytes value, or a hash-named fixed bytes value, is something the signer cannot read.
  const payloads = fields.filter((field) => {
    if (typeof field.value !== "string") return false;
    const hex = field.value.replace(/^0x/iu, "");
    if (field.type === "bytes") return hex.length > 0;
    return FIXED_BYTES_RE.test(field.type) && HASH_FIELD_RE.test(field.name) && /[1-9a-f]/iu.test(hex);
  });
  const opaque =
    payloads.length > 0
      ? `the legacy typed data signs ${payloads
          .slice(0, 2)
          .map((field) => `"${capText(cleanText(field.name, 64).text, 24)}" (${capText(field.type, 16)})`)
          .join(" and ")}, which x402check cannot read: a hash or calldata can authorize anything`
      : undefined;
  const notes = opaque ? { warnings: [opaqueNote(opaque)], danger: [], opaque } : { warnings: [], danger: [] };
  const head = `Legacy typed-data signature (eth_signTypedData v1) with ${fields.length} field(s): ${listed}`;
  const kind = interaction("message_signature");
  const preferred = visits.find((visit) => keyRank(visit.key) !== undefined) ?? visits[0];
  if (preferred) {
    const info = keyRank(preferred.key);
    return withCandidates(
      {
        action: "Typed data (v1)",
        summary: `${head}. Counterparty taken from field "${capText(preferred.key, 40)}" = ${preferred.address}.`,
        ...notes,
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
        ...notes,
        interaction: kind,
        localNote: "The request names no counterparty and the signing account is unknown, so there is nothing to check. Nothing was sent to x402check.",
      },
      [],
    );
  }
  return withCandidates({ action: "Typed data (v1)", summary, ...notes }, [{ address: signer, role: "signer", interaction: kind, rank: RANK.signer }]);
}
