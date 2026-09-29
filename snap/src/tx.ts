/**
 * Transaction (EVM calldata) decoding, including bounded recursive decoding of
 * wrapper calls: multicall, Safe execTransaction / multiSend, Universal Router
 * execute, ERC-7579 / ERC-4337 smart-account execute and EIP-7702 self-calls.
 */
import { planSimulation } from "./simulation";
import type { Candidate, Decoded } from "./util";
import {
  PERMIT2_ADDRESS,
  RANK,
  UNLIMITED_UINT160,
  UNLIMITED_UINT256,
  capText,
  describeAllowance,
  interaction,
  isIgnorableAddress,
  knownToken,
  nativeAmount,
  normalizeChainId,
  parseUint,
  payment,
  selectCandidates,
  tokenAmount,
  tokenLabel,
  unixDate,
  withCandidates,
} from "./util";

export type TransactionLike = {
  from?: unknown;
  to?: unknown;
  value?: unknown;
  data?: unknown;
  input?: unknown;
};

/** Calldata beyond this is not decoded (1 MiB). */
const MAX_CALLDATA_HEX = 2 * 1024 * 1024;
/** Wrapper nesting decoded below the top-level call. */
const MAX_DEPTH = 3;
/** Inner calls decoded per transaction. */
const MAX_INNER_CALLS = 48;
/** Items read from any dynamic array. */
const MAX_ARRAY = 32;

/** Safe MultiSend / MultiSendCallOnly deployments (1.3.0 and 1.4.1). */
const SAFE_MULTISEND = new Set([
  "0xa238cbeb142c10ef7ad8442c6d1f9e89e07e7761",
  "0x40a2accbd92bca938b02010e17a5b8929b49130d",
  "0x998739bfdaadde7c933b942a68053933098f9eda",
  "0xa1dabef33b3b82c7814b6d82a79e50f4ac44102b",
  "0x38869bf66a61cf6bdb996a6ae40d5853fd43b526",
  "0x9641d764fc13c8b624c04430c7356c1c7c8102e2",
]);

type Call = {
  /** Account whose funds/rights the call uses. */
  sender?: string;
  to: string;
  value: bigint;
  /** Lowercase hex without 0x. */
  data: string;
  /** Executed with DELEGATECALL (runs the target's code as the sender). */
  delegate?: boolean;
};

type Ctx = {
  chain?: string;
  /** The signing account (tx.from). */
  user?: string;
  depth: number;
  budget: { calls: number };
};

export type Action = {
  label: string;
  summary: string;
  candidates: Candidate[];
  warnings: string[];
  danger: string[];
};

// ---------------------------------------------------------------------------
// ABI reading (bounded; offsets validated)
// ---------------------------------------------------------------------------

/** 32-byte word at a byte offset, or undefined when out of bounds. */
function word(hex: string, offset: number): string | undefined {
  const start = offset * 2;
  if (!Number.isInteger(offset) || offset < 0 || start + 64 > hex.length) return undefined;
  return hex.slice(start, start + 64);
}

/** 32-byte word, zero-padded past the end like EVM calldataload. */
function paddedWord(hex: string, offset: number): string {
  const start = offset * 2;
  return hex.slice(start, start + 64).padEnd(64, "0");
}

function uintAt(hex: string, offset: number): bigint | undefined {
  const value = word(hex, offset);
  return value === undefined ? undefined : BigInt(`0x${value}`);
}

function wordAddress(value: string, warnings: string[]): string {
  if (!/^0{24}/u.test(value)) {
    const warning = "calldata encodes an address with non-zero padding (malformed or obfuscated)";
    if (!warnings.includes(warning)) warnings.push(warning);
  }
  return `0x${value.slice(24)}`;
}

function addressAt(hex: string, offset: number, warnings: string[]): string | undefined {
  const value = word(hex, offset);
  return value === undefined ? undefined : wordAddress(value, warnings);
}

/** A dynamic offset/length that fits the data. */
function smallAt(hex: string, offset: number): number | undefined {
  const value = uintAt(hex, offset);
  if (value === undefined || value > BigInt(hex.length / 2)) return undefined;
  return Number(value);
}

/** `bytes` whose length word is at `offset`. */
function bytesAt(hex: string, offset: number | undefined): string | undefined {
  if (offset === undefined) return undefined;
  const length = smallAt(hex, offset);
  if (length === undefined) return undefined;
  const start = (offset + 32) * 2;
  const end = start + length * 2;
  return end <= hex.length ? hex.slice(start, end) : undefined;
}

/** Head offset of an argument (relative to `base`), resolved to absolute. */
function dynamicAt(hex: string, headOffset: number, base = 0): number | undefined {
  const relative = smallAt(hex, headOffset);
  return relative === undefined ? undefined : base + relative;
}

/** `bytes[]` whose length word is at `offset`. */
function bytesArrayAt(hex: string, offset: number | undefined): string[] | undefined {
  if (offset === undefined) return undefined;
  const count = smallAt(hex, offset);
  if (count === undefined) return undefined;
  const base = offset + 32;
  const items: string[] = [];
  for (let index = 0; index < Math.min(count, MAX_ARRAY); index += 1) {
    const item = bytesAt(hex, dynamicAt(hex, base + index * 32, base));
    if (item === undefined) return items.length > 0 ? items : undefined;
    items.push(item);
  }
  return items;
}

/** `address[]` whose length word is at `offset`. */
function addressArrayAt(hex: string, offset: number | undefined, warnings: string[]): string[] | undefined {
  if (offset === undefined) return undefined;
  const count = smallAt(hex, offset);
  if (count === undefined) return undefined;
  const out: string[] = [];
  for (let index = 0; index < Math.min(count, MAX_ARRAY); index += 1) {
    const address = addressAt(hex, offset + 32 + index * 32, warnings);
    if (address === undefined) break;
    out.push(address);
  }
  return out;
}

function uintArrayAt(hex: string, offset: number | undefined): bigint[] | undefined {
  if (offset === undefined) return undefined;
  const count = smallAt(hex, offset);
  if (count === undefined) return undefined;
  const out: bigint[] = [];
  for (let index = 0; index < Math.min(count, MAX_ARRAY); index += 1) {
    const value = uintAt(hex, offset + 32 + index * 32);
    if (value === undefined) break;
    out.push(value);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Input normalization
// ---------------------------------------------------------------------------

function isHexChar(code: number): boolean {
  return (code >= 48 && code <= 57) || (code >= 65 && code <= 70) || (code >= 97 && code <= 102);
}

/**
 * Lowercase calldata hex without prefix ("" when empty), null when invalid.
 * Accepts 0x/0X/no prefix and any case; checked with a loop (no regex).
 *
 * @param value - The raw `data` / `input`.
 * @returns Normalized hex, "" or null.
 */
export function normalizeCalldata(value: unknown): string | null {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string") return null;
  let text = value.trim();
  if (text.startsWith("0x") || text.startsWith("0X")) text = text.slice(2);
  if (text.length === 0) return "";
  if (text.length % 2 === 1) return null;
  for (let index = 0; index < text.length; index += 1) {
    if (!isHexChar(text.charCodeAt(index))) return null;
  }
  return text.toLowerCase();
}

/** Lowercase address from 0x/0X + 40 hex (any case), else undefined. */
export function lenientAddress(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const text = value.trim();
  if (text.length !== 42 || text[0] !== "0" || (text[1] !== "x" && text[1] !== "X")) return undefined;
  const hex = text.slice(2);
  for (let index = 0; index < hex.length; index += 1) {
    if (!isHexChar(hex.charCodeAt(index))) return undefined;
  }
  return `0x${hex.toLowerCase()}`;
}

function isMissing(value: unknown): boolean {
  return (
    value === undefined ||
    value === null ||
    (typeof value === "string" && (value.trim() === "" || /^0x$/iu.test(value.trim())))
  );
}

// ---------------------------------------------------------------------------
// Helpers producing candidates
// ---------------------------------------------------------------------------

function contractCandidate(call: Call, ctx: Ctx, rank: number = RANK.contract): Candidate {
  return {
    address: call.to,
    role: "contract",
    interaction: interaction("contract_call"),
    rank,
    ...(call.value > 0n
      ? {
          payment: payment({ network: ctx.chain, pay_to: call.to, amount: call.value.toString(), asset: "native" }),
          amountLabel: nativeAmount(call.value, ctx.chain),
        }
      : {}),
  };
}

function plainCall(call: Call, ctx: Ctx, detail: string): Action {
  const sends = call.value > 0n ? `, sending ${nativeAmount(call.value, ctx.chain)}` : "";
  return {
    label: "Contract call",
    summary: `Contract call to ${call.to} (${detail})${sends}.`,
    candidates: [contractCandidate(call, ctx)],
    warnings: [],
    danger: [],
  };
}

function emptyAction(label: string, summary: string): Action {
  return { label, summary, candidates: [], warnings: [], danger: [] };
}

// ---------------------------------------------------------------------------
// Token and approval functions (static arguments)
// ---------------------------------------------------------------------------

type TokenDecoder = { name: string; words: number; payableWarning: boolean; decode: (args: string, call: Call, ctx: Ctx, warnings: string[]) => Action };

function approvalAction(
  call: Call,
  ctx: Ctx,
  warnings: string[],
  spender: string,
  amount: bigint,
  options: { label: string; fn: string; threshold: bigint; token: string; increase?: boolean },
): Action {
  const tokenText = tokenLabel(ctx.chain, options.token);
  if (amount === 0n) {
    if (options.increase) {
      return {
        label: `${options.label} (no change)`,
        summary: `${options.fn} on ${tokenText}: raises the allowance of spender ${spender} by 0.`,
        candidates: [{ address: spender, role: "spender", interaction: interaction("contract_call"), rank: RANK.revoke, amountLabel: "0" }],
        warnings,
        danger: [],
      };
    }
    if (knownToken(ctx.chain, options.token)) {
      return {
        label: `${options.label} (revoke)`,
        summary: `${options.fn} on ${tokenText}: sets the allowance of spender ${spender} to 0 (revokes it).`,
        candidates: [
          { address: spender, role: "spender", interaction: interaction("contract_call"), rank: RANK.revoke, amountLabel: "0 (revokes allowance)" },
        ],
        warnings,
        danger: [],
      };
    }
    // Without the token standard, approve(x, 0) is either an ERC-20 revocation or
    // an ERC-721 approval of token id 0 to x: treat it as an approval.
    return {
      label: "Token approve (revocation or NFT #0 approval)",
      summary: `${options.fn} on ${tokenText} with amount 0: an ERC-20 revocation, OR an ERC-721 approval of NFT #0 to spender ${spender} (the token standard is unknown, so it is treated as an approval).`,
      candidates: [
        {
          address: spender,
          role: "spender",
          interaction: interaction("token_approval"),
          rank: RANK.approval,
          reason: "may receive approval of NFT #0",
          amountLabel: "0 (revocation, or NFT #0 approval)",
          payment: payment({ network: ctx.chain, pay_to: spender, asset: options.token }),
        },
      ],
      warnings,
      danger: [],
    };
  }
  const allowance = describeAllowance(amount, options.threshold, warnings);
  // approve(address,uint256) is also ERC-721 approve(to, tokenId).
  const nftAmbiguous = options.fn === "ERC-20 approve" && !knownToken(ctx.chain, options.token);
  return {
    label: nftAmbiguous ? "Token approve" : options.label,
    summary: `${nftAmbiguous ? "Token approve" : options.fn} on ${tokenText}: ${options.increase ? "raises the allowance of" : "grants"} spender ${spender} ${
      options.increase ? `by ${allowance.unlimited ? "an UNLIMITED amount" : `${amount.toString()} base units`}` : allowance.phrase
    }${nftAmbiguous ? ` (or, if this is an NFT contract, approval of NFT #${amount.toString()})` : ""}.`,
    candidates: [
      {
        address: spender,
        role: "spender",
        interaction: interaction("token_approval", allowance.unlimited),
        rank: allowance.unlimited ? RANK.unlimitedApproval : RANK.approval,
        unlimited: allowance.unlimited,
        amountLabel: allowance.unlimited ? allowance.label : options.increase ? `+${amount.toString()} base units` : allowance.label,
        payment: payment({ network: ctx.chain, pay_to: spender, amount: amount.toString(), asset: options.token }),
      },
    ],
    warnings,
    danger: [],
  };
}

function transferAction(
  ctx: Ctx,
  warnings: string[],
  recipient: string,
  options: { label: string; summary: string; amountLabel: string; amount?: bigint; token: string },
): Action {
  return {
    label: options.label,
    summary: options.summary,
    candidates: [
      {
        address: recipient,
        role: "recipient",
        interaction: interaction("token_transfer"),
        rank: RANK.transfer,
        amountLabel: options.amountLabel,
        payment: payment({
          network: ctx.chain,
          pay_to: recipient,
          amount: options.amount?.toString(),
          asset: options.token,
        }),
      },
    ],
    warnings,
    danger: [],
  };
}

function pulledFrom(call: Call, source: string, warnings: string[], what: string): void {
  if (call.sender && source !== call.sender) {
    warnings.push(`${what} pulled from ${source}, which is not the sending account`);
  }
}

const TOKEN_FUNCTIONS: Record<string, TokenDecoder> = {
  a9059cbb: {
    name: "transfer(address,uint256)",
    words: 2,
    payableWarning: true,
    decode: (args, call, ctx, warnings) => {
      const recipient = wordAddress(paddedWord(args, 0), warnings);
      const amount = BigInt(`0x${paddedWord(args, 32)}`);
      return transferAction(ctx, warnings, recipient, {
        label: "ERC-20 transfer",
        summary: `ERC-20 transfer: sends ${tokenAmount(amount, ctx.chain, call.to)} to recipient ${recipient}.`,
        amountLabel: tokenAmount(amount, ctx.chain, call.to),
        amount,
        token: call.to,
      });
    },
  },
  "23b872dd": {
    name: "transferFrom(address,address,uint256)",
    words: 3,
    payableWarning: true,
    decode: (args, call, ctx, warnings) => {
      const source = wordAddress(paddedWord(args, 0), warnings);
      const recipient = wordAddress(paddedWord(args, 32), warnings);
      const amountOrId = BigInt(`0x${paddedWord(args, 64)}`);
      pulledFrom(call, source, warnings, "tokens are");
      return transferAction(ctx, warnings, recipient, {
        label: "Token transferFrom",
        summary: `transferFrom on token contract ${call.to}: moves ${amountOrId.toString()} (ERC-20 amount or NFT token id) from ${source} to recipient ${recipient}.`,
        amountLabel: `${amountOrId.toString()} (amount or NFT token id)`,
        token: call.to,
      });
    },
  },
  "095ea7b3": {
    name: "approve(address,uint256)",
    words: 2,
    payableWarning: true,
    decode: (args, call, ctx, warnings) =>
      approvalAction(call, ctx, warnings, wordAddress(paddedWord(args, 0), warnings), BigInt(`0x${paddedWord(args, 32)}`), {
        label: "ERC-20 approve",
        fn: "ERC-20 approve",
        threshold: UNLIMITED_UINT256,
        token: call.to,
      }),
  },
  "39509351": {
    name: "increaseAllowance(address,uint256)",
    words: 2,
    payableWarning: true,
    decode: (args, call, ctx, warnings) =>
      approvalAction(call, ctx, warnings, wordAddress(paddedWord(args, 0), warnings), BigInt(`0x${paddedWord(args, 32)}`), {
        label: "ERC-20 increaseAllowance",
        fn: "ERC-20 increaseAllowance",
        threshold: UNLIMITED_UINT256,
        token: call.to,
        increase: true,
      }),
  },
  d73dd623: {
    name: "increaseApproval(address,uint256)",
    words: 2,
    payableWarning: true,
    decode: (args, call, ctx, warnings) =>
      approvalAction(call, ctx, warnings, wordAddress(paddedWord(args, 0), warnings), BigInt(`0x${paddedWord(args, 32)}`), {
        label: "ERC-20 increaseApproval",
        fn: "ERC-20 increaseApproval",
        threshold: UNLIMITED_UINT256,
        token: call.to,
        increase: true,
      }),
  },
  a457c2d7: {
    name: "decreaseAllowance(address,uint256)",
    words: 2,
    payableWarning: true,
    decode: (args, call, ctx, warnings) => {
      const spender = wordAddress(paddedWord(args, 0), warnings);
      return {
        label: "ERC-20 decreaseAllowance",
        summary: `ERC-20 decreaseAllowance on ${tokenLabel(ctx.chain, call.to)}: lowers the allowance of spender ${spender}.`,
        candidates: [{ address: spender, role: "spender", interaction: interaction("contract_call"), rank: RANK.revoke }],
        warnings,
        danger: [],
      };
    },
  },
  a22cb465: {
    name: "setApprovalForAll(address,bool)",
    words: 2,
    payableWarning: true,
    decode: (args, call, ctx, warnings) => {
      const operator = wordAddress(paddedWord(args, 0), warnings);
      const approved = BigInt(`0x${paddedWord(args, 32)}`) !== 0n;
      return {
        label: approved ? "NFT setApprovalForAll" : "NFT setApprovalForAll (revoke)",
        summary: approved
          ? `setApprovalForAll on NFT collection ${call.to}: grants operator ${operator} control of ALL of the sender's items in this collection.`
          : `setApprovalForAll on NFT collection ${call.to}: revokes operator ${operator}.`,
        candidates: [
          {
            address: operator,
            role: "operator",
            interaction: interaction(approved ? "nft_approval" : "contract_call"),
            rank: approved ? RANK.unlimitedApproval : RANK.revoke,
            unlimited: approved,
            amountLabel: approved ? "ALL items in the collection" : "revokes operator",
            ...(approved ? { payment: payment({ network: ctx.chain, pay_to: operator, asset: call.to }) } : {}),
          },
        ],
        warnings,
        danger: [],
      };
    },
  },
  "42842e0e": { name: "safeTransferFrom(address,address,uint256)", words: 3, payableWarning: true, decode: nftTransfer },
  b88d4fde: { name: "safeTransferFrom(address,address,uint256,bytes)", words: 3, payableWarning: true, decode: nftTransfer },
  f242432a: {
    name: "safeTransferFrom(address,address,uint256,uint256,bytes)",
    words: 4,
    payableWarning: true,
    decode: (args, call, ctx, warnings) => {
      const source = wordAddress(paddedWord(args, 0), warnings);
      const recipient = wordAddress(paddedWord(args, 32), warnings);
      const id = BigInt(`0x${paddedWord(args, 64)}`);
      const amount = BigInt(`0x${paddedWord(args, 96)}`);
      pulledFrom(call, source, warnings, "tokens are");
      return transferAction(ctx, warnings, recipient, {
        label: "ERC-1155 transfer",
        summary: `ERC-1155 safeTransferFrom on ${call.to}: sends ${amount.toString()} of token id ${id.toString()} from ${source} to recipient ${recipient}.`,
        amountLabel: `${amount.toString()} of token id ${id.toString()}`,
        token: call.to,
      });
    },
  },
  "2eb2c2d6": {
    name: "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
    words: 2,
    payableWarning: true,
    decode: (args, call, ctx, warnings) => {
      const source = wordAddress(paddedWord(args, 0), warnings);
      const recipient = wordAddress(paddedWord(args, 32), warnings);
      const ids = uintArrayAt(args, dynamicAt(args, 64)) ?? [];
      pulledFrom(call, source, warnings, "tokens are");
      return transferAction(ctx, warnings, recipient, {
        label: "ERC-1155 batch transfer",
        summary: `ERC-1155 safeBatchTransferFrom on ${call.to}: sends ${ids.length > 0 ? `token ids ${ids.slice(0, 5).join(", ")}` : "multiple token ids"} from ${source} to recipient ${recipient}.`,
        amountLabel: `${ids.length || "multiple"} token ids`,
        token: call.to,
      });
    },
  },
  "87517c45": {
    name: "approve(address,address,uint160,uint48)",
    words: 4,
    payableWarning: true,
    decode: (args, call, ctx, warnings) => {
      const token = wordAddress(paddedWord(args, 0), warnings);
      const spender = wordAddress(paddedWord(args, 32), warnings);
      const amount = BigInt(`0x${paddedWord(args, 64)}`);
      const expiration = unixDate(BigInt(`0x${paddedWord(args, 96)}`));
      if (call.to !== PERMIT2_ADDRESS) {
        warnings.push(`Permit2-style approve sent to ${call.to}, which is not the canonical Permit2 contract`);
      }
      const action = approvalAction(call, ctx, warnings, spender, amount, {
        label: "Permit2 approve",
        fn: `Permit2 approve via ${call.to}`,
        threshold: UNLIMITED_UINT160,
        token,
        increase: false,
      });
      if (amount === 0n) {
        // Permit2 is not an NFT: zero is always a revocation.
        return {
          ...action,
          label: "Permit2 approve (revoke)",
          summary: `Permit2 approve via ${call.to}: sets the allowance of spender ${spender} on ${tokenLabel(ctx.chain, token)} to 0 (revokes it).`,
          candidates: [{ address: spender, role: "spender", interaction: interaction("contract_call"), rank: RANK.revoke, amountLabel: "0 (revokes allowance)" }],
        };
      }
      return { ...action, summary: action.summary.replace(/\.$/u, `, expiring ${expiration}.`) };
    },
  },
  d505accf: {
    name: "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    words: 4,
    payableWarning: true,
    decode: (args, call, ctx, warnings) => {
      const owner = wordAddress(paddedWord(args, 0), warnings);
      const spender = wordAddress(paddedWord(args, 32), warnings);
      const amount = BigInt(`0x${paddedWord(args, 64)}`);
      const deadline = unixDate(BigInt(`0x${paddedWord(args, 96)}`));
      pulledFrom(call, owner, warnings, "the permit is for tokens");
      const action = approvalAction(call, ctx, warnings, spender, amount, {
        label: "EIP-2612 permit (on-chain)",
        fn: `EIP-2612 permit submitted for owner ${owner}`,
        threshold: UNLIMITED_UINT256,
        token: call.to,
      });
      return { ...action, summary: action.summary.replace(/\.$/u, `, deadline ${deadline}.`) };
    },
  },
  "2b67b570": {
    name: "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
    words: 7,
    payableWarning: true,
    decode: (args, call, ctx, warnings) => {
      const owner = wordAddress(paddedWord(args, 0), warnings);
      const token = wordAddress(paddedWord(args, 32), warnings);
      const amount = BigInt(`0x${paddedWord(args, 64)}`);
      const spender = wordAddress(paddedWord(args, 160), warnings);
      pulledFrom(call, owner, warnings, "the permit is for tokens");
      return approvalAction(call, ctx, warnings, spender, amount, {
        label: "Permit2 permit (on-chain)",
        fn: `Permit2 permit submitted for owner ${owner}`,
        threshold: UNLIMITED_UINT160,
        token,
      });
    },
  },
};

function nftTransfer(args: string, call: Call, ctx: Ctx, warnings: string[]): Action {
  const source = wordAddress(paddedWord(args, 0), warnings);
  const recipient = wordAddress(paddedWord(args, 32), warnings);
  const tokenId = BigInt(`0x${paddedWord(args, 64)}`);
  pulledFrom(call, source, warnings, "the NFT is");
  return transferAction(ctx, warnings, recipient, {
    label: "NFT transfer",
    summary: `NFT safeTransferFrom on collection ${call.to}: sends token id ${tokenId.toString()} from ${source} to recipient ${recipient}.`,
    amountLabel: `token id ${tokenId.toString()}`,
    token: call.to,
  });
}

// ---------------------------------------------------------------------------
// Wrappers (recursive)
// ---------------------------------------------------------------------------

type InnerCall = Call & { note?: string };

function combine(label: string, head: string, inner: Action[], extra: Partial<Action> = {}): Action {
  const parts = inner.map((action, index) => `(${index + 1}) ${capText(action.summary.replace(/\.$/u, ""), 220)}`);
  return {
    label,
    summary: `${head}${parts.length > 0 ? `: ${parts.join("; ")}` : ""}.`,
    candidates: [...(extra.candidates ?? []), ...inner.flatMap((action) => action.candidates)],
    warnings: [...(extra.warnings ?? []), ...inner.flatMap((action) => action.warnings)],
    danger: [...(extra.danger ?? []), ...inner.flatMap((action) => action.danger)],
  };
}

function decodeInner(calls: InnerCall[], ctx: Ctx): Action[] {
  const inner: Action[] = [];
  for (const call of calls) {
    if (ctx.budget.calls <= 0) {
      inner.push(emptyAction("Not decoded", "further inner calls were not decoded (too many)"));
      break;
    }
    ctx.budget.calls -= 1;
    inner.push(decodeCall(call, { ...ctx, depth: ctx.depth + 1 }));
  }
  return inner;
}

function multicall(argsOffset: number) {
  return (args: string, call: Call, ctx: Ctx): Action => {
    const items = bytesArrayAt(args, dynamicAt(args, argsOffset));
    if (!items) return { ...plainCall(call, ctx, "malformed multicall"), warnings: ["multicall calldata could not be decoded"] };
    const inner = decodeInner(
      items.map((data) => ({ sender: call.sender, to: call.to, value: 0n, data })),
      ctx,
    );
    return combine("Multicall", `Multicall on ${call.to} with ${items.length} inner call(s)`, inner, {
      candidates: call.value > 0n ? [contractCandidate(call, ctx)] : [],
    });
  };
}

function delegateCall(call: InnerCall, ctx: Ctx): Action {
  if (SAFE_MULTISEND.has(call.to)) {
    const selector = call.data.slice(0, 8);
    if (selector === "8d80ff0a") return multiSend(call.data.slice(8), { ...call, delegate: false }, ctx);
  }
  const reason = `DELEGATECALL to ${call.to}: that contract's code runs with full control of ${
    call.sender ? `account ${call.sender}` : "the account"
  } and can move everything it holds`;
  return {
    label: "DELEGATECALL",
    summary: `DELEGATECALL (operation=1) to ${call.to} from ${call.sender ?? "the account"} with ${call.data.length / 2} bytes of calldata.`,
    candidates: [
      {
        address: call.to,
        role: "contract",
        interaction: interaction("contract_call"),
        rank: RANK.delegatecall,
        reason: "receives a DELEGATECALL",
      },
    ],
    warnings: [],
    danger: [reason],
  };
}

function multiSend(args: string, call: Call, ctx: Ctx): Action {
  const packed = bytesAt(args, dynamicAt(args, 0));
  if (packed === undefined) return { ...plainCall(call, ctx, "malformed multiSend"), warnings: ["multiSend calldata could not be decoded"] };
  const calls: InnerCall[] = [];
  let position = 0;
  while (position < packed.length && calls.length < MAX_ARRAY) {
    const header = packed.slice(position, position + (1 + 20 + 32 + 32) * 2);
    if (header.length < (1 + 20 + 32 + 32) * 2) break;
    const operation = parseInt(header.slice(0, 2), 16);
    const to = `0x${header.slice(2, 42)}`;
    const value = BigInt(`0x${header.slice(42, 106)}`);
    const length = BigInt(`0x${header.slice(106, 170)}`);
    const start = position + 170;
    if (length > BigInt((packed.length - start) / 2)) break;
    const data = packed.slice(start, start + Number(length) * 2);
    calls.push({ sender: call.sender, to, value, data, delegate: operation === 1 });
    position = start + Number(length) * 2;
  }
  const inner = decodeInner(calls, ctx);
  return combine("Safe multiSend", `Safe multiSend batch of ${calls.length} call(s)`, inner);
}

function safeExecTransaction(args: string, call: Call, ctx: Ctx): Action {
  const warnings: string[] = [];
  const to = addressAt(args, 0, warnings);
  const value = uintAt(args, 32);
  const data = bytesAt(args, dynamicAt(args, 64));
  const operation = uintAt(args, 96);
  const gasPrice = uintAt(args, 192);
  const refundReceiver = addressAt(args, 256, warnings);
  if (to === undefined || value === undefined || data === undefined || operation === undefined) {
    return { ...plainCall(call, ctx, "malformed Safe execTransaction"), warnings: ["Safe execTransaction calldata could not be decoded"] };
  }
  if (gasPrice && gasPrice > 0n && refundReceiver && !isIgnorableAddress(refundReceiver)) {
    warnings.push(`the Safe pays gas refunds to ${refundReceiver}`);
  }
  const inner = decodeInner([{ sender: call.to, to, value, data, delegate: operation === 1n }], ctx);
  return combine(
    "Safe execTransaction",
    `Safe execTransaction on Safe ${call.to} (${operation === 1n ? "DELEGATECALL" : "CALL"} to ${to}${
      value > 0n ? `, sending ${nativeAmount(value, ctx.chain)}` : ""
    })`,
    inner,
    { warnings },
  );
}

/** Universal Router recipient sentinels: address(1) = caller, address(2) = router. */
function routerRecipient(address: string, call: Call): string | undefined {
  if (address === "0x0000000000000000000000000000000000000001") return call.sender;
  if (address === "0x0000000000000000000000000000000000000002") return call.to;
  return address;
}

function universalRouter(args: string, call: Call, ctx: Ctx): Action {
  const commands = bytesAt(args, dynamicAt(args, 0));
  const inputs = bytesArrayAt(args, dynamicAt(args, 32));
  if (commands === undefined || inputs === undefined) {
    return { ...plainCall(call, ctx, "malformed Universal Router execute"), warnings: ["Universal Router calldata could not be decoded"] };
  }
  return routerPlan(commands, inputs, call, ctx, "Universal Router execute");
}

function routerPlan(commands: string, inputs: string[], call: Call, ctx: Ctx, title: string): Action {
  const warnings: string[] = [];
  const danger: string[] = [];
  const candidates: Candidate[] = [];
  const notes: string[] = [];
  const recipientCandidate = (raw: string | undefined, what: string, token?: string, amount?: bigint) => {
    if (!raw) return;
    const recipient = routerRecipient(raw, call);
    if (!recipient || recipient === call.sender || recipient === call.to || isIgnorableAddress(recipient)) return;
    warnings.push(`${what} goes to ${recipient}, not to you`);
    candidates.push({
      address: recipient,
      role: "recipient",
      interaction: interaction("token_transfer"),
      rank: RANK.transfer,
      reason: what,
      payment: payment({ network: ctx.chain, pay_to: recipient, amount: amount?.toString(), asset: token }),
    });
  };
  const permitSpender = (spender: string | undefined, token: string | undefined, amount: bigint | undefined, what: string) => {
    if (!spender) return;
    if (spender === call.to) {
      notes.push(`${what} to the router itself`);
      return;
    }
    const allowance = describeAllowance(amount, UNLIMITED_UINT160, warnings);
    danger.push(`${what} grants spender ${spender} (not the router) the right to move your tokens`);
    candidates.push({
      address: spender,
      role: "spender",
      interaction: interaction("token_approval", allowance.unlimited),
      rank: RANK.unlimitedApproval,
      unlimited: allowance.unlimited,
      amountLabel: allowance.label,
      reason: what,
      payment: payment({ network: ctx.chain, pay_to: spender, amount: amount?.toString(), asset: token }),
    });
  };
  const count = Math.min(commands.length / 2, MAX_ARRAY);
  for (let index = 0; index < count; index += 1) {
    const command = parseInt(commands.slice(index * 2, index * 2 + 2), 16) & 0x3f;
    const input = inputs[index] ?? "";
    switch (command) {
      case 0x00:
      case 0x01:
        notes.push("V3 swap");
        recipientCandidate(addressAt(input, 0, warnings), "the V3 swap output");
        break;
      case 0x08:
      case 0x09:
        notes.push("V2 swap");
        recipientCandidate(addressAt(input, 0, warnings), "the V2 swap output");
        break;
      case 0x02: {
        const token = addressAt(input, 0, warnings);
        notes.push("PERMIT2_TRANSFER_FROM");
        recipientCandidate(addressAt(input, 32, warnings), `a Permit2 transfer of your ${tokenLabel(ctx.chain, token)}`, token, uintAt(input, 64));
        break;
      }
      case 0x03: {
        const tuple = dynamicAt(input, 0);
        notes.push("PERMIT2_PERMIT_BATCH");
        permitSpender(tuple === undefined ? undefined : addressAt(input, tuple + 32, warnings), undefined, undefined, "a Permit2 batch permit");
        break;
      }
      case 0x04: {
        const token = addressAt(input, 0, warnings);
        notes.push("SWEEP");
        recipientCandidate(addressAt(input, 32, warnings), `a sweep of ${tokenLabel(ctx.chain, token)}`, token);
        break;
      }
      case 0x05: {
        const token = addressAt(input, 0, warnings);
        notes.push("TRANSFER");
        recipientCandidate(addressAt(input, 32, warnings), `a transfer of ${tokenLabel(ctx.chain, token)}`, token, uintAt(input, 64));
        break;
      }
      case 0x06: {
        const token = addressAt(input, 0, warnings);
        notes.push("PAY_PORTION");
        recipientCandidate(addressAt(input, 32, warnings), `a portion payment of ${tokenLabel(ctx.chain, token)}`, token);
        break;
      }
      case 0x0a: {
        const token = addressAt(input, 0, warnings);
        notes.push("PERMIT2_PERMIT");
        permitSpender(addressAt(input, 128, warnings), token, uintAt(input, 32), `a Permit2 permit on ${tokenLabel(ctx.chain, token)}`);
        break;
      }
      case 0x0b:
        notes.push("WRAP_ETH");
        recipientCandidate(addressAt(input, 0, warnings), "wrapped ETH");
        break;
      case 0x0c:
        notes.push("UNWRAP_WETH");
        recipientCandidate(addressAt(input, 0, warnings), "unwrapped ETH");
        break;
      case 0x0d: {
        notes.push("PERMIT2_TRANSFER_FROM_BATCH");
        const array = dynamicAt(input, 0);
        const items = array === undefined ? 0 : Math.min(smallAt(input, array) ?? 0, MAX_ARRAY);
        for (let item = 0; item < items && array !== undefined; item += 1) {
          const base = array + 32 + item * 128;
          const token = addressAt(input, base + 96, warnings);
          recipientCandidate(addressAt(input, base + 32, warnings), `a Permit2 batch transfer of your ${tokenLabel(ctx.chain, token)}`, token, uintAt(input, base + 64));
        }
        break;
      }
      case 0x21: {
        notes.push("EXECUTE_SUB_PLAN");
        if (ctx.depth < MAX_DEPTH) {
          const subCommands = bytesAt(input, dynamicAt(input, 0));
          const subInputs = bytesArrayAt(input, dynamicAt(input, 32));
          if (subCommands !== undefined && subInputs !== undefined) {
            const sub = routerPlan(subCommands, subInputs, call, { ...ctx, depth: ctx.depth + 1 }, "sub-plan");
            candidates.push(...sub.candidates);
            warnings.push(...sub.warnings);
            danger.push(...sub.danger);
          }
        }
        break;
      }
      default:
        notes.push(`command 0x${command.toString(16).padStart(2, "0")} (not decoded)`);
    }
  }
  if (call.value > 0n) candidates.push(contractCandidate(call, ctx));
  if (candidates.length === 0) candidates.push(contractCandidate(call, ctx));
  return {
    label: "Universal Router execute",
    summary: `${title} on ${call.to}: ${count} command(s): ${notes.slice(0, 12).join(", ") || "none"}.`,
    candidates,
    warnings,
    danger,
  };
}

function smartAccountExecute7579(args: string, call: Call, ctx: Ctx): Action {
  const mode = word(args, 0);
  const execution = bytesAt(args, dynamicAt(args, 32));
  if (mode === undefined || execution === undefined) {
    return { ...plainCall(call, ctx, "malformed execute"), warnings: ["smart-account execute calldata could not be decoded"] };
  }
  const callType = mode.slice(0, 2);
  const account = call.to;
  const calls: InnerCall[] = [];
  if (callType === "00" || callType === "ff") {
    const single = callType === "00";
    const minimum = single ? 104 : 40;
    if (execution.length < minimum) return { ...plainCall(call, ctx, "malformed execute"), warnings: ["smart-account execute calldata could not be decoded"] };
    calls.push({
      sender: account,
      to: `0x${execution.slice(0, 40)}`,
      value: single ? BigInt(`0x${execution.slice(40, 104)}`) : 0n,
      data: execution.slice(minimum),
      delegate: !single,
    });
  } else if (callType === "01") {
    const array = dynamicAt(execution, 0);
    const count = array === undefined ? 0 : Math.min(smallAt(execution, array) ?? 0, MAX_ARRAY);
    const base = (array ?? 0) + 32;
    for (let index = 0; index < count; index += 1) {
      const tuple = dynamicAt(execution, base + index * 32, base);
      if (tuple === undefined) break;
      const warnings: string[] = [];
      const target = addressAt(execution, tuple, warnings);
      const value = uintAt(execution, tuple + 32);
      const data = bytesAt(execution, dynamicAt(execution, tuple + 64, tuple));
      if (target === undefined || value === undefined || data === undefined) break;
      calls.push({ sender: account, to: target, value, data });
    }
  } else if (callType === "fe") {
    return emptyAction("Smart-account staticcall", `Smart-account execute on ${account}: a read-only staticcall (no state change).`);
  } else {
    return { ...plainCall(call, ctx, `execute with unknown call type 0x${callType}`), warnings: [`smart-account execute uses an unknown call type 0x${callType}`] };
  }
  const inner = decodeInner(calls, ctx);
  return combine(
    "Smart-account execute",
    `Smart-account execute (ERC-7579 ${callType === "01" ? "batch" : callType === "ff" ? "delegatecall" : "single call"}) on ${account}`,
    inner,
  );
}

function executeSingle(args: string, call: Call, ctx: Ctx): Action {
  const warnings: string[] = [];
  const target = addressAt(args, 0, warnings);
  const value = uintAt(args, 32);
  const data = bytesAt(args, dynamicAt(args, 64));
  if (target === undefined || value === undefined || data === undefined) {
    return { ...plainCall(call, ctx, "malformed execute"), warnings: ["smart-account execute calldata could not be decoded"] };
  }
  return combine("Smart-account execute", `Smart-account execute on ${call.to}`, decodeInner([{ sender: call.to, to: target, value, data }], ctx), { warnings });
}

function executeBatchArrays(withValues: boolean) {
  return (args: string, call: Call, ctx: Ctx): Action => {
    const warnings: string[] = [];
    const targets = addressArrayAt(args, dynamicAt(args, 0), warnings);
    const values = withValues ? uintArrayAt(args, dynamicAt(args, 32)) : undefined;
    const datas = bytesArrayAt(args, dynamicAt(args, withValues ? 64 : 32));
    if (!targets || !datas || (withValues && !values)) {
      return { ...plainCall(call, ctx, "malformed executeBatch"), warnings: ["smart-account executeBatch calldata could not be decoded"] };
    }
    const calls: InnerCall[] = targets.map((to, index) => ({
      sender: call.to,
      to,
      value: values?.[index] ?? 0n,
      data: datas[index] ?? "",
    }));
    return combine("Smart-account executeBatch", `Smart-account executeBatch on ${call.to}`, decodeInner(calls, ctx), { warnings });
  };
}

function executeBatchTuples(args: string, call: Call, ctx: Ctx): Action {
  const array = dynamicAt(args, 0);
  const count = array === undefined ? 0 : Math.min(smallAt(args, array) ?? 0, MAX_ARRAY);
  const base = (array ?? 0) + 32;
  const calls: InnerCall[] = [];
  const warnings: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const tuple = dynamicAt(args, base + index * 32, base);
    if (tuple === undefined) break;
    const target = addressAt(args, tuple, warnings);
    const value = uintAt(args, tuple + 32);
    const data = bytesAt(args, dynamicAt(args, tuple + 64, tuple));
    if (target === undefined || value === undefined || data === undefined) break;
    calls.push({ sender: call.to, to: target, value, data });
  }
  if (calls.length === 0 && count > 0) {
    return { ...plainCall(call, ctx, "malformed executeBatch"), warnings: ["smart-account executeBatch calldata could not be decoded"] };
  }
  return combine("Smart-account executeBatch", `Smart-account executeBatch on ${call.to}`, decodeInner(calls, ctx), { warnings });
}

type WrapperDecoder = (args: string, call: Call, ctx: Ctx) => Action;

const WRAPPERS: Record<string, WrapperDecoder> = {
  ac9650d8: multicall(0),
  "5ae401dc": multicall(32),
  "1f0464d1": multicall(32),
  "6a761202": safeExecTransaction,
  "8d80ff0a": multiSend,
  "3593564c": universalRouter,
  "24856bc3": universalRouter,
  e9ae5c53: smartAccountExecute7579,
  b61d27f6: executeSingle,
  "18dfb3c7": executeBatchArrays(false),
  "47e1da2a": executeBatchArrays(true),
  "34fcd5be": executeBatchTuples,
};

/**
 * Decodes one call (recursively for wrappers).
 *
 * @param call - The call.
 * @param ctx - Decoding context.
 * @returns The decoded action.
 */
function decodeCall(call: InnerCall, ctx: Ctx): Action {
  if (call.delegate) return delegateCall(call, ctx);
  if (call.data === "") {
    if (call.value === 0n && call.to === call.sender) {
      return emptyAction("Self-transfer", `A zero-value call to the sending account itself (${call.to}).`);
    }
    return {
      label: "Native transfer",
      summary: `Native transfer: sends ${nativeAmount(call.value, ctx.chain)} to recipient ${call.to}.`,
      candidates: [
        {
          address: call.to,
          role: "recipient",
          interaction: interaction("native_transfer"),
          rank: RANK.transfer,
          amountLabel: nativeAmount(call.value, ctx.chain),
          payment: payment({ network: ctx.chain, pay_to: call.to, amount: call.value.toString(), asset: "native" }),
        },
      ],
      warnings: [],
      danger: [],
    };
  }
  if (call.data.length < 8) return plainCall(call, ctx, `${call.data.length / 2} bytes of non-standard calldata`);
  const selector = call.data.slice(0, 8);
  const args = call.data.slice(8);
  const token = TOKEN_FUNCTIONS[selector] as TokenDecoder | undefined;
  if (token) {
    const warnings: string[] = [];
    if (args.length < token.words * 64) {
      warnings.push(
        `calldata is ${token.words * 32 - args.length / 2} byte(s) shorter than ${token.name} expects; older token contracts read the missing bytes as zeros`,
      );
    }
    const action = token.decode(args, call, ctx, warnings);
    if (call.value > 0n) {
      action.warnings.push(`sends ${nativeAmount(call.value, ctx.chain)} to ${call.to} while calling ${token.name}, which normally takes no ETH`);
      action.candidates.unshift({ ...contractCandidate(call, ctx), rank: RANK.transfer, reason: "receives the ETH sent with the call" });
    }
    return action;
  }
  const wrapper = WRAPPERS[selector] as WrapperDecoder | undefined;
  if (wrapper && ctx.depth <= MAX_DEPTH) return wrapper(args, call, ctx);
  if (wrapper) {
    return { ...plainCall(call, ctx, `wrapper 0x${selector}`), warnings: ["nested wrapper calls exceed the decoding depth"] };
  }
  return plainCall(call, ctx, `function selector 0x${selector}, ${call.data.length / 2} bytes of calldata`);
}

/**
 * Decodes an EVM transaction into the address(es) that should be checked.
 *
 * @param tx - The transaction (`to`, `from`, `value`, `data`).
 * @param chainId - CAIP-2 chain id of the network.
 * @returns The decoded request.
 */
export function decodeTransaction(tx: TransactionLike, chainId?: unknown): Decoded {
  const chain = normalizeChainId(chainId);
  const warnings: string[] = [];
  const danger: string[] = [];
  let value = parseUint(tx.value);
  const valueInvalid = value === undefined && !isMissing(tx.value);
  if (value === undefined) {
    if (valueInvalid) warnings.push("the transaction value could not be parsed");
    value = 0n;
  }
  const valueText = value > 0n ? nativeAmount(value, chain) : undefined;

  if (isMissing(tx.to)) {
    return withCandidates(
      {
        action: "Contract deployment",
        chain,
        amountLabel: valueText,
        summary: `Contract deployment (no recipient address)${valueText ? `, sending ${valueText}` : ""}.`,
        warnings,
        danger,
        localNote:
          "This transaction deploys a new contract, so there is no counterparty address to check. Nothing was sent to x402check.",
      },
      [],
    );
  }
  const to = lenientAddress(tx.to);
  if (!to) {
    return withCandidates(
      {
        action: "Unrecognized recipient",
        chain,
        summary: "Transaction with a recipient that is not a valid EVM address.",
        warnings,
        danger,
        localNote:
          "The recipient is not a valid EVM address, so x402check could not check it. Do not proceed unless you know exactly what this is.",
      },
      [],
    );
  }
  const from = lenientAddress(tx.from);
  const rawData = tx.data !== undefined && tx.data !== null && tx.data !== "" ? tx.data : tx.input;
  let data = normalizeCalldata(rawData);
  // The simulation gets the full calldata (or is skipped when it is too large).
  const fullData = data;
  if (data !== null && data.length > MAX_CALLDATA_HEX) {
    warnings.push(`the calldata is very large (${data.length / 2} bytes); only the first 1 MiB was decoded`);
    data = data.slice(0, MAX_CALLDATA_HEX);
  }

  if (isIgnorableAddress(to)) {
    if (value > 0n) danger.push(`sends ${valueText} to ${to}, a special/burn address: the funds will be lost`);
    return withCandidates(
      {
        action: to === `0x${"0".repeat(40)}` ? "Transfer to the zero address" : "Call to a precompile/special address",
        chain,
        amountLabel: valueText,
        summary: `Transaction to the special address ${to}${valueText ? `, sending ${valueText}` : ""}.`,
        warnings,
        danger,
        localNote: `The recipient ${to} is a special address that nobody controls, so there is nothing to check.`,
      },
      [],
    );
  }

  const plan = planSimulation({ chain, from, to, value: valueInvalid ? undefined : value, data: fullData });
  if ("warning" in plan && plan.warning) warnings.push(plan.warning);
  const ctx: Ctx = { chain, user: from, depth: 0, budget: { calls: MAX_INNER_CALLS } };
  const action: Action =
    data === null
      ? { ...plainCall({ sender: from, to, value, data: "" }, ctx, "unparseable calldata"), warnings: ["the calldata is not valid hex"] }
      : decodeCall({ sender: from, to, value, data }, ctx);

  const candidates = [...action.candidates];
  let summary = action.summary;
  if (value > 0n && data !== null && data !== "") {
    // Payable call: the ETH recipient `to` is always the primary counterparty;
    // the decoded inner semantics stay in the context.
    candidates.unshift({
      address: to,
      role: "contract",
      interaction: interaction("contract_call"),
      rank: RANK.payableTarget,
      reason: `receives ${valueText}`,
      amountLabel: valueText,
      payment: payment({ network: chain, pay_to: to, amount: value.toString(), asset: "native" }),
    });
    summary = `Sends ${valueText} to contract ${to} with a call: ${summary}`;
  }
  const selected = selectCandidates(candidates, [from]);
  if (from && to === from && data) {
    warnings.push(
      selected.length > 0
        ? "this calls your own account's code (EIP-7702 / smart account); the inner calls were decoded"
        : "this calls your own account's code (EIP-7702 / smart account) and its inner actions could not be decoded",
    );
  }
  const primary = selected[0];
  return withCandidates(
    {
      action: action.label,
      chain,
      unlimited: primary?.unlimited,
      amountLabel: primary?.amountLabel,
      summary,
      warnings: dedupe([...warnings, ...action.warnings]),
      danger: dedupe([...danger, ...action.danger]),
      ...("transaction" in plan ? { transaction: plan.transaction } : { simulationSkipped: plan.skipped }),
      ...(selected.length === 0
        ? {
            localNote:
              to === from
                ? "This calls your own account and no counterparty could be decoded, so it was not sent to x402check. Do not proceed unless you know exactly what it does."
                : "No counterparty could be decoded from this transaction, so it was not sent to x402check.",
          }
        : {}),
    },
    selected,
  );
}

/**
 * Decodes a single call made by `sender` (e.g. the call inside a SafeTx).
 *
 * @param call - The call; `data` is lowercase hex without 0x.
 * @param chain - CAIP-2 chain id.
 * @param user - The signing account.
 * @returns The decoded action.
 */
export function decodeCallAction(
  call: { sender?: string; to: string; value: bigint; data: string; delegate?: boolean },
  chain?: string,
  user?: string,
): Action {
  return decodeCall(call, { chain, user, depth: 0, budget: { calls: MAX_INNER_CALLS } });
}

export function dedupe(items: string[]): string[] {
  return [...new Set(items)];
}

