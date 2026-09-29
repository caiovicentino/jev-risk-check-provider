/**
 * Pure decoders for the x402check Snap.
 *
 * Every function in this file is deterministic and free of Snap globals and
 * network access, so it can be unit-tested directly. The job of each decoder is
 * to turn a raw wallet request (transaction calldata, EIP-712 typed data or a
 * personal_sign payload) into:
 *
 * - the address that actually matters for the risk check (the counterparty:
 *   recipient, spender, operator or contract), never a random hex fragment and
 *   never the user's own address unless nothing else is named;
 * - a short, human-readable summary (no raw calldata, hex blobs or JSON).
 */

export type Role =
  | "recipient"
  | "spender"
  | "operator"
  | "delegate"
  | "contract"
  | "signer"
  | "counterparty";

/**
 * What kind of interaction the request is. The backend applies deterministic
 * rules on it (e.g. approvals/permits to an EOA spender are capped at "high").
 */
export type InteractionType =
  | "native_transfer"
  | "token_transfer"
  | "token_approval"
  | "nft_approval"
  | "permit_signature"
  | "order_signature"
  | "message_signature"
  | "contract_call";

/** Mirrors the backend `interaction` object: only these two keys. */
export type Interaction = { type: InteractionType; unlimited?: true };

/** Mirrors the backend `payment` binding. All fields optional strings. */
export type Payment = {
  network?: string;
  pay_to?: string;
  /** Decimal integer string in base units. */
  amount?: string;
  /** Token contract address or "native". */
  asset?: string;
};

export type Decoded = {
  /** Short action label for the UI, e.g. "ERC-20 approve". */
  action: string;
  /**
   * Lowercase 0x-address that is risk-checked. Undefined means there is nothing
   * to check (contract deployment, malformed request) and the server must not
   * be called.
   */
  counterparty?: string;
  role?: Role;
  /** CAIP-2 chain id ("eip155:<decimal>") when known. */
  chain?: string;
  /** Structured interaction type sent to the backend. */
  interaction: Interaction;
  /** True for unlimited / all-items approvals (UI flag). */
  unlimited?: boolean;
  /** UI label for the amount or allowance ("UNLIMITED", "1000 base units"...). */
  amountLabel?: string;
  /** Concrete value transfer or allowance, when known. */
  payment?: Payment;
  /** Decoded human-readable summary (becomes the request `context`). */
  summary: string;
  /** Locally detected red flags (shown in the UI and added to the context). */
  warnings: string[];
  /** Explanation shown when the request is not sent to the server. */
  localNote?: string;
  /** Hostnames referenced inside a signed message (personal_sign). */
  referencedHosts?: string[];
};

export const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
/** Canonical Uniswap Permit2 deployment (same address on every chain). */
export const PERMIT2_ADDRESS = "0x000000000022d473030f116ddee9f6b43ac78ba3";

export const MAX_UINT256 = (1n << 256n) - 1n;
export const MAX_UINT160 = (1n << 160n) - 1n;
/** uint256 allowances at or above 2^255 are treated as unlimited. */
export const UNLIMITED_UINT256 = 1n << 255n;
/** Permit2 allowances are uint160; at or above 2^159 is unlimited. */
export const UNLIMITED_UINT160 = 1n << 159n;
/** Anything this large is effectively unlimited for any real token. */
const VERY_LARGE = 1n << 128n;

export const MAX_EXCERPT = 300;

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/u;
// An address inside free text: exactly 40 hex digits, not part of a longer hex run
// (so a 32-byte hash is never mistaken for an address).
const ADDRESS_IN_TEXT_RE = /(?<![0-9a-zA-Z])0x[0-9a-fA-F]{40}(?![0-9a-zA-Z])/gu;
const URL_IN_TEXT_RE = /\bhttps?:\/\/[^\s"'<>()[\]{}`]+/giu;
// Bare hostnames in free text, limited to TLDs commonly used by dApps and phishing
// kits to keep false positives ("v1.2", "e.g.") out.
const BARE_HOST_RE =
  /(?<![@\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|io|xyz|app|finance|fi|exchange|claim|click|link|top|site|online|live|pro|info|co|me|gg|so|dev|ai|cc|biz|us|eth|tech|network|money|cash|gift|vip|club|shop|store|website|space|world|zone|digital|lol|fun|icu|buzz|rest|sbs|cfd))(?![\w-])/giu;

const NATIVE_SYMBOLS: Record<string, string> = {
  "eip155:1": "ETH",
  "eip155:10": "ETH",
  "eip155:56": "BNB",
  "eip155:100": "xDAI",
  "eip155:137": "POL",
  "eip155:324": "ETH",
  "eip155:8453": "ETH",
  "eip155:42161": "ETH",
  "eip155:43114": "AVAX",
  "eip155:59144": "ETH",
  "eip155:81457": "ETH",
  "eip155:534352": "ETH",
  "eip155:11155111": "ETH",
  "eip155:84532": "ETH",
};

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

/**
 * Builds an interaction; `unlimited` is only ever present as `true`.
 *
 * @param type - The interaction type.
 * @param unlimited - Whether the allowance/permit amount is unlimited.
 * @returns The interaction object.
 */
export function interaction(type: InteractionType, unlimited = false): Interaction {
  return unlimited ? { type, unlimited: true } : { type };
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Returns a lowercase 0x-address, or undefined when `value` is not one. */
export function normalizeAddress(value: unknown): string | undefined {
  return typeof value === "string" && ADDRESS_RE.test(value) ? value.toLowerCase() : undefined;
}

/**
 * Parses an unsigned integer given as bigint, safe number, decimal string or
 * 0x-hex string. Returns undefined for anything else or for values > 2^256-1.
 */
export function parseUint(value: unknown): bigint | undefined {
  if (typeof value === "bigint") {
    return value >= 0n && value <= MAX_UINT256 ? value : undefined;
  }
  if (typeof value === "number") {
    return Number.isFinite(value) && Number.isInteger(value) && value >= 0 ? BigInt(value) : undefined;
  }
  if (typeof value !== "string") {
    return undefined;
  }
  const text = value.trim();
  let parsed: bigint | undefined;
  if (/^0x[0-9a-f]{1,64}$/iu.test(text)) {
    parsed = BigInt(text);
  } else if (/^\d{1,78}$/u.test(text)) {
    parsed = BigInt(text);
  }
  return parsed !== undefined && parsed <= MAX_UINT256 ? parsed : undefined;
}

/** Normalizes a chain id (CAIP-2, hex, decimal or number) to "eip155:<decimal>". */
export function normalizeChainId(value: unknown): string | undefined {
  let id: bigint | undefined;
  if (typeof value === "string") {
    const caip = /^eip155:(\d{1,20})$/u.exec(value.trim());
    id = caip ? BigInt(caip[1] as string) : parseUint(value);
  } else {
    id = parseUint(value);
  }
  if (id === undefined || id <= 0n || id > 0xffffffffffffffffn) {
    return undefined;
  }
  return `eip155:${id.toString()}`;
}

export function nativeSymbol(chain?: string): string {
  return (chain && NATIVE_SYMBOLS[chain]) || "native units";
}

/** Formats base units with the given decimals, without losing precision. */
export function formatUnits(value: bigint, decimals: number): string {
  const base = 10n ** BigInt(decimals);
  const whole = value / base;
  const fraction = value % base;
  if (fraction === 0n) {
    return whole.toString();
  }
  const fractionText = fraction.toString().padStart(decimals, "0").replace(/0+$/u, "");
  return `${whole.toString()}.${fractionText}`;
}

function nativeAmount(value: bigint, chain?: string): string {
  return `${formatUnits(value, 18)} ${nativeSymbol(chain)} (${value.toString()} wei)`;
}

/** Caps a string, appending an ellipsis when truncated. */
export function capText(text: string, max: number): string {
  if (text.length <= max) {
    return text;
  }
  return `${text.slice(0, Math.max(0, max - 1)).trimEnd()}…`;
}

function unixDate(value: bigint | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (value === 0n) {
    return "0";
  }
  // Beyond year ~5000: a "never expires" sentinel such as max uint.
  if (value > 100_000_000_000n) {
    return "never";
  }
  return new Date(Number(value) * 1000).toISOString().slice(0, 10);
}

// Invisible / direction-changing characters used to disguise text.
const INVISIBLE_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\u061C\uFEFF]/gu;
// C0/C1 control characters (tab, CR and LF are handled as whitespace).
const CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/gu;

export type CleanText = { text: string; hadInvisible: boolean };

/**
 * Makes untrusted text safe and compact for a one-line summary: removes
 * invisible and control characters, collapses whitespace, and replaces long hex
 * or base64 runs with a size marker so no raw blob reaches the context.
 */
export function cleanText(input: string): CleanText {
  const hadInvisible = INVISIBLE_RE.test(input);
  INVISIBLE_RE.lastIndex = 0;
  const text = input
    .replace(INVISIBLE_RE, "")
    .replace(CONTROL_RE, " ")
    .replace(/0x[0-9a-fA-F]{41,}/gu, (run) => `[${Math.floor((run.length - 2) / 2)}-byte hex]`)
    .replace(/\b[0-9a-fA-F]{64,}\b/gu, (run) => `[${Math.floor(run.length / 2)}-byte hex]`)
    .replace(/[A-Za-z0-9+/=_-]{120,}/gu, "[long encoded data]")
    .replace(/\s+/gu, " ")
    .trim();
  return { text, hadInvisible };
}

function quote(text: string, max: number): string {
  return `"${capText(cleanText(text).text.replace(/"/gu, "'"), max)}"`;
}

function hostFromUrl(raw: string): string | undefined {
  try {
    const host = new URL(raw).hostname.replace(/\.$/u, "").toLowerCase();
    return isPlausibleHost(host) ? host : undefined;
  } catch {
    return undefined;
  }
}

export function isPlausibleHost(host: string): boolean {
  return (
    host.length > 0 &&
    host.length <= 253 &&
    /^[a-z0-9.-]+$/u.test(host) &&
    host.includes(".") &&
    host.split(".").every((label) => label.length > 0 && label.length <= 63)
  );
}

/** Extracts distinct hostnames referenced in free text (URLs and bare domains). */
export function extractHosts(text: string, limit = 5): string[] {
  const hosts: string[] = [];
  const add = (host: string | undefined) => {
    if (host && !hosts.includes(host) && hosts.length < limit) {
      hosts.push(host);
    }
  };
  for (const match of text.matchAll(URL_IN_TEXT_RE)) {
    add(hostFromUrl(match[0].replace(/[.,;:!?]+$/u, "")));
  }
  const withoutUrls = text.replace(URL_IN_TEXT_RE, " ");
  for (const match of withoutUrls.matchAll(BARE_HOST_RE)) {
    add(hostFromUrl(`https://${match[1] as string}`));
  }
  return hosts;
}

/** Extracts distinct 0x-addresses from free text, excluding `exclude`. */
export function extractAddresses(text: string, exclude: (string | undefined)[] = []): string[] {
  const skip = new Set(exclude.filter((value): value is string => Boolean(value)));
  const found: string[] = [];
  for (const match of text.matchAll(ADDRESS_IN_TEXT_RE)) {
    const address = match[0].toLowerCase();
    if (!skip.has(address) && !found.includes(address)) {
      found.push(address);
    }
  }
  return found;
}

// ---------------------------------------------------------------------------
// Transactions (EVM calldata)
// ---------------------------------------------------------------------------

export type TransactionLike = {
  from?: unknown;
  to?: unknown;
  value?: unknown;
  data?: unknown;
  input?: unknown;
};

type TxContext = {
  contract: string;
  sender?: string;
  value: bigint;
  chain?: string;
  data: string;
  warnings: string[];
};

/** Lowercase hex without 0x ("" for empty), or null when not valid hex. */
function normalizeCalldata(value: unknown): string | null {
  if (value === undefined || value === null) {
    return "";
  }
  if (typeof value !== "string") {
    return null;
  }
  const text = value.trim();
  if (text === "" || /^0x$/iu.test(text)) {
    return "";
  }
  const match = /^0x([0-9a-fA-F]*)$/u.exec(text);
  if (!match || (match[1] as string).length % 2 !== 0) {
    return null;
  }
  return (match[1] as string).toLowerCase();
}

function isMissing(value: unknown): boolean {
  return (
    value === undefined ||
    value === null ||
    (typeof value === "string" && (value.trim() === "" || /^0x$/iu.test(value.trim())))
  );
}

function argWords(data: string, count: number): string[] | undefined {
  const body = data.slice(8);
  if (body.length < count * 64) {
    return undefined;
  }
  const words: string[] = [];
  for (let index = 0; index < count; index += 1) {
    words.push(body.slice(index * 64, (index + 1) * 64));
  }
  return words;
}

function wordToAddress(word: string, warnings: string[]): string {
  if (!/^0{24}/u.test(word)) {
    const warning = "calldata encodes an address with non-zero padding (malformed or obfuscated)";
    if (!warnings.includes(warning)) {
      warnings.push(warning);
    }
  }
  return `0x${word.slice(24)}`;
}

function wordToUint(word: string): bigint {
  return BigInt(`0x${word}`);
}

type AllowanceInfo = { unlimited: boolean; label: string; phrase: string };

function describeAllowance(amount: bigint, threshold: bigint, warnings: string[]): AllowanceInfo {
  if (amount >= threshold) {
    return {
      unlimited: true,
      label: "UNLIMITED",
      phrase: `an UNLIMITED allowance (${amount === MAX_UINT256 ? "max uint256" : amount === MAX_UINT160 ? "max uint160" : "effectively infinite"})`,
    };
  }
  if (amount >= VERY_LARGE) {
    warnings.push("allowance is extremely large (effectively unlimited)");
  }
  return {
    unlimited: false,
    label: `${amount.toString()} base units`,
    phrase: `an allowance of ${amount.toString()} base units`,
  };
}

function payment(fields: Payment): Payment | undefined {
  const out: Payment = {};
  if (fields.network) {
    out.network = fields.network;
  }
  if (fields.pay_to) {
    out.pay_to = fields.pay_to;
  }
  if (fields.amount && /^\d{1,78}$/u.test(fields.amount)) {
    out.amount = fields.amount;
  }
  if (fields.asset) {
    out.asset = fields.asset;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

function withNativeValueNote(ctx: TxContext, summary: string): string {
  if (ctx.value > 0n) {
    ctx.warnings.push(`also sends ${nativeAmount(ctx.value, ctx.chain)} to the contract`);
  }
  return summary;
}

type SelectorDecoder = (ctx: TxContext) => Omit<Decoded, "warnings" | "chain"> | undefined;

const SELECTORS: Record<string, { name: string; decode: SelectorDecoder }> = {
  // transfer(address,uint256)
  a9059cbb: {
    name: "transfer(address,uint256)",
    decode: (ctx) => {
      const words = argWords(ctx.data, 2);
      if (!words) return undefined;
      const recipient = wordToAddress(words[0] as string, ctx.warnings);
      const amount = wordToUint(words[1] as string);
      return {
        action: "ERC-20 transfer",
        counterparty: recipient,
        role: "recipient",
        interaction: interaction("token_transfer"),
        amountLabel: `${amount.toString()} base units`,
        payment: payment({ network: ctx.chain, pay_to: recipient, amount: amount.toString(), asset: ctx.contract }),
        summary: withNativeValueNote(
          ctx,
          `ERC-20 transfer: sends ${amount.toString()} base units of token ${ctx.contract} to recipient ${recipient}.`,
        ),
      };
    },
  },
  // transferFrom(address,address,uint256) — ERC-20 amount or ERC-721 token id.
  "23b872dd": {
    name: "transferFrom(address,address,uint256)",
    decode: (ctx) => {
      const words = argWords(ctx.data, 3);
      if (!words) return undefined;
      const source = wordToAddress(words[0] as string, ctx.warnings);
      const recipient = wordToAddress(words[1] as string, ctx.warnings);
      const amountOrId = wordToUint(words[2] as string);
      if (ctx.sender && source !== ctx.sender) {
        ctx.warnings.push(`tokens are pulled from ${source}, which is not the sending account`);
      }
      return {
        action: "Token transferFrom",
        counterparty: recipient,
        role: "recipient",
        interaction: interaction("token_transfer"),
        amountLabel: `${amountOrId.toString()} (amount or NFT token id)`,
        // Amount omitted: the same selector is an ERC-721 token id.
        payment: payment({ network: ctx.chain, pay_to: recipient, asset: ctx.contract }),
        summary: withNativeValueNote(
          ctx,
          `transferFrom on token contract ${ctx.contract}: moves ${amountOrId.toString()} (ERC-20 amount or NFT token id) from ${source} to recipient ${recipient}.`,
        ),
      };
    },
  },
  // approve(address,uint256)
  "095ea7b3": {
    name: "approve(address,uint256)",
    decode: (ctx) => {
      const words = argWords(ctx.data, 2);
      if (!words) return undefined;
      const spender = wordToAddress(words[0] as string, ctx.warnings);
      const amount = wordToUint(words[1] as string);
      if (amount === 0n) {
        return {
          action: "ERC-20 approve (revoke)",
          counterparty: spender,
          role: "spender",
          // A zero approval is a revocation, not an approval.
          interaction: interaction("contract_call"),
          amountLabel: "0 (revokes allowance)",
          summary: withNativeValueNote(
            ctx,
            `ERC-20 approve on token ${ctx.contract}: sets the allowance of spender ${spender} to 0 (revokes it).`,
          ),
        };
      }
      const allowance = describeAllowance(amount, UNLIMITED_UINT256, ctx.warnings);
      return {
        action: "ERC-20 approve",
        counterparty: spender,
        role: "spender",
        interaction: interaction("token_approval", allowance.unlimited),
        unlimited: allowance.unlimited,
        amountLabel: allowance.label,
        payment: payment({ network: ctx.chain, pay_to: spender, amount: amount.toString(), asset: ctx.contract }),
        summary: withNativeValueNote(
          ctx,
          `ERC-20 approve on token ${ctx.contract}: grants spender ${spender} ${allowance.phrase}.`,
        ),
      };
    },
  },
  // increaseAllowance(address,uint256)
  "39509351": {
    name: "increaseAllowance(address,uint256)",
    decode: (ctx) => {
      const words = argWords(ctx.data, 2);
      if (!words) return undefined;
      const spender = wordToAddress(words[0] as string, ctx.warnings);
      const amount = wordToUint(words[1] as string);
      const allowance = describeAllowance(amount, UNLIMITED_UINT256, ctx.warnings);
      return {
        action: "ERC-20 increaseAllowance",
        counterparty: spender,
        role: "spender",
        interaction: amount > 0n ? interaction("token_approval", allowance.unlimited) : interaction("contract_call"),
        unlimited: allowance.unlimited,
        amountLabel: allowance.unlimited ? "UNLIMITED" : `+${amount.toString()} base units`,
        payment: payment({ network: ctx.chain, pay_to: spender, amount: amount.toString(), asset: ctx.contract }),
        summary: withNativeValueNote(
          ctx,
          `ERC-20 increaseAllowance on token ${ctx.contract}: raises the allowance of spender ${spender} by ${
            allowance.unlimited ? "an UNLIMITED amount" : `${amount.toString()} base units`
          }.`,
        ),
      };
    },
  },
  // setApprovalForAll(address,bool)
  a22cb465: {
    name: "setApprovalForAll(address,bool)",
    decode: (ctx) => {
      const words = argWords(ctx.data, 2);
      if (!words) return undefined;
      const operator = wordToAddress(words[0] as string, ctx.warnings);
      const approved = wordToUint(words[1] as string) !== 0n;
      return {
        action: approved ? "NFT setApprovalForAll" : "NFT setApprovalForAll (revoke)",
        counterparty: operator,
        role: "operator",
        interaction: interaction(approved ? "nft_approval" : "contract_call"),
        unlimited: approved,
        amountLabel: approved ? "ALL items in the collection" : "revokes operator",
        payment: approved ? payment({ network: ctx.chain, pay_to: operator, asset: ctx.contract }) : undefined,
        summary: withNativeValueNote(
          ctx,
          approved
            ? `setApprovalForAll on NFT collection ${ctx.contract}: grants operator ${operator} control of ALL of the sender's items in this collection.`
            : `setApprovalForAll on NFT collection ${ctx.contract}: revokes operator ${operator}.`,
        ),
      };
    },
  },
  // safeTransferFrom(address,address,uint256)
  "42842e0e": {
    name: "safeTransferFrom(address,address,uint256)",
    decode: (ctx) => nftTransfer(ctx),
  },
  // safeTransferFrom(address,address,uint256,bytes)
  b88d4fde: {
    name: "safeTransferFrom(address,address,uint256,bytes)",
    decode: (ctx) => nftTransfer(ctx),
  },
  // ERC-1155 safeTransferFrom(address,address,uint256,uint256,bytes)
  f242432a: {
    name: "safeTransferFrom(address,address,uint256,uint256,bytes)",
    decode: (ctx) => {
      const words = argWords(ctx.data, 4);
      if (!words) return undefined;
      const source = wordToAddress(words[0] as string, ctx.warnings);
      const recipient = wordToAddress(words[1] as string, ctx.warnings);
      const id = wordToUint(words[2] as string);
      const amount = wordToUint(words[3] as string);
      return {
        action: "ERC-1155 transfer",
        counterparty: recipient,
        role: "recipient",
        interaction: interaction("token_transfer"),
        amountLabel: `${amount.toString()} of token id ${id.toString()}`,
        payment: payment({ network: ctx.chain, pay_to: recipient, asset: ctx.contract }),
        summary: withNativeValueNote(
          ctx,
          `ERC-1155 safeTransferFrom on ${ctx.contract}: sends ${amount.toString()} of token id ${id.toString()} from ${source} to recipient ${recipient}.`,
        ),
      };
    },
  },
  // ERC-1155 safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)
  "2eb2c2d6": {
    name: "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
    decode: (ctx) => {
      const words = argWords(ctx.data, 2);
      if (!words) return undefined;
      const source = wordToAddress(words[0] as string, ctx.warnings);
      const recipient = wordToAddress(words[1] as string, ctx.warnings);
      return {
        action: "ERC-1155 batch transfer",
        counterparty: recipient,
        role: "recipient",
        interaction: interaction("token_transfer"),
        amountLabel: "multiple token ids",
        payment: payment({ network: ctx.chain, pay_to: recipient, asset: ctx.contract }),
        summary: withNativeValueNote(
          ctx,
          `ERC-1155 safeBatchTransferFrom on ${ctx.contract}: sends multiple token ids from ${source} to recipient ${recipient}.`,
        ),
      };
    },
  },
  // Permit2 approve(address token,address spender,uint160 amount,uint48 expiration)
  "87517c45": {
    name: "approve(address,address,uint160,uint48)",
    decode: (ctx) => {
      const words = argWords(ctx.data, 4);
      if (!words) return undefined;
      const token = wordToAddress(words[0] as string, ctx.warnings);
      const spender = wordToAddress(words[1] as string, ctx.warnings);
      const amount = wordToUint(words[2] as string);
      const expiration = unixDate(wordToUint(words[3] as string));
      const allowance = describeAllowance(amount, UNLIMITED_UINT160, ctx.warnings);
      if (ctx.contract !== PERMIT2_ADDRESS) {
        ctx.warnings.push(`Permit2-style approve sent to ${ctx.contract}, which is not the canonical Permit2 contract`);
      }
      return {
        action: "Permit2 approve",
        counterparty: spender,
        role: "spender",
        interaction: amount > 0n ? interaction("token_approval", allowance.unlimited) : interaction("contract_call"),
        unlimited: allowance.unlimited,
        amountLabel: allowance.label,
        payment: payment({ network: ctx.chain, pay_to: spender, amount: amount.toString(), asset: token }),
        summary: withNativeValueNote(
          ctx,
          `Permit2 approve via ${ctx.contract}: grants spender ${spender} ${allowance.phrase} on token ${token}, expiring ${expiration}.`,
        ),
      };
    },
  },
  // EIP-2612 permit(address,address,uint256,uint256,uint8,bytes32,bytes32)
  d505accf: {
    name: "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    decode: (ctx) => {
      const words = argWords(ctx.data, 4);
      if (!words) return undefined;
      const owner = wordToAddress(words[0] as string, ctx.warnings);
      const spender = wordToAddress(words[1] as string, ctx.warnings);
      const amount = wordToUint(words[2] as string);
      const deadline = unixDate(wordToUint(words[3] as string));
      const allowance = describeAllowance(amount, UNLIMITED_UINT256, ctx.warnings);
      return {
        action: "EIP-2612 permit (on-chain)",
        counterparty: spender,
        role: "spender",
        // Submitting a signed permit on-chain is an approval via calldata.
        interaction: amount > 0n ? interaction("token_approval", allowance.unlimited) : interaction("contract_call"),
        unlimited: allowance.unlimited,
        amountLabel: allowance.label,
        payment: payment({ network: ctx.chain, pay_to: spender, amount: amount.toString(), asset: ctx.contract }),
        summary: withNativeValueNote(
          ctx,
          `EIP-2612 permit submitted on token ${ctx.contract}: owner ${owner} grants spender ${spender} ${allowance.phrase}, deadline ${deadline}.`,
        ),
      };
    },
  },
};

function nftTransfer(ctx: TxContext): Omit<Decoded, "warnings" | "chain"> | undefined {
  const words = argWords(ctx.data, 3);
  if (!words) return undefined;
  const source = wordToAddress(words[0] as string, ctx.warnings);
  const recipient = wordToAddress(words[1] as string, ctx.warnings);
  const tokenId = wordToUint(words[2] as string);
  if (ctx.sender && source !== ctx.sender) {
    ctx.warnings.push(`the NFT is pulled from ${source}, which is not the sending account`);
  }
  return {
    action: "NFT transfer",
    counterparty: recipient,
    role: "recipient",
    interaction: interaction("token_transfer"),
    amountLabel: `token id ${tokenId.toString()}`,
    payment: payment({ network: ctx.chain, pay_to: recipient, asset: ctx.contract }),
    summary: withNativeValueNote(
      ctx,
      `NFT safeTransferFrom on collection ${ctx.contract}: sends token id ${tokenId.toString()} from ${source} to recipient ${recipient}.`,
    ),
  };
}

function contractCall(ctx: TxContext, detail: string): Decoded {
  const sendsValue = ctx.value > 0n;
  return {
    action: "Contract call",
    counterparty: ctx.contract,
    role: "contract",
    chain: ctx.chain,
    interaction: interaction("contract_call"),
    amountLabel: sendsValue ? nativeAmount(ctx.value, ctx.chain) : undefined,
    payment: sendsValue
      ? payment({ network: ctx.chain, pay_to: ctx.contract, amount: ctx.value.toString(), asset: "native" })
      : undefined,
    summary: `Contract call to ${ctx.contract} (${detail})${sendsValue ? `, sending ${nativeAmount(ctx.value, ctx.chain)}` : ""}.`,
    warnings: ctx.warnings,
  };
}

/**
 * Decodes an EVM transaction into the counterparty that should be checked.
 *
 * @param tx - The transaction (`to`, `from`, `value`, `data`).
 * @param chainId - CAIP-2 chain id of the network.
 * @returns The decoded request.
 */
export function decodeTransaction(tx: TransactionLike, chainId?: unknown): Decoded {
  const chain = normalizeChainId(chainId);
  const warnings: string[] = [];
  const rawValue = tx.value;
  let value = parseUint(rawValue);
  if (value === undefined) {
    if (!isMissing(rawValue)) {
      warnings.push("transaction value could not be parsed");
    }
    value = 0n;
  }

  if (isMissing(tx.to)) {
    return {
      action: "Contract deployment",
      chain,
      // Never sent: there is no counterparty.
      interaction: interaction("contract_call"),
      amountLabel: value > 0n ? nativeAmount(value, chain) : undefined,
      summary: `Contract deployment (no recipient address)${value > 0n ? `, sending ${nativeAmount(value, chain)}` : ""}.`,
      warnings,
      localNote:
        "This transaction deploys a new contract, so there is no counterparty address to check. Nothing was sent to x402check.",
    };
  }

  const contract = normalizeAddress(tx.to);
  if (!contract) {
    return {
      action: "Unrecognized recipient",
      chain,
      interaction: interaction("contract_call"),
      summary: "Transaction with a recipient that is not a valid EVM address.",
      warnings,
      localNote:
        "The recipient is not a valid EVM address, so x402check could not check it. Do not proceed unless you know exactly what this is.",
    };
  }

  const ctx: TxContext = {
    contract,
    sender: normalizeAddress(tx.from),
    value,
    chain,
    data: "",
    warnings,
  };

  const data = normalizeCalldata(tx.data !== undefined ? tx.data : tx.input);
  if (data === null) {
    warnings.push("calldata is not valid hex");
    return contractCall(ctx, "unparseable calldata");
  }
  if (data === "") {
    return {
      action: "Native transfer",
      counterparty: contract,
      role: "recipient",
      chain,
      interaction: interaction("native_transfer"),
      amountLabel: nativeAmount(value, chain),
      payment: payment({ network: chain, pay_to: contract, amount: value.toString(), asset: "native" }),
      summary: `Native transfer: sends ${nativeAmount(value, chain)} to recipient ${contract}.`,
      warnings,
    };
  }
  if (data.length < 8) {
    return contractCall(ctx, `${data.length / 2} bytes of non-standard calldata`);
  }

  ctx.data = data;
  const selector = data.slice(0, 8);
  const known = SELECTORS[selector];
  if (known) {
    const decoded = known.decode(ctx);
    if (decoded) {
      return { ...decoded, chain, warnings };
    }
    warnings.push(`calldata is too short for ${known.name}`);
    return contractCall(ctx, `truncated ${known.name}`);
  }
  return contractCall(ctx, `function selector 0x${selector}, ${data.length / 2} bytes of calldata`);
}

// ---------------------------------------------------------------------------
// EIP-712 typed data (eth_signTypedData v1 / v3 / v4)
// ---------------------------------------------------------------------------

/** Field names that usually hold the party receiving rights or funds. */
const PREFERRED_KEYS = ["spender", "operator", "to", "recipient", "delegate", "taker", "receiver"];

function roleForKey(key: string): Role {
  switch (key.toLowerCase()) {
    case "spender":
      return "spender";
    case "operator":
      return "operator";
    case "delegate":
      return "delegate";
    case "to":
    case "recipient":
    case "receiver":
      return "recipient";
    default:
      return "counterparty";
  }
}

type AddressField = { key: string; path: string; address: string };

function collectAddressFields(
  node: unknown,
  path: string,
  key: string,
  depth: number,
  out: AddressField[],
  budget: { nodes: number },
): void {
  budget.nodes -= 1;
  if (budget.nodes < 0 || depth > 8) {
    return;
  }
  const address = normalizeAddress(node);
  if (address) {
    out.push({ key, path, address });
    return;
  }
  if (Array.isArray(node)) {
    node.forEach((child, index) => collectAddressFields(child, `${path}[${index}]`, key, depth + 1, out, budget));
    return;
  }
  if (isRecord(node)) {
    for (const [childKey, child] of Object.entries(node)) {
      collectAddressFields(child, path ? `${path}.${childKey}` : childKey, childKey, depth + 1, out, budget);
    }
  }
}

/** Picks the most relevant address field, excluding signer/contract/zero. */
function pickCounterpartyField(fields: AddressField[], exclude: (string | undefined)[]): AddressField | undefined {
  const skip = new Set([ZERO_ADDRESS, ...exclude.filter((value): value is string => Boolean(value))]);
  const candidates = fields.filter((field) => !skip.has(field.address));
  for (const preferred of PREFERRED_KEYS) {
    const match = candidates.find((field) => field.key.toLowerCase() === preferred);
    if (match) {
      return match;
    }
  }
  return candidates[0];
}

/** A few scalar leaves as "path=value", for context. No raw blobs. */
function scalarFields(node: unknown, limit: number): string[] {
  const out: string[] = [];
  const walk = (value: unknown, path: string, depth: number) => {
    if (out.length >= limit || depth > 4) {
      return;
    }
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      const text = cleanText(String(value)).text;
      out.push(`${path}=${capText(text, 48)}`);
      return;
    }
    if (Array.isArray(value)) {
      out.push(`${path}=[${value.length} items]`);
      return;
    }
    if (isRecord(value)) {
      for (const [key, child] of Object.entries(value)) {
        walk(child, path ? `${path}.${key}` : key, depth + 1);
      }
    }
  };
  walk(node, "", 0);
  return out;
}

type TypedDataContext = {
  method: string;
  signer?: string;
  chain?: string;
  verifyingContract?: string;
  domainName?: string;
  primaryType: string;
  message: Record<string, unknown>;
  warnings: string[];
};

function domainLabel(ctx: TypedDataContext): string {
  const parts = [ctx.domainName ? quote(ctx.domainName, 40) : "unnamed domain"];
  if (ctx.verifyingContract) {
    parts.push(`verifying contract ${ctx.verifyingContract}`);
  }
  return parts.join(", ");
}

function checkPermit2Domain(ctx: TypedDataContext): void {
  if (ctx.verifyingContract && ctx.verifyingContract !== PERMIT2_ADDRESS) {
    ctx.warnings.push(
      `Permit2-style message whose verifying contract ${ctx.verifyingContract} is not the canonical Permit2 contract`,
    );
  }
}

type TokenAmount = { token?: string; amount?: bigint; expiration?: bigint };

function describeTokenAllowance(
  entry: TokenAmount,
  threshold: bigint,
  warnings: string[],
  style: "allowance" | "transfer",
) {
  const allowance =
    entry.amount === undefined
      ? { unlimited: false, label: "unknown amount", phrase: "an allowance of unknown size" }
      : describeAllowance(entry.amount, threshold, warnings);
  const token = entry.token ?? "(unknown)";
  if (style === "transfer") {
    const amount =
      entry.amount === undefined
        ? "an unknown amount"
        : allowance.unlimited
          ? "an UNLIMITED amount"
          : `up to ${entry.amount.toString()} base units`;
    return { allowance, text: `${amount} of token ${token}` };
  }
  const expiry = entry.expiration !== undefined ? `, expiring ${unixDate(entry.expiration)}` : "";
  return { allowance, text: `${allowance.phrase} on token ${token}${expiry}` };
}

function tokenPayment(ctx: TypedDataContext, spender: string, entries: TokenAmount[]): Payment | undefined {
  if (entries.length === 1) {
    const [entry] = entries as [TokenAmount];
    return payment({
      network: ctx.chain,
      pay_to: spender,
      amount: entry.amount !== undefined ? entry.amount.toString() : undefined,
      asset: entry.token,
    });
  }
  return payment({ network: ctx.chain, pay_to: spender });
}

/**
 * Permits are approvals ("permit_signature"), except when every amount is
 * known to be zero: that grants nothing, like a revocation.
 *
 * @param amounts - The permitted amounts (undefined when unparseable).
 * @param unlimited - Whether any amount is unlimited.
 * @returns The interaction.
 */
function permitInteraction(amounts: (bigint | undefined)[], unlimited: boolean): Interaction {
  const grantsNothing = amounts.length > 0 && amounts.every((amount) => amount === 0n);
  return grantsNothing ? interaction("message_signature") : interaction("permit_signature", unlimited);
}

function decodePermit2Allowance(ctx: TypedDataContext, batch: boolean): Decoded | undefined {
  const spender = normalizeAddress(ctx.message.spender);
  if (!spender) return undefined;
  const rawDetails = ctx.message.details;
  const detailList = batch ? (Array.isArray(rawDetails) ? rawDetails : []) : [rawDetails];
  const entries: TokenAmount[] = detailList.filter(isRecord).map((detail) => ({
    token: normalizeAddress(detail.token),
    amount: parseUint(detail.amount),
    expiration: parseUint(detail.expiration),
  }));
  if (entries.length === 0) return undefined;
  checkPermit2Domain(ctx);
  const described = entries.map((entry) =>
    describeTokenAllowance(entry, UNLIMITED_UINT160, ctx.warnings, "allowance"),
  );
  const unlimited = described.some((item) => item.allowance.unlimited);
  const sigDeadline = unixDate(parseUint(ctx.message.sigDeadline));
  const shown = described.slice(0, 3).map((item) => item.text);
  if (described.length > 3) shown.push(`and ${described.length - 3} more tokens`);
  return {
    action: batch ? "Permit2 PermitBatch" : "Permit2 PermitSingle",
    counterparty: spender,
    role: "spender",
    chain: ctx.chain,
    interaction: permitInteraction(
      entries.map((entry) => entry.amount),
      unlimited,
    ),
    unlimited,
    amountLabel: unlimited ? "UNLIMITED" : entries.length === 1 ? described[0]?.allowance.label : `${entries.length} tokens`,
    payment: tokenPayment(ctx, spender, entries),
    summary: `Permit2 ${batch ? "PermitBatch" : "PermitSingle"} signature (${domainLabel(ctx)}): grants spender ${spender} ${shown.join("; ")}${
      sigDeadline ? `; signature valid until ${sigDeadline}` : ""
    }.`,
    warnings: ctx.warnings,
  };
}

function decodePermit2Transfer(ctx: TypedDataContext): Decoded | undefined {
  const spender = normalizeAddress(ctx.message.spender);
  if (!spender) return undefined;
  const rawPermitted = ctx.message.permitted;
  const list = Array.isArray(rawPermitted) ? rawPermitted : [rawPermitted];
  const entries: TokenAmount[] = list.filter(isRecord).map((item) => ({
    token: normalizeAddress(item.token),
    amount: parseUint(item.amount),
  }));
  if (entries.length === 0) return undefined;
  checkPermit2Domain(ctx);
  const described = entries.map((entry) =>
    describeTokenAllowance(entry, UNLIMITED_UINT160, ctx.warnings, "transfer"),
  );
  const unlimited = described.some((item) => item.allowance.unlimited);
  const deadline = unixDate(parseUint(ctx.message.deadline));
  const shown = described.slice(0, 3).map((item) => item.text);
  if (described.length > 3) shown.push(`and ${described.length - 3} more tokens`);
  const witness = ctx.primaryType.includes("Witness") ? " with a witness (order data)" : "";
  return {
    action: `Permit2 ${ctx.primaryType}`,
    counterparty: spender,
    role: "spender",
    chain: ctx.chain,
    interaction: permitInteraction(
      entries.map((entry) => entry.amount),
      unlimited,
    ),
    unlimited,
    amountLabel: unlimited ? "UNLIMITED" : entries.length === 1 ? described[0]?.allowance.label : `${entries.length} tokens`,
    payment: tokenPayment(ctx, spender, entries),
    summary: `Permit2 ${ctx.primaryType} signature${witness} (${domainLabel(ctx)}): lets spender ${spender} transfer ${shown.join("; ")} out of the signer's wallet${
      deadline ? `, deadline ${deadline}` : ""
    }.`,
    warnings: ctx.warnings,
  };
}

function decodeErc2612Permit(ctx: TypedDataContext): Decoded | undefined {
  const spender = normalizeAddress(ctx.message.spender);
  if (!spender) return undefined;
  const token = ctx.verifyingContract;
  if ("allowed" in ctx.message) {
    // DAI-style permit: allowed=true grants an unlimited allowance.
    const allowed = ctx.message.allowed === true || ctx.message.allowed === "true";
    const expiry = unixDate(parseUint(ctx.message.expiry));
    return {
      action: allowed ? "DAI-style permit" : "DAI-style permit (revoke)",
      counterparty: spender,
      role: "spender",
      chain: ctx.chain,
      interaction: allowed ? interaction("permit_signature", true) : interaction("message_signature"),
      unlimited: allowed,
      amountLabel: allowed ? "UNLIMITED" : "0 (revokes allowance)",
      payment: allowed ? payment({ network: ctx.chain, pay_to: spender, amount: MAX_UINT256.toString(), asset: token }) : undefined,
      summary: `DAI-style permit signature (${domainLabel(ctx)}): ${
        allowed ? `grants spender ${spender} an UNLIMITED allowance` : `revokes the allowance of spender ${spender}`
      }${expiry ? `, expiry ${expiry}` : ""}.`,
      warnings: ctx.warnings,
    };
  }
  const amount = parseUint(ctx.message.value);
  const allowance =
    amount === undefined
      ? { unlimited: false, label: "unknown amount", phrase: "an allowance of unknown size" }
      : describeAllowance(amount, UNLIMITED_UINT256, ctx.warnings);
  const deadline = unixDate(parseUint(ctx.message.deadline));
  return {
    action: "EIP-2612 permit",
    counterparty: spender,
    role: "spender",
    chain: ctx.chain,
    interaction: permitInteraction([amount], allowance.unlimited),
    unlimited: allowance.unlimited,
    amountLabel: allowance.label,
    payment: payment({ network: ctx.chain, pay_to: spender, amount: amount?.toString(), asset: token }),
    summary: `EIP-2612 permit signature (${domainLabel(ctx)}): grants spender ${spender} ${allowance.phrase} on token ${
      token ?? "(unknown)"
    }${deadline ? `, deadline ${deadline}` : ""}.`,
    warnings: ctx.warnings,
  };
}

type SeaportItem = {
  itemType: number;
  token?: string;
  id?: bigint;
  amount?: bigint;
  recipient?: string;
};

function seaportItem(value: unknown): SeaportItem | undefined {
  if (!isRecord(value)) return undefined;
  const itemType = parseUint(value.itemType);
  return {
    itemType: itemType === undefined || itemType > 5n ? -1 : Number(itemType),
    token: normalizeAddress(value.token),
    id: parseUint(value.identifierOrCriteria),
    amount: parseUint(value.startAmount),
    recipient: normalizeAddress(value.recipient),
  };
}

function describeSeaportItem(item: SeaportItem, chain?: string): string {
  const token = item.token ?? "(unknown token)";
  const amount = item.amount ?? 0n;
  switch (item.itemType) {
    case 0:
      return nativeAmount(amount, chain);
    case 1:
      return `${amount.toString()} base units of ERC-20 ${token}`;
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

function describeItems(items: SeaportItem[], chain?: string): string {
  const shown = items.slice(0, 3).map((item) => describeSeaportItem(item, chain));
  if (items.length > 3) shown.push(`and ${items.length - 3} more`);
  return shown.join(", ");
}

function decodeSeaportOrder(ctx: TypedDataContext): Decoded | undefined {
  const offerer = normalizeAddress(ctx.message.offerer);
  if (!offerer) return undefined;
  const offer = (Array.isArray(ctx.message.offer) ? ctx.message.offer : [])
    .map(seaportItem)
    .filter((item): item is SeaportItem => Boolean(item));
  const consideration = (Array.isArray(ctx.message.consideration) ? ctx.message.consideration : [])
    .map(seaportItem)
    .filter((item): item is SeaportItem => Boolean(item));
  const toOfferer = consideration.filter((item) => item.recipient === offerer);
  const toOthers = consideration.filter((item) => item.recipient && item.recipient !== offerer);

  if (ctx.signer && offerer !== ctx.signer) {
    ctx.warnings.push(`the order's offerer ${offerer} is not the signing account`);
  }
  const offersValue = offer.some((item) => item.itemType !== 0 || (item.amount ?? 0n) > 0n);
  const receivesNonNative = toOfferer.some((item) => item.itemType !== 0);
  const nativeReceived = toOfferer
    .filter((item) => item.itemType === 0)
    .reduce((sum, item) => sum + (item.amount ?? 0n), 0n);
  if (offersValue && toOfferer.length === 0) {
    ctx.warnings.push("the offerer receives NOTHING in return for the offered items");
  } else if (offersValue && !receivesNonNative && nativeReceived < 1_000_000_000_000_000n) {
    ctx.warnings.push(
      `the offerer receives only ${nativeAmount(nativeReceived, ctx.chain)} for the offered items (typical of NFT drainer listings)`,
    );
  }

  // Counterparty: the non-offerer recipient taking the largest native amount,
  // else the first non-offerer recipient, else the Seaport contract itself.
  let counterparty: string | undefined;
  let bestNative = -1n;
  for (const item of toOthers) {
    const native = item.itemType === 0 ? (item.amount ?? 0n) : -1n;
    if (counterparty === undefined || native > bestNative) {
      counterparty = item.recipient;
      bestNative = native;
    }
  }
  const role: Role = counterparty ? "recipient" : ctx.verifyingContract ? "contract" : "signer";
  const others = [...new Set(toOthers.map((item) => item.recipient as string))];
  counterparty = counterparty ?? ctx.verifyingContract ?? ctx.signer;
  if (!counterparty) return undefined;

  return {
    action: "Seaport order",
    counterparty,
    role,
    chain: ctx.chain,
    interaction: interaction("order_signature"),
    summary: `Seaport order signature (${domainLabel(ctx)}): offerer ${offerer} offers ${
      offer.length > 0 ? describeItems(offer, ctx.chain) : "nothing"
    }; the offerer receives ${toOfferer.length > 0 ? describeItems(toOfferer, ctx.chain) : "NOTHING"}; other consideration recipients: ${
      others.length > 0 ? others.slice(0, 3).join(", ") : "none"
    }.${
      role === "contract"
        ? " No third-party recipient in the order; subject is the Seaport contract."
        : role === "signer"
          ? " No counterparty address in message; subject is the signer."
          : ""
    }`,
    warnings: ctx.warnings,
  };
}

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
 * Marketplace orders: Seaport OrderComponents, Blur/0x/LooksRare/Rarible
 * orders ("Order", "MakerOrder", "ERC721Order", "BulkOrder"...), LooksRare v2
 * "Maker" and Blur bulk-listing "Root".
 *
 * @param primaryType - The EIP-712 primary type.
 * @param domainName - The EIP-712 domain name.
 * @returns Whether the typed data is a marketplace order.
 */
export function isOrderType(primaryType: string, domainName?: string): boolean {
  return (
    /order/iu.test(primaryType) ||
    primaryType === "Maker" ||
    (primaryType === "Root" && /blur/iu.test(domainName ?? ""))
  );
}

function genericTypedDataInteraction(ctx: TypedDataContext): Interaction {
  if (PERMIT_TYPES.has(ctx.primaryType)) return interaction("permit_signature");
  if (isOrderType(ctx.primaryType, ctx.domainName)) return interaction("order_signature");
  return interaction("message_signature");
}

function decodeGenericTypedData(ctx: TypedDataContext): Decoded {
  const fields: AddressField[] = [];
  collectAddressFields(ctx.message, "", "", 0, fields, { nodes: 2000 });
  const picked = pickCounterpartyField(fields, [ctx.signer, ctx.verifyingContract]);
  const details = scalarFields(ctx.message, 6).join("; ");
  const head = `EIP-712 signature (${ctx.method}, ${domainLabel(ctx)}, primary type ${quote(ctx.primaryType || "unknown", 40)})`;
  const action = `Typed data: ${capText(ctx.primaryType || "unknown", 40)}`;
  const kind = genericTypedDataInteraction(ctx);
  if (picked) {
    return {
      action,
      counterparty: picked.address,
      role: roleForKey(picked.key),
      chain: ctx.chain,
      interaction: kind,
      summary: `${head}: counterparty taken from field "${capText(picked.path, 60)}" = ${picked.address}.${
        details ? ` Fields: ${details}.` : ""
      }`,
      warnings: ctx.warnings,
    };
  }
  if (ctx.verifyingContract && ctx.verifyingContract !== ctx.signer) {
    return {
      action,
      counterparty: ctx.verifyingContract,
      role: "contract",
      chain: ctx.chain,
      interaction: kind,
      summary: `${head}: no counterparty address in the message; subject is the verifying contract.${
        details ? ` Fields: ${details}.` : ""
      }`,
      warnings: ctx.warnings,
    };
  }
  return signerSubject(
    action,
    `${head}: no counterparty address in message; subject is the signer.${details ? ` Fields: ${details}.` : ""}`,
    ctx.signer,
    ctx.chain,
    ctx.warnings,
    kind,
  );
}

function signerSubject(
  action: string,
  summary: string,
  signer: string | undefined,
  chain: string | undefined,
  warnings: string[],
  kind: Interaction = interaction("message_signature"),
): Decoded {
  if (!signer) {
    return {
      action,
      chain,
      interaction: kind,
      summary,
      warnings,
      localNote:
        "The request names no counterparty and the signing account is unknown, so there is nothing to check. Nothing was sent to x402check.",
    };
  }
  return { action, counterparty: signer, role: "signer", chain, interaction: kind, summary, warnings };
}

function parseTypedDataInput(data: unknown): unknown {
  if (typeof data === "string") {
    try {
      return JSON.parse(data) as unknown;
    } catch {
      return undefined;
    }
  }
  return data;
}

/**
 * Decodes eth_signTypedData (v1 array) and v3/v4 (object, or its JSON string).
 *
 * @param data - The `signature.data` value.
 * @param signerAddress - The signing account (`signature.from`).
 * @param method - The signature method, for the summary.
 * @returns The decoded request.
 */
export function decodeTypedData(data: unknown, signerAddress?: unknown, method = "eth_signTypedData_v4"): Decoded {
  const signer = normalizeAddress(signerAddress);
  const parsed = parseTypedDataInput(data);
  const warnings: string[] = [];
  if (Array.isArray(parsed)) {
    return decodeTypedDataV1(parsed, signer);
  }
  if (!isRecord(parsed)) {
    warnings.push("typed data could not be parsed");
    return signerSubject(
      "Typed data (unparseable)",
      `Typed-data signature (${method}) that could not be parsed; no counterparty address in message; subject is the signer.`,
      signer,
      undefined,
      warnings,
    );
  }
  const domain = isRecord(parsed.domain) ? parsed.domain : {};
  const ctx: TypedDataContext = {
    method,
    signer,
    chain: normalizeChainId(domain.chainId),
    verifyingContract: normalizeAddress(domain.verifyingContract),
    domainName: typeof domain.name === "string" ? domain.name : undefined,
    primaryType: typeof parsed.primaryType === "string" ? cleanText(parsed.primaryType).text : "",
    message: isRecord(parsed.message) ? parsed.message : {},
    warnings,
  };

  let decoded: Decoded | undefined;
  switch (ctx.primaryType) {
    case "Permit":
      decoded = decodeErc2612Permit(ctx);
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
    case "OrderComponents":
      decoded = decodeSeaportOrder(ctx);
      break;
    default:
      decoded = undefined;
  }
  return decoded ?? decodeGenericTypedData(ctx);
}

function decodeTypedDataV1(entries: unknown[], signer?: string): Decoded {
  const fields = entries.filter(isRecord).map((entry) => ({
    type: typeof entry.type === "string" ? entry.type : "",
    name: typeof entry.name === "string" ? entry.name : "",
    value: entry.value,
  }));
  const addressFields: AddressField[] = fields
    .filter((field) => field.type === "address")
    .map((field) => ({ key: field.name, path: field.name, address: normalizeAddress(field.value) as string }))
    .filter((field) => Boolean(field.address));
  const picked = pickCounterpartyField(addressFields, [signer]);
  const listed = fields
    .slice(0, 6)
    .map((field) => {
      const value = typeof field.value === "object" ? "[complex]" : cleanText(String(field.value)).text;
      return `${capText(cleanText(field.name).text, 24)} (${capText(field.type, 16)}) = ${capText(value, 48)}`;
    })
    .join("; ");
  const head = `Legacy typed-data signature (eth_signTypedData v1) with ${fields.length} field(s): ${listed}`;
  if (picked) {
    return {
      action: "Typed data (v1)",
      counterparty: picked.address,
      role: roleForKey(picked.key),
      interaction: interaction("message_signature"),
      summary: `${head}. Counterparty taken from field "${capText(picked.path, 40)}" = ${picked.address}.`,
      warnings: [],
    };
  }
  return signerSubject(
    "Typed data (v1)",
    `${head}. No counterparty address in message; subject is the signer.`,
    signer,
    undefined,
    [],
  );
}

// ---------------------------------------------------------------------------
// personal_sign
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function decodeUtf8(bytes: Uint8Array): string | undefined {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}

/** True when at least 90% of the characters are printable text. */
export function isMostlyPrintable(text: string): boolean {
  if (text.length === 0) return false;
  const chars = Array.from(text);
  const bad = chars.filter((char) => /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\uFFFD]/u.test(char)).length;
  return bad / chars.length <= 0.1;
}

/** Flattens a JSON message into "path=value" pairs for a readable excerpt. */
function jsonExcerpt(text: string): string | undefined {
  const trimmed = text.trim();
  if (!/^[[{]/u.test(trimmed)) return undefined;
  try {
    const parsed = JSON.parse(trimmed) as unknown;
    const pairs = scalarFields(parsed, 12);
    return pairs.length > 0 ? `JSON message: ${pairs.join("; ")}` : "JSON message with no readable fields";
  } catch {
    return undefined;
  }
}

type Siwe = { domain: string; address?: string; chainId?: string; uri?: string };

function parseSiwe(text: string): Siwe | undefined {
  const match = /^(?:([a-z][a-z0-9+.-]*):\/\/)?([^\s]+) wants you to sign in with your Ethereum account:\n(0x[0-9a-fA-F]{40})/u.exec(text);
  if (!match) return undefined;
  const chain = /^Chain ID: (\d{1,20})$/mu.exec(text);
  const uri = /^URI: (\S+)$/mu.exec(text);
  return {
    domain: (match[2] as string).toLowerCase(),
    address: normalizeAddress(match[3]),
    chainId: chain ? (chain[1] as string) : undefined,
    uri: uri ? (uri[1] as string) : undefined,
  };
}

/**
 * Decodes a personal_sign payload: hex → UTF-8 text when printable, then
 * extracts hostnames and 0x-addresses from the TEXT (never from the hex).
 *
 * @param data - The `signature.data` value (0x-hex, or plain text defensively).
 * @param signerAddress - The signing account.
 * @param originHostname - Hostname of the requesting site, if known.
 * @returns The decoded request.
 */
export function decodePersonalSign(data: unknown, signerAddress?: unknown, originHostname?: string): Decoded {
  const signer = normalizeAddress(signerAddress);
  const warnings: string[] = [];
  let text: string | undefined;
  let byteLength = 0;

  if (typeof data === "string" && /^0x([0-9a-fA-F]{2})*$/u.test(data)) {
    const bytes = hexToBytes(data.slice(2));
    byteLength = bytes.length;
    const decoded = decodeUtf8(bytes);
    text = decoded !== undefined && isMostlyPrintable(decoded) ? decoded : undefined;
  } else if (typeof data === "string") {
    text = data;
    byteLength = new TextEncoder().encode(data).length;
  }

  if (text === undefined) {
    const hashLike = byteLength === 32;
    if (hashLike) {
      warnings.push("the message is a raw 32-byte value (looks like a hash); blind-signing a hash can authorize anything");
    }
    return signerSubject(
      "Message signature (binary)",
      `personal_sign of binary data (${byteLength} bytes)${hashLike ? ", likely a hash" : ""}; no counterparty address in message; subject is the signer.`,
      signer,
      undefined,
      warnings,
    );
  }

  const clean = cleanText(text);
  if (clean.hadInvisible) {
    warnings.push("the message contains invisible or text-direction control characters");
  }
  const siwe = parseSiwe(text);
  let chain: string | undefined;
  if (siwe) {
    chain = siwe.chainId ? normalizeChainId(siwe.chainId) : undefined;
    const siweHost = hostFromUrl(`https://${siwe.domain}`) ?? siwe.domain;
    if (originHostname && siweHost !== originHostname) {
      warnings.push(`Sign-In with Ethereum message is for ${siweHost} but was requested by ${originHostname}`);
    }
    if (signer && siwe.address && siwe.address !== signer) {
      warnings.push(`Sign-In with Ethereum message names account ${siwe.address}, not the signer`);
    }
  }
  const hosts = extractHosts(text);
  if (siwe) {
    const siweHost = hostFromUrl(`https://${siwe.domain}`);
    if (siweHost && !hosts.includes(siweHost)) hosts.unshift(siweHost);
  }
  const addresses = extractAddresses(text, [signer, siwe?.address]);
  const excerpt = capText(jsonExcerpt(text) ?? clean.text, MAX_EXCERPT);
  const kind = siwe ? "Sign-In with Ethereum message" : "personal_sign message";
  const hostNote = hosts.length > 0 ? ` Message references: ${hosts.slice(0, 3).join(", ")}.` : "";
  const addressNote = addresses.length > 1 ? ` Other addresses in message: ${addresses.slice(1, 3).join(", ")}.` : "";

  if (addresses.length > 0) {
    const counterparty = addresses[0] as string;
    return {
      action: siwe ? "Sign-In with Ethereum" : "Message signature",
      counterparty,
      role: "counterparty",
      chain,
      interaction: interaction("message_signature"),
      summary: `${kind} (${Array.from(text).length} chars): "${excerpt}".${hostNote} Counterparty address named in message: ${counterparty}.${addressNote}`,
      warnings,
      referencedHosts: hosts,
    };
  }
  const decoded = signerSubject(
    siwe ? "Sign-In with Ethereum" : "Message signature",
    `${kind} (${Array.from(text).length} chars): "${excerpt}".${hostNote} No counterparty address in message; subject is the signer.`,
    signer,
    chain,
    warnings,
  );
  return { ...decoded, referencedHosts: hosts };
}

// ---------------------------------------------------------------------------
// Signature dispatch
// ---------------------------------------------------------------------------

export type SignatureLike = { from?: unknown; data?: unknown; signatureMethod?: unknown };

/**
 * Routes a signature request to the right decoder by method (or by data shape
 * when the method is missing).
 *
 * @param signature - The signature request.
 * @param originHostname - Hostname of the requesting site, if known.
 * @returns The decoded request.
 */
export function decodeSignature(signature: SignatureLike, originHostname?: string): Decoded {
  const method = typeof signature.signatureMethod === "string" ? signature.signatureMethod : "";
  const { data, from } = signature;
  switch (method) {
    case "personal_sign":
      return decodePersonalSign(data, from, originHostname);
    case "eth_signTypedData":
    case "eth_signTypedData_v1":
      return decodeTypedData(data, from, "eth_signTypedData v1");
    case "eth_signTypedData_v3":
      return decodeTypedData(data, from, "eth_signTypedData_v3");
    case "eth_signTypedData_v4":
      return decodeTypedData(data, from, "eth_signTypedData_v4");
    default:
      if (Array.isArray(data) || isRecord(data)) {
        return decodeTypedData(data, from, method || "typed data");
      }
      if (typeof data === "string" && /^\s*[[{]/u.test(data) && parseTypedDataInput(data) !== undefined) {
        return decodeTypedData(data, from, method || "typed data");
      }
      return decodePersonalSign(data, from, originHostname);
  }
}
