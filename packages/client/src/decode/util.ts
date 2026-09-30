// Vendored from snap/src/util.ts by scripts/sync-decoders.mjs. Edit the Snap source and re-sync.
/**
 * Shared types and helpers for the x402check decoders.
 *
 * Everything here is pure and bounded: every regular expression runs on input
 * that has already been capped in size, so a hostile multi-megabyte payload
 * can never blow the regex engine's stack (see MAX_* constants).
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
 * What kind of interaction a checked address is part of. The backend applies
 * deterministic rules on it (approvals/permits to an EOA are capped, etc.).
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
export type Interaction = { type: InteractionType; unlimited?: true | undefined };

/** Mirrors the backend `payment` binding. All fields optional strings. */
export type Payment = {
  network?: string | undefined;
  pay_to?: string | undefined;
  /** Decimal integer string in base units. */
  amount?: string | undefined;
  /** Token contract address or "native". */
  asset?: string | undefined;
};

/**
 * The transaction sent for server-side simulation (provider v0.3). Exactly the
 * keys the provider accepts: addresses as 0x-hex, value as minimal 0x-hex,
 * data as even-length 0x-hex (omitted when empty).
 */
export type SimulationTransaction = { from: string; to: string; value: string; data?: string | undefined };

/** An address worth checking, with why it matters. */
export type Candidate = {
  address: string;
  role: Role;
  interaction: Interaction;
  payment?: Payment | undefined;
  /** Short human-readable reason, e.g. "spender of an UNLIMITED allowance". */
  reason?: string | undefined;
  /** Local risk rank used to pick the primary address (higher = riskier). */
  rank: number;
  /** Unlimited / all-items grant (UI flag when this address is primary). */
  unlimited?: boolean | undefined;
  /** Amount or allowance label (UI, when this address is primary). */
  amountLabel?: string | undefined;
};

export type Decoded = {
  /** Short action label for the UI, e.g. "ERC-20 approve". */
  action: string;
  /** Primary checked address (lowercase). Undefined: nothing to check. */
  counterparty?: string | undefined;
  role?: Role | undefined;
  /** Why the primary address matters (sent with batch checks). */
  reason?: string | undefined;
  interaction: Interaction;
  payment?: Payment | undefined;
  /** Further addresses checked in the same batch (at most 2). */
  others: Candidate[];
  /** CAIP-2 chain id ("eip155:<decimal>") when known. */
  chain?: string | undefined;
  /** True for unlimited / all-items approvals (UI flag). */
  unlimited?: boolean | undefined;
  /** UI label for the amount or allowance. */
  amountLabel?: string | undefined;
  /** Decoded human-readable summary (becomes the request `context`). */
  summary: string;
  /** Locally detected red flags. */
  warnings: string[];
  /** Locally PROVEN danger (forces critical severity), e.g. delegatecall. */
  danger: string[];
  /** Explanation shown when the request is not sent to the server. */
  localNote?: string | undefined;
  /** Hostnames referenced inside a signed message (personal_sign). */
  referencedHosts?: string[] | undefined;
  /** Transaction to simulate server-side (EVM transactions only). */
  transaction?: SimulationTransaction | undefined;
  /** Why the transaction is not simulated, when it is not. */
  simulationSkipped?: string | undefined;
};

export const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
/** Canonical Uniswap Permit2 deployment (same address on every chain). */
export const PERMIT2_ADDRESS = "0x000000000022d473030f116ddee9f6b43ac78ba3";

export const MAX_UINT256 = (1n << 256n) - 1n;
export const MAX_UINT160 = (1n << 160n) - 1n;
/** uint256 allowances at or above 2^255 are unlimited. */
export const UNLIMITED_UINT256 = 1n << 255n;
/** Permit2 allowances are uint160; at or above 2^159 is unlimited. */
export const UNLIMITED_UINT160 = 1n << 159n;
/** At or above 10^30 base units an allowance is effectively unlimited. */
export const EFFECTIVELY_UNLIMITED = 10n ** 30n;

/** Excerpts of untrusted text never exceed this. */
export const MAX_EXCERPT = 300;
/** Messages larger than this are summarized, not decoded. */
export const MAX_TEXT_BYTES = 64 * 1024;
/** Untrusted strings are cut to this before any cleaning regex runs. */
export const MAX_CLEAN_INPUT = 4096;

/** Local risk ranks (higher = riskier) used to choose the primary address. */
export const RANK = {
  payableTarget: 1000,
  delegatecall: 100,
  orderOutput: 95,
  unlimitedApproval: 90,
  approval: 80,
  transfer: 70,
  contract: 40,
  verifyingContract: 30,
  revoke: 20,
  signer: 0,
} as const;

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function hasOwn(object: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(object, key);
}

const STRICT_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/u;

/** Lowercase 0x-address when `value` is exactly 0x + 40 hex digits. */
export function normalizeAddress(value: unknown): string | undefined {
  return typeof value === "string" && value.length === 42 && STRICT_ADDRESS_RE.test(value)
    ? value.toLowerCase()
    : undefined;
}

export function interaction(type: InteractionType, unlimited = false): Interaction {
  return unlimited ? { type, unlimited: true } : { type };
}

// ---------------------------------------------------------------------------
// Integers (mirrors JavaScript BigInt(), which is what MetaMask's encoders use)
// ---------------------------------------------------------------------------

const MAX_DIGITS: Record<number, number> = { 2: 256, 8: 86, 10: 78, 16: 64 };
/** Returned for well-formed numbers too large for any 256-bit type. */
export const OUT_OF_RANGE = 1n << 300n;

function isDigit(code: number, radix: number): boolean {
  if (radix === 16) {
    return (code >= 48 && code <= 57) || (code >= 65 && code <= 70) || (code >= 97 && code <= 102);
  }
  return code >= 48 && code < 48 + radix;
}

/**
 * Parses a string exactly like `BigInt(string)`: surrounding whitespace, an
 * optional sign for decimals, 0x/0o/0b prefixes (any case), leading zeros and
 * the empty string (0). No regex, so it is safe on megabyte inputs.
 *
 * @param input - The string.
 * @returns The value, OUT_OF_RANGE for huge values, or undefined when invalid.
 */
export function parseBigIntString(input: string): bigint | undefined {
  const text = input.trim();
  if (text.length === 0) return 0n;
  let index = 0;
  let radix = 10;
  let negative = false;
  const first = text.charCodeAt(0);
  if (first === 43 || first === 45) {
    negative = first === 45;
    index = 1;
  } else if (first === 48 && text.length > 1) {
    const marker = text[1];
    if (marker === "x" || marker === "X") radix = 16;
    else if (marker === "o" || marker === "O") radix = 8;
    else if (marker === "b" || marker === "B") radix = 2;
    if (radix !== 10) index = 2;
  }
  if (index >= text.length) return undefined;
  let firstSignificant = -1;
  for (let position = index; position < text.length; position += 1) {
    const code = text.charCodeAt(position);
    if (!isDigit(code, radix)) return undefined;
    if (firstSignificant < 0 && code !== 48) firstSignificant = position;
  }
  if (firstSignificant < 0) return 0n;
  const digits = text.slice(firstSignificant);
  if (digits.length > (MAX_DIGITS[radix] ?? 78)) return negative ? -OUT_OF_RANGE : OUT_OF_RANGE;
  const prefix = radix === 16 ? "0x" : radix === 8 ? "0o" : radix === 2 ? "0b" : "";
  const value = BigInt(`${prefix}${digits}`);
  return negative ? -value : value;
}

/**
 * `BigInt(value)` semantics for number | bigint | string, never throwing.
 *
 * @param value - The value.
 * @returns The integer or undefined.
 */
export function toBigIntLike(value: unknown): bigint | undefined {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return Number.isInteger(value) ? BigInt(value) : undefined;
  if (typeof value === "string") return parseBigIntString(value);
  return undefined;
}

/**
 * Parses an unsigned 256-bit quantity (transaction `value`, calldata-free
 * inputs): bigint, integer number, decimal or 0x-hex string.
 *
 * @param value - The value.
 * @returns The value or undefined.
 */
export function parseUint(value: unknown): bigint | undefined {
  const parsed = toBigIntLike(value);
  return parsed !== undefined && parsed >= 0n && parsed <= MAX_UINT256 ? parsed : undefined;
}

/** Normalizes a chain id (CAIP-2, hex, decimal or number) to "eip155:<decimal>". */
export function normalizeChainId(value: unknown): string | undefined {
  let id: bigint | undefined;
  if (typeof value === "string") {
    const caip = /^eip155:(\d{1,20})$/u.exec(value.length <= 40 ? value.trim() : "");
    id = caip ? BigInt(caip[1] as string) : parseUint(value.length <= 80 ? value : "");
  } else {
    id = parseUint(value);
  }
  if (id === undefined || id <= 0n || id > 0xffffffffffffffffn) return undefined;
  return `eip155:${id.toString()}`;
}

// ---------------------------------------------------------------------------
// Known tokens (per chain) - revocation allowlist, symbols and dust thresholds
// ---------------------------------------------------------------------------

export type TokenInfo = { symbol: string; decimals: number; stable?: boolean | undefined; wrappedNative?: boolean | undefined };

const USDC = (address: string): [string, TokenInfo] => [address, { symbol: "USDC", decimals: 6, stable: true }];
const USDT = (address: string, decimals = 6): [string, TokenInfo] => [address, { symbol: "USDT", decimals, stable: true }];
const DAI = (address: string): [string, TokenInfo] => [address, { symbol: "DAI", decimals: 18, stable: true }];
const WRAPPED = (address: string, symbol: string): [string, TokenInfo] => [
  address,
  { symbol, decimals: 18, wrappedNative: true },
];

/** Well-known ERC-20s (never NFTs) on the supported chains. */
export const KNOWN_TOKENS: Record<string, Map<string, TokenInfo>> = {
  "eip155:1": new Map([
    USDC("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
    USDT("0xdac17f958d2ee523a2206206994597c13d831ec7"),
    DAI("0x6b175474e89094c44da98b954eedeac495271d0f"),
    WRAPPED("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", "WETH"),
  ]),
  "eip155:10": new Map([
    USDC("0x0b2c639c533813f4aa9d7837caf62653d097ff85"),
    USDT("0x94b008aa00579c1307b0ef2c499ad98a8ce58e58"),
    DAI("0xda10009cbd5d07dd0cecc66161fc93d7c9000da1"),
    WRAPPED("0x4200000000000000000000000000000000000006", "WETH"),
  ]),
  "eip155:56": new Map([
    [
      "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
      { symbol: "USDC", decimals: 18, stable: true },
    ],
    USDT("0x55d398326f99059ff775485246999027b3197955", 18),
    WRAPPED("0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c", "WBNB"),
  ]),
  "eip155:137": new Map([
    USDC("0x3c499c542cef5e3811e1192ce70d8cc03d5c3359"),
    USDC("0x2791bca1f2de4661ed88a30c99a7a9449aa84174"),
    USDT("0xc2132d05d31c914a87c6611c10748aeb04b58e8f"),
    DAI("0x8f3cf7ad23cd3cadbd9735aff958023239c6a063"),
    WRAPPED("0x7ceb23fd6bc0add59e62ac25578270cff1b9f619", "WETH"),
    WRAPPED("0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270", "WPOL"),
  ]),
  "eip155:8453": new Map([
    USDC("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"),
    DAI("0x50c5725949a6f0c72e6c4a641f24049a917db0cb"),
    WRAPPED("0x4200000000000000000000000000000000000006", "WETH"),
  ]),
  "eip155:42161": new Map([
    USDC("0xaf88d065e77c8cc2239327c5edb3a432268e5831"),
    USDC("0xff970a61a04b1ca14834a43f5de4533ebddb5cc8"),
    USDT("0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9"),
    DAI("0xda10009cbd5d07dd0cecc66161fc93d7c9000da1"),
    WRAPPED("0x82af49447d8a07e3bd95bd0d56f35241523fbab1", "WETH"),
  ]),
  "eip155:43114": new Map([
    USDC("0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e"),
    USDT("0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7"),
    WRAPPED("0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7", "WAVAX"),
  ]),
};

/**
 * Looks up a well-known ERC-20. Without a chain, any chain matches.
 *
 * @param chain - CAIP-2 chain id, if known.
 * @param address - Lowercase token address.
 * @returns Token info or undefined.
 */
export function knownToken(chain: string | undefined, address: string | undefined): TokenInfo | undefined {
  if (!address) return undefined;
  if (chain) return KNOWN_TOKENS[chain]?.get(address);
  for (const tokens of Object.values(KNOWN_TOKENS)) {
    const info = tokens.get(address);
    if (info) return info;
  }
  return undefined;
}

export function tokenLabel(chain: string | undefined, address: string | undefined): string {
  if (!address) return "an unknown token";
  const info = knownToken(chain, address);
  return info ? `${info.symbol} (${address})` : `token ${address}`;
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

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

export function nativeSymbol(chain?: string): string {
  return (chain && hasOwn(NATIVE_SYMBOLS, chain) ? NATIVE_SYMBOLS[chain] : undefined) ?? "native units";
}

/** Formats base units with the given decimals, without losing precision. */
export function formatUnits(value: bigint, decimals: number): string {
  const base = 10n ** BigInt(decimals);
  const whole = value / base;
  const fraction = value % base;
  if (fraction === 0n) return whole.toString();
  const fractionText = fraction.toString().padStart(decimals, "0").replace(/0+$/u, "");
  return `${whole.toString()}.${fractionText}`;
}

export function nativeAmount(value: bigint, chain?: string): string {
  return `${formatUnits(value, 18)} ${nativeSymbol(chain)} (${value.toString()} wei)`;
}

/** Token amount, with symbol and decimals when the token is well known. */
export function tokenAmount(value: bigint, chain: string | undefined, token: string | undefined): string {
  const info = knownToken(chain, token);
  if (info) return `${formatUnits(value, info.decimals)} ${info.symbol} (${value.toString()} base units of ${token})`;
  return `${value.toString()} base units of ${token ? `token ${token}` : "an unknown token"}`;
}

/** Caps a string, appending an ellipsis when truncated. */
export function capText(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, Math.max(0, max - 1)).trimEnd()}…`;
}

export function unixDate(value: bigint | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (value === 0n) return "0";
  if (value > 100_000_000_000n) return "never";
  return new Date(Number(value) * 1000).toISOString().slice(0, 10);
}

export function shortAddress(address: string): string {
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

// ---------------------------------------------------------------------------
// Untrusted text: bounded cleaning and secret redaction
// ---------------------------------------------------------------------------

export const REDACTED = "[redacted secret-like string]";

// Invisible / direction-changing characters used to disguise text.
const INVISIBLE_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\u061C\uFEFF]/u;
const INVISIBLE_GLOBAL_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\u061C\uFEFF]/gu;
// C0/C1 control characters (tab, CR and LF are handled as whitespace).
const CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/gu;

const B58 = "1-9A-HJ-NP-Za-km-z";
// 32-byte hex secrets: bare, 0x-, pk_- or letter-suffixed (bounded by non-hex).
const HEX_SECRET_RE = /(?<![0-9a-fA-F])(?:0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])/gu;
const LONG_HEX_RE = /(?<![0-9a-fA-F])(?:0x)?[0-9a-fA-F]{41,8192}(?![0-9a-fA-F])/gu;
// 64-byte base58 keys (Solana), WIF private keys and BIP32 extended private keys.
const B58_SECRET_RE = new RegExp(`(?<![${B58}])[${B58}]{85,90}(?![${B58}])`, "gu");
const WIF_RE = new RegExp(`(?<![${B58}])[5KL][${B58}]{50,51}(?![${B58}])`, "gu");
const XPRV_RE = new RegExp(`(?<![${B58}])[xtyz]prv[${B58}]{100,108}(?![${B58}])`, "gu");
const JWT_RE = /eyJ[A-Za-z0-9_-]{2,4096}\.[A-Za-z0-9_-]{2,4096}\.[A-Za-z0-9_-]{2,4096}/gu;
// 12+ lowercase words of 3-8 letters (BIP39 words are 3-8 letters).
const MNEMONIC_RE = /(?<![A-Za-z])(?:[a-z]{3,8}[ \t\r\n,]{1,4}){11,23}[a-z]{3,8}(?![A-Za-z])/gu;
const LONG_ENCODED_RE = /[A-Za-z0-9+/=_-]{120,8192}/gu;

/**
 * Replaces secret-looking strings with a marker. Safe to run on our own
 * summaries (no mnemonic rule here: it only runs on untrusted text).
 *
 * @param text - The text (already size-capped).
 * @returns The redacted text.
 */
export function redactSecrets(text: string): string {
  return text
    .replace(JWT_RE, REDACTED)
    .replace(XPRV_RE, REDACTED)
    .replace(HEX_SECRET_RE, REDACTED)
    .replace(LONG_HEX_RE, (run) => `[${Math.floor(run.replace(/^0x/u, "").length / 2)}-byte hex data]`)
    .replace(B58_SECRET_RE, REDACTED)
    .replace(WIF_RE, REDACTED);
}

export type CleanText = { text: string; hadInvisible: boolean; truncated: boolean };

/**
 * Makes untrusted text safe and compact for a one-line summary: caps its size
 * first, removes invisible and control characters, redacts secret-looking
 * strings (hex/base58 keys, JWTs, mnemonic-like word runs) and collapses
 * blobs, so no secret or raw blob reaches the context.
 *
 * @param input - Untrusted text.
 * @param maxInput - Maximum characters considered.
 * @returns The cleaned text.
 */
export function cleanText(input: string, maxInput = MAX_CLEAN_INPUT): CleanText {
  const truncated = input.length > maxInput;
  const capped = truncated ? input.slice(0, maxInput) : input;
  const hadInvisible = INVISIBLE_RE.test(capped);
  const text = redactSecrets(
    capped
      .replace(INVISIBLE_GLOBAL_RE, "")
      .replace(CONTROL_RE, " ")
      .replace(MNEMONIC_RE, REDACTED),
  )
    .replace(LONG_ENCODED_RE, "[long encoded data]")
    .replace(/\s+/gu, " ")
    .trim();
  return { text, hadInvisible, truncated };
}

export function quote(text: string, max: number): string {
  return `"${capText(cleanText(text, max * 4).text.replace(/"/gu, "'"), max)}"`;
}

/**
 * Flattens a JSON message into "path=value" pairs for a readable excerpt.
 *
 * @param text - Untrusted text.
 * @returns The flattened excerpt, or undefined when the text is not JSON.
 */
export function scalarJson(text: string): string | undefined {
  const trimmed = text.trim();
  if (trimmed.length > MAX_TEXT_BYTES || (!trimmed.startsWith("{") && !trimmed.startsWith("["))) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed) as unknown;
  } catch {
    return undefined;
  }
  const pairs: string[] = [];
  const walk = (value: unknown, path: string, depth: number) => {
    if (pairs.length >= 12 || depth > 4) return;
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      pairs.push(`${path}=${capText(cleanText(String(value), 256).text, 48)}`);
    } else if (Array.isArray(value)) {
      pairs.push(`${path}=[${value.length} items]`);
    } else if (isRecord(value)) {
      for (const [key, child] of Object.entries(value).slice(0, 24)) {
        walk(child, path ? `${path}.${capText(key, 24)}` : capText(key, 24), depth + 1);
      }
    }
  };
  walk(parsed, "", 0);
  return pairs.length > 0 ? `JSON message: ${pairs.join("; ")}` : "JSON message with no readable fields";
}

// ---------------------------------------------------------------------------
// Hosts and addresses inside untrusted text
// ---------------------------------------------------------------------------

const URL_IN_TEXT_RE = /\bhttps?:\/\/[^\s"'<>()[\]{}`]{1,2048}/giu;
const TLDS =
  "com|org|net|io|xyz|app|finance|fi|exchange|claim|click|link|top|site|online|live|pro|info|co|me|gg|so|dev|ai|cc|biz|us|eth|tech|network|money|cash|gift|vip|club|shop|store|website|space|world|zone|digital|lol|fun|icu|buzz|rest|sbs|cfd";
// Bare hostnames; labels may contain any Unicode letter so that a homoglyph
// label (e.g. a Cyrillic U+0456 in "uniswap") is captured whole, then punycoded.
const BARE_HOST_RE = new RegExp(
  `(?<![\\p{L}\\p{N}@._-])((?:[\\p{L}\\p{N}](?:[\\p{L}\\p{N}-]{0,61}[\\p{L}\\p{N}])?\\.){1,10}(?:${TLDS}))(?![\\p{L}\\p{N}_-])`,
  "giu",
);
const ADDRESS_IN_TEXT_RE = /(?<![0-9a-zA-Z])0[xX][0-9a-fA-F]{40}(?![0-9a-zA-Z])/gu;

export function isPlausibleHost(host: string): boolean {
  return (
    host.length > 0 &&
    host.length <= 253 &&
    /^[a-z0-9.-]+$/u.test(host) &&
    host.includes(".") &&
    host.split(".").every((label) => label.length > 0 && label.length <= 63)
  );
}

/**
 * Hostname of a URL, punycode-encoded (URL parsing converts IDN labels).
 *
 * @param raw - The URL.
 * @returns The hostname or undefined.
 */
export function hostFromUrl(raw: string): string | undefined {
  try {
    const host = new URL(raw).hostname.replace(/\.$/u, "").toLowerCase();
    return isPlausibleHost(host) ? host : undefined;
  } catch {
    return undefined;
  }
}

export type TextLinks = { hosts: string[]; warnings: string[] };

/**
 * Extracts distinct hostnames referenced in free text (URLs and bare domains,
 * including internationalized ones, returned in punycode).
 *
 * @param input - Untrusted text (capped internally).
 * @param limit - Maximum number of hosts.
 * @returns Hosts plus link-related warnings.
 */
export function extractLinks(input: string, limit = 5): TextLinks {
  const text = input.length > MAX_TEXT_BYTES ? input.slice(0, MAX_TEXT_BYTES) : input;
  const hosts: string[] = [];
  const warnings: string[] = [];
  const add = (host: string | undefined) => {
    if (host && !hosts.includes(host) && hosts.length < limit) hosts.push(host);
  };
  for (const match of text.matchAll(URL_IN_TEXT_RE)) {
    const url = match[0].replace(/[.,;:!?]+$/u, "");
    const authority = /^https?:\/\/([^/?#]*)/iu.exec(url)?.[1] ?? "";
    const host = hostFromUrl(url);
    if (authority.includes("@") && host) {
      warnings.push(`a link hides its real host behind a "user@" prefix; it actually opens ${host}`);
    }
    add(host);
  }
  const withoutUrls = text.replace(URL_IN_TEXT_RE, " ");
  for (const match of withoutUrls.matchAll(BARE_HOST_RE)) {
    add(hostFromUrl(`https://${match[1] as string}`));
  }
  if (/\b(?:javascript|data|vbscript):/iu.test(text)) {
    warnings.push("the message contains a javascript:/data: link");
  }
  return { hosts, warnings };
}

/** Distinct hostnames referenced in free text (see extractLinks). */
export function extractHosts(text: string, limit = 5): string[] {
  return extractLinks(text, limit).hosts;
}

/** Distinct 0x-addresses in free text, excluding `exclude` and the zero address. */
export function extractAddresses(input: string, exclude: (string | undefined)[] = []): string[] {
  const text = input.length > MAX_TEXT_BYTES ? input.slice(0, MAX_TEXT_BYTES) : input;
  const skip = new Set([ZERO_ADDRESS, ...exclude.filter((value): value is string => Boolean(value))]);
  const found: string[] = [];
  for (const match of text.matchAll(ADDRESS_IN_TEXT_RE)) {
    const address = `0x${match[0].slice(2).toLowerCase()}`;
    if (!skip.has(address) && !found.includes(address)) found.push(address);
  }
  return found;
}

// ---------------------------------------------------------------------------
// Candidate selection
// ---------------------------------------------------------------------------

/** Addresses that are never a meaningful counterparty. */
export function isIgnorableAddress(address: string): boolean {
  if (address === ZERO_ADDRESS) return true;
  // Precompiles and router sentinels (address(1), address(2), ...).
  return /^0x0{38}[0-9a-f]{2}$/u.test(address) && BigInt(address) <= 0xffn;
}

/**
 * Orders candidates by risk, removes duplicates, ignorable and excluded
 * addresses, and keeps at most `limit`.
 *
 * @param candidates - Candidate addresses.
 * @param exclude - Addresses never checked (e.g. the user).
 * @param limit - Maximum candidates (primary + batch).
 * @returns Selected candidates, primary first.
 */
export function selectCandidates(candidates: Candidate[], exclude: (string | undefined)[] = [], limit = 3): Candidate[] {
  const skip = new Set(exclude.filter((value): value is string => Boolean(value)));
  const best = new Map<string, Candidate>();
  for (const candidate of candidates) {
    if (isIgnorableAddress(candidate.address) || skip.has(candidate.address)) continue;
    const existing = best.get(candidate.address);
    if (!existing || candidate.rank > existing.rank) best.set(candidate.address, candidate);
  }
  return [...best.values()].sort((a, b) => b.rank - a.rank).slice(0, limit);
}

/**
 * Builds a Decoded from its candidates: the riskiest becomes the primary.
 *
 * @param base - Everything but the address fields.
 * @param candidates - Selected candidates (primary first).
 * @returns The decoded request.
 */
export function withCandidates(
  base: Omit<Decoded, "counterparty" | "role" | "reason" | "interaction" | "payment" | "others"> & {
    interaction?: Interaction | undefined;
  },
  candidates: Candidate[],
): Decoded {
  const [primary, ...others] = candidates;
  if (!primary) {
    return { ...base, interaction: base.interaction ?? interaction("contract_call"), others: [] };
  }
  return {
    ...base,
    counterparty: primary.address,
    role: primary.role,
    ...(primary.reason ? { reason: primary.reason } : {}),
    interaction: primary.interaction,
    ...(primary.payment ? { payment: primary.payment } : {}),
    others,
  };
}

export function payment(fields: Payment): Payment | undefined {
  const out: Payment = {};
  if (fields.network) out.network = fields.network;
  if (fields.pay_to) out.pay_to = fields.pay_to;
  if (fields.amount && /^\d{1,78}$/u.test(fields.amount)) out.amount = fields.amount;
  if (fields.asset) out.asset = fields.asset;
  return Object.keys(out).length > 0 ? out : undefined;
}

export type AllowanceInfo = { unlimited: boolean; label: string; phrase: string };

/**
 * Describes an allowance amount. Unlimited when at or above `threshold`, or
 * effectively unlimited at or above 10^30 base units (with a warning).
 *
 * @param amount - The amount, or undefined when unknown (fails closed).
 * @param threshold - Type-specific unlimited threshold.
 * @param warnings - Receives warnings.
 * @returns Allowance description.
 */
export function describeAllowance(amount: bigint | undefined, threshold: bigint, warnings: string[]): AllowanceInfo {
  if (amount === undefined) {
    warnings.push("the allowance amount could not be decoded, so it is treated as UNLIMITED");
    return { unlimited: true, label: "UNKNOWN (treated as UNLIMITED)", phrase: "an allowance of UNKNOWN size (treated as UNLIMITED)" };
  }
  if (amount >= threshold) {
    const kind = amount === MAX_UINT256 ? "max uint256" : amount === MAX_UINT160 ? "max uint160" : "effectively infinite";
    return { unlimited: true, label: "UNLIMITED", phrase: `an UNLIMITED allowance (${kind})` };
  }
  if (amount >= EFFECTIVELY_UNLIMITED) {
    warnings.push("the allowance is effectively unlimited (at least 10^30 base units)");
    return {
      unlimited: true,
      label: "UNLIMITED (effectively)",
      phrase: `an effectively UNLIMITED allowance (${amount.toString()} base units)`,
    };
  }
  return { unlimited: false, label: `${amount.toString()} base units`, phrase: `an allowance of ${amount.toString()} base units` };
}
