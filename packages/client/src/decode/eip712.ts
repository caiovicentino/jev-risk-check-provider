// Vendored from snap/src/eip712.ts by scripts/sync-decoders.mjs. Edit the Snap source and re-sync.
/**
 * EIP-712 canonicalization that mirrors @metamask/eth-sig-util (V4), the
 * encoder MetaMask uses to compute the hash the user actually signs.
 *
 * Only fields DECLARED in `types` are kept (undeclared keys are never signed),
 * and every value is normalized exactly like the encoder does:
 * - address: 0x/0X hex of any case and length <= 20 bytes (left-padded),
 *   safe-integer numbers, and any other string through eth-sig-util's
 *   "reallyStrangeAddressToBytes" (so a DECIMAL string is an address);
 * - uint/int: JavaScript BigInt() semantics (hex/octal/binary prefixes,
 *   leading zeros, surrounding whitespace, "" = 0) with range checks;
 * - bool: JavaScript truthiness (so "false", "0" and 1 all sign as TRUE).
 * Values the encoder would reject are reported as unsignable.
 */
import { hasOwn, isRecord, parseBigIntString, toBigIntLike } from "./util.js";

export type TypedField = { name: string; type: string };
export type TypedTypes = Record<string, TypedField[]>;
export type CanonStruct = { [field: string]: CanonValue };
/**
 * address -> lowercase "0x" + 40 hex; uint/int -> bigint; bool -> boolean;
 * string -> string; bytes/bytesN -> lowercase "0x" hex; struct -> CanonStruct
 * (null when absent: V4 hashes it as zero); array -> CanonValue[];
 * undefined -> missing, unsignable or not resolvable (see Canonical).
 */
export type CanonValue = string | bigint | boolean | null | undefined | CanonStruct | CanonValue[];

export type Canonical = {
  types: TypedTypes;
  primaryType: string;
  domain: CanonStruct;
  message: CanonStruct;
  /** Paths whose raw value cannot be signed (the request would fail). */
  unsignable: string[];
  /** Paths whose value is signable but could not be resolved by the Snap. */
  unresolved: string[];
  /** Non-standard encodings, e.g. a decimal address or a "false" bool. */
  unusual: string[];
  /** The walk stopped early (too many fields or items). */
  truncated: boolean;
};

const MAX_TYPES = 256;
const MAX_FIELDS = 256;
const MAX_NODES = 4000;
const MAX_ARRAY_ITEMS = 256;
const MAX_DEPTH = 40;
const MAX_STRING = 2048;
/** Hex characters kept for `bytes` values (128 KiB of data). */
const MAX_BYTES_HEX = 256 * 1024;
const MAX_DECIMAL_ADDRESS = 4096;
const MAX_STRANGE_ADDRESS = 1024;

type Context = {
  types: TypedTypes;
  budget: number;
  unsignable: string[];
  unresolved: string[];
  unusual: string[];
  truncated: boolean;
};

function parseTypes(raw: unknown): TypedTypes | undefined {
  if (!isRecord(raw)) return undefined;
  const entries = Object.entries(raw);
  if (entries.length > MAX_TYPES) return undefined;
  // Null prototype: "constructor" & co. are never mistaken for declared types.
  const out = Object.create(null) as TypedTypes;
  for (const [name, fields] of entries) {
    if (!Array.isArray(fields) || fields.length > MAX_FIELDS) return undefined;
    const list: TypedField[] = [];
    for (const field of fields) {
      if (!isRecord(field) || typeof field.name !== "string" || typeof field.type !== "string") return undefined;
      list.push({ name: field.name, type: field.type });
    }
    out[name] = list;
  }
  if (!hasOwn(out, "EIP712Domain")) out.EIP712Domain = [];
  return out;
}

export function isStrictHexString(value: string): boolean {
  if (value.length < 3 || value.charCodeAt(0) !== 48) return false;
  const marker = value.charCodeAt(1);
  if (marker !== 120 && marker !== 88) return false;
  for (let index = 2; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    const hex = (code >= 48 && code <= 57) || (code >= 65 && code <= 70) || (code >= 97 && code <= 102);
    if (!hex) return false;
  }
  return true;
}

function display(value: unknown): string {
  if (typeof value === "string") return JSON.stringify(value.length > 40 ? `${value.slice(0, 40)}…` : value);
  if (typeof value === "bigint") return `${value.toString()}n`;
  return String(value);
}

/** 20-byte address from the bytes of a non-negative integer (first 20 bytes). */
function addressFromInteger(value: bigint): string {
  let hex = value.toString(16);
  if (hex.length % 2 === 1) hex = `0${hex}`;
  return hex.length <= 40 ? `0x${hex.padStart(40, "0")}` : `0x${hex.slice(0, 40)}`;
}

/**
 * eth-sig-util's reallyStrangeAddressToBytes: base-10 accumulation of
 * per-character digit values, then the first 20 bytes.
 *
 * @param value - The raw string.
 * @returns The address, "unsignable", or "unresolved" when too long to compute.
 */
function strangeAddress(value: string): string | "unsignable" | "unresolved" {
  let allDigits = true;
  for (let index = 0; index < value.length && allDigits; index += 1) {
    const code = value.charCodeAt(index);
    allDigits = code >= 48 && code <= 57;
  }
  if (allDigits) {
    if (value.length === 0) return addressFromInteger(0n);
    if (value.length > MAX_DECIMAL_ADDRESS) return "unresolved";
    return addressFromInteger(BigInt(value));
  }
  if (value.length > MAX_STRANGE_ADDRESS) return "unresolved";
  let accumulator = 0n;
  for (let index = 0; index < value.length; index += 1) {
    const character = BigInt(value.charCodeAt(index) - 48);
    accumulator *= 10n;
    if (character >= 49n) accumulator += character - 49n + 10n;
    else if (character >= 17n) accumulator += character - 17n + 10n;
    else accumulator += character;
  }
  return accumulator < 0n ? "unsignable" : addressFromInteger(accumulator);
}

function canonAddress(ctx: Context, value: unknown, path: string): string | undefined {
  if (typeof value === "number") {
    if (Number.isSafeInteger(value) && value >= 0) {
      const address = `0x${value.toString(16).padStart(40, "0")}`;
      ctx.unusual.push(`${path} is the number ${value}, which signs as address ${address}`);
      return address;
    }
    ctx.unsignable.push(path);
    return undefined;
  }
  if (typeof value !== "string") {
    ctx.unsignable.push(path);
    return undefined;
  }
  if (isStrictHexString(value)) {
    let hex = value.slice(2).toLowerCase();
    if (hex.length % 2 === 1) hex = `0${hex}`;
    if (hex.length > 40) {
      ctx.unsignable.push(path);
      return undefined;
    }
    const address = `0x${hex.padStart(40, "0")}`;
    if (value.length !== 42 || value[1] !== "x") {
      ctx.unusual.push(`${path} uses a non-standard address encoding (${display(value)}) that signs as ${address}`);
    }
    return address;
  }
  const resolved = strangeAddress(value);
  if (resolved === "unsignable") {
    ctx.unsignable.push(path);
    return undefined;
  }
  if (resolved === "unresolved") {
    ctx.unresolved.push(path);
    return undefined;
  }
  ctx.unusual.push(`${path} uses a non-standard address encoding (${display(value)}) that signs as ${resolved}`);
  return resolved;
}

function bitLength(type: string, prefix: "uint" | "int"): number | undefined {
  const size = type.slice(prefix.length);
  if (size === "") return 256;
  if (!/^\d{1,3}$/u.test(size)) return undefined;
  const bits = Number(size);
  return bits >= 8 && bits <= 256 && bits % 8 === 0 ? bits : undefined;
}

function noteUnusualNumber(ctx: Context, value: unknown, path: string, parsed: bigint): void {
  if (typeof value !== "string") return;
  if (/^(?:0|[1-9]\d{0,77}|0x[0-9a-fA-F]{1,64})$/u.test(value)) return;
  ctx.unusual.push(`${path} uses a non-standard number encoding (${display(value)}) that signs as ${parsed.toString()}`);
}

function canonUint(ctx: Context, type: string, value: unknown, path: string): bigint | undefined {
  const bits = bitLength(type, "uint");
  let parsed: bigint | undefined;
  if (bits !== undefined && (typeof value === "number" || typeof value === "bigint" || typeof value === "string")) {
    parsed = toBigIntLike(value);
  }
  if (bits === undefined || parsed === undefined || parsed < 0n || parsed > (1n << BigInt(bits)) - 1n) {
    ctx.unsignable.push(path);
    return undefined;
  }
  noteUnusualNumber(ctx, value, path, parsed);
  return parsed;
}

/**
 * int* values: eth-sig-util calls BigInt(value) directly (so booleans and
 * arrays coerce), checks |value| <= 2^N - 1, then encodes negatives as int256.
 */
function canonInt(ctx: Context, type: string, value: unknown, path: string): bigint | undefined {
  const bits = bitLength(type, "int");
  let parsed: bigint | undefined;
  if (typeof value === "boolean") parsed = value ? 1n : 0n;
  else if (Array.isArray(value)) parsed = value.length <= 16 ? parseBigIntString(String(value)) : undefined;
  else if (value !== null && typeof value !== "object") parsed = toBigIntLike(value);
  const max = bits === undefined ? -1n : (1n << BigInt(bits)) - 1n;
  if (bits === undefined || parsed === undefined || parsed < -max || parsed > max || parsed < -(1n << 255n)) {
    ctx.unsignable.push(path);
    return undefined;
  }
  noteUnusualNumber(ctx, value, path, parsed);
  return parsed;
}

function canonBytes(ctx: Context, value: unknown, path: string): string | undefined {
  let hex: string | undefined;
  if (typeof value === "number") {
    if (!(Number.isSafeInteger(value) && value >= 0)) {
      ctx.unsignable.push(path);
      return undefined;
    }
    hex = value.toString(16);
  } else if (typeof value === "string") {
    if (value === "0x") {
      hex = "";
    } else if (isStrictHexString(value)) {
      hex = value.slice(2);
    } else {
      // Non-hex strings are signed as their UTF-8 bytes.
      if (value.length > MAX_BYTES_HEX / 2) {
        ctx.unresolved.push(path);
        return undefined;
      }
      hex = Array.from(new TextEncoder().encode(value), (byte) => byte.toString(16).padStart(2, "0")).join("");
    }
  } else {
    ctx.unsignable.push(path);
    return undefined;
  }
  if (hex.length > MAX_BYTES_HEX) {
    ctx.unresolved.push(path);
    return undefined;
  }
  if (hex.length % 2 === 1) hex = `0${hex}`;
  return `0x${hex.toLowerCase()}`;
}

function canonString(value: unknown): string {
  if (value === null || value === undefined) return "";
  const text = typeof value === "string" ? value : String(value);
  return text.length > MAX_STRING ? text.slice(0, MAX_STRING) : text;
}

function canonValue(ctx: Context, type: string, value: unknown, path: string, depth: number): CanonValue {
  ctx.budget -= 1;
  if (ctx.budget < 0 || depth > MAX_DEPTH) {
    ctx.truncated = true;
    return undefined;
  }
  if (hasOwn(ctx.types, type)) {
    if (value === null || value === undefined) return null;
    if (!isRecord(value)) {
      ctx.unsignable.push(path);
      return undefined;
    }
    const out = Object.create(null) as CanonStruct;
    for (const field of ctx.types[type] ?? []) {
      out[field.name] = canonValue(ctx, field.type, value[field.name], `${path}.${field.name}`, depth + 1);
    }
    return out;
  }
  if (type === "function") {
    ctx.unsignable.push(path);
    return undefined;
  }
  if (value === undefined) {
    ctx.unsignable.push(`${path} (missing)`);
    return undefined;
  }
  if (type === "address") return canonAddress(ctx, value, path);
  if (type === "bool") {
    const signed = Boolean(value);
    if (typeof value !== "boolean") {
      ctx.unusual.push(`${path} is ${display(value)}, which signs as ${signed ? "TRUE" : "FALSE"}`);
    }
    return signed;
  }
  if (type === "bytes") return canonBytes(ctx, value, path);
  if (type.startsWith("bytes") && !type.includes("[")) {
    return typeof value === "string" && isStrictHexString(value) && value.length <= 66 ? value.toLowerCase() : undefined;
  }
  if (type.startsWith("int") && !type.includes("[")) return canonInt(ctx, type, value, path);
  if (type === "string") return canonString(value);
  if (type.endsWith("]")) {
    if (!Array.isArray(value)) {
      ctx.unsignable.push(path);
      return undefined;
    }
    const base = type.slice(0, type.lastIndexOf("["));
    const items = value.length > MAX_ARRAY_ITEMS ? value.slice(0, MAX_ARRAY_ITEMS) : value;
    if (items.length < value.length) ctx.truncated = true;
    return items.map((item, index) => canonValue(ctx, base, item, `${path}[${index}]`, depth + 1));
  }
  if (type.startsWith("uint")) return canonUint(ctx, type, value, path);
  ctx.unsignable.push(`${path} (unsupported type)`);
  return undefined;
}

/**
 * Canonicalizes eth_signTypedData_v3/v4 data the way MetaMask signs it.
 *
 * @param input - The typed data object.
 * @returns The canonical view, or an error when the data cannot be signed.
 */
export function canonicalizeTypedData(input: unknown): Canonical | { error: string } {
  if (!isRecord(input)) return { error: "the typed data is not an object" };
  const types = parseTypes(input.types);
  if (!types) return { error: 'the typed data has no valid "types" definition' };
  const { primaryType } = input;
  if (typeof primaryType !== "string" || primaryType.length === 0 || primaryType.length > 256) {
    return { error: "the typed data has no primaryType" };
  }
  if (primaryType !== "EIP712Domain" && !hasOwn(types, primaryType)) {
    return { error: `its primary type "${primaryType.slice(0, 40)}" is not declared in its types` };
  }
  const ctx: Context = { types, budget: MAX_NODES, unsignable: [], unresolved: [], unusual: [], truncated: false };
  const domainValue = canonValue(ctx, "EIP712Domain", input.domain, "domain", 0);
  let message: CanonStruct = Object.create(null) as CanonStruct;
  if (primaryType !== "EIP712Domain") {
    if (!isRecord(input.message)) return { error: "the typed data message is not an object" };
    const value = canonValue(ctx, primaryType, input.message, "message", 0);
    if (isCanonStruct(value)) message = value;
  }
  return {
    types,
    primaryType,
    domain: isCanonStruct(domainValue) ? domainValue : (Object.create(null) as CanonStruct),
    message,
    unsignable: ctx.unsignable,
    unresolved: ctx.unresolved,
    unusual: ctx.unusual,
    truncated: ctx.truncated,
  };
}

export function isCanonStruct(value: CanonValue): value is CanonStruct {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Declared type of `field` in struct `structType`, if any. */
export function fieldType(types: TypedTypes, structType: string, field: string): string | undefined {
  return types[structType]?.find((entry) => entry.name === field)?.type;
}

/** Declared struct type of a field of `structType` (strips array suffixes). */
export function baseType(type: string | undefined): string | undefined {
  if (!type) return undefined;
  const bracket = type.indexOf("[");
  return bracket >= 0 ? type.slice(0, bracket) : type;
}

export function canonAddressValue(value: CanonValue): string | undefined {
  return typeof value === "string" && value.length === 42 && /^0x[0-9a-f]{40}$/u.test(value) ? value : undefined;
}

export function canonBigInt(value: CanonValue): bigint | undefined {
  return typeof value === "bigint" ? value : undefined;
}

export type AddressVisit = { path: string; key: string; address: string };

/**
 * Walks declared fields and yields every address-typed value (type-directed,
 * so a string field that merely looks like an address is never used).
 *
 * @param types - Declared types.
 * @param type - Type of `value`.
 * @param value - Canonical value.
 * @param path - Path for reporting.
 * @param out - Receives visits.
 * @param depth - Current depth.
 */
export function collectAddressFields(
  types: TypedTypes,
  type: string,
  value: CanonValue,
  path: string,
  out: AddressVisit[],
  depth = 0,
): void {
  if (depth > MAX_DEPTH || out.length > 512) return;
  if (hasOwn(types, type)) {
    if (!isCanonStruct(value)) return;
    for (const field of types[type] ?? []) {
      const child = value[field.name];
      const childPath = path ? `${path}.${field.name}` : field.name;
      if (field.type === "address") {
        const address = canonAddressValue(child);
        if (address) out.push({ path: childPath, key: field.name, address });
      } else {
        collectAddressFields(types, field.type, child, childPath, out, depth + 1);
      }
    }
    return;
  }
  if (type.endsWith("]") && Array.isArray(value)) {
    const itemType = type.slice(0, type.lastIndexOf("["));
    value.forEach((item, index) => {
      if (itemType === "address") {
        const address = canonAddressValue(item);
        if (address) out.push({ path: `${path}[${index}]`, key: path.split(".").pop() ?? path, address });
      } else {
        collectAddressFields(types, itemType, item, `${path}[${index}]`, out, depth + 1);
      }
    });
  }
}
