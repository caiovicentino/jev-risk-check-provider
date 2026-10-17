// What a transaction serializer actually produced, read back: the bytes a viem account signs are
// `serializer(transaction)`, and a serializer passed with the call (a chain's own, or the caller's)
// could write anything. The guard reads the unsigned serialization and compares it with the
// transaction it checked: legacy (EIP-155), EIP-2930 and EIP-1559 only. Any other format (a blob
// or delegation transaction, a chain's own type) is refused rather than signed unread.

type Rlp = Uint8Array | Rlp[];

function hexBytes(hex: string): Uint8Array | null {
  if (!/^0x(?:[0-9a-fA-F]{2})*$/u.test(hex)) return null;
  const out = new Uint8Array((hex.length - 2) / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(2 + i * 2, 4 + i * 2), 16);
  return out;
}

function lengthAt(b: Uint8Array, at: number, size: number): number {
  if (size > 6 || at + size > b.length) throw new Error("rlp: bad length");
  let n = 0;
  for (let i = 0; i < size; i += 1) n = n * 256 + (b[at + i] as number);
  return n;
}

function item(b: Uint8Array, at: number): [Rlp, number] {
  const p = b[at];
  if (p === undefined) throw new Error("rlp: truncated");
  const take = (start: number, len: number): [Uint8Array, number] => {
    if (start + len > b.length) throw new Error("rlp: truncated");
    return [b.subarray(start, start + len), start + len];
  };
  const list = (start: number, len: number): [Rlp[], number] => {
    const end = start + len;
    if (end > b.length) throw new Error("rlp: truncated");
    const out: Rlp[] = [];
    let i = start;
    while (i < end) {
      const [x, next] = item(b, i);
      out.push(x);
      i = next;
    }
    if (i !== end) throw new Error("rlp: bad list");
    return [out, end];
  };
  if (p < 0x80) return [b.subarray(at, at + 1), at + 1];
  if (p <= 0xb7) return take(at + 1, p - 0x80);
  if (p <= 0xbf) return take(at + 1 + (p - 0xb7), lengthAt(b, at + 1, p - 0xb7));
  if (p <= 0xf7) return list(at + 1, p - 0xc0);
  return list(at + 1 + (p - 0xf7), lengthAt(b, at + 1, p - 0xf7));
}

function decode(b: Uint8Array): Rlp[] {
  const [x, end] = item(b, 0);
  if (end !== b.length || !Array.isArray(x)) throw new Error("rlp: not one list");
  return x;
}

const uint = (x: Rlp | undefined): bigint => {
  if (!(x instanceof Uint8Array)) throw new Error("rlp: expected bytes");
  let n = 0n;
  for (const byte of x) n = (n << 8n) | BigInt(byte);
  return n;
};
const hex = (x: Rlp | undefined): string => {
  if (!(x instanceof Uint8Array)) throw new Error("rlp: expected bytes");
  return `0x${Array.from(x, (v) => v.toString(16).padStart(2, "0")).join("")}`;
};
const big = (v: unknown): bigint => (typeof v === "bigint" ? v : typeof v === "number" ? BigInt(v) : 0n);

function accessListOf(x: Rlp | undefined): string {
  if (!Array.isArray(x)) throw new Error("rlp: expected an access list");
  return JSON.stringify(
    x.map((entry) => {
      if (!Array.isArray(entry) || !Array.isArray(entry[1])) throw new Error("rlp: bad access list entry");
      return [hex(entry[0]).toLowerCase(), (entry[1] as Rlp[]).map((k) => hex(k).toLowerCase())];
    }),
  );
}

function expectedAccessList(v: unknown): string {
  const list = Array.isArray(v) ? v : [];
  return JSON.stringify(
    list.map((entry: { address?: unknown; storageKeys?: unknown }) => [
      String(entry?.address ?? "").toLowerCase(),
      (Array.isArray(entry?.storageKeys) ? entry.storageKeys : []).map((k: unknown) => String(k).toLowerCase()),
    ]),
  );
}

/**
 * Why the unsigned serialization `serialized` is not the normalized transaction `tx` the guard
 * checked, or null when it is. Reads legacy (with its EIP-155 chain id), EIP-2930 and EIP-1559.
 */
export function serializedMismatch(serialized: unknown, tx: Record<string, unknown>): string | null {
  if (typeof serialized !== "string") return "the serializer did not return a hex string";
  const b = hexBytes(serialized);
  if (!b || b.length === 0) return "the serializer did not return hex bytes";
  let type: "legacy" | "eip2930" | "eip1559";
  let f: Rlp[];
  try {
    if ((b[0] as number) >= 0xc0) {
      type = "legacy";
      f = decode(b);
    } else if (b[0] === 0x01 || b[0] === 0x02) {
      type = b[0] === 0x01 ? "eip2930" : "eip1559";
      f = decode(b.subarray(1));
    } else {
      return `the serializer produced a transaction of type 0x${(b[0] as number).toString(16).padStart(2, "0")}, which this guard does not read`;
    }
  } catch (err) {
    return `the serializer's output could not be read (${(err as Error).message})`;
  }
  if (tx.type !== undefined && tx.type !== type) return `the serializer produced a ${type} transaction, not the ${String(tx.type)} one that was checked`;
  try {
    let fields: Record<string, string>;
    const expectTo = typeof tx.to === "string" ? tx.to.toLowerCase() : "0x";
    if (type === "legacy") {
      if (f.length !== 9 || uint(f[7]) !== 0n || uint(f[8]) !== 0n) return "the serializer produced a legacy transaction without its EIP-155 chain id";
      fields = { chainId: String(uint(f[6])), nonce: String(uint(f[0])), gasPrice: String(uint(f[1])), gas: String(uint(f[2])), to: hex(f[3]), value: String(uint(f[4])), data: hex(f[5]) };
    } else if (type === "eip2930") {
      if (f.length !== 8) return "the serializer produced an EIP-2930 transaction of an unexpected shape";
      fields = { chainId: String(uint(f[0])), nonce: String(uint(f[1])), gasPrice: String(uint(f[2])), gas: String(uint(f[3])), to: hex(f[4]), value: String(uint(f[5])), data: hex(f[6]), accessList: accessListOf(f[7]) };
    } else {
      if (f.length !== 9) return "the serializer produced an EIP-1559 transaction of an unexpected shape";
      fields = { chainId: String(uint(f[0])), nonce: String(uint(f[1])), maxPriorityFeePerGas: String(uint(f[2])), maxFeePerGas: String(uint(f[3])), gas: String(uint(f[4])), to: hex(f[5]), value: String(uint(f[6])), data: hex(f[7]), accessList: accessListOf(f[8]) };
    }
    const expected: Record<string, string> = {
      chainId: String(big(tx.chainId)),
      nonce: String(big(tx.nonce)),
      gas: String(big(tx.gas)),
      to: expectTo,
      value: String(big(tx.value)),
      data: typeof tx.data === "string" ? tx.data.toLowerCase() : "0x",
      ...(type === "eip1559" ? { maxPriorityFeePerGas: String(big(tx.maxPriorityFeePerGas)), maxFeePerGas: String(big(tx.maxFeePerGas)) } : { gasPrice: String(big(tx.gasPrice)) }),
      ...(type === "legacy" ? {} : { accessList: expectedAccessList(tx.accessList) }),
    };
    for (const [key, want] of Object.entries(expected)) {
      const got = key === "to" || key === "data" ? fields[key]?.toLowerCase() : fields[key];
      if (got !== want) return `the serialized transaction's ${key} is not the one that was checked`;
    }
  } catch (err) {
    return `the serializer's output could not be read (${(err as Error).message})`;
  }
  return null;
}
