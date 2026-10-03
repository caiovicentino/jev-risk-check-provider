import { createHash } from "node:crypto";

// Drainer-kit fingerprinting. Most drainer contracts are redeployments of a few kits
// ("SecurityUpdates", fake "Claim" contracts, batch sweepers): the same runtime
// bytecode up to the compiler's metadata trailer. A contract whose logic code is
// byte-identical to a listed drainer's is the same kit, even before any list names
// the new address.
//
// Only "logic" code is fingerprinted. Token, NFT, delegating (proxy) and tiny code
// is shared by countless legitimate contracts — a fake-token clone has exactly the
// real token's code — so it never produces a fingerprint, and never a match.

export type CodeKind = "none" | "delegated" | "tiny" | "delegating" | "token" | "nft" | "logic";
export type CodeFacts = {
  kind: CodeKind;
  bytes: number;
  fingerprint?: string;
  /** EIP-7702 delegation target. */
  delegate?: string;
  /** Implementation behind an EIP-1167 minimal proxy (from the code) or an EIP-1967 / Safe proxy (from storage). */
  implementation?: string;
  /**
   * A proxy whose whole code is a known forwarding pattern (EIP-1167, Safe, minimal
   * EIP-1967): it runs exactly its implementation, so it can be judged by it.
   */
  proxy?: "eip1167" | "safe" | "eip1967-minimal" | "eip1967" | "zeppelinos";
  /** Logic-code fingerprint of the delegate or implementation, when it has logic code. */
  implementation_fingerprint?: string;
  /** Addresses hard-coded in delegating code (PUSH20): candidate implementations of non-standard proxies. */
  linked?: string[];
  /** Logic-code fingerprints of `linked` addresses (used for drainer matching only, never for verification). */
  linked_fingerprints?: string[];
  /**
   * Template fingerprint of logic code: sha256 with every PUSH20/PUSH32 immediate zeroed,
   * so redeployments of one kit that differ only in immutables or hard-coded addresses
   * (the operator's wallet) share it. Used for kit families (src/kit-watch.ts).
   */
  skeleton?: string;
  /** Template fingerprint of the delegate's or implementation's logic code. */
  implementation_skeleton?: string;
};

/** EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1. */
export const EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
/**
 * The ZeppelinOS (pre-EIP-1967) implementation slot: keccak256("org.zeppelinos.proxy.implementation").
 * USDC's FiatTokenProxy keeps its implementation there, and its EIP-1967 slot is empty.
 */
export const ZEPPELINOS_IMPLEMENTATION_SLOT = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3";
const ZEPPELINOS_SLOT_HEX = ZEPPELINOS_IMPLEMENTATION_SLOT.slice(2);
/** 20 printable ASCII bytes: text embedded in the bytecode (a revert string), not an address. */
const isText = (bytes: Uint8Array): boolean => bytes.every((b) => b >= 0x20 && b <= 0x7e);
const EIP1167 = /^363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3$/;
// Safe proxies 1.1.1–1.4.1: load masterCopy from slot 0, answer masterCopy() (0xa619486e), else delegatecall.
const SAFE_PROXY_PREFIX = "608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa619486e";
const EIP1967_SLOT_HEX = EIP1967_IMPLEMENTATION_SLOT.slice(2);
/** Proxies small enough to hold nothing but the forwarding (e.g. Solady/LibClone ERC-1967 proxies). */
const MINIMAL_PROXY_BYTES = 200;

export const MIN_LOGIC_BYTES = 100;
const TOKEN_SELECTORS = ["a9059cbb", "70a08231", "18160ddd"]; // transfer, balanceOf, totalSupply
const NFT_SELECTORS = [
  ["6352211e", "42842e0e"], // ERC-721 ownerOf, safeTransferFrom(address,address,uint256)
  ["f242432a", "4e1273f4"], // ERC-1155 safeTransferFrom, balanceOfBatch
];

/** Drops the CBOR metadata trailer (its length is the last two bytes; it must start as a CBOR map). */
export function stripMetadata(code: Uint8Array): Uint8Array {
  if (code.length < 4) return code;
  const n = ((code[code.length - 2] as number) << 8) | (code[code.length - 1] as number);
  const start = code.length - 2 - n;
  if (n === 0 || start <= 0) return code;
  const first = code[start] as number;
  return first >= 0xa1 && first <= 0xb7 ? code.subarray(0, start) : code;
}

/** The code with PUSH20/PUSH32 immediates zeroed (a copy): invariant to immutables and hard-coded addresses. */
export function skeletonBytes(code: Uint8Array): Uint8Array {
  const out = Uint8Array.from(code);
  for (let i = 0; i < out.length; i++) {
    const op = out[i] as number;
    if (op >= 0x60 && op <= 0x7f) {
      const n = op - 0x5f;
      if (op === 0x73 || op === 0x7f) out.fill(0, i + 1, Math.min(out.length, i + 1 + n));
      i += n;
    }
  }
  return out;
}

/** Classifies runtime code (from eth_getCode) and fingerprints logic code: sha256 of the metadata-stripped bytes. */
export function codeFacts(codeHex: string): CodeFacts {
  const hex = codeHex.toLowerCase().replace(/^0x/, "");
  if (!hex || /^0+$/.test(hex)) return { kind: "none", bytes: 0 };
  // EIP-7702 delegation designator: an EOA whose code points at an implementation.
  if (hex.startsWith("ef0100") && hex.length === 46) return { kind: "delegated", bytes: 23, delegate: `0x${hex.slice(6)}` };
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) return { kind: "tiny", bytes: 0 };
  const raw = Buffer.from(hex, "hex");
  const minimal = EIP1167.exec(hex);
  if (minimal) return { kind: "delegating", bytes: raw.length, implementation: `0x${minimal[1]}`, proxy: "eip1167" };
  if (hex.startsWith(SAFE_PROXY_PREFIX) && raw.length <= 400) return { kind: "delegating", bytes: raw.length, proxy: "safe" };
  const code = stripMetadata(raw);
  if (code.length < MIN_LOGIC_BYTES) return { kind: "tiny", bytes: raw.length };
  const selectors = new Set<string>();
  const linked = new Set<string>();
  let delegating = false;
  for (let i = 0; i < code.length; i++) {
    const op = code[i] as number;
    if (op === 0xf4 || op === 0xf2) delegating = true; // DELEGATECALL / CALLCODE
    if (op === 0x63 && i + 4 < code.length) selectors.add(Buffer.from(code.subarray(i + 1, i + 5)).toString("hex")); // PUSH4
    if (op === 0x73 && i + 20 < code.length && linked.size < 3) {
      // PUSH20, or the byte "s" of embedded text read as an opcode: an operand that is all
      // printable ASCII ("et a proxy implement") is text, not an address.
      const operand = code.subarray(i + 1, i + 21);
      const a = Buffer.from(operand).toString("hex");
      if (!/^(0{40}|f{40})$/.test(a) && !isText(operand)) linked.add(`0x${a}`);
    }
    if (op >= 0x60 && op <= 0x7f) i += op - 0x5f; // skip PUSH data
  }
  if (delegating) {
    return {
      kind: "delegating",
      bytes: raw.length,
      proxy: raw.length <= MINIMAL_PROXY_BYTES && hex.includes(EIP1967_SLOT_HEX) ? "eip1967-minimal" : !hex.includes(EIP1967_SLOT_HEX) && hex.includes(ZEPPELINOS_SLOT_HEX) ? "zeppelinos" : "eip1967",
      ...(linked.size ? { linked: [...linked] } : {}),
    };
  }
  if (TOKEN_SELECTORS.every((s) => selectors.has(s))) return { kind: "token", bytes: raw.length };
  if (NFT_SELECTORS.some((set) => set.every((s) => selectors.has(s)))) return { kind: "nft", bytes: raw.length };
  return { kind: "logic", bytes: raw.length, fingerprint: createHash("sha256").update(code).digest("hex"), skeleton: createHash("sha256").update(skeletonBytes(code)).digest("hex") };
}

/** Whether the code makes the address a contract (EIP-7702 delegated accounts stay EOAs). */
export function isContractCode(facts: CodeFacts): boolean {
  return facts.kind !== "none" && facts.kind !== "delegated";
}

/**
 * All fingerprints that identify the code an address runs: its own, its delegate's or
 * implementation's, hard-coded links, and the template fingerprints of the first two.
 * Exact sets (Forta, ScamSniffer) never contain a template, so querying one is harmless.
 */
export function fingerprintsOf(facts: CodeFacts | undefined): string[] {
  return facts
    ? [facts.fingerprint, facts.implementation_fingerprint, ...(facts.linked_fingerprints ?? []), facts.skeleton, facts.implementation_skeleton].filter((f): f is string => typeof f === "string")
    : [];
}

export type BatchCall = (requests: Array<{ method: string; params: unknown[] }>) => Promise<Array<unknown>>;

/**
 * Follows one level of indirection so that drainer code behind an EIP-7702 delegation,
 * an EIP-1167 minimal proxy or an EIP-1967 proxy is fingerprinted too. Mutates the
 * facts in place (implementation, implementation_fingerprint). At most two batched
 * round trips; failures leave the facts as they were.
 */
export async function resolveIndirection(entries: Map<string, CodeFacts>, call: BatchCall, opts: { maxLinks?: number } = {}): Promise<void> {
  const byImpl = new Map<string, string[]>();
  const link = (address: string, impl: string) => byImpl.set(impl.toLowerCase(), [...(byImpl.get(impl.toLowerCase()) ?? []), address]);
  const byLinked = new Map<string, string[]>();
  for (const [address, f] of entries) {
    for (const l of f.linked ?? []) byLinked.set(l, [...(byLinked.get(l) ?? []), address]);
  }
  const slotReads: string[] = [];
  for (const [address, f] of entries) {
    if (f.kind === "delegated" && f.delegate) link(address, f.delegate);
    else if (f.implementation) link(address, f.implementation);
    else if (f.kind === "delegating") slotReads.push(address);
  }
  if (slotReads.length) {
    try {
      // Safe proxies keep the implementation (masterCopy) in slot 0, ZeppelinOS proxies in their
      // own slot, the others in the EIP-1967 slot.
      const slotOf = (proxy: CodeFacts["proxy"]) => (proxy === "safe" ? "0x0" : proxy === "zeppelinos" ? ZEPPELINOS_IMPLEMENTATION_SLOT : EIP1967_IMPLEMENTATION_SLOT);
      const slots = await call(slotReads.map((a) => ({ method: "eth_getStorageAt", params: [a, slotOf(entries.get(a)?.proxy), "latest"] })));
      slotReads.forEach((address, i) => {
        const word = typeof slots[i] === "string" ? (slots[i] as string).toLowerCase().replace(/^0x/, "").padStart(64, "0") : "";
        const impl = word.length === 64 ? `0x${word.slice(24)}` : "";
        if (/^0x[0-9a-f]{40}$/.test(impl) && !/^0x0{40}$/.test(impl)) {
          const f = entries.get(address) as CodeFacts;
          f.implementation = impl;
          link(address, impl);
        }
      });
    } catch {
      // storage unreadable: the proxy keeps its own classification
    }
  }
  const impls = [...byImpl.keys()];
  // Hard-coded links are a best-effort signal: bounded per call at runtime (latency).
  const links = [...byLinked.keys()].filter((l) => !byImpl.has(l)).slice(0, opts.maxLinks ?? 6);
  if (!impls.length && !links.length) return;
  try {
    const targets = [...impls, ...links];
    const codes = await call(targets.map((a) => ({ method: "eth_getCode", params: [a, "latest"] })));
    targets.forEach((target, i) => {
      const targetFacts = typeof codes[i] === "string" ? codeFacts(codes[i] as string) : undefined;
      const fp = targetFacts?.fingerprint;
      if (!fp) return;
      for (const address of byImpl.get(target) ?? []) {
        const f = entries.get(address) as CodeFacts;
        f.implementation_fingerprint = fp;
        if (targetFacts?.skeleton) f.implementation_skeleton = targetFacts.skeleton;
      }
      for (const address of byLinked.get(target) ?? []) {
        const f = entries.get(address) as CodeFacts;
        f.linked_fingerprints = [...new Set([...(f.linked_fingerprints ?? []), fp])];
      }
    });
  } catch {
    // implementation code unreadable: nothing to add
  }
}

/** The address whose source verification speaks for this code: the delegate or the implementation of an exact forwarding proxy; otherwise itself. */
export function verificationTarget(address: string, facts: CodeFacts | undefined): string {
  if (!facts) return address;
  if (facts.kind === "delegated" && facts.delegate) return facts.delegate;
  if (facts.implementation && (facts.proxy === "eip1167" || facts.proxy === "safe" || facts.proxy === "eip1967-minimal")) return facts.implementation;
  return address;
}
