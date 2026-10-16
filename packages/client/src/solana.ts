// Solana transactions and messages, read without dependencies, for the signing guard.
//
// - The wire format: legacy and v0 messages, and their address lookup tables.
// - The instructions that move or hand over the signer's assets: System (transfers, account
//   creation, assign, nonce withdrawals and authority), SPL Token and Token-2022 (transfers,
//   approvals, authority changes, closing), and the Associated Token Account program, whose
//   create instruction names a token account's owner (enforced on-chain).
// - Lamports sent to an account this transaction creates or assigns go to whoever controls that
//   account: the withdraw authority a Stake Initialize sets, the owner an InitializeAccount sets,
//   a nonce authority, the base of a seed-derived account, or else its owner program.
// - Any other program that receives the signer's account is a call to that program.
//
// Nothing is guessed. A token or system instruction the signer authorizes but this file does
// not read, an unresolved lookup table, or an unknown token-account owner leaves the check
// unfinished (the guard then refuses to sign).
import type { FetchLike } from "./types.js";

export const SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
export const DEFAULT_SOLANA_RPC = "https://api.mainnet-beta.solana.com";
export const SYSTEM_PROGRAM = "11111111111111111111111111111111";
export const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
export const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
export const ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
export const ADDRESS_LOOKUP_TABLE_PROGRAM = "AddressLookupTab1e1111111111111111111111111";
export const STAKE_PROGRAM = "Stake11111111111111111111111111111111111111";
const VOTE_PROGRAM = "Vote111111111111111111111111111111111111111";
/** The sysvars the Stake program's old account layouts carry; since Stake v5 they are optional, and the program branches on them. */
const CLOCK_SYSVAR = "SysvarC1ock11111111111111111111111111111111";
const RENT_SYSVAR = "SysvarRent111111111111111111111111111111111";
const BPF_UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111";
const COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111";
/** Native programs whose accounts' lamports answer to authorities this file does not read. */
const AUTHORITY_OWNERS = new Set([
  VOTE_PROGRAM,
  BPF_UPGRADEABLE_LOADER,
  ADDRESS_LOOKUP_TABLE_PROGRAM,
  "BPFLoader2111111111111111111111111111111111",
  "LoaderV411111111111111111111111111111111111",
  "Config1111111111111111111111111111111111111",
]);
/** Rent-exempt minimum of an account of `space` bytes: (128 + space) × 3480 × 2 lamports. */
const rentExempt = (space: bigint): bigint => (128n + space) * 6960n;
/** Native programs a seed-derived account may be assigned to without handing it to a third party's code. */
const NATIVE_OWNERS = new Set([SYSTEM_PROGRAM, STAKE_PROGRAM, VOTE_PROGRAM]);
/** Base fee per signature, and the compute limits the runtime applies without SetComputeUnitLimit. */
const LAMPORTS_PER_SIGNATURE = 5000n;
const DEFAULT_UNITS_PER_INSTRUCTION = 200_000;
const MAX_COMPUTE_UNITS = 1_400_000;
const MEMO_PROGRAMS = new Set(["MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo"]);
const U64_MAX = (1n << 64n) - 1n;
/** Bytes of an address lookup table's header, before its addresses. */
const LOOKUP_TABLE_META = 56;
/** Larger than any real message (a transaction packet is 1232 bytes): anything bigger is refused. */
const MAX_MESSAGE_BYTES = 4096;

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const DIGIT = new Map([...ALPHABET].map((c, i) => [c, i]));

export function base58Encode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i] as number;
    for (let j = 0; j < digits.length; j++) {
      carry += (digits[j] as number) << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  return "1".repeat(zeros) + digits.reverse().map((d) => ALPHABET[d]).join("");
}

export function base58Decode(text: string): Uint8Array | null {
  if (text.length === 0 || text.length > 128) return null;
  let zeros = 0;
  while (zeros < text.length && text[zeros] === "1") zeros++;
  const bytes: number[] = [];
  for (let i = zeros; i < text.length; i++) {
    const value = DIGIT.get(text[i] as string);
    if (value === undefined) return null;
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += (bytes[j] as number) * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...bytes.reverse()]);
}

export class SolanaDecodeError extends Error {
  override readonly name = "SolanaDecodeError";
}

export interface SolanaInstruction {
  programIndex: number;
  accounts: number[];
  data: Uint8Array;
}

export interface SolanaMessage {
  version: "legacy" | 0;
  header: { signatures: number; readonlySigned: number; readonlyUnsigned: number };
  staticAccounts: string[];
  blockhash: string;
  instructions: SolanaInstruction[];
  lookups: Array<{ table: string; writable: number[]; readonly: number[] }>;
}

/** A legacy or v0 message, strictly: every length consistent, every index in range, no trailing byte. */
export function decodeSolanaMessage(bytes: Uint8Array): SolanaMessage {
  if (bytes.length === 0 || bytes.length > MAX_MESSAGE_BYTES) throw new SolanaDecodeError(`a message of ${bytes.length} bytes`);
  let at = 0;
  const byte = (): number => {
    if (at >= bytes.length) throw new SolanaDecodeError("truncated");
    return bytes[at++] as number;
  };
  const take = (n: number): Uint8Array => {
    if (at + n > bytes.length) throw new SolanaDecodeError("truncated");
    const out = bytes.slice(at, at + n);
    at += n;
    return out;
  };
  // compact-u16 ("shortvec"): 1 to 3 bytes, 7 bits each, canonical.
  const length = (): number => {
    let value = 0;
    for (let i = 0; i < 3; i++) {
      const b = byte();
      value |= (b & 0x7f) << (7 * i);
      if ((b & 0x80) === 0) {
        if (i > 0 && b === 0) throw new SolanaDecodeError("non-canonical length");
        return value;
      }
    }
    throw new SolanaDecodeError("length too long");
  };
  let version: "legacy" | 0 = "legacy";
  if (((bytes[0] as number) & 0x80) !== 0) {
    if (((bytes[0] as number) & 0x7f) !== 0) throw new SolanaDecodeError(`message version ${(bytes[0] as number) & 0x7f}`);
    version = 0;
    at = 1;
  }
  const header = { signatures: byte(), readonlySigned: byte(), readonlyUnsigned: byte() };
  const count = length();
  if (count === 0 || count > 256) throw new SolanaDecodeError(`${count} accounts`);
  const staticAccounts = Array.from({ length: count }, () => base58Encode(take(32)));
  if (header.signatures === 0 || header.readonlySigned >= header.signatures || header.signatures + header.readonlyUnsigned > count) throw new SolanaDecodeError("inconsistent header");
  const blockhash = base58Encode(take(32));
  const instructions = Array.from({ length: length() }, (): SolanaInstruction => {
    const programIndex = byte();
    const accounts = Array.from(take(length()));
    return { programIndex, accounts, data: take(length()) };
  });
  const lookups = version === 0 ? Array.from({ length: length() }, () => ({ table: base58Encode(take(32)), writable: Array.from(take(length())), readonly: Array.from(take(length())) })) : [];
  if (at !== bytes.length) throw new SolanaDecodeError("trailing bytes");
  const total = count + lookups.reduce((n, l) => n + l.writable.length + l.readonly.length, 0);
  if (total > 256) throw new SolanaDecodeError(`${total} accounts`);
  for (const ix of instructions) {
    // Programs are never loaded from a lookup table.
    if (ix.programIndex >= count) throw new SolanaDecodeError("program index out of range");
    if (ix.accounts.some((i) => i >= total)) throw new SolanaDecodeError("account index out of range");
  }
  return { version, header, staticAccounts, blockhash, instructions, lookups };
}

/** Every account of a message in index order: the static ones, then each table's writable, then each table's read-only entries. */
export function accountKeys(message: SolanaMessage, tables: ReadonlyMap<string, readonly string[]>): string[] {
  const keys = [...message.staticAccounts];
  const pick = (table: string, i: number): string => {
    const address = tables.get(table)?.[i];
    if (!address) throw new SolanaDecodeError(`lookup table ${table} has no entry ${i}`);
    return address;
  };
  for (const l of message.lookups) for (const i of l.writable) keys.push(pick(l.table, i));
  for (const l of message.lookups) for (const i of l.readonly) keys.push(pick(l.table, i));
  return keys;
}

/** An address lookup table's addresses (its data after the 56-byte header). */
export function lookupTableAddresses(data: Uint8Array): string[] {
  if (data.length < LOOKUP_TABLE_META || (data.length - LOOKUP_TABLE_META) % 32 !== 0 || data[0] !== 1 || data[1] !== 0 || data[2] !== 0 || data[3] !== 0) {
    throw new SolanaDecodeError("not an address lookup table");
  }
  const out: string[] = [];
  for (let at = LOOKUP_TABLE_META; at < data.length; at += 32) out.push(base58Encode(data.subarray(at, at + 32)));
  return out;
}

export interface SolanaAccount {
  /** The program that owns the account. */
  owner: string;
  data: Uint8Array;
}

/** A token account's mint and owner (SPL Token or Token-2022), or null when the account is not one. */
export function tokenAccountInfo(account: SolanaAccount): { mint: string; owner: string } | null {
  if (account.owner !== TOKEN_PROGRAM && account.owner !== TOKEN_2022_PROGRAM) return null;
  // 165 bytes; Token-2022 accounts with extensions are longer, with the account type (2) at byte 165.
  if (account.data.length < 165 || (account.data.length > 165 && account.data[165] !== 2)) return null;
  return { mint: base58Encode(account.data.subarray(0, 32)), owner: base58Encode(account.data.subarray(32, 64)) };
}

function base64Bytes(text: string): Uint8Array {
  const raw = atob(text);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

/** `getMultipleAccounts` (base64): null for an account that does not exist. Throws on any RPC failure. */
export async function getSolanaAccounts(rpcUrl: string, addresses: readonly string[], fetchImpl: FetchLike, timeoutMs: number): Promise<Array<SolanaAccount | null>> {
  if (addresses.length === 0) return [];
  if (addresses.length > 100) throw new Error("more than 100 accounts to read");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getMultipleAccounts", params: [addresses, { encoding: "base64", commitment: "confirmed" }] }),
      signal: controller.signal,
    });
    if (res.status !== 200) throw new Error(`Solana RPC answered HTTP ${res.status}`);
    const body = JSON.parse(await res.text()) as { result?: { value?: unknown } };
    const value = body.result?.value;
    if (!Array.isArray(value) || value.length !== addresses.length) throw new Error("unexpected Solana RPC answer");
    return value.map((v: unknown) => {
      if (v === null) return null;
      const account = v as { owner?: unknown; data?: unknown };
      if (typeof account.owner !== "string" || !Array.isArray(account.data) || typeof account.data[0] !== "string") throw new Error("malformed Solana account");
      return { owner: account.owner, data: base64Bytes(account.data[0]) };
    });
  } finally {
    clearTimeout(timer);
  }
}

/** What the signer's signature would authorize, per counterparty. */
export type SolanaFinding =
  | { kind: "native_transfer"; to: string; lamports?: string | undefined; how: string }
  | { kind: "token_transfer"; account: string; owner?: string | undefined; mint?: string | undefined; amount: string }
  | { kind: "token_approval"; delegate: string; amount: string; unlimited: boolean; mint?: string | undefined }
  | { kind: "program_call"; program: string };

export interface SolanaAnalysis {
  /** Whether the signer is a required signer: if not, its signature authorizes nothing. */
  required: boolean;
  /** When the signer pays the fees: the most the transaction can charge it (signatures plus priority fee), in lamports. */
  maxFeeLamports?: bigint | undefined;
  /** It uses a durable nonce: once signed, it never expires. */
  durableNonce: boolean;
  /** Locally proven danger: the account itself, or control of it, changes hands. */
  danger: string[];
  /** Instructions the signer authorizes that this guard does not read. */
  unreadable: string[];
  notes: string[];
  findings: SolanaFinding[];
  /** Token accounts created in the transaction, with the owner the ATA program enforces. */
  created: Map<string, { owner: string; mint: string }>;
}

const AUTHORITY: Record<number, string> = { 0: "mint", 1: "freeze", 2: "account owner", 3: "close" };

function u32(data: Uint8Array, at: number): number {
  return ((data[at] as number) | ((data[at + 1] as number) << 8) | ((data[at + 2] as number) << 16)) + (data[at + 3] as number) * 0x1000000;
}

function u64(data: Uint8Array, at: number): bigint {
  let value = 0n;
  for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(data[at + i] as number);
  return value;
}

/** Reads what a message would make the signer do. Pure: resolution (tables, token owners) happens before and after. */
export function analyzeSolanaMessage(message: SolanaMessage, keys: readonly string[], signer: string): SolanaAnalysis {
  const out: SolanaAnalysis = {
    required: message.staticAccounts.slice(0, message.header.signatures).includes(signer),
    durableNonce: false,
    danger: [],
    unreadable: [],
    notes: [],
    findings: [],
    created: new Map(),
  };
  let unitLimit: number | undefined;
  let unitPrice = 0n;
  let computeInstructions = 0;
  // Lamports leaving the signer, settled after every instruction is read: an account this
  // transaction creates or assigns is controlled by its owner program or the authority its
  // initialization names, never by its own (fresh) address.
  const funded: Array<{ to: string; lamports?: string | undefined; how: string }> = [];
  /** The owner program an account is given here (CreateAccount*, Assign*, AllocateWithSeed). */
  const ownerOf = new Map<string, string>();
  const spaceOf = new Map<string, bigint>();
  /** A seed-derived account's base: it alone moves a system account's lamports (TransferWithSeed). */
  const seedBase = new Map<string, string>();
  const nonceAuthority = new Map<string, string>();
  const stakeAuthority = new Map<string, { withdrawer: string; custodian?: string | undefined }>();
  const tokenInit = new Map<string, { kind: "account" | "mint" | "multisig"; owner?: string | undefined }>();
  const closeAuthority = new Map<string, string>();
  message.instructions.forEach((ix, n) => {
    const program = keys[ix.programIndex] as string;
    const d = ix.data;
    const account = (i: number): string | undefined => {
      const index = ix.accounts[i];
      return index === undefined ? undefined : keys[index];
    };
    const involves = ix.accounts.some((i) => keys[i] === signer);
    // The signer is the authority, or one of a multisig authority's signers (listed after the fixed accounts).
    const authorizes = (authority: number, fixed: number) => account(authority) === signer || ix.accounts.slice(fixed).some((i) => keys[i] === signer);
    const unread = (what: string) => {
      if (involves) out.unreadable.push(`${what} (instruction ${n + 1})`);
    };

    if (program === COMPUTE_BUDGET_PROGRAM) {
      computeInstructions++;
      // SetComputeUnitLimit (2, u32) and SetComputeUnitPrice (3, u64 micro-lamports per unit) set the priority fee.
      if (d[0] === 2 && d.length === 5) unitLimit = u32(d, 1);
      else if (d[0] === 3 && d.length === 9) unitPrice = u64(d, 1);
      return;
    }
    if (MEMO_PROGRAMS.has(program)) return;

    if (program === SYSTEM_PROGRAM) {
      if (d.length < 4) return unread("a System instruction");
      const op = u32(d, 0);
      const to = (i: number) => account(i);
      switch (op) {
        case 0: // CreateAccount [funder, new] lamports, space, owner
        case 3: {
          // CreateAccountWithSeed [funder, new, base?] base, seed, lamports, space, owner
          const seed = op === 3 && d.length >= 44 ? Number(u64(d, 36)) : 0;
          const at = op === 0 ? 4 : 44 + seed;
          if ((op === 0 && d.length !== 52) || (op === 3 && (d.length < 44 || d.length !== 92 + seed))) return unread(`a System CreateAccount${op === 3 ? "WithSeed" : ""}`);
          const target = to(1);
          if (!target) return;
          ownerOf.set(target, base58Encode(d.subarray(at + 16, at + 48)));
          spaceOf.set(target, u64(d, at + 8));
          if (op === 3) seedBase.set(target, base58Encode(d.subarray(4, 36)));
          if (account(0) === signer && target !== signer) funded.push({ to: target, lamports: u64(d, at).toString(), how: "funds a new account" });
          return;
        }
        case 1: {
          // Assign [account] owner
          if (d.length !== 36) return unread("a System Assign");
          if (account(0) === signer) out.danger.push(`System Assign hands the signer's own account to program ${base58Encode(d.subarray(4, 36))}: that program would control everything the account holds`);
          else if (account(0)) ownerOf.set(account(0) as string, base58Encode(d.subarray(4, 36)));
          return;
        }
        case 9: // AllocateWithSeed [account, base] base, seed, space, owner: it assigns the account too.
        case 10: {
          // AssignWithSeed [account, base] base, seed, owner: the base signs for the seed-derived account.
          const length = d.length >= 44 ? Number(u64(d, 36)) : -1;
          const end = op === 9 ? 44 + length + 8 : 44 + length;
          if (length < 0 || d.length !== end + 32) return unread(`a System ${op === 9 ? "Allocate" : "Assign"}WithSeed`);
          const owner = base58Encode(d.subarray(end, end + 32));
          if (account(0)) ownerOf.set(account(0) as string, owner);
          if (op === 9 && account(0)) spaceOf.set(account(0) as string, u64(d, 44 + length));
          if ((account(0) === signer || account(1) === signer) && !NATIVE_OWNERS.has(owner)) {
            out.danger.push(`System ${op === 9 ? "Allocate" : "Assign"}WithSeed hands the signer's seed-derived account ${account(0)} to program ${owner}: that program would control everything the account holds`);
          }
          return;
        }
        case 2: {
          // Transfer [from, to] lamports
          if (d.length !== 12) return unread("a System Transfer");
          const target = to(1);
          if (account(0) === signer && target && target !== signer) funded.push({ to: target, lamports: u64(d, 4).toString(), how: "System transfer" });
          return;
        }
        case 11: {
          // TransferWithSeed [from, base, to] lamports, seed, owner
          if (d.length < 12) return unread("a System TransferWithSeed");
          const target = to(2);
          if (account(1) === signer && target && target !== signer) funded.push({ to: target, lamports: u64(d, 4).toString(), how: "System transfer with seed" });
          return;
        }
        case 4:
          // AdvanceNonceAccount: a durable nonce, so the transaction never expires.
          out.durableNonce = true;
          out.notes.push("it uses a durable nonce: once signed, it can be submitted at any later time");
          return;
        case 5: {
          // WithdrawNonceAccount [nonce, to, recent blockhashes, rent, authority] lamports
          if (d.length !== 12) return unread("a System WithdrawNonceAccount");
          const target = to(1);
          if (account(4) === signer && target && target !== signer) funded.push({ to: target, lamports: u64(d, 4).toString(), how: "nonce account withdrawal" });
          return;
        }
        case 7: {
          // AuthorizeNonceAccount [nonce, authority] new authority
          if (d.length !== 36) return unread("a System AuthorizeNonceAccount");
          const next = base58Encode(d.subarray(4, 36));
          if (account(1) === signer && next !== signer) out.danger.push(`it hands the authority of nonce account ${account(0)} to ${next}`);
          return;
        }
        case 6: // InitializeNonceAccount [nonce, recent blockhashes, rent] authority: it alone withdraws the lamports.
          if (d.length === 36 && account(0)) nonceAuthority.set(account(0) as string, base58Encode(d.subarray(4, 36)));
          return;
        case 8: // Allocate
        case 12: // UpgradeNonceAccount
          return;
        default:
          return unread(`System instruction ${op}`);
      }
    }

    if (program === TOKEN_PROGRAM || program === TOKEN_2022_PROGRAM) {
      const name = program === TOKEN_PROGRAM ? "SPL Token" : "Token-2022";
      if (d.length < 1) return unread(`a ${name} instruction`);
      const op = d[0] as number;
      switch (op) {
        case 3: {
          // Transfer [source, destination, authority, ...signers] amount
          if (d.length !== 9) return unread(`a ${name} Transfer`);
          const destination = account(1);
          if (authorizes(2, 3) && destination) out.findings.push({ kind: "token_transfer", account: destination, amount: u64(d, 1).toString() });
          return;
        }
        case 12: {
          // TransferChecked [source, mint, destination, authority, ...signers] amount, decimals
          if (d.length !== 10) return unread(`a ${name} TransferChecked`);
          const destination = account(2);
          if (authorizes(3, 4) && destination) out.findings.push({ kind: "token_transfer", account: destination, mint: account(1), amount: u64(d, 1).toString() });
          return;
        }
        case 26: {
          // Token-2022 TransferFeeExtension; 1 = TransferCheckedWithFee [source, mint, destination, authority] amount, decimals, fee
          if (program !== TOKEN_2022_PROGRAM || d[1] !== 1 || d.length !== 19) return unread(`${name} instruction ${op}`);
          const destination = account(2);
          if (authorizes(3, 4) && destination) out.findings.push({ kind: "token_transfer", account: destination, mint: account(1), amount: u64(d, 2).toString() });
          return;
        }
        case 4:
        case 13: {
          // Approve [source, delegate, owner, ...signers] amount · ApproveChecked [source, mint, delegate, owner, ...signers] amount, decimals
          if (d.length !== (op === 4 ? 9 : 10)) return unread(`a ${name} Approve`);
          const checked = op === 13;
          const delegate = account(checked ? 2 : 1);
          if (authorizes(checked ? 3 : 2, checked ? 4 : 3) && delegate && delegate !== signer) {
            const amount = u64(d, 1);
            out.findings.push({ kind: "token_approval", delegate, amount: amount.toString(), unlimited: amount === U64_MAX, ...(checked ? { mint: account(1) } : {}) });
          }
          return;
        }
        case 6: {
          // SetAuthority [account, current authority, ...signers] type, COption<Pubkey>
          if (d.length !== 3 && d.length !== 35) return unread(`a ${name} SetAuthority`);
          const next = d[2] === 1 && d.length === 35 ? base58Encode(d.subarray(3, 35)) : null;
          if (authorizes(1, 2) && next && next !== signer) {
            out.danger.push(`${name} SetAuthority hands the ${AUTHORITY[d[1] as number] ?? `type ${d[1]}`} authority of ${account(0)} to ${next}`);
          }
          return;
        }
        case 9: {
          // CloseAccount [account, destination, owner, ...signers]: its lamports (all of it, for wrapped SOL) go to destination
          const destination = account(1);
          if (authorizes(2, 3) && destination && destination !== signer) funded.push({ to: destination, how: "closing a token account sends it the account's lamports" });
          return;
        }
        case 7:
        case 14: {
          // MintTo [mint, destination, authority, ...signers] amount · MintToChecked amount, decimals: the signer's mint authority creates tokens for the destination.
          if (d.length !== (op === 7 ? 9 : 10)) return unread(`a ${name} MintTo`);
          const destination = account(1);
          if (authorizes(2, 3) && destination) out.findings.push({ kind: "token_transfer", account: destination, mint: account(0), amount: u64(d, 1).toString() });
          return;
        }
        case 8: // Burn
        case 15: // BurnChecked
          if (involves) out.notes.push(`it burns tokens (instruction ${n + 1})`);
          return;
        case 1: // InitializeAccount [account, mint, owner, rent]
        case 16: // InitializeAccount2 [account, mint, rent] owner
        case 18: {
          // InitializeAccount3 [account, mint] owner: the owner can close the account and take its lamports.
          // The token program reads the owner from the first 32 bytes after the tag and ignores the rest.
          const owner = op === 1 ? account(2) : d.length >= 33 ? base58Encode(d.subarray(1, 33)) : undefined;
          if (account(0)) tokenInit.set(account(0) as string, { kind: "account", owner });
          return;
        }
        case 0: // InitializeMint
        case 20: // InitializeMint2
          if (account(0)) tokenInit.set(account(0) as string, { kind: "mint" });
          return;
        case 2: // InitializeMultisig
        case 19: // InitializeMultisig2
          if (account(0)) tokenInit.set(account(0) as string, { kind: "multisig" });
          return;
        case 25: {
          // Token-2022 InitializeMintCloseAuthority [mint] COption<Pubkey>: the close authority takes a closed mint's lamports.
          if (program !== TOKEN_2022_PROGRAM) return unread(`${name} instruction ${op}`);
          if (d[1] === 1 && d.length >= 34 && account(0)) closeAuthority.set(account(0) as string, base58Encode(d.subarray(2, 34)));
          return;
        }
        case 5: // Revoke
        case 10: // FreezeAccount
        case 11: // ThawAccount
        case 17: // SyncNative
        case 21: // GetAccountDataSize
        case 22: // InitializeImmutableOwner
        case 23: // AmountToUiAmount
        case 24: // UiAmountToAmount
          return;
        default:
          return unread(`${name} instruction ${op}`);
      }
    }

    if (program === STAKE_PROGRAM) {
      const op = d.length >= 4 ? u32(d, 0) : -1;
      // Two account layouts since Stake v5 (SIMD-0490, on mainnet since 2026-06-18): the old one carries
      // sysvars (clock, rent, stake history) after the first accounts, the new one none, and the program
      // tells them apart by the sysvar's key at that position. So does this.
      const clockAt = (i: number) => account(i) === CLOCK_SYSVAR;
      // Initialize [stake, (rent)] Authorized { staker, withdrawer }, Lockup { unix_timestamp, epoch, custodian }:
      // the withdrawer controls the lamports, and a lockup's custodian alone can lift the lockup.
      if (op === 0 && d.length === 116 && account(0)) {
        const lockup = u64(d, 68) !== 0n || u64(d, 76) !== 0n;
        stakeAuthority.set(account(0) as string, { withdrawer: base58Encode(d.subarray(36, 68)), ...(lockup ? { custodian: base58Encode(d.subarray(84, 116)) } : {}) });
      }
      // InitializeChecked [stake, rent, staker, withdrawer] (old) or [stake, staker, withdrawer] (v5).
      if (op === 9 && account(0)) {
        const withdrawer = account(1) === RENT_SYSVAR ? account(3) : account(2);
        if (withdrawer) stakeAuthority.set(account(0) as string, { withdrawer });
      }
      if (!involves) return;
      if (op < 0) return unread("a Stake instruction");
      const kinds = ["staker", "withdrawer"];
      switch (op) {
        case 1: {
          // Authorize [stake, (clock), authority, (custodian)] new authority, which (u32). The program accepts
          // any signer among the instruction's accounts as the authority, so the signer's presence is what
          // counts, never its position.
          if (d.length !== 40) return unread("a Stake Authorize");
          const next = base58Encode(d.subarray(4, 36));
          if (next !== signer) out.danger.push(`Stake Authorize hands the ${kinds[u32(d, 36)] ?? "stake"} authority of ${account(0)} to ${next}`);
          return;
        }
        case 8: {
          // AuthorizeWithSeed [stake, base, (clock), (custodian)] new authority, which, seed, owner: the base signs.
          if (d.length < 40) return unread("a Stake AuthorizeWithSeed");
          const next = base58Encode(d.subarray(4, 36));
          if (account(1) === signer && next !== signer) out.danger.push(`Stake AuthorizeWithSeed hands the ${kinds[u32(d, 36)] ?? "stake"} authority of ${account(0)} to ${next}`);
          return;
        }
        case 10: {
          // AuthorizeChecked [stake, (clock), current authority, new authority, (custodian)] which: any signer
          // among the accounts authorizes it, as for Authorize.
          const next = clockAt(1) ? account(3) : account(2);
          if (!next) return unread("a Stake AuthorizeChecked");
          if (next !== signer) out.danger.push(`Stake AuthorizeChecked hands the ${kinds[d.length >= 8 ? u32(d, 4) : -1] ?? "stake"} authority of ${account(0)} to ${next}`);
          return;
        }
        case 11: {
          // AuthorizeCheckedWithSeed [stake, base, (clock), new authority, (custodian)] which, seed, owner: the base signs.
          const next = clockAt(2) ? account(3) : account(2);
          if (!next) return unread("a Stake AuthorizeCheckedWithSeed");
          if (account(1) === signer && next !== signer) out.danger.push(`Stake AuthorizeCheckedWithSeed hands the ${kinds[d.length >= 8 ? u32(d, 4) : -1] ?? "stake"} authority of ${account(0)} to ${next}`);
          return;
        }
        case 4: {
          // Withdraw [stake, recipient, (clock, stake history), withdraw authority, (custodian)] lamports.
          if (d.length !== 12) return unread("a Stake Withdraw");
          const recipient = account(1);
          const authority = clockAt(2) ? account(4) : account(2);
          if (authority === signer && recipient && recipient !== signer) funded.push({ to: recipient, lamports: u64(d, 4).toString(), how: "stake withdrawal" });
          return;
        }
        case 6: // SetLockup
        case 12: // SetLockupChecked
          out.danger.push(`Stake SetLockup changes the lockup or custodian of stake account ${account(0)}`);
          return;
        case 0: // Initialize
        case 2: // DelegateStake
        case 3: // Split
        case 5: // Deactivate
        case 7: // Merge
        case 9: // InitializeChecked
        case 13: // GetMinimumDelegation
        case 14: // DeactivateDelinquent
        case 16: // MoveStake
        case 17: // MoveLamports
          return;
        default:
          return unread(`Stake instruction ${op}`);
      }
    }

    // Native programs whose instructions move lamports or hand over authority from their data.
    if (program === VOTE_PROGRAM || program === BPF_UPGRADEABLE_LOADER || program === ADDRESS_LOOKUP_TABLE_PROGRAM) {
      return unread(`a ${program === VOTE_PROGRAM ? "Vote" : program === BPF_UPGRADEABLE_LOADER ? "BPF Upgradeable Loader" : "Address Lookup Table"} instruction`);
    }

    if (program === ASSOCIATED_TOKEN_PROGRAM) {
      // Create / CreateIdempotent [payer, associated account, owner, mint, system, token program]
      if (d.length === 0 || d[0] === 0 || d[0] === 1) {
        const [ata, owner, mint] = [account(1), account(2), account(3)];
        if (ata && owner && mint) out.created.set(ata, { owner, mint });
        return;
      }
      return unread(`Associated Token Account instruction ${d[0]}`);
    }

    // Any other program that receives the signer's account can act with the signer's authority.
    if (involves && !out.findings.some((f) => f.kind === "program_call" && f.program === program)) out.findings.push({ kind: "program_call", program });
  });
  settleFunding(out, signer, funded, { ownerOf, spaceOf, seedBase, nonceAuthority, stakeAuthority, tokenInit, closeAuthority });
  // The fee payer is the first static account: signatures plus the priority fee (price × limit, in micro-lamports).
  if (message.staticAccounts[0] === signer) {
    const limit = BigInt(Math.min(unitLimit ?? DEFAULT_UNITS_PER_INSTRUCTION * (message.instructions.length - computeInstructions), MAX_COMPUTE_UNITS));
    out.maxFeeLamports = LAMPORTS_PER_SIGNATURE * BigInt(message.header.signatures) + (unitPrice * limit + 999_999n) / 1_000_000n;
  }
  return out;
}

type Controls = {
  ownerOf: ReadonlyMap<string, string>;
  spaceOf: ReadonlyMap<string, bigint>;
  seedBase: ReadonlyMap<string, string>;
  nonceAuthority: ReadonlyMap<string, string>;
  stakeAuthority: ReadonlyMap<string, { withdrawer: string; custodian?: string | undefined }>;
  tokenInit: ReadonlyMap<string, { kind: "account" | "mint" | "multisig"; owner?: string | undefined }>;
  closeAuthority: ReadonlyMap<string, string>;
};

/**
 * Each payment of the signer's lamports, to whoever controls the receiving account:
 * - an account this transaction does not give an owner: the account itself (its key);
 * - a system account: its key, a seed-derived account's base, or a nonce account's authority;
 * - a stake account: the withdraw authority its Initialize sets (none here: anyone could set it, so unreadable);
 * - a token account: the owner its InitializeAccount sets; a new mint or multisig keeps at most its
 *   rent-exempt minimum (a Token-2022 mint's close authority takes it); anything else is unreadable;
 * - an account of a native program with its own authorities (Vote, loaders, lookup tables): unreadable;
 * - any other program: that program, checked as a contract call.
 */
function settleFunding(out: SolanaAnalysis, signer: string, funded: ReadonlyArray<{ to: string; lamports?: string | undefined; how: string }>, c: Controls): void {
  const lamportsInto = (account: string): bigint | undefined => {
    let total = 0n;
    for (const f of funded) {
      if (f.to !== account) continue;
      if (f.lamports === undefined) return undefined;
      total += BigInt(f.lamports);
    }
    return total;
  };
  const pay = (to: string, lamports: string | undefined, how: string) => {
    if (to !== signer) out.findings.push({ kind: "native_transfer", to, ...(lamports !== undefined ? { lamports } : {}), how });
  };
  for (const f of funded) {
    const owner = c.ownerOf.get(f.to);
    if (owner === undefined || owner === SYSTEM_PROGRAM) {
      const authority = c.nonceAuthority.get(f.to);
      const base = owner === SYSTEM_PROGRAM ? c.seedBase.get(f.to) : undefined;
      if (authority !== undefined) pay(authority, f.lamports, `${f.how}: nonce account ${f.to}, whose authority alone withdraws it`);
      else if (base !== undefined) pay(base, f.lamports, `${f.how}: seed-derived account ${f.to}, which only its base ${base} can move`);
      else pay(f.to, f.lamports, f.how);
      continue;
    }
    if (owner === STAKE_PROGRAM) {
      const authority = c.stakeAuthority.get(f.to);
      if (!authority) {
        out.unreadable.push(`lamports into stake account ${f.to}, which this transaction does not initialize (anyone could then set its withdraw authority)`);
        continue;
      }
      if (authority.custodian !== undefined && authority.custodian !== signer) {
        const lock = `stake account ${f.to} is locked up, and only custodian ${authority.custodian} can lift the lockup`;
        if (!out.danger.includes(lock)) out.danger.push(lock);
      }
      pay(authority.withdrawer, f.lamports, `${f.how}: stake account ${f.to}, whose withdraw authority is ${authority.withdrawer}`);
      continue;
    }
    if (owner === TOKEN_PROGRAM || owner === TOKEN_2022_PROGRAM) {
      const init = c.tokenInit.get(f.to);
      if (init?.kind === "account" && init.owner !== undefined) {
        pay(init.owner, f.lamports, `${f.how}: token account ${f.to}, which its owner ${init.owner} can close to take its lamports`);
        continue;
      }
      const space = c.spaceOf.get(f.to);
      const total = lamportsInto(f.to);
      if ((init?.kind === "mint" || init?.kind === "multisig") && space !== undefined && total !== undefined && total <= rentExempt(space)) {
        const closer = init.kind === "mint" ? c.closeAuthority.get(f.to) : undefined;
        if (closer !== undefined) pay(closer, f.lamports, `${f.how}: mint ${f.to}, whose close authority ${closer} can take its lamports`);
        continue;
      }
      out.unreadable.push(
        init === undefined || init.kind === "account"
          ? `lamports into token account ${f.to}, which this transaction does not initialize with an owner`
          : `more than the rent-exempt minimum into new ${init.kind} ${f.to}`,
      );
      continue;
    }
    if (AUTHORITY_OWNERS.has(owner)) {
      out.unreadable.push(`lamports into account ${f.to} of native program ${owner}, whose authorities this guard does not read`);
      continue;
    }
    if (!out.findings.some((x) => x.kind === "program_call" && x.program === owner)) out.findings.push({ kind: "program_call", program: owner });
  }
}

/** Whether bytes are a Solana transaction message: signing them as a "message" would authorize that transaction. */
export function isSolanaTransactionMessage(bytes: Uint8Array): boolean {
  try {
    decodeSolanaMessage(bytes);
    return true;
  } catch {
    return false;
  }
}
