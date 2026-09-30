// Solana transactions and messages, read without dependencies, for the signing guard.
//
// - The wire format: legacy and v0 messages, and their address lookup tables.
// - The instructions that move or hand over the signer's assets: System (transfers, account
//   creation, assign, nonce withdrawals and authority), SPL Token and Token-2022 (transfers,
//   approvals, authority changes, closing), and the Associated Token Account program, whose
//   create instruction names a token account's owner (enforced on-chain).
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
const BPF_UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111";
const COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111";
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
          if (op === 0 && d.length !== 52) return unread("a System CreateAccount");
          const target = to(1);
          if (account(0) === signer && target && target !== signer) {
            out.findings.push({ kind: "native_transfer", to: target, ...(op === 0 ? { lamports: u64(d, 4).toString() } : {}), how: "funds a new account" });
          }
          return;
        }
        case 1: {
          // Assign [account] owner
          if (d.length !== 36) return unread("a System Assign");
          if (account(0) === signer) out.danger.push(`System Assign hands the signer's own account to program ${base58Encode(d.subarray(4, 36))}: that program would control everything the account holds`);
          return;
        }
        case 10: {
          // AssignWithSeed [account, base] base, seed, owner: the base signs for the seed-derived account.
          if (account(0) !== signer && account(1) !== signer) return;
          const length = d.length >= 44 ? Number(u64(d, 36)) : -1;
          if (length < 0 || d.length !== 44 + length + 32) return unread("a System AssignWithSeed");
          const owner = base58Encode(d.subarray(44 + length, 76 + length));
          if (!NATIVE_OWNERS.has(owner)) out.danger.push(`System AssignWithSeed hands the signer's seed-derived account ${account(0)} to program ${owner}: that program would control everything the account holds`);
          return;
        }
        case 2: {
          // Transfer [from, to] lamports
          if (d.length !== 12) return unread("a System Transfer");
          const target = to(1);
          if (account(0) === signer && target && target !== signer) out.findings.push({ kind: "native_transfer", to: target, lamports: u64(d, 4).toString(), how: "System transfer" });
          return;
        }
        case 11: {
          // TransferWithSeed [from, base, to] lamports, seed, owner
          if (d.length < 12) return unread("a System TransferWithSeed");
          const target = to(2);
          if (account(1) === signer && target && target !== signer) out.findings.push({ kind: "native_transfer", to: target, lamports: u64(d, 4).toString(), how: "System transfer with seed" });
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
          if (account(4) === signer && target && target !== signer) out.findings.push({ kind: "native_transfer", to: target, lamports: u64(d, 4).toString(), how: "nonce account withdrawal" });
          return;
        }
        case 7: {
          // AuthorizeNonceAccount [nonce, authority] new authority
          if (d.length !== 36) return unread("a System AuthorizeNonceAccount");
          const next = base58Encode(d.subarray(4, 36));
          if (account(1) === signer && next !== signer) out.danger.push(`it hands the authority of nonce account ${account(0)} to ${next}`);
          return;
        }
        case 6: // InitializeNonceAccount
        case 8: // Allocate
        case 9: // AllocateWithSeed
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
          if (authorizes(2, 3) && destination && destination !== signer) out.findings.push({ kind: "native_transfer", to: destination, how: "closing a token account sends it the account's lamports" });
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
        case 0: // InitializeMint
        case 1: // InitializeAccount
        case 5: // Revoke
        case 10: // FreezeAccount
        case 11: // ThawAccount
        case 16: // InitializeAccount2
        case 17: // SyncNative
        case 18: // InitializeAccount3
        case 20: // InitializeMint2
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
      if (!involves) return;
      if (d.length < 4) return unread("a Stake instruction");
      const op = u32(d, 0);
      const kinds = ["staker", "withdrawer"];
      switch (op) {
        case 1: {
          // Authorize [stake, clock, authority, (custodian)] new authority, which (u32)
          if (d.length !== 40) return unread("a Stake Authorize");
          const next = base58Encode(d.subarray(4, 36));
          if (account(2) === signer && next !== signer) out.danger.push(`Stake Authorize hands the ${kinds[u32(d, 36)] ?? "stake"} authority of ${account(0)} to ${next}`);
          return;
        }
        case 8: {
          // AuthorizeWithSeed [stake, base, clock, (custodian)] new authority, which, seed, owner
          if (d.length < 40) return unread("a Stake AuthorizeWithSeed");
          const next = base58Encode(d.subarray(4, 36));
          if (account(1) === signer && next !== signer) out.danger.push(`Stake AuthorizeWithSeed hands the ${kinds[u32(d, 36)] ?? "stake"} authority of ${account(0)} to ${next}`);
          return;
        }
        case 10: {
          // AuthorizeChecked [stake, clock, current authority, new authority, (custodian)] which
          const next = account(3);
          if (account(2) === signer && next && next !== signer) out.danger.push(`Stake AuthorizeChecked hands the ${kinds[d.length >= 8 ? u32(d, 4) : -1] ?? "stake"} authority of ${account(0)} to ${next}`);
          return;
        }
        case 11: {
          // AuthorizeCheckedWithSeed [stake, base, clock, new authority, (custodian)] which, seed, owner
          const next = account(3);
          if (account(1) === signer && next && next !== signer) out.danger.push(`Stake AuthorizeCheckedWithSeed hands the ${kinds[d.length >= 8 ? u32(d, 4) : -1] ?? "stake"} authority of ${account(0)} to ${next}`);
          return;
        }
        case 4: {
          // Withdraw [stake, recipient, clock, stake history, withdraw authority, (custodian)] lamports
          if (d.length !== 12) return unread("a Stake Withdraw");
          const recipient = account(1);
          if (account(4) === signer && recipient && recipient !== signer) out.findings.push({ kind: "native_transfer", to: recipient, lamports: u64(d, 4).toString(), how: "stake withdrawal" });
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
  // The fee payer is the first static account: signatures plus the priority fee (price × limit, in micro-lamports).
  if (message.staticAccounts[0] === signer) {
    const limit = BigInt(Math.min(unitLimit ?? DEFAULT_UNITS_PER_INSTRUCTION * (message.instructions.length - computeInstructions), MAX_COMPUTE_UNITS));
    out.maxFeeLamports = LAMPORTS_PER_SIGNATURE * BigInt(message.header.signatures) + (unitPrice * limit + 999_999n) / 1_000_000n;
  }
  return out;
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
