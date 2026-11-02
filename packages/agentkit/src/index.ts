import { createRequire } from "node:module";
import { ActionProvider, EvmWalletProvider, WalletProvider, type Action, type Network } from "@coinbase/agentkit";
import { INTERACTION_TYPES, toCaip2, type InteractionType, type RiskCheckRequest } from "@x402check/client";
import { X402CheckBlockedError, createGuard, guardAccount, type GuardOptions, type GuardVerdict } from "@x402check/client/guard";
import { createScreener, type Screening, type X402checkOptions } from "./screen.js";

export { createScreener } from "./screen.js";
export type { Screener, Screening, ScreenedCheck, X402checkOptions } from "./screen.js";
export { X402CheckBlockedError } from "@x402check/client/guard";
export type { GuardOptions, GuardVerdict } from "@x402check/client/guard";

const MAX_CONTEXT = 4096;
const INTERCEPTED = new Set(["sign", "signMessage", "signTypedData", "signTransaction", "sendTransaction", "nativeTransfer"]);
/**
 * The wallet's members that only read. Everything else a wallet exposes (gasless transfers, trades,
 * a CDP client, a smart account or its owner) could sign or send without a check, so on a guarded
 * wallet it refuses, unless `options.passthrough` names it.
 */
const READ_ONLY = new Set(["getAddress", "getNetwork", "getName", "getBalance", "getPublicClient", "readContract", "waitForTransactionReceipt", "getCdpSdkNetwork"]);
const HEX = /^0x[0-9a-fA-F]*$/;
const INTEGER = /^\d+$/;

/**
 * The same AgentKit EVM wallet, with x402check between it and every signature: AgentKit's x402
 * payments (EIP-3009 and Permit2 typed data), transfers, approvals, contract calls and messages
 * are decoded, checked and verified before the key signs; anything but a verified allow throws
 * `X402CheckBlockedError` and nothing is signed or sent. Pass it to `AgentKit.from`.
 *
 * Only the members that read pass through as they are. Any other method (a gasless transfer, a
 * trade, `getClient()`) refuses when called; a field holding an account (a smart account, its
 * owner) shows only its address, and any other object throws. `options.passthrough` makes a member
 * reachable as it is, unchecked.
 */
export function guardWalletProvider<W extends EvmWalletProvider>(wallet: W, options: GuardOptions = {}): W {
  if (!(wallet instanceof EvmWalletProvider)) throw new TypeError("guardWalletProvider takes an AgentKit EvmWalletProvider (Solana: guardSolanaSigner from @x402check/client/guard)");
  const network = wallet.getNetwork();
  const chainId = options.chainId ?? (network.chainId && /^\d+$/.test(network.chainId) ? Number(network.chainId) : undefined);
  const guard = createGuard({ ...options, ...(chainId !== undefined ? { chainId } : {}) });
  const opts: GuardOptions = { ...options, client: guard.client, ...(chainId !== undefined ? { chainId } : {}) };
  const address = wallet.getAddress();

  // The wallet's own signing, behind the client's guard (the same decoding, copies and checks as guardAccount).
  const account = guardAccount(
    {
      address,
      sign: ({ hash }: { hash: `0x${string}` }) => wallet.sign(hash),
      // The wallet gets the caller's message unchanged; the guard read it the way the wallet signs it.
      signMessage: ({ message }: { message: string | Uint8Array | { raw: string | Uint8Array } }) => wallet.signMessage(typeof message === "object" && !(message instanceof Uint8Array) ? message.raw : message),
      signTypedData: (typedData: unknown) => wallet.signTypedData(typedData),
      signTransaction: (transaction: Parameters<W["signTransaction"]>[0]) => wallet.signTransaction(transaction),
    },
    opts,
  );

  /** Checks a transaction the wallet will sign and send itself; returns the checked copy, which is what gets sent. */
  async function checked(transaction: unknown): Promise<Parameters<W["sendTransaction"]>[0]> {
    const asked = transaction && typeof transaction === "object" ? (transaction as { chainId?: unknown }).chainId : undefined;
    // The wallet sends on its own network, whatever the transaction says: a check on another chain would not match it.
    if (asked !== undefined && chainId !== undefined && Number(asked) !== chainId) {
      await refuseMalformed("transaction", `a transaction for chain ${String(asked)}`, `the wallet sends on chain ${chainId}, so a transaction for chain ${String(asked)} would not be what was checked`, options);
    }
    let copy: unknown;
    const probe = guardAccount(
      {
        address,
        signTransaction: async (tx: unknown) => {
          copy = tx;
          return "0x" as const;
        },
      },
      opts,
    );
    await probe.signTransaction(transaction);
    return copy as Parameters<W["sendTransaction"]>[0];
  }

  const intercepted: Record<string, (...args: never[]) => Promise<unknown>> = {
    sign: (hash: `0x${string}`) => account.sign({ hash }),
    // AgentKit's viem-based wallets sign a hex string as raw bytes, so the guard reads it as bytes
    // (a 32-byte hash, or any opaque binary, is refused like sign(hash)).
    signMessage: (message: string | Uint8Array) => account.signMessage({ message: typeof message === "string" && HEX.test(message) ? { raw: message } : message }),
    signTypedData: (typedData: unknown) => account.signTypedData(typedData),
    signTransaction: (transaction: unknown) => account.signTransaction(transaction as Parameters<W["signTransaction"]>[0]),
    sendTransaction: async (transaction: unknown) => wallet.sendTransaction(await checked(transaction)),
    nativeTransfer: async (to: string, value: string) => {
      if (typeof value !== "string" || !INTEGER.test(value)) {
        await refuseMalformed("transaction", `a native transfer of ${String(value)}`, "the amount must be an integer in wei, as AgentKit's nativeTransfer takes it", options);
      }
      await checked({ to, value: BigInt(value), ...(chainId !== undefined ? { chainId } : {}) });
      return wallet.nativeTransfer(to, value);
    },
  };
  const passthrough = new Set(options.passthrough ?? []);
  const base = [EvmWalletProvider.prototype, WalletProvider.prototype] as unknown as Record<PropertyKey, unknown>[];

  const open = (prop: PropertyKey) => typeof prop === "symbol" || prop === "constructor" || READ_ONLY.has(prop as string) || passthrough.has(prop as string);
  const guarded: W = new Proxy(wallet, {
    get(target, prop) {
      if (typeof prop === "string" && INTERCEPTED.has(prop)) return intercepted[prop];
      const value: unknown = Reflect.get(target, prop, target);
      // Base-class helpers (toSigner, toEip1193Provider…) run on the guarded wallet, so they sign through it.
      if (typeof value === "function" && base.some((proto) => proto[prop] === value)) {
        return (...args: unknown[]) => (value as (...a: unknown[]) => unknown).apply(guarded, args);
      }
      if (open(prop)) {
        // The wallet's own members run on the wallet itself (private fields need the real instance).
        return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value;
      }
      // Refused synchronously: a caller that does not await the member (AgentKit's CDP actions call
      // some members that way) still sees the refusal, and no rejected promise is left to end the process.
      if (typeof value === "function") {
        return () => {
          throw unguardedError(String(prop), options, true);
        };
      }
      if (value !== null && typeof value === "object") {
        // An account (a smart account, its owner) shows its address only: it could sign, the address cannot.
        const address = (value as { address?: unknown }).address;
        if (typeof address === "string") return Object.freeze({ address });
        // Any other object (a client) could sign: not reachable.
        throw unguardedError(String(prop), options);
      }
      return value;
    },
    // Reading a field through its descriptor follows the same rules as reading it.
    getOwnPropertyDescriptor(target, prop) {
      const descriptor = Reflect.getOwnPropertyDescriptor(target, prop);
      if (!descriptor || open(prop)) return descriptor;
      if (!descriptor.configurable) throw unguardedError(String(prop), options);
      return { get: () => (guarded as Record<PropertyKey, unknown>)[prop], enumerable: descriptor.enumerable ?? false, configurable: true };
    },
  });
  return guarded;
}

function unguardedVerdict(name: string, call = false): GuardVerdict {
  const shown = call ? `${name}()` : name;
  return {
    action: "block",
    signed: false,
    kind: "unguarded_method",
    summary: `${shown} is not checked by the x402check guard`,
    reasons: [`${shown} could sign or send without a check, so the guarded wallet does not expose it (options.passthrough: ["${name}"] makes it reachable, unchecked)`],
    code: "unguarded_method",
    checks: [],
  };
}

function unguardedError(name: string, options: GuardOptions, call = false): X402CheckBlockedError {
  const verdict = unguardedVerdict(name, call);
  void Promise.resolve(options.onVerdict?.(verdict)).catch(() => undefined);
  return new X402CheckBlockedError(verdict);
}

async function refuseMalformed(kind: "transaction", summary: string, reason: string, options: GuardOptions): Promise<never> {
  const verdict: GuardVerdict = { action: "not_verified", signed: false, kind, summary, reasons: [reason], code: "invalid_transaction", checks: [] };
  await Promise.resolve(options.onVerdict?.(verdict)).catch(() => undefined);
  throw new X402CheckBlockedError(verdict);
}

/** Lone UTF-16 surrogates (a cut through an emoji) make the body invalid UTF-8, which the API refuses. */
function wellFormed(text: string): string {
  return text.replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, "\uFFFD");
}

/** Keeps the end (the most recent content), never splitting a character. */
export function fitTail(text: string, max: number): string {
  const clean = wellFormed(text);
  if (clean.length <= max) return clean;
  let tail = clean.slice(clean.length - (max - 1));
  if (/^[\uDC00-\uDFFF]/.test(tail)) tail = tail.slice(1);
  return `…${tail}`;
}

/** The CAIP-2 id of an AgentKit network: "eip155:<chainId>", or a known Solana cluster. */
export function caip2Of(network: Network): string | undefined {
  if (network.protocolFamily === "evm" && network.chainId && /^\d+$/.test(network.chainId)) return `eip155:${network.chainId}`;
  if (network.protocolFamily === "svm") {
    if (network.networkId === "solana-mainnet") return "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
    if (network.networkId === "solana-devnet") return "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
  }
  return undefined;
}

const INSTRUCTIONS: Record<Screening["action"], string> = {
  allow: "No check fired. You may proceed (this is not a guarantee of safety).",
  warn: "Ask the user to confirm before proceeding, and show them the reasons.",
  block: "Do not proceed with this counterparty.",
  not_verified: "The check did not complete or could not be verified. Do not proceed.",
};

/** The zod AgentKit itself loads, so the schema works with its framework extensions (LangChain, Vercel AI SDK, MCP). */
function agentkitZod(): typeof import("zod") {
  const here = createRequire(import.meta.url);
  return createRequire(here.resolve("@coinbase/agentkit"))("zod") as typeof import("zod");
}

/**
 * An AgentKit action provider with one action, `X402checkActionProvider_check_counterparty`: the
 * agent checks an address (and the site and content involved) before it pays, sends, approves or
 * signs, and gets back x402check's verified decision and what to do. Advice the model can skip:
 * enforce with `guardWalletProvider`.
 */
export class X402checkActionProvider extends ActionProvider<WalletProvider> {
  readonly #screen: ReturnType<typeof createScreener>;

  constructor(options: X402checkOptions = {}) {
    super("x402check", []);
    this.#screen = createScreener(options);
  }

  override getActions(walletProvider: WalletProvider): Action[] {
    const z = agentkitZod();
    const schema = z
      .object({
        address: z.string().min(1).max(256).describe("The counterparty that would receive value or rights: recipient, spender, operator or x402 payee (EVM 0x… or Solana base58)."),
        chain: z.string().max(64).optional().describe("Chain name (base, ethereum, solana…) or CAIP-2 id. Default: the agent wallet's network."),
        domain: z.string().max(512).optional().describe("The site or app involved, if any (hostname or URL)."),
        interaction: z.enum(INTERACTION_TYPES as unknown as [string, ...string[]]).optional().describe("What is about to happen with this counterparty."),
        context: z.string().optional().describe("The content that led you here, verbatim (a message, page or tool output). It is checked for injected instructions."),
      })
      .strict();
    return [
      {
        name: "X402checkActionProvider_check_counterparty",
        description:
          "Pre-payment risk check (x402check). Call it BEFORE sending funds, approving a spender, signing an order or permit, or paying an x402 invoice, with the address that would receive value or rights. It screens OFAC sanctions, phishing and drainer lists, drainer infrastructure, look-alike domains, and the content you acted on for injected instructions. Follow the returned instruction: allow → proceed, warn → ask the user, block or not_verified → do not proceed.",
        schema,
        invoke: async (raw: unknown) => {
          const parsed = schema.safeParse(raw);
          if (!parsed.success) return JSON.stringify({ action: "not_verified", reasons: [`invalid input: ${parsed.error.issues.map((i) => i.message).join("; ")}`], instruction: INSTRUCTIONS.not_verified });
          const args = parsed.data;
          const chain = args.chain?.trim() ? (toCaip2(args.chain.trim()) ?? args.chain.trim()) : caip2Of(walletProvider.getNetwork());
          const request: RiskCheckRequest = {
            wallet: args.address.trim(),
            ...(chain ? { chain } : {}),
            ...(args.domain ? { domain: args.domain.trim() } : {}),
            ...(args.context ? { context: fitTail(args.context, MAX_CONTEXT) } : {}),
            ...(args.interaction ? { interaction: { type: args.interaction as InteractionType } } : {}),
          };
          const screening = await this.#screen([request]);
          return JSON.stringify({
            action: screening.action,
            ...(screening.tier ? { tier: screening.tier } : {}),
            reasons: screening.reasons,
            instruction: INSTRUCTIONS[screening.action],
            ...(screening.checks[0]?.jws ? { attestation: screening.checks[0].jws } : {}),
          });
        },
      },
    ];
  }

  supportsNetwork(): boolean {
    return true;
  }
}

/** `AgentKit.from({ walletProvider, actionProviders: [x402checkActionProvider({ creditToken }), …] })`. */
export const x402checkActionProvider = (options: X402checkOptions = {}) => new X402checkActionProvider(options);
