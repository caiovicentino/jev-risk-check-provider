// Vendored from snap/src/simulation.ts by scripts/sync-decoders.mjs. Edit the Snap source and re-sync.
/**
 * Transaction simulation (provider v0.3).
 *
 * - `planSimulation` builds the `transaction` object sent with a risk check,
 *   or explains why the transaction is not simulated. It only ever produces
 *   objects the provider accepts (a malformed one would fail the whole check).
 * - `parseSimulation` validates `evidence.simulation` from the response.
 * - The *Text helpers turn simulated effects into plain language.
 *
 * Pure: no Snap globals, no network.
 */
import type { SimulationTransaction } from "./util.js";
import { formatUnits, isRecord, knownToken, nativeSymbol } from "./util.js";

/** Largest `data` string (including "0x") the provider accepts: 48 KiB of hex characters. */
export const MAX_SIMULATION_DATA_CHARS = 48 * 1024;

export type SimulationPlan = { transaction: SimulationTransaction } | { skipped: string; warning?: string };

export type SimulationParts = {
  /** CAIP-2 chain id ("eip155:<id>") or undefined. */
  chain?: string | undefined;
  /** Lowercase sender address, undefined when missing/invalid. */
  from?: string | undefined;
  /** Lowercase recipient address, undefined for deployments. */
  to?: string | undefined;
  /** Parsed value; undefined when the raw value could not be parsed. */
  value?: bigint | undefined;
  /** Normalized calldata hex without 0x ("" when none), null when invalid. */
  data: string | null;
};

/**
 * Decides what to send for simulation.
 *
 * @param parts - Normalized transaction parts.
 * @returns The transaction to send, or why it is not simulated.
 */
export function planSimulation(parts: SimulationParts): SimulationPlan {
  if (!parts.chain?.startsWith("eip155:")) {
    return { skipped: "simulation is only available for transactions on EVM (eip155) networks" };
  }
  if (!parts.to) return { skipped: "contract deployments are not simulated" };
  if (!parts.from) {
    const reason = "the sender address is missing or invalid, so the transaction could not be simulated";
    return { skipped: reason, warning: reason };
  }
  if (parts.value === undefined) {
    const reason = "the transaction value could not be parsed, so the transaction could not be simulated";
    return { skipped: reason, warning: reason };
  }
  if (parts.data === null) {
    const reason = "the calldata is not valid hex, so the transaction could not be simulated";
    return { skipped: reason, warning: reason };
  }
  const data = parts.data === "" ? undefined : `0x${parts.data}`;
  if (data && data.length > MAX_SIMULATION_DATA_CHARS) {
    const reason = `the transaction is too large to simulate (${parts.data.length / 2} bytes of calldata; the limit is ${
      (MAX_SIMULATION_DATA_CHARS - 2) / 2
    } bytes), so its effects were NOT simulated`;
    return { skipped: reason, warning: reason };
  }
  return {
    transaction: {
      from: parts.from,
      to: parts.to,
      value: `0x${parts.value.toString(16)}`,
      ...(data ? { data } : {}),
    },
  };
}

// ---------------------------------------------------------------------------
// Response evidence
// ---------------------------------------------------------------------------

export type AssetMovement = {
  standard: "native" | "erc20" | "erc721" | "erc1155";
  /** "native" or the token contract. */
  asset: string;
  /** Raw integer in base units. */
  amount?: string | undefined;
  token_id?: string | undefined;
  /** Final beneficiary (outflows) or the called contract (inflows); may be "". */
  counterparty: string;
  counterparty_is_contract?: boolean | undefined;
};

export type ApprovalGrant = {
  standard: "erc20" | "erc721" | "erc721-all" | "permit2";
  asset: string;
  spender: string;
  amount?: string | undefined;
  unlimited?: boolean | undefined;
  spender_is_contract?: boolean | undefined;
};

/** A contract in the transaction whose logic code matches a listed drainer's. */
export type CodeMatch = {
  address: string;
  role: "called" | "recipient" | "spender";
  /** Feeds listing the code, e.g. "forta-phishing-code", "scamsniffer-code". */
  sources: string[];
};

export type SimulationEvidence = {
  status: "ok" | "reverted" | "unavailable" | "unsupported";
  network?: string | undefined;
  outflows: AssetMovement[];
  inflows: AssetMovement[];
  approvals: ApprovalGrant[];
  findings: string[];
  code_matches: CodeMatch[];
  /** A source-verified contract (bridge, batch sender) forwarded the assets. */
  forwarder_verified?: boolean | undefined;
  /** Why the result is incomplete ("unclassified", "logs_truncated", "flows_truncated"). */
  limits: string[];
  /** Entries dropped because they were malformed. */
  dropped: number;
};

const MAX_LIST = 20;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/u;
const DIGITS_RE = /^\d{1,78}$/u;

function address(value: unknown): string | undefined {
  return typeof value === "string" && value.length === 42 && ADDRESS_RE.test(value) ? value.toLowerCase() : undefined;
}

function digits(value: unknown): string | undefined {
  return typeof value === "string" && value.length <= 78 && DIGITS_RE.test(value) ? value : undefined;
}

function parseMovement(value: unknown): AssetMovement | undefined {
  if (!isRecord(value)) return undefined;
  const { standard } = value;
  if (standard !== "native" && standard !== "erc20" && standard !== "erc721" && standard !== "erc1155") return undefined;
  const asset = standard === "native" ? "native" : address(value.asset);
  if (!asset) return undefined;
  // Inflows name the called contract, which is "" for deployments.
  const counterparty = value.counterparty === "" ? "" : address(value.counterparty);
  if (counterparty === undefined) return undefined;
  const amount = digits(value.amount);
  const tokenId = digits(value.token_id);
  return {
    standard,
    asset,
    ...(amount !== undefined ? { amount } : {}),
    ...(tokenId !== undefined ? { token_id: tokenId } : {}),
    counterparty,
    ...(typeof value.counterparty_is_contract === "boolean" ? { counterparty_is_contract: value.counterparty_is_contract } : {}),
  };
}

function parseApproval(value: unknown): ApprovalGrant | undefined {
  if (!isRecord(value)) return undefined;
  const { standard } = value;
  if (standard !== "erc20" && standard !== "erc721" && standard !== "erc721-all" && standard !== "permit2") return undefined;
  const asset = address(value.asset);
  const spender = address(value.spender);
  if (!asset || !spender) return undefined;
  const amount = digits(value.amount);
  return {
    standard,
    asset,
    spender,
    ...(amount !== undefined ? { amount } : {}),
    ...(value.unlimited === true || standard === "erc721-all" ? { unlimited: true } : {}),
    ...(typeof value.spender_is_contract === "boolean" ? { spender_is_contract: value.spender_is_contract } : {}),
  };
}

function parseCodeMatch(value: unknown): CodeMatch | undefined {
  if (!isRecord(value)) return undefined;
  const matched = address(value.address);
  const { role } = value;
  if (!matched || (role !== "called" && role !== "recipient" && role !== "spender")) return undefined;
  const sources = Array.isArray(value.sources)
    ? [...new Set(value.sources.slice(0, 8).filter((source): source is string => typeof source === "string" && /^[a-z0-9-]{1,48}$/u.test(source)))]
    : [];
  return { address: matched, role, sources };
}

function parseList<T>(value: unknown, parse: (item: unknown) => T | undefined, counter: { dropped: number }): T[] {
  if (!Array.isArray(value)) return [];
  const out: T[] = [];
  for (const item of value.slice(0, MAX_LIST)) {
    const parsed = parse(item);
    if (parsed === undefined) counter.dropped += 1;
    else out.push(parsed);
  }
  counter.dropped += Math.max(0, value.length - MAX_LIST);
  return out;
}

/**
 * Validates `evidence.simulation`. Undefined when absent or unusable, which
 * the UI reports as "NOT simulated".
 *
 * @param value - The raw evidence value.
 * @returns The validated simulation evidence.
 */
export function parseSimulation(value: unknown): SimulationEvidence | undefined {
  if (!isRecord(value)) return undefined;
  const { status } = value;
  if (status !== "ok" && status !== "reverted" && status !== "unavailable" && status !== "unsupported") return undefined;
  const counter = { dropped: 0 };
  const network = typeof value.network === "string" && /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/u.test(value.network) ? value.network : undefined;
  const findings = Array.isArray(value.findings)
    ? [
        ...new Set(
          value.findings
            .slice(0, 16)
            .filter((finding): finding is string => typeof finding === "string" && /^[a-z0-9_]{1,48}$/u.test(finding)),
        ),
      ]
    : [];
  return {
    status,
    ...(network ? { network } : {}),
    outflows: parseList(value.outflows, parseMovement, counter),
    inflows: parseList(value.inflows, parseMovement, counter),
    approvals: parseList(value.approvals, parseApproval, counter),
    findings,
    code_matches: parseList(value.code_matches, parseCodeMatch, counter),
    ...(typeof value.forwarder_verified === "boolean" ? { forwarder_verified: value.forwarder_verified } : {}),
    limits: Array.isArray(value.limits)
      ? [...new Set(value.limits.slice(0, 8).filter((limit): limit is string => typeof limit === "string" && /^[a-z0-9_]{1,32}$/u.test(limit)))]
      : [],
    dropped: counter.dropped,
  };
}

// ---------------------------------------------------------------------------
// Plain-language rendering helpers
// ---------------------------------------------------------------------------

/** 0x1234ab…cdef12: enough characters to compare an address by eye. */
export function midAddress(value: string): string {
  return value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
}

function tokenText(chain: string | undefined, token: string, amount: string | undefined): string {
  const info = knownToken(chain, token);
  if (amount === undefined) return `an unknown amount of ${info ? info.symbol : `token ${midAddress(token)}`}`;
  if (info) return `${formatUnits(BigInt(amount), info.decimals)} ${info.symbol}`;
  return `${amount} raw units of token ${midAddress(token)}`;
}

/**
 * "1.5 ETH", "5 USDC", "123 raw units of token 0x…", "NFT #7 of 0x…".
 *
 * @param movement - The movement.
 * @param chain - CAIP-2 chain id (native symbol, known tokens).
 * @returns The description.
 */
export function movementText(movement: AssetMovement, chain: string | undefined): string {
  switch (movement.standard) {
    case "native":
      return movement.amount === undefined
        ? `an unknown amount of ${nativeSymbol(chain)}`
        : `${formatUnits(BigInt(movement.amount), 18)} ${nativeSymbol(chain)}`;
    case "erc20":
      return tokenText(chain, movement.asset, movement.amount);
    case "erc721":
      return `NFT #${movement.token_id ?? "?"} of ${midAddress(movement.asset)}`;
    case "erc1155":
    default:
      return `${movement.amount ?? "an unknown amount"} × item #${movement.token_id ?? "?"} of ${midAddress(movement.asset)}`;
  }
}

/**
 * "UNLIMITED USDC", "5 USDC", "NFT #7 of 0x…", "ALL NFTs of collection 0x…".
 *
 * @param approval - The approval.
 * @param chain - CAIP-2 chain id.
 * @returns The description.
 */
export function approvalText(approval: ApprovalGrant, chain: string | undefined): string {
  const info = knownToken(chain, approval.asset);
  const name = info ? info.symbol : `token ${midAddress(approval.asset)}`;
  switch (approval.standard) {
    case "erc721":
      return `NFT #${approval.amount ?? "?"} of ${midAddress(approval.asset)}`;
    case "erc721-all":
      return `ALL NFTs of collection ${midAddress(approval.asset)}`;
    case "permit2":
      return `${approval.unlimited ? `UNLIMITED ${name}` : tokenText(chain, approval.asset, approval.amount)} via Permit2`;
    case "erc20":
    default:
      return approval.unlimited ? `UNLIMITED ${name}` : tokenText(chain, approval.asset, approval.amount);
  }
}

/** " (contract)", " (wallet)" or "" when unknown. */
export function accountKind(isContract: boolean | undefined): string {
  if (isContract === true) return " (contract)";
  if (isContract === false) return " (wallet)";
  return "";
}

export type FindingInfo = { strong: boolean; text: string };

const FINDINGS = new Map<string, FindingInfo>([
  [
    "outflow_to_undisclosed_eoa",
    {
      strong: true,
      text: "Your assets end up in a regular wallet (EOA) that this request never mentioned, and nothing comes back. This is how wallet drainers work.",
    },
  ],
  [
    "approval_to_eoa",
    {
      strong: true,
      text: "This transaction grants a spending approval to a regular wallet (EOA), not a contract. Legitimate apps approve contracts; drainers use wallets.",
    },
  ],
  [
    "outflow_to_unverified_contract",
    { strong: false, text: "Your assets go into a contract whose source code is not verified, and nothing comes back." },
  ],
  [
    "unlimited_approval",
    { strong: false, text: "This transaction grants an UNLIMITED spending approval: the spender could take all of that token, now or later." },
  ],
  [
    "outflow_exceeds_declared",
    {
      strong: true,
      text: "The recipient you are paying receives a different asset or a larger amount than this transaction shows.",
    },
  ],
  [
    "known_drainer_code",
    { strong: true, text: "A contract in this transaction runs the same code as contracts listed as wallet drainers." },
  ],
  [
    "simulation_incomplete",
    { strong: false, text: "The simulation could not check every recipient; treat this transaction as not fully verified." },
  ],
  ["simulation_reverted", { strong: false, text: "This transaction would revert (fail) if sent as is." }],
]);

const CODE_SOURCES = new Map<string, string>([
  ["forta-phishing-code", "Forta"],
  ["scamsniffer-code", "ScamSniffer"],
]);

/**
 * Plain-language line for a known-drainer-code match, by the contract's role.
 *
 * @param match - The code match.
 * @returns The description.
 */
export function codeMatchText(match: CodeMatch): string {
  const where = midAddress(match.address);
  const listedBy = match.sources.map((source) => CODE_SOURCES.get(source) ?? source);
  const suffix = listedBy.length > 0 ? ` (listed by ${listedBy.join(" and ")})` : "";
  switch (match.role) {
    case "recipient":
      return `Assets go to a contract (${where}) that runs the same code as listed wallet drainers${suffix}.`;
    case "spender":
      return `The approval goes to a contract (${where}) that runs the same code as listed wallet drainers${suffix}.`;
    case "called":
    default:
      return `The contract you are calling (${where}) runs the same code as contracts listed as wallet drainers${suffix}.`;
  }
}

/**
 * Plain-language text for a simulation finding.
 *
 * @param finding - The finding id.
 * @returns Whether it is one of the strongest findings, and its text.
 */
export function findingInfo(finding: string): FindingInfo {
  const known = FINDINGS.get(finding);
  if (known) return known;
  const words = finding.replace(/_+/gu, " ").trim();
  return { strong: false, text: `Simulation finding: ${words.charAt(0).toUpperCase()}${words.slice(1)}.` };
}

/** Assets forwarded by a source-verified contract (the provider caps at review). */
export const FORWARDER_TEXT =
  "Assets are forwarded by a verified contract to a wallet you did not name (common for bridges and batch payments) — confirm the recipient.";

const LIMIT_TEXT = new Map<string, string>([
  ["unclassified", "some recipients or spenders could not be classified"],
  ["logs_truncated", "the transaction emits more events than could be inspected"],
  ["flows_truncated", "the transaction moves assets more times than could be inspected"],
]);

export type FindingLine = { strong: boolean; text: string };

/**
 * Plain-language lines for a simulation's findings. Strong lines are
 * drainer-like (critical banner); the others are cautions. Never an all-clear.
 *
 * @param simulation - The simulation evidence.
 * @returns The lines, in finding order.
 */
export function simulationFindingLines(simulation: SimulationEvidence): FindingLine[] {
  const lines: FindingLine[] = [];
  for (const finding of simulation.findings) {
    // The section already says a reverted transaction would fail.
    if (finding === "simulation_reverted" && simulation.status === "reverted") continue;
    if (finding === "known_drainer_code" && simulation.code_matches.length > 0) {
      lines.push(...simulation.code_matches.slice(0, 3).map((match) => ({ strong: true, text: codeMatchText(match) })));
    } else if (finding === "outflow_to_undisclosed_eoa" && simulation.forwarder_verified === true) {
      lines.push({ strong: false, text: FORWARDER_TEXT });
    } else if (finding === "simulation_incomplete") {
      const why = simulation.limits.map((limit) => LIMIT_TEXT.get(limit) ?? limit.replace(/_+/gu, " "));
      const base = findingInfo(finding).text;
      lines.push({ strong: false, text: why.length > 0 ? `${base} (${why.join("; ")})` : base });
    } else {
      lines.push(findingInfo(finding));
    }
  }
  return lines;
}

/**
 * Whether the simulation result is incomplete (never read as clear).
 *
 * @param simulation - The simulation evidence.
 * @returns True when the provider flagged it incomplete.
 */
export function isIncomplete(simulation: SimulationEvidence | undefined): boolean {
  return simulation?.findings.includes("simulation_incomplete") ?? false;
}
