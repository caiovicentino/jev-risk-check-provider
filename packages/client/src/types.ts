/**
 * Wire types for the x402check risk-check API (v0.3 contract; compatible with v0.2 responses,
 * which simply omit the v0.3 fields such as `evidence.simulation`).
 */

export type RiskTier = "low" | "medium" | "high" | "critical";

export const RISK_TIERS: readonly RiskTier[] = ["low", "medium", "high", "critical"];

export const INTERACTION_TYPES = [
  "native_transfer",
  "token_transfer",
  "token_approval",
  "nft_approval",
  "permit_signature",
  "order_signature",
  "message_signature",
  "contract_call",
] as const;

export type InteractionType = (typeof INTERACTION_TYPES)[number];

/** What the user or agent is about to do with the subject. */
export interface Interaction {
  type: InteractionType;
  /** Unlimited allowance / operator-for-all. */
  unlimited?: boolean | undefined;
}

/** Binds the attestation to a concrete payment. All fields optional. */
export interface PaymentBinding {
  /** Chain alias or CAIP-2. Must agree with `chain` when both are given. */
  network?: string | undefined;
  /** Payee address. */
  pay_to?: string | undefined;
  /** Decimal amount in base units (e.g. "1000000" for 1 USDC). */
  amount?: string | undefined;
  /** "native", a token address, or a short symbol. */
  asset?: string | undefined;
  /** http(s) URL of the paid resource. */
  resource?: string | undefined;
}

/**
 * An EVM transaction for the provider to simulate (v0.3, `eth_simulateV1`).
 * Requires an EVM `chain` on the request.
 */
export interface TransactionInput {
  /** Sender (EVM address). */
  from: string;
  /** Callee or recipient (EVM address); omit for contract creation. */
  to?: string | undefined;
  /** Value in wei: decimal string or 0x-hex. */
  value?: string | undefined;
  /** Calldata, 0x-hex. */
  data?: string | undefined;
}

export interface RiskCheckRequest {
  /**
   * The subject address: the real counterparty (recipient, spender, operator, pay_to).
   * EVM `0x…`, base58 (Solana/Tron/BTC legacy), bech32, cashaddr, or CAIP-10 `ns:ref:address`.
   */
  wallet: string;
  /** Chain alias (`ethereum`, `base`, `solana`, …) or CAIP-2 (`eip155:8453`). */
  chain?: string | undefined;
  /** Hostname or http(s) URL of the site the payment or signature is for. */
  domain?: string | undefined;
  /** ≤ 4096 chars: what the agent acted on (instruction, page text, tool output). Untrusted by design. */
  context?: string | undefined;
  /** ≤ 256 chars: audience copied into the attestation (e.g. the resource server that will verify it). */
  aud?: string | undefined;
  interaction?: Interaction | undefined;
  payment?: PaymentBinding | undefined;
  /** v0.3: transaction to simulate (EVM only). */
  transaction?: TransactionInput | undefined;
  /** Caller assertion. Recorded as `asserted` in the attestation; can never lower risk. */
  screening?: { sanctions: "clean" | "flagged" | "unknown" } | undefined;
  /** Caller assertion. Recorded as `asserted` in the attestation; can never lower risk. */
  authorization?: { pre_authorized: boolean; source?: string | undefined } | undefined;
}

/** Categories the provider emits today. New ones may appear: treat unknown categories as informational. */
export type KnownCategory =
  | "intent_risk"
  | "behavioral"
  | "compliance_risk"
  | "sanctioned_address"
  | "impersonation"
  | "phishing_domain"
  | "community_flagged_domain"
  | "known_scam_address"
  | "approval_to_eoa"
  | "new_address"
  | "guard_bypass"
  | "laundering_pattern"
  | "known_threat"
  | "automated_abuse"
  | "fraud_signal"
  // v0.3 (transaction simulation and contract verification)
  | "outflow_to_undisclosed_eoa"
  | "outflow_exceeds_declared"
  | "outflow_to_unverified_contract"
  | "unlimited_approval"
  | "simulation_reverted"
  | "simulation_incomplete"
  | "unverified_contract"
  | "known_drainer_code"
  // v0.4 (kit watch: the provider's own record of drainer infrastructure)
  | "address_poisoning"
  | "compromised_wallet"
  | "auto_forwarding_wallet"
  | "drainer_operator"
  // Fail-closed review floors: a check that should have run failed transiently.
  | "onchain_unavailable"
  | "simulation_unavailable";

// `string & {}` keeps editor completion for the known names while accepting new ones.
export type Category = KnownCategory | (string & {});

export interface SanctionsEvidence {
  list: "ofac-sdn";
  as_of: string;
  /** "sha256:<hex>" of the source artifact, OFAC's SDN.XML (since provider 0.6.1). */
  digest?: string;
  status: "listed" | "not_listed";
  entity?: string;
  ticker?: string;
  match?: "exact" | "same_key";
  listed_address?: string;
}

export interface DomainEvidence {
  host: string;
  registrable: string;
  official: boolean;
  impersonation: "none" | "weak" | "strong";
  brand?: string;
  signals: string[];
}

/** v0.3: classification of the subject's runtime code. */
export interface CodeFacts {
  /** "delegated" = an EIP-7702 EOA whose code points at `delegate`. */
  kind: "none" | "delegated" | "tiny" | "delegating" | "token" | "nft" | "logic";
  bytes: number;
  /** sha256 of the logic code without compiler metadata (what drainer-kit matching compares). */
  fingerprint?: string;
  delegate?: string;
}

export interface OnchainEvidence {
  status: "ok" | "unavailable" | "unsupported";
  network?: string;
  is_contract?: boolean;
  activity?: "none" | "some";
  tx_count?: number;
  /** v0.3: set when the contract's source-verification status is known. */
  verified?: boolean;
  /** v0.3: code classification. */
  code?: CodeFacts;
}

export interface FeedEvidence {
  /** e.g. "metamask-phishing-detect", "scamsniffer-domains", "scamsniffer-addresses", "forta-phishing-code", "scamsniffer-code". */
  source: string;
  kind: "domain" | "address" | "code";
  as_of: string;
  status: "hit" | "clear" | "unavailable" | "not_applicable";
}

/** A simulated asset movement. Amounts are decimal strings in base units. */
export interface AssetMovement {
  standard: "native" | "erc20" | "erc721" | "erc1155";
  /** "native" or the token contract address. */
  asset: string;
  amount?: string;
  token_id?: string;
  /**
   * Outflows: the FINAL beneficiary (assets routed through the called contract are attributed
   * to where they end up). Inflows: the called contract.
   */
  counterparty: string;
  counterparty_is_contract?: boolean;
}

/** An approval the simulated transaction would grant. */
export interface ApprovalGrant {
  /** "erc721" is a single-token approval: `amount` then carries the token id. */
  standard: "erc20" | "erc721" | "erc721-all" | "permit2";
  asset: string;
  spender: string;
  amount?: string;
  unlimited?: boolean;
  spender_is_contract?: boolean;
}

/** v0.3: a contract in the transaction whose logic code matches a listed drainer's. */
export interface CodeMatch {
  address: string;
  role: "called" | "recipient" | "spender";
  /** The code feeds listing the fingerprint. */
  sources: string[];
}

/** v0.3: what the provider observed when simulating `transaction`. */
export interface SimulationEvidence {
  status: "ok" | "reverted" | "unavailable" | "unsupported";
  network?: string;
  outflows?: AssetMovement[];
  inflows?: AssetMovement[];
  approvals?: ApprovalGrant[];
  /**
   * e.g. "outflow_to_undisclosed_eoa", "outflow_exceeds_declared", "approval_to_eoa", "unlimited_approval",
   * "simulation_reverted", "simulation_incomplete", "known_drainer_code".
   */
  findings?: string[];
  code_matches?: CodeMatch[];
  /** Whether any contract in scope had fingerprintable logic code. */
  code_checked?: boolean;
  /**
   * Source verification of the called contract when it forwarded assets to an undisclosed wallet.
   * true (a verified forwarder such as a bridge or batch sender) turns that finding into review.
   */
  forwarder_verified?: boolean;
  /** Why the simulation is incomplete (finding `simulation_incomplete`): "unclassified", "logs_truncated", "flows_truncated". */
  limits?: string[];
  /** The block whose state the transaction was simulated on (since provider 0.6.1). */
  at_block?: number;
}

/** v0.4: what the kit watch knows about an address in the request. */
export interface KitWatchHit {
  address: string;
  role: "subject" | "called" | "recipient" | "spender";
  /**
   * poisoner_delegation: a look-alike delegated (EIP-7702) to an address-poisoning executor;
   * sweeper_delegation: a wallet delegated to a labelled sweeper (its key is compromised);
   * forwarding_delegation: a wallet whose delegate forwards what it receives (no label);
   * sweeper_destination: where a sweeper or forwarder sends what it receives;
   * drainer_kit_contract / drainer_kit_deployer: a contract in a drainer-kit family, and who deployed one.
   */
  kind: "poisoner_delegation" | "sweeper_delegation" | "forwarding_delegation" | "sweeper_destination" | "drainer_kit_contract" | "drainer_kit_deployer";
  family: string;
  /** Where the entry was observed (watchlist entries only). */
  chain?: string;
  first_seen?: string;
  /** watchlist: observed by the provider's scan; code: the address runs a family's code now. */
  via: "watchlist" | "code";
}

/** v0.4: the provider's own drainer-infrastructure watch (EIP-7702 poisoners and sweepers, drainer kits). */
export interface KitWatchEvidence {
  /** When the watch last scanned. */
  as_of: string;
  status: "hit" | "clear" | "unavailable";
  /** The coverage clock: per chain (CAIP-2), the last block the scan read (since provider 0.6.1). */
  complete_through?: Record<string, number>;
  /** Per chain, every hole recorded (ranges skipped after outages; since 0.6.2 also reads abandoned after a day), only when any (since provider 0.6.1). */
  gaps?: Record<string, number>;
  /** Per chain, code reads from scanned blocks still queued for retry, only when any (since provider 0.6.2). */
  pending?: Record<string, number>;
  /** Per chain, the first block of the current unbroken coverage: no hole lies in [`unbroken_since`, `complete_through`]; queued reads (`pending`) may (since provider 0.6.4). Since 0.6.4 `gaps` also counts the reads dropped before 0.6.2. */
  unbroken_since?: Record<string, number>;
  hits?: KitWatchHit[];
}

/** Provider-observed facts behind a verdict (never caller claims). */
export interface Evidence {
  sanctions: SanctionsEvidence;
  domain?: DomainEvidence;
  onchain: OnchainEvidence;
  feeds?: FeedEvidence[];
  simulation?: SimulationEvidence;
  kit_watch?: KitWatchEvidence;
  model: string;
  /** The model revision that answered, as the backend reported it (since provider 0.6.0). */
  model_id?: string;
}

/** Why a check could not be completed (`checked: false`). New codes may appear. */
export type CheckFailureReason = "invalid_subject" | "model_unconfigured" | "model_malformed_answers" | "model_unavailable" | (string & {});

export interface RiskCheckResult {
  /** false = the provider could not complete the check. Never an all-clear. */
  checked: boolean;
  /** With `checked: false`: why. */
  reason?: CheckFailureReason;
  /** 0–100, higher is safer. */
  score?: number;
  tier?: RiskTier;
  /** Issuer DID, e.g. "did:web:x402check.xyz". */
  provider?: string;
  categories?: Category[];
  /** Compact JWS attestation (ES256). Verify it with `verifyAttestation`. */
  jws?: string;
  /** Informational only: never use it to pick a verification key. */
  jwks_url?: string;
  checked_at?: string;
  expires_at?: string;
  evidence?: Evidence;
}

export interface RiskCheckBatchResponse {
  results: RiskCheckResult[];
}

// ---------------------------------------------------------------------------
// Attestation (JWS) claims
// ---------------------------------------------------------------------------

export interface AttestationChecks {
  /** `digest`: "sha256:<hex>" of OFAC's SDN.XML the screen ran against (since provider 0.6.1). */
  sanctions: { list: string; as_of: string; digest?: string; status: string };
  domain?: { host: string; impersonation: string };
  onchain: { status: string; network?: string; activity?: string };
  /** Threat feeds consulted, as "source@as_of:status". */
  feeds?: string[];
  /** v0.3; `at_block`: the block whose state was simulated (since provider 0.6.1). */
  simulation?: { status: string; network?: string; findings?: string[]; at_block?: number };
  /** The kit watch, when consulted: scan clock, status and coverage clock (since provider 0.6.1; `pending` since 0.6.2; `unbroken_since` since 0.6.4). */
  kit_watch?: { as_of: string; status: string; complete_through?: Record<string, number>; gaps?: Record<string, number>; pending?: Record<string, number>; unbroken_since?: Record<string, number> };
  /** Question set, or "skipped" (e.g. deterministic sanctions verdict). */
  model: string;
  /** The model revision that answered, signed (since provider 0.6.0). */
  model_id?: string;
}

export interface AttestationClaims {
  iss: string;
  sub: string;
  score: number;
  tier: RiskTier;
  iat: number;
  exp: number;
  jti?: string;
  aud?: string | string[];
  nbf?: number;
  categories?: Category[];
  input_hash?: string;
  /** What the provider itself verified for this verdict. */
  checks?: AttestationChecks;
  /** SHA-256 of the RFC 8785 canonical request fields exactly as sent (v0.3); see `requestHash`. */
  request_hash?: string;
  /** Self-reported by the caller; NOT verified by the provider. */
  asserted?: { screening?: string; pre_authorized?: boolean };
  /** The concrete payment this verdict was issued for, when the caller bound one. */
  payment?: Record<string, string>;
  /** Interaction type the verdict was issued for. */
  interaction?: string;
  [claim: string]: unknown;
}

export interface JwsHeader {
  alg?: string;
  typ?: string;
  kid?: string;
  [param: string]: unknown;
}

// ---------------------------------------------------------------------------
// x402 payment challenge (decoded PAYMENT-REQUIRED header, x402 v2)
// ---------------------------------------------------------------------------

export interface PaymentRequirements {
  scheme: string;
  /** CAIP-2 network, e.g. "eip155:8453". */
  network: string;
  /** Token address (e.g. USDC). */
  asset: string;
  /** Amount in the asset's base units (USDC: 6 decimals). */
  amount: string;
  payTo: string;
  maxTimeoutSeconds?: number;
  extra?: Record<string, unknown>;
  [field: string]: unknown;
}

export interface PaymentRequired {
  x402Version: number;
  error?: string;
  resource?: { url: string; description?: string; mimeType?: string; [field: string]: unknown };
  accepts: PaymentRequirements[];
  extensions?: Record<string, unknown>;
  [field: string]: unknown;
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/** The subset of a fetch Response the client reads. */
export interface FetchResponseLike {
  readonly status: number;
  readonly headers: { get(name: string): string | null };
  text(): Promise<string>;
}

export interface FetchInitLike {
  method: string;
  headers: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
  /** "manual" when a redirect must not be followed (e.g. before paying a resource); an implementation must honor it. */
  redirect?: "follow" | "manual" | "error";
}

/**
 * Any fetch-compatible function: `globalThis.fetch`, undici, a Worker's fetch, or an
 * x402-paying wrapper such as `wrapFetchWithPayment(fetch, x402Client)` from `@x402/fetch`.
 */
export type FetchLike = (url: string, init: FetchInitLike) => Promise<FetchResponseLike>;
