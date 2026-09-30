export type RiskTier = "low" | "medium" | "high" | "critical";

export type RiskCheckExtensionInfo = {
  required: boolean;
  risk_check_url?: string;
  min_score?: number;
  categories?: string[];
};

export type RiskCheckClientInfo = RiskCheckExtensionInfo & {
  payer_wallet?: string;
  payer_domain?: string;
};

export type SanctionsEvidence = {
  list: "ofac-sdn";
  as_of: string;
  status: "listed" | "not_listed";
  entity?: string;
  ticker?: string;
  match?: "exact" | "same_key";
  listed_address?: string;
};

export type DomainEvidence = {
  host: string;
  registrable: string;
  official: boolean;
  impersonation: "none" | "weak" | "strong";
  brand?: string;
  signals: string[];
};

export type OnchainEvidenceOut = {
  status: "ok" | "unavailable" | "unsupported";
  network?: string;
  is_contract?: boolean;
  activity?: "none" | "some";
  tx_count?: number;
  /** Source-code verification status of a contract subject, when known. */
  verified?: boolean;
  /** Code classification; `fingerprint` (logic code only) is what drainer-kit matching compares. */
  code?: import("./code-fingerprint.js").CodeFacts;
};

export type { SimulationEvidence, AssetMovement, ApprovalGrant, TransactionInput } from "./simulation.js";

export type FeedEvidence = {
  source: "metamask-phishing-detect" | "scamsniffer-domains" | "scamsniffer-addresses" | "forta-phishing-code" | "scamsniffer-code" | "x402check-kit-watch";
  kind: "domain" | "address" | "code";
  as_of: string;
  status: "hit" | "clear" | "unavailable" | "not_applicable";
};

/** The provider's own drainer-infrastructure watch (src/kit-watch.ts): what it knows about these addresses. */
export type KitWatchEvidence = {
  /** When the watch last scanned. */
  as_of: string;
  status: "hit" | "clear" | "unavailable";
  hits?: import("./kit-watch.js").KitWatchHit[];
};

/** Provider-observed facts behind a verdict (not caller claims). */
export type Evidence = {
  sanctions: SanctionsEvidence;
  domain?: DomainEvidence;
  onchain: OnchainEvidenceOut;
  feeds?: FeedEvidence[];
  simulation?: import("./simulation.js").SimulationEvidence;
  kit_watch?: KitWatchEvidence;
  model: string;
  /** The model revision that answered, as the backend reported it. */
  model_id?: string;
};

export type RiskCheckResult = {
  checked: boolean;
  /** Why `checked` is false: invalid_subject | model_unconfigured | model_malformed_answers | model_unavailable. */
  reason?: string;
  score?: number;
  tier?: RiskTier;
  provider?: string;
  categories?: string[];
  jws?: string;
  jwks_url?: string;
  checked_at?: string;
  expires_at?: string;
  evidence?: Evidence;
};

export type RiskCheckDiscovery = {
  name: string;
  version: string;
  description?: string;
  endpoint: string;
  batch_endpoint?: string;
  method: "POST" | "GET";
  pricing?: {
    amount: string;
    currency: string;
    protocol: string;
    network: string;
    unit?: string;
    /** Price of an evaluation whose request includes a transaction that is simulated. */
    amount_with_transaction?: string;
    networks?: string[];
    /** Price per evaluation by payment network (CAIP-2 → USD). */
    amounts_by_network?: Record<string, string>;
    /** Prepaid credits: one x402 payment buys a balance; checks debit it (Authorization: Bearer). */
    credits?: { check_usd: string; simulated_check_usd: string; pack_min_usd: string; pack_max_usd: string; endpoint: string };
  };
  signals?: string[];
  chains_supported?: string[];
  response_time_ms?: string;
  attestation?: {
    jwks_url: string;
    algorithm: string;
    kid: string;
    ttl: string;
    issuer?: string;
    claims?: string[];
  };
  data_sources?: Record<string, string>;
};

export type RiskCheckRequest = {
  wallet: string;
  chain?: string | undefined;
  domain?: string | undefined;
  context?: string | undefined;
  aud?: string | undefined;
  screening?: { sanctions: "clean" | "flagged" | "unknown" } | undefined;
  authorization?: { pre_authorized: boolean; source?: string | undefined } | undefined;
  /** Binds the attestation to a concrete payment (all fields optional). */
  payment?: PaymentBinding | undefined;
  /** What the user/agent is about to do with the subject (wallet integrations). */
  interaction?: Interaction | undefined;
  /** An EVM transaction to simulate (requires an eip155 `chain`). */
  transaction?: { from: string; to?: string | undefined; value?: string | undefined; data?: string | undefined } | undefined;
  /** Set by validateRequest: requestHash() of the fields as received. Never read from the body. */
  request_hash?: string | undefined;
};

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
export type Interaction = { type: InteractionType; unlimited?: boolean | undefined };
/** Interactions that grant the subject control over the user's assets. */
export const GRANTING_INTERACTIONS: ReadonlySet<InteractionType> = new Set(["token_approval", "nft_approval", "permit_signature"]);

export type PaymentBinding = {
  network?: string | undefined;
  pay_to?: string | undefined;
  amount?: string | undefined;
  asset?: string | undefined;
  resource?: string | undefined;
};

export type RiskCheckBatchRequest = {
  requests: RiskCheckRequest[];
};

export type NoulAnswer = {
  type: "noul";
  noul: number;
};

export type ChoiceAnswer = {
  type: "choice";
  choice: string;
  probabilities: Record<string, number>;
  confidence: number;
  noCalibration?: boolean | undefined;
};

export type ScoreAnswer = {
  type: "score";
  score: number;
  legend: Record<string, string>;
  probabilities: Record<string, number>;
  confidence: number;
  noCalibration?: boolean | undefined;
};

export type Answer = NoulAnswer | ChoiceAnswer | ScoreAnswer;

export type SystemOneResponse = {
  model: string;
  answers: Record<string, Answer>;
  usage: {
    input_tokens: number;
    output_tokens: number;
  };
};

export type ScoringInputs = {
  knownThreat: number;
  sanctionsConcern: number;
  launderingPattern: number;
  riskyDomain: number;
  guardBypassAttempt: number;
  riskClass: string;
  riskClassProbability: number;
  trust: number;
  trustConfidence: number;
  trustCalibrated: boolean;
};

export type ScoreBreakdown = {
  score: number;
  tier: RiskTier;
  cappedByLowConfidence: boolean;
  signals: ScoringInputs;
};
