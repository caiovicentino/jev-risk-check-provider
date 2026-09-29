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
};

export type FeedEvidence = {
  source: "metamask-phishing-detect" | "scamsniffer-domains" | "scamsniffer-addresses";
  kind: "domain" | "address";
  as_of: string;
  status: "hit" | "clear" | "unavailable" | "not_applicable";
};

/** Provider-observed facts behind a verdict (not caller claims). */
export type Evidence = {
  sanctions: SanctionsEvidence;
  domain?: DomainEvidence;
  onchain: OnchainEvidenceOut;
  feeds?: FeedEvidence[];
  model: string;
};

export type RiskCheckResult = {
  checked: boolean;
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
    networks?: string[];
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
