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
  };
  signals?: string[];
  chains_supported?: string[];
  response_time_ms?: string;
  attestation?: {
    jwks_url: string;
    algorithm: string;
    kid: string;
    ttl: string;
  };
};

export type RiskCheckRequest = {
  wallet: string;
  chain?: string | undefined;
  domain?: string | undefined;
  context?: string | undefined;
  aud?: string | undefined;
  screening?: { sanctions: "clean" | "flagged" | "unknown" } | undefined;
  authorization?: { pre_authorized: boolean; source?: string | undefined } | undefined;
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
