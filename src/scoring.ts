import type { Answer, RiskCheckRequest, ScoringInputs, ScoreBreakdown, RiskTier } from "./types.js";

export type ScoringWeights = {
  knownThreat: number;
  sanctionsConcern: number;
  launderingPattern: number;
  riskyDomain: number;
  guardBypassAttempt: number;
  riskClass: Record<string, number>;
  trustPerLevel: number;
};

export const DEFAULT_WEIGHTS: ScoringWeights = {
  knownThreat: 55,
  sanctionsConcern: 40,
  launderingPattern: 25,
  riskyDomain: 20,
  guardBypassAttempt: 45,
  riskClass: {
    benign: 0,
    automated_abuse: 20,
    fraud_signal: 30,
    unclassifiable: 10,
  },
  trustPerLevel: 4,
};

export const MIN_PRIMARY_CONFIDENCE = 0.5;

function asNumber(answer: Answer | undefined, fallback: number): number {
  if (!answer) return fallback;
  if (answer.type === "noul") return answer.noul;
  return fallback;
}

function trustScore(answer: Answer | undefined): number {
  if (answer && answer.type === "score") return answer.score;
  return 2;
}

function trustConfidence(answer: Answer | undefined): number {
  if (answer && (answer.type === "score" || answer.type === "choice")) return answer.confidence;
  return 0;
}

function trustCalibrated(answer: Answer | undefined): boolean {
  if (!answer) return false;
  if (answer.type === "score" || answer.type === "choice") return !answer.noCalibration;
  return false;
}

const RISK_CLASSES = new Set(["benign", "automated_abuse", "fraud_signal", "unclassifiable"]);

function riskClassOf(answer: Answer | undefined): string {
  return answer?.type === "choice" && RISK_CLASSES.has(answer.choice) ? answer.choice : "unclassifiable";
}

function unit(v: unknown): number {
  return typeof v === "number" && Number.isFinite(v) ? Math.min(1, Math.max(0, v)) : 0;
}

export function extractInputs(req: RiskCheckRequest, answers: Record<string, Answer>): ScoringInputs {
  return {
    knownThreat: asNumber(answers["known_threat"], 0),
    sanctionsConcern: asNumber(answers["sanctions_concern"], 0),
    launderingPattern: asNumber(answers["laundering_pattern"], 0),
    riskyDomain: asNumber(answers["risky_domain"], 0),
    guardBypassAttempt: asNumber(answers["guard_bypass_attempt"], 0),
    riskClass: riskClassOf(answers["risk_class"]),
    riskClassProbability:
      answers["risk_class"]?.type === "choice" && RISK_CLASSES.has(answers["risk_class"].choice)
        ? unit(answers["risk_class"].probabilities[answers["risk_class"].choice])
        : 0,
    trust: trustScore(answers["trust"]),
    trustConfidence: trustConfidence(answers["trust"]),
    trustCalibrated: trustCalibrated(answers["trust"]),
  };
}

export type ScoreOptions = {
  /** Caller-asserted screening result "flagged" — can only raise risk. */
  callerFlagged?: boolean;
  /** Provider-side domain analysis verdict. */
  impersonation?: "none" | "weak" | "strong";
  /** Lowest cap imposed by deterministic provider evidence (feed hits, approval to an EOA). */
  evidenceCap?: number;
};

// Caller-asserted "clean" screening deliberately has no effect on the score: a
// self-reported mitigation must never lower risk (it previously scaled the sanctions
// penalty by 0.2, which let any caller mint a low-risk attestation for a context
// that described a sanctions listing).
export function computeScore(inputs: ScoringInputs, weights: ScoringWeights = DEFAULT_WEIGHTS, opts: ScoreOptions = {}): ScoreBreakdown {
  const riskClassPenalty = Object.hasOwn(weights.riskClass, inputs.riskClass) ? (weights.riskClass[inputs.riskClass] as number) : (weights.riskClass["unclassifiable"] ?? 10);
  const riskClassScaled = riskClassPenalty * inputs.riskClassProbability;

  let penalty =
    weights.knownThreat * inputs.knownThreat +
    weights.sanctionsConcern * inputs.sanctionsConcern +
    weights.launderingPattern * inputs.launderingPattern +
    weights.riskyDomain * inputs.riskyDomain +
    weights.guardBypassAttempt * inputs.guardBypassAttempt +
    riskClassScaled;
  // Caller assertions (screening "clean", authorization.pre_authorized) never raise
  // trust deterministically; the model sees them as unverified caller claims.
  penalty -= (inputs.trust - 2) * weights.trustPerLevel;

  let score = Math.round(100 - penalty);
  let cappedByLowConfidence = false;

  if (inputs.trustCalibrated && inputs.trustConfidence < MIN_PRIMARY_CONFIDENCE) {
    score = Math.min(score, 55);
    cappedByLowConfidence = true;
  }

  if (inputs.knownThreat >= 0.85) score = Math.min(score, 20);
  if (inputs.sanctionsConcern >= 0.85) score = Math.min(score, 30);
  if (inputs.guardBypassAttempt >= 0.8) score = Math.min(score, 30);
  if (inputs.riskClass === "automated_abuse" && inputs.riskClassProbability >= 0.8) score = Math.min(score, 55);
  if (inputs.riskClass === "fraud_signal" && inputs.riskClassProbability >= 0.8) score = Math.min(score, 40);
  // Deterministic provider/integrator evidence, independent of model sampling.
  if (opts.callerFlagged) score = Math.min(score, 30);
  if (opts.impersonation === "strong") score = Math.min(score, 40);
  if (opts.evidenceCap !== undefined) score = Math.min(score, opts.evidenceCap);

  // Last-resort guard: a non-finite score fails closed to 0 rather than signing NaN.
  score = Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : 0;
  return { score, tier: tierFor(score, inputs), cappedByLowConfidence, signals: inputs };
}

// Review routing (medium tier) is signal-driven, not score-proximity-driven: a safe
// decision only routes to human review when there is a positive reason to look —
// a strong intent signal, or an uncertain risk class. Signals in the 0.2–0.3 range
// on benign-class cases reflect data availability (e.g. absent sanctions screening),
// not review-worthy concern. The block threshold is unaffected (score-only).
export const REVIEW_SIGNAL_FLOOR = 0.3;
export const REVIEW_CLASS_PROB_FLOOR = 0.5;

export function tierFor(score: number, inputs?: ScoringInputs): RiskTier {
  if (score >= 80) return "low";
  if (score >= 30) {
    if (score < 60) return "high";
    if (!inputs) return "medium";
    const elevatedSignal =
      inputs.knownThreat >= REVIEW_SIGNAL_FLOOR ||
      inputs.sanctionsConcern >= REVIEW_SIGNAL_FLOOR ||
      inputs.launderingPattern >= REVIEW_SIGNAL_FLOOR ||
      inputs.riskyDomain >= REVIEW_SIGNAL_FLOOR ||
      inputs.guardBypassAttempt >= REVIEW_SIGNAL_FLOOR ||
      ((inputs.riskClass === "automated_abuse" ||
        inputs.riskClass === "fraud_signal" ||
        inputs.riskClass === "unclassifiable") &&
        inputs.riskClassProbability >= REVIEW_CLASS_PROB_FLOOR);
    return elevatedSignal ? "medium" : "low";
  }
  return "critical";
}

export type CategoryFacts = {
  callerFlagged?: boolean;
  impersonation?: "none" | "weak" | "strong";
  newAddress?: boolean;
  phishingDomain?: boolean;
  communityFlaggedDomain?: boolean;
  knownScamAddress?: boolean;
  approvalToEoa?: boolean;
};

/** Evaluated families (intent_risk, behavioral) plus the specific findings behind the verdict. */
export function categoriesFor(inputs: ScoringInputs, facts: CategoryFacts = {}): string[] {
  const categories = ["intent_risk", "behavioral"];
  if (inputs.sanctionsConcern > 0.3 || facts.callerFlagged) categories.push("compliance_risk");
  if (facts.impersonation === "strong" || inputs.riskyDomain >= 0.5) categories.push("impersonation");
  if (inputs.guardBypassAttempt >= 0.5) categories.push("guard_bypass");
  if (inputs.launderingPattern >= 0.5) categories.push("laundering_pattern");
  if (inputs.knownThreat >= 0.5) categories.push("known_threat");
  if (inputs.riskClass === "automated_abuse" && inputs.riskClassProbability >= 0.5) categories.push("automated_abuse");
  if (inputs.riskClass === "fraud_signal" && inputs.riskClassProbability >= 0.5) categories.push("fraud_signal");
  if (facts.phishingDomain) categories.push("phishing_domain");
  if (facts.communityFlaggedDomain) categories.push("community_flagged_domain");
  if (facts.knownScamAddress) categories.push("known_scam_address");
  if (facts.approvalToEoa) categories.push("approval_to_eoa");
  if (facts.newAddress) categories.push("new_address");
  return categories;
}
