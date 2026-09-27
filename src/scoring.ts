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

export function extractInputs(req: RiskCheckRequest, answers: Record<string, Answer>): ScoringInputs {
  return {
    knownThreat: asNumber(answers["known_threat"], 0),
    sanctionsConcern: asNumber(answers["sanctions_concern"], 0),
    launderingPattern: asNumber(answers["laundering_pattern"], 0),
    riskyDomain: asNumber(answers["risky_domain"], 0),
    guardBypassAttempt: asNumber(answers["guard_bypass_attempt"], 0),
    riskClass: answers["risk_class"]?.type === "choice" ? answers["risk_class"].choice : "unclassifiable",
    riskClassProbability:
      answers["risk_class"]?.type === "choice"
        ? (answers["risk_class"].probabilities[answers["risk_class"].choice] ?? 0)
        : 0,
    trust: trustScore(answers["trust"]),
    trustConfidence: trustConfidence(answers["trust"]),
    trustCalibrated: trustCalibrated(answers["trust"]),
  };
}

export const SCREENING_TRUST_MULTIPLIER = 0.2;

export function computeScore(inputs: ScoringInputs, weights: ScoringWeights = DEFAULT_WEIGHTS, screeningClean = false, preAuthorized = false): ScoreBreakdown {
  const riskClassPenalty = weights.riskClass[inputs.riskClass] ?? weights.riskClass["unclassifiable"] ?? 10;
  const riskClassScaled = riskClassPenalty * inputs.riskClassProbability;
  const sanctionsPenalty = screeningClean
    ? weights.sanctionsConcern * inputs.sanctionsConcern * SCREENING_TRUST_MULTIPLIER
    : weights.sanctionsConcern * inputs.sanctionsConcern;

  let penalty =
    weights.knownThreat * inputs.knownThreat +
    sanctionsPenalty +
    weights.launderingPattern * inputs.launderingPattern +
    weights.riskyDomain * inputs.riskyDomain +
    weights.guardBypassAttempt * inputs.guardBypassAttempt +
    riskClassScaled;
  const trust = preAuthorized ? Math.max(inputs.trust, 3) : inputs.trust;
  penalty -= (trust - 2) * weights.trustPerLevel;

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

  score = Math.max(0, Math.min(100, score));
  return { score, tier: tierFor(score), cappedByLowConfidence, signals: inputs };
}

export function tierFor(score: number): RiskTier {
  if (score >= 80) return "low";
  if (score >= 60) return "medium";
  if (score >= 30) return "high";
  return "critical";
}

export function categoriesFor(inputs: ScoringInputs): string[] {
  const categories = ["intent_risk", "behavioral"];
  if (inputs.sanctionsConcern > 0.3) categories.push("compliance_risk");
  return categories;
}
