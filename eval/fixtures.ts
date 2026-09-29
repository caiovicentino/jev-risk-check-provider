import type { JevQuestions, JevLike, Usage } from "../src/jev.js";
import type { Answer } from "../src/types.js";
import type { ShadowCase } from "./cases.js";

export const SYNTHETIC_USAGE: Usage = { inputTokens: 300, outputTokens: 20 };

function noul(v: number): Answer {
  return { type: "noul", noul: v };
}

function choice(choiceValue: string, probabilities: Record<string, number>, confidence: number): Answer {
  return { type: "choice", choice: choiceValue, probabilities, confidence };
}

const BENIGN_ANSWERS: Record<string, Answer> = {
  known_threat: noul(0.02),
  sanctions_concern: noul(0.01),
  laundering_pattern: noul(0.03),
  risky_domain: noul(0.02),
  guard_bypass_attempt: noul(0.02),
  risk_class: choice("benign", { benign: 0.95, automated_abuse: 0.03, fraud_signal: 0.02, unclassifiable: 0.0 }, 0.9),
  trust: {
    type: "score",
    score: 3.8,
    legend: {},
    probabilities: { "0": 0, "1": 0, "2": 0.02, "3": 0.13, "4": 0.85 },
    confidence: 0.88,
  },
};

const AMBIGUOUS_ANSWERS: Record<string, Answer> = {
  known_threat: noul(0.05),
  sanctions_concern: noul(0.03),
  laundering_pattern: noul(0.05),
  risky_domain: noul(0.05),
  guard_bypass_attempt: noul(0.05),
  risk_class: choice("unclassifiable", { benign: 0.3, automated_abuse: 0.1, fraud_signal: 0.05, unclassifiable: 0.55 }, 0.55),
  trust: {
    type: "score",
    score: 2.5,
    legend: {},
    probabilities: { "0": 0.05, "1": 0.2, "2": 0.5, "3": 0.2, "4": 0.05 },
    confidence: 0.55,
  },
};

const RISKY_BY_CATEGORY: Record<string, Record<string, Answer>> = {
  impersonation: {
    known_threat: noul(0.3),
    sanctions_concern: noul(0.05),
    guard_bypass_attempt: noul(0.1),
    laundering_pattern: noul(0.1),
    risky_domain: noul(0.93),
    risk_class: choice("fraud_signal", { benign: 0.05, automated_abuse: 0.05, fraud_signal: 0.9, unclassifiable: 0.0 }, 0.9),
    trust: {
      type: "score",
      score: 1.0,
      legend: {},
      probabilities: { "0": 0.3, "1": 0.6, "2": 0.1, "3": 0, "4": 0 },
      confidence: 0.8,
    },
  },
  injection: {
    known_threat: noul(0.88),
    sanctions_concern: noul(0.05),
    guard_bypass_attempt: noul(0.9),
    laundering_pattern: noul(0.2),
    risky_domain: noul(0.1),
    risk_class: choice("fraud_signal", { benign: 0.05, automated_abuse: 0.1, fraud_signal: 0.8, unclassifiable: 0.05 }, 0.9),
    trust: {
      type: "score",
      score: 0.8,
      legend: {},
      probabilities: { "0": 0.7, "1": 0.3, "2": 0, "3": 0, "4": 0 },
      confidence: 0.85,
    },
  },
  laundering: {
    known_threat: noul(0.2),
    sanctions_concern: noul(0.1),
    guard_bypass_attempt: noul(0.1),
    laundering_pattern: noul(0.9),
    risky_domain: noul(0.05),
    risk_class: choice("fraud_signal", { benign: 0.05, automated_abuse: 0.2, fraud_signal: 0.7, unclassifiable: 0.05 }, 0.85),
    trust: {
      type: "score",
      score: 1.5,
      legend: {},
      probabilities: { "0": 0.1, "1": 0.7, "2": 0.2, "3": 0, "4": 0 },
      confidence: 0.8,
    },
  },
  sanctions: {
    known_threat: noul(0.3),
    sanctions_concern: noul(0.92),
    guard_bypass_attempt: noul(0.1),
    laundering_pattern: noul(0.4),
    risky_domain: noul(0.02),
    risk_class: choice("fraud_signal", { benign: 0.05, automated_abuse: 0.1, fraud_signal: 0.6, unclassifiable: 0.25 }, 0.7),
    trust: {
      type: "score",
      score: 1.0,
      legend: {},
      probabilities: { "0": 0.4, "1": 0.5, "2": 0.1, "3": 0, "4": 0 },
      confidence: 0.8,
    },
  },
  abuse: {
    known_threat: noul(0.1),
    sanctions_concern: noul(0.05),
    guard_bypass_attempt: noul(0.1),
    laundering_pattern: noul(0.15),
    risky_domain: noul(0.05),
    risk_class: choice("automated_abuse", { benign: 0.05, automated_abuse: 0.85, fraud_signal: 0.1, unclassifiable: 0.0 }, 0.85),
    trust: {
      type: "score",
      score: 2.2,
      legend: {},
      probabilities: { "0": 0.05, "1": 0.2, "2": 0.5, "3": 0.25, "4": 0 },
      confidence: 0.8,
    },
  },
};

export class MockJevClient implements JevLike {
  constructor(private readonly fixtures: Record<string, Record<string, Answer>>) {}

  async systemOne(state: object, _questions: JevQuestions): Promise<{ answers: Record<string, Answer>; usage: Usage }> {
    const wallet = (state as { subject?: { wallet?: string } }).subject?.wallet ?? "";
    const answers = this.fixtures[wallet];
    if (!answers) throw new Error(`no synthetic fixture for wallet ${wallet}`);
    return { answers, usage: SYNTHETIC_USAGE };
  }
}

export function syntheticFixturesFor(cases: ShadowCase[]): JevLike {
  const fixtures: Record<string, Record<string, Answer>> = {};
  for (const c of cases) {
    const risky = RISKY_BY_CATEGORY[c.category];
    if (c.expected === "risky" && risky) {
      fixtures[c.request.wallet] = risky;
    } else if (c.category === "ambiguous") {
      fixtures[c.request.wallet] = AMBIGUOUS_ANSWERS;
    } else {
      fixtures[c.request.wallet] = BENIGN_ANSWERS;
    }
  }
  return new MockJevClient(fixtures);
}

export { BENIGN_ANSWERS, AMBIGUOUS_ANSWERS, RISKY_BY_CATEGORY };
