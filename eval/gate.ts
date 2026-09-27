import { readLatestEntries, DECISION_THRESHOLD, EVAL_EVIDENCE_DIR } from "./harness.js";
import { CASES } from "./cases.js";
import { baselineDecision } from "./baseline.js";

export type GateCriteria = {
  verifiedChecks: number;
  realRiskyVerified: number;
  dismissedReal: number;
  jevFalseConfirms: number;
  baselineFalseFlags: number;
  reviewShare: number;
};

export type GateReport = GateCriteria & {
  ready: boolean;
  failures: string[];
};

export const GATE_TARGETS = {
  minVerifiedChecks: 50,
  minRealRiskyVerified: 5,
  maxDismissedReal: 0,
  maxReviewShare: 0.2,
};

export type GateTargets = typeof GATE_TARGETS;

export function deriveDecision(score: number | null, checked: boolean): "safe" | "risky" | "unchecked" {
  if (!checked || score === null) return "unchecked";
  return score >= DECISION_THRESHOLD ? "safe" : "risky";
}

export function evaluateGate(logFile: string, targets: GateTargets = GATE_TARGETS): GateReport {
  const latest = readLatestEntries(logFile);
  let verifiedChecks = 0;
  let realRiskyVerified = 0;
  let dismissedReal = 0;
  let jevFalseConfirms = 0;
  let verifiedTotal = 0;

  for (const c of CASES) {
    const entry = latest.get(c.id);
    if (!entry || entry.verified === null) continue;
    verifiedTotal++;
    const decision = deriveDecision(entry.score, entry.checked);
    if (c.expected === "risky") {
      if (entry.verified === "real") {
        verifiedChecks++;
        if (decision === "risky") realRiskyVerified++;
        else if (decision === "safe") dismissedReal++;
      } else if (decision === "risky") {
        jevFalseConfirms++;
      }
    } else {
      if (entry.verified === "real") {
        verifiedChecks++;
        if (decision === "risky") jevFalseConfirms++;
      }
    }
  }

  let baselineFalseFlags = 0;
  for (const c of CASES) {
    if (c.expected === "safe" && baselineDecision(c).decision === "risky") baselineFalseFlags++;
  }

  let reviewShare = 0;
  if (verifiedTotal > 0) {
    const capped = CASES.filter((c) => latest.get(c.id)?.tier === "medium" && deriveDecision(latest.get(c.id)?.score ?? null, true) === "safe").length;
    reviewShare = capped / verifiedTotal;
  }

  const failures: string[] = [];
  if (verifiedChecks < targets.minVerifiedChecks) failures.push(`verified checks ${verifiedChecks}/${targets.minVerifiedChecks}`);
  if (realRiskyVerified < targets.minRealRiskyVerified) failures.push(`verified risky real cases ${realRiskyVerified}/${targets.minRealRiskyVerified}`);
  if (dismissedReal > targets.maxDismissedReal) failures.push(`real risky dismissed by JEV: ${dismissedReal}`);
  if (jevFalseConfirms > baselineFalseFlags) failures.push(`JEV false confirms ${jevFalseConfirms} > baseline false flags ${baselineFalseFlags}`);
  if (reviewShare > targets.maxReviewShare) failures.push(`review share ${Math.round(reviewShare * 100)}% > ${Math.round(targets.maxReviewShare * 100)}%`);

  return {
    verifiedChecks,
    realRiskyVerified,
    dismissedReal,
    jevFalseConfirms,
    baselineFalseFlags,
    reviewShare,
    ready: failures.length === 0,
    failures,
  };
}

export { EVAL_EVIDENCE_DIR };
