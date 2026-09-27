import type { ShadowCase } from "./cases.js";
import type { RiskCheckRequest } from "../src/types.js";
import { leetNormalize, SUSPICIOUS_TLDS, BRAND_TOKEN_DOMAINS } from "../src/domain-analysis.js";

export type BaselineVerdict = {
  decision: "safe" | "risky";
  reasons: string[];
};

const RISK_KEYWORDS =
  /\b(drain|siphon|mixing|mixer|peel chain|peel|hop-through|structuring|sanctions?|act before|before deadline|urgent|rotate between)\b/i;

export function baselineDecision(c: ShadowCase): BaselineVerdict {
  const req: RiskCheckRequest = c.request;
  const reasons: string[] = [];

  if (req.domain) {
    const domain = req.domain.toLowerCase();
    for (const [brand, official] of Object.entries(BRAND_TOKEN_DOMAINS)) {
      if (domain === official) continue;
      if (domain.includes(brand) || leetNormalize(domain).includes(brand)) {
        reasons.push(`brand-lookalike domain (${brand})`);
      }
    }
    for (const tld of SUSPICIOUS_TLDS) {
      if (domain.endsWith(tld)) {
        reasons.push(`suspicious tld (${tld})`);
      }
    }
  }

  const context = req.context ?? "";
  const match = context.match(RISK_KEYWORDS);
  if (match) {
    reasons.push(`risk keyword (${match[0]?.toLowerCase()})`);
  }

  return { decision: reasons.length > 0 ? "risky" : "safe", reasons };
}
