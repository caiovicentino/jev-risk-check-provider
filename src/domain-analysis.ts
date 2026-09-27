export const SUSPICIOUS_TLDS = [".click", ".xyz", ".top", ".info", ".live", ".support", ".help"];

const LEET: Record<string, string> = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t" };

export const BRAND_TOKEN_DOMAINS: Record<string, string> = {
  coinbase: "coinbase.com",
  metamask: "metamask.io",
  phantom: "phantom.app",
  ledger: "ledger.com",
  binance: "binance.com",
  jupiter: "jupiter.ag",
  solana: "solana.com",
};

export function leetNormalize(input: string): string {
  return input
    .split("")
    .map((ch) => LEET[ch] ?? ch)
    .join("");
}

export type DomainAnalysis = {
  domain: string;
  normalized: string;
  leet_substitution: boolean;
  brand_tokens: string[];
  official_brands: string[];
  suspicious_tld: boolean;
};

export function analyzeDomain(domain: string): DomainAnalysis {
  const lower = domain.toLowerCase();
  const normalized = leetNormalize(lower);
  const brandTokens: string[] = [];
  const officialBrands: string[] = [];
  for (const [brand, official] of Object.entries(BRAND_TOKEN_DOMAINS)) {
    if (lower === official) officialBrands.push(brand);
    else if (lower.includes(brand) || normalized.includes(brand)) brandTokens.push(brand);
  }
  const hasLeet = normalized !== lower && brandTokens.length > 0;
  const suspiciousTld = SUSPICIOUS_TLDS.some((tld) => lower.endsWith(tld));
  return {
    domain: lower,
    normalized,
    leet_substitution: hasLeet,
    brand_tokens: brandTokens,
    official_brands: officialBrands,
    suspicious_tld: suspiciousTld,
  };
}
