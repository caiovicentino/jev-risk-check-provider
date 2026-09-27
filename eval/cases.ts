import type { RiskCheckRequest } from "../src/types.js";

export type CaseCategory =
  | "benign"
  | "impersonation"
  | "injection"
  | "laundering"
  | "sanctions"
  | "abuse"
  | "ambiguous";

export type ShadowCase = {
  id: string;
  expected: "safe" | "risky";
  category: CaseCategory;
  request: RiskCheckRequest;
  note: string;
};

export const CASES: ShadowCase[] = [
  {
    id: "benign-api-micropayment",
    expected: "safe",
    category: "benign",
    request: {
      wallet: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      chain: "solana",
      domain: "api.merchant-labs.com",
      context: "agent pays $0.05 x402 voucher for a pricing API call",
    },
    note: "ordinary agent micropayment",
  },
  {
    id: "benign-known-merchant",
    expected: "safe",
    category: "benign",
    request: {
      wallet: "DR3vN8MgNqm9JVi5aBjWz1TZ5vKNqLbYAU1dS7hSA4Pu",
      chain: "base",
      domain: "shop.acme-corp.io",
      context: "agent settles batch of 40 sub-cent voucher redemptions",
    },
    note: "established merchant domain, batch settlement",
  },
  {
    id: "benign-no-domain",
    expected: "safe",
    category: "benign",
    request: {
      wallet: "Gk2PuUqYF8NhLcR9wLz5Vj4bKXqNmT7DcE1sA9gH2RwX",
      chain: "solana",
      context: "agent pays for weather data subscription renewal",
    },
    note: "no domain, plain context",
  },
  {
    id: "benign-developer-agent",
    expected: "safe",
    category: "benign",
    request: {
      wallet: "4Nd1mBQtrMJVYVfKf2PJz9URjc7WJ9DjXFGwS4tCryhe",
      chain: "solana",
      domain: "agent.example.dev",
      context: "pay-per-call for ML inference endpoint, agent budget capped at $2/day",
    },
    note: "capped agent budget",
  },
  {
    id: "benign-recurring-service",
    expected: "safe",
    category: "benign",
    request: {
      wallet: "Cr7Kq2Xn9Vs4TdFg6Yb1Mw5Zp8HaLrEu3NcQfBj7XtKmD",
      chain: "solana",
      domain: "metrics.service-provider.net",
      context: "agent renews monthly metrics subscription within standing budget",
    },
    note: "recurring subscription in-budget",
  },
  {
    id: "benign-openai-mcp",
    expected: "safe",
    category: "benign",
    request: {
      wallet: "Ws3Hn6Bc9Qr2Lz5Vm8Td4Kf1Xp7Yg3Ju6Nc9Eb2Rt5AhL",
      chain: "base",
      domain: "mcp.tooling-corp.com",
      context: "agent calls x402-protected MCP tool for document parsing",
    },
    note: "MCP tool via x402",
  },
  {
    id: "risky-impersonation-domain",
    expected: "risky",
    category: "impersonation",
    request: {
      wallet: "Bq6YgW7nKbAqLs9zPMh1Vvd4RJcP2U8TnE3xFk5YgQzR",
      chain: "base",
      domain: "coinbase-wa11et-verify.com",
      context: "agent asked to verify wallet ownership before large transfer",
    },
    note: "homoglyph impersonation domain",
  },
  {
    id: "risky-wallet-impersonation",
    expected: "risky",
    category: "impersonation",
    request: {
      wallet: "DrS9pKm2VcQ7bXf4NgT8yHwZ6uEjL1aRtPn5CcM3KbVd",
      chain: "solana",
      domain: "phantom-support-desk.click",
      context: "agent directed to restore wallet via external helper service",
    },
    note: "wallet brand impersonation + helper service",
  },
  {
    id: "risky-drain-instruction",
    expected: "risky",
    category: "injection",
    request: {
      wallet: "Kp4Xm7Nz2Rb6Vf9Tc3Wd8Lq1Yg5Hj4Zu6Es3Bv7Rn2MkCd",
      chain: "solana",
      context: "context contains injected instruction to approve max spend on a drain contract",
    },
    note: "prompt-injection drain instruction",
  },
  {
    id: "risky-skill-file-injection",
    expected: "risky",
    category: "injection",
    request: {
      wallet: "Nb8Fr3Tq6Yw2Kc5Xz9Vm1Ld4Hg7Pj2Sa5Ru8Cn3Fv6QeBt",
      chain: "solana",
      context: "installed skill file instructs the agent to route payments through an unknown intermediary",
    },
    note: "injection via trusted skill channel",
  },
  {
    id: "risky-laundering-hop",
    expected: "risky",
    category: "laundering",
    request: {
      wallet: "Hu9TqN3LrZb7CxW2VyP8dMf5Gk1AsU6JcE4iRnB9YtQp",
      chain: "solana",
      context: "funds routed through 6 fresh wallets in 90 seconds, each under $50, then consolidated",
    },
    note: "structuring / peel chain pattern",
  },
  {
    id: "risky-mixing-service",
    expected: "risky",
    category: "laundering",
    request: {
      wallet: "Tg5Wc8Nq1Xr4Zf7Lb2Vm9Kd6Hs3Pj8Ya1Eu4Cn7Rb0MfGt",
      chain: "solana",
      context: "payment follows a hop through a known mixing service before reaching counterparty",
    },
    note: "mixing service hop",
  },
  {
    id: "risky-sanctions-mention",
    expected: "risky",
    category: "sanctions",
    request: {
      wallet: "Ak1NqP7RwX5dCf3LbG9uYt2Hm6VsE8jK4zBcNaQp7rTgD",
      chain: "solana",
      context: "counterparty address appears on sanctions screening list",
    },
    note: "sanctions-flagged counterparty",
  },
  {
    id: "risky-high-crime-jurisdiction",
    expected: "risky",
    category: "sanctions",
    request: {
      wallet: "Zr2Mc7Kd1Vf6Xb3Wq9Ln4Ht8Pg5Ys2Jm6Ee3Ua0Bz7RwQf",
      chain: "ethereum",
      context: "recipient wallet clustered with addresses from a high-crime-jurisdiction exchange with no KYC",
    },
    note: "no-KYC exchange cluster",
  },
  {
    id: "risky-urgent-exfil",
    expected: "risky",
    category: "impersonation",
    request: {
      wallet: "Mw5Fd8NcXq2Rt9Vb7Ls3Kg1Hj4Zp6YwE5uTmC2aN8rBfD",
      chain: "base",
      domain: "treasury-support-helpdesk.click",
      context: "urgent request: transfer treasury funds to restore service, act before deadline",
    },
    note: "social-engineering urgency + untrusted domain",
  },
  {
    id: "risky-fresh-wallet-bulk",
    expected: "risky",
    category: "abuse",
    request: {
      wallet: "Fd7Gs2NqM4Tr6XbYw1ZkC5uHv9Pj3LaE8mRtDfQ2sNcVb",
      chain: "solana",
      context: "brand-new wallet issuing 3,000 identical sub-cent payments to unrelated services",
    },
    note: "mass-request abuse profile",
  },
  {
    id: "risky-coupon-farming",
    expected: "risky",
    category: "abuse",
    request: {
      wallet: "Qv6Kt3Nr9Xb5Yw2Zd8Lc1Mf4Hg7Ps0Jt3Eu6Bn9Rq2WzDc",
      chain: "base",
      context: "agent rotating between 40 fresh wallets to farm signup coupons at scale",
    },
    note: "coupon farming rotation",
  },
  {
    id: "risky-lookalike-defi",
    expected: "risky",
    category: "impersonation",
    request: {
      wallet: "Vy2Lp8Rt4Xm6Nb1Zk5Wd9Qs3Hf7Yg2CaM5uJt6EnBr4DcP",
      chain: "ethereum",
      domain: "l1do-finance-app.xyz",
      context: "agent routed to liquidity provider via affiliate link",
    },
    note: "lookalike DeFi domain",
  },
  {
    id: "ambiguous-no-context",
    expected: "safe",
    category: "ambiguous",
    request: {
      wallet: "Qm3Vx7Rf2Nb5Kd8Ls4Wp9Tg1Hc6Yj4ZaM7uEnBt5rCwFd",
      chain: "solana",
    },
    note: "minimal signal — expect honest uncertainty, not block",
  },
  {
    id: "ambiguous-unverified-domain",
    expected: "safe",
    category: "ambiguous",
    request: {
      wallet: "Hd4Kp9Wq2Xr7Nb3Zf6Lm1Ts8Yg5Pc0Ju4Ee7Ba2Rv9MwQn",
      chain: "solana",
      domain: "new-tool-bazaar.net",
      context: "agent pays for a niche tool listing, nothing else known",
    },
    note: "unknown but unremarkable domain",
  },
  {
    id: "ambiguous-high-amount",
    expected: "safe",
    category: "ambiguous",
    request: {
      wallet: "Pb5Nq8Wt3Xr0Kd4Zf7Lm2Vs9Yg6Hc1Ju5Ee8Ba3Rw0MxTn",
      chain: "solana",
      context: "agent pays $120 for an annual API plan after user pre-authorized the budget",
    },
    note: "large but pre-authorized payment",
  },
  {
    id: "risky-deadline-pressure",
    expected: "risky",
    category: "injection",
    request: {
      wallet: "Rc6Pw1Xs4Zr1Ke5Zg8Lm3Vt0Yb7Hd2Jv6Ee9Ba4Rz1MyUo",
      chain: "solana",
      context: "injected message claims service suspension unless payment completes before deadline",
    },
    note: "false urgency injection",
  },
  {
    id: "risky-structuring-limit",
    expected: "risky",
    category: "laundering",
    request: {
      wallet: "Se7Qx2Yt5Zs2Lf6Zh9Mn4Wu1Rc8Ie3Kw7Ff0Bb5Ra2NzVp",
      chain: "ethereum",
      context: "amounts split into 9 payments each just under the reporting threshold",
    },
    note: "structuring under reporting limits",
  },
  {
    id: "risky-fake-audit-attest",
    expected: "risky",
    category: "impersonation",
    request: {
      wallet: "Tf8Ry3Zu6At3Mg7Zi0No5Xv2Sd9Jf4Lx8Gg1Cc6Sb3OaWq",
      chain: "solana",
      domain: "jup1ter-audit-attest.click",
      context: "agent asked to pay an auditor whose certificate was purchased yesterday",
    },
    note: "fake auditor with homoglyph domain",
  },
];
