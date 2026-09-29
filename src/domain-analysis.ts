import { parse } from "tldts";

// Weak signal only (never flagged alone). `.xyz` is deliberately absent: it is a
// mainstream web3 TLD (mirror.xyz, zapper.xyz, this provider's own domain).
export const SUSPICIOUS_TLDS = [".click", ".top", ".info", ".live", ".support", ".help", ".icu", ".cfd", ".sbs", ".rest", ".buzz", ".bond"];

// brand token -> official registrable domains. Subdomains of an official domain are official.
// Tokens are chosen for DISTINCTIVENESS among major wallets, exchanges and protocols:
// ordinary words ("balancer", "marinade", "curve", "safe") are left out because
// brand+lure matching on them would flag unrelated sites.
export const BRANDS: Record<string, string[]> = {
  coinbase: ["coinbase.com"],
  metamask: ["metamask.io"],
  phantom: ["phantom.app", "phantom.com"],
  ledger: ["ledger.com", "ledgerwallet.com"],
  trezor: ["trezor.io"],
  binance: ["binance.com", "binance.us", "binance.org"],
  jupiter: ["jup.ag"],
  solana: ["solana.com", "solana.org"],
  uniswap: ["uniswap.org"],
  opensea: ["opensea.io"],
  kraken: ["kraken.com"],
  trustwallet: ["trustwallet.com"],
  rabby: ["rabby.io"],
  pancakeswap: ["pancakeswap.finance"],
  raydium: ["raydium.io"],
  magiceden: ["magiceden.io"],
  etherscan: ["etherscan.io"],
  walletconnect: ["walletconnect.com", "walletconnect.org", "walletconnect.network", "reown.com"],
  lido: ["lido.fi"],
  aave: ["aave.com"],
  kucoin: ["kucoin.com"],
  bybit: ["bybit.com"],
  bitget: ["bitget.com"],
  dydx: ["dydx.exchange", "dydx.trade"],
  arbitrum: ["arbitrum.io", "arbitrum.foundation"],
  zksync: ["zksync.io"],
  starknet: ["starknet.io"],
  layerzero: ["layerzero.network"],
  wormhole: ["wormhole.com"],
  eigenlayer: ["eigenlayer.xyz", "eigenfoundation.org"],
  renzoprotocol: ["renzoprotocol.com"],
  rocketpool: ["rocketpool.net"],
  stakewise: ["stakewise.io"],
  ethena: ["ethena.fi"],
  hyperliquid: ["hyperliquid.xyz"],
  jito: ["jito.network"],
  pumpfun: ["pump.fun"],
  sushiswap: ["sushi.com"],
  makerdao: ["makerdao.com"],
  chainlink: ["chain.link"],
  polymarket: ["polymarket.com"],
  aptos: ["aptosfoundation.org", "aptoslabs.com"],
  tronlink: ["tronlink.org"],
  solflare: ["solflare.com"],
  zerion: ["zerion.io"],
  debank: ["debank.com"],
  basescan: ["basescan.org"],
  solscan: ["solscan.io"],
  arbiscan: ["arbiscan.io"],
  farcaster: ["farcaster.xyz"],
  warpcast: ["warpcast.com"],
};

/** First official domain per brand (kept for the keyword baseline and older callers). */
export const BRAND_TOKEN_DOMAINS: Record<string, string> = Object.fromEntries(
  Object.entries(BRANDS).map(([brand, domains]) => [brand, domains[0] as string]),
);

// Words phishing kits pair with a brand to make a lure ("coinbase-wallet-verify").
const LURE_WORDS = [
  "verify", "verification", "support", "helpdesk", "desk", "wallet", "auth", "login", "signin", "secure", "security",
  "claim", "airdrop", "reward", "rewards", "bonus", "giveaway", "connect", "restore", "recovery", "recover", "unlock",
  "validate", "validation", "sync", "rectify", "migrate", "migration", "refund", "gift", "free", "dapp", "portal", "kyc",
  "pay", "payment", "payments", "checkout", "billing", "invoice",
];

// Dictionary words / names within one edit of a brand token.
const TYPO_STOPWORDS = new Set(["finance", "trevor", "rabbi", "tabby", "solano", "solara", "hedger", "leader", "phantoms", "openseas", "jupyter", "habby", "kraker", "ledgers", "starnet"]);
// Typosquat matching only for tokens long enough that one edit is still distinctive.
const TYPO_MIN_LEN = 7;
// Short tokens ("lido", "aave", "jito", "dydx") only match as a whole label/word, never inside another word ("slido").
const WORD_ONLY_MAX_LEN = 4;

const LEET: Record<string, string> ={ "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a" };

// Latin lookalikes used in IDN homograph attacks (Cyrillic, Greek, Armenian, Latin-ext).
const CONFUSABLES: Record<string, string> = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g",
  "һ": "h", "ӏ": "l", "ո": "n", "ս": "u", "ν": "v", "ο": "o", "α": "a", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "μ": "m",
  "ɑ": "a", "ı": "i", "ⅼ": "l", "ｍ": "m", "ö": "o", "ó": "o", "ò": "o", "ô": "o", "á": "a", "à": "a", "â": "a", "ä": "a",
  "é": "e", "è": "e", "ê": "e", "ë": "e", "í": "i", "ì": "i", "ï": "i", "ú": "u", "ù": "u", "ü": "u", "ç": "c", "ñ": "n",
};

export type DomainAnalysis = {
  /** Normalized hostname (lowercase, punycode as served). */
  host: string;
  /** Registrable domain (eTLD+1, public-suffix aware incl. private suffixes such as vercel.app). */
  registrable: string;
  /** Host belongs to an official brand domain (including its subdomains). */
  official: boolean;
  impersonation: "none" | "weak" | "strong";
  brand?: string;
  signals: string[];
};

export function leetNormalize(input: string): string {
  return input
    .split("")
    .map((ch) => LEET[ch] ?? ch)
    .join("");
}

/** Accepts a bare host or an http(s) URL; returns the lowercase hostname or null. */
export function normalizeHost(input: string): string | null {
  const raw = input.trim();
  if (!raw || raw.length > 2048 || /\s/.test(raw)) return null;
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  const host = url.hostname.replace(/\.$/, "").toLowerCase();
  if (!host || host.length > 253) return null;
  if (host.startsWith("[")) return host; // IPv6 literal
  if (!/^[a-z0-9.-]+$/.test(host) || host.split(".").some((l) => l.length === 0 || l.length > 63)) return null;
  return host;
}

// RFC 3492 punycode decoder (labels starting with "xn--").
function punycodeDecode(input: string): string | null {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  const output: number[] = [];
  let n = 128, i = 0, bias = 72;
  const basic = input.lastIndexOf("-");
  for (let j = 0; j < Math.max(basic, 0); j++) output.push(input.charCodeAt(j));
  const adapt = (delta: number, numPoints: number, first: boolean): number => {
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((base - tMin) * tMax) >> 1) {
      delta = Math.floor(delta / (base - tMin));
      k += base;
    }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length; ) {
    const oldi = i;
    for (let w = 1, k = base; ; k += base) {
      if (idx >= input.length) return null;
      const c = input.charCodeAt(idx++);
      const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
      if (digit >= base) return null;
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    bias = adapt(i - oldi, output.length + 1, oldi === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

function toUnicodeHost(host: string): string {
  return host
    .split(".")
    .map((label) => (label.startsWith("xn--") ? (punycodeDecode(label.slice(4)) ?? label) : label))
    .join(".");
}

function skeleton(unicodeHost: string): string {
  return [...unicodeHost.normalize("NFKC")].map((ch) => CONFUSABLES[ch] ?? ch).join("");
}

// Optimal string alignment distance (Damerau–Levenshtein with adjacent transpositions).
function editDistance(a: string, b: string, max = 2): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array<number>(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) (d[0] as number[])[j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min((d[i - 1] as number[])[j]! + 1, (d[i] as number[])[j - 1]! + 1, (d[i - 1] as number[])[j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, (d[i - 2] as number[])[j - 2]! + 1);
      (d[i] as number[])[j] = v;
    }
  }
  return (d[a.length] as number[])[b.length]!;
}

export function analyzeDomain(input: string): DomainAnalysis | null {
  const host = normalizeHost(input);
  if (!host) return null;
  const parsed = parse(host, { allowPrivateDomains: true });
  const signals: string[] = [];
  if (parsed.isIp || host.startsWith("[")) {
    return { host, registrable: host, official: false, impersonation: "none", signals: ["ip_host"] };
  }
  const registrable = parsed.domain ?? host;
  for (const [brand, domains] of Object.entries(BRANDS)) {
    if (domains.includes(registrable)) return { host, registrable, official: true, impersonation: "none", brand, signals: ["official_domain"] };
  }

  const unicodeHost = toUnicodeHost(host);
  if (unicodeHost !== host) signals.push("punycode");
  const skel = skeleton(unicodeHost);
  const leet = leetNormalize(host);
  const words = host.split(/[.-]/).filter(Boolean);
  const lureIn = (text: string): boolean =>
    text.split(/[.-]/).filter(Boolean).some((w) => LURE_WORDS.includes(w) || LURE_WORDS.some((l) => l.length >= 6 && w.includes(l)));
  // Lure words are judged with the brand token removed: "walletconnect" is a brand, not a lure.
  const lureWithout = (token: string): boolean => lureIn(host.split(token).join("-"));
  if (lureIn(host)) signals.push("lure_keyword");
  if (SUSPICIOUS_TLDS.some((tld) => host.endsWith(tld))) signals.push("suspicious_tld");
  const contains = (haystack: string, token: string): boolean =>
    token.length <= WORD_ONLY_MAX_LEN ? haystack.split(/[.-]/).includes(token) : haystack.includes(token);

  // Pass 1: exact / leet / homoglyph matches across every brand. Pass 2 (only if
  // nothing matched): one-edit typosquats, skipping ordinary words one edit away
  // from a brand ("finance" vs "binance", "trevor" vs "trezor").
  const matches: Array<{ token: string; via: string }> = [];
  for (const token of Object.keys(BRANDS)) {
    if (contains(host, token)) matches.push({ token, via: "brand_token" });
    else if (contains(leet, token)) matches.push({ token, via: "leet_substitution" });
    else if (skel !== host && contains(skel, token)) matches.push({ token, via: "homoglyph" });
  }
  if (matches.length === 0) {
    for (const token of Object.keys(BRANDS)) {
      if (token.length < TYPO_MIN_LEN) continue;
      if (words.some((w) => w.length >= TYPO_MIN_LEN && !TYPO_STOPWORDS.has(w) && editDistance(w, token) === 1)) matches.push({ token, via: "typosquat" });
    }
  }
  // "uniswap.org.evil.com": an official domain reused as a label prefix of another registrable domain.
  for (const [token, domains] of Object.entries(BRANDS)) {
    if (domains.some((d) => host.startsWith(`${d}.`) || host.includes(`.${d}.`))) matches.unshift({ token, via: "official_domain_as_subdomain" });
  }
  const strengthOf = (m: { token: string; via: string }): "weak" | "strong" => (m.via === "brand_token" && !lureWithout(m.token) ? "weak" : "strong");
  const best = matches.find((m) => strengthOf(m) === "strong") ?? matches[0];
  for (const m of matches) signals.push(m.via);
  return {
    host,
    registrable,
    official: false,
    impersonation: best ? strengthOf(best) : "none",
    ...(best ? { brand: best.token } : {}),
    signals: [...new Set(signals)],
  };
}
