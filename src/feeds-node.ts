import { existsSync, readFileSync } from "node:fs";
import { hashSetFromBytes, type ThreatIntelFeeds } from "./threat-intel.js";
import { METAMASK_ALLOWLIST, METAMASK_FEED_META } from "./data/threat-feeds.js";

/**
 * Node-side feed loader (server, evals, tests). The MetaMask set ships in src/data;
 * ScamSniffer blobs are read from .cache/threat-feeds when present (built locally by
 * scripts/update-threat-feeds.ts --scamsniffer; never committed).
 */
export function loadFeedsFromDisk(opts: { scamsniffer?: boolean } = {}): ThreatIntelFeeds {
  const root = new URL("../", import.meta.url);
  const feeds: ThreatIntelFeeds = {
    metamaskDomains: { set: hashSetFromBytes(readFileSync(new URL("src/data/metamask-phishing.bin", root))), as_of: METAMASK_FEED_META.as_of },
    metamaskAllow: new Set(METAMASK_ALLOWLIST),
  };
  const cache = new URL(".cache/threat-feeds/", root);
  if (opts.scamsniffer !== false && existsSync(new URL("scamsniffer-meta.json", cache))) {
    const meta = JSON.parse(readFileSync(new URL("scamsniffer-meta.json", cache), "utf8")) as { as_of: string };
    feeds.scamsnifferDomains = { set: hashSetFromBytes(readFileSync(new URL("scamsniffer-domains.bin", cache))), as_of: meta.as_of };
    feeds.scamsnifferAddresses = { set: hashSetFromBytes(readFileSync(new URL("scamsniffer-addresses.bin", cache))), as_of: meta.as_of };
  }
  return feeds;
}
