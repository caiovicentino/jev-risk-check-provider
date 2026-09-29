import { hashSetFromBytes, type LoadedFeed } from "../src/threat-intel.js";
import type { WorkerEnv } from "./runtime.js";

// ScamSniffer data is GPL-3.0: it lives only in the operator's KV (uploaded by
// scripts/update-threat-feeds.ts --scamsniffer --upload) and is read at runtime.
const KEYS = { domains: "feed:scamsniffer:domains:v1", addresses: "feed:scamsniffer:addresses:v1", meta: "feed:scamsniffer:meta:v1" };
const TTL_MS = 60 * 60 * 1000;

type ScamSnifferFeeds = { scamsnifferDomains?: LoadedFeed | null; scamsnifferAddresses?: LoadedFeed | null };

let cache: { at: number; value: Promise<ScamSnifferFeeds> } | null = null;

async function load(env: WorkerEnv): Promise<ScamSnifferFeeds> {
  const kv = env.RATE;
  if (!kv) return {};
  try {
    const metaRaw = await kv.get(KEYS.meta);
    if (!metaRaw) return {}; // never uploaded: feed not configured (not consulted)
    const meta = JSON.parse(metaRaw) as { as_of: string };
    const [domains, addresses] = await Promise.all([
      kv.get(KEYS.domains, { type: "arrayBuffer", cacheTtl: 3600 }),
      kv.get(KEYS.addresses, { type: "arrayBuffer", cacheTtl: 3600 }),
    ]);
    return {
      scamsnifferDomains: domains ? { set: hashSetFromBytes(domains), as_of: meta.as_of } : null,
      scamsnifferAddresses: addresses ? { set: hashSetFromBytes(addresses), as_of: meta.as_of } : null,
    };
  } catch {
    // configured but unreadable: consulted-and-unavailable, stated in the evidence
    return { scamsnifferDomains: null, scamsnifferAddresses: null };
  }
}

/** Per-isolate cache (1h); a failed load is retried on the next request. */
export async function loadScamSniffer(env: WorkerEnv): Promise<ScamSnifferFeeds> {
  if (!cache || Date.now() - cache.at > TTL_MS) cache = { at: Date.now(), value: load(env) };
  const value = await cache.value;
  if (value.scamsnifferDomains === null || value.scamsnifferAddresses === null) cache = null;
  return value;
}
