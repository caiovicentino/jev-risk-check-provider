import { getContractAddress, type Hex } from "viem";
import { recoverAuthorizationAddress } from "viem/utils";
import { codeFacts, isContractCode, resolveIndirection, type BatchCall, type CodeFacts } from "./code-fingerprint.js";

// Kit watch: provider-owned intelligence about drainer infrastructure, built by reading
// every new block on Ethereum and Base. Public lists name a few thousand addresses,
// days after the fact; the infrastructure itself is visible on-chain the moment it is
// set up:
//
//  - EIP-7702 delegations to malicious delegates. An address-poisoning executor
//    ("Poisoner") is delegated by the look-alike addresses its operator controls; an
//    auto-forwarding sweeper is delegated by wallets whose keys are compromised, so
//    anything sent to them is gone. Either way, paying the authority pays the thief.
//  - New contracts whose logic matches a drainer-kit family, and the EOAs that deploy
//    them (operators).
//
// Families come from labelled sources (Forta, ScamSniffer, verified public exposures)
// and grow by behaviour: a delegate that forwards every wei it receives to another
// address is a sweeper, whoever deployed it. Everything a scan produces is private
// (operator KV): it is the provider's own data, and part of it is derived from GPL data.

export const WATCH_CHAINS = ["eip155:1", "eip155:8453"] as const;
export type WatchChain = (typeof WATCH_CHAINS)[number];
const CHAIN_IDS: Record<WatchChain, number> = { "eip155:1": 1, "eip155:8453": 8453 };

/**
 * poisoner / sweeper / drainer_kit: labelled (a public exposure, a list, or a listed
 * sibling). forwarder: learned from behaviour alone (every wei received is passed on).
 */
export type FamilyClass = "poisoner" | "sweeper" | "forwarder" | "drainer_kit";
export type Family = {
  id: string;
  class: FamilyClass;
  /** Logic-code fingerprints (src/code-fingerprint.ts). */
  exact: string[];
  /** Template fingerprints (immutables and hard-coded addresses masked); only for specific templates. */
  skeleton: string[];
  /** Where the label comes from: forta, scamsniffer, exposure:<who>, explorer:blockscout, behaviour:auto-forward. */
  sources: string[];
  first_seen?: string;
};
export type Registry = { updated_at: string; families: Family[] };

export type FamilyIndex = { exact: Map<string, Family>; skeleton: Map<string, Family>; size: number };

export function indexFamilies(registry: Registry | null | undefined): FamilyIndex {
  const exact = new Map<string, Family>();
  const skeleton = new Map<string, Family>();
  for (const f of registry?.families ?? []) {
    for (const fp of f.exact) exact.set(fp, f);
    for (const sk of f.skeleton) skeleton.set(sk, f);
  }
  return { exact, skeleton, size: registry?.families.length ?? 0 };
}

/** The family whose code this is: exact logic first, then the template. */
export function familyOf(index: FamilyIndex, facts: Pick<CodeFacts, "fingerprint" | "skeleton"> | undefined): Family | undefined {
  if (!facts) return undefined;
  return (facts.fingerprint ? index.exact.get(facts.fingerprint) : undefined) ?? (facts.skeleton ? index.skeleton.get(facts.skeleton) : undefined);
}

export type WatchKind =
  /** A look-alike address delegated to an address-poisoning executor: its operator controls it. */
  | "poisoner_delegation"
  /** A wallet delegated to a labelled sweeper family: its key is compromised. */
  | "sweeper_delegation"
  /** A wallet delegated to code that forwards every incoming wei elsewhere (behaviour, no label yet). */
  | "forwarding_delegation"
  /** Where a sweeper forwards what it receives. */
  | "sweeper_destination"
  /** A contract whose logic matches a drainer-kit family. */
  | "drainer_kit_contract"
  /** The EOA that deployed a drainer-kit contract. */
  | "drainer_kit_deployer";

/** One watchlist entry (compact: stored per address in KV). */
export type WatchEntry = {
  k: WatchKind;
  /** Chain where it was observed (CAIP-2). EOA kinds hold on every EVM chain: the same key controls the address. */
  c: WatchChain;
  /** Family id. */
  f: string;
  /** First seen (unix seconds). */
  t: number;
  b?: number;
  x?: string;
  /** The delegate, the destination or the kit contract this entry derives from. */
  d?: string;
};

/** Kinds that describe who controls an EOA: they hold across chains. */
export const EOA_KINDS: ReadonlySet<WatchKind> = new Set(["poisoner_delegation", "sweeper_delegation", "forwarding_delegation", "sweeper_destination", "drainer_kit_deployer"]);

export type DelegateClass = FamilyClass | "not_forwarding" | "unprobed";
export type DelegateVerdict = {
  class: DelegateClass;
  family?: string;
  /** When the verdict was reached (unix seconds). */
  at: number;
  /** Forwarding probes run so far (behaviour is re-checked on a few authorities). */
  probes?: number;
  bytes?: number;
  /** The delegate's code kind when classified ("tiny", "logic", "delegating", ...). */
  code_kind?: string;
};

/**
 * Forwarding observed on one account generalizes to every account delegated to the same code only
 * when that code is a small, self-contained forwarder. A proxy or a larger implementation can
 * forward for one account (its own configuration) and not for others, so there the behaviour is
 * the probed account's alone: an attacker cannot flag the users of a shared delegate.
 */
export const FORWARDER_MAX_BYTES = 1024;
export function forwardingGeneralizes(verdict: Pick<DelegateVerdict, "bytes" | "code_kind">): boolean {
  return (verdict.code_kind === "tiny" || verdict.code_kind === "logic") && (verdict.bytes ?? Number.POSITIVE_INFINITY) <= FORWARDER_MAX_BYTES;
}

/** Authorizations recovered per scan, and authorities flagged per delegate per scan: bounds CPU and KV work. */
const MAX_AUTHORIZATIONS_PER_SCAN = 1000;
const MAX_FLAGGED_PER_DELEGATE = 100;

export type Creation = { address: string; deployer: string; tx: string; block: number };
export type Authorization = { delegate: string; tx: string; block: number; raw: RawAuthorization };
export type RawAuthorization = { chainId: string; address: string; nonce: string; yParity?: string; v?: string; r: string; s: string };
type RawTx = { hash: string; from: string; to?: string | null; nonce: string; type?: string; authorizationList?: RawAuthorization[] };
export type RawBlock = { number: string; timestamp: string; transactions: Array<RawTx | string> };

const ZERO = "0x0000000000000000000000000000000000000000";

/** Top-level contract creations and EIP-7702 authorizations valid for this chain. */
export function blockActivity(block: RawBlock, chain: WatchChain): { creations: Creation[]; authorizations: Authorization[] } {
  const number = Number.parseInt(block.number, 16);
  const creations: Creation[] = [];
  const authorizations: Authorization[] = [];
  for (const tx of block.transactions) {
    if (typeof tx === "string") continue;
    if (!tx.to) {
      try {
        creations.push({ address: getContractAddress({ from: tx.from as Hex, nonce: BigInt(tx.nonce), opcode: "CREATE" }).toLowerCase(), deployer: tx.from.toLowerCase(), tx: tx.hash, block: number });
      } catch {
        // malformed transaction: nothing to record
      }
    }
    if (tx.type === "0x4") {
      for (const a of tx.authorizationList ?? []) {
        const chainId = Number.parseInt(a.chainId, 16);
        // 0 = valid on every chain. The protocol skips anything else silently.
        if (chainId !== 0 && chainId !== CHAIN_IDS[chain]) continue;
        authorizations.push({ delegate: a.address.toLowerCase(), tx: tx.hash, block: number, raw: a });
      }
    }
  }
  return { creations, authorizations };
}

/** The EOA that signed an authorization; null when the signature does not recover. */
export async function authorityOf(a: RawAuthorization): Promise<string | null> {
  try {
    const yParity = Number.parseInt(a.yParity ?? a.v ?? "0x0", 16);
    const authority = await recoverAuthorizationAddress({
      authorization: { address: a.address as Hex, chainId: Number.parseInt(a.chainId, 16), nonce: Number.parseInt(a.nonce, 16), r: a.r as Hex, s: a.s as Hex, yParity },
    });
    return authority.toLowerCase();
  } catch {
    return null;
  }
}

/** Runs one eth_simulateV1 call; resolves to the raw simulated call result, or null when unavailable. */
export type SimulateCall = (call: { from: string; to: string; value: string; data: string }, stateOverrides: Record<string, { balance: string }>) => Promise<{ status?: string; logs?: Array<{ address: string; topics: string[]; data: string }> } | null>;

const NATIVE = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const PROBE_SENDER = "0x000000000000000000000000000000000000dEaD";
const PROBE_VALUE = 10n ** 16n;

export type ForwardingProbe = { forwards: boolean; destinations: string[] };

/**
 * Sends 0.01 ETH (simulated) to `authority` and follows it: a delegate that passes at
 * least half of it on to another address, in the same call, is an auto-forwarder.
 * Null when the simulation is unavailable.
 */
export async function probeForwarding(simulate: SimulateCall, authority: string): Promise<ForwardingProbe | null> {
  const a = authority.toLowerCase();
  const res = await simulate({ from: PROBE_SENDER, to: a, value: `0x${PROBE_VALUE.toString(16)}`, data: "0x" }, { [PROBE_SENDER]: { balance: `0x${(PROBE_VALUE * 2n).toString(16)}` } }).catch(() => null);
  if (!res) return null;
  if (res.status !== "0x1") return { forwards: false, destinations: [] };
  let forwarded = 0n;
  const destinations = new Set<string>();
  for (const l of res.logs ?? []) {
    if (l.address.toLowerCase() !== NATIVE || l.topics[0] !== TRANSFER_TOPIC || l.topics.length < 3) continue;
    const from = `0x${(l.topics[1] as string).slice(26)}`.toLowerCase();
    const to = `0x${(l.topics[2] as string).slice(26)}`.toLowerCase();
    if (from !== a || to === a || to === PROBE_SENDER.toLowerCase()) continue;
    forwarded += BigInt(l.data);
    destinations.add(to);
  }
  return { forwards: forwarded * 2n >= PROBE_VALUE, destinations: [...destinations] };
}

export type ScanDeps = {
  chain: WatchChain;
  /** Batched JSON-RPC (eth_getCode, eth_getStorageAt, ...) in request order; failed items are undefined. */
  call: BatchCall;
  simulate: SimulateCall;
  families: FamilyIndex;
  /** Known delegate verdicts (mutated in place: the caller persists them). */
  delegates: Map<string, DelegateVerdict>;
  /** Fingerprints that must never be classified as malicious (guarded implementations). */
  guarded?: ReadonlySet<string>;
  now?: () => number;
  /** Probes per scan (each is one eth_simulateV1 call). */
  maxProbes?: number;
};

export type ScanResult = {
  entries: Array<{ address: string; entry: WatchEntry }>;
  /** Families the scan learned (auto-forwarding delegates): the caller adds them to the registry. */
  learned: Family[];
  stats: { blocks: number; creations: number; authorizations: number; delegates_new: number; probes: number; kit_contracts: number; flagged_authorities: number; degraded: number };
};

const REPROBE_AFTER_S = 6 * 3600;
const MAX_PROBES_PER_DELEGATE = 3;

/** Scans already-fetched blocks: classifies new contracts and every delegate authorized in them. */
export async function scanBlocks(blocks: RawBlock[], deps: ScanDeps): Promise<ScanResult> {
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const maxProbes = deps.maxProbes ?? 12;
  const entries: ScanResult["entries"] = [];
  const learned: Family[] = [];
  const stats: ScanResult["stats"] = { blocks: blocks.length, creations: 0, authorizations: 0, delegates_new: 0, probes: 0, kit_contracts: 0, flagged_authorities: 0, degraded: 0 };
  const creations: Creation[] = [];
  const authorizations: Authorization[] = [];
  const blockTime = new Map<number, number>();
  const seenSignatures = new Set<string>();
  for (const b of blocks) {
    const act = blockActivity(b, deps.chain);
    creations.push(...act.creations);
    // The same signed authorization repeated (a replay inside the attacker's own transaction) is one authorization.
    for (const a of act.authorizations) {
      const key = `${a.raw.r}|${a.raw.s}`;
      if (seenSignatures.has(key) || authorizations.length >= MAX_AUTHORIZATIONS_PER_SCAN) continue;
      seenSignatures.add(key);
      authorizations.push(a);
    }
    blockTime.set(Number.parseInt(b.number, 16), Number.parseInt(b.timestamp, 16));
  }
  stats.creations = creations.length;
  stats.authorizations = authorizations.length;
  const seenAt = (block: number) => blockTime.get(block) ?? now();
  const isGuarded = (f: CodeFacts) => !!f.fingerprint && (deps.guarded?.has(f.fingerprint) ?? false);

  const reprobeDue = (v: DelegateVerdict | undefined) => !!v && v.class === "not_forwarding" && (v.probes ?? 0) < MAX_PROBES_PER_DELEGATE && now() - v.at > REPROBE_AFTER_S;

  // --- new contracts: kit families, and delegates deployed before their first use ---
  const needCode = (d: string) => d !== ZERO && (!deps.delegates.has(d) || reprobeDue(deps.delegates.get(d)));
  const codeTargets = [...new Set([...creations.map((c) => c.address), ...authorizations.map((a) => a.delegate).filter(needCode)])];
  const facts = new Map<string, CodeFacts>();
  for (let i = 0; i < codeTargets.length; i += 50) {
    const chunk = codeTargets.slice(i, i + 50);
    const codes = await deps.call(chunk.map((a) => ({ method: "eth_getCode", params: [a, "latest"] }))).catch(() => [] as unknown[]);
    chunk.forEach((a, k) => {
      if (typeof codes[k] === "string") facts.set(a, codeFacts(codes[k] as string));
      // Code that could not be read is unknown, never "no code": it is retried when seen again.
      else stats.degraded++;
    });
  }
  // Proxies are judged by what they run (as at evaluation time).
  const created = new Map(creations.filter((c) => facts.get(c.address)?.kind === "delegating").map((c) => [c.address, facts.get(c.address) as CodeFacts]));
  if (created.size) await resolveIndirection(created, deps.call).catch(() => undefined);
  for (const c of creations) {
    const f = facts.get(c.address);
    if (!f || isGuarded(f)) continue;
    const family = familyOf(deps.families, f) ?? familyOf(deps.families, f.implementation_fingerprint ? { fingerprint: f.implementation_fingerprint, ...(f.implementation_skeleton ? { skeleton: f.implementation_skeleton } : {}) } : undefined);
    if (!family) continue;
    const t = seenAt(c.block);
    // A new poisoner or sweeper deployment is known before anyone delegates to it.
    if (family.class !== "drainer_kit" && !deps.delegates.has(c.address)) deps.delegates.set(c.address, { class: family.class, family: family.id, at: t, bytes: f.bytes });
    // Behaviour-only families describe what a delegate does, not who deployed it.
    if (family.class === "forwarder") continue;
    stats.kit_contracts++;
    entries.push({ address: c.address, entry: { k: "drainer_kit_contract", c: deps.chain, f: family.id, t, b: c.block, x: c.tx } });
    entries.push({ address: c.deployer, entry: { k: "drainer_kit_deployer", c: deps.chain, f: family.id, t, b: c.block, x: c.tx, d: c.address } });
  }

  // --- delegates: known families, then behaviour ---
  const byDelegate = new Map<string, Authorization[]>();
  for (const a of authorizations) if (a.delegate !== ZERO) byDelegate.set(a.delegate, [...(byDelegate.get(a.delegate) ?? []), a]);
  for (const [delegate, auths] of byDelegate) {
    let verdict = deps.delegates.get(delegate);
    if (!verdict) {
      const f = facts.get(delegate);
      // Its code could not be read this time: no verdict is cached, so it is classified when seen again.
      if (!f) continue;
      stats.delegates_new++;
      const family = f && !isGuarded(f) ? familyOf(deps.families, f) : undefined;
      verdict = family ? { class: family.class, family: family.id, at: now(), bytes: f.bytes, code_kind: f.kind } : { class: "unprobed", at: now(), bytes: f.bytes, code_kind: f.kind };
      // Code that cannot run as a delegate (empty, a 7702 designator itself) is not a threat.
      if (!family && (f.kind === "none" || f.kind === "delegated")) verdict = { class: "not_forwarding", at: now(), bytes: f.bytes, code_kind: f.kind, probes: MAX_PROBES_PER_DELEGATE };
      deps.delegates.set(delegate, verdict);
    }
    const probeDue = (verdict.class === "unprobed" || reprobeDue(verdict)) && stats.probes < maxProbes;
    if (probeDue) {
      const authority = await firstDelegatedAuthority(auths, delegate, deps.call);
      if (authority) {
        stats.probes++;
        const probe = await probeForwarding(deps.simulate, authority.address);
        if (probe) {
          // Facts from this run, or those recorded with the verdict (an older verdict without a code kind never generalizes).
          const f = facts.get(delegate) ?? (verdict.bytes !== undefined ? ({ kind: verdict.code_kind, bytes: verdict.bytes } as unknown as CodeFacts) : undefined);
          const base = { at: now(), probes: (verdict.probes ?? 0) + 1, ...(f ? { bytes: f.bytes, code_kind: f.kind } : {}) };
          if (probe.forwards && !(f && isGuarded(f)) && f && forwardingGeneralizes({ bytes: f.bytes, code_kind: f.kind })) {
            // A small, self-contained forwarder: its logic becomes a family (redeployments are
            // known on sight); code with no logic fingerprint is known by the delegate's address.
            let id = `fwd-at-${delegate.slice(2, 14)}`;
            if (f.fingerprint) {
              const family: Family = { id: `fwd-${f.fingerprint.slice(0, 12)}`, class: "forwarder", exact: [f.fingerprint], skeleton: [], sources: ["behaviour:auto-forward"], first_seen: new Date(now() * 1000).toISOString() };
              learned.push(family);
              deps.families.exact.set(f.fingerprint, family);
              id = family.id;
            }
            verdict = { class: "forwarder", family: id, ...base };
          } else {
            verdict = { class: "not_forwarding", ...base };
            // Forwarding by a proxy or a larger implementation is the probed account's own behaviour.
            if (probe.forwards && !(f && isGuarded(f))) {
              stats.flagged_authorities++;
              entries.push({ address: authority.address, entry: { k: "forwarding_delegation", c: deps.chain, f: `fwd-acct-${delegate.slice(2, 14)}`, t: seenAt(authority.auth.block), b: authority.auth.block, x: authority.auth.tx, d: delegate } });
            }
          }
          deps.delegates.set(delegate, verdict);
          // The addresses a forwarder sends to are chosen by whoever wrote it: they are never
          // recorded against those addresses (anyone could otherwise flag a merchant's wallet).
        }
      }
    }
    if (verdict.class === "not_forwarding" || verdict.class === "unprobed" || verdict.class === "drainer_kit") continue;
    const kind: WatchKind = verdict.class === "poisoner" ? "poisoner_delegation" : verdict.class === "sweeper" ? "sweeper_delegation" : "forwarding_delegation";
    // Only authorities whose account delegates to it right now: a stale or replayed authorization flags no one.
    const recovered: Array<{ address: string; auth: Authorization }> = [];
    for (const a of auths.slice(0, MAX_FLAGGED_PER_DELEGATE)) {
      const authority = await authorityOf(a.raw);
      if (authority && !recovered.some((r) => r.address === authority)) recovered.push({ address: authority, auth: a });
    }
    if (!recovered.length) continue;
    const codes = await deps.call(recovered.map((r) => ({ method: "eth_getCode", params: [r.address, "latest"] }))).catch(() => [] as unknown[]);
    const designator = `0xef0100${delegate.slice(2)}`;
    recovered.forEach(({ address, auth }, i) => {
      const code = codes[i];
      if (typeof code !== "string") {
        stats.degraded++;
        return;
      }
      if (code.toLowerCase() !== designator) return;
      stats.flagged_authorities++;
      entries.push({ address, entry: { k: kind, c: deps.chain, f: verdict?.family ?? "", t: seenAt(auth.block), b: auth.block, x: auth.tx, d: delegate } });
    });
  }
  return { entries, learned, stats };
}

/** The first authority (in block order) whose code still designates `delegate`: only it can be probed. */
async function firstDelegatedAuthority(auths: Authorization[], delegate: string, call: BatchCall): Promise<{ address: string; auth: Authorization } | null> {
  const candidates: Array<{ address: string; auth: Authorization }> = [];
  for (const auth of auths.slice(0, 4)) {
    const address = await authorityOf(auth.raw);
    if (address) candidates.push({ address, auth });
  }
  if (!candidates.length) return null;
  const codes = await call(candidates.map((c) => ({ method: "eth_getCode", params: [c.address, "latest"] }))).catch(() => [] as unknown[]);
  const designator = `0xef0100${delegate.slice(2)}`;
  return candidates.find((_, i) => typeof codes[i] === "string" && (codes[i] as string).toLowerCase() === designator) ?? null;
}

/** Merges a scan's entries into one per address, keeping the earliest sighting and the strongest kind. */
export function mergeEntries(list: ScanResult["entries"]): Map<string, WatchEntry> {
  const out = new Map<string, WatchEntry>();
  for (const { address, entry } of list) {
    const prev = out.get(address);
    if (!prev || KIND_RANK[entry.k] > KIND_RANK[prev.k] || (KIND_RANK[entry.k] === KIND_RANK[prev.k] && entry.t < prev.t)) out.set(address, entry);
  }
  return out;
}

/** Stronger evidence wins when one address is seen twice: labelled families over behaviour. */
export const KIND_RANK: Record<WatchKind, number> = {
  forwarding_delegation: 1,
  sweeper_destination: 2,
  drainer_kit_deployer: 3,
  drainer_kit_contract: 4,
  sweeper_delegation: 5,
  poisoner_delegation: 6,
};

/** Evaluation-time access to the kit watch (deploy/kit-watch.ts in production). */
export type KitWatchLookup = {
  families(): Promise<FamilyIndex>;
  /** When the watch last scanned (ISO): stated with every verdict that consulted it. */
  asOf(): Promise<string>;
  /** Watchlist entries for these addresses that hold on `network`. */
  addresses(addresses: string[], network: string): Promise<Map<string, WatchEntry>>;
  /** The scan's verdict on an EIP-7702 delegate (covers delegates with no logic fingerprint). */
  delegate?(network: string, delegate: string): Promise<DelegateVerdict | undefined>;
};

/** What delegating to a delegate the scan classified makes an EOA; null when it is not a threat. */
export function kindForDelegate(verdict: DelegateVerdict | undefined): WatchKind | null {
  if (!verdict) return null;
  if (verdict.class === "poisoner") return "poisoner_delegation";
  if (verdict.class === "sweeper") return "sweeper_delegation";
  // Behaviour seen on one account applies to every account delegated to the same code only for small forwarders.
  if (verdict.class === "forwarder") return forwardingGeneralizes(verdict) ? "forwarding_delegation" : null;
  return null;
}

export type KitWatchHit = {
  address: string;
  role: "subject" | "called" | "recipient" | "spender";
  kind: WatchKind;
  family: string;
  /** Where the entry was observed; omitted for code matches (they hold where the code runs). */
  chain?: string;
  first_seen?: string;
  /** watchlist: observed by the scan; code: the address runs a family's code right now. */
  via: "watchlist" | "code";
};

/** What running a family's code makes an address: a delegated EOA is its delegate's victim or tool. */
export function kindForCode(family: Family, facts: Pick<CodeFacts, "kind">): WatchKind | null {
  if (facts.kind === "delegated") {
    if (family.class === "poisoner") return "poisoner_delegation";
    if (family.class === "sweeper") return "sweeper_delegation";
    if (family.class === "forwarder") return "forwarding_delegation";
    return "drainer_kit_contract";
  }
  // A behaviour-learned delegate says nothing about contracts that share its code.
  return family.class === "forwarder" ? null : "drainer_kit_contract";
}

/** The family of the code an address runs: its own logic, or its delegate's / implementation's. */
export function runningFamily(index: FamilyIndex, facts: CodeFacts | undefined): Family | undefined {
  if (!facts) return undefined;
  return familyOf(index, facts) ?? (facts.implementation_fingerprint ? familyOf(index, { fingerprint: facts.implementation_fingerprint, ...(facts.implementation_skeleton ? { skeleton: facts.implementation_skeleton } : {}) }) : undefined);
}
