/**
 * Insight and dialog UI. Pure: (decoded request, outcome) -> JSX + severity.
 */
import type { JSXElement } from "@metamask/snaps-sdk/jsx";
import {
  Address,
  Banner,
  Bold,
  Box,
  Copyable,
  Divider,
  Heading,
  Link,
  Row,
  Section,
  Text,
} from "@metamask/snaps-sdk/jsx";

import type { BatchItem, CheckOutcome, Evidence, FeedEvidence, Tier, Verdict } from "./request";
import { API_ORIGIN, JWKS_URL } from "./request";
import type { Candidate, Decoded, InteractionType, Role } from "./util";
import { capText, shortAddress } from "./util";

export type RequestKind = "transaction" | "signature";

export type InsightResult = {
  content: JSXElement;
  severity?: "critical";
};

type Child = JSXElement | null;

/** The address a verdict is about, with the details shown next to it. */
type Subject = {
  address?: string;
  role?: Role;
  interaction?: InteractionType;
  unlimited?: boolean;
  amountLabel?: string;
};

const TIER_COPY: Record<Tier, { verdict: string; advice: string }> = {
  low: {
    verdict: "No significant risk signals found.",
    advice: "Still verify the counterparty and amount before you confirm.",
  },
  medium: {
    verdict: "Some risk signals present.",
    advice: "Review carefully before you confirm.",
  },
  high: {
    verdict: "High risk detected.",
    advice: "We recommend you do NOT proceed.",
  },
  critical: {
    verdict: "Critical risk detected.",
    advice: "Do NOT proceed. This matches fraud, drainer or laundering patterns.",
  },
};

const TIER_RANK: Record<Tier, number> = { low: 1, medium: 2, high: 3, critical: 4 };

const ROLE_LABEL: Record<Role, string> = {
  recipient: "recipient",
  spender: "spender",
  operator: "operator",
  delegate: "delegate",
  contract: "contract",
  signer: "signer (you)",
  counterparty: "counterparty",
};

/** Interactions that grant spending rights (backend caps these on EOAs). */
const APPROVAL_TYPES = new Set<InteractionType>(["token_approval", "nft_approval", "permit_signature"]);

// Maps (not plain objects): keys come from the server, and a plain-object
// lookup of e.g. "constructor" would return a function.
const CATEGORY_LABELS = new Map<string, string>([
  ["approval_to_eoa", "Approval to a regular wallet (EOA)"],
  ["phishing_domain", "Phishing domain"],
  ["known_scam_address", "Known scam address"],
  ["sanctioned_address", "Sanctioned address"],
  ["new_address", "New address (no history)"],
]);

/**
 * Human-readable category label ("known_scam_address" -> "Known scam address").
 *
 * @param category - The category id.
 * @returns The label.
 */
export function categoryLabel(category: string): string {
  const known = CATEGORY_LABELS.get(category);
  if (known) return known;
  const words = category.replace(/[_-]+/gu, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

const FEED_HIT_LABELS = new Map<string, string>([
  ["metamask-phishing-detect", "Listed on MetaMask phishing list"],
  ["scamsniffer-addresses", "Known scam address (ScamSniffer)"],
  ["scamsniffer-domains", "Listed phishing domain (ScamSniffer)"],
]);

/**
 * Loud line for a threat-feed hit.
 *
 * @param feed - The feed evidence with status "hit".
 * @returns The label.
 */
export function feedHitLabel(feed: FeedEvidence): string {
  return FEED_HIT_LABELS.get(feed.source) ?? `Listed by ${feed.source}${feed.kind ? ` (${feed.kind})` : ""}`;
}

function compact(children: Child[]): JSXElement[] {
  return children.filter((child): child is JSXElement => child !== null);
}

function sentence(text: string): string {
  const trimmed = text.trim();
  const capitalized = trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
  return /[.!?]$/u.test(capitalized) ? capitalized : `${capitalized}.`;
}

function primarySubject(decoded: Decoded): Subject {
  return {
    address: decoded.counterparty,
    role: decoded.role,
    interaction: decoded.interaction.type,
    unlimited: decoded.unlimited,
    amountLabel: decoded.amountLabel,
  };
}

function candidateSubject(candidate: Candidate): Subject {
  return {
    address: candidate.address,
    role: candidate.role,
    interaction: candidate.interaction.type,
    unlimited: candidate.unlimited,
    amountLabel: candidate.amountLabel,
  };
}

function amountRowLabel(subject: Subject): string {
  if (subject.role === "operator") return "Scope";
  if (subject.role === "spender") return "Allowance";
  return "Amount";
}

/** What was decoded and which address was checked (or would have been). */
function subjectSection(decoded: Decoded, subject: Subject, host: string | undefined, checked: boolean): JSXElement {
  const rows: Child[] = [
    <Row label="Action">
      <Text>{decoded.action}</Text>
    </Row>,
    subject.address && subject.role ? (
      <Row
        label={`${checked ? "Checked" : "Not checked"}: ${ROLE_LABEL[subject.role]}`}
        variant={checked ? "default" : "warning"}
        tooltip="The address this request gives rights or value to."
      >
        <Address address={subject.address as `0x${string}`} />
      </Row>
    ) : null,
    subject.unlimited ? (
      <Row label={amountRowLabel(subject)} variant="critical">
        <Text>
          <Bold>{subject.amountLabel ?? "UNLIMITED"}</Bold>
        </Text>
      </Row>
    ) : subject.amountLabel ? (
      <Row label={amountRowLabel(subject)}>
        <Text>{subject.amountLabel}</Text>
      </Row>
    ) : null,
    host ? (
      <Row label="Site">
        <Text>{host}</Text>
      </Row>
    ) : null,
    decoded.chain ? (
      <Row label="Chain">
        <Text>{decoded.chain}</Text>
      </Row>
    ) : null,
  ];
  return <Section>{compact(rows)}</Section>;
}

function signerNote(subject: Subject): Child {
  if (subject.role !== "signer") return null;
  return (
    <Text color="warning">
      No counterparty address was found in this request, so your own signing address was checked instead.
    </Text>
  );
}

function dangerBanner(danger: string[]): Child {
  if (danger.length === 0) return null;
  return (
    <Banner title="Dangerous request — do not sign" severity="danger">
      {danger.slice(0, 4).map((reason) => (
        <Text>{capText(sentence(reason), 220)}</Text>
      ))}
    </Banner>
  );
}

function warningsBanner(warnings: string[]): Child {
  if (warnings.length === 0) return null;
  return (
    <Banner title="Warnings from decoding this request" severity="warning">
      {warnings.slice(0, 4).map((warning) => (
        <Text>{capText(sentence(warning), 200)}</Text>
      ))}
    </Banner>
  );
}

function evidenceRows(evidence: Evidence | undefined, subject: Subject): Child[] {
  if (!evidence) return [];
  const rows: Child[] = [];
  const { sanctions, domain, onchain } = evidence;
  if (sanctions) {
    rows.push(
      sanctions.status === "listed" ? (
        <Row label="OFAC SDN" variant="critical">
          <Text>
            <Bold>{`LISTED${sanctions.entity ? `: ${sanctions.entity}` : ""}`}</Bold>
            {` (list as of ${sanctions.as_of})`}
          </Text>
        </Row>
      ) : (
        <Row label="OFAC SDN">
          <Text>{`Not listed (list as of ${sanctions.as_of})`}</Text>
        </Row>
      ),
    );
  }
  if (domain) {
    const brand = domain.brand ?? "a known brand";
    if (domain.impersonation === "strong") {
      rows.push(
        <Row label="Site check" variant="critical">
          <Text>{`${domain.host} impersonates ${brand}`}</Text>
        </Row>,
      );
    } else if (domain.impersonation === "weak") {
      rows.push(
        <Row label="Site check" variant="warning">
          <Text>{`${domain.host}: possible impersonation of ${brand}`}</Text>
        </Row>,
      );
    } else {
      rows.push(
        <Row label="Site check">
          <Text>
            {domain.official
              ? `${domain.host}: official ${domain.brand ? `${domain.brand} ` : ""}domain`
              : `${domain.host}: no impersonation signals`}
          </Text>
        </Row>,
      );
    }
    if (domain.impersonation !== "none" && domain.signals.length > 0) {
      rows.push(<Text color="muted">{`Site signals: ${domain.signals.join("; ")}`}</Text>);
    }
  }
  if (onchain) {
    if (onchain.status === "ok") {
      if (onchain.activity === "none") {
        rows.push(
          <Row label="On-chain" variant="warning">
            <Text>New address: no on-chain activity found</Text>
          </Row>,
        );
      } else if (onchain.activity === "some") {
        rows.push(
          <Row label="On-chain">
            <Text>{`Active address${onchain.tx_count !== undefined ? ` (${onchain.tx_count} transactions)` : ""}`}</Text>
          </Row>,
        );
      }
      if (onchain.is_contract === true) {
        rows.push(
          <Row label="Type">
            <Text>Counterparty is a contract</Text>
          </Row>,
        );
      } else if (onchain.is_contract === false && subject.interaction && APPROVAL_TYPES.has(subject.interaction)) {
        const who = subject.role === "operator" ? "Operator" : "Spender";
        rows.push(
          <Row label="Type" variant="critical">
            <Text>{`${who} is a regular wallet (EOA), not a contract — typical of drainers`}</Text>
          </Row>,
        );
      }
    } else {
      rows.push(
        <Row label="On-chain">
          <Text>{onchain.status === "unsupported" ? "On-chain check not supported on this network" : "On-chain data unavailable"}</Text>
        </Row>,
      );
    }
  }
  return rows;
}

function attestation(verdict: Verdict): Child[] {
  const keysUrl = verdict.jwks_url ?? JWKS_URL;
  if (!verdict.jws) {
    return [<Text color="muted">This verdict was not signed.</Text>, <Link href={keysUrl}>Provider public keys (JWKS)</Link>];
  }
  return [
    <Text color="muted">Signed verdict (JWS). Verify it independently against the provider's public keys:</Text>,
    <Copyable value={verdict.jws} />,
    <Link href={keysUrl}>Provider public keys (JWKS)</Link>,
  ];
}

function feedLines(feeds: FeedEvidence[] | undefined): { hits: FeedEvidence[]; summary?: string } {
  if (!feeds) return { hits: [] };
  const hits = feeds.filter((feed) => feed.status === "hit");
  const clear = feeds.filter((feed) => feed.status === "clear").length;
  const unavailable = feeds.filter((feed) => feed.status === "unavailable").length;
  const parts = [clear > 0 ? `${clear} clear` : "", unavailable > 0 ? `${unavailable} unavailable` : ""].filter(Boolean);
  return { hits, summary: parts.length > 0 ? `Threat feeds: ${parts.join(", ")}` : undefined };
}

/** Sanctions or threat-feed hit, or a high/critical tier. */
function isAlarming(verdict: Verdict): boolean {
  return (
    verdict.tier === "high" ||
    verdict.tier === "critical" ||
    verdict.evidence?.sanctions?.status === "listed" ||
    (verdict.evidence?.feeds ?? []).some((feed) => feed.status === "hit")
  );
}

/** Higher = worse: list hits, then tier (unknown counts as medium), then lower score. */
function riskKey(verdict: Verdict): [number, number] {
  const listed =
    verdict.evidence?.sanctions?.status === "listed" || (verdict.evidence?.feeds ?? []).some((feed) => feed.status === "hit");
  return [(listed ? 10 : 0) + TIER_RANK[verdict.tier ?? "medium"], 100 - (verdict.score ?? 50)];
}

function verdictLine(verdict: Verdict): string {
  return `score ${verdict.score !== undefined ? verdict.score : "?"}/100 · ${verdict.tier ?? "unknown tier"}`;
}

type Also = { candidate: Candidate; item: BatchItem };

function alsoCheckedSection(entries: Also[]): Child {
  if (entries.length === 0) return null;
  return (
    <Section>
      {entries.map(({ candidate, item }) => (
        <Row
          label={`Also checked: ${ROLE_LABEL[candidate.role]}`}
          variant={item.status !== "ok" ? "warning" : isAlarming(item.verdict) ? "critical" : "default"}
        >
          <Text>{`${shortAddress(candidate.address)} · ${item.status === "ok" ? verdictLine(item.verdict) : "NOT verified"}`}</Text>
        </Row>
      ))}
    </Section>
  );
}

function verdictContent(decoded: Decoded, verdict: Verdict, host: string | undefined, subject: Subject, also: Also[] = []): InsightResult {
  const sanctions = verdict.evidence?.sanctions;
  const sanctioned = sanctions?.status === "listed";
  const feeds = feedLines(verdict.evidence?.feeds);
  const listedInFeed = feeds.hits.length > 0;
  const localDanger = decoded.danger.length > 0;
  // An unknown or missing tier never gets the "no significant risk" copy, and a
  // sanctions / threat-feed hit or locally proven danger gets the critical copy.
  const copyTier: Tier = sanctioned || listedInFeed || localDanger ? "critical" : (verdict.tier ?? "medium");
  const copy = TIER_COPY[copyTier];
  const categories = verdict.categories.length > 0 ? verdict.categories.map(categoryLabel).join(", ") : undefined;
  const alarmingOther = also.some((entry) => entry.item.status === "ok" && isAlarming(entry.item.verdict));

  const children: Child[] = [
    sanctioned ? (
      <Banner title="OFAC-sanctioned address — do not proceed" severity="danger">
        <Text>
          {`${sanctions?.entity ?? "This address"} is on the OFAC SDN sanctions list (list as of ${sanctions?.as_of ?? "unknown date"}).`}
        </Text>
      </Banner>
    ) : null,
    listedInFeed ? (
      <Banner title="Listed as malicious — do not proceed" severity="danger">
        {feeds.hits.slice(0, 4).map((feed) => (
          <Text>
            <Bold>{feedHitLabel(feed)}</Bold>
            {feed.as_of ? ` (as of ${feed.as_of})` : ""}
          </Text>
        ))}
      </Banner>
    ) : null,
    dangerBanner(decoded.danger),
    <Heading>{`x402check · ${verdictLine(verdict)}`}</Heading>,
    <Text>
      <Bold>{copy.verdict}</Bold> {copy.advice}
    </Text>,
    subjectSection(decoded, subject, host, true),
    also.length > 0 ? <Text color="muted">{`${also.length + 1} addresses were checked; the worst verdict is shown.`}</Text> : null,
    alsoCheckedSection(also),
    signerNote(subject),
    warningsBanner(decoded.warnings),
  ];
  const facts: Child[] = [
    ...evidenceRows(verdict.evidence, subject),
    categories ? (
      <Row label="Categories">
        <Text>{categories}</Text>
      </Row>
    ) : null,
    feeds.summary ? <Text color="muted">{feeds.summary}</Text> : null,
  ];
  if (compact(facts).length > 0) children.push(<Section>{compact(facts)}</Section>);
  children.push(<Divider />, ...attestation(verdict));
  const critical = isAlarming(verdict) || alarmingOther || localDanger;
  return {
    content: <Box>{compact(children)}</Box>,
    ...(critical ? { severity: "critical" as const } : {}),
  };
}

function failureContent(
  decoded: Decoded,
  host: string | undefined,
  title: string,
  explanation: string,
  also: Also[] = [],
): InsightResult {
  const localDanger = decoded.danger.length > 0;
  const alarming = also.some((entry) => entry.item.status === "ok" && isAlarming(entry.item.verdict));
  return {
    content: (
      <Box>
        {compact([
          dangerBanner(decoded.danger),
          <Heading>{`x402check · ${title}`}</Heading>,
          <Text>{explanation}</Text>,
          subjectSection(decoded, primarySubject(decoded), host, false),
          alsoCheckedSection(also),
          signerNote(primarySubject(decoded)),
          warningsBanner(decoded.warnings),
        ])}
      </Box>
    ),
    ...(localDanger || alarming ? { severity: "critical" as const } : {}),
  };
}

function batchCandidates(decoded: Decoded): Candidate[] {
  const primary: Candidate = {
    address: decoded.counterparty ?? "",
    role: decoded.role ?? "counterparty",
    interaction: decoded.interaction,
    rank: 0,
    unlimited: decoded.unlimited,
    amountLabel: decoded.amountLabel,
  };
  return [primary, ...decoded.others];
}

function renderBatch(decoded: Decoded, items: BatchItem[], kind: RequestKind, host: string | undefined): InsightResult {
  const candidates = batchCandidates(decoded);
  const entries: Also[] = items
    .map((item, index) => ({ item, candidate: candidates[index] }))
    .filter((entry): entry is Also => entry.candidate !== undefined);
  let worst: (Also & { item: { status: "ok"; verdict: Verdict } }) | undefined;
  for (const entry of entries) {
    if (entry.item.status !== "ok") continue;
    if (!worst) {
      worst = entry as Also & { item: { status: "ok"; verdict: Verdict } };
      continue;
    }
    const [a1, a2] = riskKey(entry.item.verdict);
    const [b1, b2] = riskKey(worst.item.verdict);
    if (a1 > b1 || (a1 === b1 && a2 > b2)) worst = entry as Also & { item: { status: "ok"; verdict: Verdict } };
  }
  const failed = entries.filter((entry) => entry.item.status !== "ok");
  if (!worst || (failed.length > 0 && !isAlarming(worst.item.verdict))) {
    // Fail closed: an address that could not be verified is never an all-clear.
    return failureContent(
      decoded,
      host,
      "verification failed — NOT verified",
      `${failed.length} of ${entries.length} addresses in this ${kind} could not be verified, so it was NOT verified.`,
      entries,
    );
  }
  const others = entries.filter((entry) => entry !== worst);
  return verdictContent(decoded, worst.item.verdict, host, candidateSubject(worst.candidate), others);
}

/**
 * Renders the result of a risk check.
 *
 * @param decoded - The decoded request.
 * @param outcome - The check outcome.
 * @param kind - Transaction or signature (for copy).
 * @param host - Hostname of the requesting site.
 * @returns Content and optional severity.
 */
export function renderOutcome(decoded: Decoded, outcome: CheckOutcome, kind: RequestKind, host?: string): InsightResult {
  switch (outcome.kind) {
    case "ok":
      return verdictContent(decoded, outcome.verdict, host, primarySubject(decoded));
    case "batch":
      return renderBatch(decoded, outcome.items, kind, host);
    case "network_error":
      return failureContent(
        decoded,
        host,
        "unavailable — NOT verified",
        `The risk service could not be reached${outcome.timedOut ? " in time" : ""}, so this ${kind} was NOT checked. This is not an all-clear: proceed only if you fully trust the counterparty.`,
      );
    case "quota":
      return failureContent(
        decoded,
        host,
        "free daily checks used up — this was NOT checked",
        `This install has used all of its free daily risk checks, so this ${kind} was NOT checked. The free quota resets daily.`,
      );
    case "http_error":
      return failureContent(
        decoded,
        host,
        "check failed — NOT verified",
        `The risk service returned an error (HTTP ${outcome.status}), so this ${kind} was NOT verified.`,
      );
    case "invalid_response":
      return failureContent(decoded, host, "check failed — NOT verified", `The risk service returned an unreadable response, so this ${kind} was NOT verified.`);
    case "unverified":
    default:
      return failureContent(
        decoded,
        host,
        "verification failed — NOT verified",
        `The provider could not evaluate this request and failed closed. This ${kind} was NOT verified.`,
      );
  }
}

/**
 * Renders a request that is not sent to the server (e.g. contract deployment).
 * Locally proven danger still makes it critical.
 *
 * @param decoded - The decoded request.
 * @param host - Hostname of the requesting site.
 * @returns Content and optional severity.
 */
export function renderLocalOnly(decoded: Decoded, host?: string): InsightResult {
  return {
    content: (
      <Box>
        {compact([
          dangerBanner(decoded.danger),
          <Heading>x402check · not checked</Heading>,
          <Text>{decoded.localNote ?? "There is no counterparty address to check. Nothing was sent to x402check."}</Text>,
          subjectSection(decoded, primarySubject(decoded), host, false),
          warningsBanner(decoded.warnings),
        ])}
      </Box>
    ),
    ...(decoded.danger.length > 0 ? { severity: "critical" as const } : {}),
  };
}

/**
 * Static content for an unexpected internal error: never throws, never an
 * all-clear.
 *
 * @param kind - Transaction or signature (for copy).
 * @returns Content with critical severity.
 */
export function renderInternalError(kind: RequestKind): InsightResult {
  return {
    content: (
      <Box>
        <Heading>x402check · check failed — NOT verified</Heading>
        <Text>
          {`x402check hit an internal error while analyzing this ${kind}, so it was NOT verified. Do not proceed unless you fully trust the site and the counterparty.`}
        </Text>
      </Box>
    ),
    severity: "critical",
  };
}

/**
 * Runs an insight computation and never throws: any unexpected error (e.g. a
 * RangeError from a hostile payload) becomes the critical "check failed — NOT
 * verified" insight instead of a MetaMask error screen.
 *
 * @param kind - Transaction or signature (for copy).
 * @param work - The insight computation.
 * @returns The insight.
 */
export async function withFallback(kind: RequestKind, work: () => Promise<InsightResult>): Promise<InsightResult> {
  try {
    return await work();
  } catch {
    return renderInternalError(kind);
  }
}

/**
 * One-time privacy disclosure shown on install (and after updating from a
 * version that did not show it).
 *
 * @returns Dialog content.
 */
export function disclosureContent(): JSXElement {
  return (
    <Box>
      <Heading>x402check: what this Snap sends</Heading>
      <Text>
        Before you confirm a transaction or signature, x402check sends a risk-check request to <Bold>x402check.xyz</Bold>. Each
        request contains only:
      </Text>
      <Text>
        - the counterparty address(es) (recipient, spender, operator or contract, up to three per request; your own address only
        when a message names no one else)
      </Text>
      <Text>- the chain ID</Text>
      <Text>- the requesting site (its hostname)</Text>
      <Text>
        - a decoded, human-readable summary of the transaction or signature (for example: "approve UNLIMITED token 0x… to spender
        0x…"), with secret-looking strings removed
      </Text>
      <Text>
        Purpose: score the counterparty and site for drainer, fraud, sanctions and impersonation risk, and show you a signed verdict
        before you sign.
      </Text>
      <Text>
        A random install ID is sent only to count your free daily checks. It is not derived from your Secret Recovery Phrase and is
        reset if you reinstall.
      </Text>
      <Text>
        <Bold>Your private keys and Secret Recovery Phrase never leave your wallet.</Bold> x402check cannot sign or move anything.
      </Text>
      <Link href={API_ORIGIN}>x402check.xyz</Link>
    </Box>
  );
}
