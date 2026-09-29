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

import type { Decoded, InteractionType, Role } from "./decode";
import { capText } from "./decode";
import type { CheckOutcome, Evidence, FeedEvidence, Tier, Verdict } from "./request";
import { API_ORIGIN, JWKS_URL } from "./request";

export type RequestKind = "transaction" | "signature";

export type InsightResult = {
  content: JSXElement;
  severity?: "critical";
};

type Child = JSXElement | null;

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

function amountRowLabel(decoded: Decoded): string {
  if (decoded.role === "operator") return "Scope";
  if (decoded.role === "spender") return "Allowance";
  return "Amount";
}

/** What was decoded and which address was checked (or would have been). */
function subjectSection(decoded: Decoded, host: string | undefined, checked: boolean): JSXElement {
  const rows: Child[] = [
    <Row label="Action">
      <Text>{decoded.action}</Text>
    </Row>,
    decoded.counterparty && decoded.role ? (
      <Row
        label={`${checked ? "Checked" : "Not checked"}: ${ROLE_LABEL[decoded.role]}`}
        variant={checked ? "default" : "warning"}
        tooltip="The address this request gives rights or value to."
      >
        <Address address={decoded.counterparty as `0x${string}`} />
      </Row>
    ) : null,
    decoded.unlimited ? (
      <Row label={amountRowLabel(decoded)} variant="critical">
        <Text>
          <Bold>{decoded.amountLabel ?? "UNLIMITED"}</Bold>
        </Text>
      </Row>
    ) : decoded.amountLabel ? (
      <Row label={amountRowLabel(decoded)}>
        <Text>{decoded.amountLabel}</Text>
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

function signerNote(decoded: Decoded): Child {
  if (decoded.role !== "signer") return null;
  return (
    <Text color="warning">
      No counterparty address was found in this request, so your own signing address was checked instead.
    </Text>
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

function evidenceRows(evidence: Evidence | undefined, decoded: Decoded): Child[] {
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
            <Text>
              {`Active address${onchain.tx_count !== undefined ? ` (${onchain.tx_count} transactions)` : ""}`}
            </Text>
          </Row>,
        );
      }
      if (onchain.is_contract === true) {
        rows.push(
          <Row label="Type">
            <Text>Counterparty is a contract</Text>
          </Row>,
        );
      } else if (onchain.is_contract === false && APPROVAL_TYPES.has(decoded.interaction.type)) {
        const who = decoded.role === "operator" ? "Operator" : "Spender";
        rows.push(
          <Row label="Type" variant="critical">
            <Text>{`${who} is a regular wallet (EOA), not a contract — typical of drainers`}</Text>
          </Row>,
        );
      }
    } else {
      rows.push(
        <Row label="On-chain">
          <Text>
            {onchain.status === "unsupported"
              ? "On-chain check not supported on this network"
              : "On-chain data unavailable"}
          </Text>
        </Row>,
      );
    }
  }
  return rows;
}

function attestation(verdict: Verdict): Child[] {
  const keysUrl = verdict.jwks_url ?? JWKS_URL;
  if (!verdict.jws) {
    return [
      <Text color="muted">This verdict was not signed.</Text>,
      <Link href={keysUrl}>Provider public keys (JWKS)</Link>,
    ];
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

function verdictContent(decoded: Decoded, verdict: Verdict, host: string | undefined): InsightResult {
  const sanctions = verdict.evidence?.sanctions;
  const sanctioned = sanctions?.status === "listed";
  const feeds = feedLines(verdict.evidence?.feeds);
  const listedInFeed = feeds.hits.length > 0;
  // An unknown or missing tier never gets the "no significant risk" copy, and a
  // sanctions or threat-feed hit always gets the critical copy.
  const copyTier: Tier = sanctioned || listedInFeed ? "critical" : (verdict.tier ?? "medium");
  const copy = TIER_COPY[copyTier];
  const score = verdict.score !== undefined ? String(verdict.score) : "?";
  const tierLabel = verdict.tier ?? "unknown tier";
  const categories =
    verdict.categories.length > 0 ? verdict.categories.map(categoryLabel).join(", ") : undefined;

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
    <Heading>{`x402check · score ${score}/100 · ${tierLabel}`}</Heading>,
    <Text>
      <Bold>{copy.verdict}</Bold> {copy.advice}
    </Text>,
    subjectSection(decoded, host, true),
    signerNote(decoded),
    warningsBanner(decoded.warnings),
  ];
  const facts: Child[] = [
    ...evidenceRows(verdict.evidence, decoded),
    categories ? (
      <Row label="Categories">
        <Text>{categories}</Text>
      </Row>
    ) : null,
    feeds.summary ? <Text color="muted">{feeds.summary}</Text> : null,
  ];
  if (compact(facts).length > 0) {
    children.push(<Section>{compact(facts)}</Section>);
  }
  children.push(<Divider />, ...attestation(verdict));

  const highTier = verdict.tier === "high" || verdict.tier === "critical";
  return {
    content: <Box>{compact(children)}</Box>,
    ...(highTier || sanctioned || listedInFeed ? { severity: "critical" as const } : {}),
  };
}

function failureContent(decoded: Decoded, host: string | undefined, title: string, explanation: string): InsightResult {
  return {
    content: (
      <Box>
        {compact([
          <Heading>{`x402check · ${title}`}</Heading>,
          <Text>{explanation}</Text>,
          subjectSection(decoded, host, false),
          signerNote(decoded),
          warningsBanner(decoded.warnings),
        ])}
      </Box>
    ),
  };
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
export function renderOutcome(
  decoded: Decoded,
  outcome: CheckOutcome,
  kind: RequestKind,
  host?: string,
): InsightResult {
  switch (outcome.kind) {
    case "ok":
      return verdictContent(decoded, outcome.verdict, host);
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
      return failureContent(
        decoded,
        host,
        "check failed — NOT verified",
        `The risk service returned an unreadable response, so this ${kind} was NOT verified.`,
      );
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
 *
 * @param decoded - The decoded request.
 * @param host - Hostname of the requesting site.
 * @returns Content.
 */
export function renderLocalOnly(decoded: Decoded, host?: string): InsightResult {
  return {
    content: (
      <Box>
        {compact([
          <Heading>x402check · not checked</Heading>,
          <Text>{decoded.localNote ?? "There is no counterparty address to check. Nothing was sent to x402check."}</Text>,
          subjectSection(decoded, host, false),
          warningsBanner(decoded.warnings),
        ])}
      </Box>
    ),
  };
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
        Before you confirm a transaction or signature, x402check sends a risk-check request to{" "}
        <Bold>x402check.xyz</Bold>. Each request contains only:
      </Text>
      <Text>- the counterparty address (recipient, spender, operator or contract; your own address only when a message names no one else)</Text>
      <Text>- the chain ID</Text>
      <Text>- the requesting site (its hostname)</Text>
      <Text>- a decoded, human-readable summary of the transaction or signature (for example: "approve UNLIMITED token 0x… to spender 0x…")</Text>
      <Text>
        Purpose: score the counterparty and site for drainer, fraud, sanctions and impersonation risk, and show you a signed verdict before you sign.
      </Text>
      <Text>
        A random install ID is sent only to count your free daily checks. It is not derived from your Secret Recovery Phrase and is reset if you reinstall.
      </Text>
      <Text>
        <Bold>Your private keys and Secret Recovery Phrase never leave your wallet.</Bold> x402check cannot sign or move anything.
      </Text>
      <Link href={API_ORIGIN}>x402check.xyz</Link>
    </Box>
  );
}
