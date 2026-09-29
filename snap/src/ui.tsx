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

import { PAID_CHECKS_SUPPORTED } from "./config";
import type { BatchItem, CheckOutcome, Evidence, FeedEvidence, Tier, Verdict } from "./request";
import { API_ORIGIN, JWKS_URL, MAX_CHECKS } from "./request";
import type { AssetMovement, SimulationEvidence } from "./simulation";
import { accountKind, approvalText, isIncomplete, midAddress, movementText, simulationFindingLines } from "./simulation";
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
  ["known_drainer_code", "Known drainer code (same code as listed wallet drainers)"],
  ["onchain_unavailable", "Spender could not be classified (on-chain lookup failed) — not fully verified"],
  ["simulation_unavailable", "Transaction simulation failed — not fully verified"],
]);

/** Categories meaning part of the check could not be completed. */
const INCOMPLETE_CATEGORIES = new Set(["onchain_unavailable", "simulation_unavailable"]);

const UNVERIFIED_REASONS = new Map<string, string>([
  ["invalid_subject", "the checked address was rejected as invalid"],
  ["model_unconfigured", "the risk model is not configured"],
  ["model_malformed_answers", "the risk model returned malformed answers"],
  ["model_unavailable", "the risk model was unavailable"],
]);

/**
 * Readable reason for a `checked: false` response.
 *
 * @param reason - The provider's reason id.
 * @returns The text, or undefined when there is no reason.
 */
export function unverifiedReason(reason: string | undefined): string | undefined {
  if (!reason) return undefined;
  return UNVERIFIED_REASONS.get(reason) ?? reason.replace(/_+/gu, " ");
}

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
  ["forta-phishing-code", "Runs known wallet-drainer code (Forta drainer code fingerprints)"],
  ["scamsniffer-code", "Runs known wallet-drainer code (ScamSniffer drainer code fingerprints)"],
]);

const FEED_NAMES = new Map<string, string>([
  ["metamask-phishing-detect", "MetaMask phishing list"],
  ["scamsniffer-addresses", "ScamSniffer scam addresses"],
  ["scamsniffer-domains", "ScamSniffer phishing domains"],
  ["forta-phishing-code", "Forta drainer code fingerprints"],
  ["scamsniffer-code", "ScamSniffer drainer code fingerprints"],
]);

/**
 * Loud line for a threat-feed hit. A code-feed hit means the checked address
 * itself runs known wallet-drainer code.
 *
 * @param feed - The feed evidence with status "hit".
 * @returns The label.
 */
export function feedHitLabel(feed: FeedEvidence): string {
  return FEED_HIT_LABELS.get(feed.source) ?? `Listed by ${feed.source}${feed.kind ? ` (${feed.kind})` : ""}`;
}

/**
 * Readable name of a threat feed ("Forta drainer code fingerprints").
 *
 * @param source - The feed source id.
 * @returns The name.
 */
export function feedName(source: string): string {
  return FEED_NAMES.get(source) ?? source;
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
      if (onchain.code?.kind === "delegated" && onchain.code.delegate) {
        rows.push(
          <Row label="Account">
            <Text>{`EIP-7702 delegated account → ${midAddress(onchain.code.delegate)}`}</Text>
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
  const names = (status: FeedEvidence["status"]) =>
    feeds.filter((feed) => feed.status === status).map((feed) => feedName(feed.source));
  const clear = names("clear");
  const unavailable = names("unavailable");
  const counts = [clear.length > 0 ? `${clear.length} clear` : "", unavailable.length > 0 ? `${unavailable.length} unavailable` : ""].filter(Boolean);
  const detail = [clear.length > 0 ? `clear: ${clear.join(", ")}` : "", unavailable.length > 0 ? `unavailable: ${unavailable.join(", ")}` : ""]
    .filter(Boolean)
    .join("; ");
  return { hits, summary: counts.length > 0 ? capText(`Threat feeds: ${counts.join(", ")} (${detail})`, 400) : undefined };
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

/** The provider could not complete part of this check (a lookup or the simulation failed). */
function incompleteVerdict(verdict: Verdict): boolean {
  return verdict.categories.some((category) => INCOMPLETE_CATEGORIES.has(category));
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
          variant={
            item.status !== "ok" ? "warning" : isAlarming(item.verdict) ? "critical" : incompleteVerdict(item.verdict) ? "warning" : "default"
          }
        >
          <Text>{`${shortAddress(candidate.address)} · ${
            item.status === "ok"
              ? `${verdictLine(item.verdict)}${incompleteVerdict(item.verdict) ? " · not fully verified" : ""}`
              : `NOT verified${item.status === "unverified" && item.reason ? ` (${unverifiedReason(item.reason)})` : ""}`
          }`}</Text>
        </Row>
      ))}
    </Section>
  );
}

/** Rows shown per simulated list before "and N more". */
const MAX_SIMULATION_ROWS = 5;
const SIMULATION_TITLE = "What this transaction does (simulated)";

function hasStrongFinding(simulation: SimulationEvidence | undefined): boolean {
  return simulation ? simulationFindingLines(simulation).some((line) => line.strong) : false;
}

/** Findings as prominent banners: drainer-like ones as danger, the rest as cautions. */
function simulationBanners(simulation: SimulationEvidence | undefined): Child[] {
  if (!simulation) return [];
  const findings = simulationFindingLines(simulation);
  const strong = findings.filter((finding) => finding.strong);
  const other = findings.filter((finding) => !finding.strong);
  return [
    strong.length > 0 ? (
      <Banner title="Simulation: likely wallet drainer — do not proceed" severity="danger">
        {strong.slice(0, 4).map((finding) => (
          <Text>{finding.text}</Text>
        ))}
      </Banner>
    ) : null,
    other.length > 0 ? (
      <Banner title="Simulation warnings" severity="warning">
        {other.slice(0, 4).map((finding) => (
          <Text>{finding.text}</Text>
        ))}
      </Banner>
    ) : null,
  ];
}

function notSimulated(reason: string): JSXElement {
  return (
    <Section>
      <Heading size="sm">{SIMULATION_TITLE}</Heading>
      <Text color="warning">
        <Bold>NOT simulated:</Bold> {reason}
      </Text>
    </Section>
  );
}

function moreRow(total: number): Child {
  return total > MAX_SIMULATION_ROWS ? <Text color="muted">{`and ${total - MAX_SIMULATION_ROWS} more`}</Text> : null;
}

function movementRows(label: string, movements: AssetMovement[], chain: string | undefined, arrow: "→" | "from"): Child[] {
  return [
    ...movements.slice(0, MAX_SIMULATION_ROWS).map((movement) => {
      const where = movement.counterparty
        ? `${arrow === "→" ? " → " : " from "}${midAddress(movement.counterparty)}${accountKind(movement.counterparty_is_contract)}`
        : "";
      return (
        <Row label={label}>
          <Text>{`${movementText(movement, chain)}${where}`}</Text>
        </Row>
      );
    }),
    moreRow(movements.length),
  ];
}

/**
 * What the transaction does according to the provider's simulation, or an
 * explicit statement that its effects were NOT simulated (never an all-clear).
 *
 * @param decoded - The decoded request.
 * @param simulation - Simulation evidence from the verdict, if any.
 * @param kind - Only transactions are simulated.
 * @returns The section, or null for signatures.
 */
function simulationSection(decoded: Decoded, simulation: SimulationEvidence | undefined, kind: RequestKind): Child {
  if (kind !== "transaction") return null;
  if (!simulation) {
    return notSimulated(
      decoded.simulationSkipped
        ? sentence(decoded.simulationSkipped)
        : "the risk service did not return a simulation, so this transaction's effects are unknown.",
    );
  }
  if (simulation.status === "unavailable") {
    return notSimulated("the simulation service was unavailable, so this transaction's effects are unknown.");
  }
  if (simulation.status === "unsupported") {
    return notSimulated(
      `simulation is not available on ${simulation.network ?? decoded.chain ?? "this network"}, so this transaction's effects are unknown.`,
    );
  }
  if (simulation.status === "reverted") {
    return (
      <Section>
        <Heading size="sm">{SIMULATION_TITLE}</Heading>
        <Text color="error">
          <Bold>This transaction would revert (fail) if sent as is.</Bold>
        </Text>
      </Section>
    );
  }
  const chain = simulation.network ?? decoded.chain;
  const approvals = simulation.approvals;
  const rows: Child[] = [
    ...movementRows("You send", simulation.outflows, chain, "→"),
    ...movementRows("You receive", simulation.inflows, chain, "from"),
    ...approvals.slice(0, MAX_SIMULATION_ROWS).map((approval) => (
      <Row label="Grants" variant={approval.unlimited || approval.spender_is_contract === false ? "critical" : "warning"}>
        <Text>{`${approvalText(approval, chain)} to ${midAddress(approval.spender)}${accountKind(approval.spender_is_contract)}`}</Text>
      </Row>
    )),
    moreRow(approvals.length),
  ];
  const empty = simulation.outflows.length + simulation.inflows.length + approvals.length === 0;
  return (
    <Section>
      {compact([
        <Heading size="sm">{SIMULATION_TITLE}</Heading>,
        ...rows,
        empty && !isIncomplete(simulation) ? <Text>No asset movements or approvals were detected in the simulation.</Text> : null,
        isIncomplete(simulation) ? (
          <Text color="warning">The simulation was incomplete, so the effects listed here may not be everything.</Text>
        ) : null,
        simulation.dropped > 0 ? <Text color="muted">{`${simulation.dropped} simulated effect(s) could not be displayed.`}</Text> : null,
      ])}
    </Section>
  );
}

/** Simulation evidence of a batch: the primary item carries the transaction. */
function batchSimulation(items: BatchItem[]): SimulationEvidence | undefined {
  for (const item of items) {
    if (item.status === "ok" && item.verdict.evidence?.simulation) return item.verdict.evidence.simulation;
  }
  return undefined;
}

type VerdictOptions = {
  host: string | undefined;
  subject: Subject;
  kind: RequestKind;
  simulation: SimulationEvidence | undefined;
  also?: Also[];
};

function verdictContent(decoded: Decoded, verdict: Verdict, options: VerdictOptions): InsightResult {
  const { host, subject, kind, simulation } = options;
  const also = options.also ?? [];
  const sanctions = verdict.evidence?.sanctions;
  const sanctioned = sanctions?.status === "listed";
  const feeds = feedLines(verdict.evidence?.feeds);
  const listedInFeed = feeds.hits.length > 0;
  const localDanger = decoded.danger.length > 0;
  // An unknown or missing tier never gets the "no significant risk" copy, and a
  // sanctions / threat-feed hit or locally proven danger gets the critical copy.
  const drainerSimulation = hasStrongFinding(simulation);
  // Incomplete checks are never an all-clear: at least the "review" copy. In a
  // batch, one address that was not fully verified makes the whole check so.
  const notFullyVerified =
    isIncomplete(simulation) ||
    incompleteVerdict(verdict) ||
    also.some((entry) => entry.item.status === "ok" && incompleteVerdict(entry.item.verdict));
  const baseTier: Tier = verdict.tier === "low" && notFullyVerified ? "medium" : (verdict.tier ?? "medium");
  const copyTier: Tier = sanctioned || listedInFeed || localDanger || drainerSimulation ? "critical" : baseTier;
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
    ...simulationBanners(simulation),
    <Heading>{`x402check · ${verdictLine(verdict)}`}</Heading>,
    <Text>
      <Bold>{copy.verdict}</Bold> {copy.advice}
    </Text>,
    notFullyVerified ? (
      <Text color="warning">Not fully verified: part of this check could not be completed. Treat it with caution.</Text>
    ) : null,
    subjectSection(decoded, subject, host, true),
    simulationSection(decoded, simulation, kind),
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
  const critical = isAlarming(verdict) || alarmingOther || localDanger || drainerSimulation;
  return {
    content: <Box>{compact(children)}</Box>,
    ...(critical ? { severity: "critical" as const } : {}),
  };
}

function failureContent(
  decoded: Decoded,
  host: string | undefined,
  kind: RequestKind,
  title: string,
  explanation: string,
  also: Also[] = [],
  simulation?: SimulationEvidence,
): InsightResult {
  const localDanger = decoded.danger.length > 0;
  const alarming = also.some((entry) => entry.item.status === "ok" && isAlarming(entry.item.verdict));
  return {
    content: (
      <Box>
        {compact([
          dangerBanner(decoded.danger),
          ...simulationBanners(simulation),
          <Heading>{`x402check · ${title}`}</Heading>,
          <Text>{explanation}</Text>,
          subjectSection(decoded, primarySubject(decoded), host, false),
          simulationSection(decoded, simulation, kind),
          alsoCheckedSection(also),
          signerNote(primarySubject(decoded)),
          warningsBanner(decoded.warnings),
        ])}
      </Box>
    ),
    ...(localDanger || alarming || hasStrongFinding(simulation) ? { severity: "critical" as const } : {}),
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
  const simulation = batchSimulation(items);
  if (!worst || (failed.length > 0 && !isAlarming(worst.item.verdict))) {
    // Fail closed: an address that could not be verified is never an all-clear.
    return failureContent(
      decoded,
      host,
      kind,
      "verification failed — NOT verified",
      `${failed.length} of ${entries.length} addresses in this ${kind} could not be verified, so it was NOT verified.`,
      entries,
      simulation,
    );
  }
  const others = entries.filter((entry) => entry !== worst);
  return verdictContent(decoded, worst.item.verdict, { host, subject: candidateSubject(worst.candidate), kind, simulation, also: others });
}

/**
 * Why an HTTP 402 is not a verdict: every x402check evaluation is paid per call
 * (x402), and this Snap cannot pay yet.
 *
 * @param kind - Transaction or signature.
 * @returns The explanation.
 */
export function paymentRequiredText(kind: RequestKind): string {
  return `x402check checks are paid per call (x402) and this Snap cannot pay yet — the ${kind} was NOT checked.`;
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
      return verdictContent(decoded, outcome.verdict, {
        host,
        subject: primarySubject(decoded),
        kind,
        simulation: outcome.verdict.evidence?.simulation,
      });
    case "batch":
      return renderBatch(decoded, outcome.items, kind, host);
    case "network_error":
      return failureContent(
        decoded,
        host,
        kind,
        "unavailable — NOT verified",
        `The risk service could not be reached${outcome.timedOut ? " in time" : ""}, so this ${kind} was NOT checked. This is not an all-clear: proceed only if you fully trust the counterparty.`,
      );
    case "payment_required":
      return failureContent(
        decoded,
        host,
        kind,
        "payment required — NOT verified",
        `${paymentRequiredText(kind)} This is not an all-clear: proceed only if you fully trust the counterparty.`,
      );
    case "http_error":
      return failureContent(
        decoded,
        host,
        kind,
        "check failed — NOT verified",
        `The risk service returned an error (HTTP ${outcome.status}), so this ${kind} was NOT verified.`,
      );
    case "invalid_response":
      return failureContent(decoded, host, kind, "check failed — NOT verified", `The risk service returned an unreadable response, so this ${kind} was NOT verified.`);
    case "unverified":
    default: {
      const reason = outcome.kind === "unverified" ? unverifiedReason(outcome.reason) : undefined;
      return failureContent(
        decoded,
        host,
        kind,
        "verification failed — NOT verified",
        `The provider could not evaluate this request and failed closed${reason ? ` (${reason})` : ""}. This ${kind} was NOT verified.`,
      );
    }
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

/** Shown on every request while this Snap cannot pay for checks (src/config.ts). */
export const NOT_SENT_TEXT =
  "NOT verified by x402check: checks are paid per call (x402) and this Snap version cannot pay yet — nothing was sent.";

function involvedSection(others: Candidate[]): Child {
  if (others.length === 0) return null;
  return (
    <Section>
      {others.slice(0, MAX_CHECKS - 1).map((candidate) => (
        <Row label={`Also involved: ${ROLE_LABEL[candidate.role]}`} variant="warning">
          <Address address={candidate.address as `0x${string}`} />
        </Row>
      ))}
    </Section>
  );
}

/**
 * The insight while paid checks are off: only what was decoded locally, marked
 * NOT verified by x402check, never an all-clear. Locally proven danger is
 * still critical.
 *
 * @param decoded - The decoded request.
 * @param host - Hostname of the requesting site.
 * @param kind - Transaction or signature (for copy).
 * @returns Content and optional severity.
 */
export function renderUnpaid(decoded: Decoded, host: string | undefined, kind: RequestKind): InsightResult {
  return {
    content: (
      <Box>
        {compact([
          dangerBanner(decoded.danger),
          <Heading>x402check · NOT verified</Heading>,
          <Text>
            <Bold>{NOT_SENT_TEXT}</Bold>
          </Text>,
          <Text>
            {`This is not an all-clear. What follows was decoded locally from the ${kind}; no address or site was risk-checked. Proceed only if you fully trust the site and the counterparty.`}
          </Text>,
          decoded.localNote ? <Text color="muted">{decoded.localNote}</Text> : null,
          subjectSection(decoded, primarySubject(decoded), host, false),
          involvedSection(decoded.others),
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
 * Disclosure while paid checks are off: nothing leaves the wallet.
 *
 * @returns Dialog content.
 */
function localOnlyDisclosure(): JSXElement {
  return (
    <Box>
      <Heading>x402check: nothing leaves your wallet</Heading>
      <Text>
        <Bold>This version of x402check sends nothing</Bold>: not to x402check.xyz and not anywhere else. It has no network access.
      </Text>
      <Text>
        Before you confirm a transaction or signature, it decodes the request inside your wallet and shows who really receives your
        funds or permissions (recipient, spender, operator or contract), with warnings about risky patterns it can detect locally,
        such as unlimited approvals or orders that give your assets away for nothing.
      </Text>
      <Text>
        It does not check addresses or sites with x402check's risk service: those checks are paid per call (x402), and this version
        cannot pay yet. Every request is therefore shown as NOT verified by x402check, never as an all-clear.
      </Text>
      <Text>
        Paid checks are planned for a later version, which will show you an updated notice listing what it sends.
      </Text>
      <Text>The only thing it stores is which version of this notice you have seen.</Text>
      <Text>
        <Bold>Your private keys and Secret Recovery Phrase never leave your wallet.</Bold> x402check cannot sign or move anything.
      </Text>
      <Link href={API_ORIGIN}>x402check.xyz</Link>
    </Box>
  );
}

/**
 * Disclosure for the paid mode (PAID_CHECKS_SUPPORTED true): exactly what the
 * request code in src/request.ts sends. Before turning paid checks on, add how
 * a check is paid (who pays, how much, and what the user approves).
 *
 * @returns Dialog content.
 */
function paidModeDisclosure(): JSXElement {
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
        - for transactions only: the full transaction (from, to, value and calldata). x402check simulates it on a public RPC node
        of that chain to show what it would do, and may look up contract source verification on Blockscout. Signatures are never
        simulated.
      </Text>
      <Text>
        Purpose: score the counterparty and site for drainer, fraud, sanctions and impersonation risk, and show you a signed verdict
        before you sign.
      </Text>
      <Text>No install ID is added to these requests. x402check checks are paid per call (x402).</Text>
      <Text>
        <Bold>Your private keys and Secret Recovery Phrase never leave your wallet.</Bold> x402check cannot sign or move anything.
      </Text>
      <Link href={API_ORIGIN}>x402check.xyz</Link>
    </Box>
  );
}

/**
 * One-time privacy disclosure shown on install, and after an update whose
 * disclosure changed (DISCLOSURE_VERSION).
 *
 * @param paidChecks - Whether paid checks are on (defaults to the Snap's switch).
 * @returns Dialog content.
 */
export function disclosureContent(paidChecks: boolean = PAID_CHECKS_SUPPORTED): JSXElement {
  return paidChecks ? paidModeDisclosure() : localOnlyDisclosure();
}
