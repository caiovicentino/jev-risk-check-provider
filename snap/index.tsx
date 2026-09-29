import {
  OnTransactionHandler,
  OnSignatureHandler,
  OnInstallHandler,
} from "@metamask/snaps-sdk";
import {
  Section,
  Text,
  Heading,
  Divider,
  Row,
  Link,
  Copyable,
} from "@metamask/snaps-sdk/jsx";

const ENDPOINT = "https://x402check.xyz/v1/risk-check";
const JWK_URL = "https://x402check.xyz/.well-known/jwks.json";

type Verdict = {
  checked?: boolean;
  score?: number;
  tier?: string;
  categories?: string[];
  jws?: string;
};

type SnapState = { clientId?: string } | null;

async function getClientId(): Promise<string> {
  const state = (await snap_manageState({ operation: "get" })) as SnapState;
  if (state?.clientId) return state.clientId;
  const entropy = await snap_getEntropy("x402check-client-id");
  const cid = entropy.slice(0, 16);
  await snap_manageState({
    operation: "update",
    newState: { clientId: cid } as SnapState,
  });
  return cid;
}

async function check(
  body: Record<string, unknown>,
  clientId: string,
): Promise<Verdict | null> {
  try {
    const res = await fetch(ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Risk-Check-Client": clientId,
      },
      body: JSON.stringify(body),
    });
    if (res.status !== 200) return null;
    return (await res.json()) as Verdict;
  } catch {
    return null;
  }
}

const TIER_COPY: Record<string, { verdict: string; advice: string }> = {
  low: {
    verdict: "No significant risk signals",
    advice: "As always, verify the recipient before confirming.",
  },
  medium: {
    verdict: "Some risk signals present",
    advice: "Review carefully before confirming.",
  },
  high: {
    verdict: "High risk detected",
    advice: "We recommend NOT proceeding. Check the categories below.",
  },
  critical: {
    verdict: "Critical risk detected",
    advice: "Do NOT proceed. This matches fraud or laundering patterns.",
  },
};

function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max)}…`;
}

function shortAddress(value: string): string {
  return value.length <= 14 ? value : `${value.slice(0, 8)}…${value.slice(-4)}`;
}

function shortJws(jws: string): string {
  const parts = jws.split(".");
  if (parts.length !== 3) return "present";
  return `${parts[0].slice(0, 20)}…${parts[2].slice(0, 12)}…`;
}

function unavailableContent(subject: string) {
  return (
    <Section>
      <Heading>x402check · unavailable</Heading>
      <Text>
        The risk check could not be run (network or provider error). This is
        NOT a clean bill of health — the payment was simply not verified.
        Proceed with caution.
      </Text>
      <Text>Attempted subject: {truncate(subject, 90)}</Text>
    </Section>
  );
}

function unverifiedContent(subject: string) {
  return (
    <Section>
      <Heading>x402check · verification failed</Heading>
      <Text>
        The risk check could not be evaluated (provider refused the request).
        This is a fail-closed result: this payment was NOT verified. Proceeding
        is at your own risk.
      </Text>
      <Text>Attempted subject: {truncate(subject, 90)}</Text>
    </Section>
  );
}

function verdictContent(v: Verdict, subject: string) {
  const tier = v.tier ?? "unknown";
  const copy = TIER_COPY[tier] ?? TIER_COPY.low;
  const risky = tier === "high" || tier === "critical";
  const children = [
    <Heading>x402check · score {v.score ?? "?"}/100 · {tier}</Heading>,
    <Text>{copy.verdict}. Checked: {truncate(subject, 90)}</Text>,
    <Text>{copy.advice}</Text>,
  ];
  if (v.categories && v.categories.length > 0) {
    children.push(
      <Text>Categories: {v.categories.join(", ")}</Text>,
    );
  }
  children.push(<Divider />);
  if (v.jws) {
    children.push(<Copyable value={v.jws} />);
    children.push(
      <Text>
        Verdict is signed (ES256, kid jev-attest-v1) and independently
        verifiable: {shortJws(v.jws)}
      </Text>,
    );
  }
  children.push(<Link href={JWK_URL}>Public key set (JWKS)</Link>);
  return (
    <Section>
      {children}
    </Section>
  );
}

function extractDomains(payload: string): string[] {
  const urls = payload.match(/https?:\/\/[^\s"'<>)\]]+/g) ?? [];
  const domains = urls.map((u) => {
    try {
      return new URL(u).hostname;
    } catch {
      return "";
    }
  });
  return [...new Set(domains.filter(Boolean))].slice(0, 3);
}

export const onTransaction: OnTransactionHandler = async ({
  transaction,
  chainId,
  transactionOrigin,
}) => {
  const clientId = await getClientId();
  const to = String((transaction as { to?: unknown }).to ?? "unknown");
  const value = String((transaction as { value?: unknown }).value ?? "");
  const context = `direct wallet transfer${transactionOrigin ? ` initiated on ${transactionOrigin}` : ""}${value ? ` with value ${value} wei` : ""}`;
  const body: Record<string, unknown> = {
    wallet: to,
    chain: chainId,
    context,
  };
  if (transactionOrigin) body.domain = transactionOrigin;
  const v = await check(body, clientId);
  const subject = `${shortAddress(to)} on ${chainId}${transactionOrigin ? ` via ${transactionOrigin}` : ""}`;
  const content = !v
    ? unavailableContent(subject)
    : v.checked === false
      ? unverifiedContent(subject)
      : verdictContent(v, subject);
  const severity = v?.tier === "high" || v?.tier === "critical" ? "critical" : undefined;
  return severity ? { content, severity } : { content };
};

export const onSignature: OnSignatureHandler = async ({
  signature,
  signatureOrigin,
}) => {
  const clientId = await getClientId();
  const raw = String((signature as { data?: unknown }).data ?? "");
  const from = String((signature as { from?: unknown }).from ?? "unknown");
  const domains = extractDomains(raw);
  const context = `signature request${domains.length ? ` referencing ${domains.join(", ")}` : ""}: ${truncate(raw, 220)}`;
  const body: Record<string, unknown> = {
    wallet: from,
    context,
  };
  if (signatureOrigin) body.domain = signatureOrigin;
  const v = await check(body, clientId);
  const subject = `${shortAddress(from)} signing${signatureOrigin ? ` on ${signatureOrigin}` : ""}`;
  const content = !v
    ? unavailableContent(subject)
    : v.checked === false
      ? unverifiedContent(subject)
      : verdictContent(v, subject);
  const severity = v?.tier === "high" || v?.tier === "critical" ? "critical" : undefined;
  return severity ? { content, severity } : { content };
};

export const onInstall: OnInstallHandler = async () => {
  await getClientId();
  return null;
};
