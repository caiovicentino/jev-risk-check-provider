/**
 * personal_sign decoding: hex -> UTF-8 text when printable, then hosts and
 * addresses are extracted from the TEXT (never from the hex). Payloads larger
 * than 64 KiB are summarized without decoding.
 */
import type { Candidate, Decoded } from "./util";
import {
  MAX_EXCERPT,
  MAX_TEXT_BYTES,
  RANK,
  capText,
  cleanText,
  extractAddresses,
  extractLinks,
  hostFromUrl,
  interaction,
  normalizeAddress,
  normalizeChainId,
  scalarJson,
  withCandidates,
} from "./util";

function isEvenHexPayload(data: string): boolean {
  if (data.length < 2 || data[0] !== "0" || (data[1] !== "x" && data[1] !== "X") || data.length % 2 === 1) return false;
  for (let index = 2; index < data.length; index += 1) {
    const code = data.charCodeAt(index);
    const hex = (code >= 48 && code <= 57) || (code >= 65 && code <= 70) || (code >= 97 && code <= 102);
    if (!hex) return false;
  }
  return true;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function decodeUtf8(bytes: Uint8Array): string | undefined {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}

/** True when at least 90% of the characters are printable text. */
export function isMostlyPrintable(text: string): boolean {
  if (text.length === 0) return false;
  let total = 0;
  let bad = 0;
  for (const char of text) {
    total += 1;
    if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\uFFFD]/u.test(char)) bad += 1;
  }
  return bad / total <= 0.1;
}

type Siwe = { domain: string; address?: string; chainId?: string };

function parseSiwe(text: string): Siwe | undefined {
  const match = /^(?:[a-z][a-z0-9+.-]{0,31}:\/\/)?([^\s]{1,253}) wants you to sign in with your Ethereum account:\r?\n(0x[0-9a-fA-F]{40})/u.exec(
    text.slice(0, 1024),
  );
  if (!match) return undefined;
  const chain = /^Chain ID: (\d{1,20})\r?$/mu.exec(text);
  return {
    domain: (match[1] as string).toLowerCase(),
    address: normalizeAddress((match[2] as string).toLowerCase()),
    chainId: chain ? (chain[1] as string) : undefined,
  };
}

function signerOnly(
  signer: string | undefined,
  base: { action: string; summary: string; warnings: string[]; chain?: string; referencedHosts?: string[] },
): Decoded {
  if (!signer) {
    return withCandidates(
      {
        ...base,
        danger: [],
        interaction: interaction("message_signature"),
        localNote:
          "The request names no counterparty and the signing account is unknown, so there is nothing to check. Nothing was sent to x402check.",
      },
      [],
    );
  }
  return withCandidates({ ...base, danger: [] }, [
    { address: signer, role: "signer", interaction: interaction("message_signature"), rank: RANK.signer },
  ]);
}

/**
 * Decodes a personal_sign payload.
 *
 * @param data - The `signature.data` value (0x-hex, or plain text defensively).
 * @param signerAddress - The signing account.
 * @param originHostname - Hostname of the requesting site, if known.
 * @returns The decoded request.
 */
export function decodePersonalSign(data: unknown, signerAddress?: unknown, originHostname?: string): Decoded {
  const signer = normalizeAddress(typeof signerAddress === "string" ? signerAddress.toLowerCase() : signerAddress);
  const warnings: string[] = [];
  let text: string | undefined;
  let byteLength = 0;

  if (typeof data === "string" && data.length > 2 + MAX_TEXT_BYTES * 2) {
    const size = /^0[xX]/u.test(data.slice(0, 2)) ? Math.floor((data.length - 2) / 2) : data.length;
    warnings.push(`the message is very large (${size} bytes) and was not decoded; review it carefully`);
    return signerOnly(signer, {
      action: "Message signature (large payload)",
      summary: `personal_sign of a large payload (${size} bytes), not decoded; no counterparty address in message; subject is the signer.`,
      warnings,
    });
  }
  if (typeof data === "string" && isEvenHexPayload(data)) {
    const bytes = hexToBytes(data.slice(2));
    byteLength = bytes.length;
    const decoded = decodeUtf8(bytes);
    text = decoded !== undefined && isMostlyPrintable(decoded) ? decoded : undefined;
  } else if (typeof data === "string") {
    text = data;
    byteLength = new TextEncoder().encode(data).length;
  }

  if (text === undefined) {
    const hashLike = byteLength === 32;
    if (hashLike) {
      warnings.push("the message is a raw 32-byte value (looks like a hash); blind-signing a hash can authorize anything");
    }
    return signerOnly(signer, {
      action: "Message signature (binary)",
      summary: `personal_sign of binary data (${byteLength} bytes)${hashLike ? ", likely a hash" : ""}; no counterparty address in message; subject is the signer.`,
      warnings,
    });
  }

  const clean = cleanText(text, 2048);
  if (clean.hadInvisible) warnings.push("the message contains invisible or text-direction control characters");
  const siwe = parseSiwe(text);
  let chain: string | undefined;
  const links = extractLinks(text);
  const hosts = links.hosts;
  warnings.push(...links.warnings);
  if (siwe) {
    chain = siwe.chainId ? normalizeChainId(siwe.chainId) : undefined;
    const siweHost = hostFromUrl(`https://${siwe.domain}`);
    const shownHost = siweHost ?? siwe.domain;
    if (originHostname && shownHost !== originHostname) {
      warnings.push(`Sign-In with Ethereum message is for ${shownHost} but was requested by ${originHostname}`);
    }
    if (signer && siwe.address && siwe.address !== signer) {
      warnings.push(`Sign-In with Ethereum message names account ${siwe.address}, not the signer`);
    }
    if (siweHost && !hosts.includes(siweHost)) hosts.unshift(siweHost);
  }
  const addresses = extractAddresses(text, [signer, siwe?.address]);
  const excerpt = capText(scalarJson(text) ?? clean.text, MAX_EXCERPT);
  const kind = siwe ? "Sign-In with Ethereum message" : "personal_sign message";
  const length = Array.from(text.length > MAX_TEXT_BYTES ? text.slice(0, MAX_TEXT_BYTES) : text).length;
  const hostNote = hosts.length > 0 ? ` Message references: ${hosts.slice(0, 3).join(", ")}.` : "";
  const action = siwe ? "Sign-In with Ethereum" : "Message signature";

  if (addresses.length > 0) {
    // Several addresses: none is trusted to be "the" counterparty; up to three
    // are checked together and the worst verdict is shown.
    const checked = addresses.slice(0, 3);
    const candidates: Candidate[] = checked.map((address, index) => ({
      address,
      role: "counterparty",
      interaction: interaction("message_signature"),
      rank: RANK.transfer - index * 0.001,
      reason: `address #${index + 1} named in the message`,
    }));
    const named =
      checked.length === 1
        ? ` Counterparty address named in message: ${checked[0]}.`
        : ` Addresses named in message (all checked): ${checked.join(", ")}${addresses.length > 3 ? ` and ${addresses.length - 3} more` : ""}.`;
    return withCandidates(
      {
        action,
        chain,
        summary: `${kind} (${length} chars): "${excerpt}".${hostNote}${named}`,
        warnings,
        danger: [],
        referencedHosts: hosts,
      },
      candidates,
    );
  }
  return signerOnly(signer, {
    action,
    chain,
    summary: `${kind} (${length} chars): "${excerpt}".${hostNote} No counterparty address in message; subject is the signer.`,
    warnings,
    referencedHosts: hosts,
  });
}
