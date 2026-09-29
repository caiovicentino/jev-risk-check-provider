/**
 * @jest-environment node
 *
 * Regression tests for review finding 9 (probes p4, p4b): secret redaction,
 * internationalized hostnames and messages naming several addresses.
 */
import { describe, expect, it } from '@jest/globals';

import { REDACTED, cleanText, decodePersonalSign, decodeSignature, redactSecrets } from '../../src/decode';
import { buildRiskCheckBodies, originHost } from '../../src/request';
import { DRAINER, RECIPIENT, USDC, USER, utf8Hex } from '../helpers';

const PRIVATE_KEY = '4c0883a69102937d6231471b5dbb6204fe512961708279f8b3e8b1b1c3a6a2c0';
const SOLANA_SECRET = '4NMwxzmYj2uvHuq8xoqhY8RXg63KSVJM1DXkpbmkUY7YQWuoyQgFnnzn6yo3CMnqZasnNPNuAT2TLwQsCaKkUddp';
const MNEMONIC = 'abandon ability able about above absent absorb abstract absurd abuse access accident';
const JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
const IDN_UNISWAP = 'un\u0456swap.org';

function context(text: string, origin: string | undefined = 'https://app.example.com'): string {
  const decoded = decodeSignature({ from: USER, data: utf8Hex(text), signatureMethod: 'personal_sign' }, originHost(origin));
  const [body] = buildRiskCheckBodies(decoded, origin);
  return body?.context ?? '';
}

describe('finding 9a: secret-looking strings never reach the context', () => {
  it.each([
    ['hex private key with pk_ prefix', `Export: pk_${PRIVATE_KEY}`, PRIVATE_KEY],
    ['hex private key followed by a letter', `key=${PRIVATE_KEY}z`, PRIVATE_KEY],
    ['0x-prefixed hex private key', `key 0x${PRIVATE_KEY}.`, PRIVATE_KEY],
    ['88-char base58 secret key', `Backup secret: ${SOLANA_SECRET}`, SOLANA_SECRET],
    ['BIP39-like 12-word phrase', `Verify wallet: ${MNEMONIC}`, 'abandon ability able'],
    ['JWT session token', `Session: ${JWT}`, JWT.slice(0, 30)],
  ])('%s', (_label, text, secret) => {
    const ctx = context(text);
    expect(ctx).toContain(REDACTED);
    expect(ctx).not.toContain(secret);
  });

  it('keeps addresses and ordinary prose intact', () => {
    const ctx = context(`Send the refund to ${RECIPIENT} please, thanks a lot for helping me out today`);
    expect(ctx).toContain(RECIPIENT);
    expect(ctx).not.toContain(REDACTED);
  });

  it('the final context pass redacts secrets even outside the excerpt', () => {
    expect(redactSecrets(`summary with 0x${PRIVATE_KEY} inside`)).toBe(`summary with ${REDACTED} inside`);
    expect(cleanText(`x ${'ab'.repeat(40)} y`).text).toBe('x [40-byte hex data] y');
  });
});

describe('finding 9b: internationalized hosts are punycode-encoded, never truncated', () => {
  it('a bare IDN host is sent in punycode (not "swap.org")', () => {
    const decoded = decodePersonalSign(utf8Hex(`Claim your airdrop at ${IDN_UNISWAP} today`), USER);
    expect(decoded.referencedHosts).toStrictEqual(['xn--unswap-qvf.org']);
    const [body] = buildRiskCheckBodies(decoded, undefined);
    expect(body?.domain).toBe('xn--unswap-qvf.org');
    expect(body?.context).not.toMatch(/references: swap\.org/u);
  });

  it('an IDN URL and an IDN origin are punycoded too', () => {
    expect(decodePersonalSign(utf8Hex(`Claim at https://${IDN_UNISWAP}/claim`), USER).referencedHosts).toStrictEqual(['xn--unswap-qvf.org']);
    expect(originHost(IDN_UNISWAP)).toBe('xn--unswap-qvf.org');
    expect(originHost(`https://${IDN_UNISWAP}`)).toBe('xn--unswap-qvf.org');
  });

  it('flags user@host links and javascript:/data: links', () => {
    const userinfo = decodePersonalSign(utf8Hex('Verify at https://app.uniswap.org@evil-claim.xyz/x'), USER);
    expect(userinfo.referencedHosts).toStrictEqual(['evil-claim.xyz']);
    expect(userinfo.warnings.join()).toContain('it actually opens evil-claim.xyz');
    expect(decodePersonalSign(utf8Hex('Open javascript:alert(1) now'), USER).warnings.join()).toContain('javascript:/data: link');
  });
});

describe('finding 9c: several addresses in a message are all checked (batch)', () => {
  it('two addresses: both checked, neither trusted to be "the" counterparty', () => {
    const decoded = decodePersonalSign(utf8Hex(`Claim for token ${USDC}, payout wallet ${DRAINER}`), USER);
    expect([decoded.counterparty, ...decoded.others.map((other) => other.address)]).toStrictEqual([USDC, DRAINER]);
    expect(decoded.summary).toContain('Addresses named in message (all checked)');
    const bodies = buildRiskCheckBodies(decoded, 'https://app.example.com');
    expect(bodies.map((body) => body.wallet)).toStrictEqual([USDC, DRAINER]);
    expect(bodies[1]?.context).toContain(`Checked address: counterparty ${DRAINER}`);
    for (const body of bodies) expect(body.context.length).toBeLessThanOrEqual(700);
  });

  it('at most three addresses are checked', () => {
    const many = ['0x1111111111111111111111111111111111111111', '0x2222222222222222222222222222222222222222', RECIPIENT, DRAINER];
    const decoded = decodePersonalSign(utf8Hex(`Addresses: ${many.join(' ')}`), USER);
    expect(buildRiskCheckBodies(decoded, undefined)).toHaveLength(3);
    expect(decoded.summary).toContain('and 1 more');
  });
});

describe('finding 8 (personal_sign): large payloads are summarized', () => {
  it('a 4 MiB message is not decoded and does not throw', () => {
    const decoded = decodePersonalSign(`0x${'61'.repeat(4 * 1024 * 1024)}`, USER);
    expect(decoded.counterparty).toBe(USER);
    expect(decoded.summary).toContain('large payload (4194304 bytes)');
    expect(decoded.warnings.join()).toContain('very large');
  });
});
