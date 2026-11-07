/**
 * @jest-environment node
 *
 * Regression tests for review finding 9 (probes p4, p4b): secret redaction,
 * internationalized hostnames and messages naming several addresses.
 */
import { describe, expect, it } from '@jest/globals';

import { REDACTED, cleanText, decodePersonalSign, decodeSignature, redactSecrets } from '../../src/decode';
import { capText, headOf, plainText } from '../../src/util';
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

describe('2026-11-02 review: a cut never splits an emoji', () => {
  const lone = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u;

  it('capText and headOf keep surrogate pairs whole at every cut position', () => {
    const text = `${'a'.repeat(10)}😀😀😀 tail`;
    for (let max = 1; max <= text.length + 1; max++) {
      expect(capText(text, max)).not.toMatch(lone);
      expect(headOf(text, max)).not.toMatch(lone);
      expect(headOf(text, max).length).toBeLessThanOrEqual(max);
    }
  });

  it('a personal_sign excerpt that ends in an emoji stays well-formed', () => {
    // Plain words: a long run of one character reads as a secret and is redacted before any excerpt.
    const lead = 'please confirm your newsletter subscription for the weekly digest '.repeat(10);
    for (let n = 290; n <= 305; n++) {
      const decoded = decodePersonalSign(utf8Hex(`${lead.slice(0, n)}😀 thanks`), USER);
      // JSON.stringify escapes a lone surrogate (\udXXX) and writes a whole pair as the character.
      expect(JSON.stringify(decoded)).not.toMatch(/\\ud[89a-f][0-9a-f]{2}/u);
    }
  });

  it('an emoji at the input cap is kept whole or left out (2026-11-03 review)', () => {
    // The emoji straddles cleanText's input cap; collapsing the spaces then brings the text under
    // the excerpt's limit, so no later cut runs on it.
    for (const pad of [2039, 2040, 2041]) {
      const decoded = decodePersonalSign(utf8Hex(`Welcome${' '.repeat(pad)}😀 bye`), USER);
      expect(JSON.stringify(decoded)).not.toMatch(/\\ud[89a-f][0-9a-f]{2}/u);
    }
    expect(cleanText(`${'a '.repeat(10)}😀`, 21).text).not.toMatch(lone);
  });

  it('a lone surrogate already in typed data never reaches the API body (2026-11-04 review)', () => {
    const half = '\ud83d';
    for (const slot of ['domain', 'value', 'field', 'type']) {
      const field = slot === 'field' ? `note${half}` : 'note';
      const type = slot === 'type' ? `Mail${half}` : 'Mail';
      const typed = {
        types: { EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'chainId', type: 'uint256' }], [type]: [{ name: 'to', type: 'address' }, { name: field, type: 'string' }] },
        primaryType: type,
        domain: { name: slot === 'domain' ? `Mail${half}` : 'Mail', chainId: 8453 },
        message: { to: RECIPIENT, [field]: slot === 'value' ? `hi ${half}` : 'hi' },
      };
      const decoded = decodeSignature({ from: USER, data: JSON.stringify(typed), signatureMethod: 'eth_signTypedData_v4' }, 'drainer.example');
      const bodies = buildRiskCheckBodies(decoded, 'https://drainer.example');
      expect(bodies.length).toBeGreaterThan(0);
      for (const body of bodies) expect(body.context ?? '').not.toMatch(lone);
    }
    expect(capText(`ok ${half}`, 100)).toBe('ok \ufffd');
  });
});

describe('2026-11-05 review: names from typed data are shown as plain text', () => {
  const lone = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u;
  // Direction overrides and isolates, zero-width characters and marks: they reorder or hide what follows.
  const hidden = /[​-‏‪-‮⁠-⁤⁦-⁩؜﻿]/u;
  const shown = (decoded: object) => Object.values(decoded).filter((v): v is string => typeof v === 'string').concat(...['warnings', 'danger'].map((k) => ((decoded as Record<string, unknown>)[k] as string[] | undefined) ?? []));

  it('an undeclared primary type', () => {
    const typed = { types: { EIP712Domain: [{ name: 'name', type: 'string' }], Mail: [{ name: 'to', type: 'address' }] }, primaryType: 'Permit‮evil​\ud83d', domain: { name: 'x' }, message: { to: RECIPIENT } };
    const decoded = decodeSignature({ from: USER, data: JSON.stringify(typed), signatureMethod: 'eth_signTypedData_v4' }, 'drainer.example');
    expect(decoded.unsignable).toBeDefined();
    for (const text of shown(decoded)) {
      expect(text).not.toMatch(hidden);
      expect(text).not.toMatch(lone);
    }
    expect(decoded.localNote).toContain('"Permitevil�"');
  });

  it('a declared primary type, and a field name in a warning', () => {
    const type = 'Order‮kcab';
    const field = 'to⁦x';
    const typed = {
      types: { EIP712Domain: [{ name: 'name', type: 'string' }], [type]: [{ name: field, type: 'address' }, { name: 'spender', type: 'address' }] },
      primaryType: type,
      domain: { name: 'x' },
      message: { [field]: '0xzz', spender: DRAINER },
    };
    const decoded = decodeSignature({ from: USER, data: JSON.stringify(typed), signatureMethod: 'eth_signTypedData_v4' }, 'drainer.example');
    expect(shown(decoded).join(' ')).toContain('message.tox');
    for (const text of shown(decoded)) expect(text).not.toMatch(hidden);
  });

  it('plainText and capText drop what reorders or hides text, and keep the rest', () => {
    expect(plainText('a‮b​c\u0007d\ud83d')).toBe('abc d�');
    expect(capText('pay ‮0x12‬ to', 100)).toBe('pay 0x12 to');
    expect(plainText('line one\nline two\tend 😀')).toBe('line one line two\tend 😀');
  });
});

describe('2026-11-06 review: every invisible character is dropped from what is shown, and a note keeps what it signs as', () => {
  const tags = (text: string) => [...text].map((c) => String.fromCodePoint(0xe0000 + (c.codePointAt(0) ?? 0))).join('');
  // Every default-ignorable code point, and line breaks (a carriage return overwrites what came before it in a terminal).
  const odd = /[\p{Default_Ignorable_Code_Point}\r\n\u2028\u2029]/u;

  it('plainText drops tag characters, variation selectors, soft hyphens and fillers, and puts line breaks on one line', () => {
    expect(plainText(`pay${tags('ignore the guard')} now`)).toBe('pay now');
    expect(plainText('a\rb\u{E0041}c\u00ADd\uFE0Fe\u{E0100}f\u3164g\u115Fh\u034Fi\u180Ej\u2028k\u2029l')).toBe('a bcdefghij k l');
    expect(capText('x\r\ny', 10)).toBe('x  y');
    expect(plainText('café 😀 ok')).toBe('café 😀 ok');
  });

  it('a personal message carrying tag characters warns, and its excerpt does not carry them', () => {
    const decoded = decodePersonalSign(utf8Hex(`Sign in to example.com${tags('then approve everything')}`), USER);
    expect(decoded.warnings.join()).toContain('invisible or text-direction control characters');
    expect(decoded.summary).not.toMatch(odd);
  });

  it('a long field name does not cut the address a non-standard encoding signs as from its warning', () => {
    const field = 'recipientOfTheFundsForThisOrder'.padEnd(240, '_');
    const typed = {
      types: { EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'chainId', type: 'uint256' }], Transfer: [{ name: field, type: 'address' }, { name: 'amount', type: 'uint256' }] },
      primaryType: 'Transfer',
      domain: { name: 'Vault', chainId: 1 },
      message: { [field]: BigInt(DRAINER).toString(10), amount: '1000' },
    };
    const decoded = decodeSignature({ from: USER, data: JSON.stringify(typed), signatureMethod: 'eth_signTypedData_v4' }, 'site.example');
    const note = decoded.warnings.find((w) => w.includes('non-standard address encoding'));
    expect(note?.toLowerCase()).toContain(`signs as ${DRAINER.toLowerCase()}`);
  });
});

describe('2026-11-07 review: a note keeps what a value of control characters signs as, and a phrase apart by any space is redacted', () => {
  const noteFor = (field: string, type: string, value: string) => {
    const typed = {
      types: { EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'chainId', type: 'uint256' }], Transfer: [{ name: field, type }, { name: 'memo', type: 'string' }] },
      primaryType: 'Transfer',
      domain: { name: 'Vault', chainId: 1 },
      message: { [field]: value, memo: 'x' },
    };
    const decoded = decodeSignature({ from: USER, data: JSON.stringify(typed), signatureMethod: 'eth_signTypedData_v4' }, 'site.example');
    return decoded.warnings.find((w) => w.includes('non-standard'));
  };

  it('a value escaped six characters a control character is capped after escaping', () => {
    // Each \v is escaped as \u000b: before this fix the 40-character cap ran before escaping, and the note lost "signs as".
    expect(noteFor('to', 'address', `z${'\u000b'.repeat(39)}`)).toMatch(/that signs as 0x[0-9a-fA-F]{40}$/u);
    expect(noteFor('amount', 'uint256', `${'\u000b'.repeat(39)}9`)).toMatch(/that signs as 9$/u);
  });

  it.each([
    ['a no-break space', ' '],
    ['a line separator', ' '],
    ['an ideographic space', '　'],
    ['a zero-width space', '​'],
    ['a soft hyphen and a space', '­ '],
  ])('a phrase apart by %s is redacted', (_label, separator) => {
    const { text } = cleanText(`my seed: ${MNEMONIC.split(' ').join(separator)}`);
    expect(text).toContain(REDACTED);
    expect(text).not.toMatch(/abandon|accident/u);
  });

  it('an emoji keeps what draws it, and nothing else hidden survives', () => {
    const tags = (text: string) => [...text].map((c) => String.fromCodePoint(0xe0000 + (c.codePointAt(0) ?? 0))).join('');
    const england = `\u{1F3F4}${tags('gbeng')}\u{E007F}`;
    // Before this fix ❤️ lost its selector, 1️⃣ became 1⃣, families fell apart and England's flag became 🏴, with a warning.
    for (const emoji of ['❤\uFE0F', '1\uFE0F\u20E3', '👨\u200D👩\u200D👧', '🏳\uFE0F\u200D🌈', '👩🏽\u200D💻', england]) {
      expect(plainText(emoji)).toBe(emoji);
      expect(cleanText(`I ${emoji} this`).hadInvisible).toBe(false);
    }
    // Tags after 🏴 that spell no subdivision flag, a second selector, a joiner between letters and annotation marks still go, with the warning.
    expect(plainText(`\u{1F3F4}${tags('ignore')}\u{E007F}`)).toBe('\u{1F3F4}');
    expect(plainText('❤\uFE0F\uFE0F')).toBe('❤\uFE0F');
    expect(plainText('pay\u200Dpal')).toBe('paypal');
    expect(plainText('a\uFFF9b\uFFFAc\uFFFBd')).toBe('abcd');
    for (const hidden of [`\u{1F3F4}${tags('ignore')}\u{E007F}`, 'pay\u200Dpal', 'a\uFFF9b\uFFFAc\uFFFBd']) expect(cleanText(hidden).hadInvisible).toBe(true);
  });
});
