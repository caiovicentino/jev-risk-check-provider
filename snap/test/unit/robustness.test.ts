/**
 * @jest-environment node
 *
 * Regression tests for review finding 8 (probes p5, p6): nothing in the
 * decode -> body -> render pipeline may throw, whatever the input size or
 * shape, and every rendered tree must be valid Snap UI.
 */
import { describe, expect, it } from '@jest/globals';
import { RootJSXElementStruct } from '@metamask/snaps-sdk/jsx';

import { cleanText, decodeSignature, decodeTransaction } from '../../src/decode';
import type { Decoded } from '../../src/decode';
import type { CheckOutcome } from '../../src/request';
import { buildRiskCheckBodies, originHost, parseVerdict } from '../../src/request';
import { renderLocalOnly, renderOutcome } from '../../src/ui';
import { DRAINER, SAFE_TX_TYPES, USER, safeTx } from '../helpers';

const MiB = 1024 * 1024;

const OUTCOMES: CheckOutcome[] = [
  { kind: 'ok', verdict: parseVerdict({ checked: true, score: 90, tier: 'low', categories: [] }) as never },
  {
    kind: 'ok',
    verdict: parseVerdict({
      checked: true,
      score: 3,
      tier: 'critical',
      categories: ['known_scam_address'],
      evidence: { onchain: { status: 'ok', is_contract: false, activity: 'none' }, feeds: [{ source: 'x', status: 'hit' }], sanctions: { status: 'listed', as_of: '2026' } },
    }) as never,
  },
  { kind: 'batch', items: [{ status: 'ok', verdict: { checked: true, categories: [], score: 50, tier: 'high' } }, { status: 'unverified' }, { status: 'invalid' }] },
  { kind: 'network_error', timedOut: true },
  { kind: 'quota' },
  { kind: 'unverified' },
];

/** decode -> bodies -> render for every outcome; returns failures instead of throwing. */
function pipeline(decode: () => Decoded, origin: unknown): string | undefined {
  try {
    const decoded = decode();
    const bodies = buildRiskCheckBodies(decoded, origin);
    JSON.stringify(bodies);
    const host = originHost(origin);
    const results = bodies.length > 0 ? OUTCOMES.map((outcome) => renderOutcome(decoded, outcome, 'transaction', host)) : [renderLocalOnly(decoded, host)];
    for (const result of results) {
      if (!RootJSXElementStruct.is(result.content)) return 'invalid Snap UI';
      if (result.severity !== undefined && result.severity !== 'critical') return 'invalid severity';
    }
    for (const body of bodies) if (body.context.length > 700) return 'context too long';
    return undefined;
  } catch (error) {
    return `threw ${(error as Error).message}`;
  }
}

describe('p6: very large inputs never throw', () => {
  it('a 4 MiB personal_sign', () => {
    expect(pipeline(() => decodeSignature({ from: USER, data: `0x${'61'.repeat(4 * MiB)}`, signatureMethod: 'personal_sign' }), 'https://app.example.com')).toBeUndefined();
  });

  it('typed data with a 4 MiB declared bytes field and a 4 MiB undeclared field', () => {
    const blob = `0x${'ab'.repeat(4 * MiB)}`;
    const declared = safeTx(DRAINER, blob, 0);
    const undeclared = { ...safeTx(DRAINER, '0x', 0), message: { ...safeTx(DRAINER, '0x', 0).message, junk: blob } };
    for (const data of [declared, undeclared]) {
      expect(pipeline(() => decodeSignature({ from: USER, data, signatureMethod: 'eth_signTypedData_v4' }), 'https://app.safe.global')).toBeUndefined();
    }
    expect(decodeSignature({ from: USER, data: undeclared, signatureMethod: 'eth_signTypedData_v4' }).counterparty).toBe(DRAINER);
    expect(SAFE_TX_TYPES.SafeTx).toHaveLength(10);
  });

  it('cleanText on 16M characters of hex and base64-like runs', () => {
    for (const text of [`0x${'a'.repeat(16 * MiB)}`, 'Q'.repeat(16 * MiB), 'a'.repeat(16 * MiB)]) {
      expect(() => cleanText(text)).not.toThrow();
    }
  });

  it('20 MB of calldata and a deeply nested JSON string', () => {
    expect(pipeline(() => decodeTransaction({ from: USER, to: DRAINER, data: `0x3593564c${'00'.repeat(20 * MiB)}` }, 'eip155:1'), undefined)).toBeUndefined();
    expect(pipeline(() => decodeSignature({ from: USER, data: `${'['.repeat(5000)}${']'.repeat(5000)}` }), undefined)).toBeUndefined();
  });
});

describe('p5: fuzzing the full pipeline never throws', () => {
  const weird: unknown[] = [
    undefined, null, 0, -1, 1.5, NaN, Infinity, 2 ** 70, 10n ** 80n, -5n, true, '', ' ', '0x', '0X', '0x0', '0xzz', 'abc',
    '1e18', '-1', `0x${'f'.repeat(65)}`, `0x${'f'.repeat(64)}`, [], [1], {}, { a: 1 }, { toString: 1 }, '\u202E0x1',
    DRAINER, DRAINER.toUpperCase(), `0X${DRAINER.slice(2)}`, `${DRAINER} `, 'eip155:1', 'eip155:0', 'eip155:99999999999999999999', '0x1', '1',
  ];
  const origins: unknown[] = [undefined, null, '', 'metamask', 'npm:@x/y', 'https://app.example.com', 'http://192.168.0.1:80', 'https://[::1]', 'https://a..b', 42, {}, 'https://ex ample.com', 'javascript:alert(1)'];
  const datas: unknown[] = [
    ...weird,
    '0x095ea7b3',
    `0x095ea7b3${'00'.repeat(63)}`,
    `0x095ea7b3${'ff'.repeat(64)}`,
    `0xa22cb465${'ff'.repeat(64)}`,
    `0x87517c45${'ff'.repeat(128)}`,
    `0xd505accf${'ff'.repeat(128)}`,
    `0x2eb2c2d6${'00'.repeat(64)}`,
    `0xac9650d8${'ff'.repeat(96)}`,
    `0x6a761202${'ff'.repeat(320)}`,
    `0x3593564c${'ff'.repeat(96)}`,
    `0xe9ae5c53${'ff'.repeat(96)}`,
  ];

  it('transactions', () => {
    const failures: string[] = [];
    let index = 0;
    for (const to of weird) {
      for (const data of datas) {
        const value = weird[index % weird.length];
        const chain = weird[(index * 7) % weird.length];
        const origin = origins[index % origins.length];
        const from = weird[(index * 3) % weird.length];
        index += 1;
        const failure =
          pipeline(() => decodeTransaction({ from, to, value, data } as never, chain), origin) ??
          pipeline(() => decodeTransaction({ from, to, value, input: data } as never, chain), origin);
        if (failure) failures.push(`#${index}: ${failure}`);
      }
    }
    expect(failures).toStrictEqual([]);
  });

  it('signatures', () => {
    const methods: unknown[] = ['personal_sign', 'eth_signTypedData', 'eth_signTypedData_v3', 'eth_signTypedData_v4', 'eth_sign', undefined, 7, ''];
    const shapes: unknown[] = [
      ...weird,
      { types: {}, primaryType: 'Permit', domain: null, message: null },
      { types: { Permit: [{ name: 'spender', type: 'address' }] }, primaryType: 'Permit', domain: { chainId: {} }, message: { spender: DRAINER } },
      { types: { Permit: 5 }, primaryType: 'Permit', domain: {}, message: {} },
      { types: { EIP712Domain: [], X: [{ name: 'a', type: 'X[]' }] }, primaryType: 'X', domain: {}, message: { a: [{ a: [{ a: [] }] }] } },
      { types: { EIP712Domain: [], X: [{ name: 'a', type: 'constructor' }] }, primaryType: 'X', domain: {}, message: { a: 1 } },
      { types: { EIP712Domain: [], PermitBatch: [{ name: 'details', type: 'D[]' }, { name: 'spender', type: 'address' }], D: [{ name: 'amount', type: 'uint160' }] }, primaryType: 'PermitBatch', domain: {}, message: { spender: DRAINER, details: [null, 1, { amount: 'x' }] } },
      [{ type: 'address', name: 'to', value: DRAINER }, { type: 5, name: {}, value: null }, null, 'x'],
      JSON.stringify({ types: {}, primaryType: 'Permit', domain: {}, message: {} }),
      '[1,2,3]',
      '{',
      `0x${'7b'.repeat(10)}`,
    ];
    const failures: string[] = [];
    let index = 0;
    for (const method of methods) {
      for (const data of shapes) {
        const from = weird[index % weird.length];
        const origin = origins[index % origins.length];
        index += 1;
        const failure = pipeline(() => decodeSignature({ from, data, signatureMethod: method } as never, originHost(origin)), origin);
        if (failure) failures.push(`#${index}: ${failure}`);
      }
    }
    expect(failures).toStrictEqual([]);
  });
});
