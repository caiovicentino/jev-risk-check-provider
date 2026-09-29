/**
 * @jest-environment node
 *
 * Regression tests for review findings 1, 2 and 7-SafeTx (probes p1, p7):
 * the Snap must decode exactly what MetaMask signs. Every "same hash" claim
 * is proven with @metamask/eth-sig-util, the encoder MetaMask uses.
 */
import { describe, expect, it } from '@jest/globals';

import { canonicalizeTypedData, decodeTypedData } from '../../src/decode';
import type { CanonValue } from '../../src/decode';
import {
  DRAINER,
  MAX_UINT160,
  MAX_UINT256,
  SAFE,
  UNIVERSAL_ROUTER,
  USDC,
  USER,
  ZERO,
  daiPermit,
  eip712Hash,
  erc2612Permit,
  permitSingle,
  safeTx,
} from '../helpers';

const DECIMAL_DRAINER = BigInt(DRAINER).toString(10);

function signs(data: unknown): string | undefined {
  try {
    return eip712Hash(data);
  } catch {
    return undefined;
  }
}

describe('p1: permit variants that sign the canonical drainer hash', () => {
  const canonical = erc2612Permit(DRAINER, MAX_UINT256.toString());
  const canonicalHash = eip712Hash(canonical);
  const variants: [string, unknown][] = [
    ['spender as a DECIMAL string', erc2612Permit(DECIMAL_DRAINER, MAX_UINT256.toString())],
    ['spender with an uppercase 0X prefix', erc2612Permit(`0X${DRAINER.slice(2).toUpperCase()}`, MAX_UINT256.toString())],
    ['value = 0x + 8 leading zeros + 64 f', erc2612Permit(DRAINER, `0x${'0'.repeat(8)}${'f'.repeat(64)}`)],
    ['value = 0b + 256 ones', erc2612Permit(DRAINER, `0b${'1'.repeat(256)}`)],
    ['value = decimal with leading zeros', erc2612Permit(DRAINER, `000${MAX_UINT256.toString()}`)],
    ['value with surrounding whitespace', erc2612Permit(DRAINER, ` ${MAX_UINT256.toString()}\n`)],
    ['undeclared decoy key allowed:false', erc2612Permit(DRAINER, MAX_UINT256.toString(), 1, { allowed: false })],
    ['undeclared decoy key spender2', erc2612Permit(DRAINER, MAX_UINT256.toString(), 1, { spender2: UNIVERSAL_ROUTER })],
  ];

  it.each(variants)('%s: same hash, same spender, UNLIMITED', (_label, data) => {
    expect(signs(data)).toBe(canonicalHash);
    const decoded = decodeTypedData(data, USER);
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.role).toBe('spender');
    expect(decoded.unlimited).toBe(true);
    expect(decoded.interaction).toStrictEqual({ type: 'permit_signature', unlimited: true });
    expect(decoded.payment).toStrictEqual({ network: 'eip155:1', pay_to: DRAINER, amount: MAX_UINT256.toString(), asset: USDC });
  });

  it('flags non-standard encodings as warnings in the context', () => {
    expect(decodeTypedData(variants[0]?.[1], USER).warnings.join()).toContain(`signs as ${DRAINER}`);
  });

  it('an unsignable (negative) amount fails closed as UNLIMITED', () => {
    for (const value of ['-1', -1]) {
      const data = erc2612Permit(DRAINER, value);
      expect(signs(data)).toBeUndefined();
      const decoded = decodeTypedData(data, USER);
      expect(decoded.counterparty).toBe(DRAINER);
      expect(decoded.unlimited).toBe(true);
      expect(decoded.amountLabel).toContain('UNKNOWN');
      expect(decoded.interaction).toStrictEqual({ type: 'permit_signature', unlimited: true });
      expect(decoded.warnings.join()).toContain('cannot sign this request as-is');
    }
  });

  it('Permit2 PermitSingle: decimal spender and zero-padded hex amount sign the canonical hash', () => {
    const hash = eip712Hash(permitSingle(DRAINER, MAX_UINT160.toString()));
    for (const data of [
      permitSingle(DECIMAL_DRAINER, MAX_UINT160.toString()),
      permitSingle(DRAINER, `0x${'0'.repeat(30)}${'f'.repeat(40)}`),
    ]) {
      expect(signs(data)).toBe(hash);
      const decoded = decodeTypedData(data, USER);
      expect(decoded.counterparty).toBe(DRAINER);
      expect(decoded.interaction).toStrictEqual({ type: 'permit_signature', unlimited: true });
    }
  });
});

describe('p1/p8: DAI permit `allowed` follows JavaScript truthiness', () => {
  const trueHash = eip712Hash(daiPermit(true));
  const falseHash = eip712Hash(daiPermit(false));

  it.each([['"false"', 'false'], ['"0"', '0'], ['1', 1], ['"yes"', 'yes']])('allowed = %s signs as TRUE and is an UNLIMITED permit', (_label, allowed) => {
    const data = daiPermit(allowed);
    expect(signs(data)).toBe(trueHash);
    const decoded = decodeTypedData(data, USER);
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.action).toBe('DAI-style permit');
    expect(decoded.unlimited).toBe(true);
    expect(decoded.interaction).toStrictEqual({ type: 'permit_signature', unlimited: true });
    expect(decoded.warnings.join()).toContain('which signs as TRUE');
  });

  it.each([['false', false], ['0', 0], ['""', ''], ['null', null]])('allowed = %s signs as FALSE (a revocation)', (_label, allowed) => {
    const data = daiPermit(allowed);
    expect(signs(data)).toBe(falseHash);
    const decoded = decodeTypedData(data, USER);
    expect(decoded.action).toBe('DAI-style permit (revoke)');
    expect(decoded.unlimited).toBe(false);
    expect(decoded.interaction).toStrictEqual({ type: 'message_signature' });
  });

  it('an undeclared `allowed` key never turns an EIP-2612 permit into a revocation', () => {
    const decoded = decodeTypedData(erc2612Permit(DRAINER, '5', 1, { allowed: false }), USER);
    expect(decoded.action).toBe('EIP-2612 permit');
    expect(decoded.interaction).toStrictEqual({ type: 'permit_signature' });
  });
});

describe('p7: SafeTx decoys', () => {
  const canonical = safeTx(DRAINER, '0xa9059cbb', 1);
  const hash = eip712Hash(canonical);

  it.each([
    ['undeclared spender = router', safeTx(DRAINER, '0xa9059cbb', 1, { spender: UNIVERSAL_ROUTER })],
    ['`to` as a decimal string', safeTx(DECIMAL_DRAINER, '0xa9059cbb', 1)],
  ])('%s signs the canonical hash; the DELEGATECALL target is checked and flagged', (_label, data) => {
    expect(signs(data)).toBe(hash);
    const decoded = decodeTypedData(data, USER);
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.counterparty).not.toBe(UNIVERSAL_ROUTER);
    expect(decoded.danger.join()).toContain(`DELEGATECALL to ${DRAINER}`);
    expect(decoded.summary).toContain(`SafeTx for Safe ${SAFE}`);
  });
});

describe('canonicalization agrees with eth-sig-util on every value', () => {
  const mk = (type: string, value: unknown) => ({
    types: { EIP712Domain: [], Probe: [{ name: 'a', type }] },
    primaryType: 'Probe',
    domain: {},
    message: { a: value },
  });
  const values: unknown[] = [
    DRAINER,
    DRAINER.toUpperCase().replace('0X', '0x'),
    `0X${DRAINER.slice(2)}`,
    DECIMAL_DRAINER,
    `00${DECIMAL_DRAINER}`,
    DRAINER.slice(2),
    '0x1234',
    '0x123',
    `0x00${DRAINER.slice(2)}`,
    '0x',
    '0X1',
    '',
    ' 12 ',
    '+5',
    '-5',
    '0b101',
    '0o17',
    '1e3',
    'abc',
    'zz',
    'false',
    'true',
    255,
    0,
    -1,
    1.5,
    2 ** 60,
    true,
    false,
    null,
    [],
    {},
  ];
  const toSignable = (value: CanonValue): unknown => (typeof value === 'bigint' ? value.toString() : value);

  it.each(['address', 'uint256', 'uint160', 'uint8', 'bool', 'int256'])('type %s', (type) => {
    for (const value of values) {
      const data = mk(type, value);
      const signed = signs(data);
      const canon = canonicalizeTypedData(data);
      if ('error' in canon) throw new Error(canon.error);
      if (signed === undefined) {
        expect({ value, unsignable: canon.unsignable.length > 0 }).toStrictEqual({ value, unsignable: true });
      } else {
        expect({ value, unsignable: canon.unsignable }).toStrictEqual({ value, unsignable: [] });
        expect({ value, hash: signs(mk(type, toSignable(canon.message.a))) }).toStrictEqual({ value, hash: signed });
      }
    }
  });

  it('keeps only declared fields and reports undeclared primary types as unsignable', () => {
    const canon = canonicalizeTypedData(erc2612Permit(DRAINER, '1', 1, { spender2: UNIVERSAL_ROUTER, allowed: false }));
    if ('error' in canon) throw new Error(canon.error);
    expect(Object.keys(canon.message).sort()).toStrictEqual(['deadline', 'nonce', 'owner', 'spender', 'value']);
    const undeclared = { types: {}, primaryType: 'OrderComponents', domain: {}, message: { offerer: USER } };
    expect(signs(undeclared)).toBeUndefined();
    expect(canonicalizeTypedData(undeclared)).toStrictEqual({ error: 'its primary type "OrderComponents" is not declared in its types' });
    const decoded = decodeTypedData(undeclared, USER);
    expect(decoded.counterparty).toBeUndefined();
    expect(decoded.localNote).toContain('cannot sign it as-is');
  });

  it('a struct field that is null or missing is hashed as zero (V4), not unsignable', () => {
    const data = {
      types: { EIP712Domain: [], Outer: [{ name: 'inner', type: 'Inner' }], Inner: [{ name: 'to', type: 'address' }] },
      primaryType: 'Outer',
      domain: {},
      message: { inner: null },
    };
    expect(signs(data)).toBeDefined();
    const canon = canonicalizeTypedData(data);
    if ('error' in canon) throw new Error(canon.error);
    expect(canon.message.inner).toBeNull();
    expect(canon.unsignable).toStrictEqual([]);
    expect(ZERO).toHaveLength(42);
  });
});
