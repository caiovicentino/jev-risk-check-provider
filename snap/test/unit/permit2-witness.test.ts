/**
 * @jest-environment node
 *
 * Audit finding cg-1: an x402 payment signed through the Permit2 transfer
 * method (PermitWitnessTransferFrom to the x402 Permit2 proxy) names its payee
 * only in the witness (`to`). The payee must be checked, bound to the permit's
 * amount and token, not just the proxy. Types are @x402/evm 2.27's
 * permit2WitnessTypes / uptoPermit2WitnessTypes; every fixture is signable.
 */
import { describe, expect, it } from '@jest/globals';

import { decodeTypedData } from '../../src/decode';
import { buildRiskCheckBodies } from '../../src/request';
import { DRAINER, PERMIT2, USER, eip712Hash } from '../helpers';

const USDC_BASE = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
const EXACT_PROXY = '0x402085c248eea27d92e8b30b2c58ed07f9e20001';
const UPTO_PROXY = '0x4020a4f3b7b90cca423b9fabcc0ce57c6c240002';
const FACILITATOR = '0x2222222222222222222222222222222222222222';

const TOKEN_PERMISSIONS = [
  { name: 'token', type: 'address' },
  { name: 'amount', type: 'uint256' },
];
const PERMIT_WITNESS = [
  { name: 'permitted', type: 'TokenPermissions' },
  { name: 'spender', type: 'address' },
  { name: 'nonce', type: 'uint256' },
  { name: 'deadline', type: 'uint256' },
  { name: 'witness', type: 'Witness' },
];

function x402Permit2(witnessFields: { name: string; type: string }[], witness: Record<string, unknown>, spender = EXACT_PROXY, amount = '10000') {
  return {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      PermitWitnessTransferFrom: PERMIT_WITNESS,
      TokenPermissions: TOKEN_PERMISSIONS,
      Witness: witnessFields,
    },
    primaryType: 'PermitWitnessTransferFrom',
    domain: { name: 'Permit2', chainId: 8453, verifyingContract: PERMIT2 },
    message: {
      permitted: { token: USDC_BASE, amount },
      spender,
      nonce: '77',
      deadline: '1790000000',
      witness,
    },
  };
}

const EXACT_WITNESS = [
  { name: 'to', type: 'address' },
  { name: 'validAfter', type: 'uint256' },
];

function decode(data: unknown) {
  expect(() => eip712Hash(data)).not.toThrow();
  return decodeTypedData(data, USER);
}

describe('cg-1: the payee of an x402 Permit2 payment is checked, bound to the permit', () => {
  it('exact scheme (Witness{to, validAfter}): the payee is the primary counterparty; the proxy is checked too', () => {
    const decoded = decode(x402Permit2(EXACT_WITNESS, { to: DRAINER, validAfter: '0' }));
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.role).toBe('recipient');
    expect(decoded.interaction).toStrictEqual({ type: 'token_transfer' });
    expect(decoded.payment).toStrictEqual({ network: 'eip155:8453', pay_to: DRAINER, amount: '10000', asset: USDC_BASE });
    expect(decoded.others.map((other) => other.address)).toStrictEqual([EXACT_PROXY]);
    expect(decoded.summary).toContain('the x402 exact-payment Permit2 proxy');
    expect(decoded.summary).toContain(`to ${DRAINER} (witness "to"): an x402 payment`);
    expect(decoded.danger).toStrictEqual([]);
    expect(decoded.opaque).toBeUndefined();
    const bodies = buildRiskCheckBodies(decoded, 'https://api.example.com');
    expect(bodies.map((body) => body.wallet)).toStrictEqual([DRAINER, EXACT_PROXY]);
    expect(bodies[0]?.payment).toStrictEqual({ network: 'eip155:8453', pay_to: DRAINER, amount: '10000', asset: USDC_BASE });
    expect(bodies[0]?.interaction).toStrictEqual({ type: 'token_transfer' });
    expect(bodies[1]?.interaction).toStrictEqual({ type: 'permit_signature' });
    expect(bodies[0]?.context).toContain(`Checked address: recipient ${DRAINER}`);
  });

  it('a witness with an extra bytes field is still recognized (not opaque) and still binds the payee', () => {
    const decoded = decode(
      x402Permit2([...EXACT_WITNESS, { name: 'extra', type: 'bytes' }], { to: DRAINER, validAfter: '0', extra: '0x1234' }),
    );
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.payment?.amount).toBe('10000');
    expect(decoded.opaque).toBeUndefined();
  });

  it('upto scheme (Witness{to, facilitator, validAfter}): the payee is bound with the maximum amount', () => {
    const decoded = decode(
      x402Permit2(
        [
          { name: 'to', type: 'address' },
          { name: 'facilitator', type: 'address' },
          { name: 'validAfter', type: 'uint256' },
        ],
        { to: DRAINER, facilitator: FACILITATOR, validAfter: '0' },
        UPTO_PROXY,
        '2500000',
      ),
    );
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.payment).toStrictEqual({ network: 'eip155:8453', pay_to: DRAINER, amount: '2500000', asset: USDC_BASE });
    expect(decoded.summary).toContain('the x402 upto-payment Permit2 proxy');
    expect(decoded.others.map((other) => other.address)).toContain(UPTO_PROXY);
  });

  it('a payment to the signer itself adds no payee check (the proxy stays the counterparty)', () => {
    const decoded = decode(x402Permit2(EXACT_WITNESS, { to: USER, validAfter: '0' }));
    expect(decoded.counterparty).toBe(EXACT_PROXY);
    expect(decoded.summary).toContain('to you (witness "to")');
  });

  it('a payee in a Permit2 witness of any spender is checked (not only the x402 proxies)', () => {
    const other = '0x3333333333333333333333333333333333333333';
    const decoded = decode(x402Permit2(EXACT_WITNESS, { to: DRAINER, validAfter: '0' }, other));
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.others.map((candidate) => candidate.address)).toStrictEqual([other]);
    expect(decoded.summary).not.toContain('x402 payment');
  });
});
