/**
 * @jest-environment node
 *
 * SDK review (2026-10-16), findings 2 and 5: every counterparty a request
 * names is kept (the signing guard checks them all; the Snap checks
 * MAX_CHECKS and says so), a batch that is not read in full is `opaque`
 * (MultiSend, multicall and ERC-7579 batches past 32 calls, leftover bytes,
 * Seaport bulk listings past 64 orders), and an unrecognized typed-data
 * struct that grants a spender, delegatee or operator an amount is read as a
 * permit, not as a plain message.
 */
import { describe, expect, it } from '@jest/globals';
import { RootJSXElementStruct } from '@metamask/snaps-sdk/jsx';

import { decodeTransaction, decodeTypedData } from '../../src/decode';
import type { BatchItem } from '../../src/request';
import { buildRiskCheckBodies, MAX_CHECKS } from '../../src/request';
import { renderOutcome, renderUnpaid } from '../../src/ui';
import {
  DOMAIN_TYPE_4,
  DRAINER,
  EMPTY_ORDER,
  MULTISEND_CALL_ONLY,
  SAFE,
  SEAPORT_DOMAIN,
  SEAPORT_TYPES,
  USDC,
  USER,
  calldata,
  eip712Hash,
  encBytes,
  eth,
  execute7579,
  multiSend,
  multicall,
  nft,
  orderComponents,
  safeExec,
  textOf,
  word,
} from '../helpers';

const BAYC = '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d';
const DECOYS = ['0x1111111111111111111111111111111111111112', '0x3333333333333333333333333333333333333333', '0x4444444444444444444444444444444444444444'];
const transfer = (to: string, amount: bigint) => calldata('a9059cbb', to, amount);
const checked = (decoded: { counterparty?: string | undefined; others: { address: string }[] }) => [decoded.counterparty, ...decoded.others.map((other) => other.address)];
const safeBatch = (entries: { operation: 0 | 1; to: string; value: bigint; data: string }[]) =>
  decodeTransaction({ from: USER, to: SAFE, value: '0x0', data: safeExec(MULTISEND_CALL_ONLY, 0n, multiSend(entries), 1) }, 'eip155:1');

describe('every counterparty is kept; how many are checked is the caller’s decision', () => {
  const batch = safeBatch([...DECOYS.map((to) => ({ operation: 0 as const, to: USDC, value: 0n, data: transfer(to, 1n) })), { operation: 0, to: USDC, value: 0n, data: transfer(DRAINER, 10n ** 12n) }]);

  it('a Safe MultiSend paying four recipients names all four', () => {
    expect(checked(batch)).toHaveLength(4);
    expect(checked(batch)).toContain(DRAINER);
    expect(batch.opaque).toBeUndefined();
  });

  it('the Snap still builds MAX_CHECKS bodies; a caller may ask for all of them', () => {
    expect(buildRiskCheckBodies(batch)).toHaveLength(MAX_CHECKS);
    expect(buildRiskCheckBodies(batch, undefined, 10).map((body) => body.wallet)).toContain(DRAINER);
  });
});

describe('a batch that is not read in full is opaque', () => {
  const inert = { operation: 0 as const, to: SAFE, value: 0n, data: '0x' };

  it('MultiSend: the 33rd call is not decoded, so the batch is opaque', () => {
    const decoded = safeBatch([...Array.from({ length: 32 }, () => inert), { operation: 0, to: USDC, value: 0n, data: transfer(DRAINER, 10n ** 12n) }]);
    expect(checked(decoded)).not.toContain(DRAINER);
    expect(decoded.opaque).toContain('more than 32 calls');
  });

  it('MultiSend: bytes left over after the last call that parses are opaque', () => {
    // One well-formed call, then a header announcing more data than the batch holds.
    const call = `00${USDC.slice(2)}${word(0n)}${word(68n)}${transfer(DECOYS[0] as string, 1n).slice(2)}`;
    const truncatedCall = `00${DRAINER.slice(2)}${word(0n)}${word(4096n)}${'ab'.repeat(16)}`;
    const data = safeExec(MULTISEND_CALL_ONLY, 0n, `0x8d80ff0a${word(0x20n)}${encBytes(`0x${call}${truncatedCall}`)}`, 1);
    const decoded = decodeTransaction({ from: USER, to: SAFE, value: '0x0', data }, 'eip155:1');
    expect(decoded.opaque).toMatch(/bytes of the multiSend batch could not be decoded/u);
  });

  it('a multicall of 33 calls is opaque', () => {
    const decoded = decodeTransaction({ from: USER, to: '0x2626664c2603336e57b271c5c0b26f421741e481', value: '0x0', data: multicall(Array.from({ length: 33 }, () => transfer(DRAINER, 1n))) }, 'eip155:1');
    expect(decoded.opaque).toContain('33 calls; only the first 32 were decoded');
  });

  it('an ERC-7579 batch of 33 calls on the signer’s own account is opaque', () => {
    const calls = Array.from({ length: 33 }, () => ({ to: USDC, value: 0n, data: transfer(DRAINER, 1n) }));
    const decoded = decodeTransaction({ from: USER, to: USER, value: '0x0', data: execute7579('batch', calls) }, 'eip155:1');
    expect(decoded.opaque).toContain('33 batched calls; only the first 32 were decoded');
  });

  it('a Seaport bulk listing of more than 64 orders is opaque; 4 orders are read in full', () => {
    const leaves = [orderComponents([nft(BAYC, '1')], [eth('1', USER)]), ...Array.from({ length: 127 }, () => EMPTY_ORDER)];
    let tree: unknown[] = leaves;
    while (tree.length > 1) tree = Array.from({ length: tree.length / 2 }, (_v, index) => [tree[2 * index], tree[2 * index + 1]]);
    const bulk = { types: { ...SEAPORT_TYPES, BulkOrder: [{ name: 'tree', type: `OrderComponents${'[2]'.repeat(7)}` }] }, primaryType: 'BulkOrder', domain: SEAPORT_DOMAIN, message: { tree: tree[0] } };
    expect(() => eip712Hash(bulk)).not.toThrow();
    expect(decodeTypedData(bulk, USER).opaque).toContain('more than 64 orders');
    const small = { ...bulk, types: { ...SEAPORT_TYPES, BulkOrder: [{ name: 'tree', type: 'OrderComponents[2][2]' }] }, message: { tree: [[leaves[0], EMPTY_ORDER], [EMPTY_ORDER, EMPTY_ORDER]] } };
    expect(decodeTypedData(small, USER).opaque).toBeUndefined();
  });
});

describe('an unrecognized struct that grants an amount is read as a permit', () => {
  const delegation = (value: bigint) => ({
    types: {
      EIP712Domain: DOMAIN_TYPE_4,
      DelegationWithSig: [
        { name: 'delegatee', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
      ],
    },
    primaryType: 'DelegationWithSig',
    domain: { name: 'Aave Ethereum Variable Debt USDC', version: '1', chainId: 1, verifyingContract: '0x72e95b8931767c79ba4eee721354d6e99a61d004' },
    message: { delegatee: DRAINER, value: value.toString(), nonce: '0', deadline: '1790000000' },
  });

  it('Aave credit delegation of 2^256-1: the delegatee is checked as an UNLIMITED permit', () => {
    const data = delegation((1n << 256n) - 1n);
    expect(() => eip712Hash(data)).not.toThrow();
    const decoded = decodeTypedData(data, USER);
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.interaction).toStrictEqual({ type: 'permit_signature', unlimited: true });
    expect(buildRiskCheckBodies(decoded)[0]?.interaction).toStrictEqual({ type: 'permit_signature', unlimited: true });
  });

  it('a bounded amount is a permit without the unlimited flag; zero grants nothing', () => {
    expect(decodeTypedData(delegation(1_000_000n), USER).interaction).toStrictEqual({ type: 'permit_signature' });
    expect(decodeTypedData(delegation(0n), USER).interaction).toStrictEqual({ type: 'message_signature' });
  });
});

describe('the Snap says when a request names more counterparties than it checks', () => {
  const batch = safeBatch([...DECOYS.map((to) => ({ operation: 0 as const, to: USDC, value: 0n, data: transfer(to, 1n) })), { operation: 0, to: USDC, value: 0n, data: transfer(DRAINER, 10n ** 12n) }]);
  const good: BatchItem = { status: 'ok', verdict: { checked: true, categories: [], score: 92, tier: 'low' } };

  it('a batch whose checked addresses are clean is NOT verified while others were not checked', () => {
    const result = renderOutcome(batch, { kind: 'batch', items: [good, good, good] }, 'transaction', 'app.safe.global');
    expect(RootJSXElementStruct.is(result.content)).toBe(true);
    const text = textOf(result.content);
    expect(text).toContain('not fully checked — NOT verified');
    expect(text).toContain('1 of the 4 addresses');
    expect(text).not.toContain('No significant risk');
  });

  it('unpaid: the addresses not listed are counted', () => {
    const result = renderUnpaid(batch, 'app.safe.global', 'transaction');
    expect(RootJSXElementStruct.is(result.content)).toBe(true);
    expect(textOf(result.content)).toContain('Also involved: 1 more address, not shown.');
  });
});
