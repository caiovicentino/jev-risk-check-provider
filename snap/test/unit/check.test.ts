/**
 * @jest-environment node
 */
import { describe, expect, it } from '@jest/globals';

import { insightHandlers, runCheck } from '../../src/check';
import { PAID_CHECKS_SUPPORTED } from '../../src/config';
import { decodeSignature, decodeTransaction } from '../../src/decode';
import type { FetchLike } from '../../src/request';
import { NOT_SENT_TEXT } from '../../src/ui';
import {
  BAYC,
  DRAINER,
  MAX_UINT256,
  RECIPIENT,
  SAFE,
  UNIVERSAL_ROUTER,
  USDC,
  USER,
  WETH,
  calldata,
  erc20Item,
  nft,
  permitSingle,
  safeExec,
  seaportOrder,
  textOf,
  uniswapXOrder,
  utf8Hex,
} from '../helpers';

/** A transport that records every call; it must never be reached while paid checks are off. */
function spyFetch(): { fetchImpl: FetchLike; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl: FetchLike = async (input) => {
    calls.push(input);
    return { status: 200, json: async () => ({ checked: true, score: 99, tier: 'low', categories: [] }) };
  };
  return { fetchImpl, calls };
}

const ORIGIN = 'https://app.example-dex.xyz';
const TRANSACTIONS = [
  { from: USER, to: RECIPIENT, value: '0x2386f26fc10000', data: '0x' },
  { from: USER, to: USDC, value: '0x0', data: calldata('a9059cbb', RECIPIENT, 5_000_000n) },
  { from: USER, to: USDC, value: '0x0', data: calldata('095ea7b3', DRAINER, MAX_UINT256) },
  { from: USER, to: BAYC, value: '0x0', data: calldata('a22cb465', DRAINER, 1n) },
  { from: USER, to: DRAINER, value: '0x1', data: calldata('095ea7b3', UNIVERSAL_ROUTER, 0n) },
  { from: USER, to: SAFE, value: '0x0', data: safeExec(DRAINER, 0n, '0x12345678', 1) },
  { from: USER, value: '0x0', data: '0x6080604052' },
];
const SIGNATURES = [
  { from: USER, data: permitSingle(DRAINER), signatureMethod: 'eth_signTypedData_v4' },
  { from: USER, data: uniswapXOrder([{ token: USDC, amount: '9999000000', recipient: DRAINER }]), signatureMethod: 'eth_signTypedData_v4' },
  { from: USER, data: seaportOrder([nft(BAYC, '1')], [erc20Item(WETH, '1', USER)]), signatureMethod: 'eth_signTypedData_v4' },
  { from: USER, data: utf8Hex(`Claim for token ${USDC}, payout wallet ${DRAINER}`), signatureMethod: 'personal_sign' },
];

describe('the paid-checks switch', () => {
  it('this version ships with paid checks off', () => {
    // Turning them on also needs "endowment:network-access" back in the
    // manifest (test/snap.test.ts checks that the two agree).
    expect(PAID_CHECKS_SUPPORTED).toBe(false);
  });

  it('with paid checks off, no transaction or signature ever reaches fetch; each is NOT verified, never an all-clear', async () => {
    const { fetchImpl, calls } = spyFetch();
    const results = [
      ...(await Promise.all(TRANSACTIONS.map(async (tx) => runCheck(decodeTransaction(tx, 'eip155:1'), ORIGIN, 'transaction', { paidChecks: false, fetchImpl })))),
      ...(await Promise.all(SIGNATURES.map(async (sig) => runCheck(decodeSignature(sig, 'app.example-dex.xyz'), ORIGIN, 'signature', { paidChecks: false, fetchImpl })))),
    ];
    expect(calls).toStrictEqual([]);
    for (const result of results) {
      const text = textOf(result.content);
      expect(text).toContain('x402check · NOT verified');
      expect(text).toContain(NOT_SENT_TEXT);
      expect(text).not.toContain('No significant risk');
      expect(text).not.toMatch(/score \d+\/100/u);
    }
  });

  it('with paid checks off, local danger is still critical and a plain request has no severity', async () => {
    const { fetchImpl, calls } = spyFetch();
    const mode = { paidChecks: false, fetchImpl };
    const listing = await runCheck(decodeSignature(SIGNATURES[2] as never, undefined), ORIGIN, 'signature', mode);
    expect(listing.severity).toBe('critical');
    expect(textOf(listing.content)).toContain('Dangerous request — do not sign');
    const delegatecall = await runCheck(decodeTransaction(TRANSACTIONS[5] as never, 'eip155:1'), ORIGIN, 'transaction', mode);
    expect(delegatecall.severity).toBe('critical');
    const plain = await runCheck(decodeTransaction(TRANSACTIONS[0] as never, 'eip155:1'), ORIGIN, 'transaction', mode);
    expect(plain.severity).toBeUndefined();
    expect(calls).toStrictEqual([]);
  });

  it('with paid checks off, the handlers the Snap exports never call fetch either', async () => {
    const { fetchImpl, calls } = spyFetch();
    const handlers = insightHandlers({ paidChecks: false, fetchImpl });
    const tx = await handlers.onTransaction({ transaction: TRANSACTIONS[2] as never, chainId: 'eip155:1', transactionOrigin: ORIGIN });
    const sig = await handlers.onSignature({ signature: SIGNATURES[1] as never, signatureOrigin: ORIGIN });
    expect(calls).toStrictEqual([]);
    expect(textOf((tx as { content: unknown }).content)).toContain(NOT_SENT_TEXT);
    expect(textOf((sig as { content: unknown }).content)).toContain(NOT_SENT_TEXT);
  });

  it('with paid checks on, the same pipeline does call x402check (the paid mode is kept)', async () => {
    const { fetchImpl, calls } = spyFetch();
    const result = await runCheck(decodeTransaction(TRANSACTIONS[2] as never, 'eip155:1'), ORIGIN, 'transaction', { paidChecks: true, fetchImpl });
    expect(calls).toStrictEqual(['https://x402check.xyz/v1/risk-check']);
    expect(textOf(result.content)).toContain('x402check · score 99/100 · low');
  });
});
