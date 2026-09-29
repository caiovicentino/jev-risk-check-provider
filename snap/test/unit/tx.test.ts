/**
 * @jest-environment node
 *
 * Regression tests for review findings 3, 6, 7 and 9d (probe p2/p3):
 * payable calls, wrapper transactions, approval classification and
 * effectively-unlimited amounts.
 */
import { describe, expect, it } from '@jest/globals';

import { decodeTransaction } from '../../src/decode';
import { buildRiskCheckBodies } from '../../src/request';
import {
  BAYC,
  DRAINER,
  MAX_UINT160,
  MAX_UINT256,
  MULTISEND_CALL_ONLY,
  NPM,
  PERMIT2,
  RECIPIENT,
  SAFE,
  UNIVERSAL_ROUTER,
  USDC,
  USDT,
  USER,
  ZERO,
  calldata,
  execute4337,
  execute7579,
  multiSend,
  multicall,
  multicallDeadline,
  routerExecute,
  safeExec,
  urPermit2Permit,
  urTokenRecipient,
  word,
} from '../helpers';

const APPROVE_MAX = calldata('095ea7b3', DRAINER, MAX_UINT256);
const tx = (to: string | undefined, data: unknown, value: unknown = '0x0', extra: Record<string, unknown> = {}) =>
  decodeTransaction({ from: USER, to, value, data, ...extra }, 'eip155:1');
const checked = (decoded: ReturnType<typeof decodeTransaction>) => [decoded.counterparty, ...decoded.others.map((other) => other.address)];

describe('p2: calldata encodings all decode to the same spender', () => {
  it.each([
    ['lowercase', APPROVE_MAX],
    ['uppercase hex digits', `0x${APPROVE_MAX.slice(2).toUpperCase()}`],
    ['0X prefix', `0X${APPROVE_MAX.slice(2)}`],
    ['no prefix', APPROVE_MAX.slice(2)],
    ['extra trailing bytes', `${APPROVE_MAX}deadbeef`],
  ])('%s', (_label, data) => {
    const decoded = tx(USDT, data);
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.interaction).toStrictEqual({ type: 'token_approval', unlimited: true });
  });

  it('reads `input` when `data` is missing or null', () => {
    expect(decodeTransaction({ from: USER, to: USDT, input: APPROVE_MAX }, 'eip155:1').counterparty).toBe(DRAINER);
    expect(decodeTransaction({ from: USER, to: USDT, data: null, input: APPROVE_MAX }, 'eip155:1').counterparty).toBe(DRAINER);
  });

  it('short calldata is zero-padded like old token contracts read it (and warned)', () => {
    const decoded = tx(USDT, APPROVE_MAX.slice(0, -2));
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.unlimited).toBe(true);
    expect(decoded.warnings.join()).toContain('1 byte(s) shorter than approve(address,uint256)');
  });
});

describe('p2/finding 3: a payable call checks the ETH recipient first', () => {
  it.each([
    ['approve(router, 0)', calldata('095ea7b3', UNIVERSAL_ROUTER, 0n)],
    ['transfer(recipient, 1)', calldata('a9059cbb', RECIPIENT, 1n)],
  ])('5 ETH to the drainer contract with %s', (_label, data) => {
    const decoded = tx(DRAINER, data, '0x4563918244f40000');
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.role).toBe('contract');
    expect(decoded.interaction).toStrictEqual({ type: 'contract_call' });
    expect(decoded.payment).toStrictEqual({ network: 'eip155:1', pay_to: DRAINER, amount: '5000000000000000000', asset: 'native' });
    expect(decoded.summary).toMatch(/^Sends 5 ETH \(5000000000000000000 wei\) to contract 0x9d17bb55b57b31329cf01aa7017948e398b277bc with a call: /u);
    expect(decoded.warnings.join()).toContain('which normally takes no ETH');
    const bodies = buildRiskCheckBodies(decoded, 'https://app.example.com');
    expect(bodies[0]?.wallet).toBe(DRAINER);
  });
});

describe('finding 7: approvals', () => {
  it('approve(x, 0) is a revocation only on well-known ERC-20s', () => {
    const revoke = tx(USDC, calldata('095ea7b3', DRAINER, 0n));
    expect(revoke.interaction).toStrictEqual({ type: 'contract_call' });
    expect(revoke.action).toBe('ERC-20 approve (revoke)');
    const ambiguous = tx(BAYC, calldata('095ea7b3', DRAINER, 0n));
    expect(ambiguous.counterparty).toBe(DRAINER);
    expect(ambiguous.interaction).toStrictEqual({ type: 'token_approval' });
    expect(ambiguous.summary).toContain('an ERC-20 revocation, OR an ERC-721 approval of NFT #0');
    // Unknown chain: no allowlist applies.
    const unknownChain = decodeTransaction({ from: USER, to: USDC, data: calldata('095ea7b3', DRAINER, 0n) }, 'eip155:999999');
    expect(unknownChain.interaction).toStrictEqual({ type: 'token_approval' });
  });

  it('increaseApproval (0xd73dd623) is an approval like increaseAllowance', () => {
    for (const selector of ['d73dd623', '39509351']) {
      const decoded = tx(USDC, calldata(selector, DRAINER, MAX_UINT256));
      expect(decoded.counterparty).toBe(DRAINER);
      expect(decoded.interaction).toStrictEqual({ type: 'token_approval', unlimited: true });
    }
  });

  it('finding 9d: amounts at or above 10^30 are effectively unlimited', () => {
    const at = tx(USDC, calldata('095ea7b3', DRAINER, 10n ** 30n));
    expect(at.unlimited).toBe(true);
    expect(at.interaction).toStrictEqual({ type: 'token_approval', unlimited: true });
    expect(at.warnings.join()).toContain('effectively unlimited');
    const below = tx(USDC, calldata('095ea7b3', DRAINER, 10n ** 30n - 1n));
    expect(below.unlimited).toBe(false);
    expect(below.interaction).toStrictEqual({ type: 'token_approval' });
    const permit2 = tx(PERMIT2, calldata('87517c45', USDC, DRAINER, 10n ** 30n, 0n));
    expect(permit2.interaction).toStrictEqual({ type: 'token_approval', unlimited: true });
  });
});

describe('finding 6: wrapper transactions', () => {
  it('multicall(bytes[]) on the Uniswap position manager exposes setApprovalForAll', () => {
    const decoded = tx(NPM, multicall([calldata('a22cb465', DRAINER, 1n)]));
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.role).toBe('operator');
    expect(decoded.interaction).toStrictEqual({ type: 'nft_approval' });
    expect(decoded.action).toBe('Multicall');
  });

  it('multicall(uint256,bytes[]) picks the riskiest inner counterparty', () => {
    const decoded = tx(NPM, multicallDeadline([calldata('a9059cbb', RECIPIENT, 1n), calldata('095ea7b3', DRAINER, MAX_UINT256)]));
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.others.map((other) => other.address)).toContain(RECIPIENT);
  });

  it('Safe execTransaction with DELEGATECALL is proven danger', () => {
    const decoded = tx(SAFE, safeExec(DRAINER, 0n, '0x12345678', 1));
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.danger.join()).toContain(`DELEGATECALL to ${DRAINER}`);
  });

  it('Safe execTransaction CALL decodes the inner token call from the Safe', () => {
    const decoded = tx(SAFE, safeExec(USDC, 0n, APPROVE_MAX, 0, 1n, DRAINER));
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.interaction).toStrictEqual({ type: 'token_approval', unlimited: true });
    expect(decoded.danger).toStrictEqual([]);
    expect(decoded.warnings.join()).toContain(`pays gas refunds to ${DRAINER}`);
  });

  it('Safe DELEGATECALL to MultiSendCallOnly decodes each inner call', () => {
    const batch = multiSend([
      { operation: 0, to: USDC, value: 0n, data: APPROVE_MAX },
      { operation: 0, to: RECIPIENT, value: 5n, data: '0x' },
    ]);
    const decoded = tx(SAFE, safeExec(MULTISEND_CALL_ONLY, 0n, batch, 1));
    expect(decoded.danger).toStrictEqual([]);
    expect(checked(decoded)).toStrictEqual(expect.arrayContaining([DRAINER, RECIPIENT]));
    expect(decoded.counterparty).toBe(DRAINER);
  });

  it('Universal Router PERMIT2_PERMIT to a foreign spender is proven danger', () => {
    const decoded = tx(UNIVERSAL_ROUTER, routerExecute([0x0a], [urPermit2Permit(USDC, MAX_UINT160, DRAINER)]));
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.interaction).toStrictEqual({ type: 'token_approval', unlimited: true });
    expect(decoded.danger.join()).toContain(`grants spender ${DRAINER} (not the router)`);
  });

  it('Universal Router PERMIT2_PERMIT to the router itself is normal', () => {
    const decoded = tx(UNIVERSAL_ROUTER, routerExecute([0x0a], [urPermit2Permit(USDC, MAX_UINT160, UNIVERSAL_ROUTER)]));
    expect(decoded.danger).toStrictEqual([]);
    expect(decoded.counterparty).toBe(UNIVERSAL_ROUTER);
  });

  it('Universal Router TRANSFER and SWEEP recipients are checked (sentinels are not)', () => {
    const decoded = tx(
      UNIVERSAL_ROUTER,
      routerExecute([0x05, 0x04, 0x05], [
        urTokenRecipient(USDC, DRAINER, 10n),
        urTokenRecipient(USDC, RECIPIENT, 0n),
        urTokenRecipient(USDC, '0x0000000000000000000000000000000000000001', 1n),
      ], false),
    );
    expect(checked(decoded)).toStrictEqual(expect.arrayContaining([DRAINER, RECIPIENT]));
    expect(checked(decoded)).not.toContain('0x0000000000000000000000000000000000000001');
    expect(decoded.warnings.join()).toContain(`goes to ${DRAINER}, not to you`);
  });

  it('Universal Router EXECUTE_SUB_PLAN is decoded recursively', () => {
    const inner = `0x${word(0x40n)}${word(0x80n)}${word(1n)}${'0a'.padEnd(64, '0')}${word(1n)}${word(0x20n)}${word(BigInt((urPermit2Permit(USDC, MAX_UINT160, DRAINER).length - 2) / 2))}${urPermit2Permit(USDC, MAX_UINT160, DRAINER).slice(2).padEnd(Math.ceil((urPermit2Permit(USDC, MAX_UINT160, DRAINER).length - 2) / 64) * 64, '0')}`;
    const decoded = tx(UNIVERSAL_ROUTER, routerExecute([0x21], [inner]));
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.danger.join()).toContain('not the router');
  });

  it('ERC-7579 execute: single, batch and delegatecall', () => {
    const single = tx(USER, execute7579('single', [{ to: USDC, value: 0n, data: APPROVE_MAX }]));
    expect(single.counterparty).toBe(DRAINER);
    const batch = tx(USER, execute7579('batch', [
      { to: RECIPIENT, value: 1n, data: '0x' },
      { to: BAYC, value: 0n, data: calldata('a22cb465', DRAINER, 1n) },
    ]));
    expect(batch.counterparty).toBe(DRAINER);
    expect(batch.others.map((other) => other.address)).toContain(RECIPIENT);
    expect(batch.warnings.join()).toContain("calls your own account's code");
    const delegate = tx(USER, execute7579('delegate', [{ to: DRAINER, value: 0n, data: '0x12345678' }]));
    expect(delegate.counterparty).toBe(DRAINER);
    expect(delegate.danger.join()).toContain('DELEGATECALL');
  });

  it('ERC-4337 execute(address,uint256,bytes) decodes the inner call', () => {
    const decoded = tx('0x2222222222222222222222222222222222222222', execute4337(USDC, 0n, APPROVE_MAX));
    expect(decoded.counterparty).toBe(DRAINER);
  });

  it('an undecodable call to your own account is not an all-clear', () => {
    const decoded = tx(USER, `0xe9ae5c53${word(0n)}${word(0x40n)}${word(0n)}`);
    expect(decoded.counterparty).toBeUndefined();
    expect(decoded.localNote).toContain('calls your own account');
  });

  it('wrapper nesting is bounded', () => {
    let data: string = APPROVE_MAX;
    for (let level = 0; level < 8; level += 1) data = multicall([data]);
    expect(() => tx(NPM, data)).not.toThrow();
    const decoded = tx(NPM, data);
    expect(decoded.warnings.join()).toContain('exceed the decoding depth');
  });
});

describe('special recipients', () => {
  it('value sent to the zero address or a precompile is lost: proven danger, nothing sent', () => {
    for (const to of [ZERO, '0x0000000000000000000000000000000000000001']) {
      const decoded = tx(to, '0x', '0x1');
      expect(decoded.counterparty).toBeUndefined();
      expect(decoded.danger.join()).toContain('the funds will be lost');
    }
  });
});
