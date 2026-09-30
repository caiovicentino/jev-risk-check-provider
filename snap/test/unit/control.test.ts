/**
 * @jest-environment node
 *
 * Audit finding cg-4: control changes move no asset (the simulation shows
 * nothing) yet hand over the account. Inside every decoded call (a direct
 * transaction, Safe execTransaction / SafeTx, multiSend, smart-account execute,
 * an EIP-7702 self-call, a user operation), Safe owner / module / guard /
 * fallback-handler changes, ERC-7579 module installs, Coinbase Smart Wallet
 * owner changes and ownership transfers or upgrades of the signer's own account
 * are proven danger naming the new controller. What still cannot be read (an
 * undecoded self-call, a deployment with value, calls past the decoding
 * limits) is opaque.
 */
import { describe, expect, it } from '@jest/globals';
import { RootJSXElementStruct } from '@metamask/snaps-sdk/jsx';

import { decodeTransaction, decodeTypedData, opaqueNote } from '../../src/decode';
import { MAX_CONTEXT, buildRiskCheckBodies, parseVerdict } from '../../src/request';
import { renderLocalOnly, renderOutcome, renderUnpaid } from '../../src/ui';
import { executeWithOperation, executeWithoutChainIdValidation, installModule, uninstallModule, upgradeToAndCall } from '../account-fixtures';
import {
  DRAINER,
  MULTISEND_CALL_ONLY,
  NPM,
  RECIPIENT,
  SAFE,
  USDC,
  USER,
  ZERO,
  calldata,
  eip712Hash,
  execute4337,
  execute7579,
  multiSend,
  multicall,
  safeExec,
  safeTx,
} from '../helpers';

const SENTINEL = '0x0000000000000000000000000000000000000001';
const SOME_CONTRACT = '0x1234567890123456789012345678901234567890';
const PROXY_ADMIN = '0x3333333333333333333333333333333333333333';
const SMART_WALLET = '0x7777777777777777777777777777777777777777';

const tx = (to: string | undefined, data: string, value = '0x0') => decodeTransaction({ from: USER, to, value, data }, 'eip155:1');
const signSafeTx = (data: string) => {
  const typed = safeTx(SAFE, data, 0);
  expect(() => eip712Hash(typed)).not.toThrow();
  return decodeTypedData(typed, USER);
};
const checked = (decoded: ReturnType<typeof decodeTransaction>) => [decoded.counterparty, ...decoded.others.map((other) => other.address)];

describe('cg-4: Safe owner, module, guard and fallback-handler changes are proven danger', () => {
  it('audit repro: Safe execTransaction calling addOwnerWithThreshold(DRAINER, 1)', () => {
    const decoded = tx(SAFE, safeExec(SAFE, 0n, calldata('0d582f13', DRAINER, 1n), 0));
    expect(decoded.danger).toStrictEqual([`adds ${DRAINER} as an owner of Safe ${SAFE} and sets its threshold to 1`]);
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.role).toBe('delegate');
    expect(decoded.summary).toContain('Safe owner added');
    expect(buildRiskCheckBodies(decoded)[0]?.context).toMatch(/^Proven danger: adds 0x9d17/u);
  });

  it.each([
    ['enableModule', calldata('610b5925', DRAINER), `enables module ${DRAINER} on Safe ${SAFE}: a Safe module can execute any transaction`],
    ['swapOwner', calldata('e318b52b', SENTINEL, RECIPIENT, DRAINER), `replaces owner ${RECIPIENT} of Safe ${SAFE} with ${DRAINER}`],
    ['removeOwner', calldata('f8dc5dd9', SENTINEL, RECIPIENT, 1n), `removes owner ${RECIPIENT} from Safe ${SAFE} and sets its threshold to 1`],
    ['changeThreshold', calldata('694e80c3', 1n), `changes the signature threshold of Safe ${SAFE} to 1`],
    ['disableModule', calldata('e009cfde', SENTINEL, DRAINER), `disables module ${DRAINER} of Safe ${SAFE}`],
    ['setGuard', calldata('e19a9dd9', DRAINER), `sets the transaction guard of Safe ${SAFE} to ${DRAINER}`],
    ['setGuard(0)', calldata('e19a9dd9', ZERO), `removes the transaction guard of Safe ${SAFE}`],
    ['setModuleGuard', calldata('e068df37', DRAINER), `sets the module guard of Safe ${SAFE} to ${DRAINER}`],
    ['setFallbackHandler', calldata('f08a0323', DRAINER), `sets the fallback handler of Safe ${SAFE} to ${DRAINER}: the handler answers every call`],
  ])('SafeTx signature calling %s', (_label, data, danger) => {
    const decoded = signSafeTx(data);
    expect(decoded.danger.join()).toContain(danger);
    expect(decoded.opaque).toBeUndefined();
  });

  it('a new controller is the primary counterparty (checked, besides the local block)', () => {
    const decoded = signSafeTx(calldata('f08a0323', DRAINER));
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.reason).toBe(`becomes the fallback handler of Safe ${SAFE}`);
  });

  it('setFallbackHandler inside a Safe multiSend (DELEGATECALL to MultiSendCallOnly)', () => {
    const batch = multiSend([
      { operation: 0, to: USDC, value: 0n, data: calldata('a9059cbb', RECIPIENT, 1n) },
      { operation: 0, to: SAFE, value: 0n, data: calldata('f08a0323', DRAINER) },
    ]);
    const decoded = tx(SAFE, safeExec(MULTISEND_CALL_ONLY, 0n, batch, 1));
    expect(decoded.danger.join()).toContain(`sets the fallback handler of Safe ${SAFE} to ${DRAINER}`);
    expect(checked(decoded)).toStrictEqual(expect.arrayContaining([DRAINER, RECIPIENT]));
  });
});

describe('cg-4: modular accounts, EIP-7702 self-calls and smart wallets', () => {
  it('audit repro: a 7702 self-call installModule(1, DRAINER, "") is proven danger naming the validator', () => {
    const decoded = tx(USER, installModule(1n, DRAINER));
    expect(decoded.danger).toStrictEqual([
      `installs validator module ${DRAINER} on account ${USER}: a validator module can authorize any operation of the account`,
    ]);
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.opaque).toBeUndefined();
  });

  it('an executor installed through ERC-7579 execute (self-call inside a self-call)', () => {
    const decoded = tx(USER, execute7579('single', [{ to: USER, value: 0n, data: installModule(2n, DRAINER, '0x1234') }]));
    expect(decoded.danger.join()).toContain(`installs executor module ${DRAINER} on account ${USER}`);
  });

  it('uninstallModule is a control change too', () => {
    expect(tx(USER, uninstallModule(4n, DRAINER)).danger.join()).toContain(`uninstalls hook module ${DRAINER} from account ${USER}`);
  });

  it('Coinbase Smart Wallet executeWithoutChainIdValidation adding an owner on every chain', () => {
    const decoded = tx(SMART_WALLET, executeWithoutChainIdValidation([calldata('0f0f3f24', DRAINER)]));
    expect(decoded.danger).toStrictEqual([`adds ${DRAINER} as an owner of smart wallet ${SMART_WALLET}`]);
    expect(decoded.warnings.join()).toContain('replayable on every chain');
    expect(decoded.counterparty).toBe(DRAINER);
  });

  it('the Safe 4337 module path: executeUserOp calling addOwnerWithThreshold on the Safe', () => {
    const decoded = tx(SAFE, executeWithOperation('7bb37428', SAFE, 0n, calldata('0d582f13', DRAINER, 1n), 0));
    expect(decoded.danger.join()).toContain(`adds ${DRAINER} as an owner of Safe ${SAFE}`);
  });

  it('a smart account execute() calling its own transferOwnership is danger', () => {
    const decoded = tx(SMART_WALLET, execute4337(SMART_WALLET, 0n, calldata('f2fde38b', DRAINER)));
    expect(decoded.danger.join()).toContain(`transfers ownership of your account ${SMART_WALLET} to ${DRAINER}`);
  });
});

describe('cg-4: ownership and upgrades of the signer\'s own account are danger; elsewhere they are flagged', () => {
  it('transferOwnership of your own account (EIP-7702 self-call) is proven danger', () => {
    const decoded = tx(USER, calldata('f2fde38b', DRAINER));
    expect(decoded.danger).toStrictEqual([`transfers ownership of your account ${USER} to ${DRAINER}: the new owner takes control of it`]);
    expect(decoded.counterparty).toBe(DRAINER);
  });

  it('transferOwnership of another contract is flagged and both addresses are checked, without local danger', () => {
    const decoded = tx(SOME_CONTRACT, calldata('f2fde38b', DRAINER));
    expect(decoded.danger).toStrictEqual([]);
    expect(decoded.warnings.join()).toContain(`transfers ownership of contract ${SOME_CONTRACT} to ${DRAINER}`);
    expect(checked(decoded)).toStrictEqual([DRAINER, SOME_CONTRACT]);
  });

  it('Solady completeOwnershipHandover of your own account is proven danger', () => {
    expect(tx(USER, calldata('f04e283e', DRAINER)).danger.join()).toContain(`hands ownership of your account ${USER} to ${DRAINER}`);
  });

  it('acceptOwnership on your own account is danger; on another contract it only makes you its owner', () => {
    expect(tx(USER, '0x79ba5097').danger.join()).toContain(`completes a pending two-step ownership transfer of your account ${USER}`);
    const elsewhere = tx(SOME_CONTRACT, '0x79ba5097');
    expect(elsewhere.danger).toStrictEqual([]);
    expect(elsewhere.summary).toContain('the calling account becomes its owner');
  });

  it('renounceOwnership of your own account is danger', () => {
    expect(tx(USER, '0x715018a6').danger.join()).toContain(`renounces ownership of your account ${USER}`);
  });

  it('upgradeToAndCall of your own account names the new code', () => {
    const decoded = tx(USER, upgradeToAndCall(DRAINER, '0x8129fc1c'));
    expect(decoded.danger).toStrictEqual([
      `upgrades your account ${USER} to new code at ${DRAINER} and runs a setup call with it: that code controls everything the account holds`,
    ]);
    expect(decoded.counterparty).toBe(DRAINER);
  });

  it('a Safe upgrading itself through a SafeTx (self-call) is danger', () => {
    expect(signSafeTx(calldata('3659cfe6', DRAINER)).danger.join()).toContain(`upgrades your account ${SAFE} to new code at ${DRAINER}`);
  });

  it('upgradeTo on another proxy is flagged, not proven danger', () => {
    const decoded = tx(SOME_CONTRACT, calldata('3659cfe6', DRAINER));
    expect(decoded.danger).toStrictEqual([]);
    expect(decoded.warnings.join()).toContain(`upgrades proxy ${SOME_CONTRACT} to the implementation ${DRAINER}`);
  });

  it('ProxyAdmin upgrade: danger when the proxy is your account, flagged otherwise', () => {
    expect(tx(PROXY_ADMIN, calldata('99a88ec4', USER, DRAINER)).danger.join()).toContain(`upgrades your account ${USER} to new code at ${DRAINER}`);
    const other = tx(PROXY_ADMIN, calldata('99a88ec4', SOME_CONTRACT, DRAINER));
    expect(other.danger).toStrictEqual([]);
    expect(other.warnings.join()).toContain(`upgrades proxy ${SOME_CONTRACT}`);
  });

  it('changeAdmin of your own account hands over its upgrade rights', () => {
    expect(tx(USER, calldata('8f283970', DRAINER)).danger.join()).toContain(`hands the upgrade rights of your account ${USER} to ${DRAINER}`);
  });
});

describe('cg-4: what cannot be read is opaque', () => {
  it('audit repro: a 7702 self-call with calldata that is not decoded is never an all-clear', () => {
    // At the top level of a transaction it has no counterparty and a local note:
    // the guard refuses it with its own code (unreadable_self_call).
    const top = tx(USER, calldata('deadbeef', DRAINER));
    expect(top.counterparty).toBeUndefined();
    expect(top.localNote).toContain('calls your own account');
    expect(top.opaque).toBeUndefined();
    // Nested in a call the account makes (where an address would be checked instead), it is opaque.
    const nested = tx(USER, execute7579('single', [{ to: USER, value: 0n, data: calldata('deadbeef', DRAINER) }]));
    expect(nested.opaque).toContain(`account ${USER} calls its own code (function selector 0xdeadbeef`);
    expect(nested.warnings[0]).toBe(opaqueNote(nested.opaque as string));
    const safe = tx(SAFE, safeExec(SAFE, 0n, calldata('deadbeef'), 0));
    expect(safe.opaque).toContain(`account ${SAFE} calls its own code`);
    expect(signSafeTx(calldata('deadbeef')).opaque).toContain(`account ${SAFE} calls its own code`);
  });

  it('the same undecoded call to another contract is checked (and simulated), not opaque', () => {
    const decoded = tx(SOME_CONTRACT, calldata('deadbeef', DRAINER));
    expect(decoded.opaque).toBeUndefined();
    expect(decoded.counterparty).toBe(SOME_CONTRACT);
    expect(decoded.transaction).toBeDefined();
  });

  it('calldata too short for a control function reverts on-chain: it is not taken for that change', () => {
    // installModule without its bytes argument: 2 of its 3 head words.
    const truncated = `0x9517e29f${'0'.repeat(63)}1${'0'.repeat(24)}${DRAINER.slice(2)}`;
    const top = tx(USER, truncated);
    expect(top.danger).toStrictEqual([]);
    expect(top.counterparty).toBeUndefined();
    const nested = tx(USER, execute7579('single', [{ to: USER, value: 0n, data: truncated }]));
    expect(nested.danger).toStrictEqual([]);
    expect(nested.opaque).toContain('calls its own code (function selector 0x9517e29f');
  });

  it('audit repro: a deployment carrying value is flagged (the guard refuses it as not simulated); a zero-value one is not', () => {
    const funded = decodeTransaction({ from: USER, data: '0x6080', value: '0x8ac7230489e80000' }, 'eip155:1');
    expect(funded.warnings[0]).toContain('the deployment sends 10 ETH (10000000000000000000 wei) to a new contract whose init code decides');
    expect(funded.counterparty).toBeUndefined();
    expect(funded.opaque).toBeUndefined();
    expect(decodeTransaction({ from: USER, data: '0x6080', value: '0x0' }, 'eip155:1').warnings).toStrictEqual([]);
  });

  it('calls nested past the decoding depth are opaque', () => {
    let data: string = calldata('095ea7b3', DRAINER, 1n);
    for (let level = 0; level < 8; level += 1) data = multicall([data]);
    expect(tx(NPM, data).opaque).toContain('nested more than 3 levels deep');
  });

  it('more inner calls than the decoding budget are opaque', () => {
    const calls = Array.from({ length: 30 }, () => multicall([calldata('a9059cbb', RECIPIENT, 1n), calldata('a9059cbb', RECIPIENT, 1n)]));
    expect(tx(NPM, multicall(calls)).opaque).toContain('more than 48 inner calls');
  });
});

describe('control changes and opaque results render as valid Snap UI', () => {
  it('danger is critical, the opaque reason is the first warning, and every context fits', () => {
    const ok = { kind: 'ok' as const, verdict: parseVerdict({ checked: true, score: 90, tier: 'low', categories: [] }) as never };
    const results = [
      tx(SAFE, safeExec(SAFE, 0n, calldata('0d582f13', DRAINER, 1n), 0)),
      tx(USER, installModule(1n, DRAINER)),
      tx(USER, calldata('deadbeef', DRAINER)),
      decodeTransaction({ from: USER, data: '0x6080', value: '0x1' }, 'eip155:1'),
      signSafeTx(calldata('f08a0323', DRAINER)),
    ];
    for (const decoded of results) {
      const bodies = buildRiskCheckBodies(decoded, 'https://app.safe.global');
      for (const body of bodies) expect(body.context.length).toBeLessThanOrEqual(MAX_CONTEXT);
      const rendered = [renderUnpaid(decoded, 'app.safe.global', 'transaction'), bodies.length > 0 ? renderOutcome(decoded, ok, 'transaction', 'app.safe.global') : renderLocalOnly(decoded, 'app.safe.global')];
      for (const result of rendered) {
        expect(RootJSXElementStruct.is(result.content)).toBe(true);
        expect(result.severity).toBe(decoded.danger.length > 0 ? 'critical' : undefined);
      }
      if (decoded.opaque) expect(decoded.warnings[0]).toBe(opaqueNote(decoded.opaque));
    }
  });
});
