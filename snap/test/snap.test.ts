/**
 * Integration tests: the BUILT bundle (dist/bundle.js, pinned by the manifest
 * shasum) runs in MetaMask's SES execution environment via @metamask/snaps-jest.
 * Only `snap`, `ethereum`, the SES default endowments and the endowments the
 * manifest grants exist there, so a bare `snap_manageState(...)` would throw a
 * ReferenceError here exactly as in MetaMask.
 *
 * This version ships with paid checks OFF (src/config.ts): the manifest grants
 * no network access and the Snap sends nothing. The transport underneath
 * `fetch` is still redirected to a local mock API (harness/worker-entry.cjs),
 * which shows that no request is ever made, and which serves the paid-mode
 * scenarios (harness/paid-scenarios.ts) as soon as the flag is turned on.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';
import type {} from '@metamask/snaps-jest';

import { PAID_CHECKS_SUPPORTED } from '../src/config';
import { DISCLOSURE_VERSION } from '../src/state';
import { NOT_SENT_TEXT, disclosureContent } from '../src/ui';
import { MockApi } from './harness/mock-api';
import { sesSnap } from './harness/paid-mode';
import { ORIGIN, paidModeScenarios, severityOf } from './harness/paid-scenarios';
import type { BuiltSnap } from './harness/snap';
import { installBuiltSnap, readSnapState } from './harness/snap';
import {
  BAYC,
  DRAINER,
  MAX_UINT256,
  REACTOR,
  RECIPIENT,
  SAFE,
  UNIVERSAL_ROUTER,
  USDC,
  USER,
  WETH,
  calldata,
  erc20Item,
  erc2612Permit,
  nft,
  permitSingle,
  safeExec,
  seaportOrder,
  textOf,
  uniswapXOrder,
  utf8Hex,
} from './helpers';

const MANIFEST = JSON.parse(readFileSync(path.join(__dirname, '..', 'snap.manifest.json'), 'utf8')) as {
  initialPermissions: Record<string, unknown>;
};

/** Runs only in the shipped mode (paid checks off) / only once paid checks are on. */
const localOnlyMode = PAID_CHECKS_SUPPORTED ? describe.skip : describe;
const paidMode = PAID_CHECKS_SUPPORTED ? describe : describe.skip;

describe('x402check snap (built bundle in the SES execution environment)', () => {
  const api = new MockApi();
  let mockOrigin: string;

  beforeAll(async () => {
    mockOrigin = await api.start();
  });

  afterAll(async () => {
    await api.stop();
  });

  beforeEach(() => {
    api.reset();
  });

  const install = async (): Promise<BuiltSnap> =>
    installBuiltSnap(mockOrigin, { unencryptedState: { disclosureVersion: DISCLOSURE_VERSION } });

  /** Custom (X-*) request headers seen by the API; the Snap sends none (no client or install id). */
  const customHeaders = (): string[] =>
    api.requests.flatMap((request) => Object.keys(request.headers).filter((name) => name.startsWith('x-')));

  describe('least privilege', () => {
    it('the manifest grants network access only when paid checks are on (off in this version)', () => {
      const expected = [
        'endowment:lifecycle-hooks',
        'endowment:signature-insight',
        'endowment:transaction-insight',
        'snap_dialog',
        'snap_manageState',
        ...(PAID_CHECKS_SUPPORTED ? ['endowment:network-access'] : []),
      ].sort();
      expect(Object.keys(MANIFEST.initialPermissions).sort()).toStrictEqual(expected);
      expect('endowment:network-access' in MANIFEST.initialPermissions).toBe(PAID_CHECKS_SUPPORTED);
    });

    it('the installed Snap is granted exactly the manifest permissions', async () => {
      const snap = await install();
      const messenger = snap.controllerMessenger as unknown as { call(action: string, ...args: unknown[]): unknown };
      const granted = messenger.call('PermissionController:getPermissions', snap.snapId) as Record<string, unknown>;
      expect(Object.keys(granted).sort()).toStrictEqual(Object.keys(MANIFEST.initialPermissions).sort());
      expect('endowment:network-access' in granted).toBe(PAID_CHECKS_SUPPORTED);
    });
  });

  describe('lifecycle and privacy', () => {
    it('onInstall shows the disclosure and stores no identifier', async () => {
      const fresh = await installBuiltSnap(mockOrigin);
      const pending = fresh.onInstall();
      const ui = await pending.getInterface();
      expect(ui.type).toBe('alert');
      const text = textOf(ui.content);
      expect(text).toBe(textOf(disclosureContent()));
      expect(text).toContain('private keys and Secret Recovery Phrase never leave your wallet');
      expect(text).not.toMatch(/free|daily|quota|random install/iu);
      await (ui as { ok(): Promise<void> }).ok();
      expect(await pending).toRespondWith(null);

      // Only the disclosure version is stored, and nothing is sent on install.
      expect(readSnapState(fresh, false)).toStrictEqual({ disclosureVersion: DISCLOSURE_VERSION });
      expect(readSnapState(fresh, true)).toBeNull();
      expect(api.requests).toHaveLength(0);

      // Insights neither send nor store an identifier.
      await fresh.onTransaction({ from: USER, to: RECIPIENT, value: '0x1', data: '0x', origin: ORIGIN });
      await fresh.onTransaction({ from: USER, to: RECIPIENT, value: '0x2', data: '0x', origin: ORIGIN });
      expect(api.requests).toHaveLength(PAID_CHECKS_SUPPORTED ? 2 : 0);
      expect(customHeaders()).toStrictEqual([]);
      expect(readSnapState(fresh, false)).toStrictEqual({ disclosureVersion: DISCLOSURE_VERSION });
    });

    it('an install id left by 0.2-0.3 is never sent', async () => {
      const stale = await installBuiltSnap(mockOrigin, {
        unencryptedState: { installId: 'ab'.repeat(16), disclosureVersion: DISCLOSURE_VERSION },
      });
      await stale.onTransaction({ from: USER, to: RECIPIENT, value: '0x1', data: '0x', origin: ORIGIN });
      expect(api.requests).toHaveLength(PAID_CHECKS_SUPPORTED ? 1 : 0);
      expect(customHeaders()).toStrictEqual([]);
      expect(JSON.stringify(api.requests.map((request) => request.body))).not.toContain('ab'.repeat(16));
    });

    it('onUpdate from 0.1.x drops the SRP-derived client id, stores no install id and shows the disclosure', async () => {
      const legacy = await installBuiltSnap(mockOrigin, { state: { clientId: '0x1234567890abcd' } });
      const pending = legacy.onUpdate();
      const ui = await pending.getInterface();
      expect(ui.type).toBe('alert');
      await (ui as { ok(): Promise<void> }).ok();
      await pending;
      expect(readSnapState(legacy, true)).toBeNull();
      expect(readSnapState(legacy, false)).toStrictEqual({ disclosureVersion: DISCLOSURE_VERSION });
      await legacy.onTransaction({ from: USER, to: RECIPIENT, value: '0x1', data: '0x', origin: ORIGIN });
      expect(api.requests).toHaveLength(PAID_CHECKS_SUPPORTED ? 1 : 0);
      expect(JSON.stringify(api.requests.map((request) => request.body))).not.toContain('1234567890abcd');
    });

    it('onUpdate from 0.3.0 deletes the install id, shows the current disclosure and keeps unrelated state', async () => {
      const previous = await installBuiltSnap(mockOrigin, {
        state: { unrelated: 'keep' },
        unencryptedState: { installId: 'ef'.repeat(16), disclosureVersion: 2 },
      });
      const pending = previous.onUpdate();
      const ui = await pending.getInterface();
      expect(ui.type).toBe('alert');
      expect(textOf(ui.content)).toBe(textOf(disclosureContent()));
      await (ui as { ok(): Promise<void> }).ok();
      expect(await pending).toRespondWith(null);
      expect(readSnapState(previous, false)).toStrictEqual({ disclosureVersion: DISCLOSURE_VERSION });
      expect(readSnapState(previous, true)).toStrictEqual({ unrelated: 'keep' });
    });

    it('onUpdate from 0.2.0 (disclosure v1) shows the current disclosure and records its version', async () => {
      const previous = await installBuiltSnap(mockOrigin, { unencryptedState: { installId: 'ef'.repeat(16), disclosureVersion: 1 } });
      const pending = previous.onUpdate();
      const ui = await pending.getInterface();
      expect(ui.type).toBe('alert');
      expect(textOf(ui.content)).toBe(textOf(disclosureContent()));
      await (ui as { ok(): Promise<void> }).ok();
      expect(await pending).toRespondWith(null);
      expect(readSnapState(previous, false)).toStrictEqual({ disclosureVersion: DISCLOSURE_VERSION });
    });

    it('onUpdate deletes a stored install id even when the disclosure is current (no dialog)', async () => {
      const current = await installBuiltSnap(mockOrigin, {
        unencryptedState: { installId: 'cd'.repeat(16), disclosureVersion: DISCLOSURE_VERSION, other: 1 },
      });
      expect(await current.onUpdate()).toRespondWith(null);
      expect(readSnapState(current, false)).toStrictEqual({ disclosureVersion: DISCLOSURE_VERSION, other: 1 });
    });

    it('onUpdate on a current install shows no dialog and keeps non-legacy encrypted state', async () => {
      const current = await installBuiltSnap(mockOrigin, {
        state: { unrelated: 'keep' },
        unencryptedState: { disclosureVersion: DISCLOSURE_VERSION },
      });
      expect(await current.onUpdate()).toRespondWith(null);
      expect(readSnapState(current, true)).toStrictEqual({ unrelated: 'keep' });
      expect(readSnapState(current, false)).toStrictEqual({ disclosureVersion: DISCLOSURE_VERSION });
    });
  });

  localOnlyMode('this version: paid checks off, nothing is sent', () => {
    let snap: BuiltSnap;

    beforeEach(async () => {
      snap = await install();
    });

    const notVerified = (text: string): void => {
      expect(text).toContain('x402check · NOT verified');
      expect(text).toContain(NOT_SENT_TEXT);
      expect(text).toContain('This is not an all-clear.');
      expect(text).not.toContain('No significant risk');
      expect(text).not.toMatch(/score \d+\/100/u);
    };

    it('the disclosure says that nothing is sent, decoding is local and paid checks are planned', async () => {
      const fresh = await installBuiltSnap(mockOrigin);
      const pending = fresh.onInstall();
      const ui = await pending.getInterface();
      const text = textOf(ui.content);
      expect(text).toContain('x402check: nothing leaves your wallet');
      expect(text).toContain('This version of x402check sends nothing');
      expect(text).toContain('It has no network access.');
      expect(text).toContain('decodes the request inside your wallet');
      expect(text).toContain('those checks are paid per call (x402), and this version cannot pay yet');
      expect(text).toContain('NOT verified by x402check, never as an all-clear');
      expect(text).toContain('Paid checks are planned for a later version');
      expect(text).not.toContain('sends a risk-check request');
      expect(DISCLOSURE_VERSION).toBe(3);
      await (ui as { ok(): Promise<void> }).ok();
      await pending;
    });

    it('no transaction or signature ever reaches the network; each is decoded locally and marked NOT verified', async () => {
      const transactions = [
        { chainId: 'eip155:8453', from: USER, to: RECIPIENT, value: '0x2386f26fc10000', data: '0x', origin: ORIGIN },
        { from: USER, to: USDC, data: calldata('a9059cbb', RECIPIENT, 5_000_000n), origin: ORIGIN },
        { from: USER, to: BAYC, data: calldata('a22cb465', DRAINER, 1n), origin: ORIGIN },
        { from: USER, to: DRAINER, value: '0x4563918244f40000', data: calldata('095ea7b3', UNIVERSAL_ROUTER, 0n), origin: ORIGIN },
        { chainId: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', from: USER, to: RECIPIENT, value: '0x1', data: '0x', origin: ORIGIN },
      ] as const;
      for (const transaction of transactions) {
        const response = await snap.onTransaction(transaction);
        notVerified(textOf(response.getInterface().content));
      }
      const signatures = [
        { from: USER, data: permitSingle(DRAINER), signatureMethod: 'eth_signTypedData_v4', origin: ORIGIN },
        { from: USER, data: erc2612Permit(DRAINER, '1000000', '0x2105'), signatureMethod: 'eth_signTypedData_v4', origin: ORIGIN },
        { from: USER, data: uniswapXOrder([{ token: USDC, amount: '9999000000', recipient: DRAINER }]), signatureMethod: 'eth_signTypedData_v4', origin: 'https://app.uniswap.org' },
        { from: USER, data: utf8Hex('Claim your airdrop now at https://jup1ter-audit.click/claim?id=42'), signatureMethod: 'personal_sign', origin: ORIGIN },
        {
          from: USER,
          data: [
            { type: 'string', name: 'action', value: 'Authorize transfer' },
            { type: 'address', name: 'to', value: RECIPIENT },
          ],
          signatureMethod: 'eth_signTypedData',
          origin: ORIGIN,
        },
      ] as const;
      for (const signature of signatures) {
        const response = await snap.onSignature(signature as never);
        notVerified(textOf(response.getInterface().content));
      }
      expect(api.requests).toHaveLength(0);
    });

    it('shows what was decoded: the real counterparty, the amount, other addresses involved', async () => {
      const approve = await snap.onTransaction({ from: USER, to: USDC, data: calldata('095ea7b3', DRAINER, MAX_UINT256), origin: ORIGIN });
      const approveText = textOf(approve.getInterface().content);
      expect(approveText).toContain(`Not checked: spender ${DRAINER}`);
      expect(approveText).toContain('UNLIMITED');
      expect(approveText).toContain('app.example-dex.xyz');
      const order = await snap.onSignature({
        from: USER,
        data: uniswapXOrder([{ token: USDC, amount: '9999000000', recipient: DRAINER }]),
        signatureMethod: 'eth_signTypedData_v4',
        origin: 'https://app.uniswap.org',
      });
      const orderText = textOf(order.getInterface().content);
      expect(orderText).toContain(`Not checked: recipient ${DRAINER}`);
      expect(orderText).toContain(`Also involved: spender ${REACTOR}`);
      const deployment = await sesSnap(snap).onRawTransaction({
        chainId: 'eip155:1',
        transactionOrigin: ORIGIN,
        transaction: { from: USER, value: '0x0', data: '0x6080604052348015600f57600080fd5b50603f80601d6000396000f3fe', gas: '0x5208', maxFeePerGas: '0x1', maxPriorityFeePerGas: '0x1', nonce: '0x0' },
      });
      const deploymentText = textOf(deployment.getInterface().content);
      notVerified(deploymentText);
      expect(deploymentText).toContain('deploys a new contract');
      expect(api.requests).toHaveLength(0);
    });

    it('locally proven danger is still critical; without it there is no severity', async () => {
      const listing = await snap.onSignature({
        from: USER,
        data: seaportOrder([nft(BAYC, '1'), nft(BAYC, '2')], [erc20Item(WETH, '1', USER)]),
        signatureMethod: 'eth_signTypedData_v4',
        origin: ORIGIN,
      });
      expect(severityOf(listing)).toBe('critical');
      const listingText = textOf(listing.getInterface().content);
      expect(listingText).toContain('Dangerous request — do not sign');
      expect(listingText).toContain('typical of NFT drainer listings');
      notVerified(listingText);

      const delegatecall = await snap.onTransaction({ from: USER, to: SAFE, data: safeExec(DRAINER, 0n, '0x12345678', 1), origin: 'https://app.safe.global' });
      expect(severityOf(delegatecall)).toBe('critical');
      expect(textOf(delegatecall.getInterface().content)).toContain(`DELEGATECALL to ${DRAINER}`);

      const plain = await snap.onTransaction({ from: USER, to: RECIPIENT, value: '0x1', data: '0x', origin: ORIGIN });
      expect(severityOf(plain)).toBeUndefined();
      expect(api.requests).toHaveLength(0);
    });

    it('a 4 MiB personal_sign and a 4 MiB typed-data field still produce an insight, not an error', async () => {
      const big = await snap.onSignature({ from: USER, data: `0x${'61'.repeat(4 * 1024 * 1024)}`, signatureMethod: 'personal_sign', origin: ORIGIN });
      expect(big.response).toHaveProperty('result');
      notVerified(textOf(big.getInterface().content));
      const typed = erc2612Permit(DRAINER, '5', 1, { junk: `0x${'ab'.repeat(4 * 1024 * 1024)}` });
      const response = await snap.onSignature({ from: USER, data: typed, signatureMethod: 'eth_signTypedData_v4', origin: ORIGIN });
      expect(response.response).toHaveProperty('result');
      expect(textOf(response.getInterface().content)).toContain(`Not checked: spender ${DRAINER}`);
      expect(api.requests).toHaveLength(0);
    }, 120000);
  });

  paidMode('paid mode through the SES bundle', () => {
    paidModeScenarios({ api, makeSnap: async () => sesSnap(await install()) });
  });
});
