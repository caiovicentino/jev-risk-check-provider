/**
 * Integration tests: the BUILT bundle (dist/bundle.js, pinned by the manifest
 * shasum) runs in MetaMask's SES execution environment via @metamask/snaps-jest.
 * Only `snap`, `ethereum`, `fetch` and the SES default endowments exist there,
 * so a bare `snap_manageState(...)` would throw a ReferenceError here exactly as
 * in MetaMask. The network transport is redirected to a local mock API
 * (see harness/worker-entry.cjs) so request bodies can be asserted.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';
import type {} from '@metamask/snaps-jest';
import { assertIsResponseWithInterface, handleRequest } from '@metamask/snaps-simulation';

import { DISCLOSURE_VERSION } from '../src/state';
import { LOW_RISK_VERDICT, MockApi } from './harness/mock-api';
import type { BuiltSnap } from './harness/snap';
import { installBuiltSnap, readSnapState } from './harness/snap';
import {
  BAYC,
  DRAINER,
  MAX_UINT160,
  MAX_UINT256,
  NPM,
  REACTOR,
  RECIPIENT,
  SAFE,
  UNIVERSAL_ROUTER,
  USDC,
  USER,
  WETH,
  calldata,
  daiPermit,
  erc20Item,
  erc2612Permit,
  eth,
  multicall,
  nft,
  permitSingle,
  safeExec,
  seaportOrder,
  textOf,
  uniswapXOrder,
  utf8Hex,
} from './helpers';

// snaps-simulation's own (older) snaps-utils HandlerType enum; the string value
// is what reaches the execution environment.
type SimulationHandler = Parameters<typeof handleRequest>[0]['handler'];

function severityOf(response: { response: unknown }): unknown {
  const inner = response.response as { result?: { severity?: unknown } };
  return inner.result?.severity;
}

const ORIGIN = 'https://app.example-dex.xyz';

describe('x402check snap (built bundle in the SES execution environment)', () => {
  const api = new MockApi();
  let mockOrigin: string;
  let snap: BuiltSnap;

  beforeAll(async () => {
    mockOrigin = await api.start();
  });

  afterAll(async () => {
    await api.stop();
  });

  beforeEach(async () => {
    api.reset();
    snap = await installBuiltSnap(mockOrigin, {
      unencryptedState: { installId: 'ab'.repeat(16), disclosureVersion: DISCLOSURE_VERSION },
    });
  });

  describe('lifecycle and privacy', () => {
    it('onInstall shows the disclosure alert and persists a random install id', async () => {
      const fresh = await installBuiltSnap(mockOrigin);
      const pending = fresh.onInstall();
      const ui = await pending.getInterface();
      expect(ui.type).toBe('alert');
      const text = textOf(ui.content);
      expect(text).toContain('x402check.xyz');
      expect(text).toContain('counterparty address');
      expect(text).toContain('chain ID');
      expect(text).toContain('requesting site');
      expect(text).toContain('human-readable summary');
      expect(text).toContain('random install ID');
      expect(text).toContain('not derived from your Secret Recovery Phrase');
      expect(text).toContain('private keys and Secret Recovery Phrase never leave your wallet');
      await (ui as { ok(): Promise<void> }).ok();
      expect(await pending).toRespondWith(null);

      const state = readSnapState(fresh, false);
      expect(state?.installId).toMatch(/^[0-9a-f]{32}$/u);
      expect(state?.disclosureVersion).toBe(DISCLOSURE_VERSION);
      // Nothing is sent to the network on install.
      expect(api.requests).toHaveLength(0);

      // The id is used for requests and stays stable across calls.
      await fresh.onTransaction({ from: USER, to: RECIPIENT, value: '0x1', data: '0x', origin: ORIGIN });
      await fresh.onTransaction({ from: USER, to: RECIPIENT, value: '0x2', data: '0x', origin: ORIGIN });
      expect(api.requests).toHaveLength(2);
      expect(api.requests[0]?.headers['x-risk-check-client']).toBe(state?.installId);
      expect(api.requests[1]?.headers['x-risk-check-client']).toBe(state?.installId);
      expect(readSnapState(fresh, false)?.installId).toBe(state?.installId);
    });

    it('install ids are random, not derived from the Secret Recovery Phrase', async () => {
      // Both installs use the same simulated SRP; an SRP-derived id would match.
      const first = await installBuiltSnap(mockOrigin);
      await first.onTransaction({ from: USER, to: RECIPIENT, value: '0x1', data: '0x', origin: ORIGIN });
      const second = await installBuiltSnap(mockOrigin);
      await second.onTransaction({ from: USER, to: RECIPIENT, value: '0x1', data: '0x', origin: ORIGIN });
      const [a, b] = api.requests.map((request) => request.headers['x-risk-check-client']);
      expect(a).toMatch(/^[0-9a-f]{32}$/u);
      expect(b).toMatch(/^[0-9a-f]{32}$/u);
      expect(a).not.toBe(b);
    });

    it('uses the persisted install id', async () => {
      await snap.onTransaction({ from: USER, to: RECIPIENT, value: '0x1', data: '0x', origin: ORIGIN });
      expect(api.last?.headers['x-risk-check-client']).toBe('ab'.repeat(16));
      expect(api.last?.headers['content-type']).toBe('application/json');
      expect(api.last?.method).toBe('POST');
      expect(api.last?.path).toBe('/v1/risk-check');
    });

    it('onUpdate from 0.1.x drops the SRP-derived client id and shows the disclosure', async () => {
      const legacy = await installBuiltSnap(mockOrigin, { state: { clientId: '0x1234567890abcd' } });
      const pending = legacy.onUpdate();
      const ui = await pending.getInterface();
      expect(ui.type).toBe('alert');
      await (ui as { ok(): Promise<void> }).ok();
      await pending;
      expect(readSnapState(legacy, true)).toBeNull();
      const state = readSnapState(legacy, false);
      expect(state?.installId).toMatch(/^[0-9a-f]{32}$/u);
      await legacy.onTransaction({ from: USER, to: RECIPIENT, value: '0x1', data: '0x', origin: ORIGIN });
      expect(api.last?.headers['x-risk-check-client']).toBe(state?.installId);
      expect(api.last?.headers['x-risk-check-client']).not.toContain('1234567890abcd');
    });

    it('onUpdate on a current install shows no dialog and keeps non-legacy encrypted state', async () => {
      const current = await installBuiltSnap(mockOrigin, {
        state: { unrelated: 'keep' },
        unencryptedState: { installId: 'cd'.repeat(16), disclosureVersion: DISCLOSURE_VERSION },
      });
      expect(await current.onUpdate()).toRespondWith(null);
      expect(readSnapState(current, true)).toStrictEqual({ unrelated: 'keep' });
      expect(readSnapState(current, false)).toStrictEqual({ installId: 'cd'.repeat(16), disclosureVersion: DISCLOSURE_VERSION });
    });

    it('onUpdate from 0.2.0 (disclosure v1) shows the new transaction disclosure and records the new version', async () => {
      const previous = await installBuiltSnap(mockOrigin, { unencryptedState: { installId: 'ef'.repeat(16), disclosureVersion: 1 } });
      const pending = previous.onUpdate();
      const ui = await pending.getInterface();
      expect(ui.type).toBe('alert');
      const text = textOf(ui.content);
      expect(text).toContain('the full transaction (from, to, value and calldata)');
      expect(text).toContain('public RPC node');
      expect(text).toContain('Blockscout');
      await (ui as { ok(): Promise<void> }).ok();
      expect(await pending).toRespondWith(null);
      expect(readSnapState(previous, false)).toStrictEqual({ installId: 'ef'.repeat(16), disclosureVersion: DISCLOSURE_VERSION });
    });
  });

  describe('transactions: the checked address is the real counterparty', () => {
    it('native transfer checks the recipient with the value as payment', async () => {
      const response = await snap.onTransaction({
        chainId: 'eip155:8453',
        from: USER,
        to: RECIPIENT,
        value: '0x2386f26fc10000',
        data: '0x',
        origin: ORIGIN,
      });
      expect(api.last?.body).toStrictEqual({
        wallet: RECIPIENT,
        chain: 'eip155:8453',
        domain: 'app.example-dex.xyz',
        context: expect.stringContaining('Native transfer: sends 0.01 ETH (10000000000000000 wei) to recipient'),
        payment: { network: 'eip155:8453', pay_to: RECIPIENT, amount: '10000000000000000', asset: 'native' },
        interaction: { type: 'native_transfer' },
        transaction: { from: USER, to: RECIPIENT, value: '0x2386f26fc10000' },
      });
      const text = textOf(response.getInterface().content);
      expect(text).toContain('x402check · score 88/100 · low');
      expect(text).toContain('No significant risk signals found.');
      expect(text).toContain('Checked: recipient');
      expect(severityOf(response)).toBeUndefined();
    });

    it('ERC-20 transfer checks the recipient, not the token contract', async () => {
      await snap.onTransaction({
        from: USER,
        to: USDC,
        data: calldata('a9059cbb', RECIPIENT, 5_000_000n),
        origin: ORIGIN,
      });
      const body = api.last?.body;
      expect(body.wallet).toBe(RECIPIENT);
      expect(body.payment).toStrictEqual({ network: 'eip155:1', pay_to: RECIPIENT, amount: '5000000', asset: USDC });
      expect(body.interaction).toStrictEqual({ type: 'token_transfer' });
      expect(body.context).toContain(`ERC-20 transfer: sends 5 USDC (5000000 base units of ${USDC}) to recipient ${RECIPIENT}`);
    });

    it('approve(drainer, MAX) checks the SPENDER and flags UNLIMITED', async () => {
      const response = await snap.onTransaction({
        from: USER,
        to: USDC,
        data: calldata('095ea7b3', DRAINER, MAX_UINT256),
        origin: ORIGIN,
      });
      const body = api.last?.body;
      expect(body.wallet).toBe(DRAINER);
      expect(body.wallet).not.toBe(USDC);
      expect(body.interaction).toStrictEqual({ type: 'token_approval', unlimited: true });
      expect(body.payment).toStrictEqual({
        network: 'eip155:1',
        pay_to: DRAINER,
        amount: MAX_UINT256.toString(),
        asset: USDC,
      });
      expect(body.context).toContain('UNLIMITED allowance');
      expect(body.context).not.toContain('direct wallet transfer');
      expect(body.context).not.toMatch(/0x095ea7b3|[0-9a-f]{64}/u);
      const text = textOf(response.getInterface().content);
      expect(text).toContain('Checked: spender');
      expect(text).toContain(DRAINER);
      expect(text).toContain('Allowance');
      expect(text).toContain('UNLIMITED');
    });

    it('setApprovalForAll checks the operator', async () => {
      const response = await snap.onTransaction({
        from: USER,
        to: BAYC,
        data: calldata('a22cb465', DRAINER, 1n),
        origin: ORIGIN,
      });
      const body = api.last?.body;
      expect(body.wallet).toBe(DRAINER);
      expect(body.interaction).toStrictEqual({ type: 'nft_approval' });
      expect(body.context).toContain(`grants operator ${DRAINER} control of ALL`);
      const text = textOf(response.getInterface().content);
      expect(text).toContain('Checked: operator');
      expect(text).toContain('ALL items in the collection');
    });

    it('contract deployment is not sent anywhere', async () => {
      const response = await handleRequest({
        snapId: snap.snapId,
        store: snap.store,
        executionService: snap.executionService,
        controllerMessenger: snap.controllerMessenger,
        runSaga: snap.runSaga,
        handler: 'onTransaction' as unknown as SimulationHandler,
        request: {
          method: '',
          params: {
            chainId: 'eip155:1',
            transactionOrigin: ORIGIN,
            transaction: {
              from: USER,
              value: '0x0',
              data: '0x6080604052348015600f57600080fd5b50603f80601d6000396000f3fe',
              gas: '0x5208',
              maxFeePerGas: '0x1',
              maxPriorityFeePerGas: '0x1',
              nonce: '0x0',
            },
          },
        },
      });
      expect(api.requests).toHaveLength(0);
      assertIsResponseWithInterface(response);
      const text = textOf(response.getInterface().content);
      expect(text).toContain('x402check · not checked');
      expect(text).toContain('deploys a new contract');
    });
  });

  describe('signatures: typed data and messages are decoded', () => {
    it('Permit2 PermitSingle: legit router and drainer produce different requests', async () => {
      await snap.onSignature({
        from: USER,
        data: permitSingle(UNIVERSAL_ROUTER),
        signatureMethod: 'eth_signTypedData_v4',
        origin: ORIGIN,
      });
      await snap.onSignature({
        from: USER,
        data: permitSingle(DRAINER),
        signatureMethod: 'eth_signTypedData_v4',
        origin: ORIGIN,
      });
      const [legit, drainer] = api.requests.map((request) => request.body);
      expect(legit.wallet).toBe(UNIVERSAL_ROUTER);
      expect(drainer.wallet).toBe(DRAINER);
      expect(legit).not.toStrictEqual(drainer);
      expect(legit.chain).toBe('eip155:1');
      expect(drainer.interaction).toStrictEqual({ type: 'permit_signature', unlimited: true });
      expect(drainer.payment).toStrictEqual({
        network: 'eip155:1',
        pay_to: DRAINER,
        amount: MAX_UINT160.toString(),
        asset: USDC,
      });
      expect(drainer.context).toContain(`Permit2 PermitSingle signature`);
      expect(drainer.context).toContain(`grants spender ${DRAINER} an UNLIMITED allowance`);
      expect(drainer.wallet).not.toBe(USER);
    });

    it('EIP-2612 Permit checks the spender', async () => {
      await snap.onSignature({
        from: USER,
        data: erc2612Permit(DRAINER, '1000000', '0x2105'),
        signatureMethod: 'eth_signTypedData_v4',
        origin: ORIGIN,
      });
      const body = api.last?.body;
      expect(body.wallet).toBe(DRAINER);
      expect(body.chain).toBe('eip155:8453');
      expect(body.interaction).toStrictEqual({ type: 'permit_signature' });
      expect(body.payment).toStrictEqual({ network: 'eip155:8453', pay_to: DRAINER, amount: '1000000', asset: USDC });
      expect(body.context).toContain(`EIP-2612 permit signature ("USD Coin", verifying contract ${USDC})`);
    });

    it('Seaport order checks the non-offerer recipient and notes what the offerer receives', async () => {
      await snap.onSignature({
        from: USER,
        data: seaportOrder([nft(BAYC, '1234')], [eth('1', DRAINER)]),
        signatureMethod: 'eth_signTypedData_v4',
        origin: ORIGIN,
      });
      const body = api.last?.body;
      expect(body.wallet).toBe(DRAINER);
      expect(body.interaction).toStrictEqual({ type: 'order_signature' });
      expect(body.context).toContain('the offerer receives NOTHING');
      expect(body.context).toContain(`NFT ${BAYC} #1234`);
    });

    it('typed data v1 (array) checks the address-typed value that is not the signer', async () => {
      await snap.onSignature({
        from: USER,
        data: [
          { type: 'string', name: 'action', value: 'Authorize transfer' },
          { type: 'address', name: 'owner', value: USER },
          { type: 'address', name: 'to', value: RECIPIENT },
          { type: 'uint256', name: 'amount', value: '42' },
        ],
        signatureMethod: 'eth_signTypedData',
        origin: ORIGIN,
      });
      const body = api.last?.body;
      expect(body.wallet).toBe(RECIPIENT);
      expect(body.interaction).toStrictEqual({ type: 'message_signature' });
      expect(body.context).toContain('Legacy typed-data signature (eth_signTypedData v1)');
    });

    it('personal_sign phishing text is decoded; no fake address is taken from the hex', async () => {
      const message = 'Claim your airdrop now at https://jup1ter-audit.click/claim?id=42 and sign to verify eligibility.';
      const hex = utf8Hex(message);
      const response = await snap.onSignature({
        from: USER,
        data: hex,
        signatureMethod: 'personal_sign',
        origin: 'https://untrusted-airdrop.example.com',
      });
      const body = api.last?.body;
      // The old snap took the first 20 bytes of the hex as a "counterparty".
      expect(body.wallet).not.toBe(`0x${hex.slice(2, 42)}`);
      expect(body.wallet).toBe(USER);
      expect(body.domain).toBe('untrusted-airdrop.example.com');
      expect(body.interaction).toStrictEqual({ type: 'message_signature' });
      expect(body.context).toContain('Claim your airdrop now at https://jup1ter-audit.click/claim?id=42');
      expect(body.context).toContain('Message references: jup1ter-audit.click');
      expect(body.context).toContain('No counterparty address in message; subject is the signer');
      expect(body.context).not.toContain(hex.slice(2, 42));
      expect(Object.keys(body).sort()).toStrictEqual(['context', 'domain', 'interaction', 'wallet']);
      const text = textOf(response.getInterface().content);
      expect(text).toContain('Checked: signer (you)');
      expect(text).toContain('your own signing address was checked');
    });
  });

  describe('failure modes are never an all-clear', () => {
    const send = async () =>
      snap.onTransaction({ from: USER, to: USDC, data: calldata('095ea7b3', DRAINER, MAX_UINT256), origin: ORIGIN });

    it('HTTP 402 says the free checks are used up and NOT checked', async () => {
      api.respondWith({ status: 402, json: { error: 'payment_required' } });
      const response = await send();
      const text = textOf(response.getInterface().content);
      expect(text).toContain('x402check · free daily checks used up — this was NOT checked');
      expect(text).not.toContain('No significant risk');
      expect(text).toContain('UNLIMITED');
    });

    it('HTTP 500 says check failed, NOT verified', async () => {
      api.respondWith({ status: 500, text: 'boom' });
      const text = textOf((await send()).getInterface().content);
      expect(text).toContain('x402check · check failed — NOT verified');
      expect(text).toContain('HTTP 500');
    });

    it('network error says unavailable, NOT verified', async () => {
      api.respondWith('network-error');
      const text = textOf((await send()).getInterface().content);
      expect(text).toContain('x402check · unavailable — NOT verified');
      expect(text).not.toContain('No significant risk');
    });

    it('checked:false says verification failed, NOT verified', async () => {
      api.respondWith({ status: 200, json: { checked: false } });
      const text = textOf((await send()).getInterface().content);
      expect(text).toContain('x402check · verification failed — NOT verified');
    });

    it('an unknown or missing tier never shows the no-risk copy', async () => {
      api.respondWith({ status: 200, json: { checked: true, score: 3, tier: 'pristine' } });
      const text = textOf((await send()).getInterface().content);
      expect(text).toContain('x402check · score 3/100 · unknown tier');
      expect(text).toContain('Some risk signals present.');
      expect(text).not.toContain('No significant risk');
    });
  });

  describe('evidence rendering', () => {
    it('sanctions-listed evidence is critical and loud', async () => {
      api.respondWith({
        status: 200,
        json: {
          ...LOW_RISK_VERDICT,
          score: 20,
          tier: 'low',
          evidence: {
            sanctions: { list: 'ofac-sdn', as_of: '2026-09-01', status: 'listed', entity: 'LAZARUS GROUP' },
            onchain: { status: 'ok', activity: 'some', is_contract: false, tx_count: 12 },
          },
        },
      });
      const response = await snap.onTransaction({ from: USER, to: RECIPIENT, value: '0x1', data: '0x', origin: ORIGIN });
      expect(severityOf(response)).toBe('critical');
      const text = textOf(response.getInterface().content);
      expect(text).toContain('OFAC-sanctioned address — do not proceed');
      expect(text).toContain('LAZARUS GROUP');
      expect(text).toContain('2026-09-01');
      expect(text).toContain('Critical risk detected.');
      expect(text).not.toContain('No significant risk');
    });

    it('high tier is critical; domain, on-chain, feeds and categories are rendered', async () => {
      api.respondWith({
        status: 200,
        json: {
          checked: true,
          score: 91,
          tier: 'high',
          categories: ['approval_to_eoa', 'phishing_domain', 'new_address'],
          jws: LOW_RISK_VERDICT.jws,
          jwks_url: 'https://x402check.xyz/.well-known/jwks.json',
          evidence: {
            sanctions: { list: 'ofac-sdn', as_of: '2026-09-01', status: 'not_listed' },
            domain: {
              host: 'app.example-dex.xyz',
              registrable: 'example-dex.xyz',
              official: false,
              impersonation: 'strong',
              brand: 'Uniswap',
              signals: ['brand lookalike'],
            },
            onchain: { status: 'ok', activity: 'none', is_contract: false, tx_count: 0 },
            feeds: [
              { source: 'scamsniffer-addresses', kind: 'address', as_of: '2026-09-28', status: 'hit' },
              { source: 'metamask-phishing-detect', kind: 'domain', as_of: '2026-09-28', status: 'clear' },
            ],
          },
        },
      });
      const response = await snap.onTransaction({
        from: USER,
        to: USDC,
        data: calldata('095ea7b3', DRAINER, MAX_UINT256),
        origin: ORIGIN,
      });
      expect(severityOf(response)).toBe('critical');
      const text = textOf(response.getInterface().content);
      expect(text).toContain('x402check · score 91/100 · high');
      expect(text).toContain('Known scam address (ScamSniffer)');
      expect(text).toContain('Not listed (list as of 2026-09-01)');
      expect(text).toContain('app.example-dex.xyz impersonates Uniswap');
      expect(text).toContain('New address: no on-chain activity found');
      expect(text).toContain('Spender is a regular wallet (EOA), not a contract — typical of drainers');
      expect(text).toContain('Approval to a regular wallet (EOA), Phishing domain, New address (no history)');
      expect(text).toContain(LOW_RISK_VERDICT.jws);
      expect(text).toContain('https://x402check.xyz/.well-known/jwks.json');
    });

    it('contract counterparty and an older server without evidence render gracefully', async () => {
      api.respondWith({
        status: 200,
        json: { ...LOW_RISK_VERDICT, evidence: { onchain: { status: 'ok', activity: 'some', is_contract: true } } },
      });
      const withEvidence = textOf(
        (await snap.onTransaction({ from: USER, to: USDC, data: calldata('12345678'), origin: ORIGIN })).getInterface()
          .content,
      );
      expect(withEvidence).toContain('Counterparty is a contract');
      expect(api.last?.body.interaction).toStrictEqual({ type: 'contract_call' });

      api.respondWith({ status: 200, json: { checked: true, score: 40, tier: 'medium' } });
      const response = await snap.onTransaction({ from: USER, to: RECIPIENT, value: '0x1', data: '0x', origin: ORIGIN });
      const text = textOf(response.getInterface().content);
      expect(text).toContain('x402check · score 40/100 · medium');
      expect(text).toContain('This verdict was not signed.');
      expect(severityOf(response)).toBeUndefined();
    });
  });

  describe('review regressions through the SES bundle', () => {
    const CRITICAL = { checked: true, score: 12, tier: 'critical', categories: ['known_scam_address'] };
    const worstForDrainer = (request: { path: string; body: any }) =>
      request.path.endsWith('/batch')
        ? { status: 200, json: { results: request.body.requests.map((item: { wallet: string }) => (item.wallet === DRAINER ? CRITICAL : LOW_RISK_VERDICT)) } }
        : { status: 200, json: LOW_RISK_VERDICT };

    it('finding 1: a permit whose spender is a DECIMAL string checks the drainer, UNLIMITED', async () => {
      await snap.onSignature({
        from: USER,
        data: erc2612Permit(BigInt(DRAINER).toString(10), `0x${'0'.repeat(8)}${'f'.repeat(64)}`),
        signatureMethod: 'eth_signTypedData_v4',
        origin: ORIGIN,
      });
      expect(api.last?.path).toBe('/v1/risk-check');
      expect(api.last?.body.wallet).toBe(DRAINER);
      expect(api.last?.body.interaction).toStrictEqual({ type: 'permit_signature', unlimited: true });
      expect(api.last?.body.context).toContain(`signs as ${DRAINER}`);
    });

    it('finding 2: DAI permit with allowed:"false" is an UNLIMITED permit, not a revocation', async () => {
      const response = await snap.onSignature({ from: USER, data: daiPermit('false'), signatureMethod: 'eth_signTypedData_v4', origin: ORIGIN });
      expect(api.last?.body.interaction).toStrictEqual({ type: 'permit_signature', unlimited: true });
      const text = textOf(response.getInterface().content);
      expect(text).toContain('UNLIMITED');
      expect(text).not.toContain('revoke');
    });

    it('finding 3: a payable call checks the ETH recipient (batch with the decoded inner spender)', async () => {
      await snap.onTransaction({ from: USER, to: DRAINER, value: '0x4563918244f40000', data: calldata('095ea7b3', UNIVERSAL_ROUTER, 0n), origin: ORIGIN });
      expect(api.last?.path).toBe('/v1/risk-check/batch');
      const requests = api.last?.body.requests as { wallet: string; payment?: unknown; interaction: unknown }[];
      expect(requests.map((item) => item.wallet)).toStrictEqual([DRAINER, UNIVERSAL_ROUTER]);
      expect(requests[0]?.payment).toStrictEqual({ network: 'eip155:1', pay_to: DRAINER, amount: '5000000000000000000', asset: 'native' });
      expect(requests[0]?.interaction).toStrictEqual({ type: 'contract_call' });
    });

    it('finding 4: a Seaport listing paying 1 unit of WETH is critical even if the server says low', async () => {
      const response = await snap.onSignature({
        from: USER,
        data: seaportOrder([nft(BAYC, '1'), nft(BAYC, '2')], [erc20Item(WETH, '1', USER)]),
        signatureMethod: 'eth_signTypedData_v4',
        origin: ORIGIN,
      });
      expect(severityOf(response)).toBe('critical');
      const text = textOf(response.getInterface().content);
      expect(text).toContain('Dangerous request — do not sign');
      expect(text).toContain('typical of NFT drainer listings');
      expect(api.last?.body.context).toMatch(/^Proven danger: /u);
    });

    it('finding 5: a UniswapX output to a third party is checked first; the worst verdict is shown', async () => {
      api.respondWith(worstForDrainer);
      const response = await snap.onSignature({
        from: USER,
        data: uniswapXOrder([{ token: USDC, amount: '9999000000', recipient: DRAINER }]),
        signatureMethod: 'eth_signTypedData_v4',
        origin: 'https://app.uniswap.org',
      });
      expect(api.last?.path).toBe('/v1/risk-check/batch');
      expect(api.last?.body.requests.map((item: { wallet: string }) => item.wallet)).toStrictEqual([DRAINER, REACTOR]);
      expect(severityOf(response)).toBe('critical');
      const text = textOf(response.getInterface().content);
      expect(text).toContain('x402check · score 12/100 · critical');
      expect(text).toContain(`Checked: recipient ${DRAINER}`);
      expect(text).toContain('Also checked: spender');
    });

    it('finding 6: multicall and Safe DELEGATECALL wrappers are decoded', async () => {
      await snap.onTransaction({ from: USER, to: NPM, data: multicall([calldata('a22cb465', DRAINER, 1n)]), origin: ORIGIN });
      expect(api.last?.body.wallet).toBe(DRAINER);
      expect(api.last?.body.interaction).toStrictEqual({ type: 'nft_approval' });
      const response = await snap.onTransaction({ from: USER, to: SAFE, data: safeExec(DRAINER, 0n, '0x12345678', 1), origin: 'https://app.safe.global' });
      expect(api.last?.body.wallet).toBe(DRAINER);
      expect(severityOf(response)).toBe('critical');
      expect(textOf(response.getInterface().content)).toContain(`DELEGATECALL to ${DRAINER}`);
    });

    it('finding 7: approve(x, 0) on an NFT contract is an approval, on USDC a revocation', async () => {
      await snap.onTransaction({ from: USER, to: BAYC, data: calldata('095ea7b3', DRAINER, 0n), origin: ORIGIN });
      expect(api.last?.body.interaction).toStrictEqual({ type: 'token_approval' });
      await snap.onTransaction({ from: USER, to: USDC, data: calldata('095ea7b3', DRAINER, 0n), origin: ORIGIN });
      expect(api.last?.body.interaction).toStrictEqual({ type: 'contract_call' });
    });

    it('finding 8: a 4 MiB personal_sign and a typed-data field of 4 MiB produce an insight, not an error', async () => {
      const big = await snap.onSignature({ from: USER, data: `0x${'61'.repeat(4 * 1024 * 1024)}`, signatureMethod: 'personal_sign', origin: ORIGIN });
      expect(big.response).toHaveProperty('result');
      expect(textOf(big.getInterface().content)).toContain('x402check · score 88/100 · low');
      expect(api.last?.body.context).toContain('large payload (4194304 bytes)');
      const typed = erc2612Permit(DRAINER, '5', 1, { junk: `0x${'ab'.repeat(4 * 1024 * 1024)}` });
      const response = await snap.onSignature({ from: USER, data: typed, signatureMethod: 'eth_signTypedData_v4', origin: ORIGIN });
      expect(response.response).toHaveProperty('result');
      expect(api.last?.body.wallet).toBe(DRAINER);
    }, 120000);

    it('finding 9a/9b: secrets are redacted and IDN hosts are punycoded in what the bundle sends', async () => {
      const key = '4c0883a69102937d6231471b5dbb6204fe512961708279f8b3e8b1b1c3a6a2c0';
      await snap.onSignature({ from: USER, data: utf8Hex(`Export: pk_${key}`), signatureMethod: 'personal_sign', origin: ORIGIN });
      expect(api.last?.body.context).toContain('[redacted secret-like string]');
      expect(api.last?.body.context).not.toContain(key);
      await snap.onSignature({ from: USER, data: utf8Hex('Claim your airdrop at un\u0456swap.org today'), signatureMethod: 'personal_sign', origin: 'metamask' });
      expect(api.last?.body.domain).toBe('xn--unswap-qvf.org');
    });

    it('finding 9c: a message naming two addresses checks both and shows the worst verdict', async () => {
      api.respondWith(worstForDrainer);
      const response = await snap.onSignature({
        from: USER,
        data: utf8Hex(`Claim for token ${USDC}, payout wallet ${DRAINER}`),
        signatureMethod: 'personal_sign',
        origin: ORIGIN,
      });
      expect(api.last?.path).toBe('/v1/risk-check/batch');
      expect(api.last?.body.requests.map((item: { wallet: string }) => item.wallet)).toStrictEqual([USDC, DRAINER]);
      expect(severityOf(response)).toBe('critical');
      const text = textOf(response.getInterface().content);
      expect(text).toContain('score 12/100 · critical');
      expect(text).toContain(`Checked: counterparty ${DRAINER}`);
      expect(text).toContain('score 88/100 · low');
    });
  });

  describe('transaction simulation (provider v0.3) through the SES bundle', () => {
    const simulated = (simulation: unknown, tier = 'low', score = 90) => ({
      status: 200,
      json: { checked: true, score, tier, categories: [], evidence: { simulation } },
    });

    it('sends the transaction to simulate with the risk check', async () => {
      await snap.onTransaction({ from: USER, to: USDC, value: '0x0', data: calldata('095ea7b3', DRAINER, MAX_UINT256), origin: ORIGIN });
      expect(api.last?.path).toBe('/v1/risk-check');
      expect(api.last?.body.transaction).toStrictEqual({ from: USER, to: USDC, value: '0x0', data: calldata('095ea7b3', DRAINER, MAX_UINT256) });
      expect(api.last?.body.chain).toBe('eip155:1');
    });

    it('renders the simulated effects and makes a drainer finding critical', async () => {
      api.respondWith(
        simulated({
          status: 'ok',
          network: 'eip155:1',
          outflows: [{ standard: 'native', asset: 'native', amount: '1000000000000000000', counterparty: DRAINER, counterparty_is_contract: false }],
          inflows: [],
          approvals: [],
          findings: ['outflow_to_undisclosed_eoa'],
        }),
      );
      const response = await snap.onTransaction({ from: USER, to: RECIPIENT, value: '0xde0b6b3a7640000', data: '0x', origin: ORIGIN });
      expect(severityOf(response)).toBe('critical');
      const text = textOf(response.getInterface().content).replace(/\s+/gu, ' ');
      expect(text).toContain('Simulation: likely wallet drainer — do not proceed');
      expect(text).toContain('What this transaction does (simulated)');
      expect(text).toContain('You send 1 ETH → 0x9d17bb…b277bc (wallet)');
      expect(text).not.toContain('No significant risk');
    });

    it('reverted and unavailable simulations are stated plainly', async () => {
      api.respondWith(simulated({ status: 'reverted', network: 'eip155:1', findings: ['simulation_reverted'] }, 'medium', 60));
      const reverted = await snap.onTransaction({ from: USER, to: USDC, data: calldata('a9059cbb', RECIPIENT, 1n), origin: ORIGIN });
      expect(textOf(reverted.getInterface().content)).toContain('This transaction would revert (fail) if sent as is.');
      api.respondWith(simulated({ status: 'unavailable', network: 'eip155:1' }));
      const unavailable = await snap.onTransaction({ from: USER, to: USDC, data: calldata('a9059cbb', RECIPIENT, 1n), origin: ORIGIN });
      expect(textOf(unavailable.getInterface().content).replace(/\s+/gu, ' ')).toContain('NOT simulated: the simulation service was unavailable');
    });

    it('oversize calldata is not sent for simulation, with a visible warning', async () => {
      // 49,154 characters: just over the provider's 48 KiB cap.
      const data: `0x${string}` = `0xdeadbeef${'00'.repeat(24_572)}`;
      const response = await snap.onTransaction({ from: USER, to: RECIPIENT, data, origin: ORIGIN });
      expect(api.last?.body.transaction).toBeUndefined();
      const text = textOf(response.getInterface().content).replace(/\s+/gu, ' ');
      expect(text).toContain('too large to simulate');
      expect(text).toContain('NOT simulated');
    });

    it('a non-EVM chain and signatures never send a transaction', async () => {
      await snap.onTransaction({ chainId: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', from: USER, to: RECIPIENT, value: '0x1', data: '0x', origin: ORIGIN });
      expect(api.last?.body).not.toHaveProperty('transaction');
      expect(api.last?.body).not.toHaveProperty('chain');
      const response = await snap.onSignature({ from: USER, data: permitSingle(DRAINER), signatureMethod: 'eth_signTypedData_v4', origin: ORIGIN });
      expect(api.last?.body).not.toHaveProperty('transaction');
      expect(textOf(response.getInterface().content)).not.toContain('simulated');
    });
  });

  describe('drainer-kit code fingerprints through the SES bundle', () => {
    it('a reverted simulation of a known drainer contract is critical, with the revert line and the banner', async () => {
      api.respondWith({
        status: 200,
        json: {
          checked: true,
          score: 60,
          tier: 'medium',
          categories: ['known_drainer_code'],
          evidence: {
            simulation: {
              status: 'reverted',
              network: 'eip155:1',
              findings: ['simulation_reverted', 'known_drainer_code'],
              code_matches: [{ address: DRAINER, role: 'called', sources: ['forta-phishing-code'] }],
            },
            feeds: [{ source: 'scamsniffer-code', kind: 'code', as_of: '2026-09-28', status: 'hit' }],
          },
        },
      });
      const response = await snap.onTransaction({ from: USER, to: DRAINER, data: calldata('deadbeef', 1n), origin: ORIGIN });
      expect(severityOf(response)).toBe('critical');
      const text = textOf(response.getInterface().content).replace(/\s+/gu, ' ');
      expect(text).toContain('This transaction would revert (fail) if sent as is.');
      expect(text).toContain('The contract you are calling (0x9d17bb…b277bc) runs the same code as contracts listed as wallet drainers (listed by Forta).');
      expect(text).toContain('Runs known wallet-drainer code (ScamSniffer drainer code fingerprints)');
      expect(text).toContain('Known drainer code');
    });
  });

  describe('provider review follow-up through the SES bundle', () => {
    it('outflow_exceeds_declared is critical; a checked:false reason is shown', async () => {
      api.respondWith({
        status: 200,
        json: {
          checked: true,
          score: 30,
          tier: 'high',
          categories: [],
          evidence: { simulation: { status: 'ok', outflows: [], inflows: [], approvals: [], findings: ['outflow_exceeds_declared'] } },
        },
      });
      const exceeds = await snap.onTransaction({ from: USER, to: USDC, data: calldata('a9059cbb', RECIPIENT, 1n), origin: ORIGIN });
      expect(severityOf(exceeds)).toBe('critical');
      expect(textOf(exceeds.getInterface().content)).toContain('receives a different asset or a larger amount than this transaction shows');
      api.respondWith({ status: 200, json: { checked: false, reason: 'model_malformed_answers' } });
      const unverified = await snap.onTransaction({ from: USER, to: USDC, data: calldata('a9059cbb', RECIPIENT, 1n), origin: ORIGIN });
      expect(textOf(unverified.getInterface().content)).toContain('failed closed (the risk model returned malformed answers)');
    });
  });
});
