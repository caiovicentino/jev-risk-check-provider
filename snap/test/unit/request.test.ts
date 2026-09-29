/**
 * @jest-environment node
 */
import { describe, expect, it } from '@jest/globals';

import { decodePersonalSign, decodeTransaction, decodeTypedData } from '../../src/decode';
import {
  BATCH_ENDPOINT,
  ENDPOINT,
  MAX_CONTEXT,
  buildRiskCheckBodies,
  buildRiskCheckBody,
  classifyBatchResponse,
  classifyResponse,
  composeContext,
  originHost,
  parseVerdict,
  postRiskCheck,
  postRiskChecks,
} from '../../src/request';
import { DRAINER, MAX_UINT256, RECIPIENT, REACTOR, USDC, USER, calldata, permitSingle, uniswapXOrder, utf8Hex } from '../helpers';
import { decodeTypedData as decodeTyped } from '../../src/decode';

const ALLOWED_KEYS = ['chain', 'context', 'domain', 'interaction', 'payment', 'transaction', 'wallet'];

describe('originHost', () => {
  it('returns the hostname of web origins only', () => {
    expect(originHost('https://App.Uniswap.org')).toBe('app.uniswap.org');
    expect(originHost('https://app.uniswap.org:8443/path?q=1')).toBe('app.uniswap.org');
    expect(originHost('app.uniswap.org')).toBe('app.uniswap.org');
    expect(originHost('example.com.')).toBe('example.com');
    expect(originHost('metamask')).toBeUndefined();
    expect(originHost('npm:@scope/snap')).toBeUndefined();
    expect(originHost('http://localhost:3000')).toBeUndefined();
    expect(originHost('https://evil.com /x')).toBeUndefined();
    expect(originHost(undefined)).toBeUndefined();
  });
});

describe('buildRiskCheckBody', () => {
  it('sends exactly the contract fields, with interaction limited to type/unlimited', () => {
    const decoded = decodeTransaction({ from: USER, to: USDC, data: calldata('095ea7b3', DRAINER, MAX_UINT256) }, 'eip155:1');
    const body = buildRiskCheckBody(decoded, 'https://app.example.com');
    expect(body).toStrictEqual({
      wallet: DRAINER,
      chain: 'eip155:1',
      domain: 'app.example.com',
      context: expect.any(String),
      payment: { network: 'eip155:1', pay_to: DRAINER, amount: MAX_UINT256.toString(), asset: USDC },
      interaction: { type: 'token_approval', unlimited: true },
      transaction: { from: USER, to: USDC, value: '0x0', data: calldata('095ea7b3', DRAINER, MAX_UINT256) },
    });
    expect(Object.keys(body ?? {}).every((key) => ALLOWED_KEYS.includes(key))).toBe(true);
    expect(Object.keys(body?.interaction ?? {}).sort()).toStrictEqual(['type', 'unlimited']);
    expect(body?.context).toContain('Requested by app.example.com.');
    // Human-readable only: no calldata words or selector blobs.
    expect(body?.context).not.toMatch(/[0-9a-f]{64}/u);
  });

  it('omits chain, domain and payment when unknown', () => {
    const decoded = decodePersonalSign(utf8Hex('Hello there'), USER);
    const body = buildRiskCheckBody(decoded, 'metamask');
    expect(body).toStrictEqual({
      wallet: USER,
      context: expect.stringContaining('No counterparty address in message; subject is the signer.'),
      interaction: { type: 'message_signature' },
    });
  });

  it('uses a host named in the message when there is no web origin', () => {
    const decoded = decodePersonalSign(utf8Hex('Verify at https://jup1ter-audit.click/x'), USER);
    expect(buildRiskCheckBody(decoded, undefined)?.domain).toBe('jup1ter-audit.click');
    expect(buildRiskCheckBody(decoded, 'https://airdrop.example.com')?.domain).toBe('airdrop.example.com');
  });

  it('produces different bodies for a legit and a drainer Permit2 from the same site', () => {
    const origin = 'https://app.example.com';
    const legit = buildRiskCheckBody(decodeTypedData(permitSingle('0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad'), USER), origin);
    const drainer = buildRiskCheckBody(decodeTypedData(permitSingle(DRAINER), USER), origin);
    expect(legit?.wallet).toBe('0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad');
    expect(drainer?.wallet).toBe(DRAINER);
    expect(legit).not.toStrictEqual(drainer);
  });

  it('returns undefined when there is nothing to check', () => {
    expect(buildRiskCheckBody(decodeTransaction({ from: USER, data: '0x6080' }), 'https://x.example.com')).toBeUndefined();
  });

  it('caps the context at 700 characters', () => {
    const decoded = decodeTransaction({ from: USER, to: RECIPIENT, data: '0x' });
    const context = composeContext({ ...decoded, summary: 'x'.repeat(2000) }, 'site.example.com');
    expect(context.length).toBe(MAX_CONTEXT);
    expect(context.endsWith('…')).toBe(true);
  });
});

describe('response handling', () => {
  it('classifies statuses and bodies', () => {
    expect(classifyResponse(402, undefined)).toStrictEqual({ kind: 'payment_required' });
    // A 402 is never read as a verdict, whatever its body says.
    expect(classifyResponse(402, { checked: true, score: 99, tier: 'low' })).toStrictEqual({ kind: 'payment_required' });
    expect(classifyResponse(500, undefined)).toStrictEqual({ kind: 'http_error', status: 500 });
    expect(classifyResponse(422, { error: 'invalid_request' })).toStrictEqual({ kind: 'http_error', status: 422 });
    expect(classifyResponse(200, undefined)).toStrictEqual({ kind: 'invalid_response' });
    expect(classifyResponse(200, { score: 3 })).toStrictEqual({ kind: 'invalid_response' });
    expect(classifyResponse(200, { checked: false, score: 1, tier: 'low' })).toStrictEqual({ kind: 'unverified' });
    expect(classifyResponse(200, { checked: false, reason: 'invalid_subject' })).toStrictEqual({ kind: 'unverified', reason: 'invalid_subject' });
    expect(classifyBatchResponse(200, { results: [{ checked: false, reason: 'model_unavailable' }] }, 1)).toStrictEqual({
      kind: 'batch',
      items: [{ status: 'unverified', reason: 'model_unavailable' }],
    });
    expect(classifyResponse(200, { checked: true, score: 10, tier: 'low' })).toStrictEqual({
      kind: 'ok',
      verdict: { checked: true, score: 10, tier: 'low', categories: [] },
    });
  });

  it('sanitizes the verdict', () => {
    const verdict = parseVerdict({
      checked: true,
      score: 140.6,
      tier: 'pristine',
      categories: ['known_scam_address', 42, ''],
      jws: 'not a jws',
      jwks_url: 'http://insecure.example/jwks',
      provider: 'x402check',
      extra: 'ignored',
      evidence: {
        sanctions: { list: 'ofac-sdn', as_of: '2026-09-01', status: 'listed', entity: 'SOME ENTITY' },
        domain: { host: 'uniswap-claim.xyz', registrable: 'uniswap-claim.xyz', official: false, impersonation: 'strong', brand: 'Uniswap', signals: ['lookalike', 7] },
        onchain: { status: 'ok', is_contract: false, activity: 'none', tx_count: 0 },
        feeds: [
          { source: 'scamsniffer-addresses', kind: 'address', as_of: '2026-09-28', status: 'hit' },
          { source: 'bogus', status: 'maybe' },
        ],
      },
    });
    expect(verdict).toStrictEqual({
      checked: true,
      score: 100,
      categories: ['known_scam_address'],
      provider: 'x402check',
      evidence: {
        sanctions: { list: 'ofac-sdn', as_of: '2026-09-01', status: 'listed', entity: 'SOME ENTITY' },
        domain: {
          host: 'uniswap-claim.xyz',
          registrable: 'uniswap-claim.xyz',
          official: false,
          impersonation: 'strong',
          brand: 'Uniswap',
          signals: ['lookalike'],
        },
        onchain: { status: 'ok', is_contract: false, activity: 'none', tx_count: 0 },
        feeds: [{ source: 'scamsniffer-addresses', kind: 'address', as_of: '2026-09-28', status: 'hit' }],
      },
    });
  });
});

describe('postRiskCheck', () => {
  const body = { wallet: RECIPIENT, context: 'test', interaction: { type: 'native_transfer' as const } };

  it('POSTs JSON with only a Content-Type header (no client or install id)', async () => {
    const calls: { url: string; init: { method: string; headers: Record<string, string>; body: string } }[] = [];
    const outcome = await postRiskCheck(body, async (url, init) => {
      calls.push({ url, init });
      return { status: 200, json: async () => ({ checked: true, score: 5, tier: 'low' }) };
    });
    expect(outcome.kind).toBe('ok');
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(ENDPOINT);
    expect(calls[0]?.init.method).toBe('POST');
    expect(calls[0]?.init.headers).toStrictEqual({ 'Content-Type': 'application/json' });
    expect(JSON.parse(calls[0]?.init.body ?? '')).toStrictEqual(body);
  });

  it('maps thrown errors and timeouts to network_error', async () => {
    expect(
      await postRiskCheck(body, async () => {
        throw new TypeError('fetch failed');
      }),
    ).toStrictEqual({ kind: 'network_error', timedOut: false });
    const hanging = await postRiskCheck(
      body,
      async (_url, init) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => reject(new Error('aborted')));
        }),
      20,
    );
    expect(hanging).toStrictEqual({ kind: 'network_error', timedOut: true });
  });

  it('maps HTTP 402 (x402 payment required) to payment_required without reading the body, single and batch', async () => {
    let bodyRead = false;
    const paymentRequired = async () => ({
      status: 402,
      json: async () => {
        bodyRead = true;
        return { checked: true, score: 99, tier: 'low' };
      },
    });
    expect(await postRiskCheck(body, paymentRequired)).toStrictEqual({ kind: 'payment_required' });
    expect(await postRiskChecks([body, { ...body, wallet: USER }], paymentRequired)).toStrictEqual({ kind: 'payment_required' });
    expect(bodyRead).toBe(false);
  });

  it('treats an unparseable 200 body as invalid', async () => {
    const outcome = await postRiskCheck(body, async () => ({
      status: 200,
      json: async () => {
        throw new SyntaxError('bad json');
      },
    }));
    expect(outcome).toStrictEqual({ kind: 'invalid_response' });
  });
});

describe('batch checks (several addresses)', () => {
  const decoded = decodeTyped(uniswapXOrder([{ token: USDC, amount: '9999000000', recipient: DRAINER }]), USER);
  const bodies = buildRiskCheckBodies(decoded, 'https://app.uniswap.org');

  it('builds one body per address with its own interaction, payment and a checked-address sentence', () => {
    expect(bodies.map((body) => body.wallet)).toStrictEqual([DRAINER, REACTOR]);
    expect(bodies[0]?.interaction).toStrictEqual({ type: 'token_transfer' });
    expect(bodies[0]?.payment).toStrictEqual({ network: 'eip155:1', pay_to: DRAINER, amount: '9999000000', asset: USDC });
    expect(bodies[1]?.interaction).toStrictEqual({ type: 'permit_signature' });
    expect(bodies[0]?.context).toMatch(new RegExp(`Checked address: recipient ${DRAINER} \\(receives an order output`, 'u'));
    for (const body of bodies) {
      expect(body.context.length).toBeLessThanOrEqual(MAX_CONTEXT);
      expect(Object.keys(body).every((key) => ALLOWED_KEYS.includes(key))).toBe(true);
    }
  });

  it('keeps the checked-address sentence when the summary is huge', () => {
    const long = composeContext({ ...decoded, summary: 'x'.repeat(5000) }, 'app.uniswap.org', decoded.others[0]);
    expect(long.length).toBeLessThanOrEqual(MAX_CONTEXT);
    expect(long).toContain(`Checked address: spender ${REACTOR}`);
  });

  it('POSTs {requests} to the batch endpoint and maps results in order', async () => {
    const calls: { url: string; body: string }[] = [];
    const outcome = await postRiskChecks(bodies, async (url, init) => {
      calls.push({ url, body: init.body });
      expect(init.headers).toStrictEqual({ 'Content-Type': 'application/json' });
      return {
        status: 200,
        json: async () => ({ results: [{ checked: true, score: 10, tier: 'critical' }, { checked: false }] }),
      };
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe(BATCH_ENDPOINT);
    expect(JSON.parse(calls[0]?.body ?? '')).toStrictEqual({ requests: bodies });
    expect(outcome).toStrictEqual({
      kind: 'batch',
      items: [{ status: 'ok', verdict: { checked: true, score: 10, tier: 'critical', categories: [] } }, { status: 'unverified' }],
    });
  });

  it('a single address still uses the single endpoint', async () => {
    const urls: string[] = [];
    await postRiskChecks([bodies[0] as never], async (url) => {
      urls.push(url);
      return { status: 200, json: async () => ({ checked: true }) };
    });
    expect(urls).toStrictEqual([ENDPOINT]);
  });

  it('validates the batch response shape and statuses', () => {
    expect(classifyBatchResponse(200, { results: [{ checked: true }] }, 2)).toStrictEqual({ kind: 'invalid_response' });
    expect(classifyBatchResponse(200, { nope: [] }, 1)).toStrictEqual({ kind: 'invalid_response' });
    expect(classifyBatchResponse(200, { results: [42] }, 1)).toStrictEqual({ kind: 'batch', items: [{ status: 'invalid' }] });
    expect(classifyBatchResponse(402, undefined, 2)).toStrictEqual({ kind: 'payment_required' });
    expect(classifyBatchResponse(413, undefined, 2)).toStrictEqual({ kind: 'http_error', status: 413 });
    expect(classifyBatchResponse(422, { error: 'invalid_request', field: 'wallet', index: 1 }, 2)).toStrictEqual({
      kind: 'http_error',
      status: 422,
    });
  });
});
