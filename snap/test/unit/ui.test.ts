/**
 * @jest-environment node
 */
import { describe, expect, it } from '@jest/globals';
import { RootJSXElementStruct } from '@metamask/snaps-sdk/jsx';

import { decodePersonalSign, decodeTransaction } from '../../src/decode';
import type { BatchItem, CheckOutcome, Verdict } from '../../src/request';
import { categoryLabel, disclosureContent, feedHitLabel, renderInternalError, renderLocalOnly, renderOutcome, withFallback } from '../../src/ui';
import { BAYC, DRAINER, MAX_UINT256, RECIPIENT, SAFE, USDC, USER, ZERO, calldata, safeExec, textOf, utf8Hex } from '../helpers';

const approval = decodeTransaction({ from: USER, to: USDC, data: calldata('095ea7b3', DRAINER, MAX_UINT256) }, 'eip155:1');
const transfer = decodeTransaction({ from: USER, to: RECIPIENT, value: '0x1', data: '0x' }, 'eip155:1');
const ok = (verdict: Partial<Verdict>): CheckOutcome => ({
  kind: 'ok',
  verdict: { checked: true, categories: [], ...verdict },
});

function render(outcome: CheckOutcome, decoded = approval) {
  const result = renderOutcome(decoded, outcome, 'transaction', 'app.example.com');
  // Every rendered tree must be valid Snap JSX.
  expect(RootJSXElementStruct.is(result.content)).toBe(true);
  return { text: textOf(result.content), severity: result.severity };
}

describe('renderOutcome', () => {
  it('low tier: no-risk copy, heading with score and tier, checked role, no severity', () => {
    const { text, severity } = render(ok({ score: 7, tier: 'low', jws: 'a.b.c' }), transfer);
    expect(text).toContain('x402check · score 7/100 · low');
    expect(text).toContain('No significant risk signals found.');
    expect(text).toContain('Checked: recipient');
    expect(text).toContain('a.b.c');
    expect(severity).toBeUndefined();
  });

  it('missing or unknown tier is treated as medium, never as no-risk', () => {
    for (const verdict of [{ score: 2 }, { score: 2, tier: undefined }]) {
      const { text, severity } = render(ok(verdict));
      expect(text).toContain('x402check · score 2/100 · unknown tier');
      expect(text).toContain('Some risk signals present.');
      expect(text).not.toContain('No significant risk');
      expect(severity).toBeUndefined();
    }
    expect(render(ok({})).text).toContain('score ?/100');
  });

  it('high and critical tiers are critical severity', () => {
    expect(render(ok({ score: 80, tier: 'high' })).severity).toBe('critical');
    expect(render(ok({ score: 99, tier: 'critical' })).severity).toBe('critical');
    expect(render(ok({ score: 50, tier: 'medium' })).severity).toBeUndefined();
  });

  it('shows the spender, the UNLIMITED allowance and the requesting site', () => {
    const { text } = render(ok({ score: 30, tier: 'medium' }));
    expect(text).toContain('Checked: spender');
    expect(text).toContain(DRAINER);
    expect(text).toContain('Allowance');
    expect(text).toContain('UNLIMITED');
    expect(text).toContain('app.example.com');
  });

  it('sanctions listing overrides a low tier: loud banner and critical severity', () => {
    const { text, severity } = render(
      ok({
        score: 10,
        tier: 'low',
        evidence: { sanctions: { list: 'ofac-sdn', as_of: '2026-09-01', status: 'listed', entity: 'ACME MIXER' } },
      }),
    );
    expect(severity).toBe('critical');
    expect(text).toContain('OFAC-sanctioned address — do not proceed');
    expect(text).toContain('ACME MIXER is on the OFAC SDN sanctions list (list as of 2026-09-01)');
    expect(text).toContain('Critical risk detected.');
    expect(text).not.toContain('No significant risk');
  });

  it('threat-feed hits are loud and critical; clear feeds are summarized', () => {
    const { text, severity } = render(
      ok({
        score: 60,
        tier: 'medium',
        evidence: {
          feeds: [
            { source: 'metamask-phishing-detect', kind: 'domain', as_of: '2026-09-28', status: 'hit' },
            { source: 'scamsniffer-domains', status: 'hit' },
            { source: 'scamsniffer-addresses', status: 'clear' },
            { source: 'other-feed', status: 'unavailable' },
          ],
        },
      }),
    );
    expect(severity).toBe('critical');
    expect(text).toContain('Listed as malicious — do not proceed');
    expect(text).toContain('Listed on MetaMask phishing list');
    expect(text).toContain('Listed phishing domain (ScamSniffer)');
    expect(text).toContain('Threat feeds: 1 clear, 1 unavailable');
  });

  it('renders domain, on-chain facts, EOA spender warning and readable categories', () => {
    const { text } = render(
      ok({
        score: 88,
        tier: 'high',
        categories: ['approval_to_eoa', 'known_scam_address', 'drainer_kit'],
        evidence: {
          sanctions: { list: 'ofac-sdn', as_of: '2026-09-01', status: 'not_listed' },
          domain: {
            host: 'app.example.com',
            registrable: 'example.com',
            official: false,
            impersonation: 'weak',
            brand: 'Uniswap',
            signals: ['typo distance 1'],
          },
          onchain: { status: 'ok', activity: 'none', is_contract: false },
        },
      }),
    );
    expect(text).toContain('Not listed (list as of 2026-09-01)');
    expect(text).toContain('app.example.com: possible impersonation of Uniswap');
    expect(text).toContain('Site signals: typo distance 1');
    expect(text).toContain('New address: no on-chain activity found');
    expect(text).toContain('Spender is a regular wallet (EOA), not a contract — typical of drainers');
    expect(text).toContain('Approval to a regular wallet (EOA), Known scam address, Drainer kit');
  });

  it('does not show the EOA warning for plain transfers, and shows contracts', () => {
    const eoaTransfer = render(ok({ tier: 'low', evidence: { onchain: { status: 'ok', is_contract: false } } }), transfer);
    expect(eoaTransfer.text).not.toContain('regular wallet (EOA)');
    const operator = decodeTransaction({ from: USER, to: BAYC, data: calldata('a22cb465', DRAINER, 1n) });
    expect(render(ok({ tier: 'low', evidence: { onchain: { status: 'ok', is_contract: false } } }), operator).text).toContain(
      'Operator is a regular wallet (EOA)',
    );
    expect(render(ok({ tier: 'low', evidence: { onchain: { status: 'ok', is_contract: true } } })).text).toContain(
      'Counterparty is a contract',
    );
    expect(render(ok({ tier: 'low', evidence: { onchain: { status: 'unsupported' } } })).text).toContain(
      'On-chain check not supported on this network',
    );
  });

  it('distinguishes every failure mode, none of which is an all-clear', () => {
    const cases: [CheckOutcome, string][] = [
      [{ kind: 'network_error', timedOut: false }, 'x402check · unavailable — NOT verified'],
      [{ kind: 'network_error', timedOut: true }, 'could not be reached in time'],
      [{ kind: 'quota' }, 'x402check · free daily checks used up — this was NOT checked'],
      [{ kind: 'http_error', status: 503 }, 'x402check · check failed — NOT verified'],
      [{ kind: 'invalid_response' }, 'x402check · check failed — NOT verified'],
      [{ kind: 'unverified' }, 'x402check · verification failed — NOT verified'],
    ];
    for (const [outcome, expected] of cases) {
      const { text, severity } = render(outcome);
      expect(text).toContain(expected);
      expect(text).not.toContain('No significant risk');
      expect(text).toContain('Not checked: spender');
      expect(severity).toBeUndefined();
    }
  });
});

describe('other content', () => {
  it('local-only content for requests with no counterparty', () => {
    const deployment = decodeTransaction({ from: USER, data: '0x6080' });
    const { content } = renderLocalOnly(deployment, 'app.example.com');
    expect(RootJSXElementStruct.is(content)).toBe(true);
    expect(textOf(content)).toContain('x402check · not checked');
    expect(textOf(content)).toContain('Nothing was sent to x402check');
  });

  it('the disclosure lists what is sent, where, why, and what never leaves the wallet', () => {
    const content = disclosureContent();
    expect(RootJSXElementStruct.is(content)).toBe(true);
    const text = textOf(content);
    for (const expected of [
      'x402check.xyz',
      'the counterparty address',
      'the chain ID',
      'the requesting site',
      'human-readable summary',
      'Purpose:',
      'random install ID',
      'not derived from your Secret Recovery Phrase',
      'reset if you reinstall',
      'Your private keys and Secret Recovery Phrase never leave your wallet.',
    ]) {
      expect(text).toContain(expected);
    }
  });

  it('labels', () => {
    expect(categoryLabel('sanctioned_address')).toBe('Sanctioned address');
    expect(categoryLabel('mixer-interaction')).toBe('Mixer interaction');
    expect(categoryLabel('constructor')).toBe('Constructor');
    expect(feedHitLabel({ source: '__proto__', status: 'hit' })).toBe('Listed by __proto__');
    expect(feedHitLabel({ source: 'scamsniffer-addresses', status: 'hit' })).toBe('Known scam address (ScamSniffer)');
    expect(feedHitLabel({ source: 'chainabuse', kind: 'address', status: 'hit' })).toBe('Listed by chainabuse (address)');
  });
});

describe('batch verdicts (several addresses checked)', () => {
  const twoAddresses = decodePersonalSign(utf8Hex(`Claim for token ${USDC}, payout wallet ${DRAINER}`), USER);
  const good = (score: number, tier: Verdict['tier']): BatchItem => ({ status: 'ok', verdict: { checked: true, categories: [], score, tier } });
  const renderBatch = (items: BatchItem[]) => {
    const result = renderOutcome(twoAddresses, { kind: 'batch', items }, 'signature', 'app.example.com');
    expect(RootJSXElementStruct.is(result.content)).toBe(true);
    return { text: textOf(result.content), severity: result.severity };
  };

  it('shows the WORST verdict (highest tier, then lowest score) for its own address and lists the others', () => {
    const { text, severity } = renderBatch([good(92, 'low'), good(18, 'critical')]);
    expect(text).toContain('x402check · score 18/100 · critical');
    expect(text).toContain(`Checked: counterparty ${DRAINER}`);
    expect(text).toContain('Also checked: counterparty');
    expect(text).toContain('score 92/100 · low');
    expect(text).toContain('2 addresses were checked; the worst verdict is shown.');
    expect(severity).toBe('critical');
    // Same tier: the lower score is worse.
    expect(renderBatch([good(55, 'high'), good(35, 'high')]).text).toContain('score 35/100 · high');
  });

  it('fails closed when an address could not be verified and nothing else is alarming', () => {
    const { text, severity } = renderBatch([good(95, 'low'), { status: 'unverified' }]);
    expect(text).toContain('x402check · verification failed — NOT verified');
    expect(text).toContain('1 of 2 addresses');
    expect(text).not.toContain('No significant risk');
    expect(severity).toBeUndefined();
  });

  it('an alarming verdict still wins over an unverified one', () => {
    const { text, severity } = renderBatch([{ status: 'invalid' }, good(10, 'critical')]);
    expect(text).toContain('score 10/100 · critical');
    expect(text).toContain('NOT verified');
    expect(severity).toBe('critical');
  });
});

describe('locally proven danger', () => {
  const delegatecall = decodeTransaction({ from: USER, to: SAFE, data: safeExec(DRAINER, 0n, '0x12345678', 1) }, 'eip155:1');

  it('is loud and critical even when the server says low risk', () => {
    const result = renderOutcome(delegatecall, ok({ score: 95, tier: 'low' }), 'transaction', 'app.safe.global');
    const text = textOf(result.content);
    expect(text).toContain('Dangerous request — do not sign');
    expect(text).toContain(`DELEGATECALL to ${DRAINER}`);
    expect(text).toContain('Critical risk detected.');
    expect(text).not.toContain('No significant risk');
    expect(result.severity).toBe('critical');
  });

  it('local-only results with danger are critical too', () => {
    const burn = decodeTransaction({ from: USER, to: ZERO, value: '0x1', data: '0x' }, 'eip155:1');
    const result = renderLocalOnly(burn, 'app.example.com');
    expect(textOf(result.content)).toContain('the funds will be lost');
    expect(result.severity).toBe('critical');
  });

  it('failures keep the danger banner and critical severity', () => {
    const result = renderOutcome(delegatecall, { kind: 'network_error', timedOut: false }, 'transaction');
    expect(textOf(result.content)).toContain('Dangerous request — do not sign');
    expect(result.severity).toBe('critical');
  });
});

describe('internal errors', () => {
  it('withFallback turns any exception into the static failure insight (finding 8)', async () => {
    const result = await withFallback('transaction', async () => {
      throw new RangeError('Maximum call stack size exceeded');
    });
    expect(textOf(result.content)).toContain('x402check · check failed — NOT verified');
    expect(result.severity).toBe('critical');
    const passthrough = await withFallback('transaction', async () => renderLocalOnly(approval));
    expect(textOf(passthrough.content)).toContain('x402check · not checked');
  });

  it('render a static "check failed — NOT verified" insight with critical severity', () => {
    const result = renderInternalError('signature');
    expect(RootJSXElementStruct.is(result.content)).toBe(true);
    expect(textOf(result.content)).toContain('x402check · check failed — NOT verified');
    expect(result.severity).toBe('critical');
  });
});
