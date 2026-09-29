/**
 * @jest-environment node
 *
 * Transaction simulation (provider v0.3): what the Snap sends, how the
 * returned evidence is parsed, and how it is rendered.
 */
import { describe, expect, it } from '@jest/globals';
import { RootJSXElementStruct } from '@metamask/snaps-sdk/jsx';

import { decodeSignature, decodeTransaction } from '../../src/decode';
import type { CheckOutcome, RiskCheckBody } from '../../src/request';
import { buildRiskCheckBodies, parseVerdict } from '../../src/request';
import { FORWARDER_TEXT, MAX_SIMULATION_DATA_CHARS, codeMatchText, parseSimulation, simulationFindingLines } from '../../src/simulation';
import { DISCLOSURE_VERSION } from '../../src/state';
import { categoryLabel, disclosureContent, feedHitLabel, feedName, renderOutcome, unverifiedReason } from '../../src/ui';
import { BAYC, DRAINER, MAX_UINT256, PERMIT2, RECIPIENT, UNIVERSAL_ROUTER, USDC, USER, calldata, permitSingle, textOf, utf8Hex } from '../helpers';

const ORIGIN = 'https://app.example.com';
/** UI text with whitespace collapsed (fragments of one Text are joined with spaces). */
const flat = (node: unknown) => textOf(node).replace(/\s+/gu, ' ');
const APPROVE_MAX = calldata('095ea7b3', DRAINER, MAX_UINT256);

function bodiesFor(tx: Record<string, unknown>, chain: unknown = 'eip155:1'): RiskCheckBody[] {
  return buildRiskCheckBodies(decodeTransaction(tx, chain), ORIGIN);
}

/** The provider's validation rules for `transaction` (src/validate.ts). */
function providerAccepts(transaction: Record<string, unknown>): boolean {
  const keys = Object.keys(transaction);
  const evm = (value: unknown) => typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/u.test(value);
  if (keys.some((key) => !['from', 'to', 'value', 'data'].includes(key))) return false;
  if (!evm(transaction.from)) return false;
  if (transaction.to !== undefined && !evm(transaction.to)) return false;
  if (transaction.value !== undefined) {
    const { value } = transaction;
    if (typeof value !== 'string' || !/^(0x[0-9a-fA-F]{1,64}|\d{1,78})$/u.test(value) || BigInt(value) >= 2n ** 256n) return false;
  }
  if (transaction.data !== undefined) {
    const { data } = transaction;
    if (typeof data !== 'string' || !/^0x([0-9a-fA-F]{2})*$/u.test(data) || data.length > 48 * 1024) return false;
  }
  return true;
}

describe('the risk-check request carries the transaction to simulate', () => {
  it('eip155 transaction with `to`: from, to, value (0x-hex) and data are sent with the primary item', () => {
    const [body] = bodiesFor({ from: USER, to: USDC, value: '0x0', data: APPROVE_MAX });
    expect(body?.transaction).toStrictEqual({ from: USER, to: USDC, value: '0x0', data: APPROVE_MAX });
    expect(body?.chain).toBe('eip155:1');
    expect(body?.wallet).toBe(DRAINER);
  });

  it.each([
    ['decimal string', '1000000000000000000'],
    ['number', 1e18],
    ['hex with leading zeros', `0x${'0'.repeat(70)}de0b6b3a7640000`],
    ['uppercase hex', '0XDE0B6B3A7640000'],
    ['hex with whitespace', ' 0xde0b6b3a7640000 '],
  ])('value given as %s is normalized to minimal 0x-hex', (_label, value) => {
    const [body] = bodiesFor({ from: USER, to: RECIPIENT, value, data: '0x' });
    expect(body?.transaction?.value).toBe('0xde0b6b3a7640000');
  });

  it('a missing value is 0x0; addresses are lowercased; calldata is lowercase 0x-hex', () => {
    const [body] = bodiesFor({ from: USER.toUpperCase().replace('0X', '0x'), to: `0X${USDC.slice(2).toUpperCase()}`, data: APPROVE_MAX.toUpperCase().replace('0X', '0x') });
    expect(body?.transaction).toStrictEqual({ from: USER, to: USDC, value: '0x0', data: APPROVE_MAX });
  });

  it.each([['"0x"', '0x'], ['""', ''], ['undefined', undefined], ['null', null]])('data %s is omitted', (_label, data) => {
    const [body] = bodiesFor({ from: USER, to: RECIPIENT, value: '0x1', data });
    expect(body?.transaction).toStrictEqual({ from: USER, to: RECIPIENT, value: '0x1' });
  });

  it('uses `input` when `data` is missing', () => {
    const [body] = bodiesFor({ from: USER, to: USDC, input: APPROVE_MAX });
    expect(body?.transaction?.data).toBe(APPROVE_MAX);
  });

  it(`data of exactly ${MAX_SIMULATION_DATA_CHARS} characters is sent; one byte more is not, with a visible warning`, () => {
    const atLimit = `0xdeadbeef${'00'.repeat((MAX_SIMULATION_DATA_CHARS - 10) / 2)}`;
    expect(atLimit).toHaveLength(MAX_SIMULATION_DATA_CHARS);
    expect(bodiesFor({ from: USER, to: RECIPIENT, data: atLimit })[0]?.transaction?.data).toBe(atLimit);
    const decoded = decodeTransaction({ from: USER, to: RECIPIENT, data: `${atLimit}00` }, 'eip155:1');
    const [body] = buildRiskCheckBodies(decoded, ORIGIN);
    expect(body).toBeDefined();
    expect(body?.transaction).toBeUndefined();
    expect(decoded.warnings.join()).toContain('too large to simulate (24576 bytes of calldata; the limit is 24575 bytes)');
    expect(body?.context).toContain('too large to simulate');
    const ui = flat(renderOutcome(decoded, { kind: 'ok', verdict: { checked: true, categories: [], score: 90, tier: 'low' } }, 'transaction').content);
    expect(ui).toContain('Warnings from decoding this request');
    expect(ui).toContain('NOT simulated: The transaction is too large to simulate');
  });

  it.each([['a non-EVM chain', 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'], ['an unknown chain', undefined], ['chain id 0', 'eip155:0']])(
    'no transaction is sent on %s',
    (_label, chain) => {
      const decoded = decodeTransaction({ from: USER, to: RECIPIENT, value: '0x1', data: '0x' }, chain);
      const [body] = buildRiskCheckBodies(decoded, ORIGIN);
      expect(body?.transaction).toBeUndefined();
      expect(body?.chain).toBeUndefined();
      expect(decoded.simulationSkipped).toContain('only available for transactions on EVM (eip155) networks');
    },
  );

  it('deployments and special recipients send nothing at all', () => {
    expect(bodiesFor({ from: USER, data: '0x6080' })).toStrictEqual([]);
    expect(bodiesFor({ from: USER, to: '0x0000000000000000000000000000000000000000', value: '0x1' })).toStrictEqual([]);
  });

  it.each([
    ['sender is missing', { to: RECIPIENT, value: '0x1' }, 'sender address is missing or invalid'],
    ['value is not a number', { from: USER, to: RECIPIENT, value: '1e18' }, 'value could not be parsed'],
    ['calldata is not hex', { from: USER, to: RECIPIENT, data: '0xzz' }, 'calldata is not valid hex'],
  ])('when the %s, the transaction is not sent (the check still is), with a warning', (_label, tx, reason) => {
    const decoded = decodeTransaction(tx, 'eip155:1');
    const [body] = buildRiskCheckBodies(decoded, ORIGIN);
    expect(body).toBeDefined();
    expect(body?.transaction).toBeUndefined();
    expect(decoded.warnings.join()).toContain(reason);
  });

  it('a batch carries the transaction only on the primary item (simulated once)', () => {
    const bodies = bodiesFor({ from: USER, to: DRAINER, value: '0x4563918244f40000', data: calldata('095ea7b3', UNIVERSAL_ROUTER, 0n) });
    expect(bodies.map((body) => body.wallet)).toStrictEqual([DRAINER, UNIVERSAL_ROUTER]);
    expect(bodies[0]?.transaction).toStrictEqual({ from: USER, to: DRAINER, value: '0x4563918244f40000', data: calldata('095ea7b3', UNIVERSAL_ROUTER, 0n) });
    expect(bodies[1]?.transaction).toBeUndefined();
  });

  it('signatures never send a transaction', () => {
    for (const signature of [
      { from: USER, data: permitSingle(DRAINER), signatureMethod: 'eth_signTypedData_v4' },
      { from: USER, data: utf8Hex(`pay ${DRAINER} and ${RECIPIENT}`), signatureMethod: 'personal_sign' },
    ]) {
      for (const body of buildRiskCheckBodies(decodeSignature(signature), ORIGIN)) expect(body).not.toHaveProperty('transaction');
    }
  });

  it('every transaction the Snap sends passes the provider validation', () => {
    const values: unknown[] = [undefined, null, 0, 1, 1e18, 2 ** 60, '0x', '0x0', '0X1f', ' 12 ', '000123', `0x${'f'.repeat(64)}`, `0x${'0'.repeat(80)}1`, '-1', 'abc', 10n ** 30n];
    const datas: unknown[] = [undefined, null, '', '0x', '0X', APPROVE_MAX, APPROVE_MAX.slice(2), APPROVE_MAX.toUpperCase(), '0x123', '0xzz', `0x${'ab'.repeat(24_000)}`];
    const accounts: unknown[] = [USER, USER.toUpperCase(), `0X${USER.slice(2)}`, undefined, '0x1234', RECIPIENT];
    let sent = 0;
    for (const value of values) {
      for (const data of datas) {
        for (const from of accounts) {
          for (const body of bodiesFor({ from, to: RECIPIENT, value, data })) {
            if (!body.transaction) continue;
            sent += 1;
            expect({ transaction: body.transaction, accepted: providerAccepts(body.transaction) }).toStrictEqual({ transaction: body.transaction, accepted: true });
            expect(body.chain?.startsWith('eip155:')).toBe(true);
          }
        }
      }
    }
    expect(sent).toBeGreaterThan(100);
  });
});

describe('simulation evidence parsing', () => {
  it('keeps valid entries, drops malformed ones, accepts an empty inflow counterparty', () => {
    const parsed = parseSimulation({
      status: 'ok',
      network: 'eip155:1',
      outflows: [
        { standard: 'native', asset: 'native', amount: '1000000000000000000', counterparty: DRAINER, counterparty_is_contract: false },
        { standard: 'erc20', asset: 'not-an-address', amount: '1', counterparty: DRAINER },
        { standard: 'bogus', asset: USDC, counterparty: DRAINER },
      ],
      inflows: [{ standard: 'erc20', asset: USDC, amount: '5000000', counterparty: '' }],
      approvals: [
        { standard: 'erc721-all', asset: BAYC, spender: DRAINER },
        { standard: 'erc20', asset: USDC, spender: 'nope' },
      ],
      findings: ['approval_to_eoa', 'approval_to_eoa', 42, 'Bad Finding!'],
    });
    expect(parsed).toStrictEqual({
      status: 'ok',
      network: 'eip155:1',
      outflows: [{ standard: 'native', asset: 'native', amount: '1000000000000000000', counterparty: DRAINER, counterparty_is_contract: false }],
      inflows: [{ standard: 'erc20', asset: USDC, amount: '5000000', counterparty: '' }],
      approvals: [{ standard: 'erc721-all', asset: BAYC, spender: DRAINER, unlimited: true }],
      findings: ['approval_to_eoa'],
      code_matches: [],
      limits: [],
      dropped: 3,
    });
  });

  it('an unknown status means no simulation', () => {
    expect(parseSimulation({ status: 'maybe' })).toBeUndefined();
    const verdict = parseVerdict({ checked: true, evidence: { simulation: { status: 'maybe' } } });
    expect(verdict).toStrictEqual({ checked: true, categories: [] });
  });
});

describe('rendering the simulated effects', () => {
  const approve = decodeTransaction({ from: USER, to: USDC, value: '0x0', data: APPROVE_MAX }, 'eip155:1');
  const verdictWith = (simulation: unknown, tier: 'low' | 'medium' | 'high' | 'critical' = 'low', score = 90): CheckOutcome => {
    const verdict = parseVerdict({ checked: true, score, tier, categories: [], evidence: { simulation } });
    if (!verdict || verdict.checked === false) throw new Error('bad verdict');
    return { kind: 'ok', verdict };
  };
  const render = (outcome: CheckOutcome, decoded = approve, kind: 'transaction' | 'signature' = 'transaction') => {
    const result = renderOutcome(decoded, outcome, kind, 'app.example.com');
    expect(RootJSXElementStruct.is(result.content)).toBe(true);
    return { text: flat(result.content), severity: result.severity };
  };

  it('lists outflows, inflows and approvals with formatted amounts', () => {
    const { text } = render(
      verdictWith({
        status: 'ok',
        network: 'eip155:1',
        outflows: [
          { standard: 'native', asset: 'native', amount: '1500000000000000000', counterparty: DRAINER, counterparty_is_contract: false },
          { standard: 'erc20', asset: '0x1234567890123456789012345678901234567890', amount: '123', counterparty: RECIPIENT, counterparty_is_contract: true },
          { standard: 'erc721', asset: BAYC, token_id: '7', counterparty: DRAINER },
          { standard: 'erc1155', asset: BAYC, token_id: '9', amount: '3', counterparty: DRAINER },
        ],
        inflows: [{ standard: 'erc20', asset: USDC, amount: '5000000', counterparty: UNIVERSAL_ROUTER, counterparty_is_contract: true }],
        approvals: [
          { standard: 'erc20', asset: USDC, spender: DRAINER, amount: MAX_UINT256.toString(), unlimited: true, spender_is_contract: false },
          { standard: 'erc20', asset: USDC, spender: UNIVERSAL_ROUTER, amount: '2500000', spender_is_contract: true },
          { standard: 'erc721-all', asset: BAYC, spender: DRAINER, unlimited: true },
          { standard: 'erc721', asset: BAYC, spender: DRAINER, amount: '7' },
          { standard: 'permit2', asset: USDC, spender: DRAINER, unlimited: true },
        ],
        findings: [],
      }),
    );
    expect(text).toContain('What this transaction does (simulated)');
    expect(text).toContain('You send 1.5 ETH → 0x9d17bb…b277bc (wallet)');
    expect(text).toContain('You send 123 raw units of token 0x123456…567890 → 0xbf88b1…0e0178 (contract)');
    expect(text).toContain('You send NFT #7 of 0xbc4ca0…36f13d → 0x9d17bb…b277bc');
    expect(text).toContain('You send 3 × item #9 of 0xbc4ca0…36f13d');
    expect(text).toContain('You receive 5 USDC from 0x3fc91a…2b7fad (contract)');
    expect(text).toContain('Grants UNLIMITED USDC to 0x9d17bb…b277bc (wallet)');
    expect(text).toContain('Grants 2.5 USDC to 0x3fc91a…2b7fad (contract)');
    expect(text).toContain('Grants ALL NFTs of collection 0xbc4ca0…36f13d to 0x9d17bb…b277bc');
    expect(text).toContain('Grants NFT #7 of 0xbc4ca0…36f13d');
    expect(text).toContain('Grants UNLIMITED USDC via Permit2 to 0x9d17bb…b277bc');
    expect(PERMIT2).toHaveLength(42);
  });

  it('caps long lists with "and N more"', () => {
    const outflows = Array.from({ length: 7 }, (_, index) => ({ standard: 'native', asset: 'native', amount: `${index + 1}`, counterparty: DRAINER }));
    const { text } = render(verdictWith({ status: 'ok', outflows, inflows: [], approvals: [], findings: [] }));
    expect(text.match(/You send/gu)).toHaveLength(5);
    expect(text).toContain('and 2 more');
  });

  it('an ok simulation with no effects says so', () => {
    expect(render(verdictWith({ status: 'ok', outflows: [], inflows: [], approvals: [], findings: [] })).text).toContain(
      'No asset movements or approvals were detected in the simulation.',
    );
  });

  it.each(['outflow_to_undisclosed_eoa', 'approval_to_eoa'])('%s is a loud danger and forces critical severity', (finding) => {
    const { text, severity } = render(verdictWith({ status: 'ok', outflows: [], inflows: [], approvals: [], findings: [finding] }, 'low', 90));
    expect(text).toContain('Simulation: likely wallet drainer — do not proceed');
    expect(text).toContain(finding === 'approval_to_eoa' ? 'grants a spending approval to a regular wallet (EOA)' : 'regular wallet (EOA) that this request never mentioned');
    expect(text).toContain('Critical risk detected.');
    expect(text).not.toContain('No significant risk');
    expect(severity).toBe('critical');
  });

  it.each([
    ['outflow_to_unverified_contract', 'contract whose source code is not verified'],
    ['unlimited_approval', 'grants an UNLIMITED spending approval'],
    ['some_new_finding', 'Simulation finding: Some new finding.'],
  ])('%s is shown as a simulation warning', (finding, expected) => {
    const { text, severity } = render(verdictWith({ status: 'ok', outflows: [], inflows: [], approvals: [], findings: [finding] }, 'high', 45));
    expect(text).toContain('Simulation warnings');
    expect(text).toContain(expected);
    expect(severity).toBe('critical');
  });

  it('reverted: says the transaction would fail, without repeating it as a warning', () => {
    const { text } = render(verdictWith({ status: 'reverted', network: 'eip155:1', findings: ['simulation_reverted'] }, 'medium', 60));
    expect(text).toContain('This transaction would revert (fail) if sent as is.');
    expect(text).not.toContain('Simulation warnings');
  });

  it.each([
    ['unavailable', { status: 'unavailable', network: 'eip155:1' }, 'NOT simulated: the simulation service was unavailable'],
    ['unsupported', { status: 'unsupported', network: 'eip155:43114' }, 'NOT simulated: simulation is not available on eip155:43114'],
    ['missing (older provider)', undefined, 'NOT simulated: the risk service did not return a simulation'],
  ])('%s: explicitly NOT simulated, never an all-clear', (_label, simulation, expected) => {
    const { text } = render(verdictWith(simulation));
    expect(text).toContain(expected);
    expect(text).not.toContain('No asset movements');
  });

  it('failed checks state that the effects were NOT simulated', () => {
    for (const outcome of [{ kind: 'network_error', timedOut: false }, { kind: 'quota' }, { kind: 'unverified' }] as CheckOutcome[]) {
      expect(render(outcome).text).toContain('NOT simulated');
    }
  });

  it('signatures never show a simulation section', () => {
    const signature = decodeSignature({ from: USER, data: permitSingle(DRAINER), signatureMethod: 'eth_signTypedData_v4' });
    expect(render(verdictWith(undefined), signature, 'signature').text).not.toContain('simulated');
  });

  it('a batch shows the primary item simulation even when another address has the worst verdict', () => {
    const payable = decodeTransaction({ from: USER, to: DRAINER, value: '0x1', data: calldata('095ea7b3', UNIVERSAL_ROUTER, 0n) }, 'eip155:1');
    const simulated = parseVerdict({
      checked: true,
      score: 85,
      tier: 'low',
      evidence: { simulation: { status: 'ok', outflows: [{ standard: 'native', asset: 'native', amount: '1', counterparty: DRAINER }], inflows: [], approvals: [], findings: [] } },
    });
    const { text } = render(
      {
        kind: 'batch',
        items: [
          { status: 'ok', verdict: simulated as never },
          { status: 'ok', verdict: { checked: true, categories: [], score: 20, tier: 'critical' } },
        ],
      },
      payable,
    );
    expect(text).toContain('score 20/100 · critical');
    expect(text).toContain('You send 0.000000000000000001 ETH → 0x9d17bb…b277bc');
  });
});

describe('privacy disclosure', () => {
  it('says the full transaction is sent, simulated on a public RPC node, with Blockscout lookups; version bumped', () => {
    const text = textOf(disclosureContent());
    expect(text).toContain('the full transaction (from, to, value and calldata)');
    expect(text).toContain('simulates it on a public RPC node of that chain');
    expect(text).toContain('Blockscout');
    expect(text).toContain('Signatures are never simulated');
    expect(DISCLOSURE_VERSION).toBe(2);
  });
});

describe('drainer-kit code fingerprints (provider v0.3.1)', () => {
  const approve = decodeTransaction({ from: USER, to: USDC, value: '0x0', data: APPROVE_MAX }, 'eip155:1');
  const outcome = (evidence: Record<string, unknown>, tier = 'low', score = 90): CheckOutcome => {
    const verdict = parseVerdict({ checked: true, score, tier, categories: [], evidence });
    if (!verdict || verdict.checked === false) throw new Error('bad verdict');
    return { kind: 'ok', verdict };
  };
  const render = (value: CheckOutcome) => {
    const result = renderOutcome(approve, value, 'transaction', 'app.example.com');
    expect(RootJSXElementStruct.is(result.content)).toBe(true);
    return { text: flat(result.content), severity: result.severity };
  };

  it('the size limit matches the provider cap (48 KiB of hex characters)', () => {
    expect(MAX_SIMULATION_DATA_CHARS).toBe(49_152);
  });

  it('parses code_matches, dropping malformed entries and unknown source ids', () => {
    const parsed = parseSimulation({
      status: 'ok',
      findings: ['known_drainer_code'],
      code_matches: [
        { address: DRAINER, role: 'called', sources: ['forta-phishing-code', 'scamsniffer-code', 'Bad Source!', 7] },
        { address: 'nope', role: 'called', sources: [] },
        { address: DRAINER, role: 'owner', sources: [] },
      ],
    });
    expect(parsed?.code_matches).toStrictEqual([{ address: DRAINER, role: 'called', sources: ['forta-phishing-code', 'scamsniffer-code'] }]);
    expect(parsed?.dropped).toBe(2);
  });

  it.each([
    ['called', 'The contract you are calling (0x9d17bb…b277bc) runs the same code as contracts listed as wallet drainers'],
    ['recipient', 'Assets go to a contract (0x9d17bb…b277bc) that runs the same code as listed wallet drainers'],
    ['spender', 'The approval goes to a contract (0x9d17bb…b277bc) that runs the same code as listed wallet drainers'],
  ])('known_drainer_code on the %s contract is a loud, critical drainer banner', (role, expected) => {
    const { text, severity } = render(
      outcome({
        simulation: {
          status: 'ok',
          outflows: [],
          inflows: [],
          approvals: [],
          findings: ['known_drainer_code'],
          code_matches: [{ address: DRAINER, role, sources: ['forta-phishing-code'] }],
        },
      }),
    );
    expect(text).toContain('Simulation: likely wallet drainer — do not proceed');
    expect(text).toContain(`${expected} (listed by Forta).`);
    expect(text).toContain('Critical risk detected.');
    expect(severity).toBe('critical');
  });

  it('a reverted simulation with drainer code shows both the revert line and the banner', () => {
    const { text, severity } = render(
      outcome(
        {
          simulation: {
            status: 'reverted',
            network: 'eip155:1',
            findings: ['simulation_reverted', 'known_drainer_code'],
            code_matches: [{ address: DRAINER, role: 'called', sources: ['scamsniffer-code', 'forta-phishing-code'] }],
          },
        },
        'medium',
        60,
      ),
    );
    expect(text).toContain('This transaction would revert (fail) if sent as is.');
    expect(text).toContain('The contract you are calling (0x9d17bb…b277bc) runs the same code as contracts listed as wallet drainers (listed by ScamSniffer and Forta).');
    expect(text).not.toContain('Simulation warnings');
    expect(severity).toBe('critical');
    expect(codeMatchText({ address: DRAINER, role: 'called', sources: [] })).not.toContain('listed by');
  });

  it('known_drainer_code without details still gets the generic drainer line', () => {
    const { text } = render(outcome({ simulation: { status: 'ok', findings: ['known_drainer_code'] } }));
    expect(text).toContain('A contract in this transaction runs the same code as contracts listed as wallet drainers.');
  });

  it('code feeds have readable labels; a hit on the checked address is loud and critical', () => {
    expect(feedName('forta-phishing-code')).toBe('Forta drainer code fingerprints');
    expect(feedName('scamsniffer-code')).toBe('ScamSniffer drainer code fingerprints');
    expect(feedHitLabel({ source: 'scamsniffer-code', kind: 'code', status: 'hit' })).toBe(
      'Runs known wallet-drainer code (ScamSniffer drainer code fingerprints)',
    );
    const hit = render(
      outcome({
        feeds: [
          { source: 'forta-phishing-code', kind: 'code', as_of: '2026-09-28', status: 'hit' },
          { source: 'scamsniffer-code', kind: 'code', as_of: '', status: 'unavailable' },
          { source: 'scamsniffer-addresses', kind: 'address', as_of: '2026-09-28', status: 'clear' },
        ],
      }),
    );
    expect(hit.text).toContain('Listed as malicious — do not proceed');
    expect(hit.text).toContain('Runs known wallet-drainer code (Forta drainer code fingerprints) (as of 2026-09-28)');
    expect(hit.text).toContain('Threat feeds: 1 clear, 1 unavailable (clear: ScamSniffer scam addresses; unavailable: ScamSniffer drainer code fingerprints)');
    expect(hit.severity).toBe('critical');
    const clear = render(outcome({ feeds: [{ source: 'forta-phishing-code', kind: 'code', as_of: '2026-09-28', status: 'clear' }] }));
    expect(clear.text).toContain('clear: Forta drainer code fingerprints');
    expect(clear.severity).toBeUndefined();
  });

  it('an EIP-7702 delegated account shows its delegate; other code kinds add no line', () => {
    const delegated = render(
      outcome({ onchain: { status: 'ok', is_contract: false, activity: 'some', code: { kind: 'delegated', bytes: 23, delegate: RECIPIENT } } }),
    );
    expect(delegated.text).toContain('Account EIP-7702 delegated account → 0xbf88b1…0e0178');
    for (const code of [{ kind: 'logic', bytes: 5000, fingerprint: `0x${'ab'.repeat(32)}` }, { kind: 'delegated', bytes: 23 }, { kind: 'weird', bytes: 1 }]) {
      expect(render(outcome({ onchain: { status: 'ok', code } })).text).not.toContain('EIP-7702');
    }
    const verdict = parseVerdict({ checked: true, evidence: { onchain: { status: 'ok', code: { kind: 'logic', bytes: -1 } } } });
    expect(verdict).toStrictEqual({ checked: true, categories: [], evidence: { onchain: { status: 'ok' } } });
  });
});

describe('provider review follow-up: payee scoping, incomplete results, forwarders, reasons', () => {
  const transfer = decodeTransaction({ from: USER, to: USDC, data: calldata('a9059cbb', RECIPIENT, 5_000_000n) }, 'eip155:1');
  const outcome = (evidence: Record<string, unknown>, tier = 'low', score = 90, categories: string[] = []): CheckOutcome => {
    const verdict = parseVerdict({ checked: true, score, tier, categories, evidence });
    if (!verdict || verdict.checked === false) throw new Error('bad verdict');
    return { kind: 'ok', verdict };
  };
  const render = (value: CheckOutcome, decoded = transfer) => {
    const result = renderOutcome(decoded, value, 'transaction', 'app.example.com');
    expect(RootJSXElementStruct.is(result.content)).toBe(true);
    return { text: flat(result.content), severity: result.severity };
  };
  const sim = (extra: Record<string, unknown>) => ({ status: 'ok', outflows: [], inflows: [], approvals: [], findings: [], ...extra });

  it('outflow_exceeds_declared is a critical drainer banner', () => {
    const { text, severity } = render(outcome({ simulation: sim({ findings: ['outflow_exceeds_declared'] }) }));
    expect(text).toContain('Simulation: likely wallet drainer — do not proceed');
    expect(text).toContain('The recipient you are paying receives a different asset or a larger amount than this transaction shows.');
    expect(severity).toBe('critical');
  });

  it('simulation_incomplete is a caution with its limits, and never an all-clear', () => {
    const value = outcome({ simulation: sim({ findings: ['simulation_incomplete'], limits: ['unclassified', 'logs_truncated'] }) });
    const { text, severity } = render(value);
    expect(text).toContain('Simulation warnings');
    expect(text).toContain(
      'The simulation could not check every recipient; treat this transaction as not fully verified. (some recipients or spenders could not be classified; the transaction emits more events than could be inspected)',
    );
    expect(text).toContain('Not fully verified: part of this check could not be completed.');
    expect(text).toContain('Some risk signals present.');
    expect(text).not.toContain('No significant risk');
    expect(text).not.toContain('No asset movements or approvals were detected');
    expect(text).toContain('The simulation was incomplete');
    expect(severity).toBeUndefined();
    expect(parseSimulation(sim({ limits: ['flows_truncated', 'flows_truncated', 'Bad!'] }))?.limits).toStrictEqual(['flows_truncated']);
  });

  it('outflow_to_undisclosed_eoa through a VERIFIED forwarder is a caution, not the drainer banner', () => {
    const forwarded = render(outcome({ simulation: sim({ findings: ['outflow_to_undisclosed_eoa'], forwarder_verified: true }) }, 'medium', 65));
    expect(forwarded.text).toContain(FORWARDER_TEXT);
    expect(forwarded.text).toContain('Simulation warnings');
    expect(forwarded.text).not.toContain('likely wallet drainer');
    expect(forwarded.severity).toBeUndefined();
    const unverified = render(outcome({ simulation: sim({ findings: ['outflow_to_undisclosed_eoa'], forwarder_verified: false }) }, 'medium', 65));
    expect(unverified.text).toContain('likely wallet drainer');
    expect(unverified.severity).toBe('critical');
    expect(simulationFindingLines(parseSimulation(sim({ findings: ['outflow_to_undisclosed_eoa'], forwarder_verified: true })) as never)).toStrictEqual([
      { strong: false, text: FORWARDER_TEXT },
    ]);
  });

  it('onchain_unavailable and simulation_unavailable read as not fully verified', () => {
    expect(categoryLabel('onchain_unavailable')).toBe('Spender could not be classified (on-chain lookup failed) — not fully verified');
    expect(categoryLabel('simulation_unavailable')).toBe('Transaction simulation failed — not fully verified');
    for (const category of ['onchain_unavailable', 'simulation_unavailable']) {
      const { text } = render(outcome({}, 'low', 85, [category]));
      expect(text).toContain('Not fully verified');
      expect(text).toContain('Some risk signals present.');
      expect(text).not.toContain('No significant risk');
    }
  });

  it('in a batch, one address that was not fully verified makes the whole check not fully verified', () => {
    const approve = decodeTransaction({ from: USER, to: DRAINER, value: '0x1', data: calldata('095ea7b3', UNIVERSAL_ROUTER, 0n) }, 'eip155:1');
    const { text, severity } = render(
      {
        kind: 'batch',
        items: [
          { status: 'ok', verdict: { checked: true, categories: ['onchain_unavailable'], score: 95, tier: 'low' } },
          { status: 'ok', verdict: { checked: true, categories: [], score: 90, tier: 'low' } },
        ],
      },
      approve,
    );
    expect(text).toContain('score 90/100 · low');
    expect(text).toContain('score 95/100 · low · not fully verified');
    expect(text).toContain('Not fully verified: part of this check could not be completed.');
    expect(text).not.toContain('No significant risk');
    expect(severity).toBeUndefined();
  });

  it('checked:false shows the provider reason in the NOT verified message', () => {
    expect(parseVerdict({ checked: false, reason: 'model_unavailable' })).toStrictEqual({ checked: false, reason: 'model_unavailable' });
    expect(parseVerdict({ checked: false, reason: 'Bad Reason!' })).toStrictEqual({ checked: false });
    expect(unverifiedReason('invalid_subject')).toBe('the checked address was rejected as invalid');
    expect(unverifiedReason('model_unconfigured')).toBe('the risk model is not configured');
    expect(unverifiedReason('model_malformed_answers')).toBe('the risk model returned malformed answers');
    expect(unverifiedReason('brand_new_reason')).toBe('brand new reason');
    const { text } = render({ kind: 'unverified', reason: 'model_unavailable' });
    expect(text).toContain('failed closed (the risk model was unavailable). This transaction was NOT verified.');
    const batch = render(
      { kind: 'batch', items: [{ status: 'ok', verdict: { checked: true, categories: [], score: 90, tier: 'low' } }, { status: 'unverified', reason: 'invalid_subject' }] },
      decodeTransaction({ from: USER, to: DRAINER, value: '0x1', data: calldata('095ea7b3', UNIVERSAL_ROUTER, 0n) }, 'eip155:1'),
    );
    expect(batch.text).toContain('NOT verified (the checked address was rejected as invalid)');
  });

  it('Arbitrum transactions are sent for simulation like any EVM chain', () => {
    const [body] = bodiesFor({ from: USER, to: RECIPIENT, value: '0x1', data: '0x' }, 'eip155:42161');
    expect(body?.transaction).toStrictEqual({ from: USER, to: RECIPIENT, value: '0x1' });
    expect(body?.chain).toBe('eip155:42161');
  });

  it('transfers keep sending the decoded payee asset and amount next to the transaction', () => {
    const [erc20] = buildRiskCheckBodies(transfer, ORIGIN);
    expect(erc20?.payment).toStrictEqual({ network: 'eip155:1', pay_to: RECIPIENT, amount: '5000000', asset: USDC });
    expect(erc20?.transaction?.data).toBe(calldata('a9059cbb', RECIPIENT, 5_000_000n));
    const [native] = bodiesFor({ from: USER, to: RECIPIENT, value: '0xde0b6b3a7640000', data: '0x' });
    expect(native?.payment).toStrictEqual({ network: 'eip155:1', pay_to: RECIPIENT, amount: '1000000000000000000', asset: 'native' });
    expect(native?.transaction).toStrictEqual({ from: USER, to: RECIPIENT, value: '0xde0b6b3a7640000' });
  });
});
