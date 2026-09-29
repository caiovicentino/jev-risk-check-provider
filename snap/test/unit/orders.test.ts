/**
 * @jest-environment node
 *
 * Regression tests for review findings 4 and 5 (probe p3): marketplace
 * listing drainers and UniswapX outputs. Every fixture declares its real
 * EIP-712 types and is proven signable with eth-sig-util first.
 */
import { describe, expect, it } from '@jest/globals';

import { decodeSignature, decodeTypedData } from '../../src/decode';
import { buildRiskCheckBodies } from '../../src/request';
import {
  BAYC,
  BLUR_EXCHANGE,
  DRAINER,
  EMPTY_ORDER,
  LOOKSRARE,
  OPENSEA_FEE,
  REACTOR,
  SEAPORT,
  USDC,
  USER,
  WETH,
  ZERO,
  blurOrder,
  blurRoot,
  eip712Hash,
  erc20Item,
  eth,
  looksRareMaker,
  nft,
  orderComponents,
  seaportBulkOrder,
  seaportOrder,
  uniswapXOrder,
} from '../helpers';

const NFTS = [nft(BAYC, '1'), nft(BAYC, '2')];

function decode(data: unknown) {
  expect(() => eip712Hash(data)).not.toThrow();
  return decodeTypedData(data, USER);
}

describe('Seaport', () => {
  it('classic drainer: offerer receives nothing, the attacker recipient is checked', () => {
    const decoded = decode(seaportOrder(NFTS, [eth('1', DRAINER)]));
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.interaction).toStrictEqual({ type: 'order_signature' });
    expect(decoded.danger).toContain('the offerer receives NOTHING in return for the offered items');
  });

  it('dust in ANY item type: 1 base unit of WETH to the offerer is flagged', () => {
    const decoded = decode(seaportOrder(NFTS, [erc20Item(WETH, '1', USER)]));
    expect(decoded.danger.join()).toContain('the offerer receives only 0.000000000000000001 WETH');
    expect(decoded.counterparty).toBe(SEAPORT);
    expect(decoded.role).toBe('contract');
  });

  it('uses min(startAmount, endAmount): a price decaying to 1 wei is dust', () => {
    const decoded = decode(
      seaportOrder(NFTS, [eth('100000000000000000000', USER, '1')], USER, { startTime: '1700000000', endTime: '1759150000' }),
    );
    expect(decoded.danger.join()).toContain('0.000000000000000001 ETH (1 wei) (at the lowest point of the price)');
    expect(decoded.warnings.join()).toContain('the price changes over time: from 100 ETH');
  });

  it('never picks the zero address as the counterparty', () => {
    const decoded = decode(seaportOrder(NFTS, [eth('2', ZERO), eth('1', DRAINER)]));
    expect(decoded.counterparty).toBe(DRAINER);
    expect([decoded.counterparty, ...decoded.others.map((other) => other.address)]).not.toContain(ZERO);
    expect(decoded.warnings.join()).toContain('zero/burn address');
  });

  it('decodes a BulkOrder tree through the Seaport analysis', () => {
    const decoded = decode(seaportBulkOrder([orderComponents(NFTS, [eth('1', USER)])]));
    expect(decoded.action).toBe('Seaport bulk listing');
    expect(decoded.interaction).toStrictEqual({ type: 'order_signature' });
    expect(decoded.danger.join()).toContain('typical of NFT drainer listings');
    expect(decoded.summary).toContain('covering 1 order(s)');
  });

  it('BulkOrder: every non-empty leaf is analysed and its recipients checked (batch)', () => {
    const decoded = decode(
      seaportBulkOrder([orderComponents([nft(BAYC, '1')], [eth('9', USER), eth('1', OPENSEA_FEE)]), EMPTY_ORDER, orderComponents([nft(BAYC, '2')], [eth('1', DRAINER)])]),
    );
    expect(decoded.summary).toContain('covering 2 order(s)');
    const checked = [decoded.counterparty, ...decoded.others.map((other) => other.address)];
    expect(checked).toContain(DRAINER);
    expect(checked).toContain(OPENSEA_FEE);
    expect(decoded.danger).toContain('the offerer receives NOTHING in return for the offered items');
  });

  it('a JSON-string Seaport order is decoded the same way', () => {
    const data = seaportOrder(NFTS, [eth('1', DRAINER)]);
    const decoded = decodeSignature({ from: USER, data: JSON.stringify(data), signatureMethod: 'eth_signTypedData_v4' });
    expect(decoded.counterparty).toBe(DRAINER);
  });

  it('a legit listing (offerer paid, OpenSea fee) raises no flags', () => {
    const decoded = decode(seaportOrder([nft(BAYC, '7')], [eth('9750000000000000000', USER), eth('250000000000000000', OPENSEA_FEE)]));
    expect(decoded.counterparty).toBe(OPENSEA_FEE);
    expect(decoded.danger).toStrictEqual([]);
    expect(decoded.warnings).toStrictEqual([]);
  });

  it('paid only in an unknown token: warned, not called dust', () => {
    const decoded = decode(seaportOrder([nft(BAYC, '7')], [erc20Item('0x1234567890123456789012345678901234567890', '5000000000000000000000', USER)]));
    expect(decoded.danger).toStrictEqual([]);
    expect(decoded.warnings.join()).toContain('unknown token(s)');
  });
});

describe('Blur and LooksRare', () => {
  it('Blur Order selling for 1 wei is dangerous', () => {
    const decoded = decode(blurOrder('1'));
    expect(decoded.action).toBe('Blur listing');
    expect(decoded.interaction).toStrictEqual({ type: 'order_signature' });
    expect(decoded.danger.join()).toContain(`lists ${BAYC} #1 for only 0.000000000000000001 ETH`);
    expect(decoded.counterparty).toBe(BLUR_EXCHANGE);
  });

  it('Blur Order at a real price is not flagged; high fees are warned and the fee recipient checked', () => {
    expect(decode(blurOrder('25000000000000000000')).danger).toStrictEqual([]);
    const decoded = decode(blurOrder('25000000000000000000', 1, [{ rate: 9000, recipient: DRAINER }]));
    expect(decoded.warnings.join()).toContain('fees send 90% of the sale price');
    expect(decoded.counterparty).toBe(DRAINER);
  });

  it('Blur bulk Root is a blind signature and is warned', () => {
    const decoded = decode(blurRoot());
    expect(decoded.action).toBe('Blur bulk listing (blind root)');
    expect(decoded.warnings.join()).toContain('blind bulk-listing signature');
    expect(decoded.interaction).toStrictEqual({ type: 'order_signature' });
  });

  it('LooksRare v2 Maker ask at price 0 is dangerous; a bid is not', () => {
    const decoded = decode(looksRareMaker('0'));
    expect(decoded.action).toBe('LooksRare order');
    expect(decoded.danger.join()).toContain('for only 0 ETH');
    expect(decoded.counterparty).toBe(LOOKSRARE);
    expect(decode(looksRareMaker('0', 0)).danger).toStrictEqual([]);
  });
});

describe('p3: UniswapX (Permit2 witness) outputs', () => {
  it('an output to a third party becomes the primary counterparty; the reactor is checked too', () => {
    const decoded = decode(uniswapXOrder([{ token: USDC, amount: '9999000000', recipient: DRAINER }]));
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.role).toBe('recipient');
    expect(decoded.interaction).toStrictEqual({ type: 'token_transfer' });
    expect(decoded.payment).toStrictEqual({ network: 'eip155:1', pay_to: DRAINER, amount: '9999000000', asset: USDC });
    expect(decoded.others.map((other) => other.address)).toContain(REACTOR);
    expect(decoded.warnings.join()).toContain(`goes to ${DRAINER}, not to you`);
    const bodies = buildRiskCheckBodies(decoded, 'https://app.uniswap.org');
    expect(bodies.map((body) => body.wallet)).toStrictEqual([DRAINER, REACTOR]);
    expect(bodies[1]?.interaction).toStrictEqual({ type: 'permit_signature' });
  });

  it('an order paying out to the signer keeps the reactor (spender) as the counterparty', () => {
    const decoded = decode(uniswapXOrder([{ token: USDC, amount: '9999000000', recipient: USER }]));
    expect(decoded.counterparty).toBe(REACTOR);
    expect(decoded.warnings).toStrictEqual([]);
    expect(decoded.summary).toContain('to you');
  });

  it('a swapper that is not the signer is warned', () => {
    const decoded = decode(uniswapXOrder([{ token: USDC, amount: '1', recipient: USER }], DRAINER));
    expect(decoded.warnings.join()).toContain(`swapper ${DRAINER} is not the signing account`);
  });
});
