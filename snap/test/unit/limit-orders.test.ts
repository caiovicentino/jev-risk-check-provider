/**
 * @jest-environment node
 *
 * Audit finding cg-7: ERC-20 limit orders that sell the signer's tokens for
 * nothing or dust (1inch Limit Order Protocol v3/v4, 0x v4, CoW Protocol,
 * UniswapX) are proven danger, like the Seaport rule; a foreign receiver of the
 * proceeds, a private taker and fee recipients are checked with the amounts
 * they get; both sides of the price reach the context. Every fixture declares
 * the protocol's real EIP-712 types and is proven signable with eth-sig-util.
 */
import { describe, expect, it } from '@jest/globals';

import { decodeTypedData } from '../../src/decode';
import { buildRiskCheckBodies } from '../../src/request';
import { DOMAIN_TYPE_4, DRAINER, PERMIT2, REACTOR, USDC, USER, WETH, ZERO, eip712Hash } from '../helpers';

const ONEINCH_V4 = '0x111111125421ca6dc452d289314280a0f8842a65';
const ONEINCH_V3 = '0x1111111254eeb25477b68fb85ed929f73a960582';
const ZEROX = '0xdef1c0ded9bec7f1a1670819833240f027b25eff';
const COW = '0x9008d19f58aabd9ed0d60971565aa8510560ab41';
const UNKNOWN_TOKEN = '0x1234567890123456789012345678901234567890';
const GETTER = '0x4444444444444444444444444444444444444444';
const FEE_RECIPIENT = '0x5555555555555555555555555555555555555555';
const NATIVE_MARKER = '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
const MILLION_USDC = '1000000000000';
const B32 = `0x${'0'.repeat(64)}`;

function decode(data: unknown) {
  expect(() => eip712Hash(data)).not.toThrow();
  return decodeTypedData(data, USER);
}

const checked = (decoded: ReturnType<typeof decodeTypedData>) => [decoded.counterparty, ...decoded.others.map((other) => other.address)];

// 1inch Limit Order Protocol v4 (Aggregation Router v6).
function inchV4(message: Record<string, unknown> = {}) {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE_4,
      Order: [
        { name: 'salt', type: 'uint256' },
        { name: 'maker', type: 'address' },
        { name: 'receiver', type: 'address' },
        { name: 'makerAsset', type: 'address' },
        { name: 'takerAsset', type: 'address' },
        { name: 'makingAmount', type: 'uint256' },
        { name: 'takingAmount', type: 'uint256' },
        { name: 'makerTraits', type: 'uint256' },
      ],
    },
    primaryType: 'Order',
    domain: { name: '1inch Aggregation Router', version: '6', chainId: 1, verifyingContract: ONEINCH_V4 },
    message: {
      salt: '1',
      maker: USER,
      receiver: ZERO,
      makerAsset: USDC,
      takerAsset: WETH,
      makingAmount: MILLION_USDC,
      takingAmount: '1',
      makerTraits: '0',
      ...message,
    },
  };
}

// 1inch Limit Order Protocol v3 (Aggregation Router v5).
function inchV3(message: Record<string, unknown> = {}) {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE_4,
      Order: [
        { name: 'salt', type: 'uint256' },
        { name: 'makerAsset', type: 'address' },
        { name: 'takerAsset', type: 'address' },
        { name: 'maker', type: 'address' },
        { name: 'receiver', type: 'address' },
        { name: 'allowedSender', type: 'address' },
        { name: 'makingAmount', type: 'uint256' },
        { name: 'takingAmount', type: 'uint256' },
        { name: 'offsets', type: 'uint256' },
        { name: 'interactions', type: 'bytes' },
      ],
    },
    primaryType: 'Order',
    domain: { name: '1inch Aggregation Router', version: '5', chainId: 1, verifyingContract: ONEINCH_V3 },
    message: {
      salt: '1',
      makerAsset: USDC,
      takerAsset: WETH,
      maker: USER,
      receiver: ZERO,
      allowedSender: ZERO,
      makingAmount: '1000000000',
      takingAmount: '400000000000000000',
      offsets: '0',
      interactions: '0x',
      ...message,
    },
  };
}

/** v3 `offsets`: eight uint32 end offsets of the interaction fields, low field first. */
function v3Offsets(lengths: number[]): string {
  let end = 0;
  let offsets = 0n;
  lengths.forEach((length, index) => {
    end += length;
    offsets |= BigInt(end) << BigInt(32 * index);
  });
  for (let index = lengths.length; index < 8; index += 1) offsets |= BigInt(end) << BigInt(32 * index);
  return offsets.toString();
}

function zeroExLimit(message: Record<string, unknown> = {}) {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE_4,
      LimitOrder: [
        { name: 'makerToken', type: 'address' },
        { name: 'takerToken', type: 'address' },
        { name: 'makerAmount', type: 'uint128' },
        { name: 'takerAmount', type: 'uint128' },
        { name: 'takerTokenFeeAmount', type: 'uint128' },
        { name: 'maker', type: 'address' },
        { name: 'taker', type: 'address' },
        { name: 'sender', type: 'address' },
        { name: 'feeRecipient', type: 'address' },
        { name: 'pool', type: 'bytes32' },
        { name: 'expiry', type: 'uint64' },
        { name: 'salt', type: 'uint256' },
      ],
    },
    primaryType: 'LimitOrder',
    domain: { name: 'ZeroEx', version: '1.0.0', chainId: 1, verifyingContract: ZEROX },
    message: {
      makerToken: USDC,
      takerToken: WETH,
      makerAmount: MILLION_USDC,
      takerAmount: '1',
      takerTokenFeeAmount: '0',
      maker: USER,
      taker: ZERO,
      sender: ZERO,
      feeRecipient: ZERO,
      pool: B32,
      expiry: '1790000000',
      salt: '1',
      ...message,
    },
  };
}

function zeroExRfq(message: Record<string, unknown> = {}) {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE_4,
      RfqOrder: [
        { name: 'makerToken', type: 'address' },
        { name: 'takerToken', type: 'address' },
        { name: 'makerAmount', type: 'uint128' },
        { name: 'takerAmount', type: 'uint128' },
        { name: 'maker', type: 'address' },
        { name: 'taker', type: 'address' },
        { name: 'txOrigin', type: 'address' },
        { name: 'pool', type: 'bytes32' },
        { name: 'expiry', type: 'uint64' },
        { name: 'salt', type: 'uint256' },
      ],
    },
    primaryType: 'RfqOrder',
    domain: { name: 'ZeroEx', version: '1.0.0', chainId: 1, verifyingContract: ZEROX },
    message: {
      makerToken: USDC,
      takerToken: WETH,
      makerAmount: '5000000000',
      takerAmount: '2000000000000000000',
      maker: USER,
      taker: ZERO,
      txOrigin: FEE_RECIPIENT,
      pool: B32,
      expiry: '1790000000',
      salt: '9',
      ...message,
    },
  };
}

function cowOrder(message: Record<string, unknown> = {}) {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE_4,
      Order: [
        { name: 'sellToken', type: 'address' },
        { name: 'buyToken', type: 'address' },
        { name: 'receiver', type: 'address' },
        { name: 'sellAmount', type: 'uint256' },
        { name: 'buyAmount', type: 'uint256' },
        { name: 'validTo', type: 'uint32' },
        { name: 'appData', type: 'bytes32' },
        { name: 'feeAmount', type: 'uint256' },
        { name: 'kind', type: 'string' },
        { name: 'partiallyFillable', type: 'bool' },
        { name: 'sellTokenBalance', type: 'string' },
        { name: 'buyTokenBalance', type: 'string' },
      ],
    },
    primaryType: 'Order',
    domain: { name: 'Gnosis Protocol', version: 'v2', chainId: 1, verifyingContract: COW },
    message: {
      sellToken: USDC,
      buyToken: WETH,
      receiver: ZERO,
      sellAmount: '2000000000',
      buyAmount: '800000000000000000',
      validTo: '1790000000',
      appData: `0x${'ab'.repeat(32)}`,
      feeAmount: '0',
      kind: 'sell',
      partiallyFillable: false,
      sellTokenBalance: 'erc20',
      buyTokenBalance: 'erc20',
      ...message,
    },
  };
}

const ORDER_INFO = [
  { name: 'reactor', type: 'address' },
  { name: 'swapper', type: 'address' },
  { name: 'nonce', type: 'uint256' },
  { name: 'deadline', type: 'uint256' },
  { name: 'additionalValidationContract', type: 'address' },
  { name: 'additionalValidationData', type: 'bytes' },
];
const TOKEN_PERMISSIONS = [
  { name: 'token', type: 'address' },
  { name: 'amount', type: 'uint256' },
];
const info = { reactor: REACTOR, swapper: USER, nonce: '1', deadline: '1790000000', additionalValidationContract: ZERO, additionalValidationData: '0x' };

type Out = { token: string; amount: string; recipient: string };

/** UniswapX ExclusiveDutchOrder through Permit2 PermitWitnessTransferFrom. */
function exclusiveDutch(outputs: Out[], input = MILLION_USDC) {
  return {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      PermitWitnessTransferFrom: [
        { name: 'permitted', type: 'TokenPermissions' },
        { name: 'spender', type: 'address' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
        { name: 'witness', type: 'ExclusiveDutchOrder' },
      ],
      TokenPermissions: TOKEN_PERMISSIONS,
      ExclusiveDutchOrder: [
        { name: 'info', type: 'OrderInfo' },
        { name: 'decayStartTime', type: 'uint256' },
        { name: 'decayEndTime', type: 'uint256' },
        { name: 'exclusiveFiller', type: 'address' },
        { name: 'exclusivityOverrideBps', type: 'uint256' },
        { name: 'inputToken', type: 'address' },
        { name: 'inputStartAmount', type: 'uint256' },
        { name: 'inputEndAmount', type: 'uint256' },
        { name: 'outputs', type: 'DutchOutput[]' },
      ],
      OrderInfo: ORDER_INFO,
      DutchOutput: [
        { name: 'token', type: 'address' },
        { name: 'startAmount', type: 'uint256' },
        { name: 'endAmount', type: 'uint256' },
        { name: 'recipient', type: 'address' },
      ],
    },
    primaryType: 'PermitWitnessTransferFrom',
    domain: { name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 },
    message: {
      permitted: { token: USDC, amount: input },
      spender: REACTOR,
      nonce: '1',
      deadline: '1790000000',
      witness: {
        info,
        decayStartTime: '1700000000',
        decayEndTime: '1700000100',
        exclusiveFiller: ZERO,
        exclusivityOverrideBps: '0',
        inputToken: USDC,
        inputStartAmount: input,
        inputEndAmount: input,
        outputs: outputs.map((output) => ({ token: output.token, startAmount: output.amount, endAmount: output.amount, recipient: output.recipient })),
      },
    },
  };
}

/** UniswapX PriorityOrder (outputs grow with the priority fee; `amount` is the minimum). */
function priorityOrder(outputs: Out[], input = '1000000000') {
  return {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      PermitWitnessTransferFrom: [
        { name: 'permitted', type: 'TokenPermissions' },
        { name: 'spender', type: 'address' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
        { name: 'witness', type: 'PriorityOrder' },
      ],
      TokenPermissions: TOKEN_PERMISSIONS,
      PriorityOrder: [
        { name: 'info', type: 'OrderInfo' },
        { name: 'cosigner', type: 'address' },
        { name: 'auctionStartBlock', type: 'uint256' },
        { name: 'baselinePriorityFeeWei', type: 'uint256' },
        { name: 'input', type: 'PriorityInput' },
        { name: 'outputs', type: 'PriorityOutput[]' },
      ],
      OrderInfo: ORDER_INFO,
      PriorityInput: [
        { name: 'token', type: 'address' },
        { name: 'amount', type: 'uint256' },
        { name: 'mpsPerPriorityFeeWei', type: 'uint256' },
      ],
      PriorityOutput: [
        { name: 'token', type: 'address' },
        { name: 'amount', type: 'uint256' },
        { name: 'mpsPerPriorityFeeWei', type: 'uint256' },
        { name: 'recipient', type: 'address' },
      ],
    },
    primaryType: 'PermitWitnessTransferFrom',
    domain: { name: 'Permit2', chainId: 8453, verifyingContract: PERMIT2 },
    message: {
      permitted: { token: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913', amount: input },
      spender: REACTOR,
      nonce: '1',
      deadline: '1790000000',
      witness: {
        info,
        cosigner: ZERO,
        auctionStartBlock: '1',
        baselinePriorityFeeWei: '0',
        input: { token: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913', amount: input, mpsPerPriorityFeeWei: '0' },
        outputs: outputs.map((output) => ({ token: output.token, amount: output.amount, mpsPerPriorityFeeWei: '1', recipient: output.recipient })),
      },
    },
  };
}

describe('cg-7: 1inch Limit Order Protocol', () => {
  it('audit repro: a v4 order selling 1,000,000 USDC for 1 wei is proven danger, and both amounts reach the context', () => {
    const decoded = decode(inchV4());
    expect(decoded.action).toBe('1inch limit order (v4)');
    expect(decoded.interaction).toStrictEqual({ type: 'order_signature' });
    expect(decoded.danger.join()).toContain(`sells 1000000 USDC (${MILLION_USDC} base units of ${USDC}) for only 0.000000000000000001 WETH`);
    // No third party: the router (verifying contract) is the subject, never the token.
    expect(decoded.counterparty).toBe(ONEINCH_V4);
    const [body] = buildRiskCheckBodies(decoded, 'https://app.1inch.io');
    expect(body?.context).toMatch(/^Proven danger: /u);
    expect(body?.context).toContain(`${MILLION_USDC} base units of ${USDC}`);
    expect(body?.context).toContain(`1 base units of ${WETH}`);
  });

  it('a fair v4 order raises nothing', () => {
    const decoded = decode(inchV4({ makingAmount: '1000000000', takingAmount: '400000000000000000' }));
    expect(decoded.danger).toStrictEqual([]);
    expect(decoded.warnings).toStrictEqual([]);
    expect(decoded.opaque).toBeUndefined();
    expect(decoded.summary).toContain('sells 1000 USDC');
    expect(decoded.summary).toContain('for 0.4 WETH');
    expect(decoded.summary).toContain('the proceeds go to you');
  });

  it('takingAmount 0 sells for NOTHING', () => {
    expect(decode(inchV4({ takingAmount: '0' })).danger.join()).toContain('for NOTHING (0 WETH');
  });

  it('proceeds to a foreign receiver: you receive NOTHING; the receiver is checked with the proceeds bound', () => {
    const decoded = decode(inchV4({ receiver: DRAINER, makingAmount: '1000000000', takingAmount: '400000000000000000' }));
    expect(decoded.danger.join()).toContain(`you receive NOTHING from this order: its proceeds (0.4 WETH`);
    expect(decoded.danger.join()).toContain(`go to ${DRAINER}`);
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.role).toBe('recipient');
    expect(decoded.interaction).toStrictEqual({ type: 'order_signature' });
    expect(decoded.payment).toStrictEqual({ network: 'eip155:1', pay_to: DRAINER, amount: '400000000000000000', asset: WETH });
  });

  it('paid in a token of unknown value: warned with both amounts, not called dust', () => {
    const decoded = decode(inchV4({ takerAsset: UNKNOWN_TOKEN, makingAmount: '1000000000', takingAmount: '5000000000000000000000' }));
    expect(decoded.danger).toStrictEqual([]);
    expect(decoded.warnings.join()).toContain(`whose value x402check does not know: check that 5000000000000000000000 base units of token ${UNKNOWN_TOKEN} is worth 1000 USDC`);
  });

  it('an order whose maker is not the signer is warned (the maker is still "you" for the price)', () => {
    const decoded = decode(inchV4({ maker: DRAINER }));
    expect(decoded.warnings.join()).toContain(`the order's maker ${DRAINER} is not the signing account`);
    expect(decoded.danger.join()).toContain('for only');
  });

  it('v4 HAS_EXTENSION: the extension can replace the signed amounts, so the order is opaque', () => {
    const decoded = decode(inchV4({ makingAmount: '1000000000', takingAmount: '400000000000000000', makerTraits: (1n << 249n).toString() }));
    expect(decoded.opaque).toContain('has an extension');
    expect(decoded.warnings[0]).toMatch(/^x402check cannot read what this authorizes: /u);
    expect(decoded.danger).toStrictEqual([]);
  });

  it('v4 private order and expiry are shown from makerTraits', () => {
    const traits = (1790000000n << 80n) | BigInt(`0x${DRAINER.slice(-20)}`);
    const decoded = decode(inchV4({ makingAmount: '1000000000', takingAmount: '400000000000000000', makerTraits: traits.toString() }));
    expect(decoded.summary).toContain(`only a taker whose address ends in ${DRAINER.slice(-20)} may fill it`);
    expect(decoded.summary).toContain('expires 2026-09-21');
    expect(decoded.opaque).toBeUndefined();
  });

  it('v3: allowedSender is a counterparty that receives what you sell', () => {
    const decoded = decode(inchV3({ allowedSender: DRAINER }));
    expect(decoded.action).toBe('1inch limit order (v3)');
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.role).toBe('counterparty');
    expect(decoded.payment).toStrictEqual({ network: 'eip155:1', pay_to: DRAINER, amount: '1000000000', asset: USDC });
    expect(decoded.danger).toStrictEqual([]);
  });

  it('v3: a getTakingAmount getter contract makes the price unverifiable (opaque); the "x" getter does not', () => {
    const getter = `${GETTER.slice(2)}${'ab'.repeat(8)}`;
    const custom = decode(inchV3({ offsets: v3Offsets([0, 0, 0, getter.length / 2]), interactions: `0x${getter}` }));
    expect(custom.opaque).toContain('getter contract');
    const exactOnly = decode(inchV3({ offsets: v3Offsets([0, 0, 1, 1]), interactions: '0x7878' }));
    expect(exactOnly.opaque).toBeUndefined();
    const predicate = decode(inchV3({ offsets: v3Offsets([0, 0, 0, 0, 4]), interactions: '0x12345678' }));
    expect(predicate.opaque).toBeUndefined();
    expect(predicate.summary).toContain('it carries predicate data that x402check does not decode');
  });

  it('v3 dust price is proven danger too', () => {
    expect(decode(inchV3({ takingAmount: '1' })).danger.join()).toContain('for only 0.000000000000000001 WETH');
  });
});

describe('cg-7: 0x v4', () => {
  it('audit repro: a LimitOrder selling 1,000,000 USDC for 1 wei is proven danger', () => {
    const decoded = decode(zeroExLimit());
    expect(decoded.action).toBe('0x v4 LimitOrder');
    expect(decoded.danger.join()).toContain('for only 0.000000000000000001 WETH');
    expect(decoded.counterparty).toBe(ZEROX);
  });

  it('a private taker receives what you sell; the fee recipient gets the taker fee; both are checked', () => {
    const decoded = decode(
      zeroExLimit({ makerAmount: '1000000000', takerAmount: '400000000000000000', taker: DRAINER, feeRecipient: FEE_RECIPIENT, takerTokenFeeAmount: '1000000000000000' }),
    );
    expect(decoded.danger).toStrictEqual([]);
    expect(checked(decoded)).toStrictEqual([DRAINER, FEE_RECIPIENT]);
    expect(decoded.payment).toStrictEqual({ network: 'eip155:1', pay_to: DRAINER, amount: '1000000000', asset: USDC });
    expect(decoded.others[0]?.payment).toStrictEqual({ network: 'eip155:1', pay_to: FEE_RECIPIENT, amount: '1000000000000000', asset: WETH });
    expect(decoded.summary).toContain(`only ${DRAINER} may fill it`);
  });

  it('RfqOrder: a fair order raises nothing; txOrigin is checked', () => {
    const decoded = decode(zeroExRfq());
    expect(decoded.action).toBe('0x v4 RfqOrder');
    expect(decoded.danger).toStrictEqual([]);
    expect(decoded.warnings).toStrictEqual([]);
    expect(decoded.counterparty).toBe(FEE_RECIPIENT);
    expect(decoded.summary).toContain('only 0x5555555555555555555555555555555555555555 may submit the fill (txOrigin)');
    // The pool (bytes32) of a recognized order is never a reason to be opaque.
    expect(decoded.opaque).toBeUndefined();
  });

  it('RfqOrder selling for dust is proven danger', () => {
    expect(decode(zeroExRfq({ takerAmount: '999' })).danger.join()).toContain('typical of drainer orders');
  });
});

describe('cg-7: CoW Protocol', () => {
  it('a fair sell order raises nothing (appData bytes32 is not opaque)', () => {
    const decoded = decode(cowOrder());
    expect(decoded.action).toBe('CoW Protocol order');
    expect(decoded.danger).toStrictEqual([]);
    expect(decoded.warnings).toStrictEqual([]);
    expect(decoded.opaque).toBeUndefined();
    expect(decoded.summary).toContain('sells 2000 USDC');
    expect(decoded.summary).toContain('for at least 0.8 WETH');
  });

  it('selling for 1 wei of native ETH (the 0xEeee marker) is proven danger', () => {
    const decoded = decode(cowOrder({ buyToken: NATIVE_MARKER, buyAmount: '1' }));
    expect(decoded.danger.join()).toContain('for only 0.000000000000000001 ETH (1 wei)');
  });

  it('a custom receiver takes the proceeds: you receive NOTHING, the receiver is checked', () => {
    const decoded = decode(cowOrder({ receiver: DRAINER }));
    expect(decoded.danger.join()).toContain('you receive NOTHING from this order');
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.payment).toStrictEqual({ network: 'eip155:1', pay_to: DRAINER, amount: '800000000000000000', asset: WETH });
  });

  it('a buy order is described as a buy, with its fee', () => {
    const decoded = decode(cowOrder({ kind: 'buy', feeAmount: '1000000' }));
    expect(decoded.summary).toContain('buys 0.8 WETH');
    expect(decoded.summary).toContain('for at most 2000 USDC');
    expect(decoded.summary).toContain('plus a fee of 1 USDC');
  });
});

describe('cg-7: UniswapX (Permit2 witness orders)', () => {
  it('audit repro: 1,000,000 USDC in, 1 wei out to the signer is proven danger', () => {
    const decoded = decode(exclusiveDutch([{ token: WETH, amount: '1', recipient: USER }]));
    expect(decoded.danger.join()).toContain('you receive only 0.000000000000000001 WETH');
    expect(decoded.danger.join()).toContain(`in exchange for 1000000 USDC`);
    expect(decoded.counterparty).toBe(REACTOR);
  });

  it('native output (token = zero address) is priced as ETH', () => {
    const dust = decode(exclusiveDutch([{ token: ZERO, amount: '5', recipient: USER }]));
    expect(dust.danger.join()).toContain('you receive only 0.000000000000000005 ETH');
    const fair = decode(exclusiveDutch([{ token: ZERO, amount: '400000000000000000', recipient: USER }], '1000000000'));
    expect(fair.danger).toStrictEqual([]);
  });

  it('all outputs to a third party: you receive NOTHING', () => {
    const decoded = decode(exclusiveDutch([{ token: WETH, amount: '400000000000000000', recipient: DRAINER }], '1000000000'));
    expect(decoded.danger.join()).toContain(`you receive NOTHING from this order in exchange for 1000 USDC`);
    expect(decoded.danger.join()).toContain(`its outputs go to ${DRAINER}`);
    expect(decoded.counterparty).toBe(DRAINER);
  });

  it('a fair order with a small interface fee raises no danger; the fee recipient is checked', () => {
    const decoded = decode(
      exclusiveDutch(
        [
          { token: WETH, amount: '399000000000000000', recipient: USER },
          { token: WETH, amount: '1000000000000000', recipient: FEE_RECIPIENT },
        ],
        '1000000000',
      ),
    );
    expect(decoded.danger).toStrictEqual([]);
    expect(checked(decoded)).toStrictEqual([FEE_RECIPIENT, REACTOR]);
  });

  it('outputs in an unknown token are warned with both sides of the price', () => {
    const decoded = decode(exclusiveDutch([{ token: UNKNOWN_TOKEN, amount: '5000000000000000000000', recipient: USER }], '1000000000'));
    expect(decoded.danger).toStrictEqual([]);
    expect(decoded.warnings.join()).toContain(`check that 5000000000000000000000 base units of token ${UNKNOWN_TOKEN} is worth 1000 USDC`);
  });

  it('PriorityOrder: the minimum output (amount) is what counts', () => {
    const baseWeth = '0x4200000000000000000000000000000000000006';
    expect(decode(priorityOrder([{ token: baseWeth, amount: '400000000000000000', recipient: USER }])).danger).toStrictEqual([]);
    const dust = decode(priorityOrder([{ token: baseWeth, amount: '7', recipient: USER }]));
    expect(dust.danger.join()).toContain('you receive only 0.000000000000000007 WETH');
    expect(dust.chain).toBe('eip155:8453');
  });

  it('additionalValidationData (bytes) of a recognized order is never opaque', () => {
    const data = exclusiveDutch([{ token: WETH, amount: '400000000000000000', recipient: USER }], '1000000000');
    const withData = { ...data, message: { ...data.message, witness: { ...data.message.witness, info: { ...info, additionalValidationData: '0xdeadbeef' } } } };
    expect(decode(withData).opaque).toBeUndefined();
  });
});

describe('cg-7: orders of an unknown format', () => {
  const unknownOrder = {
    types: {
      EIP712Domain: DOMAIN_TYPE_4,
      SwapOrder: [
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
        { name: 'partner', type: 'string' },
        { name: 'route', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'flags', type: 'uint256' },
        { name: 'inputToken', type: 'address' },
        { name: 'outputToken', type: 'address' },
        { name: 'inputAmount', type: 'uint256' },
        { name: 'minOutputAmount', type: 'uint256' },
      ],
    },
    primaryType: 'SwapOrder',
    domain: { name: 'Some DEX', version: '1', chainId: 1, verifyingContract: DRAINER },
    message: {
      nonce: '1',
      deadline: '1790000000',
      partner: 'x',
      route: 'y',
      version: '1',
      flags: '0',
      inputToken: USDC,
      outputToken: WETH,
      inputAmount: MILLION_USDC,
      minOutputAmount: '1',
    },
  };

  it('amounts and tokens reach the context first, with a warning, even past the field cap', () => {
    const decoded = decode(unknownOrder);
    expect(decoded.interaction).toStrictEqual({ type: 'order_signature' });
    expect(decoded.summary).toContain(`inputAmount=${MILLION_USDC}`);
    expect(decoded.summary).toContain('minOutputAmount=1');
    expect(decoded.summary).toContain(`inputToken=${USDC}`);
    expect(decoded.warnings.join()).toContain('does not know this order format');
    for (const body of buildRiskCheckBodies(decoded)) expect(body.context).toContain('minOutputAmount=1');
  });
});
