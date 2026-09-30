/**
 * @jest-environment node
 *
 * Audit finding cg-3: typed data that carries calldata or a hash executed as
 * the signer was checked against a bystander. Calls are now decoded (ERC-4337
 * user operations and Safe 4337 operations, ERC-2771 forward requests,
 * EIP712Base meta-transactions), ERC-7739 wrappers are unwrapped, and typed
 * data whose payload cannot be read (SafeMessage, hash wrappers, unknown
 * calldata carriers) is `opaque`. Every fixture is signable (eth-sig-util).
 */
import { describe, expect, it } from '@jest/globals';

import { decodeTypedData, opaqueNote } from '../../src/decode';
import { buildRiskCheckBodies } from '../../src/request';
import { executeBatchArrays, executeBatchTuples, executeWithOperation, executeWithoutChainIdValidation } from '../account-fixtures';
import {
  B32_ZERO,
  BAYC,
  DOMAIN_TYPE_4,
  DRAINER,
  MAX_UINT256,
  RECIPIENT,
  SAFE,
  USDC,
  USER,
  WETH,
  calldata,
  eip712Hash,
  erc20Item,
  erc2612Permit,
  execute4337,
  nft,
  seaportOrder,
  utf8Hex,
  word,
} from '../helpers';

const USDC_BASE = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913';
const USDC_E_POLYGON = '0x2791bca1f2de4661ed88a30c99a7a9449aa84174';
const ENTRY_POINT_08 = '0x4337084d9e255ff0702461cf8895ce9e3b5ff108';
const ENTRY_POINT_07 = '0x0000000071727de22e5e9d8baf0edac6f37da032';
const SAFE_4337_MODULE = '0x75cf11467937ce3f2f357ce24ffc3dbf8fd5c226';
const SMART_ACCOUNT = '0x7777777777777777777777777777777777777777';
const PAYMASTER = '0x8888888888888888888888888888888888888888';
const FACTORY = '0x9999999999999999999999999999999999999999';
const FORWARDER = '0x6666666666666666666666666666666666666666';

const TRANSFER_TO_DRAINER = calldata('a9059cbb', DRAINER, 1_000_000_000n);

function decode(data: unknown, signer: string = USER) {
  expect(() => eip712Hash(data)).not.toThrow();
  return decodeTypedData(data, signer);
}

const checked = (decoded: ReturnType<typeof decodeTypedData>) => [decoded.counterparty, ...decoded.others.map((other) => other.address)];

/** ERC-4337 v0.8 user operation, as viem's getUserOperationTypedData builds it. */
function packedUserOp(sender: string, callData: string, extra: Record<string, unknown> = {}) {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE_4,
      PackedUserOperation: [
        { type: 'address', name: 'sender' },
        { type: 'uint256', name: 'nonce' },
        { type: 'bytes', name: 'initCode' },
        { type: 'bytes', name: 'callData' },
        { type: 'bytes32', name: 'accountGasLimits' },
        { type: 'uint256', name: 'preVerificationGas' },
        { type: 'bytes32', name: 'gasFees' },
        { type: 'bytes', name: 'paymasterAndData' },
      ],
    },
    primaryType: 'PackedUserOperation',
    domain: { name: 'ERC4337', version: '1', chainId: 8453, verifyingContract: ENTRY_POINT_08 },
    message: {
      sender,
      nonce: '0',
      initCode: '0x',
      callData,
      accountGasLimits: `0x${word(100000n).slice(32)}${word(200000n).slice(32)}`,
      preVerificationGas: '50000',
      gasFees: `0x${word(1n).slice(32)}${word(2n).slice(32)}`,
      paymasterAndData: '0x',
      ...extra,
    },
  };
}

/** Safe4337Module v0.3.0 SafeOp. */
function safeOp(callData: string) {
  return {
    types: {
      EIP712Domain: [
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      SafeOp: [
        { type: 'address', name: 'safe' },
        { type: 'uint256', name: 'nonce' },
        { type: 'bytes', name: 'initCode' },
        { type: 'bytes', name: 'callData' },
        { type: 'uint128', name: 'verificationGasLimit' },
        { type: 'uint128', name: 'callGasLimit' },
        { type: 'uint256', name: 'preVerificationGas' },
        { type: 'uint128', name: 'maxPriorityFeePerGas' },
        { type: 'uint128', name: 'maxFeePerGas' },
        { type: 'bytes', name: 'paymasterAndData' },
        { type: 'uint48', name: 'validAfter' },
        { type: 'uint48', name: 'validUntil' },
        { type: 'address', name: 'entryPoint' },
      ],
    },
    primaryType: 'SafeOp',
    domain: { chainId: 1, verifyingContract: SAFE_4337_MODULE },
    message: {
      safe: SAFE,
      nonce: '0',
      initCode: '0x',
      callData,
      verificationGasLimit: '100000',
      callGasLimit: '100000',
      preVerificationGas: '50000',
      maxPriorityFeePerGas: '1',
      maxFeePerGas: '2',
      paymasterAndData: '0x',
      validAfter: '0',
      validUntil: '0',
      entryPoint: ENTRY_POINT_07,
    },
  };
}

/** OpenZeppelin v5 ERC2771Forwarder request (withDeadline) or MinimalForwarder (without). */
function forwardRequest(from: string, to: string, data: string, withDeadline = true) {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE_4,
      ForwardRequest: [
        { name: 'from', type: 'address' },
        { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'gas', type: 'uint256' },
        { name: 'nonce', type: 'uint256' },
        ...(withDeadline ? [{ name: 'deadline', type: 'uint48' }] : []),
        { name: 'data', type: 'bytes' },
      ],
    },
    primaryType: 'ForwardRequest',
    domain: { name: 'ERC2771Forwarder', version: '1', chainId: 1, verifyingContract: FORWARDER },
    message: { from, to, value: '0', gas: '100000', nonce: '0', ...(withDeadline ? { deadline: '1790000000' } : {}), data },
  };
}

/** Polygon EIP712Base meta-transaction: the chain id is the domain salt. */
function metaTransaction(functionSignature: string, from: string = USER) {
  return {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'verifyingContract', type: 'address' },
        { name: 'salt', type: 'bytes32' },
      ],
      MetaTransaction: [
        { name: 'nonce', type: 'uint256' },
        { name: 'from', type: 'address' },
        { name: 'functionSignature', type: 'bytes' },
      ],
    },
    primaryType: 'MetaTransaction',
    domain: { name: 'USD Coin (PoS)', version: '1', verifyingContract: USDC_E_POLYGON, salt: `0x${word(137n)}` },
    message: { nonce: '0', from, functionSignature },
  };
}

type Typed = { types: Record<string, unknown>; primaryType: string; domain: Record<string, unknown>; message: Record<string, unknown> };

/** ERC-7739 TypedDataSign, as viem's experimental erc7739 signTypedData builds it. */
function typedDataSign(inner: Typed, account: string = SMART_ACCOUNT) {
  return {
    types: {
      ...inner.types,
      TypedDataSign: [
        { name: 'contents', type: inner.primaryType },
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
        { name: 'salt', type: 'bytes32' },
      ],
    },
    primaryType: 'TypedDataSign',
    domain: inner.domain,
    message: { contents: inner.message, name: 'Solady Account', version: '1', chainId: 1, verifyingContract: account, salt: B32_ZERO },
  };
}

/** ERC-7739 PersonalSign(bytes prefixed), under the smart account's domain. */
function personalSign7739(messageHex: string, account: string = SMART_ACCOUNT) {
  const bytes = Buffer.from(messageHex.replace(/^0x/u, ''), 'hex');
  const prefixed = Buffer.concat([Buffer.from(`\x19Ethereum Signed Message:\n${bytes.length}`, 'utf8'), bytes]);
  return {
    types: { EIP712Domain: DOMAIN_TYPE_4, PersonalSign: [{ name: 'prefixed', type: 'bytes' }] },
    primaryType: 'PersonalSign',
    domain: { name: 'Solady Account', version: '1', chainId: 1, verifyingContract: account },
    message: { prefixed: `0x${prefixed.toString('hex')}` },
  };
}

function simple(primaryType: string, fields: { name: string; type: string }[], message: Record<string, unknown>, domain: Record<string, unknown> = { chainId: 1, verifyingContract: SAFE }) {
  return {
    types: {
      EIP712Domain: Object.keys(domain).map((name) => ({ name, type: name === 'chainId' ? 'uint256' : name === 'verifyingContract' ? 'address' : 'string' })),
      [primaryType]: fields,
    },
    primaryType,
    domain,
    message,
  };
}

describe('cg-3 (a): ERC-4337 user operations decode their callData as calls of the account', () => {
  it('audit repro: execute(USDC, 0, transfer(DRAINER)) checks the drainer, bound to the transfer, not the EntryPoint', () => {
    const decoded = decode(packedUserOp(USER, execute4337(USDC_BASE, 0n, TRANSFER_TO_DRAINER)));
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.role).toBe('recipient');
    expect(decoded.interaction).toStrictEqual({ type: 'token_transfer' });
    expect(decoded.payment).toStrictEqual({ network: 'eip155:8453', pay_to: DRAINER, amount: '1000000000', asset: USDC_BASE });
    expect(checked(decoded)).not.toContain(ENTRY_POINT_08);
    expect(decoded.opaque).toBeUndefined();
    expect(decoded.summary).toContain(`ERC-4337 user operation signature for account ${USER} (EntryPoint ${ENTRY_POINT_08})`);
    expect(decoded.summary).toContain('sends 1000 USDC');
  });

  it('SimpleAccount executeBatch(address[], bytes[]) of a separate smart account: every call is decoded', () => {
    const callData = executeBatchArrays([USDC, USDC], [calldata('095ea7b3', DRAINER, MAX_UINT256), calldata('a9059cbb', RECIPIENT, 1n)]);
    const decoded = decode({ ...packedUserOp(SMART_ACCOUNT, callData), domain: { name: 'ERC4337', version: '1', chainId: 1, verifyingContract: ENTRY_POINT_08 } });
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.interaction).toStrictEqual({ type: 'token_approval', unlimited: true });
    expect(checked(decoded)).toContain(RECIPIENT);
  });

  it('Coinbase Smart Wallet / Simple7702Account executeBatch((address,uint256,bytes)[]), and Ambire executeBySender', () => {
    const batch = executeBatchTuples([{ to: USDC_BASE, value: 0n, data: TRANSFER_TO_DRAINER }, { to: RECIPIENT, value: 5n, data: '0x' }]);
    expect(checked(decode(packedUserOp(USER, batch)))).toStrictEqual([DRAINER, RECIPIENT]);
    // Same ABI layout, Ambire's selector.
    const ambire = decode(packedUserOp(USER, batch.replace(/^0x34fcd5be/u, '0xabc5345e')));
    expect(checked(ambire)).toStrictEqual([DRAINER, RECIPIENT]);
    expect(ambire.opaque).toBeUndefined();
  });

  it('callData that is not a known account entry point is opaque (the account runs its own unknown code)', () => {
    const decoded = decode(packedUserOp(USER, calldata('12345678', DRAINER)));
    expect(decoded.opaque).toContain(`account ${USER} calls its own code (function selector 0x12345678`);
    expect(decoded.warnings[0]).toBe(opaqueNote(decoded.opaque as string));
    // Its only address is the account itself: nothing to check, which is not an all-clear.
    expect(decoded.counterparty).toBeUndefined();
  });

  it('the paymaster and the account factory are checked too; a 7702 initCode marker is described', () => {
    const decoded = decode(
      packedUserOp(USER, execute4337(USDC_BASE, 0n, TRANSFER_TO_DRAINER), {
        paymasterAndData: `${PAYMASTER}${'00'.repeat(32)}`,
        initCode: `${FACTORY}5fbfb9cf${word(USER)}${word(0n)}`,
      }),
    );
    expect(checked(decoded)).toStrictEqual([DRAINER, FACTORY, PAYMASTER]);
    const marker = decode(packedUserOp(USER, execute4337(USDC_BASE, 0n, TRANSFER_TO_DRAINER), { initCode: `0x7702${'00'.repeat(18)}` }));
    expect(marker.summary).toContain('EIP-7702 delegated account');
  });

  it('Safe 4337 SafeOp: executeUserOp is decoded as a call from the Safe; operation 1 is a DELEGATECALL', () => {
    const call = decode(safeOp(executeWithOperation('7bb37428', USDC, 0n, TRANSFER_TO_DRAINER, 0)));
    expect(call.counterparty).toBe(DRAINER);
    expect(call.summary).toContain(`Safe 4337 operation signature for account ${SAFE} (EntryPoint ${ENTRY_POINT_07})`);
    const delegate = decode(safeOp(executeWithOperation('541d63c8', DRAINER, 0n, '0x12345678', 1)));
    expect(delegate.danger.join()).toContain(`DELEGATECALL to ${DRAINER}`);
  });

  it('Kernel v2 execute(address,uint256,bytes,uint8) through a user operation', () => {
    const decoded = decode(packedUserOp(SMART_ACCOUNT, executeWithOperation('51945447', USDC_BASE, 0n, TRANSFER_TO_DRAINER, 0)));
    expect(decoded.counterparty).toBe(DRAINER);
  });

  it('cg-4 through a user operation: a Coinbase Smart Wallet adding an owner on every chain is proven danger', () => {
    const decoded = decode(packedUserOp(SMART_ACCOUNT, executeWithoutChainIdValidation([calldata('0f0f3f24', DRAINER)])));
    expect(decoded.danger).toStrictEqual([`adds ${DRAINER} as an owner of smart wallet ${SMART_ACCOUNT}`]);
    expect(decoded.warnings.join()).toContain('replayable on every chain');
    expect(decoded.counterparty).toBe(DRAINER);
  });
});

describe('cg-3 (b, c): forward requests and meta-transactions', () => {
  it('audit repro: ERC-2771 ForwardRequest with transfer(DRAINER) checks the drainer, not the token contract', () => {
    for (const withDeadline of [true, false]) {
      const decoded = decode(forwardRequest(USER, USDC, TRANSFER_TO_DRAINER, withDeadline));
      expect(decoded.counterparty).toBe(DRAINER);
      expect(decoded.payment).toStrictEqual({ network: 'eip155:1', pay_to: DRAINER, amount: '1000000000', asset: USDC });
      expect(checked(decoded)).not.toContain(USDC);
      expect(decoded.summary).toContain(`a call from ${USER} to ${USDC}`);
    }
  });

  it('a forward request for another account is warned', () => {
    const decoded = decode(forwardRequest(SMART_ACCOUNT, USDC, TRANSFER_TO_DRAINER));
    expect(decoded.warnings.join()).toContain(`the request acts for account ${SMART_ACCOUNT}, not the signing account`);
  });

  it('audit repro: Polygon MetaTransaction transfer(DRAINER): the drainer is checked, on the chain from the salt', () => {
    const decoded = decode(metaTransaction(TRANSFER_TO_DRAINER));
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.chain).toBe('eip155:137');
    expect(decoded.payment).toStrictEqual({ network: 'eip155:137', pay_to: DRAINER, amount: '1000000000', asset: USDC_E_POLYGON });
    expect(decoded.summary).toContain('sends 1000 USDC');
  });

  it('a meta-transaction whose functionSignature approves a drainer is an unlimited approval', () => {
    const decoded = decode(metaTransaction(calldata('095ea7b3', DRAINER, MAX_UINT256)));
    expect(decoded.interaction).toStrictEqual({ type: 'token_approval', unlimited: true });
  });
});

describe('cg-3 (d): ERC-7739 TypedDataSign keeps the wrapped semantics', () => {
  it('audit repro: an unlimited permit wrapped in TypedDataSign is still a permit_signature, unlimited, with its payment binding', () => {
    const permit = erc2612Permit(DRAINER, MAX_UINT256.toString(), 1, { owner: SMART_ACCOUNT });
    const plain = decode(permit, SMART_ACCOUNT);
    const wrapped = decode(typedDataSign(permit));
    expect(wrapped.counterparty).toBe(DRAINER);
    expect(wrapped.interaction).toStrictEqual({ type: 'permit_signature', unlimited: true });
    expect(wrapped.interaction).toStrictEqual(plain.interaction);
    expect(wrapped.payment).toStrictEqual(plain.payment);
    expect(wrapped.payment).toStrictEqual({ network: 'eip155:1', pay_to: DRAINER, amount: MAX_UINT256.toString(), asset: USDC });
    expect(wrapped.unlimited).toBe(true);
    expect(wrapped.action).toBe('ERC-7739: EIP-2612 permit');
    expect(wrapped.summary).toContain(`ERC-7739 nested signature (TypedDataSign) for smart account ${SMART_ACCOUNT}`);
    expect(wrapped.opaque).toBeUndefined();
    expect(buildRiskCheckBodies(wrapped)[0]?.interaction).toStrictEqual({ type: 'permit_signature', unlimited: true });
  });

  it('a wrapped drainer listing keeps its proven danger', () => {
    const listing = seaportOrder([nft(BAYC, '1')], [erc20Item(WETH, '1', SMART_ACCOUNT)], SMART_ACCOUNT);
    const decoded = decode(typedDataSign(listing));
    expect(decoded.danger.join()).toContain('typical of NFT drainer listings');
  });

  it('a wrapped SafeMessage stays opaque', () => {
    const inner = simple('SafeMessage', [{ name: 'message', type: 'bytes' }], { message: `0x${'9f'.repeat(32)}` });
    expect(decode(typedDataSign(inner)).opaque).toContain('Safe message');
  });

  it('PersonalSign: a text message is decoded like personal_sign; binary (a hash) is opaque', () => {
    const text = decode(personalSign7739(utf8Hex('Sign in to app.example.com, nonce 42')));
    expect(text.opaque).toBeUndefined();
    expect(text.referencedHosts).toStrictEqual(['app.example.com']);
    expect(text.summary).toContain('ERC-7739 nested personal message (PersonalSign)');
    // A message that itself starts with digits still splits at the right length.
    expect(decode(personalSign7739(utf8Hex('2024 was a good year'))).opaque).toBeUndefined();
    // sha256("test"): 32 bytes that are not text.
    const hash = decode(personalSign7739('0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'));
    expect(hash.opaque).toContain('(a 32-byte hash) as a personal message');
  });
});

describe('cg-3 (e): payloads that cannot be read are opaque; recognized types are not', () => {
  it('audit repro: SafeMessage signs an opaque hash for the Safe', () => {
    const decoded = decode(simple('SafeMessage', [{ name: 'message', type: 'bytes' }], { message: `0x${'9f'.repeat(32)}` }));
    expect(decoded.opaque).toContain(`this Safe message (SafeMessage for Safe ${SAFE}) signs "message" (bytes, 32 bytes, likely a hash)`);
    expect(decoded.warnings[0]).toMatch(/^x402check cannot read what this authorizes: /u);
  });

  it.each([
    ['Coinbase Smart Wallet', 'CoinbaseSmartWalletMessage', [{ name: 'hash', type: 'bytes32' }], { hash: `0x${'11'.repeat(32)}` }],
    ['Kernel', 'Kernel', [{ name: 'hash', type: 'bytes32' }], { hash: `0x${'11'.repeat(32)}` }],
    ['Hyperliquid agent action', 'Agent', [{ name: 'source', type: 'string' }, { name: 'connectionId', type: 'bytes32' }], { source: 'a', connectionId: `0x${'22'.repeat(32)}` }],
    ['a pure hash wrapper', 'Anything', [{ name: 'x', type: 'bytes32' }, { name: 'nonce', type: 'uint256' }], { x: `0x${'33'.repeat(32)}`, nonce: '1' }],
    ['LightAccount', 'LightAccountMessage', [{ name: 'message', type: 'bytes' }], { message: '0x1234' }],
    [
      'an unknown calldata carrier',
      'Execute',
      [{ name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' }],
      { to: USDC, value: '0', data: TRANSFER_TO_DRAINER },
    ],
  ])('%s', (_label, primaryType, fields, message) => {
    const decoded = decode(simple(primaryType as string, fields as { name: string; type: string }[], message as Record<string, unknown>));
    expect(decoded.opaque).toMatch(/which x402check cannot read/u);
  });

  it('calldata nested in a struct array is found too', () => {
    const data = {
      types: {
        EIP712Domain: DOMAIN_TYPE_4,
        Execute: [
          { name: 'calls', type: 'Call[]' },
          { name: 'nonce', type: 'uint256' },
        ],
        Call: [
          { name: 'to', type: 'address' },
          { name: 'value', type: 'uint256' },
          { name: 'data', type: 'bytes' },
        ],
      },
      primaryType: 'Execute',
      domain: { name: 'Porto', version: '1', chainId: 1, verifyingContract: SMART_ACCOUNT },
      message: { calls: [{ to: USDC, value: '0', data: TRANSFER_TO_DRAINER }], nonce: '1' },
    };
    expect(decode(data).opaque).toContain('"calls[0].data" (bytes, 68 bytes)');
  });

  it('recognized or harmless bytes32 fields never make a request opaque', () => {
    const eip3009 = {
      types: {
        EIP712Domain: DOMAIN_TYPE_4,
        TransferWithAuthorization: [
          { name: 'from', type: 'address' },
          { name: 'to', type: 'address' },
          { name: 'value', type: 'uint256' },
          { name: 'validAfter', type: 'uint256' },
          { name: 'validBefore', type: 'uint256' },
          { name: 'nonce', type: 'bytes32' },
        ],
      },
      primaryType: 'TransferWithAuthorization',
      domain: { name: 'USD Coin', version: '2', chainId: 1, verifyingContract: USDC },
      message: { from: USER, to: RECIPIENT, value: '1000', validAfter: '0', validBefore: '1790000000', nonce: `0x${'44'.repeat(32)}` },
    };
    const vote = simple(
      'Vote',
      [
        { name: 'from', type: 'address' },
        { name: 'space', type: 'string' },
        { name: 'timestamp', type: 'uint64' },
        { name: 'proposal', type: 'bytes32' },
        { name: 'choice', type: 'uint32' },
      ],
      { from: USER, space: 'dao.eth', timestamp: '1700000000', proposal: `0x${'55'.repeat(32)}`, choice: '1' },
      { name: 'snapshot', version: '0.1.4' },
    );
    const login = simple('Login', [{ name: 'wallet', type: 'address' }, { name: 'nonce', type: 'bytes32' }, { name: 'issuedAt', type: 'string' }], {
      wallet: USER,
      nonce: `0x${'66'.repeat(32)}`,
      issuedAt: '2026-09-30',
    });
    const seaport = seaportOrder([nft(BAYC, '7')], [erc20Item(WETH, '9000000000000000000', USER)], USER, { zoneHash: `0x${'77'.repeat(32)}`, conduitKey: `0x${'88'.repeat(32)}` });
    for (const data of [eip3009, vote, login, seaport]) {
      expect(decode(data).opaque).toBeUndefined();
    }
    // EIP-3009 through the generic path still checks the payee.
    expect(decode(eip3009).counterparty).toBe(RECIPIENT);
  });

  it('a Blur bulk-listing Root (a blind Merkle root of orders) is opaque', () => {
    const root = {
      types: { EIP712Domain: DOMAIN_TYPE_4, Root: [{ name: 'root', type: 'bytes32' }] },
      primaryType: 'Root',
      domain: { name: 'Blur Exchange', version: '1.0', chainId: 1, verifyingContract: '0x000000000000ad05ccc4f10045630fb830b95127' },
      message: { root: `0x${'ab'.repeat(32)}` },
    };
    expect(decode(root).opaque).toContain('blind bulk-listing signature');
  });

  it('legacy (v1) typed data with a bytes value is opaque', () => {
    const decoded = decodeTypedData(
      [
        { type: 'string', name: 'action', value: 'Execute' },
        { type: 'bytes', name: 'payload', value: TRANSFER_TO_DRAINER },
      ],
      USER,
      'eth_signTypedData v1',
    );
    expect(decoded.opaque).toContain('"payload" (bytes)');
    const plain = decodeTypedData([{ type: 'string', name: 'Message', value: 'Hi' }], USER, 'eth_signTypedData v1');
    expect(plain.opaque).toBeUndefined();
  });
});
