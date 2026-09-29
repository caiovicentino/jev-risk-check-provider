/**
 * @jest-environment node
 */
import { describe, expect, it } from '@jest/globals';

import {
  cleanText,
  decodePersonalSign,
  decodeSignature,
  decodeTransaction,
  decodeTypedData,
  extractAddresses,
  extractHosts,
  isOrderType,
  normalizeChainId,
  parseUint,
} from '../../src/decode';
import {
  BAYC,
  DAI,
  DOMAIN_TYPE_4,
  DRAINER,
  MAX_UINT160,
  MAX_UINT256,
  PERMIT2,
  RECIPIENT,
  REACTOR,
  UNIVERSAL_ROUTER,
  USDC,
  USER,
  calldata,
  daiPermit,
  eip712Hash,
  erc2612Permit,
  permitBatch,
  permitBatchTransferFrom,
  permitSingle,
  permitTransferFrom,
  uniswapXOrder,
  utf8Hex,
} from '../helpers';

const tx = (to: string | undefined, data: string, value: string = '0x0') => ({ from: USER, to, value, data });

describe('parsing helpers', () => {
  it('parses hex and decimal uints and rejects junk', () => {
    expect(parseUint('0x2386f26fc10000')).toBe(10_000_000_000_000_000n);
    expect(parseUint('10000000000000000')).toBe(10_000_000_000_000_000n);
    expect(parseUint(' 0x10 ')).toBe(16n);
    expect(parseUint(`0x${'0'.repeat(70)}de0b6b3a7640000`)).toBe(10n ** 18n);
    expect(parseUint(42)).toBe(42n);
    expect(parseUint('-1')).toBeUndefined();
    expect(parseUint('1e18')).toBeUndefined();
    expect(parseUint(1.5)).toBeUndefined();
    expect(parseUint(`0x1${'0'.repeat(64)}`)).toBeUndefined();
  });

  it('normalizes chain ids to CAIP-2', () => {
    expect(normalizeChainId('eip155:8453')).toBe('eip155:8453');
    expect(normalizeChainId(1)).toBe('eip155:1');
    expect(normalizeChainId(8453n)).toBe('eip155:8453');
    expect(normalizeChainId('0x2105')).toBe('eip155:8453');
    expect(normalizeChainId('137')).toBe('eip155:137');
    expect(normalizeChainId('solana:mainnet')).toBeUndefined();
    expect(normalizeChainId(0)).toBeUndefined();
  });

  it('extracts hosts from URLs and bare domains, and addresses only when exactly 20 bytes', () => {
    expect(extractHosts('go to https://Jup1ter-Audit.click/claim?x=1, or visit uniswap-airdrop.xyz now')).toStrictEqual([
      'jup1ter-audit.click',
      'uniswap-airdrop.xyz',
    ]);
    expect(extractHosts('version v1.2 e.g. something')).toStrictEqual([]);
    const hash = `0x${'ab'.repeat(32)}`;
    expect(extractAddresses(`hash ${hash} and ${RECIPIENT.toUpperCase().replace('0X', '0x')}`)).toStrictEqual([RECIPIENT]);
    expect(extractAddresses(`me ${USER}`, [USER])).toStrictEqual([]);
  });

  it('cleans invisible characters and collapses blobs', () => {
    const cleaned = cleanText(`pay\u202Egnp.exe\u200B now 0x${'ff'.repeat(40)}\n\tend`);
    expect(cleaned.hadInvisible).toBe(true);
    expect(cleaned.text).toBe('paygnp.exe now [40-byte hex data] end');
  });
});

describe('decodeTransaction', () => {
  it('native transfer: recipient, value as decimal payment (hex or decimal input)', () => {
    for (const value of ['0x2386f26fc10000', '10000000000000000']) {
      const decoded = decodeTransaction(tx(RECIPIENT, '0x', value), 'eip155:1');
      expect(decoded.counterparty).toBe(RECIPIENT);
      expect(decoded.role).toBe('recipient');
      expect(decoded.interaction).toStrictEqual({ type: 'native_transfer' });
      expect(decoded.payment).toStrictEqual({
        network: 'eip155:1',
        pay_to: RECIPIENT,
        amount: '10000000000000000',
        asset: 'native',
      });
      expect(decoded.summary).toBe(`Native transfer: sends 0.01 ETH (10000000000000000 wei) to recipient ${RECIPIENT}.`);
    }
    expect(decodeTransaction({ to: RECIPIENT, value: '0x1' }).interaction.type).toBe('native_transfer');
  });

  it('ERC-20 transfer: recipient, token as asset', () => {
    const decoded = decodeTransaction(tx(USDC, calldata('a9059cbb', RECIPIENT, 1_500_000n)), 'eip155:1');
    expect(decoded.counterparty).toBe(RECIPIENT);
    expect(decoded.interaction).toStrictEqual({ type: 'token_transfer' });
    expect(decoded.payment).toStrictEqual({ network: 'eip155:1', pay_to: RECIPIENT, amount: '1500000', asset: USDC });
    expect(decoded.summary).toContain(`sends 1.5 USDC (1500000 base units of ${USDC})`);
  });

  it('transferFrom: the `to` argument; amount omitted (ERC-20 amount or NFT id)', () => {
    const decoded = decodeTransaction(tx(BAYC, calldata('23b872dd', DRAINER, RECIPIENT, 77n)), 'eip155:1');
    expect(decoded.counterparty).toBe(RECIPIENT);
    expect(decoded.interaction).toStrictEqual({ type: 'token_transfer' });
    expect(decoded.payment).toStrictEqual({ network: 'eip155:1', pay_to: RECIPIENT, asset: BAYC });
    expect(decoded.warnings.join()).toContain(`pulled from ${DRAINER}`);
  });

  it('approve(spender, MAX): spender is checked, never the token; UNLIMITED', () => {
    const decoded = decodeTransaction(tx(USDC, calldata('095ea7b3', DRAINER, MAX_UINT256)), 'eip155:1');
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.counterparty).not.toBe(USDC);
    expect(decoded.role).toBe('spender');
    expect(decoded.unlimited).toBe(true);
    expect(decoded.interaction).toStrictEqual({ type: 'token_approval', unlimited: true });
    expect(decoded.summary).toContain('UNLIMITED allowance (max uint256)');
  });

  it('approve thresholds: >= 2^255 unlimited, >= 10^30 effectively unlimited, below is not', () => {
    const at = decodeTransaction(tx(USDC, calldata('095ea7b3', DRAINER, 1n << 255n)));
    expect(at.interaction).toStrictEqual({ type: 'token_approval', unlimited: true });
    const effectively = decodeTransaction(tx(USDC, calldata('095ea7b3', DRAINER, (1n << 255n) - 1n)));
    expect(effectively.interaction).toStrictEqual({ type: 'token_approval', unlimited: true });
    expect(effectively.warnings).toContain('the allowance is effectively unlimited (at least 10^30 base units)');
    const small = decodeTransaction(tx(USDC, calldata('095ea7b3', UNIVERSAL_ROUTER, 1000n)));
    expect(small.interaction).toStrictEqual({ type: 'token_approval' });
    expect(small.amountLabel).toBe('1000 base units');
  });

  it('setApprovalForAll: operator; true is nft_approval, false is contract_call', () => {
    const granted = decodeTransaction(tx(BAYC, calldata('a22cb465', DRAINER, 1n)));
    expect(granted.counterparty).toBe(DRAINER);
    expect(granted.role).toBe('operator');
    expect(granted.interaction).toStrictEqual({ type: 'nft_approval' });
    expect(granted.unlimited).toBe(true);
    const revoked = decodeTransaction(tx(BAYC, calldata('a22cb465', DRAINER, 0n)));
    expect(revoked.interaction).toStrictEqual({ type: 'contract_call' });
    expect(revoked.unlimited).toBe(false);
  });

  it('safeTransferFrom (with and without bytes) and ERC-1155 transfers check the `to` argument', () => {
    const plain = decodeTransaction(tx(BAYC, calldata('42842e0e', USER, RECIPIENT, 5n)));
    expect(plain.counterparty).toBe(RECIPIENT);
    expect(plain.interaction).toStrictEqual({ type: 'token_transfer' });
    expect(decodeTransaction(tx(BAYC, calldata('b88d4fde', USER, RECIPIENT, 5n, 0x80n, 0n))).counterparty).toBe(RECIPIENT);
    const erc1155 = decodeTransaction(tx(BAYC, calldata('f242432a', USER, RECIPIENT, 5n, 3n, 0xa0n, 0n)));
    expect(erc1155.counterparty).toBe(RECIPIENT);
    expect(decodeTransaction(tx(BAYC, calldata('2eb2c2d6', USER, RECIPIENT, 0xa0n, 0xc0n, 0xe0n))).counterparty).toBe(RECIPIENT);
  });

  it('Permit2 approve(token, spender, amount, expiration): spender (2nd arg), token asset', () => {
    const decoded = decodeTransaction(tx(PERMIT2, calldata('87517c45', USDC, DRAINER, MAX_UINT160, 1790000000n)), 1);
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.interaction).toStrictEqual({ type: 'token_approval', unlimited: true });
    expect(decoded.payment).toStrictEqual({ network: 'eip155:1', pay_to: DRAINER, amount: MAX_UINT160.toString(), asset: USDC });
    expect(decoded.warnings).toHaveLength(0);
    const fake = decodeTransaction(tx(DRAINER, calldata('87517c45', USDC, DRAINER, 5n, 0n)));
    expect(fake.warnings.join()).toContain('not the canonical Permit2 contract');
    expect(decodeTransaction(tx(PERMIT2, calldata('87517c45', USDC, DRAINER, 0n, 0n))).interaction.type).toBe('contract_call');
  });

  it('EIP-2612 permit(...) submitted on-chain: spender', () => {
    const decoded = decodeTransaction(
      tx(USDC, calldata('d505accf', USER, DRAINER, MAX_UINT256, 1790000000n, 27n, `0x${'11'.repeat(32)}`, `0x${'22'.repeat(32)}`)),
    );
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.interaction).toStrictEqual({ type: 'token_approval', unlimited: true });
  });

  it('unknown selector: the contract called; with ETH value the contract is the payment recipient', () => {
    const decoded = decodeTransaction(tx(UNIVERSAL_ROUTER, calldata('deadbeef', 1n, 2n), '0xde0b6b3a7640000'), 'eip155:1');
    expect(decoded.counterparty).toBe(UNIVERSAL_ROUTER);
    expect(decoded.role).toBe('contract');
    expect(decoded.interaction).toStrictEqual({ type: 'contract_call' });
    expect(decoded.payment).toStrictEqual({ network: 'eip155:1', pay_to: UNIVERSAL_ROUTER, amount: '1000000000000000000', asset: 'native' });
    expect(decoded.summary).toContain('function selector 0xdeadbeef');
  });

  it('flags non-canonical address padding', () => {
    const dirty = `0x095ea7b3${'ff'.repeat(12)}${DRAINER.slice(2)}${(5n).toString(16).padStart(64, '0')}`;
    const decoded = decodeTransaction(tx(USDC, dirty));
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.warnings.join()).toContain('non-zero padding');
  });

  it('contract deployment (no `to`) has no counterparty and a local note', () => {
    for (const to of [undefined, null, '', '0x']) {
      const decoded = decodeTransaction({ from: USER, to, data: '0x6080', value: '0x0' });
      expect(decoded.counterparty).toBeUndefined();
      expect(decoded.localNote).toContain('deploys a new contract');
    }
  });

  it('an invalid `to` is not checked', () => {
    const decoded = decodeTransaction({ from: USER, to: '0x1234', data: '0x' });
    expect(decoded.counterparty).toBeUndefined();
    expect(decoded.localNote).toContain('not a valid EVM address');
  });
});

describe('decodeTypedData (v3/v4)', () => {
  it('Permit2 PermitSingle: legit router vs drainer resolve to their own spenders', () => {
    const legit = decodeTypedData(permitSingle(UNIVERSAL_ROUTER), USER);
    const drainer = decodeTypedData(permitSingle(DRAINER), USER);
    expect(legit.counterparty).toBe(UNIVERSAL_ROUTER);
    expect(drainer.counterparty).toBe(DRAINER);
    expect(drainer.role).toBe('spender');
    expect(drainer.chain).toBe('eip155:1');
    expect(drainer.interaction).toStrictEqual({ type: 'permit_signature', unlimited: true });
    expect(drainer.payment).toStrictEqual({ network: 'eip155:1', pay_to: DRAINER, amount: MAX_UINT160.toString(), asset: USDC });
    expect(legit.summary).not.toBe(drainer.summary);
  });

  it('Permit2 amounts: 1000 is limited, 0 grants nothing, 2^159 and above are unlimited', () => {
    expect(decodeTypedData(permitSingle(DRAINER, '1000'), USER).interaction).toStrictEqual({ type: 'permit_signature' });
    expect(decodeTypedData(permitSingle(DRAINER, '0'), USER).interaction).toStrictEqual({ type: 'message_signature' });
    expect(decodeTypedData(permitSingle(DRAINER, (1n << 159n).toString()), USER).interaction).toStrictEqual({
      type: 'permit_signature',
      unlimited: true,
    });
  });

  it('accepts typed data given as a JSON string', () => {
    expect(decodeTypedData(JSON.stringify(permitSingle(DRAINER)), USER).counterparty).toBe(DRAINER);
  });

  it('Permit2 message with a non-canonical verifying contract is flagged', () => {
    const decoded = decodeTypedData(permitSingle(DRAINER, '5', DRAINER), USER);
    expect(decoded.warnings.join()).toContain('not the canonical Permit2 contract');
  });

  it('Permit2 PermitBatch: spender, all tokens listed', () => {
    const data = permitBatch(DRAINER, [
      { token: USDC, amount: '5' },
      { token: DAI, amount: MAX_UINT160.toString() },
    ]);
    expect(() => eip712Hash(data)).not.toThrow();
    const decoded = decodeTypedData(data, USER);
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.interaction).toStrictEqual({ type: 'permit_signature', unlimited: true });
    expect(decoded.payment).toStrictEqual({ network: 'eip155:1', pay_to: DRAINER });
    expect(decoded.summary).toContain(USDC);
    expect(decoded.summary).toContain(DAI);
  });

  it('Permit2 SignatureTransfer (plain, batch and witness): spender', () => {
    const single = decodeTypedData(permitTransferFrom(DRAINER, USDC, MAX_UINT256.toString()), USER);
    expect(single.counterparty).toBe(DRAINER);
    expect(single.interaction).toStrictEqual({ type: 'permit_signature', unlimited: true });
    expect(single.summary).toContain('lets spender');
    const batch = decodeTypedData(
      permitBatchTransferFrom(DRAINER, [
        { token: USDC, amount: '10' },
        { token: DAI, amount: '20' },
      ]),
      USER,
    );
    expect(batch.counterparty).toBe(DRAINER);
    expect(batch.interaction).toStrictEqual({ type: 'permit_signature' });
    const witness = decodeTypedData(uniswapXOrder([{ token: USDC, amount: '9', recipient: USER }]), USER);
    expect(witness.counterparty).toBe(REACTOR);
    expect(witness.summary).toContain('V2DutchOrder');
  });

  it('EIP-2612 Permit: spender, token from the domain, chain from hex chainId', () => {
    const decoded = decodeTypedData(erc2612Permit(DRAINER, '1000000', '0x2105'), USER);
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.chain).toBe('eip155:8453');
    expect(decoded.interaction).toStrictEqual({ type: 'permit_signature' });
    expect(decoded.payment).toStrictEqual({ network: 'eip155:8453', pay_to: DRAINER, amount: '1000000', asset: USDC });
    expect(decodeTypedData(erc2612Permit(DRAINER, MAX_UINT256.toString()), USER).interaction).toStrictEqual({
      type: 'permit_signature',
      unlimited: true,
    });
    expect(decodeTypedData(erc2612Permit(DRAINER, 0), USER).interaction).toStrictEqual({ type: 'message_signature' });
  });

  it('DAI-style Permit: allowed=true is unlimited, false grants nothing', () => {
    const granted = decodeTypedData(daiPermit(true), USER);
    expect(granted.counterparty).toBe(DRAINER);
    expect(granted.interaction).toStrictEqual({ type: 'permit_signature', unlimited: true });
    expect(granted.unlimited).toBe(true);
    expect(decodeTypedData(daiPermit(false), USER).interaction).toStrictEqual({ type: 'message_signature' });
  });

  it('other marketplace orders are order_signature', () => {
    const order = {
      types: {
        EIP712Domain: DOMAIN_TYPE_4,
        Order: [
          { name: 'maker', type: 'address' },
          { name: 'taker', type: 'address' },
          { name: 'price', type: 'uint256' },
        ],
      },
      primaryType: 'Order',
      domain: { name: '0x Protocol', version: '1', chainId: 1, verifyingContract: DRAINER },
      message: { maker: USER, taker: RECIPIENT, price: '1' },
    };
    const decoded = decodeTypedData(order, USER);
    expect(decoded.interaction).toStrictEqual({ type: 'order_signature' });
    expect(decoded.counterparty).toBe(RECIPIENT);
    expect(isOrderType('Root', 'Blur Exchange')).toBe(true);
    expect(isOrderType('Maker')).toBe(true);
    expect(isOrderType('Mail')).toBe(false);
  });

  it('generic typed data: declared address fields only, preferred keys first, signer and contract excluded', () => {
    const data = {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' },
        ],
        Delegation: [
          { name: 'owner', type: 'address' },
          { name: 'contract', type: 'address' },
          { name: 'note', type: 'string' },
          { name: 'nested', type: 'Nested' },
        ],
        Nested: [
          { name: 'delegate', type: 'address' },
          { name: 'other', type: 'address' },
        ],
      },
      primaryType: 'Delegation',
      domain: { name: 'Some dApp', chainId: 10, verifyingContract: USDC },
      message: { owner: USER, contract: USDC, note: `pay ${RECIPIENT}`, nested: { delegate: DRAINER, other: RECIPIENT }, spender: UNIVERSAL_ROUTER },
    };
    const decoded = decodeTypedData(data, USER);
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.role).toBe('delegate');
    expect(decoded.chain).toBe('eip155:10');
    expect(decoded.interaction).toStrictEqual({ type: 'message_signature' });
    expect(decoded.summary).toContain('counterparty taken from field "nested.delegate"');
    // The undeclared `spender` key is never read.
    expect([decoded.counterparty, ...decoded.others.map((other) => other.address)]).not.toContain(UNIVERSAL_ROUTER);
  });

  it('generic typed data without addresses falls back to the verifying contract, then the signer', () => {
    const login = (withContract: boolean) => ({
      types: {
        EIP712Domain: withContract ? [{ name: 'verifyingContract', type: 'address' }] : [],
        Login: [{ name: 'nonce', type: 'uint256' }],
      },
      primaryType: 'Login',
      domain: withContract ? { verifyingContract: RECIPIENT } : {},
      message: { nonce: 1 },
    });
    const withContract = decodeTypedData(login(true), USER);
    expect(withContract.counterparty).toBe(RECIPIENT);
    expect(withContract.role).toBe('contract');
    const signerOnly = decodeTypedData(login(false), USER);
    expect(signerOnly.counterparty).toBe(USER);
    expect(signerOnly.role).toBe('signer');
    expect(signerOnly.summary).toContain('no counterparty address in message; subject is the signer');
  });
});

describe('decodeTypedData (v1 array)', () => {
  it('checks the address-typed value that is not the signer', () => {
    const decoded = decodeTypedData(
      [
        { type: 'string', name: 'Message', value: 'Hi' },
        { type: 'address', name: 'owner', value: USER },
        { type: 'address', name: 'to', value: RECIPIENT },
      ],
      USER,
      'eth_signTypedData v1',
    );
    expect(decoded.counterparty).toBe(RECIPIENT);
    expect(decoded.role).toBe('recipient');
    expect(decoded.interaction).toStrictEqual({ type: 'message_signature' });
    expect(decoded.summary).toContain('Message (string) = Hi');
  });

  it('falls back to the signer when only the signer is named', () => {
    const decoded = decodeTypedData([{ type: 'address', name: 'owner', value: USER }], USER);
    expect(decoded.counterparty).toBe(USER);
    expect(decoded.summary).toContain('No counterparty address in message; subject is the signer');
  });
});

describe('decodePersonalSign', () => {
  it('decodes hex to text, extracts the URL host, and never takes an address from the hex', () => {
    const message = 'Claim your airdrop at https://jup1ter-audit.click/claim now';
    const hex = utf8Hex(message);
    const decoded = decodePersonalSign(hex, USER);
    expect(decoded.counterparty).toBe(USER);
    expect(decoded.counterparty).not.toBe(`0x${hex.slice(2, 42)}`);
    expect(decoded.role).toBe('signer');
    expect(decoded.referencedHosts).toStrictEqual(['jup1ter-audit.click']);
    expect(decoded.interaction).toStrictEqual({ type: 'message_signature' });
    expect(decoded.summary).toContain(`"${message}"`);
    expect(decoded.summary).toContain('No counterparty address in message; subject is the signer.');
  });

  it('uses an address named in the text as the counterparty', () => {
    const decoded = decodePersonalSign(utf8Hex(`I approve transfers to ${DRAINER} for my vault ${USER}`), USER);
    expect(decoded.counterparty).toBe(DRAINER);
    expect(decoded.role).toBe('counterparty');
    expect(decoded.others).toStrictEqual([]);
  });

  it('binary payloads are described, and a 32-byte hash is flagged', () => {
    const decoded = decodePersonalSign(`0x${'9f'.repeat(32)}`, USER);
    expect(decoded.counterparty).toBe(USER);
    expect(decoded.summary).toContain('binary data (32 bytes)');
    expect(decoded.warnings.join()).toContain('looks like a hash');
  });

  it('parses Sign-In with Ethereum and flags a domain mismatch with the requesting site', () => {
    const siwe = [
      'app.uniswap.org wants you to sign in with your Ethereum account:',
      USER,
      '',
      'Sign in to Uniswap.',
      '',
      'URI: https://app.uniswap.org',
      'Version: 1',
      'Chain ID: 8453',
      'Nonce: abc123',
      'Issued At: 2026-09-29T10:00:00Z',
    ].join('\n');
    const decoded = decodePersonalSign(utf8Hex(siwe), USER, 'uniswap-login.xyz');
    expect(decoded.chain).toBe('eip155:8453');
    expect(decoded.counterparty).toBe(USER);
    expect(decoded.referencedHosts?.[0]).toBe('app.uniswap.org');
    expect(decoded.warnings.join()).toContain('is for app.uniswap.org but was requested by uniswap-login.xyz');
    // CRLF line endings parse too.
    expect(decodePersonalSign(utf8Hex(siwe.replace(/\n/gu, '\r\n')), USER, 'uniswap-login.xyz').chain).toBe('eip155:8453');
  });

  it('flattens JSON messages and caps the excerpt at 300 chars', () => {
    const json = decodePersonalSign(utf8Hex(JSON.stringify({ action: 'login', nonce: 7 })), USER);
    expect(json.summary).toContain('JSON message: action=login; nonce=7');
    const long = decodePersonalSign(utf8Hex(`Welcome! ${'lorem ipsum '.repeat(100)}`), USER);
    const excerpt = /"(.*)"/u.exec(long.summary)?.[1] ?? '';
    expect(excerpt.length).toBeLessThanOrEqual(300);
  });

  it('flags hidden text-direction characters', () => {
    const decoded = decodePersonalSign(utf8Hex('Approve \u202Etxt.exe'), USER);
    expect(decoded.warnings.join()).toContain('invisible or text-direction control characters');
  });
});

describe('decodeSignature dispatch', () => {
  it('routes by method and by data shape', () => {
    expect(decodeSignature({ from: USER, data: permitSingle(DRAINER), signatureMethod: 'eth_signTypedData_v4' }).counterparty).toBe(DRAINER);
    expect(decodeSignature({ from: USER, data: permitSingle(DRAINER), signatureMethod: 'eth_signTypedData_v3' }).counterparty).toBe(DRAINER);
    expect(decodeSignature({ from: USER, data: permitSingle(DRAINER) }).counterparty).toBe(DRAINER);
    expect(decodeSignature({ from: USER, data: utf8Hex('hello'), signatureMethod: 'personal_sign' }).counterparty).toBe(USER);
  });
});
