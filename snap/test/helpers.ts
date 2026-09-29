/**
 * Shared fixtures and helpers for the unit and integration tests.
 *
 * Every typed-data fixture declares its full EIP-712 types, so it is exactly
 * what MetaMask can sign; `eip712Hash` (from @metamask/eth-sig-util, the
 * encoder MetaMask uses) proves it in the tests.
 */
import { SignTypedDataVersion, TypedDataUtils } from '@metamask/eth-sig-util';

export type Hex = `0x${string}`;

export const USER = '0xb48057e647b2572f5eae241b515fbc58b7ce249e' as const;
export const RECIPIENT = '0xbf88b1f49b5e8ec386289341c4a5ee00bb0e0178' as const;
export const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' as const;
export const USDT = '0xdac17f958d2ee523a2206206994597c13d831ec7' as const;
export const DAI = '0x6b175474e89094c44da98b954eedeac495271d0f' as const;
export const WETH = '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2' as const;
export const DRAINER = '0x9d17bb55b57b31329cf01aa7017948e398b277bc' as const;
export const UNIVERSAL_ROUTER = '0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad' as const;
export const PERMIT2 = '0x000000000022d473030f116ddee9f6b43ac78ba3' as const;
export const SEAPORT = '0x0000000000000068f116a894984e2db1123eb395' as const;
export const OPENSEA_FEE = '0x0000a26b00c1f0df003000390027140000faa719' as const;
export const BAYC = '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d' as const;
export const NPM = '0xc36442b4a4522e871399cd717abdd847ab11fe88' as const;
export const SAFE = '0x1111111111111111111111111111111111111111' as const;
export const REACTOR = '0x00000011f84b9aa48e5f8aa8b9897600006289be' as const;
export const BLUR_EXCHANGE = '0x000000000000ad05ccc4f10045630fb830b95127' as const;
export const LOOKSRARE = '0x0000000000e655fae4d56241588680f86e3b2377' as const;
export const MULTISEND_CALL_ONLY = '0x40a2accbd92bca938b02010e17a5b8929b49130d' as const;
export const ZERO = '0x0000000000000000000000000000000000000000' as const;
export const B32_ZERO = `0x${'0'.repeat(64)}` as const;
export const MAX_UINT256 = (1n << 256n) - 1n;
export const MAX_UINT160 = (1n << 160n) - 1n;

// ---------------------------------------------------------------------------
// ABI encoding
// ---------------------------------------------------------------------------

/** ABI-encodes one static argument as a 32-byte word (hex, no 0x). */
export const word = (value: bigint | string): string =>
  typeof value === 'string'
    ? value.toLowerCase().replace(/^0x/u, '').padStart(64, '0')
    : value.toString(16).padStart(64, '0');

/** Builds calldata from a 4-byte selector (no 0x) and static arguments. */
export const calldata = (selector: string, ...args: (bigint | string)[]): Hex =>
  `0x${selector}${args.map(word).join('')}`;

export const utf8Hex = (text: string): Hex => `0x${Buffer.from(text, 'utf8').toString('hex')}`;

const strip = (hex: string) => hex.replace(/^0x/u, '');
const padRight = (hex: string) => hex + '0'.repeat((64 - (hex.length % 64)) % 64);

/** ABI `bytes` payload (length word + right-padded data). */
export const encBytes = (hex: string): string => word(BigInt(strip(hex).length / 2)) + padRight(strip(hex));

/** ABI `bytes[]` payload (length, offsets, items). */
export function encBytesArray(items: string[]): string {
  let head = word(BigInt(items.length));
  let tail = '';
  let offset = items.length * 32;
  for (const item of items) {
    head += word(BigInt(offset));
    const encoded = encBytes(item);
    tail += encoded;
    offset += encoded.length / 2;
  }
  return head + tail;
}

export const multicall = (inner: string[]): Hex => `0xac9650d8${word(0x20n)}${encBytesArray(inner)}`;
export const multicallDeadline = (inner: string[]): Hex => `0x5ae401dc${word(1790000000n)}${word(0x40n)}${encBytesArray(inner)}`;

/** Safe execTransaction(to, value, data, operation, 0, 0, gasPrice, 0, refundReceiver, signatures). */
export function safeExec(to: string, value: bigint, data: string, operation: 0 | 1, gasPrice = 0n, refundReceiver: string = ZERO): Hex {
  const dataEncoded = encBytes(data);
  const signatureOffset = 0x140 + dataEncoded.length / 2;
  return `0x6a761202${word(to)}${word(value)}${word(0x140n)}${word(BigInt(operation))}${word(0n)}${word(0n)}${word(gasPrice)}${word(ZERO)}${word(refundReceiver)}${word(BigInt(signatureOffset))}${dataEncoded}${encBytes(`0x${'ab'.repeat(65)}`)}`;
}

/** Safe multiSend(bytes) with packed (operation, to, value, length, data) entries. */
export function multiSend(entries: { operation: 0 | 1; to: string; value: bigint; data: string }[]): Hex {
  const packed = entries
    .map((entry) => `${entry.operation.toString(16).padStart(2, '0')}${strip(entry.to)}${word(entry.value)}${word(BigInt(strip(entry.data).length / 2))}${strip(entry.data)}`)
    .join('');
  return `0x8d80ff0a${word(0x20n)}${encBytes(`0x${packed}`)}`;
}

/** Universal Router execute(bytes commands, bytes[] inputs, uint256 deadline). */
export function routerExecute(commands: number[], inputs: string[], withDeadline = true): Hex {
  const commandBytes = `0x${commands.map((command) => command.toString(16).padStart(2, '0')).join('')}`;
  const commandsEncoded = encBytes(commandBytes);
  if (withDeadline) {
    return `0x3593564c${word(0x60n)}${word(BigInt(0x60 + commandsEncoded.length / 2))}${word(1790000000n)}${commandsEncoded}${encBytesArray(inputs)}`;
  }
  return `0x24856bc3${word(0x40n)}${word(BigInt(0x40 + commandsEncoded.length / 2))}${commandsEncoded}${encBytesArray(inputs)}`;
}

/** UR PERMIT2_PERMIT input: (PermitSingle, bytes signature). */
export const urPermit2Permit = (token: string, amount: bigint, spender: string): string =>
  `0x${word(token)}${word(amount)}${word(1790000000n)}${word(0n)}${word(spender)}${word(1790000000n)}${word(0xe0n)}${encBytes(`0x${'cd'.repeat(65)}`)}`;

/** UR TRANSFER / SWEEP input: (token, recipient, value). */
export const urTokenRecipient = (token: string, recipient: string, value: bigint): string =>
  `0x${word(token)}${word(recipient)}${word(value)}`;

/** ERC-7579 execute(bytes32 mode, bytes executionCalldata). */
export function execute7579(callType: 'single' | 'batch' | 'delegate', calls: { to: string; value: bigint; data: string }[]): Hex {
  let execution: string;
  let mode: string;
  if (callType === 'batch') {
    mode = `01${'0'.repeat(62)}`;
    // abi.encode(Execution[]): offset, length, tuple offsets, tuples.
    const tuples = calls.map((call) => `${word(call.to)}${word(call.value)}${word(0x60n)}${encBytes(call.data)}`);
    let offsets = '';
    let offset = calls.length * 32;
    for (const tuple of tuples) {
      offsets += word(BigInt(offset));
      offset += tuple.length / 2;
    }
    execution = `0x${word(0x20n)}${word(BigInt(calls.length))}${offsets}${tuples.join('')}`;
  } else {
    const [call] = calls as [{ to: string; value: bigint; data: string }];
    mode = `${callType === 'single' ? '00' : 'ff'}${'0'.repeat(62)}`;
    execution = callType === 'single' ? `0x${strip(call.to)}${word(call.value)}${strip(call.data)}` : `0x${strip(call.to)}${strip(call.data)}`;
  }
  return `0xe9ae5c53${mode}${word(0x40n)}${encBytes(execution)}`;
}

/** ERC-4337 SimpleAccount execute(address,uint256,bytes). */
export const execute4337 = (to: string, value: bigint, data: string): Hex =>
  `0xb61d27f6${word(to)}${word(value)}${word(0x60n)}${encBytes(data)}`;

// ---------------------------------------------------------------------------
// EIP-712
// ---------------------------------------------------------------------------

/** The hash MetaMask signs for eth_signTypedData_v4 (throws when unsignable). */
export function eip712Hash(data: unknown): string {
  return Buffer.from(TypedDataUtils.eip712Hash(data as never, SignTypedDataVersion.V4)).toString('hex');
}

export const DOMAIN_TYPE_4 = [
  { name: 'name', type: 'string' },
  { name: 'version', type: 'string' },
  { name: 'chainId', type: 'uint256' },
  { name: 'verifyingContract', type: 'address' },
];
const DOMAIN_TYPE_3 = [
  { name: 'name', type: 'string' },
  { name: 'chainId', type: 'uint256' },
  { name: 'verifyingContract', type: 'address' },
];

export const PERMIT_TYPES = {
  EIP712Domain: DOMAIN_TYPE_4,
  Permit: [
    { name: 'owner', type: 'address' },
    { name: 'spender', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'nonce', type: 'uint256' },
    { name: 'deadline', type: 'uint256' },
  ],
};

export function erc2612Permit(spender: unknown, value: unknown, chainId: unknown = 1, extra: Record<string, unknown> = {}) {
  return {
    types: PERMIT_TYPES,
    primaryType: 'Permit',
    domain: { name: 'USD Coin', version: '2', chainId, verifyingContract: USDC },
    message: { owner: USER, spender, value, nonce: 0, deadline: '1790000000', ...extra },
  };
}

export const DAI_PERMIT_TYPES = {
  EIP712Domain: DOMAIN_TYPE_4,
  Permit: [
    { name: 'holder', type: 'address' },
    { name: 'spender', type: 'address' },
    { name: 'nonce', type: 'uint256' },
    { name: 'expiry', type: 'uint256' },
    { name: 'allowed', type: 'bool' },
  ],
};

export function daiPermit(allowed: unknown, spender: unknown = DRAINER) {
  return {
    types: DAI_PERMIT_TYPES,
    primaryType: 'Permit',
    domain: { name: 'Dai Stablecoin', version: '1', chainId: 1, verifyingContract: DAI },
    message: { holder: USER, spender, nonce: 0, expiry: 0, allowed },
  };
}

const PERMIT_DETAILS = [
  { name: 'token', type: 'address' },
  { name: 'amount', type: 'uint160' },
  { name: 'expiration', type: 'uint48' },
  { name: 'nonce', type: 'uint48' },
];

export function permitSingle(spender: unknown, amount: unknown = MAX_UINT160.toString(), verifyingContract: string = PERMIT2) {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE_3,
      PermitDetails: PERMIT_DETAILS,
      PermitSingle: [
        { name: 'details', type: 'PermitDetails' },
        { name: 'spender', type: 'address' },
        { name: 'sigDeadline', type: 'uint256' },
      ],
    },
    primaryType: 'PermitSingle',
    domain: { name: 'Permit2', chainId: 1, verifyingContract },
    message: {
      details: { token: USDC, amount, expiration: '1790000000', nonce: '0' },
      spender,
      sigDeadline: '1790000000',
    },
  };
}

export function permitBatch(spender: string, details: { token: string; amount: string }[]) {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE_3,
      PermitDetails: PERMIT_DETAILS,
      PermitBatch: [
        { name: 'details', type: 'PermitDetails[]' },
        { name: 'spender', type: 'address' },
        { name: 'sigDeadline', type: 'uint256' },
      ],
    },
    primaryType: 'PermitBatch',
    domain: { name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 },
    message: {
      details: details.map((detail) => ({ ...detail, expiration: '0', nonce: '0' })),
      spender,
      sigDeadline: '1790000000',
    },
  };
}

const TOKEN_PERMISSIONS = [
  { name: 'token', type: 'address' },
  { name: 'amount', type: 'uint256' },
];

export function permitTransferFrom(spender: string, token: string, amount: string) {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE_3,
      TokenPermissions: TOKEN_PERMISSIONS,
      PermitTransferFrom: [
        { name: 'permitted', type: 'TokenPermissions' },
        { name: 'spender', type: 'address' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
      ],
    },
    primaryType: 'PermitTransferFrom',
    domain: { name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 },
    message: { permitted: { token, amount }, spender, nonce: '1', deadline: '1790000000' },
  };
}

export function permitBatchTransferFrom(spender: string, permitted: { token: string; amount: string }[]) {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE_3,
      TokenPermissions: TOKEN_PERMISSIONS,
      PermitBatchTransferFrom: [
        { name: 'permitted', type: 'TokenPermissions[]' },
        { name: 'spender', type: 'address' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
      ],
    },
    primaryType: 'PermitBatchTransferFrom',
    domain: { name: 'Permit2', chainId: 1, verifyingContract: PERMIT2 },
    message: { permitted, spender, nonce: '1', deadline: '1790000000' },
  };
}

/** UniswapX V2 Dutch order signed through Permit2 PermitWitnessTransferFrom. */
export function uniswapXOrder(outputs: { token: string; amount: string; recipient: string }[], swapper: string = USER) {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE_3,
      PermitWitnessTransferFrom: [
        { name: 'permitted', type: 'TokenPermissions' },
        { name: 'spender', type: 'address' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
        { name: 'witness', type: 'V2DutchOrder' },
      ],
      TokenPermissions: TOKEN_PERMISSIONS,
      V2DutchOrder: [
        { name: 'info', type: 'OrderInfo' },
        { name: 'cosigner', type: 'address' },
        { name: 'baseInputToken', type: 'address' },
        { name: 'baseInputStartAmount', type: 'uint256' },
        { name: 'baseInputEndAmount', type: 'uint256' },
        { name: 'baseOutputs', type: 'DutchOutput[]' },
      ],
      OrderInfo: [
        { name: 'reactor', type: 'address' },
        { name: 'swapper', type: 'address' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
        { name: 'additionalValidationContract', type: 'address' },
        { name: 'additionalValidationData', type: 'bytes' },
      ],
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
      permitted: { token: USDC, amount: '10000000000' },
      spender: REACTOR,
      nonce: '1',
      deadline: '1790000000',
      witness: {
        info: { reactor: REACTOR, swapper, nonce: '1', deadline: '1790000000', additionalValidationContract: ZERO, additionalValidationData: '0x' },
        cosigner: '0x0000000000000000000000000000000000000abc',
        baseInputToken: USDC,
        baseInputStartAmount: '10000000000',
        baseInputEndAmount: '10000000000',
        baseOutputs: outputs.map((output) => ({ token: output.token, startAmount: output.amount, endAmount: output.amount, recipient: output.recipient })),
      },
    },
  };
}

export const SEAPORT_TYPES = {
  EIP712Domain: DOMAIN_TYPE_4,
  OrderComponents: [
    { name: 'offerer', type: 'address' },
    { name: 'zone', type: 'address' },
    { name: 'offer', type: 'OfferItem[]' },
    { name: 'consideration', type: 'ConsiderationItem[]' },
    { name: 'orderType', type: 'uint8' },
    { name: 'startTime', type: 'uint256' },
    { name: 'endTime', type: 'uint256' },
    { name: 'zoneHash', type: 'bytes32' },
    { name: 'salt', type: 'uint256' },
    { name: 'conduitKey', type: 'bytes32' },
    { name: 'counter', type: 'uint256' },
  ],
  OfferItem: [
    { name: 'itemType', type: 'uint8' },
    { name: 'token', type: 'address' },
    { name: 'identifierOrCriteria', type: 'uint256' },
    { name: 'startAmount', type: 'uint256' },
    { name: 'endAmount', type: 'uint256' },
  ],
  ConsiderationItem: [
    { name: 'itemType', type: 'uint8' },
    { name: 'token', type: 'address' },
    { name: 'identifierOrCriteria', type: 'uint256' },
    { name: 'startAmount', type: 'uint256' },
    { name: 'endAmount', type: 'uint256' },
    { name: 'recipient', type: 'address' },
  ],
};

type SeaportItem = {
  itemType: string;
  token: string;
  identifierOrCriteria: string;
  startAmount: string;
  endAmount: string;
  recipient?: string;
};

export const SEAPORT_DOMAIN = { name: 'Seaport', version: '1.6', chainId: 1, verifyingContract: SEAPORT };

export function orderComponents(offer: SeaportItem[], consideration: SeaportItem[], offerer: string = USER, extra: Record<string, unknown> = {}) {
  return {
    offerer,
    zone: ZERO,
    offer,
    consideration,
    orderType: '0',
    startTime: '0',
    endTime: '1790000000',
    zoneHash: B32_ZERO,
    salt: '1',
    conduitKey: B32_ZERO,
    counter: '0',
    ...extra,
  };
}

export const EMPTY_ORDER = orderComponents([], [], ZERO, { endTime: '0', salt: '0' });

export function seaportOrder(offer: SeaportItem[], consideration: SeaportItem[], offerer: string = USER, extra: Record<string, unknown> = {}) {
  return { types: SEAPORT_TYPES, primaryType: 'OrderComponents', domain: SEAPORT_DOMAIN, message: orderComponents(offer, consideration, offerer, extra) };
}

/** Seaport BulkOrder of height 2 (four leaves). */
export function seaportBulkOrder(leaves: unknown[]) {
  const padded = [...leaves, EMPTY_ORDER, EMPTY_ORDER, EMPTY_ORDER, EMPTY_ORDER].slice(0, 4);
  return {
    types: { ...SEAPORT_TYPES, BulkOrder: [{ name: 'tree', type: 'OrderComponents[2][2]' }] },
    primaryType: 'BulkOrder',
    domain: SEAPORT_DOMAIN,
    message: { tree: [[padded[0], padded[1]], [padded[2], padded[3]]] },
  };
}

export const nft = (token: string, id: string): SeaportItem => ({ itemType: '2', token, identifierOrCriteria: id, startAmount: '1', endAmount: '1' });

export const eth = (wei: string, recipient: string, endWei: string = wei): SeaportItem => ({
  itemType: '0',
  token: ZERO,
  identifierOrCriteria: '0',
  startAmount: wei,
  endAmount: endWei,
  recipient,
});

export const erc20Item = (token: string, amount: string, recipient: string): SeaportItem => ({
  itemType: '1',
  token,
  identifierOrCriteria: '0',
  startAmount: amount,
  endAmount: amount,
  recipient,
});

export const BLUR_TYPES = {
  EIP712Domain: DOMAIN_TYPE_4,
  Order: [
    { name: 'trader', type: 'address' },
    { name: 'side', type: 'uint8' },
    { name: 'matchingPolicy', type: 'address' },
    { name: 'collection', type: 'address' },
    { name: 'tokenId', type: 'uint256' },
    { name: 'amount', type: 'uint256' },
    { name: 'paymentToken', type: 'address' },
    { name: 'price', type: 'uint256' },
    { name: 'listingTime', type: 'uint256' },
    { name: 'expirationTime', type: 'uint256' },
    { name: 'fees', type: 'Fee[]' },
    { name: 'salt', type: 'uint256' },
    { name: 'extraParams', type: 'bytes' },
    { name: 'nonce', type: 'uint256' },
  ],
  Fee: [
    { name: 'rate', type: 'uint16' },
    { name: 'recipient', type: 'address' },
  ],
};

const BLUR_DOMAIN = { name: 'Blur Exchange', version: '1.0', chainId: 1, verifyingContract: BLUR_EXCHANGE };

export function blurOrder(price: string, side = 1, fees: { rate: number; recipient: string }[] = []) {
  return {
    types: BLUR_TYPES,
    primaryType: 'Order',
    domain: BLUR_DOMAIN,
    message: {
      trader: USER,
      side,
      matchingPolicy: '0x0000000000dab4a563819e8fd93dba3b25bc3495',
      collection: BAYC,
      tokenId: '1',
      amount: '1',
      paymentToken: ZERO,
      price,
      listingTime: '0',
      expirationTime: '1790000000',
      fees,
      salt: '1',
      extraParams: '0x',
      nonce: '0',
    },
  };
}

export function blurRoot() {
  return {
    types: { EIP712Domain: DOMAIN_TYPE_4, Root: [{ name: 'root', type: 'bytes32' }] },
    primaryType: 'Root',
    domain: BLUR_DOMAIN,
    message: { root: `0x${'ab'.repeat(32)}` },
  };
}

export function looksRareMaker(price: string, quoteType = 1) {
  return {
    types: {
      EIP712Domain: DOMAIN_TYPE_4,
      Maker: [
        { name: 'quoteType', type: 'uint8' },
        { name: 'globalNonce', type: 'uint256' },
        { name: 'subsetNonce', type: 'uint256' },
        { name: 'orderNonce', type: 'uint256' },
        { name: 'strategyId', type: 'uint256' },
        { name: 'collectionType', type: 'uint8' },
        { name: 'collection', type: 'address' },
        { name: 'currency', type: 'address' },
        { name: 'signer', type: 'address' },
        { name: 'startTime', type: 'uint256' },
        { name: 'endTime', type: 'uint256' },
        { name: 'price', type: 'uint256' },
        { name: 'itemIds', type: 'uint256[]' },
        { name: 'amounts', type: 'uint256[]' },
        { name: 'additionalParameters', type: 'bytes' },
      ],
    },
    primaryType: 'Maker',
    domain: { name: 'LooksRareProtocol', version: '2', chainId: 1, verifyingContract: LOOKSRARE },
    message: {
      quoteType,
      globalNonce: '0',
      subsetNonce: '0',
      orderNonce: '0',
      strategyId: '0',
      collectionType: 0,
      collection: BAYC,
      currency: ZERO,
      signer: USER,
      startTime: '0',
      endTime: '1790000000',
      price,
      itemIds: ['1'],
      amounts: ['1'],
      additionalParameters: '0x',
    },
  };
}

export const SAFE_TX_TYPES = {
  EIP712Domain: [
    { name: 'chainId', type: 'uint256' },
    { name: 'verifyingContract', type: 'address' },
  ],
  SafeTx: [
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'data', type: 'bytes' },
    { name: 'operation', type: 'uint8' },
    { name: 'safeTxGas', type: 'uint256' },
    { name: 'baseGas', type: 'uint256' },
    { name: 'gasPrice', type: 'uint256' },
    { name: 'gasToken', type: 'address' },
    { name: 'refundReceiver', type: 'address' },
    { name: 'nonce', type: 'uint256' },
  ],
};

export function safeTx(to: unknown, data: string, operation: number, extra: Record<string, unknown> = {}) {
  return {
    types: SAFE_TX_TYPES,
    primaryType: 'SafeTx',
    domain: { chainId: 1, verifyingContract: SAFE },
    message: {
      ...extra,
      to,
      value: '0',
      data,
      operation,
      safeTxGas: '0',
      baseGas: '0',
      gasPrice: '0',
      gasToken: ZERO,
      refundReceiver: ZERO,
      nonce: '7',
    },
  };
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

/** All human-visible strings of a Snap UI tree (text, labels, titles, addresses). */
export function textOf(node: unknown): string {
  if (node === null || node === undefined || typeof node === 'boolean') return '';
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (Array.isArray(node)) return node.map(textOf).join(' ');
  if (typeof node === 'object') {
    const { props } = node as { props?: Record<string, unknown> };
    if (!props) return '';
    const parts: string[] = [];
    for (const key of ['title', 'label', 'address', 'value', 'href']) {
      if (typeof props[key] === 'string') parts.push(props[key] as string);
    }
    parts.push(textOf(props.children));
    return parts.join(' ');
  }
  return '';
}
