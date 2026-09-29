/**
 * Shared fixtures and helpers for the unit and integration tests.
 */
export const USER = '0xb48057e647b2572f5eae241b515fbc58b7ce249e' as const;
export const RECIPIENT = '0xbf88b1f49b5e8ec386289341c4a5ee00bb0e0178' as const;
export const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' as const;
export const DAI = '0x6b175474e89094c44da98b954eedeac495271d0f' as const;
export const DRAINER = '0x9d17bb55b57b31329cf01aa7017948e398b277bc' as const;
export const UNIVERSAL_ROUTER = '0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad' as const;
export const PERMIT2 = '0x000000000022d473030f116ddee9f6b43ac78ba3' as const;
export const SEAPORT = '0x0000000000000068f116a894984e2db1123eb395' as const;
export const OPENSEA_FEE = '0x0000a26b00c1f0df003000390027140000faa719' as const;
export const BAYC = '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d' as const;
export const ZERO = '0x0000000000000000000000000000000000000000' as const;
export const MAX_UINT256 = (1n << 256n) - 1n;
export const MAX_UINT160 = (1n << 160n) - 1n;

/** ABI-encodes one static argument as a 32-byte word (hex, no 0x). */
export const word = (value: bigint | string): string =>
  typeof value === 'string'
    ? value.toLowerCase().replace(/^0x/u, '').padStart(64, '0')
    : value.toString(16).padStart(64, '0');

/** Builds calldata from a 4-byte selector (no 0x) and static arguments. */
export type Hex = `0x${string}`;

export const calldata = (selector: string, ...args: (bigint | string)[]): Hex =>
  `0x${selector}${args.map(word).join('')}`;

export const utf8Hex = (text: string): Hex => `0x${Buffer.from(text, 'utf8').toString('hex')}`;

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

export function permitSingle(spender: string, amount: bigint = MAX_UINT160, verifyingContract: string = PERMIT2) {
  return {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      PermitDetails: [
        { name: 'token', type: 'address' },
        { name: 'amount', type: 'uint160' },
        { name: 'expiration', type: 'uint48' },
        { name: 'nonce', type: 'uint48' },
      ],
      PermitSingle: [
        { name: 'details', type: 'PermitDetails' },
        { name: 'spender', type: 'address' },
        { name: 'sigDeadline', type: 'uint256' },
      ],
    },
    primaryType: 'PermitSingle',
    domain: { name: 'Permit2', chainId: 1, verifyingContract },
    message: {
      details: { token: USDC, amount: amount.toString(), expiration: '1790000000', nonce: '0' },
      spender,
      sigDeadline: '1790000000',
    },
  };
}

export function erc2612Permit(spender: string, value: string | number, chainId: unknown = 1) {
  return {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      Permit: [
        { name: 'owner', type: 'address' },
        { name: 'spender', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
      ],
    },
    primaryType: 'Permit',
    domain: { name: 'USD Coin', version: '2', chainId, verifyingContract: USDC },
    message: { owner: USER, spender, value, nonce: 0, deadline: '1790000000' },
  };
}

type SeaportItem = {
  itemType: string;
  token: string;
  identifierOrCriteria: string;
  startAmount: string;
  endAmount: string;
  recipient?: string;
};

export function seaportOrder(offer: SeaportItem[], consideration: SeaportItem[], offerer: string = USER) {
  return {
    types: { OrderComponents: [] },
    primaryType: 'OrderComponents',
    domain: { name: 'Seaport', version: '1.6', chainId: 1, verifyingContract: SEAPORT },
    message: {
      offerer,
      zone: ZERO,
      offer,
      consideration,
      orderType: '0',
      startTime: '0',
      endTime: '1790000000',
      zoneHash: `0x${'0'.repeat(64)}`,
      salt: '0',
      conduitKey: `0x${'0'.repeat(64)}`,
      counter: '0',
    },
  };
}

export const nft = (token: string, id: string): SeaportItem => ({
  itemType: '2',
  token,
  identifierOrCriteria: id,
  startAmount: '1',
  endAmount: '1',
});

export const eth = (wei: string, recipient: string): SeaportItem => ({
  itemType: '0',
  token: ZERO,
  identifierOrCriteria: '0',
  startAmount: wei,
  endAmount: wei,
  recipient,
});
