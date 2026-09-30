/**
 * ABI fixtures for smart-account calls (ERC-4337 entry points, Safe module,
 * ERC-7579, Coinbase Smart Wallet) and control changes. Encodings were checked
 * against viem's encodeFunctionData.
 */
import type { Hex } from './helpers';
import { encBytes, encBytesArray, word } from './helpers';

export type Call = { to: string; value: bigint; data: string };

/** executeBatch((address,uint256,bytes)[]): Coinbase Smart Wallet, Kernel v2, Simple7702Account. */
export function executeBatchTuples(calls: Call[]): Hex {
  const tuples = calls.map((call) => `${word(call.to)}${word(call.value)}${word(0x60n)}${encBytes(call.data)}`);
  let offsets = '';
  let offset = calls.length * 32;
  for (const tuple of tuples) {
    offsets += word(BigInt(offset));
    offset += tuple.length / 2;
  }
  return `0x34fcd5be${word(0x20n)}${word(BigInt(calls.length))}${offsets}${tuples.join('')}`;
}

/** executeBatch(address[],bytes[]): SimpleAccount, LightAccount. */
export function executeBatchArrays(targets: string[], datas: string[]): Hex {
  const targetsEncoded = `${word(BigInt(targets.length))}${targets.map((target) => word(target)).join('')}`;
  return `0x18dfb3c7${word(0x40n)}${word(BigInt(0x40 + targetsEncoded.length / 2))}${targetsEncoded}${encBytesArray(datas)}`;
}

/** (address,uint256,bytes,uint8): Safe 4337 module executeUserOp (7bb37428), Kernel v2 execute (51945447). */
export function executeWithOperation(selector: string, to: string, value: bigint, data: string, operation: 0 | 1): Hex {
  return `0x${selector}${word(to)}${word(value)}${word(0x80n)}${word(BigInt(operation))}${encBytes(data)}`;
}

/** ERC-7579 installModule(uint256,address,bytes). */
export const installModule = (typeId: bigint, module: string, init = '0x'): Hex =>
  `0x9517e29f${word(typeId)}${word(module)}${word(0x60n)}${encBytes(init)}`;

/** ERC-7579 uninstallModule(uint256,address,bytes). */
export const uninstallModule = (typeId: bigint, module: string, init = '0x'): Hex =>
  `0xa71763a8${word(typeId)}${word(module)}${word(0x60n)}${encBytes(init)}`;

/** UUPS upgradeToAndCall(address,bytes). */
export const upgradeToAndCall = (implementation: string, data = '0x'): Hex =>
  `0x4f1ef286${word(implementation)}${word(0x40n)}${encBytes(data)}`;

/** Coinbase Smart Wallet executeWithoutChainIdValidation(bytes[]). */
export const executeWithoutChainIdValidation = (calls: string[]): Hex => `0x2c2abd1e${word(0x20n)}${encBytesArray(calls)}`;
