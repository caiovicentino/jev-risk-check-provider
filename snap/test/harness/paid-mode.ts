/**
 * Drivers for the paid-mode scenarios (test/harness/paid-scenarios.ts).
 *
 * The shipped Snap has paid checks OFF (PAID_CHECKS_SUPPORTED = false in
 * src/config.ts), so its bundle never sends anything. The paid pipeline is
 * kept for when the Snap can pay, and is exercised here through the same
 * interface two ways:
 * - `hookedPaidSnap`: the Snap's own handler factory (`insightHandlers`) with
 *   `paidChecks: true`, in Node, with requests shaped exactly as
 *   @metamask/snaps-simulation shapes them and the transport pointed at the
 *   local mock API;
 * - `sesSnap`: the built bundle in the SES execution environment. It only
 *   runs paid scenarios when the shipped flag is on.
 */
import type { OnSignatureHandler, OnTransactionHandler } from '@metamask/snaps-sdk';
import { SignatureOptionsStruct, TransactionOptionsStruct, assertIsResponseWithInterface, handleRequest } from '@metamask/snaps-simulation';

import { insightHandlers } from '../../src/check';
import type { FetchLike } from '../../src/request';
import { API_ORIGIN } from '../../src/request';
import type { BuiltSnap } from './snap';

export type TransactionRequest = Parameters<BuiltSnap['onTransaction']>[0];
export type SignatureRequest = Parameters<BuiltSnap['onSignature']>[0];
export type RawTransaction = { chainId: string; transactionOrigin?: string; transaction: Record<string, string> };
export type InsightResponse = { response: unknown; getInterface(): { content: unknown } };

/** What the paid-mode scenarios need from a Snap. */
export type SnapLike = {
  onTransaction(request: TransactionRequest): Promise<InsightResponse>;
  onSignature(request: SignatureRequest): Promise<InsightResponse>;
  /** Sends the handler params as given, without simulated defaults (e.g. a deployment has no `to`). */
  onRawTransaction(params: RawTransaction): Promise<InsightResponse>;
};

// snaps-simulation's own (older) snaps-utils HandlerType enum; the string value
// is what reaches the execution environment.
type SimulationHandler = Parameters<typeof handleRequest>[0]['handler'];

/**
 * The built bundle in SES, behind the scenario interface.
 *
 * @param snap - The installed built Snap.
 * @returns The driver.
 */
export function sesSnap(snap: BuiltSnap): SnapLike {
  return {
    onTransaction: async (request) => snap.onTransaction(request),
    onSignature: async (request) => snap.onSignature(request),
    onRawTransaction: async (params) => {
      const response = await handleRequest({
        snapId: snap.snapId,
        store: snap.store,
        executionService: snap.executionService,
        controllerMessenger: snap.controllerMessenger,
        runSaga: snap.runSaga,
        handler: 'onTransaction' as unknown as SimulationHandler,
        request: { method: '', params },
      });
      assertIsResponseWithInterface(response);
      return response;
    },
  };
}

/** Wraps a handler result in the shape snaps-simulation responses have. */
function asResponse(result: unknown): InsightResponse {
  const content = (result as { content?: unknown } | null)?.content;
  return { response: { result }, getInterface: () => ({ content }) };
}

/**
 * The Snap's handlers with paid checks ON (the test hook), in Node.
 *
 * @param mockOrigin - Origin of the local mock API that stands in for x402check.xyz.
 * @returns The driver.
 */
export function hookedPaidSnap(mockOrigin: string): SnapLike {
  const fetchImpl: FetchLike = async (input, init) => {
    if (input !== API_ORIGIN && !input.startsWith(`${API_ORIGIN}/`)) {
      throw new TypeError(`paid-mode test driver: blocked network request to ${input}`);
    }
    return fetch(`${mockOrigin}${input.slice(API_ORIGIN.length)}`, init);
  };
  const handlers = insightHandlers({ paidChecks: true, fetchImpl });
  return {
    onTransaction: async (request) => {
      const { origin: transactionOrigin, chainId, ...transaction } = TransactionOptionsStruct.create(request ?? {});
      const args = { transaction, chainId, transactionOrigin } as unknown as Parameters<OnTransactionHandler>[0];
      return asResponse(await handlers.onTransaction(args));
    },
    onSignature: async (request) => {
      const { origin: signatureOrigin, ...signature } = SignatureOptionsStruct.create(request ?? {});
      const args = { signature, signatureOrigin } as unknown as Parameters<OnSignatureHandler>[0];
      return asResponse(await handlers.onSignature(args));
    },
    onRawTransaction: async (params) =>
      asResponse(await handlers.onTransaction(params as unknown as Parameters<OnTransactionHandler>[0])),
  };
}
