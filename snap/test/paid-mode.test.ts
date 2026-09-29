/**
 * @jest-environment node
 *
 * The paid pipeline (request bodies, verdicts, evidence, simulation, failure
 * modes) through the Snap's own handler factory with paid checks ON via the
 * test hook (`insightHandlers({ paidChecks: true })`). The shipped bundle has
 * paid checks off and sends nothing (test/snap.test.ts); the same scenarios
 * also run against the built bundle in SES once PAID_CHECKS_SUPPORTED is on.
 */
import { afterAll, beforeAll, describe } from '@jest/globals';

import { MockApi } from './harness/mock-api';
import { hookedPaidSnap } from './harness/paid-mode';
import { paidModeScenarios } from './harness/paid-scenarios';

describe('paid mode through the handler hook (paidChecks: true)', () => {
  const api = new MockApi();
  let mockOrigin = '';

  beforeAll(async () => {
    mockOrigin = await api.start();
  });

  afterAll(async () => {
    await api.stop();
  });

  paidModeScenarios({ api, makeSnap: async () => hookedPaidSnap(mockOrigin) });
});
