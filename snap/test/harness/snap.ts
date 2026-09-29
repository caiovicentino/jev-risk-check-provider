/**
 * Installs the BUILT Snap (snap.manifest.json + dist/bundle.js, served by the
 * snaps-jest environment) in MetaMask's real Node execution environment, with
 * only the network transport redirected to a local mock API.
 */
import path from 'node:path';
import { Worker } from 'node:worker_threads';

import { NodeThreadExecutionService } from '@metamask/snaps-controllers/node';
// Loads the `snapsEnvironment` global and the custom matcher typings.
import type {} from '@metamask/snaps-jest';
import type { InstalledSnap, SimulationUserOptions, SnapHelpers } from '@metamask/snaps-simulation';
import { getState } from '@metamask/snaps-simulation';

// Resolve post-message-stream from snaps-controllers' own dependency tree so the
// stream class matches the one the execution service expects.
const controllersDir = path.dirname(require.resolve('@metamask/snaps-controllers/package.json'));
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { ThreadParentMessageStream } = require(
  require.resolve('@metamask/post-message-stream/node', { paths: [controllersDir] }),
) as typeof import('@metamask/post-message-stream/node');

const WORKER_ENTRY = path.join(__dirname, 'worker-entry.cjs');
const EXECUTION_ENVIRONMENT = require.resolve('@metamask/snaps-execution-environments/node-thread');

/**
 * Creates a NodeThreadExecutionService whose worker first installs the fetch
 * redirect (see worker-entry.cjs) and then loads the official execution
 * environment bundle.
 *
 * @param mockOrigin - Origin of the local mock API (http://127.0.0.1:PORT).
 * @returns The execution service class.
 */
export function mockFetchExecutionService(mockOrigin: string) {
  return class MockFetchExecutionService extends NodeThreadExecutionService {
    protected async initEnvStream() {
      const worker = new Worker(WORKER_ENTRY, {
        stdout: true,
        stderr: true,
        workerData: { mockOrigin, executionEnvironment: EXECUTION_ENVIRONMENT },
      });
      worker.stdout.on('data', (data: Buffer) => console.log(data.toString()));
      worker.stderr.on('data', (data: Buffer) => console.error(data.toString()));
      const stream = new ThreadParentMessageStream({ thread: worker });
      return { worker, stream };
    }
  };
}

export type BuiltSnap = InstalledSnap & SnapHelpers;

/**
 * Installs the built Snap and returns the full simulation instance (helpers
 * plus the Redux store, to inspect persisted state).
 *
 * @param mockOrigin - Origin of the local mock API.
 * @param options - Simulation options (initial state, etc.).
 * @returns The installed Snap.
 */
export async function installBuiltSnap(mockOrigin: string, options: SimulationUserOptions = {}): Promise<BuiltSnap> {
  return (await snapsEnvironment.installSnap(undefined, {
    executionService: mockFetchExecutionService(mockOrigin),
    options,
  })) as BuiltSnap;
}

/**
 * Reads the Snap's persisted state from the simulation store.
 *
 * @param snap - The installed Snap.
 * @param encrypted - Which state to read.
 * @returns The parsed state, or null.
 */
export function readSnapState(snap: InstalledSnap, encrypted: boolean): Record<string, unknown> | null {
  const raw = getState(encrypted)(snap.store.getState()) as string | null;
  return raw ? (JSON.parse(raw) as Record<string, unknown>) : null;
}
