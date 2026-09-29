'use strict';

/*
 * Test-only bootstrap for the Snap execution worker thread.
 *
 * It runs BEFORE the official MetaMask execution environment
 * (@metamask/snaps-execution-environments/node-thread, which applies SES
 * lockdown and evaluates the Snap bundle in its own compartment). The only thing
 * it changes is the host transport underneath `fetch`: requests to
 * https://x402check.xyz are redirected to a local mock server so the tests can
 * inspect the exact request bodies and choose responses. Every other network
 * destination is refused.
 *
 * The Snap itself still sees only the globals MetaMask gives it: `snap`,
 * `ethereum`, the SES default endowments and the endowments granted by its
 * permissions (`fetch` via endowment:network-access). A bare
 * `snap_manageState(...)` call is a ReferenceError there, as in MetaMask.
 */
const { workerData } = require('node:worker_threads');

const REAL_ORIGIN = 'https://x402check.xyz';
const hostFetch = globalThis.fetch;

globalThis.fetch = function redirectedFetch(input, init) {
  let url;
  if (typeof input === 'string') {
    url = input;
  } else if (input instanceof URL) {
    url = input.href;
  } else if (input && typeof input.url === 'string') {
    url = input.url;
  }
  if (typeof url === 'string' && (url === REAL_ORIGIN || url.startsWith(`${REAL_ORIGIN}/`))) {
    return hostFetch(`${workerData.mockOrigin}${url.slice(REAL_ORIGIN.length)}`, init);
  }
  return Promise.reject(new TypeError(`x402check test harness: blocked network request to ${String(url)}`));
};

require(workerData.executionEnvironment);
