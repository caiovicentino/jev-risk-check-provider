/**
 * A local stand-in for https://x402check.xyz used by the integration tests.
 * Records every request (headers + parsed JSON body) and replies with a
 * programmable response, or drops the connection to simulate a network error.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';

export type RecordedRequest = {
  method: string;
  path: string;
  headers: http.IncomingHttpHeaders;
  body: any;
};

export type MockReply =
  | { status: number; json?: unknown; text?: string; headers?: Record<string, string> }
  | 'network-error';

export type Responder = (request: RecordedRequest) => MockReply;

/** Safety score: 100 = safe; the backend maps >= 80 to "low" risk. */
export const LOW_RISK_VERDICT = {
  checked: true,
  score: 88,
  tier: 'low',
  categories: [],
  provider: 'x402check',
  jws: 'eyJhbGciOiJFUzI1NiIsImtpZCI6ImpldiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl',
  jwks_url: 'https://x402check.xyz/.well-known/jwks.json',
};

/** Low-risk verdict for /v1/risk-check, one per item for /v1/risk-check/batch. */
export const lowRisk: Responder = (request) =>
  request.path.endsWith('/batch')
    ? { status: 200, json: { results: (request.body?.requests ?? []).map(() => LOW_RISK_VERDICT) } }
    : { status: 200, json: LOW_RISK_VERDICT };

export class MockApi {
  readonly requests: RecordedRequest[] = [];

  #responder: Responder = lowRisk;

  readonly #server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      let body: unknown = raw;
      try {
        body = JSON.parse(raw);
      } catch {
        // keep raw text
      }
      const recorded: RecordedRequest = {
        method: req.method ?? '',
        path: req.url ?? '',
        headers: req.headers,
        body,
      };
      this.requests.push(recorded);
      const reply = this.#responder(recorded);
      if (reply === 'network-error') {
        req.socket.destroy();
        return;
      }
      const payload = reply.json !== undefined ? JSON.stringify(reply.json) : (reply.text ?? '');
      res.writeHead(reply.status, {
        'Content-Type': reply.json !== undefined ? 'application/json' : 'text/plain',
        ...reply.headers,
      });
      res.end(payload);
    });
  });

  async start(): Promise<string> {
    await new Promise<void>((resolve) => this.#server.listen(0, '127.0.0.1', resolve));
    const { port } = this.#server.address() as AddressInfo;
    return `http://127.0.0.1:${port}`;
  }

  async stop(): Promise<void> {
    this.#server.closeAllConnections();
    await new Promise<void>((resolve) => this.#server.close(() => resolve()));
  }

  /** Sets the reply for subsequent requests. */
  respondWith(reply: MockReply | Responder): void {
    this.#responder = typeof reply === 'function' ? reply : () => reply;
  }

  reset(): void {
    this.requests.length = 0;
    this.respondWith(lowRisk);
  }

  get last(): RecordedRequest | undefined {
    return this.requests[this.requests.length - 1];
  }
}
