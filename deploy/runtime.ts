// Minimal Workers runtime surface used by the deploy modules (kept local so the
// code type-checks alongside the Node sources without @cloudflare/workers-types).
export interface KVNamespace {
  get(key: string): Promise<string | null>;
  get(key: string, opts: { type: "arrayBuffer"; cacheTtl?: number }): Promise<ArrayBuffer | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
}
export interface SqlStorage {
  exec(query: string, ...params: unknown[]): { toArray(): unknown[] };
}
export interface DurableObjectState {
  storage: { sql: SqlStorage } | unknown;
}
export interface DurableObjectStub {
  fetch(input: string, init?: RequestInit): Promise<Response>;
}
export interface DurableObjectNamespace {
  idFromName(name: string): unknown;
  get(id: unknown): DurableObjectStub;
}
export interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
}

export type WorkerEnv = {
  PROVIDER_HOST?: string;
  TYPESAFE_API_KEY?: string;
  AI_GATEWAY_API_KEY?: string;
  JEV_ATTEST_PRIVATE_KEY?: string;
  JEV_ATTEST_PUBLIC_JWK?: string;
  PAY_TO_EVM?: string;
  PAY_TO_SOL?: string;
  X402_FACILITATOR_URL?: string;
  FREE_TIER_DAILY?: string;
  SOL_RPC_URL?: string;
  SOL_RPC_URL_MAINNET?: string;
  X402_FACILITATOR_URL_MAINNET?: string;
  X402_FACILITATOR_URL_PAYAI?: string;
  /** "true" also accepts testnet payments. Never set in production: testnet USDC is free. */
  ENABLE_TESTNETS?: string;
  /** "off" disables provider-side on-chain lookups. */
  ONCHAIN?: string;
  /** JSON map {caip2: rpcUrl} overriding the public default RPCs. */
  RPC_URLS?: string;
  RATE?: KVNamespace;
  COUNTER?: DurableObjectNamespace;
};

