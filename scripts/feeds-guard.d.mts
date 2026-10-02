// Types for scripts/feeds-guard.mjs, which stays plain JavaScript: the feeds workflow's publish
// job runs it with node alone.
export declare const LIMITS: Readonly<{ ofacMaxShrink: number; ofacMaxGrowth: number; metamaskMaxChange: number; maxAheadMs: number }>;
/** The reasons not to sign `next` given the published manifest (null: none published); [] means sign. */
export declare function feedsGuard(next: unknown, published: unknown, now?: number): string[];
