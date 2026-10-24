export type Acceptance = { advisory: string; nodes: string[]; reason: string; review: string };
export type AuditReport = {
  vulnerabilities?: Record<string, { severity: string; nodes: string[]; via: Array<string | { url?: string }> }>;
  metadata?: { vulnerabilities?: Record<string, number> };
};
export declare const ACCEPTED: Acceptance[];
export declare function failures(report: AuditReport, today?: string): string[];
