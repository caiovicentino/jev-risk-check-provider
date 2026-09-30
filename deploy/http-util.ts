import type { HTTPAdapter } from "@x402/core/http";

// Small HTTP helpers shared by the paywall (deploy/protected.ts) and credits (deploy/credits.ts).

export function fetchAdapter(request: Request, body: unknown): HTTPAdapter {
  return {
    getHeader: (name) => request.headers.get(name) ?? undefined,
    getMethod: () => request.method,
    getPath: () => new URL(request.url).pathname,
    getUrl: () => request.url,
    getAcceptHeader: () => request.headers.get("accept") ?? "*/*",
    getUserAgent: () => request.headers.get("user-agent") ?? "",
    getBody: () => body,
  };
}

export function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return Response.json(body, { status, headers });
}

/** Whether every evaluation in a 200 response was produced (checked: true): only then is anything charged. */
export async function allChecked(res: Response): Promise<boolean> {
  try {
    const body = (await res.json()) as { checked?: unknown; results?: Array<{ checked?: unknown }> };
    if (Array.isArray(body.results)) return body.results.length > 0 && body.results.every((r) => r.checked === true);
    return body.checked === true;
  } catch {
    return false;
  }
}
