import { createServer } from "node:http";
import { createHandler } from "./handler.js";
import { Provider } from "./provider.js";

export type ServerDeps = {
  provider: Provider;
  port: number;
};

export function startServer(deps: ServerDeps): { close: () => Promise<void> } {
  const handler = createHandler({ provider: deps.provider });
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", `http://localhost:${deps.port}`);
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (typeof v === "string") headers.set(k, v);
      else if (Array.isArray(v)) headers.set(k, v.join(", "));
    }
    const method = req.method ?? "GET";
    const hasBody = method === "POST" || method === "PUT" || method === "PATCH";
    const request = new Request(url, {
      method,
      headers,
      body: hasBody ? req : undefined,
      duplex: hasBody ? "half" : undefined,
    } as RequestInit);
    handler(request)
      .then(async (response) => {
        res.statusCode = response.status;
        response.headers.forEach((value, key) => res.setHeader(key, value));
        const body = await response.arrayBuffer();
        res.end(Buffer.from(body));
      })
      .catch((err) => {
        res.statusCode = 500;
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ error: "internal_error", detail: String(err) }));
      });
  });
  server.listen(deps.port);
  return {
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}
