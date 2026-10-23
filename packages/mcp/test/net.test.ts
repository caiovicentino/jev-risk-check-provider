// Where x402check_pay may connect (mcp-9): public addresses only, checked on the URL as written
// and again on the addresses its host name resolves to, with the connection pinned to them.
import assert from "node:assert/strict";
import type { LookupAddress } from "node:dns";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, test } from "node:test";
import zlib, { brotliCompressSync, deflateSync, gzipSync } from "node:zlib";
import { Agent, fetch as undiciFetch } from "undici";
import {
  ACCEPT_ENCODING,
  codingsAccepted,
  isPublicAddress,
  NonPublicAddressError,
  publicOnlyFetch,
  publicOnlyLookup,
  type Resolver,
  resourceFetch,
  UnrequestedEncodingError,
} from "../src/net.js";
import { resourceUrl } from "../src/pay.js";

const PUBLIC = ["8.8.8.8", "1.1.1.1", "93.184.215.14", "100.63.255.255", "100.128.0.1", "172.32.0.1", "192.0.1.1", "223.255.255.255", "2606:4700:4700::1111", "2001:4860:4860::8888", "2a00:1450:4001:82b::200e", "2001:200::1"];

const NOT_PUBLIC = [
  // IPv4: this network, private, CGNAT, loopback, link-local, protocol assignments, documentation, 6to4 relay, benchmarking, multicast, reserved
  "0.0.0.0", "10.0.0.1", "100.64.0.1", "100.127.255.255", "127.0.0.1", "169.254.169.254", "172.16.0.1", "172.31.255.255", "192.0.0.170", "192.0.2.1",
  "192.88.99.1", "192.168.1.1", "198.18.0.1", "198.19.255.255", "198.51.100.7", "203.0.113.9", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
  // IPv6: unspecified, loopback, IPv4-mapped and -compatible, NAT64 (well-known and local-use), discard, Teredo, documentation, 6to4, ULA, link-local, site-local, multicast, outside 2000::/3
  "::", "::1", "::ffff:127.0.0.1", "::ffff:8.8.8.8", "::ffff:a9fe:a9fe", "::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::1", "100::1", "2001::1",
  "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:db8::1", "3fff::1", "2002:a9fe:a9fe::1", "fc00::1", "fd12:3456::1", "fe80::1", "fe80::1%en0", "fec0::1", "ff02::1", "5f00::1", "4000::1",
  // not an address
  "", "localhost", "8.8.8", "::g",
];

describe("isPublicAddress", () => {
  test("public unicast addresses", () => {
    for (const address of PUBLIC) assert.equal(isPublicAddress(address), true, address);
  });
  test("private, loopback, link-local, CGNAT, multicast, reserved, documentation and IPv6 transition ranges", () => {
    for (const address of NOT_PUBLIC) assert.equal(isPublicAddress(address), false, address);
  });
});

describe("resourceUrl: IP literals as written", () => {
  test("literals in non-public ranges are refused, whatever their spelling", () => {
    for (const url of [
      "https://[64:ff9b::a9fe:a9fe]/latest/meta-data", // NAT64 of 169.254.169.254
      "https://[64:ff9b::169.254.169.254]/latest/meta-data",
      "https://[2002:a9fe:a9fe::1]/", // 6to4 of 169.254.169.254
      "https://[2001::a9fe:a9fe]/", // Teredo
      "https://[fec0::1]/", // site-local
      "https://[::ffff:a9fe:a9fe]/",
      "https://[::a9fe:a9fe]/",
      "https://[2001:db8::1]/",
      "https://100.64.0.1/",
      "https://192.0.2.1/",
      "https://0x7f.1/",
      "https://0251.0376.0251.0376/", // octal 169.254.169.254
      "https://127.1/",
      "https://[::]/",
    ]) {
      assert.equal(typeof resourceUrl(url), "string", url);
    }
  });
  test("public literals and host names pass (host names are checked again when resolved)", () => {
    for (const url of ["https://8.8.8.8/x", "https://[2606:4700:4700::1111]/x", "https://api.weather.example/v1", "https://169.254.169.254.nip.io/"]) {
      assert.ok(resourceUrl(url) instanceof URL, url);
    }
  });
});

type Answer = { err: NodeJS.ErrnoException | null; address: string | LookupAddress[]; family?: number | undefined };

function lookupWith(resolve: Resolver, hostname: string, options: { all?: boolean; family?: number | "IPv4" | "IPv6" }): Promise<Answer> {
  return new Promise((done) => {
    publicOnlyLookup(resolve)(hostname, options as never, (err, address, family) => done({ err, address, family }));
  });
}

describe("publicOnlyLookup: the connection gets exactly the addresses checked", () => {
  const answers = (list: Array<{ address: string; family: number }>): Resolver => async () => list;

  test("public answers pass, in either callback form", async () => {
    const both = answers([
      { address: "93.184.215.14", family: 4 },
      { address: "2606:2800:21f:cb07:6820:80da:af6b:8b2c", family: 6 },
    ]);
    const all = await lookupWith(both, "example.org", { all: true });
    assert.equal(all.err, null);
    assert.deepEqual(all.address, [
      { address: "93.184.215.14", family: 4 },
      { address: "2606:2800:21f:cb07:6820:80da:af6b:8b2c", family: 6 },
    ]);
    const one = await lookupWith(both, "example.org", {});
    assert.deepEqual([one.err, one.address, one.family], [null, "93.184.215.14", 4]);
    const v6 = await lookupWith(both, "example.org", { family: 6 });
    assert.deepEqual([v6.address, v6.family], ["2606:2800:21f:cb07:6820:80da:af6b:8b2c", 6]);
  });

  test("any non-public answer refuses the host (not only the first)", async () => {
    for (const list of [
      [{ address: "10.0.0.7", family: 4 }],
      [
        { address: "93.184.215.14", family: 4 },
        { address: "127.0.0.1", family: 4 },
      ],
      [{ address: "::ffff:169.254.169.254", family: 6 }],
      [{ address: "fd00::1", family: 6 }],
    ]) {
      const answer = await lookupWith(answers(list), "rebind.example", { all: true });
      assert.ok(answer.err instanceof NonPublicAddressError, JSON.stringify(list));
      assert.doesNotMatch(answer.err.message, /10\.0|127\.|169\.254|fd00/, "the internal address is not echoed");
    }
  });

  test("no usable answer, or a failing resolver, is an error", async () => {
    const none = await lookupWith(answers([]), "empty.example", { all: true });
    assert.equal(none.err?.code, "ENOTFOUND");
    const wrongFamily = await lookupWith(answers([{ address: "93.184.215.14", family: 4 }]), "v4only.example", { family: 6 });
    assert.equal(wrongFamily.err?.code, "ENOTFOUND");
    const failing = await lookupWith(async () => Promise.reject(Object.assign(new Error("getaddrinfo ENOTFOUND"), { code: "ENOTFOUND" })), "nx.example", { all: true });
    assert.equal(failing.err?.code, "ENOTFOUND");
  });

  test("publicOnlyFetch fails before connecting when the name resolves to a private address", async () => {
    const asked: string[] = [];
    const fetch = publicOnlyFetch(async (host) => {
      asked.push(host);
      return [{ address: "127.0.0.1", family: 4 }];
    });
    await assert.rejects(fetch("https://api.weather.example/v1"), (err: unknown) => err instanceof Error && err.cause instanceof NonPublicAddressError);
    assert.deepEqual(asked, ["api.weather.example"]);
  });
});

// CVE-2026-111497 (2026-10-21): the Brotli decoder of Node.js before 22.23.4, 24.22.1 and 26.12.1
// writes out of bounds on a crafted stream. A resource is any server, so x402check_pay asks for gzip
// or deflate only and refuses any other coding from the headers, before a decoder exists.
describe("content codings a resource may answer in", () => {
  test("codingsAccepted reads every Content-Encoding header, in any case and spacing", () => {
    const h = (...pairs: string[]) => pairs.map((p) => Buffer.from(p));
    assert.equal(codingsAccepted(h()), true);
    assert.equal(codingsAccepted(h("Content-Type", "application/json")), true);
    assert.equal(codingsAccepted(h("content-encoding", "gzip")), true);
    assert.equal(codingsAccepted(h("Content-Encoding", " X-GZIP , deflate,, identity ")), true);
    assert.equal(codingsAccepted(h("Content-Encoding", "")), true);
    assert.equal(codingsAccepted(h("Content-Encoding", "br")), false);
    assert.equal(codingsAccepted(h("CONTENT-ENCODING", "GZIP, BR")), false);
    assert.equal(codingsAccepted(h("Content-Encoding", "gzip", "content-encoding", "br")), false, "a second header counts too");
    assert.equal(codingsAccepted(h("Content-Encoding", "zstd")), false);
    assert.equal(codingsAccepted(["content-encoding", "br"]), false, "string headers are read too");
  });

  test("a resource that answers in Brotli is refused before anything is decoded; gzip, deflate and none are read", async () => {
    const seen: Array<string | undefined> = [];
    const body = JSON.stringify({ ok: true });
    const server = createServer((req, res) => {
      seen.push(req.headers["accept-encoding"]);
      const answer: Record<string, [string | undefined, Buffer]> = {
        "/br": ["br", brotliCompressSync(body)],
        "/mixed": ["GZIP, br", brotliCompressSync(gzipSync(body))],
        "/zstd": ["zstd", Buffer.from(body)],
        "/gzip": ["gzip", gzipSync(body)],
        "/deflate": ["deflate", deflateSync(body)],
        "/plain": [undefined, Buffer.from(body)],
      };
      const [coding, bytes] = answer[req.url ?? ""] ?? [undefined, Buffer.from("{}")];
      res.writeHead(402, { "content-type": "application/json", ...(coding ? { "content-encoding": coding } : {}) });
      res.end(bytes);
    });
    await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
    const { port } = server.address() as AddressInfo;
    // fetch creates its decoders through node:zlib's exports: count the Brotli ones (the property is read-only, not frozen).
    const decoders = { brotli: 0 };
    const original = Object.getOwnPropertyDescriptor(zlib, "createBrotliDecompress") as PropertyDescriptor;
    const agent = new Agent();
    try {
      Object.defineProperty(zlib, "createBrotliDecompress", {
        ...original,
        value: (...args: Parameters<typeof zlib.createBrotliDecompress>) => {
          decoders.brotli++;
          return (original.value as typeof zlib.createBrotliDecompress)(...args);
        },
      });
      // The resource fetch over a plain Agent: publicOnlyFetch's own refuses this loopback server.
      const fetch = resourceFetch(() => agent);
      for (const path of ["/br", "/mixed", "/zstd"]) {
        await assert.rejects(fetch(`http://127.0.0.1:${port}${path}`), (err: unknown) => err instanceof Error && err.cause instanceof UnrequestedEncodingError, path);
      }
      assert.equal(decoders.brotli, 0, "no Brotli decoder was created");
      for (const path of ["/gzip", "/deflate", "/plain"]) {
        const res = await fetch(`http://127.0.0.1:${port}${path}`, { headers: { "accept-encoding": "br" } });
        assert.equal(res.status, 402, path);
        assert.deepEqual(await res.json(), { ok: true }, path);
      }
      assert.deepEqual(new Set(seen), new Set([ACCEPT_ENCODING]), "every request asks for gzip or deflate only, whatever the caller set");
      // The same response through undici's fetch without the guard (a benign stream): the count above means something.
      assert.deepEqual(await (await undiciFetch(`http://127.0.0.1:${port}/br`, { dispatcher: agent })).json(), { ok: true });
      assert.equal(decoders.brotli, 1, "the unguarded fetch decoded Brotli");
    } finally {
      Object.defineProperty(zlib, "createBrotliDecompress", original);
      await agent.close();
      await new Promise((done) => server.close(done));
    }
  });
});
