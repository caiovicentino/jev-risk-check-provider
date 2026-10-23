// Where x402check_pay may connect: public addresses only.
//
// resourceUrl() refuses IP literals in non-public ranges as written. A host NAME is refused too
// when it resolves to one: the resource fetch connects through an undici Agent whose DNS lookup
// refuses any non-public answer, and the connection uses exactly the addresses that lookup
// checked, so a name cannot be re-pointed (DNS rebinding) between the check and the connect.
//
// It also asks a resource for gzip or deflate only, and refuses a response in any other content
// coding before a byte of it is decoded. A resource is any server, so its compressed body reaches a
// decoder in the process that holds the payer key: the Brotli decoder of Node.js before 22.23.4,
// 24.22.1 and 26.12.1 writes out of bounds on a crafted stream (CVE-2026-111497, 2026-10-21).
import { promises as dns } from "node:dns";
import { BlockList, isIP, type LookupFunction } from "node:net";
import { Agent, DecoratorHandler, type Dispatcher, fetch as undiciFetch } from "undici";

// Everything that is not a globally reachable unicast address (IANA special-purpose registries).
// One list per family: a BlockList holding IPv6 rules also matches IPv4 addresses through their
// IPv4-mapped form, so "::/3" would match every IPv4 address.
const NON_PUBLIC_V4 = new BlockList();
const NON_PUBLIC_V6 = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8], // "this network"
  ["10.0.0.0", 8], // private
  ["100.64.0.0", 10], // shared address space (CGNAT)
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local (cloud metadata)
  ["172.16.0.0", 12], // private
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // documentation
  ["192.88.99.0", 24], // 6to4 relay anycast (deprecated)
  ["192.168.0.0", 16], // private
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // documentation
  ["203.0.113.0", 24], // documentation
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved, broadcast
] as const) {
  NON_PUBLIC_V4.addSubnet(network, prefix, "ipv4");
}
// IPv6: only global unicast (2000::/3) can be public. Outside it: ::, ::1, IPv4-mapped
// (::ffff:0:0/96) and -compatible forms, NAT64 (64:ff9b::/96, 64:ff9b:1::/48), discard
// (100::/64), unique local (fc00::/7), link-local (fe80::/10), site-local (fec0::/10) and
// multicast (ff00::/8). Inside it, the IETF protocol block (Teredo 2001::/32 included), 6to4
// (2002::/16, which embeds an IPv4 address) and the documentation prefixes are refused too.
for (const [network, prefix] of [
  ["::", 3],
  ["4000::", 2],
  ["8000::", 1],
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["3fff::", 20],
] as const) {
  NON_PUBLIC_V6.addSubnet(network, prefix, "ipv6");
}

/** A globally reachable unicast IP address: false for private, loopback, link-local, CGNAT, multicast, reserved, documentation and IPv6 transition ranges. */
export function isPublicAddress(address: string): boolean {
  // A zone index ("fe80::1%en0") scopes an address to a local interface; BlockList ignores it.
  if (typeof address !== "string" || address.includes("%")) return false;
  const family = isIP(address);
  if (family === 0) return false;
  try {
    return family === 4 ? !NON_PUBLIC_V4.check(address, "ipv4") : !NON_PUBLIC_V6.check(address, "ipv6");
  } catch {
    return false;
  }
}

/** A host name resolved to a non-public address: nothing was requested. */
export class NonPublicAddressError extends Error {
  override readonly name = "NonPublicAddressError";
  constructor(readonly host: string) {
    super("the host name resolves to a private, loopback, link-local or reserved address");
  }
}

export type ResolvedAddress = { address: string; family: number };
/** DNS resolution of a host name: every address it has. */
export type Resolver = (hostname: string) => Promise<readonly ResolvedAddress[]>;

const systemResolver: Resolver = (hostname) => dns.lookup(hostname, { all: true, verbatim: true });

function notFound(hostname: string): NodeJS.ErrnoException {
  return Object.assign(new Error(`${hostname} has no usable address`), { code: "ENOTFOUND" });
}

/**
 * A `lookup` for net/tls connections that refuses a host with any non-public address, and
 * otherwise answers with exactly the addresses it checked (the connection is pinned to them).
 */
export function publicOnlyLookup(resolve: Resolver = systemResolver): LookupFunction {
  return (hostname, options, callback) => {
    resolve(hostname).then(
      (found) => {
        const all = found.filter((a) => a !== null && typeof a === "object" && typeof a.address === "string" && (a.family === 4 || a.family === 6));
        if (all.length === 0) return callback(notFound(hostname), "", undefined);
        if (all.some((a) => !isPublicAddress(a.address))) return callback(new NonPublicAddressError(hostname), "", undefined);
        const family = options.family === 4 || options.family === "IPv4" ? 4 : options.family === 6 || options.family === "IPv6" ? 6 : 0;
        const usable = family === 0 ? all : all.filter((a) => a.family === family);
        const first = usable[0];
        if (!first) return callback(notFound(hostname), "", undefined);
        if (options.all) return callback(null, usable.map((a) => ({ address: a.address, family: a.family })));
        return callback(null, first.address, first.family);
      },
      (err: NodeJS.ErrnoException) => callback(err, "", undefined),
    );
  };
}

/** The content codings a resource is asked for. */
export const ACCEPT_ENCODING = "gzip, deflate";
// What a response may be in: the codings asked for, gzip's legacy alias, and none at all.
const ACCEPTED_CODINGS = new Set(["gzip", "x-gzip", "deflate", "identity"]);

/** A resource answered in a content coding it was not asked for (Brotli included): none of its body was decoded. */
export class UnrequestedEncodingError extends Error {
  override readonly name = "UnrequestedEncodingError";
  constructor() {
    super("the resource answered in a content coding it was not asked for, so its body was not decoded");
  }
}

/** Whether every content coding a response names (any `Content-Encoding` header, any case) is one asked for. */
export function codingsAccepted(rawHeaders: ReadonlyArray<Buffer | string>): boolean {
  const text = (v: Buffer | string | undefined) => (typeof v === "string" ? v : v === undefined ? "" : Buffer.from(v).toString("latin1"));
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    if (text(rawHeaders[i]).trim().toLowerCase() !== "content-encoding") continue;
    for (const coding of text(rawHeaders[i + 1]).split(",")) {
      const c = coding.trim().toLowerCase();
      if (c !== "" && !ACCEPTED_CODINGS.has(c)) return false;
    }
  }
  return true;
}

/**
 * Refuses a response in a content coding that was not asked for, from its headers, before fetch
 * sets up a decoder. undici aborts a request whose `onHeaders` throws: fetch then rejects with
 * the error as its cause, and the connection is closed.
 */
class CodingGuard extends DecoratorHandler {
  readonly #handler: Dispatcher.DispatchHandlers;
  constructor(handler: Dispatcher.DispatchHandlers) {
    super(handler);
    this.#handler = handler;
  }
  onHeaders(statusCode: number, headers: Buffer[], resume: () => void, statusText: string): boolean {
    if (statusCode >= 200 && !codingsAccepted(headers)) throw new UnrequestedEncodingError();
    return this.#handler.onHeaders?.(statusCode, headers, resume, statusText) ?? true;
  }
}

/** The undici interceptor that applies `CodingGuard` to every request. */
export const refuseUnrequestedCodings: Dispatcher.DispatcherComposeInterceptor = (dispatch) => (options, handler) => dispatch(options, new CodingGuard(handler));

/**
 * The fetch x402check_pay requests resources with when no custom fetch is configured: it connects
 * only to public addresses (host names resolved and pinned, see `publicOnlyLookup`) and never
 * follows a redirect. A host with a non-public address fails with a `NonPublicAddressError` cause.
 */
export function publicOnlyFetch(resolve?: Resolver): typeof globalThis.fetch {
  return resourceFetch(() => new Agent({ connect: { lookup: publicOnlyLookup(resolve) } }));
}

/**
 * The resource fetch over a dispatcher (`publicOnlyFetch`'s, or a test's): it asks for gzip or
 * deflate only, refuses any other content coding with an `UnrequestedEncodingError` cause, and
 * never follows a redirect.
 */
export function resourceFetch(makeDispatcher: () => Dispatcher): typeof globalThis.fetch {
  let dispatcher: Dispatcher | undefined;
  return async (input, init) => {
    dispatcher ??= makeDispatcher().compose(refuseUnrequestedCodings);
    const request = new Request(input, init);
    const body = request.method === "GET" || request.method === "HEAD" ? undefined : Buffer.from(await request.arrayBuffer());
    const res = await undiciFetch(request.url, {
      method: request.method,
      headers: [...[...request.headers].filter(([name]) => name !== "accept-encoding"), ["accept-encoding", ACCEPT_ENCODING]],
      ...(body && body.byteLength > 0 ? { body } : {}),
      redirect: "manual",
      signal: request.signal,
      dispatcher,
    });
    return res as unknown as Response;
  };
}
