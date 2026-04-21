/**
 * DNS-over-HTTPS resolver + fetch wrapper. Node.js only.
 *
 * Mirrors the Rust `aex-net` crate and Python SDK's `aex_sdk.resolver`.
 * Uses `tangerine` to perform DoH queries against Cloudflare 1.1.1.1, and
 * `undici` to plug the resolved IP back into the outgoing HTTPS connection
 * via `Agent.connect.lookup`. The TLS SNI + Host header stay set to the
 * original hostname so certificate validation continues to work.
 *
 * ## Browser compatibility
 *
 * This module is Node.js only. In browser contexts, the platform fetch
 * already bypasses OS-level DNS quirks for HTTPS URLs, so DoH is neither
 * necessary nor available. Browser consumers should pass the native
 * `fetch` to {@link SpizeClient} and skip the resolver wiring.
 */
import Tangerine from "tangerine";
import { Agent, fetch as undiciFetch } from "undici";
import { isIP } from "node:net";

/**
 * A DNS resolver that queries Cloudflare DNS-over-HTTPS.
 *
 * Holds no mutable state besides internal tangerine config; safe to share
 * across concurrent callers. Each `resolve` call performs a fresh DoH
 * query — no cache, matching the Rust crate's behaviour.
 */
export class CloudflareDoHResolver {
  private readonly inner: Tangerine;

  constructor() {
    // Tangerine defaults to DoH against Cloudflare; setting servers to
    // the 1.1.1.1 endpoints keeps behaviour explicit and in line with
    // the Rust + Python siblings.
    this.inner = new Tangerine({
      servers: ["1.1.1.1", "1.0.0.1"],
    });
  }

  /** Resolve a hostname to its first A record (IPv4). Throws on failure. */
  async resolve(hostname: string): Promise<string> {
    const raw = (await this.inner.resolve4(hostname)) as
      | string
      | string[]
      | { address: string }[]
      | undefined;
    if (!raw) {
      throw new Error(`no A record returned for ${JSON.stringify(hostname)}`);
    }
    const list = Array.isArray(raw) ? raw : [raw];
    const first = list[0];
    if (first === undefined) {
      throw new Error(`no A record returned for ${JSON.stringify(hostname)}`);
    }
    return typeof first === "string" ? first : first.address;
  }
}

/**
 * Decide whether a given URL needs DoH pre-resolution.
 *
 * Pass-through for: non-HTTPS URLs, IP literals, localhost / single-label
 * hostnames. These don't exercise the system resolver's search-domain path.
 */
export function needsDoh(url: URL): boolean {
  if (url.protocol !== "https:") return false;
  const host = url.hostname;
  if (!host || !host.includes(".")) return false;
  return !isIP(host);
}

/**
 * Build a fetch implementation that pre-resolves HTTPS hostnames via DoH
 * before connecting. Pass-through for HTTP, localhost, and IP literals.
 *
 * Implementation: uses an `undici.Agent` whose `connect.lookup` is driven
 * by the DoH resolver. The outgoing URL's hostname is kept intact (for
 * SNI + cert validation + Host header); only the resolved IP is used at
 * the socket layer.
 */
export function buildDohFetch(
  resolver: CloudflareDoHResolver = new CloudflareDoHResolver(),
): typeof globalThis.fetch {
  const dispatcher = new Agent({
    connect: {
      // Node's lookup contract: (hostname, options, callback)
      lookup: (hostname, _options, callback) => {
        resolver
          .resolve(hostname)
          .then((ip) => callback(null, ip, isIP(ip) || 4))
          .catch((err) => callback(err, "", 0));
      },
    },
  });

  const doFetch = ((input, init) => {
    // Pass-through for requests that don't need DoH.
    const rawUrl =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
    const url = new URL(rawUrl);
    if (!needsDoh(url)) {
      return globalThis.fetch(input, init);
    }
    return undiciFetch(input as never, {
      ...(init ?? {}),
      dispatcher,
    } as never) as unknown as Promise<Response>;
  }) as typeof globalThis.fetch;

  return doFetch;
}
