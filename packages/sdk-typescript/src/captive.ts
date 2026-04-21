/**
 * Captive-portal detection via three standard probe endpoints.
 *
 * TypeScript mirror of the Rust `aex-net::captive` and Python
 * `aex_sdk.captive` modules. Behaviour is identical to the precision
 * described by `docs/protocol-v1.md` §5.3.
 */

/** Apple captive-portal probe URL. */
export const APPLE_URL = "http://captive.apple.com/hotspot-detect.html";
/** Google 204 endpoint. */
export const GOOGLE_URL = "http://www.google.com/generate_204";
/** Microsoft NCSI probe URL. */
export const MS_URL = "http://www.msftncsi.com/ncsi.txt";

const APPLE_EXPECTED_BODY_FRAGMENT = "Success";
const MS_EXPECTED_BODY = "Microsoft NCSI";

const PROBE_TIMEOUT_MS = 5000;

/**
 * Network reachability state.
 *
 * Serialised via {@link networkStateToStdoutValue} into the
 * `AEX_NETWORK_STATE=<value>` stdout flag emitted by the data-plane
 * binary. Values must stay in sync with Rust + Python.
 */
export type NetworkState =
  | "direct"
  | "captive_portal"
  | "limited"
  | "unknown";

/** Canonical string emitted by the AEX_NETWORK_STATE=<value> stdout flag. */
export function networkStateToStdoutValue(state: NetworkState): string {
  return state;
}

type ProbeVerdict = "ok" | "captive" | "unexpected" | "failed";

export interface DetectNetworkStateOptions {
  fetch?: typeof globalThis.fetch;
  appleUrl?: string;
  googleUrl?: string;
  msUrl?: string;
  timeoutMs?: number;
}

/** Fire the three probes in parallel and return the consensus state. */
export async function detectNetworkState(
  options: DetectNetworkStateOptions = {},
): Promise<NetworkState> {
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  const timeoutMs = options.timeoutMs ?? PROBE_TIMEOUT_MS;
  const appleUrl = options.appleUrl ?? APPLE_URL;
  const googleUrl = options.googleUrl ?? GOOGLE_URL;
  const msUrl = options.msUrl ?? MS_URL;

  const [apple, google, ms] = await Promise.all([
    probeApple(fetchImpl, appleUrl, timeoutMs),
    probeGoogle(fetchImpl, googleUrl, timeoutMs),
    probeMs(fetchImpl, msUrl, timeoutMs),
  ]);

  return consensus([apple, google, ms]);
}

export function consensus(results: readonly ProbeVerdict[]): NetworkState {
  if (results.includes("captive")) return "captive_portal";
  if (results.every((v) => v === "ok")) return "direct";
  if (results.every((v) => v === "failed")) return "unknown";
  return "limited";
}

async function probeApple(
  fetchImpl: typeof globalThis.fetch,
  url: string,
  timeoutMs: number,
): Promise<ProbeVerdict> {
  const resp = await safeFetch(fetchImpl, url, timeoutMs, "manual");
  if (!resp) return "failed";
  if (resp.status >= 300 && resp.status < 400) return "captive";
  if (!resp.ok) return "unexpected";
  const body = await resp.text().catch(() => null);
  if (body === null) return "failed";
  return body.includes(APPLE_EXPECTED_BODY_FRAGMENT) ? "ok" : "captive";
}

async function probeGoogle(
  fetchImpl: typeof globalThis.fetch,
  url: string,
  timeoutMs: number,
): Promise<ProbeVerdict> {
  const resp = await safeFetch(fetchImpl, url, timeoutMs, "manual");
  if (!resp) return "failed";
  if (resp.status >= 300 && resp.status < 400) return "captive";
  if (resp.status === 204) return "ok";
  return "unexpected";
}

async function probeMs(
  fetchImpl: typeof globalThis.fetch,
  url: string,
  timeoutMs: number,
): Promise<ProbeVerdict> {
  const resp = await safeFetch(fetchImpl, url, timeoutMs, "manual");
  if (!resp) return "failed";
  if (resp.status >= 300 && resp.status < 400) return "captive";
  if (!resp.ok) return "unexpected";
  const body = await resp.text().catch(() => null);
  if (body === null) return "failed";
  return body.trim() === MS_EXPECTED_BODY ? "ok" : "captive";
}

async function safeFetch(
  fetchImpl: typeof globalThis.fetch,
  url: string,
  timeoutMs: number,
  redirect: "manual" | "error" | "follow",
): Promise<Response | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetchImpl(url, { signal: ctrl.signal, redirect });
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
