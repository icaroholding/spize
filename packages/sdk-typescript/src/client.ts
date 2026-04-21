import { hex, Identity, randomNonce } from "./identity.js";
import { SpizeError, SpizeHttpError } from "./errors.js";
import { CloudflareDoHResolver, buildDohFetch } from "./resolver.js";
import {
  registrationChallengeBytes,
  ReceiptAction,
  transferIntentBytes,
  transferReceiptBytes,
} from "./wire.js";

export interface SpizeClientOptions {
  baseUrl: string;
  identity: Identity;
  /**
   * Custom fetch implementation. When provided, this overrides every
   * HTTP call and the resolver is ignored (useful for tests with
   * MockTransport-like shims).
   */
  fetch?: typeof globalThis.fetch;
  /**
   * DoH resolver used to build the fetch for tunnel-facing calls
   * ({@link SpizeClient.fetchFromTunnel}, {@link SpizeClient.uploadBlobAdmin}).
   * Node.js only; ignored in browsers.
   */
  resolver?: CloudflareDoHResolver;
  timeoutMs?: number;
}

export interface AgentResponse {
  agent_id: string;
  public_key_hex: string;
  fingerprint: string;
  org: string;
  name: string;
  created_at: string;
}

export interface TransferResponse {
  transferId: string;
  state:
    | "awaiting_scan"
    | "ready_for_pickup"
    | "accepted"
    | "delivered"
    | "rejected"
    | string;
  senderAgentId: string;
  recipient: string;
  sizeBytes: number;
  declaredMime: string | null;
  filename: string | null;
  scannerVerdict: Record<string, unknown> | null;
  policyDecision: Record<string, unknown> | null;
  rejectionCode: string | null;
  rejectionReason: string | null;
  createdAt: string;

  wasRejected: boolean;
  wasDelivered: boolean;
}

export interface AckResponse {
  transfer_id: string;
  state: string;
  audit_chain_head: string;
}

export interface InboxEntry {
  transfer_id: string;
  sender_agent_id: string;
  state: string;
  size_bytes: number;
  declared_mime: string | null;
  filename: string | null;
  created_at: string;
}

export interface InboxResponse {
  agent_id: string;
  count: number;
  entries: InboxEntry[];
}

/**
 * Signed capability (M2) — recipient presents this to the sender's data
 * plane to fetch blob bytes. The signature is from the control plane's
 * signing key; the data plane verifies it with that public key + the
 * declared `data_plane_url` as the audience.
 */
export interface DataPlaneTicket {
  transfer_id: string;
  recipient: string;
  data_plane_url: string;
  expires: number;
  nonce: string;
  signature: string; // hex-encoded Ed25519
}

/**
 * Canonical JSON encoding suitable for the `X-AEX-Ticket` header value.
 * Keys are emitted without whitespace so the header is identical across
 * SDKs.
 */
export function ticketAsHeader(ticket: DataPlaneTicket): string {
  return JSON.stringify({
    transfer_id: ticket.transfer_id,
    recipient: ticket.recipient,
    data_plane_url: ticket.data_plane_url,
    expires: ticket.expires,
    nonce: ticket.nonce,
    signature: ticket.signature,
  });
}

function fromTransferJson(body: {
  transfer_id: string;
  state: string;
  sender_agent_id: string;
  recipient: string;
  size_bytes: number;
  declared_mime: string | null;
  filename: string | null;
  scanner_verdict: Record<string, unknown> | null;
  policy_decision: Record<string, unknown> | null;
  rejection_code: string | null;
  rejection_reason: string | null;
  created_at: string;
}): TransferResponse {
  return {
    transferId: body.transfer_id,
    state: body.state,
    senderAgentId: body.sender_agent_id,
    recipient: body.recipient,
    sizeBytes: Number(body.size_bytes),
    declaredMime: body.declared_mime,
    filename: body.filename,
    scannerVerdict: body.scanner_verdict,
    policyDecision: body.policy_decision,
    rejectionCode: body.rejection_code,
    rejectionReason: body.rejection_reason,
    createdAt: body.created_at,
    wasRejected: body.state === "rejected",
    wasDelivered: body.state === "delivered",
  };
}

export class SpizeClient {
  readonly baseUrl: string;
  readonly identity: Identity;
  private readonly _fetch: typeof globalThis.fetch;
  private readonly _tunnelFetch: typeof globalThis.fetch;
  private readonly timeoutMs: number;

  constructor(opts: SpizeClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.identity = opts.identity;
    this._fetch = opts.fetch ?? globalThis.fetch.bind(globalThis);
    // Tunnel-facing calls go through DoH by default so a freshly-created
    // *.trycloudflare.com hostname resolves even on wifi with a search-
    // domain suffix. A caller-supplied `fetch` opts out of DoH entirely
    // (intended for tests + browser builds where DoH is irrelevant).
    if (opts.fetch) {
      this._tunnelFetch = opts.fetch;
    } else {
      this._tunnelFetch = buildDohFetch(opts.resolver);
    }
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  // ---------- health ----------

  async health(): Promise<Record<string, unknown>> {
    return this.getJson("/healthz");
  }

  // ---------- registration ----------

  async register(): Promise<AgentResponse> {
    const issuedAt = Math.floor(Date.now() / 1000);
    const nonce = randomNonce();
    const challenge = registrationChallengeBytes({
      publicKeyHex: this.identity.publicKeyHex,
      org: this.identity.org,
      name: this.identity.name,
      nonce,
      issuedAtUnix: issuedAt,
    });
    const sig = await this.identity.sign(challenge);
    return this.postJson("/v1/agents/register", {
      public_key_hex: this.identity.publicKeyHex,
      org: this.identity.org,
      name: this.identity.name,
      nonce,
      issued_at: issuedAt,
      signature_hex: hex.encode(sig),
    });
  }

  async getAgent(agentId: string): Promise<AgentResponse> {
    return this.getJson(`/v1/agents/${agentId}`);
  }

  // ---------- transfers ----------

  async send(args: {
    recipient: string;
    data: Uint8Array;
    declaredMime?: string;
    filename?: string;
  }): Promise<TransferResponse> {
    const declaredMime = args.declaredMime ?? "";
    const filename = args.filename ?? "";
    const issuedAt = Math.floor(Date.now() / 1000);
    const nonce = randomNonce();
    const canonical = transferIntentBytes({
      senderAgentId: this.identity.agentId,
      recipient: args.recipient,
      sizeBytes: args.data.length,
      declaredMime,
      filename,
      nonce,
      issuedAtUnix: issuedAt,
    });
    const sig = await this.identity.sign(canonical);
    const body = await this.postJson<any>("/v1/transfers", {
      sender_agent_id: this.identity.agentId,
      recipient: args.recipient,
      declared_mime: declaredMime,
      filename,
      nonce,
      issued_at: issuedAt,
      intent_signature_hex: hex.encode(sig),
      blob_hex: hex.encode(args.data),
    });
    return fromTransferJson(body);
  }

  async getTransfer(transferId: string): Promise<TransferResponse> {
    const body = await this.getJson<any>(`/v1/transfers/${transferId}`);
    return fromTransferJson(body);
  }

  async download(transferId: string): Promise<Uint8Array> {
    const body = await this.postJson<{ blob_hex: string }>(
      `/v1/transfers/${transferId}/download`,
      await this.buildReceipt(transferId, "download"),
    );
    return hex.decode(body.blob_hex);
  }

  async ack(transferId: string): Promise<AckResponse> {
    return this.postJson(
      `/v1/transfers/${transferId}/ack`,
      await this.buildReceipt(transferId, "ack"),
    );
  }

  /** List transfers waiting for this identity (state: ready_for_pickup or accepted). */
  async inbox(): Promise<InboxResponse> {
    return this.postJson("/v1/inbox", await this.buildReceipt("inbox", "inbox"));
  }

  // ---------- M2 (peer-to-peer data plane) ----------

  /**
   * Announce a transfer WITHOUT uploading the payload. The sender must
   * be running an `aex-data-plane` reachable at `tunnelUrl`; the control
   * plane stores the URL and signs tickets against it.
   */
  async sendViaTunnel(args: {
    recipient: string;
    declaredSize: number;
    declaredMime: string;
    filename: string;
    tunnelUrl: string;
  }): Promise<TransferResponse> {
    const issuedAt = Math.floor(Date.now() / 1000);
    const nonce = randomNonce();
    const canonical = transferIntentBytes({
      senderAgentId: this.identity.agentId,
      recipient: args.recipient,
      sizeBytes: args.declaredSize,
      declaredMime: args.declaredMime,
      filename: args.filename,
      nonce,
      issuedAtUnix: issuedAt,
    });
    const sig = await this.identity.sign(canonical);
    const body = await this.postJson<any>("/v1/transfers", {
      sender_agent_id: this.identity.agentId,
      recipient: args.recipient,
      declared_mime: args.declaredMime,
      filename: args.filename,
      nonce,
      issued_at: issuedAt,
      intent_signature_hex: hex.encode(sig),
      blob_hex: "",
      tunnel_url: args.tunnelUrl,
      declared_size: args.declaredSize,
    });
    return fromTransferJson(body);
  }

  /**
   * Request a signed data-plane ticket for a transfer in
   * `ready_for_pickup` state. The returned ticket is used with
   * {@link fetchFromTunnel} to pull the bytes directly from the sender.
   */
  async requestTicket(transferId: string): Promise<DataPlaneTicket> {
    const body = await this.postJson<DataPlaneTicket>(
      `/v1/transfers/${transferId}/ticket`,
      await this.buildReceipt(transferId, "request_ticket"),
    );
    return {
      transfer_id: body.transfer_id,
      recipient: body.recipient,
      data_plane_url: body.data_plane_url,
      expires: Number(body.expires),
      nonce: body.nonce,
      signature: body.signature,
    };
  }

  /**
   * Fetch blob bytes from the sender's data plane using a previously
   * requested ticket. This request does NOT go through the control
   * plane — the bytes flow directly from the sender's tunnel.
   */
  async fetchFromTunnel(ticket: DataPlaneTicket): Promise<Uint8Array> {
    const url = `${ticket.data_plane_url.replace(/\/+$/, "")}/blob/${ticket.transfer_id}`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const resp = await this._tunnelFetch(url, {
        method: "GET",
        headers: { "x-aex-ticket": ticketAsHeader(ticket) },
        signal: ctrl.signal,
      });
      if (!resp.ok) {
        let body: { code?: string; message?: string } = {};
        try {
          body = (await resp.json()) as typeof body;
        } catch {
          /* empty */
        }
        throw new SpizeHttpError(
          resp.status,
          body.code ?? null,
          body.message ?? resp.statusText,
        );
      }
      const buf = await resp.arrayBuffer();
      return new Uint8Array(buf);
    } catch (err) {
      if (err instanceof SpizeError) throw err;
      if (err instanceof Error && err.name === "AbortError") {
        throw new SpizeError(
          `fetch_from_tunnel timed out after ${this.timeoutMs}ms`,
        );
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Upload a blob to a data plane's admin endpoint (M2 orchestrated mode).
   *
   * Wraps `POST /admin/blob/:transfer_id` on `aex-data-plane`. Used by
   * demos and desktop orchestrators that launch a data-plane with a
   * short-lived admin token and push blobs for pre-declared transfer
   * IDs. DoH-routed, same reason as {@link fetchFromTunnel}.
   */
  async uploadBlobAdmin(args: {
    dataPlaneUrl: string;
    transferId: string;
    adminToken: string;
    payload: Uint8Array;
    mime?: string;
    filename?: string;
  }): Promise<void> {
    const mime = args.mime ?? "application/octet-stream";
    const filename = args.filename ?? "blob";
    const base = args.dataPlaneUrl.replace(/\/+$/, "");
    const qs = new URLSearchParams({ mime, filename }).toString();
    const url = `${base}/admin/blob/${args.transferId}?${qs}`;

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const resp = await this._tunnelFetch(url, {
        method: "POST",
        headers: {
          "x-aex-admin-token": args.adminToken,
          "content-type": "application/octet-stream",
        },
        // Uint8Array is a valid BodyInit in both the lib.dom fetch and
        // the undici fetch used by Node, but the types diverge — cast
        // keeps TS happy across both.
        body: args.payload as unknown as ReadableStream<Uint8Array>,
        signal: ctrl.signal,
      });
      if (resp.status !== 201) {
        const body = await resp.text().catch(() => "");
        throw new SpizeError(
          `admin upload rejected: status=${resp.status} body=${body.slice(0, 300)}`,
        );
      }
    } catch (err) {
      if (err instanceof SpizeError) throw err;
      if (err instanceof Error && err.name === "AbortError") {
        throw new SpizeError(
          `upload_blob_admin timed out after ${this.timeoutMs}ms`,
        );
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  private async buildReceipt(
    transferId: string,
    action: ReceiptAction,
  ): Promise<Record<string, unknown>> {
    const issuedAt = Math.floor(Date.now() / 1000);
    const nonce = randomNonce();
    const canonical = transferReceiptBytes({
      recipientAgentId: this.identity.agentId,
      transferId,
      action,
      nonce,
      issuedAtUnix: issuedAt,
    });
    const sig = await this.identity.sign(canonical);
    return {
      recipient_agent_id: this.identity.agentId,
      nonce,
      issued_at: issuedAt,
      signature_hex: hex.encode(sig),
    };
  }

  // ---------- HTTP helpers ----------

  private async getJson<T>(path: string): Promise<T> {
    return this.request<T>(path, { method: "GET" });
  }

  private async postJson<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const resp = await this._fetch(`${this.baseUrl}${path}`, {
        ...init,
        signal: ctrl.signal,
      });
      if (!resp.ok) {
        let body: { code?: string; message?: string } = {};
        try {
          body = (await resp.json()) as typeof body;
        } catch {
          /* empty */
        }
        throw new SpizeHttpError(
          resp.status,
          body.code ?? null,
          body.message ?? resp.statusText,
        );
      }
      return (await resp.json()) as T;
    } catch (err) {
      if (err instanceof SpizeError) throw err;
      if (err instanceof Error && err.name === "AbortError") {
        throw new SpizeError(`request timed out after ${this.timeoutMs}ms`);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }
}
