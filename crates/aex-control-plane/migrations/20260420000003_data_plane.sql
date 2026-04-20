-- M2: data-plane support. Sender serves bytes via Cloudflare tunnel;
-- the control plane issues short-lived tickets so recipients can fetch
-- directly from the sender. The control plane never sees payload bytes.

ALTER TABLE transfers ADD COLUMN tunnel_url TEXT;

-- Per-ticket nonce replay protection. Tickets are single-use.
CREATE TABLE data_plane_ticket_nonces (
    nonce       TEXT        PRIMARY KEY,
    transfer_id TEXT        NOT NULL,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_data_plane_ticket_nonces_expires
    ON data_plane_ticket_nonces (expires_at);
