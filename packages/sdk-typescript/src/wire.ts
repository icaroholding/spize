/**
 * Canonical wire-format functions.
 *
 * These MUST produce byte-for-byte identical output to
 * `aex_core::wire` (Rust) and `aex_sdk.wire` (Python). The tests in
 * `tests/wire.test.ts` use the same golden vectors as those projects —
 * DO NOT modify without updating all three in lockstep.
 */

export const PROTOCOL_VERSION = "v1";
export const MAX_CLOCK_SKEW_SECS = 300;
export const MIN_NONCE_LEN = 32;
export const MAX_NONCE_LEN = 128;

const ENCODER = new TextEncoder();

function validateAsciiLine(
  s: string,
  field: string,
  { allowEmpty = false }: { allowEmpty?: boolean } = {},
): void {
  if (s.length === 0) {
    if (allowEmpty) return;
    throw new Error(`${field} is empty`);
  }
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code > 0x7f || code === 0x0a || code === 0x0d || code === 0x00) {
      throw new Error(`${field} has invalid char at ${i}: ${s[i]}`);
    }
  }
}

function validateNonce(nonce: string): void {
  if (nonce.length < MIN_NONCE_LEN || nonce.length > MAX_NONCE_LEN) {
    throw new Error(
      `nonce length ${nonce.length} outside [${MIN_NONCE_LEN}, ${MAX_NONCE_LEN}]`,
    );
  }
  if (!/^[0-9a-fA-F]+$/.test(nonce)) {
    throw new Error("nonce must be hex");
  }
}

export function registrationChallengeBytes(args: {
  publicKeyHex: string;
  org: string;
  name: string;
  nonce: string;
  issuedAtUnix: number;
}): Uint8Array {
  validateAsciiLine(args.publicKeyHex, "public_key_hex");
  validateAsciiLine(args.org, "org");
  validateAsciiLine(args.name, "name");
  validateNonce(args.nonce);
  return ENCODER.encode(
    `spize-register:${PROTOCOL_VERSION}\n` +
      `pub=${args.publicKeyHex}\n` +
      `org=${args.org}\n` +
      `name=${args.name}\n` +
      `nonce=${args.nonce}\n` +
      `ts=${args.issuedAtUnix}`,
  );
}

export function transferIntentBytes(args: {
  senderAgentId: string;
  recipient: string;
  sizeBytes: number | bigint;
  declaredMime: string;
  filename: string;
  nonce: string;
  issuedAtUnix: number;
}): Uint8Array {
  validateAsciiLine(args.senderAgentId, "sender_agent_id");
  validateAsciiLine(args.recipient, "recipient");
  validateAsciiLine(args.declaredMime, "declared_mime", { allowEmpty: true });
  validateAsciiLine(args.filename, "filename", { allowEmpty: true });
  validateNonce(args.nonce);
  return ENCODER.encode(
    `spize-transfer-intent:${PROTOCOL_VERSION}\n` +
      `sender=${args.senderAgentId}\n` +
      `recipient=${args.recipient}\n` +
      `size=${args.sizeBytes}\n` +
      `mime=${args.declaredMime}\n` +
      `filename=${args.filename}\n` +
      `nonce=${args.nonce}\n` +
      `ts=${args.issuedAtUnix}`,
  );
}

/**
 * Canonical bytes signed by the OUTGOING (current) key when rotating
 * to a new one. See ADR-0024 and `aex_core::wire::rotate_key_challenge_bytes`.
 */
export function rotateKeyChallengeBytes(args: {
  agentId: string;
  oldPublicKeyHex: string;
  newPublicKeyHex: string;
  nonce: string;
  issuedAtUnix: number;
}): Uint8Array {
  validateAsciiLine(args.agentId, "agent_id");
  validateAsciiLine(args.oldPublicKeyHex, "old_public_key_hex");
  validateAsciiLine(args.newPublicKeyHex, "new_public_key_hex");
  validateNonce(args.nonce);
  if (args.oldPublicKeyHex === args.newPublicKeyHex) {
    throw new Error("old_public_key_hex and new_public_key_hex must differ");
  }
  return ENCODER.encode(
    `spize-rotate-key:${PROTOCOL_VERSION}\n` +
      `agent=${args.agentId}\n` +
      `old_pub=${args.oldPublicKeyHex}\n` +
      `new_pub=${args.newPublicKeyHex}\n` +
      `nonce=${args.nonce}\n` +
      `ts=${args.issuedAtUnix}`,
  );
}

export type ReceiptAction = "download" | "ack" | "inbox" | "request_ticket";

const RECEIPT_ACTIONS: readonly ReceiptAction[] = [
  "download",
  "ack",
  "inbox",
  "request_ticket",
];

export function transferReceiptBytes(args: {
  recipientAgentId: string;
  transferId: string;
  action: ReceiptAction;
  nonce: string;
  issuedAtUnix: number;
}): Uint8Array {
  validateAsciiLine(args.recipientAgentId, "recipient_agent_id");
  validateAsciiLine(args.transferId, "transfer_id");
  validateAsciiLine(args.action, "action");
  validateNonce(args.nonce);
  if (!RECEIPT_ACTIONS.includes(args.action)) {
    throw new Error(
      `action must be one of ${RECEIPT_ACTIONS.join(", ")}, got ${args.action}`,
    );
  }
  return ENCODER.encode(
    `spize-transfer-receipt:${PROTOCOL_VERSION}\n` +
      `recipient=${args.recipientAgentId}\n` +
      `transfer=${args.transferId}\n` +
      `action=${args.action}\n` +
      `nonce=${args.nonce}\n` +
      `ts=${args.issuedAtUnix}`,
  );
}
