export class SpizeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SpizeError";
  }
}

export class SpizeHttpError extends SpizeError {
  /**
   * Carries the raw status code, server-provided error `code` tag,
   * the public message, and (Sprint 3, AEX Delight #3) an optional
   * `runbookUrl` pointing at operator remediation docs. Older
   * control planes (pre-v1.3.0-beta.1) don't emit `runbook_url`; in
   * that case this field is `null`.
   */
  constructor(
    public readonly statusCode: number,
    public readonly code: string | null,
    message: string,
    public readonly runbookUrl: string | null = null,
  ) {
    const suffix = runbookUrl ? ` [runbook: ${runbookUrl}]` : "";
    super(`[${statusCode}] ${code ?? "error"}: ${message}${suffix}`);
    this.name = "SpizeHttpError";
  }
}

export class IdentityError extends SpizeError {
  constructor(message: string) {
    super(message);
    this.name = "IdentityError";
  }
}
