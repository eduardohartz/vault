/**
 * Server-side configuration.
 *
 * `APP_URL` is read at runtime rather than through a NEXT_PUBLIC_ variable
 * because public variables are inlined at build time — the previous
 * `NEXT_PUBLIC_APP_URL` was never set in compose.yml or .env.example, so every
 * self-hosted deployment produced share links pointing at localhost.
 */

function readAppUrl(): URL | null {
  const raw = process.env.APP_URL || process.env.NEXT_PUBLIC_APP_URL
  if (!raw) {
    return null
  }

  try {
    return new URL(raw)
  } catch {
    console.error(`Invalid APP_URL: ${raw}`)
    return null
  }
}

/**
 * Absolute base URL for links we hand to users.
 *
 * Falls back to the incoming request's origin so a deployment that forgets to
 * set APP_URL still emits usable share links instead of localhost ones.
 */
export function getBaseUrl(request?: { url: string, headers: Headers }): string {
  const configured = readAppUrl()
  if (configured) {
    return configured.origin
  }

  if (request) {
    const forwardedHost = request.headers.get("x-forwarded-host")
    const forwardedProto = request.headers.get("x-forwarded-proto")
    if (forwardedHost) {
      return `${forwardedProto || "https"}://${forwardedHost}`
    }
    return new URL(request.url).origin
  }

  return "http://localhost:3000"
}

/** WebAuthn Relying Party ID — the registrable domain, no scheme or port. */
export function getRpId(request?: { url: string, headers: Headers }): string {
  if (process.env.WEBAUTHN_RP_ID) {
    return process.env.WEBAUTHN_RP_ID
  }
  return new URL(getBaseUrl(request)).hostname
}

export function getRpName(): string {
  return process.env.WEBAUTHN_RP_NAME || "Vault"
}

/**
 * Origins accepted during WebAuthn verification. Defaults to the app's own
 * origin; WEBAUTHN_ALLOWED_ORIGINS can add more for split-domain setups.
 */
export function getAllowedOrigins(request?: { url: string, headers: Headers }): string[] {
  const extra = (process.env.WEBAUTHN_ALLOWED_ORIGINS || "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean)

  return Array.from(new Set([getBaseUrl(request), ...extra]))
}

export function getMaxUsers(): number {
  const parsed = Number.parseInt(process.env.MAX_USERS ?? "", 10)
  // A single shared default, rather than the previous 0-here/10-there split
  // that let the UI claim registration was closed while the API allowed ten.
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 3
}

/** Maximum size of a single uploaded file, in bytes. */
export function getMaxFileSize(): number {
  const parsed = Number.parseInt(process.env.MAX_FILE_SIZE_BYTES ?? "", 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 100 * 1024 * 1024
}

/** Maximum total stored bytes per user. */
export function getMaxUserQuota(): number {
  const parsed = Number.parseInt(process.env.MAX_USER_QUOTA_BYTES ?? "", 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 1024 * 1024 * 1024
}

export function getEncryptedFilesDir(): string {
  return process.env.ENCRYPTED_FILES_DIR || "./encrypted_files"
}

export const SESSION_COOKIE_NAME = "vault_session"

/** Session lifetime in milliseconds. */
export function getSessionTtlMs(): number {
  const parsed = Number.parseInt(process.env.SESSION_TTL_MINUTES ?? "", 10)
  const minutes = Number.isFinite(parsed) && parsed > 0 ? parsed : 60
  return minutes * 60 * 1000
}
