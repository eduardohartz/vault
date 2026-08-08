import type { NextRequest } from "next/server"
import type { SessionUser } from "./session"
import { NextResponse } from "next/server"
import { clientIp, rateLimit } from "./rate-limit"
import { getSessionUser } from "./session"

/** Consistent JSON error, with no-store so responses are never cached. */
export function apiError(message: string, status: number, extraHeaders?: HeadersInit): NextResponse {
  return NextResponse.json(
    { error: message },
    { status, headers: { "Cache-Control": "no-store", ...(extraHeaders ?? {}) } },
  )
}

export function apiJson(body: unknown, status = 200): NextResponse {
  return NextResponse.json(body, { status, headers: { "Cache-Control": "no-store" } })
}

/**
 * Resolve the caller's session, or return a 401 response to hand straight back.
 *
 * Every route previously trusted `Authorization: Bearer <userId>` — an
 * unexpiring, unrevocable value equal to the user's database primary key.
 */
export async function requireSession(): Promise<{ user: SessionUser } | { response: NextResponse }> {
  const user = await getSessionUser()

  if (!user) {
    return { response: apiError("Unauthorized", 401) }
  }

  return { user }
}

/** Apply a rate limit keyed on route plus client IP. */
export function enforceRateLimit(request: NextRequest, route: string, limit: number, windowMs: number): NextResponse | null {
  const result = rateLimit(`${route}:${clientIp(request)}`, limit, windowMs)

  if (!result.allowed) {
    return apiError("Too many requests. Please slow down.", 429, {
      "Retry-After": String(result.retryAfterSeconds),
    })
  }

  return null
}

/** Normalise a username the same way everywhere. */
export function normalizeUsername(value: unknown): string | null {
  if (typeof value !== "string") {
    return null
  }

  const trimmed = value.trim().toLowerCase()

  if (trimmed.length < 1 || trimmed.length > 64) {
    return null
  }

  // Keep usernames to a predictable shape; they are shown in the UI and used
  // as WebAuthn user names.
  if (!/^[a-z0-9._-]+$/.test(trimmed)) {
    return null
  }

  return trimmed
}
