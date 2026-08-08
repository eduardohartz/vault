import type { NextRequest } from "next/server"

/**
 * Fixed-window rate limiting.
 *
 * In-process and therefore per-instance. That is the right trade for a
 * self-hosted single-container deployment; a multi-replica setup would need a
 * shared store. Previously there was no limiting at all, which left username
 * enumeration, login brute force, and registration-slot exhaustion wide open.
 */

type Bucket = { count: number, resetAt: number }

const buckets = new Map<string, Bucket>()

// Keep the map from growing without bound on a long-running server.
const MAX_TRACKED_KEYS = 10_000

function sweep(now: number): void {
  for (const [key, bucket] of buckets) {
    if (bucket.resetAt <= now) {
      buckets.delete(key)
    }
  }
}

export function clientIp(request: NextRequest): string {
  const forwarded = request.headers.get("x-forwarded-for")
  if (forwarded) {
    return forwarded.split(",")[0].trim()
  }
  return request.headers.get("x-real-ip") || "unknown"
}

export type RateLimitResult = { allowed: boolean, retryAfterSeconds: number }

export function rateLimit(key: string, limit: number, windowMs: number): RateLimitResult {
  const now = Date.now()

  if (buckets.size > MAX_TRACKED_KEYS) {
    sweep(now)
  }

  const bucket = buckets.get(key)

  if (!bucket || bucket.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + windowMs })
    return { allowed: true, retryAfterSeconds: 0 }
  }

  bucket.count += 1

  if (bucket.count > limit) {
    return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000)) }
  }

  return { allowed: true, retryAfterSeconds: 0 }
}

/** Reset all buckets. Test-only. */
export function resetRateLimits(): void {
  buckets.clear()
}
