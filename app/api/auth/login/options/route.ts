import type { NextRequest } from "next/server"
import { apiError, apiJson, enforceRateLimit } from "@/lib/api"
import { pruneExpired } from "@/lib/session"
import { buildAuthenticationOptions } from "@/lib/webauthn"

export async function POST(request: NextRequest) {
  const limited = enforceRateLimit(request, "login-options", 20, 60_000)
  if (limited) {
    return limited
  }

  try {
    await pruneExpired()

    // Discoverable credentials, so no username is required or accepted here.
    // Not taking one also means this endpoint reveals nothing about which
    // accounts exist.
    const options = await buildAuthenticationOptions(request)

    return apiJson({ options })
  } catch (error) {
    console.error("Failed to build authentication options:", error)
    return apiError("Could not start authentication", 500)
  }
}
