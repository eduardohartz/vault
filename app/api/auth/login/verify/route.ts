import type { NextRequest } from "next/server"
import { apiError, apiJson, enforceRateLimit } from "@/lib/api"
import { createSession, setSessionCookie } from "@/lib/session"
import { verifyAuthentication } from "@/lib/webauthn"

export async function POST(request: NextRequest) {
  const limited = enforceRateLimit(request, "login-verify", 20, 60_000)
  if (limited) {
    return limited
  }

  try {
    const body = await request.json().catch(() => null)

    if (!body?.response || typeof body.challenge !== "string") {
      return apiError("Bad Request", 400)
    }

    const result = await verifyAuthentication(request, body.response, body.challenge)

    if (!result.verified) {
      // Deliberately generic: distinguishing "unknown credential" from "bad
      // signature" would leak which credentials are registered.
      return apiError("Authentication failed", 401)
    }

    const token = await createSession(result.user.id)
    await setSessionCookie(token)

    return apiJson({
      success: true,
      user: {
        id: result.user.id,
        username: result.user.username,
        keyVersion: result.user.keyVersion,
      },
    })
  } catch (error) {
    console.error("Authentication verification failed:", error)
    return apiError("Authentication failed", 500)
  }
}
