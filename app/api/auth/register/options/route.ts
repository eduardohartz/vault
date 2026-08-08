import type { NextRequest } from "next/server"
import { apiError, apiJson, enforceRateLimit, normalizeUsername } from "@/lib/api"
import { prisma } from "@/lib/db"
import { getMaxUsers } from "@/lib/env"
import { pruneExpired } from "@/lib/session"
import { buildRegistrationOptions } from "@/lib/webauthn"

export async function POST(request: NextRequest) {
  const limited = enforceRateLimit(request, "register-options", 10, 60_000)
  if (limited) {
    return limited
  }

  try {
    await pruneExpired()

    const body = await request.json().catch(() => null)
    const username = normalizeUsername(body?.username)

    if (!username) {
      return apiError("Username must be 1-64 characters, using letters, numbers, dot, underscore or hyphen.", 400)
    }

    const existing = await prisma.user.findUnique({ where: { username } })
    if (existing) {
      return apiError("Username is taken", 409)
    }

    if ((await prisma.user.count()) >= getMaxUsers()) {
      return apiError("Maximum number of users reached", 403)
    }

    const options = await buildRegistrationOptions(request, username)

    return apiJson({ options })
  } catch (error) {
    console.error("Failed to build registration options:", error)
    return apiError("Could not start registration", 500)
  }
}
