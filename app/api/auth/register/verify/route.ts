import type { NextRequest } from "next/server"
import { Prisma } from "@prisma/client"
import { apiError, apiJson, enforceRateLimit } from "@/lib/api"
import { CURRENT_KEY_VERSION } from "@/lib/crypto-manager"
import { prisma } from "@/lib/db"
import { getMaxUsers } from "@/lib/env"
import { createSession, setSessionCookie } from "@/lib/session"
import { verifyRegistration } from "@/lib/webauthn"

export async function POST(request: NextRequest) {
  const limited = enforceRateLimit(request, "register-verify", 10, 60_000)
  if (limited) {
    return limited
  }

  try {
    const body = await request.json().catch(() => null)

    if (!body?.response || typeof body.challenge !== "string") {
      return apiError("Bad Request", 400)
    }

    const result = await verifyRegistration(request, body.response, body.challenge)

    if (!result.verified) {
      return apiError(result.reason, 401)
    }

    if (!result.username) {
      return apiError("Registration challenge is missing its username", 400)
    }

    const { credential } = result

    // Serializable so the user-count check and the insert cannot interleave
    // with a concurrent registration and overshoot MAX_USERS.
    const user = await prisma.$transaction(
      async (tx) => {
        if ((await tx.user.count()) >= getMaxUsers()) {
          throw new Error("MAX_USERS")
        }

        return tx.user.create({
          data: {
            username: result.username!,
            credentialId: credential.id,
            credentialPublicKey: Buffer.from(credential.publicKey),
            counter: credential.counter,
            transports: credential.transports ?? [],
            keyVersion: CURRENT_KEY_VERSION,
          },
        })
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.Serializable },
    ).catch((error: unknown) => {
      if (error instanceof Error && error.message === "MAX_USERS") {
        return null
      }
      throw error
    })

    if (!user) {
      return apiError("Maximum number of users reached", 403)
    }

    const token = await createSession(user.id)
    await setSessionCookie(token)

    return apiJson({
      success: true,
      user: { id: user.id, username: user.username, keyVersion: user.keyVersion },
    })
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
      return apiError("Username or credential already registered", 409)
    }
    console.error("Registration verification failed:", error)
    return apiError("Registration failed", 500)
  }
}
