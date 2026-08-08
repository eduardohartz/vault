import { createHash, randomBytes } from "node:crypto"
import { cookies } from "next/headers"
import { prisma } from "./db"
import { getSessionTtlMs, SESSION_COOKIE_NAME } from "./env"

/**
 * Session handling.
 *
 * Replaces the previous scheme, where the client sent the user's database
 * primary key as `Authorization: Bearer <uuid>`. That value never expired,
 * could not be revoked, and granted full account control to anyone who saw it
 * in a log or proxy trace.
 *
 * A session token is 32 random bytes. Only its SHA-256 hash is stored, so a
 * database leak cannot be replayed as a live session.
 */

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex")
}

export type SessionUser = {
  id: string
  username: string
  keyVersion: number
}

export async function createSession(userId: string): Promise<string> {
  const token = randomBytes(32).toString("base64url")

  await prisma.session.create({
    data: {
      tokenHash: hashToken(token),
      userId,
      expiresAt: new Date(Date.now() + getSessionTtlMs()),
    },
  })

  return token
}

export async function setSessionCookie(token: string): Promise<void> {
  const cookieStore = await cookies()

  cookieStore.set(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    // Secure is required for WebAuthn anyway (secure context), but stays off
    // for plain-HTTP localhost development so the cookie is still set.
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: Math.floor(getSessionTtlMs() / 1000),
  })
}

export async function clearSessionCookie(): Promise<void> {
  const cookieStore = await cookies()
  cookieStore.set(SESSION_COOKIE_NAME, "", { httpOnly: true, path: "/", maxAge: 0 })
}

/**
 * Resolve the current session, or null. Expired sessions are deleted on sight
 * so they cannot linger and be resurrected by a clock change.
 */
export async function getSessionUser(): Promise<SessionUser | null> {
  const cookieStore = await cookies()
  const token = cookieStore.get(SESSION_COOKIE_NAME)?.value

  if (!token) {
    return null
  }

  const session = await prisma.session.findUnique({
    where: { tokenHash: hashToken(token) },
    include: { user: true },
  })

  if (!session) {
    return null
  }

  if (session.expiresAt.getTime() <= Date.now()) {
    await prisma.session.delete({ where: { id: session.id } }).catch(() => {})
    return null
  }

  // Best-effort activity stamp; never fail a request because of it.
  void prisma.session
    .update({ where: { id: session.id }, data: { lastUsedAt: new Date() } })
    .catch(() => {})

  return {
    id: session.user.id,
    username: session.user.username,
    keyVersion: session.user.keyVersion,
  }
}

export async function destroyCurrentSession(): Promise<void> {
  const cookieStore = await cookies()
  const token = cookieStore.get(SESSION_COOKIE_NAME)?.value

  if (token) {
    await prisma.session.deleteMany({ where: { tokenHash: hashToken(token) } }).catch(() => {})
  }

  await clearSessionCookie()
}

/** Remove expired sessions and challenges. Cheap enough to run opportunistically. */
export async function pruneExpired(): Promise<void> {
  const now = new Date()
  await Promise.all([
    prisma.session.deleteMany({ where: { expiresAt: { lte: now } } }).catch(() => {}),
    prisma.challenge.deleteMany({ where: { expiresAt: { lte: now } } }).catch(() => {}),
  ])
}
