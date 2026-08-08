import { apiJson } from "@/lib/api"
import { prisma } from "@/lib/db"
import { getMaxUsers } from "@/lib/env"
import { getSessionUser } from "@/lib/session"

/**
 * Current session plus whether registration is still open.
 *
 * This replaces the old /api/auth/username endpoint, which answered
 * "does this username exist?" for anyone who asked — free user enumeration.
 * Sign-in uses discoverable credentials and needs no username at all, so
 * nothing here is keyed on one.
 */
export async function GET() {
  const user = await getSessionUser()

  let canRegister = false
  try {
    canRegister = (await prisma.user.count()) < getMaxUsers()
  } catch (error) {
    console.error("Failed to read user count:", error)
  }

  if (!user) {
    return apiJson({ authenticated: false, canRegister })
  }

  return apiJson({ authenticated: true, user, canRegister })
}
