import { rm } from "node:fs/promises"
import { join } from "node:path"
import { apiError, apiJson, requireSession } from "@/lib/api"
import { prisma } from "@/lib/db"
import { getEncryptedFilesDir } from "@/lib/env"
import { destroyCurrentSession } from "@/lib/session"

export async function DELETE() {
  const auth = await requireSession()
  if ("response" in auth) {
    return auth.response
  }

  const encryptedFilesDir = getEncryptedFilesDir()

  try {
    const fileRecords = await prisma.file.findMany({
      where: { userId: auth.user.id },
      include: { SharedFile: true },
    })

    // Collect every path first, then await all removals *before* deleting the
    // user. The previous version used `forEach(async ...)`, which discards the
    // returned promises: the cascade delete ran first, so the lookups for
    // shared files found nothing and shared ciphertext was left on disk
    // forever — while "delete my account and all files" reported success.
    const paths = fileRecords.flatMap((record) => {
      const own = [join(encryptedFilesDir, record.encryptedPath)]
      if (record.SharedFile) {
        own.push(join(encryptedFilesDir, record.SharedFile.sharedFilePath))
      }
      return own
    })

    const results = await Promise.allSettled(paths.map((path) => rm(path, { force: true })))

    const failures = results.filter((r) => r.status === "rejected")
    if (failures.length > 0) {
      // Refuse to drop the database rows we would need to retry with. Leaving
      // the account intact is recoverable; orphaned ciphertext is not.
      console.error(`Failed to delete ${failures.length} file(s) from disk:`, failures)
      return apiError("Could not delete all of your files. Nothing was removed; please try again.", 500)
    }

    await prisma.user.delete({ where: { id: auth.user.id } })
    await destroyCurrentSession()

    return apiJson({ success: true })
  } catch (error) {
    console.error("Account deletion failed:", error)
    return apiError("Failed to delete account", 500)
  }
}
