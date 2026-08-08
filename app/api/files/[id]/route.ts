import { readFile, rm } from "node:fs/promises"
import { join } from "node:path"
import { apiError, apiJson, requireSession } from "@/lib/api"
import { prisma } from "@/lib/db"
import { getEncryptedFilesDir } from "@/lib/env"

const ENCRYPTED_FILES_DIR = getEncryptedFilesDir()

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireSession()
  if ("response" in auth) {
    return auth.response
  }

  try {
    const { id } = await params

    const fileRecord = await prisma.file.findFirst({
      where: { id, userId: auth.user.id },
      select: {
        id: true,
        encryptedName: true,
        originalSize: true,
        uploadedAt: true,
        nameIv: true,
        encryptedPath: true,
      },
    })

    if (!fileRecord) {
      return apiError("File not found", 404)
    }

    const filePath = join(ENCRYPTED_FILES_DIR, fileRecord.encryptedPath)
    const parsed = JSON.parse(await readFile(filePath, "utf8"))

    const { encryptedPath, ...safeRecord } = fileRecord

    return apiJson({
      file: {
        ...safeRecord,
        encryptedData: parsed.encryptedData,
        iv: parsed.iv,
      },
    })
  } catch (error) {
    console.error("Failed to fetch file:", error)
    return apiError("Failed to fetch file", 500)
  }
}

export async function DELETE(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireSession()
  if ("response" in auth) {
    return auth.response
  }

  try {
    const { id } = await params

    const fileRecord = await prisma.file.findFirst({
      where: { id, userId: auth.user.id },
      include: { SharedFile: true },
    })

    if (!fileRecord) {
      return apiError("File not found", 404)
    }

    const paths = [join(ENCRYPTED_FILES_DIR, fileRecord.encryptedPath)]
    if (fileRecord.SharedFile) {
      paths.push(join(ENCRYPTED_FILES_DIR, fileRecord.SharedFile.sharedFilePath))
    }

    const results = await Promise.allSettled(paths.map((path) => rm(path, { force: true })))
    const failures = results.filter((r) => r.status === "rejected")

    if (failures.length > 0) {
      // Keep the row so the blob stays reachable and the delete can be retried.
      console.error("Failed to delete file from disk:", failures)
      return apiError("Could not delete the file from storage. Nothing was removed.", 500)
    }

    // Cascades to SharedFile.
    await prisma.file.delete({ where: { id } })

    return apiJson({ success: true })
  } catch (error) {
    console.error("Delete failed:", error)
    return apiError("Failed to delete file", 500)
  }
}
