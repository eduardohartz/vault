import type { NextRequest } from "next/server"
import { existsSync } from "node:fs"
import { mkdir, rm, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { apiError, apiJson, enforceRateLimit, requireSession } from "@/lib/api"
import { prisma } from "@/lib/db"
import { getEncryptedFilesDir, getMaxFileSize, getMaxUserQuota } from "@/lib/env"

const ENCRYPTED_FILES_DIR = getEncryptedFilesDir()

// AES-GCM appends a 16-byte authentication tag, so ciphertext is always exactly
// plaintext + 16. That lets us verify the client's claimed size rather than
// trusting it for quota accounting.
const GCM_TAG_BYTES = 16

async function ensureDirectoryExists() {
  if (!existsSync(ENCRYPTED_FILES_DIR)) {
    await mkdir(ENCRYPTED_FILES_DIR, { recursive: true })
  }
}

export async function GET() {
  const auth = await requireSession()
  if ("response" in auth) {
    return auth.response
  }

  try {
    // Include share state in the same query. The client previously issued a
    // separate request per file to discover this, turning one page load into
    // N+1 round trips.
    const files = await prisma.file.findMany({
      where: { userId: auth.user.id },
      orderBy: { uploadedAt: "desc" },
      select: {
        id: true,
        encryptedName: true,
        originalSize: true,
        iv: true,
        nameIv: true,
        uploadedAt: true,
        SharedFile: {
          select: { shareToken: true, expiresAt: true, createdAt: true },
        },
      },
    })

    return apiJson({
      files: files.map(({ SharedFile, ...file }) => ({
        ...file,
        isShared: SharedFile !== null,
        share: SharedFile
          ? { shareToken: SharedFile.shareToken, expiresAt: SharedFile.expiresAt, createdAt: SharedFile.createdAt }
          : null,
      })),
    })
  } catch (error) {
    console.error("Failed to load files:", error)
    return apiError("Failed to load files", 500)
  }
}

export async function POST(request: NextRequest) {
  const auth = await requireSession()
  if ("response" in auth) {
    return auth.response
  }

  const limited = enforceRateLimit(request, "upload", 60, 60_000)
  if (limited) {
    return limited
  }

  const maxFileSize = getMaxFileSize()

  // Reject oversized bodies before buffering them into memory. Uploads were
  // previously unbounded, so a single large request could exhaust the server.
  const contentLength = Number.parseInt(request.headers.get("content-length") ?? "", 10)
  if (Number.isFinite(contentLength) && contentLength > maxFileSize * 2) {
    return apiError(`File exceeds the ${Math.floor(maxFileSize / 1024 / 1024)} MB limit`, 413)
  }

  let filePath: string | null = null

  try {
    await ensureDirectoryExists()

    const formData = await request.formData()
    const encryptedData = formData.get("encryptedData")
    const iv = formData.get("iv")
    const encryptedName = formData.get("encryptedName")
    const nameIv = formData.get("nameIv")
    const rawOriginalSize = formData.get("originalSize")

    if (
      typeof encryptedData !== "string"
      || typeof iv !== "string"
      || typeof encryptedName !== "string"
      || typeof nameIv !== "string"
      || typeof rawOriginalSize !== "string"
    ) {
      return apiError("Bad Request", 400)
    }

    const originalSize = Number.parseInt(rawOriginalSize, 10)

    // `!originalSize` used to reject a perfectly valid zero-byte file.
    if (!Number.isInteger(originalSize) || originalSize < 0) {
      return apiError("Bad Request", 400)
    }

    if (originalSize > maxFileSize) {
      return apiError(`File exceeds the ${Math.floor(maxFileSize / 1024 / 1024)} MB limit`, 413)
    }

    const ciphertext = Buffer.from(encryptedData, "base64")

    if (ciphertext.length !== originalSize + GCM_TAG_BYTES) {
      return apiError("Encrypted payload does not match the declared size", 400)
    }

    const used = await prisma.file.aggregate({
      where: { userId: auth.user.id },
      _sum: { originalSize: true },
    })

    const quota = getMaxUserQuota()
    if ((used._sum.originalSize ?? 0) + originalSize > quota) {
      return apiError(`Storage quota of ${Math.floor(quota / 1024 / 1024)} MB exceeded`, 413)
    }

    const fileName = `${crypto.randomUUID()}.enc`
    filePath = join(ENCRYPTED_FILES_DIR, fileName)

    await writeFile(filePath, JSON.stringify({ encryptedData, iv }), "utf8")

    const newFile = await prisma.file.create({
      data: {
        encryptedName,
        originalSize,
        encryptedPath: fileName,
        iv,
        nameIv,
        userId: auth.user.id,
      },
      select: {
        id: true,
        encryptedName: true,
        originalSize: true,
        iv: true,
        nameIv: true,
        uploadedAt: true,
      },
    })

    return apiJson({ success: true, file: { ...newFile, isShared: false, share: null } })
  } catch (error) {
    // The database row is the source of truth. If the insert failed after the
    // blob landed on disk, remove the blob so it cannot accumulate as an
    // unreferenced orphan.
    if (filePath) {
      await rm(filePath, { force: true }).catch(() => {})
    }
    console.error("Upload failed:", error)
    return apiError("Upload failed", 500)
  }
}
