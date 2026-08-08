import type { NextRequest } from "next/server"
import { Buffer } from "node:buffer"
import fs from "node:fs/promises"
import path from "node:path"
import { apiError, apiJson, enforceRateLimit, requireSession } from "@/lib/api"
import { prisma } from "@/lib/db"
import { getBaseUrl, getEncryptedFilesDir, getMaxFileSize } from "@/lib/env"

const ENCRYPTED_FILES_DIR = getEncryptedFilesDir()
const GCM_TAG_BYTES = 16

export async function POST(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireSession()
  if ("response" in auth) {
    return auth.response
  }

  const limited = enforceRateLimit(request, "share-create", 30, 60_000)
  if (limited) {
    return limited
  }

  const maxFileSize = getMaxFileSize()
  let sharedFileFullPath: string | null = null

  try {
    const { id } = await params

    const formData = await request.formData()
    const encryptedData = formData.get("encryptedData")
    const iv = formData.get("iv")
    const salt = formData.get("salt")
    const encryptedName = formData.get("encryptedName")
    const nameIv = formData.get("nameIv")
    const nameSalt = formData.get("nameSalt")
    const rawOriginalSize = formData.get("originalSize")
    const rawExpiresAt = formData.get("expiresAt")

    if (
      typeof encryptedData !== "string"
      || typeof iv !== "string"
      || typeof salt !== "string"
      || typeof encryptedName !== "string"
      || typeof nameIv !== "string"
      || typeof nameSalt !== "string"
      || typeof rawOriginalSize !== "string"
    ) {
      return apiError("Bad Request", 400)
    }

    const originalSize = Number.parseInt(rawOriginalSize, 10)
    if (!Number.isInteger(originalSize) || originalSize < 0 || originalSize > maxFileSize) {
      return apiError("Bad Request", 400)
    }

    let expiresAt: Date | null = null
    if (typeof rawExpiresAt === "string" && rawExpiresAt.length > 0) {
      const parsed = new Date(rawExpiresAt)
      if (Number.isNaN(parsed.getTime()) || parsed.getTime() <= Date.now()) {
        return apiError("Share expiry must be a valid date in the future", 400)
      }
      expiresAt = parsed
    }

    const file = await prisma.file.findFirst({
      where: { id, userId: auth.user.id },
      include: { SharedFile: true },
    })

    if (!file) {
      return apiError("File not found or access denied", 404)
    }

    if (file.SharedFile) {
      return apiError("File already shared", 409)
    }

    const ciphertext = Buffer.from(encryptedData, "base64")
    if (ciphertext.length !== originalSize + GCM_TAG_BYTES) {
      return apiError("Encrypted payload does not match the declared size", 400)
    }

    const shareToken = crypto.randomUUID()
    const sharedFilePath = `shared_${shareToken}.enc`
    sharedFileFullPath = path.join(ENCRYPTED_FILES_DIR, sharedFilePath)

    await fs.writeFile(sharedFileFullPath, ciphertext)

    await prisma.sharedFile.create({
      data: {
        shareToken,
        salt,
        fileId: file.id,
        sharedById: auth.user.id,
        expiresAt,
        sharedFilePath,
        iv,
        encryptedName,
        nameIv,
        nameSalt,
        originalSize,
      },
    })

    return apiJson({
      success: true,
      shareToken,
      shareUrl: `${getBaseUrl(request)}/share/${shareToken}`,
      expiresAt,
      message: "Share link created. Send the share key to the recipient separately.",
    })
  } catch (error) {
    if (sharedFileFullPath) {
      await fs.rm(sharedFileFullPath, { force: true }).catch(() => {})
    }
    console.error("Failed to create share:", error)
    return apiError("Failed to create share", 500)
  }
}

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireSession()
  if ("response" in auth) {
    return auth.response
  }

  try {
    const { id } = await params

    const share = await prisma.sharedFile.findFirst({
      where: { fileId: id, sharedById: auth.user.id },
      select: {
        id: true,
        shareToken: true,
        expiresAt: true,
        createdAt: true,
        originalSize: true,
      },
    })

    if (!share) {
      return apiError("Share not found", 404)
    }

    return apiJson({
      ...share,
      shareUrl: `${getBaseUrl(request)}/share/${share.shareToken}`,
    })
  } catch (error) {
    console.error("Failed to fetch share:", error)
    return apiError("Failed to fetch share", 500)
  }
}

export async function DELETE(_request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireSession()
  if ("response" in auth) {
    return auth.response
  }

  try {
    const { id } = await params

    const share = await prisma.sharedFile.findFirst({
      where: { fileId: id, sharedById: auth.user.id },
    })

    if (!share) {
      return apiError("Share not found", 404)
    }

    try {
      await fs.rm(path.join(ENCRYPTED_FILES_DIR, share.sharedFilePath), { force: true })
    } catch (error) {
      // Keep the row so the blob stays reachable and the unshare can be retried;
      // silently dropping it would leave decryptable ciphertext on disk.
      console.error("Failed to delete shared file from disk:", error)
      return apiError("Could not remove the shared copy from storage. The share is still active.", 500)
    }

    await prisma.sharedFile.delete({ where: { id: share.id } })

    return apiJson({ success: true, message: "Removed share" })
  } catch (error) {
    console.error("Failed to unshare file:", error)
    return apiError("Failed to unshare file", 500)
  }
}
