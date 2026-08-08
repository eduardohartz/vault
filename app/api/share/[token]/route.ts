import type { NextRequest } from "next/server"
import fs from "node:fs/promises"
import path from "node:path"
import { apiError, apiJson, enforceRateLimit } from "@/lib/api"
import { prisma } from "@/lib/db"
import { getEncryptedFilesDir } from "@/lib/env"

const ENCRYPTED_FILES_DIR = getEncryptedFilesDir()

/**
 * Delete expired shares, removing the ciphertext from disk before the row.
 *
 * Expired shares previously returned 410 but were never cleaned up, so the
 * encrypted copy sat on disk indefinitely.
 */
async function reapExpiredShares(): Promise<void> {
  try {
    const expired = await prisma.sharedFile.findMany({
      where: { expiresAt: { not: null, lte: new Date() } },
      select: { id: true, sharedFilePath: true },
      take: 50,
    })

    for (const share of expired) {
      try {
        await fs.rm(path.join(ENCRYPTED_FILES_DIR, share.sharedFilePath), { force: true })
        await prisma.sharedFile.delete({ where: { id: share.id } })
      } catch (error) {
        console.error(`Failed to reap expired share ${share.id}:`, error)
      }
    }
  } catch (error) {
    console.error("Failed to reap expired shares:", error)
  }
}

export async function GET(request: NextRequest, { params }: { params: Promise<{ token: string }> }) {
  const limited = enforceRateLimit(request, "share-fetch", 60, 60_000)
  if (limited) {
    return limited
  }

  try {
    const { token } = await params

    const sharedFile = await prisma.sharedFile.findUnique({
      where: { shareToken: token },
    })

    if (!sharedFile) {
      return apiError("Shared file not found", 404)
    }

    if (sharedFile.expiresAt && sharedFile.expiresAt.getTime() <= Date.now()) {
      void reapExpiredShares()
      return apiError("Share link has expired", 410)
    }

    const filePath = path.join(ENCRYPTED_FILES_DIR, sharedFile.sharedFilePath)

    let encryptedFileContent: Buffer
    try {
      encryptedFileContent = await fs.readFile(filePath)
    } catch {
      return apiError("File not found on server", 404)
    }

    void reapExpiredShares()

    return apiJson({
      id: sharedFile.id,
      salt: sharedFile.salt,
      iv: sharedFile.iv,
      encryptedName: sharedFile.encryptedName,
      nameIv: sharedFile.nameIv,
      nameSalt: sharedFile.nameSalt,
      originalSize: sharedFile.originalSize,
      encryptedData: encryptedFileContent.toString("base64"),
      expiresAt: sharedFile.expiresAt,
      // The real creation time. This previously returned `new Date()`, so a
      // recipient always saw the file as having been shared just now.
      createdAt: sharedFile.createdAt,
    })
  } catch (error) {
    console.error("Failed to fetch shared file:", error)
    return apiError("Failed to fetch shared file", 500)
  }
}
