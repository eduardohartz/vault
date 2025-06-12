import fs from "node:fs/promises"
import path from "node:path"
import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/db"

export async function GET(request: NextRequest, { params }: { params: { token: string } }) {
  try {
    const sharedFile = await prisma.sharedFile.findUnique({
      where: { shareToken: params.token },
      include: {
        file: false,
      },
    })

    if (!sharedFile) {
      return NextResponse.json({ error: "Shared file not found" }, { status: 404 })
    }

    if (sharedFile.expiresAt && new Date() > sharedFile.expiresAt) {
      return NextResponse.json({ error: "Share link has expired" }, { status: 410 })
    }

    const encryptedFilesDir = process.env.ENCRYPTED_FILES_DIR || "./encrypted_files"
    const filePath = path.join(encryptedFilesDir, sharedFile.sharedFilePath)

    try {
      await fs.access(filePath)
    } catch {
      return NextResponse.json({ error: "File not found on server" }, { status: 404 })
    }

    const encryptedFileContent = await fs.readFile(filePath)

    const encryptedDataBase64 = encryptedFileContent.toString("base64")

    return NextResponse.json({
      id: sharedFile.id,
      salt: sharedFile.salt,
      expiresAt: sharedFile.expiresAt ? new Date(sharedFile.expiresAt) : null,
      sharedFilePath: sharedFile.sharedFilePath,
      iv: sharedFile.iv,
      encryptedName: sharedFile.encryptedName,
      nameIv: sharedFile.nameIv,
      nameSalt: sharedFile.nameSalt,
      originalSize: sharedFile.originalSize,
      encryptedData: encryptedDataBase64,
      createdAt: new Date(),
    })
  } catch {
    return NextResponse.json({ error: "Failed to fetch shared file" }, { status: 500 })
  }
}
