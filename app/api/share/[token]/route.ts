import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/db"
import fs from "fs/promises"
import path from "path"

export async function GET(
  request: NextRequest,
  { params }: { params: { token: string } },
) {
  try {
    // Find the shared file by token
    const sharedFile = await prisma.sharedFile.findUnique({
      where: { shareToken: params.token },
      include: {
        file: true,
      },
    })

    if (!sharedFile) {
      return NextResponse.json(
        { error: "Shared file not found" },
        { status: 404 },
      )
    }

    // Check if share has expired
    if (sharedFile.expiresAt && new Date() > sharedFile.expiresAt) {
      return NextResponse.json(
        { error: "Share link has expired" },
        { status: 410 },
      )
    }

    // Get the encrypted file path
    const encryptedFilesDir =
      process.env.ENCRYPTED_FILES_DIR || "./encrypted_files"
    const filePath = path.join(encryptedFilesDir, sharedFile.sharedFilePath)

    // Check if file exists
    try {
      await fs.access(filePath)
    } catch (error) {
      return NextResponse.json(
        { error: "File not found on server" },
        { status: 404 },
      )
    }

    // Read the encrypted file as binary
    const encryptedFileContent = await fs.readFile(filePath)

    // Convert to base64 for JSON transport
    const encryptedDataBase64 = encryptedFileContent.toString("base64")

    // Return file metadata and encrypted data - NO USER INFO
    return NextResponse.json({
      file: {
        id: sharedFile.file.id,
        encryptedName: sharedFile.file.encryptedName,
        nameIv: sharedFile.file.nameIv,
        nameSalt: sharedFile.file.nameSalt,
        originalSize: sharedFile.file.originalSize,
        encryptedData: encryptedDataBase64,
        iv: sharedFile.iv,
        salt: sharedFile.salt,
        uploadedAt: sharedFile.file.uploadedAt,
      },
      expiresAt: sharedFile.expiresAt,
      // NO sharedBy user info - this was the security issue
    })
  } catch (error) {
    console.error("Share fetch error:", error)
    return NextResponse.json(
      { error: "Failed to fetch shared file" },
      { status: 500 },
    )
  }
}
