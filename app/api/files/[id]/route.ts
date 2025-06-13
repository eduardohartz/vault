import { readFile, rm } from "node:fs/promises"
import { join } from "node:path"
import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/db"

const ENCRYPTED_FILES_DIR = process.env.ENCRYPTED_FILES_DIR || "./encrypted_files"

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const userId = request.headers.get("Authorization")?.replace("Bearer ", "")

    if (!userId) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
    }

    const fileRecord = await prisma.file.findFirst({
      where: {
        id: (await params).id,
        userId,
      },
      select: {
        id: true,
        encryptedName: true,
        originalSize: true,
        uploadedAt: true,
        salt: true,
        iv: true,
        nameSalt: true,
        nameIv: true,
        encryptedPath: true,
      },
    })

    if (!fileRecord) {
      return NextResponse.json({ error: "Error fetching file" }, { status: 404 })
    }

    const filePath = join(ENCRYPTED_FILES_DIR, fileRecord.encryptedPath)
    const encryptedFileData = await readFile(filePath, "utf8")
    const parsedData = JSON.parse(encryptedFileData)

    return NextResponse.json({
      file: {
        ...fileRecord,
        encryptedData: parsedData.encryptedData,
        iv: parsedData.iv,
      },
    })
  } catch {
    return NextResponse.json({ error: "Error fetching file" }, { status: 404 })
  }
}

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const userId = request.headers.get("Authorization")?.replace("Bearer ", "")

    if (!userId) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
    }

    const fileRecord = await prisma.file.findFirst({
      where: {
        id: (await params).id,
        userId,
      },
    })

    if (!fileRecord) {
      return NextResponse.json({ error: "Error fetching file" }, { status: 404 })
    }

    const filePath = join(ENCRYPTED_FILES_DIR, fileRecord.encryptedPath)
    try {
      await rm(filePath)
    } catch (error) {
      console.error("Failed to delete file from disk:", error)
    }

    const shared = await prisma.sharedFile.findUnique({
      where: { fileId: (await params).id },
    })

    if (shared) {
      const sharedFilePath = join(ENCRYPTED_FILES_DIR, shared.sharedFilePath)
      try {
        await rm(sharedFilePath)
      } catch (error) {
        console.error("Failed to delete shared file from disk:", error)
      }

      await prisma.sharedFile.delete({
        where: { id: shared.id },
      })
    }

    await prisma.file.delete({
      where: { id: (await params).id },
    })

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error("Delete error:", error)
    return NextResponse.json({ error: "Error fetching file" }, { status: 500 })
  }
}
