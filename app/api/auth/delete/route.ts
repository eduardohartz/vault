import { rm } from "node:fs/promises"
import { join } from "node:path"
import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/db"

const ENCRYPTED_FILES_DIR = process.env.ENCRYPTED_FILES_DIR || "./encrypted_files"

export async function DELETE(request: NextRequest) {
  try {
    const userId = request.headers.get("Authorization")?.replace("Bearer ", "")

    if (!userId) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
    }

    const fileRecords = await prisma.file.findMany({
      where: {
        userId,
      },
    })

    if (fileRecords.length > 0) {
      try {
        fileRecords.forEach(async (fileRecord) => {
          const filePath = join(ENCRYPTED_FILES_DIR, fileRecord.encryptedPath)
          await rm(filePath)

          const shared = await prisma.sharedFile.findUnique({
            where: { fileId: fileRecord.id },
          })

          if (shared) {
            const sharedFilePath = join(ENCRYPTED_FILES_DIR, shared.sharedFilePath)
            await rm(sharedFilePath)
          }
        })
      } catch (error) {
        console.error("Failed to delete file from disk:", error)
      }
    }

    await prisma.user.delete({
      where: { id: userId },
    })

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error("Delete error:", error)
    return NextResponse.json({ error: "Error fetching file" }, { status: 500 })
  }
}
