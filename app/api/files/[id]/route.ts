import { type NextRequest, NextResponse } from "next/server"
import { readFile, unlink } from "fs/promises"
import { join } from "path"
import { prisma } from "@/lib/db"

const ENCRYPTED_FILES_DIR =
  process.env.ENCRYPTED_FILES_DIR || "./encrypted_files"

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } },
) {
  try {
    const { searchParams } = new URL(request.url)
    const userId = searchParams.get("userId")

    if (!userId) {
      return NextResponse.json(
        { error: "User ID required for private file access" },
        { status: 400 },
      )
    }

    const fileRecord = await prisma.file.findFirst({
      where: {
        id: params.id,
        userId: userId,
      },
    })

    if (!fileRecord) {
      return NextResponse.json(
        { error: "File not found or access denied" },
        { status: 404 },
      )
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
  } catch (error) {
    console.error("File fetch error:", error)
    return NextResponse.json({ error: "File not found" }, { status: 404 })
  }
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } },
) {
  try {
    const { searchParams } = new URL(request.url)
    const userId = searchParams.get("userId")

    if (!userId) {
      return NextResponse.json({ error: "User ID required" }, { status: 400 })
    }

    const fileRecord = await prisma.file.findFirst({
      where: {
        id: params.id,
        userId: userId,
      },
    })

    if (!fileRecord) {
      return NextResponse.json(
        { error: "File not found or access denied" },
        { status: 404 },
      )
    }

    const filePath = join(ENCRYPTED_FILES_DIR, fileRecord.encryptedPath)
    try {
      await unlink(filePath)
    } catch (error) {
      console.error("Failed to delete file from disk:", error)
    }

    await prisma.file.delete({
      where: { id: params.id },
    })

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error("Delete error:", error)
    return NextResponse.json({ error: "Delete failed" }, { status: 500 })
  }
}
