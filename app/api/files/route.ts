import { type NextRequest, NextResponse } from "next/server"
import { writeFile, mkdir } from "fs/promises"
import { join } from "path"
import { existsSync } from "fs"
import { prisma } from "@/lib/db"

const ENCRYPTED_FILES_DIR =
  process.env.ENCRYPTED_FILES_DIR || "./encrypted_files"

async function ensureDirectoryExists() {
  if (!existsSync(ENCRYPTED_FILES_DIR)) {
    await mkdir(ENCRYPTED_FILES_DIR, { recursive: true })
  }
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const userId = searchParams.get("userId")

    if (!userId) {
      return NextResponse.json({ error: "User ID required" }, { status: 400 })
    }

    const files = await prisma.file.findMany({
      where: { userId },
      orderBy: { uploadedAt: "desc" },
    })

    return NextResponse.json({ files })
  } catch (error) {
    console.error("Files fetch error:", error)
    return NextResponse.json({ error: "Failed to load files" }, { status: 500 })
  }
}

export async function POST(request: NextRequest) {
  try {
    await ensureDirectoryExists()

    const formData = await request.formData()
    const encryptedData = formData.get("encryptedData") as string
    const iv = formData.get("iv") as string
    const salt = formData.get("salt") as string
    const encryptedName = formData.get("encryptedName") as string
    const nameIv = formData.get("nameIv") as string
    const nameSalt = formData.get("nameSalt") as string
    const originalSize = Number.parseInt(formData.get("originalSize") as string)
    const userId = formData.get("userId") as string

    if (
      !encryptedData ||
      !iv ||
      !salt ||
      !encryptedName ||
      !nameIv ||
      !nameSalt ||
      !originalSize ||
      !userId
    ) {
      return NextResponse.json(
        { error: "Missing required fields" },
        { status: 400 },
      )
    }

    const fileId = crypto.randomUUID()
    const fileName = `${fileId}.enc`
    const filePath = join(ENCRYPTED_FILES_DIR, fileName)

    const encryptedFileData = {
      encryptedData,
      iv,
    }

    await writeFile(filePath, JSON.stringify(encryptedFileData), "utf8")

    const newFile = await prisma.file.create({
      data: {
        encryptedName,
        originalSize,
        encryptedPath: fileName,
        salt,
        iv,
        nameSalt,
        nameIv,
        userId,
      },
    })

    return NextResponse.json({ success: true, file: newFile })
  } catch (error) {
    console.error("Upload error:", error)
    return NextResponse.json({ error: "Upload failed" }, { status: 500 })
  }
}
