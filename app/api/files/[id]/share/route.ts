import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/db"
import fs from "fs/promises"
import path from "path"

const ENCRYPTED_FILES_DIR =
  process.env.ENCRYPTED_FILES_DIR || "./encrypted_files"

export async function POST(
  request: NextRequest,
  { params }: { params: { id: string } },
) {
  try {
    const { userId, expiresAt, shareKey } = await request.json()

    if (!userId) {
      return NextResponse.json({ error: "User ID required" }, { status: 400 })
    }

    const file = await prisma.file.findFirst({
      where: {
        id: params.id,
        userId: userId,
      },
    })

    if (!file) {
      return NextResponse.json(
        { error: "File not found or access denied" },
        { status: 404 },
      )
    }

    const filePath = path.join(ENCRYPTED_FILES_DIR, file.encryptedPath)
    const fileContent = await fs.readFile(filePath, "utf8")
    const fileData = JSON.parse(fileContent)

    const shareToken = crypto.randomUUID()
    const shareSalt = crypto.getRandomValues(new Uint8Array(16))
    const shareSaltBase64 = Buffer.from(shareSalt).toString("base64")

    const sharedFilePath = `shared_${shareToken}.bin`
    const sharedFileFullPath = path.join(ENCRYPTED_FILES_DIR, sharedFilePath)

    await fs.writeFile(
      sharedFileFullPath,
      Buffer.from(fileData.encryptedData, "base64"),
    )

    const sharedFile = await prisma.sharedFile.create({
      data: {
        shareToken,
        salt: shareSaltBase64,
        fileId: file.id,
        sharedById: userId,
        expiresAt: expiresAt ? new Date(expiresAt) : null,
        sharedFilePath: sharedFilePath,
        iv: fileData.iv,
      },
    })

    const baseUrl = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000"
    const shareUrl = `${baseUrl}/share/${shareToken}`

    return NextResponse.json({
      success: true,
      shareToken,
      shareUrl,
      message:
        "Share link created! Remember to share the share key with the recipient.",
    })
  } catch (error) {
    console.error("Share error:", error)
    return NextResponse.json(
      { error: "Failed to create share" },
      { status: 500 },
    )
  }
}

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } },
) {
  try {
    const { searchParams } = new URL(request.url)
    const userId = searchParams.get("userId")

    if (!userId) {
      return NextResponse.json({ error: "User ID required" }, { status: 400 })
    }

    const shares = await prisma.sharedFile.findMany({
      where: {
        fileId: params.id,
        sharedById: userId,
      },
      orderBy: { createdAt: "desc" },
    })

    return NextResponse.json({ shares })
  } catch (error) {
    console.error("Share fetch error:", error)
    return NextResponse.json(
      { error: "Failed to fetch shares" },
      { status: 500 },
    )
  }
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } },
) {
  try {
    const { userId } = await request.json()

    if (!userId) {
      return NextResponse.json({ error: "User ID required" }, { status: 400 })
    }

    const file = await prisma.file.findFirst({
      where: {
        id: params.id,
        userId: userId,
      },
    })

    if (!file) {
      return NextResponse.json(
        { error: "File not found or access denied" },
        { status: 404 },
      )
    }

    const shares = await prisma.sharedFile.findMany({
      where: {
        fileId: params.id,
        sharedById: userId,
      },
    })

    for (const share of shares) {
      if (share.sharedFilePath) {
        try {
          const sharedFilePath = path.join(
            ENCRYPTED_FILES_DIR,
            share.sharedFilePath,
          )
          await fs.unlink(sharedFilePath)
        } catch (err) {
          console.error("Failed to delete shared file:", err)
        }
      }
    }

    const deleteResult = await prisma.sharedFile.deleteMany({
      where: {
        fileId: params.id,
        sharedById: userId,
      },
    })

    return NextResponse.json({
      success: true,
      message: `Removed ${deleteResult.count} share(s)`,
    })
  } catch (error) {
    console.error("Unshare error:", error)
    return NextResponse.json(
      { error: "Failed to unshare file" },
      { status: 500 },
    )
  }
}
