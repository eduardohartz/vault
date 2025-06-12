import { Buffer } from "node:buffer"
import fs from "node:fs/promises"
import path from "node:path"
import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/db"

const ENCRYPTED_FILES_DIR = process.env.ENCRYPTED_FILES_DIR || "./encrypted_files"

export async function POST(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const formData = await request.formData()
    const encryptedData = formData.get("encryptedData") as string
    const iv = formData.get("iv") as string
    const salt = formData.get("salt") as string
    const encryptedName = formData.get("encryptedName") as string
    const nameIv = formData.get("nameIv") as string
    const nameSalt = formData.get("nameSalt") as string
    const originalSize = Number.parseInt(formData.get("originalSize") as string)
    const userId = formData.get("userId") as string
    const expiresAt = formData.get("expiresAt") as string

    if (!userId) {
      return NextResponse.json({ error: "User ID required" }, { status: 400 })
    }

    const file = await prisma.file.findFirst({
      where: {
        id: params.id,
        userId,
      },
    })

    if (!file) {
      return NextResponse.json({ error: "File not found or access denied" }, { status: 404 })
    }

    const shareToken = crypto.randomUUID()

    const sharedFilePath = `shared_${shareToken}.bin`
    const sharedFileFullPath = path.join(ENCRYPTED_FILES_DIR, sharedFilePath)

    await fs.writeFile(sharedFileFullPath, Buffer.from(encryptedData, "base64"))

    await prisma.sharedFile.create({
      data: {
        shareToken,
        salt,
        fileId: file.id,
        sharedById: userId,
        expiresAt: expiresAt ? new Date(expiresAt) : null,
        sharedFilePath,
        iv,
        encryptedName,
        nameIv,
        nameSalt,
        originalSize,
        createdAt: new Date(),
      },
    })

    const baseUrl = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000"
    const shareUrl = `${baseUrl}/share/${shareToken}`

    return NextResponse.json({
      success: true,
      shareToken,
      shareUrl,
      message: "Share link created! Remember to share the share key with the recipient.",
    })
  } catch {
    return NextResponse.json({ error: "Failed to create share" }, { status: 500 })
  }
}

export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
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
      select: {
        id: true,
        shareToken: true,
        expiresAt: true,
        iv: true,
        encryptedName: true,
        nameIv: true,
        nameSalt: true,
        originalSize: true,
        createdAt: true,
      },
    })

    return NextResponse.json({ shares })
  } catch {
    return NextResponse.json({ error: "Failed to fetch shares" }, { status: 500 })
  }
}

export async function DELETE(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const { userId } = await request.json()

    if (!userId) {
      return NextResponse.json({ error: "User ID required" }, { status: 400 })
    }

    const file = await prisma.file.findFirst({
      where: {
        id: params.id,
        userId,
      },
    })

    if (!file) {
      return NextResponse.json({ error: "File not found or access denied" }, { status: 404 })
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
          const sharedFilePath = path.join(ENCRYPTED_FILES_DIR, share.sharedFilePath)
          await fs.rm(sharedFilePath)
        } catch {}
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
  } catch {
    return NextResponse.json({ error: "Failed to unshare file" }, { status: 500 })
  }
}
