import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/db"

export async function POST(request: NextRequest) {
  try {
    const { username, credentialId, publicKey } = await request.json()

    const maxUsers = Number.parseInt(process.env.MAX_USERS || "10")
    const userCount = await prisma.user.count()

    if (userCount >= maxUsers) {
      return NextResponse.json({ error: `Maximum number of users reached` }, { status: 400 })
    }

    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ username: username.trim().toLowerCase() }, { credentialId }],
      },
    })

    if (existingUser) {
      return NextResponse.json({ error: "User already exists" }, { status: 400 })
    }

    const newUser = await prisma.user.create({
      data: {
        username: username.trim().toLowerCase(),
        credentialId,
        publicKey,
      },
    })

    return NextResponse.json({ success: true, userId: newUser.id })
  } catch {
    return NextResponse.json({ error: "Registration failed" }, { status: 500 })
  }
}
