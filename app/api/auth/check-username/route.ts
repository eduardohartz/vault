import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/db"

export async function POST(request: NextRequest) {
  try {
    const { username } = await request.json()

    if (!username || username.trim().length === 0) {
      return NextResponse.json({ error: "Username is required" }, { status: 400 })
    }

    const existingUser = await prisma.user.findUnique({
      where: { username: username.trim() },
    })

    const userCount = await prisma.user.count()
    const maxUsers = Number.parseInt(process.env.MAX_USERS || "0")

    return NextResponse.json({
      exists: !!existingUser,
      canRegister: !existingUser && userCount < maxUsers,
    })
  } catch {
    return NextResponse.json({ error: "Failed to check username" }, { status: 500 })
  }
}
