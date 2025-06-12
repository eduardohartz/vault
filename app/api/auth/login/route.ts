import { type NextRequest, NextResponse } from "next/server"
import { prisma } from "@/lib/db"

export async function POST(request: NextRequest) {
  try {
    const { credentialId, publicKey } = await request.json()

    const user = await prisma.user.findUnique({
      where: { credentialId, publicKey },
    })

    if (!user) {
      return NextResponse.json({ error: "Error logging in" }, { status: 401 })
    }

    return NextResponse.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
      },
    })
  } catch {
    return NextResponse.json({ error: "Authentication failed" }, { status: 500 })
  }
}
