import { NextResponse } from "next/server"

let registeredUsers: Array<{
  id: string
  username: string
  credentialId: string
  publicKey: string
}> = []

if (typeof global !== "undefined") {
  if (!global.registeredUsers) {
    global.registeredUsers = []
  }
  registeredUsers = global.registeredUsers
}

export async function GET() {
  return NextResponse.json({
    hasUsers: registeredUsers.length > 0,
    userCount: registeredUsers.length,
  })
}
