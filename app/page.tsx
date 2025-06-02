"use client"

import { useState } from "react"
import AuthPage from "@/components/auth-page"
import FileManager from "@/components/file-manager"

export default function Home() {
  const [user, setUser] = useState<{
    id: string
    username: string
    shareKey: string
    privateKeyRaw: Uint8Array
  } | null>(null)

  const handleAuthenticated = (authenticatedUser: {
    id: string
    username: string
    shareKey: string
    privateKeyRaw: Uint8Array
  }) => {
    setUser(authenticatedUser)
  }

  const handleLogout = () => {
    setUser(null)
  }

  if (!user) {
    return <AuthPage onAuthenticated={handleAuthenticated} />
  }

  return <FileManager user={user} onLogout={handleLogout} />
}
