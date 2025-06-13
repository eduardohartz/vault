"use client"

import { useState } from "react"
import AuthPage from "@/components/auth-page"
import FileManager from "@/components/file-manager"
import Inactivity from "@/components/inactivity"

export default function Home() {
  const [user, setUser] = useState<{
    id: string
    username: string
    shareKey: string
    privateKey: any
    publicKey: any
  } | null>(null)

  const handleAuthenticated = (authenticatedUser: { id: string, username: string, shareKey: string, privateKey: any, publicKey: any }) => {
    setUser(authenticatedUser)
  }

  const handleLogout = () => {
    setUser(null)
  }

  if (!user) {
    return <AuthPage onAuthenticated={handleAuthenticated} />
  }

  return (
    <>
      <Inactivity />
      <FileManager user={user} onLogout={handleLogout} />
    </>
  )
}
