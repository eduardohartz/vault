"use client"

import type { AuthenticatedUser } from "@/components/auth-page"
import { useCallback, useState } from "react"
import AuthPage from "@/components/auth-page"
import FileManager from "@/components/file-manager"
import SessionGuard from "@/components/session-guard"

export default function Home() {
  const [user, setUser] = useState<AuthenticatedUser | null>(null)

  // Reload rather than only clearing state: derived CryptoKeys and any
  // decrypted filenames still referenced by the React tree go with the JS
  // context. Callers revoke the server session before getting here.
  const handleLogout = useCallback(() => {
    setUser(null)
    window.location.reload()
  }, [])

  if (!user) {
    return <AuthPage onAuthenticated={setUser} />
  }

  return (
    <>
      <SessionGuard onExpire={handleLogout} />
      <FileManager user={user} onLogout={handleLogout} />
    </>
  )
}
