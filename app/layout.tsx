import type { Metadata } from "next"
import type React from "react"
import { Inter } from "next/font/google"
import { headers } from "next/headers"
import { ThemeProvider } from "@/components/theme-provider"
import "./globals.css"

const inter = Inter({ subsets: ["latin"], variable: "--font-inter", display: "swap" })

export const metadata: Metadata = {
  title: "Vault",
  description: "End-to-end encrypted, passkey-protected file storage",
  robots: { index: false, follow: false },
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Supplied by middleware.ts; next-themes needs it to nonce its inline
  // theme-bootstrap script, which the CSP would otherwise block.
  const nonce = (await headers()).get("x-nonce") ?? undefined

  return (
    <html lang="en" suppressHydrationWarning className={inter.variable}>
      <body className={inter.className}>
        <ThemeProvider nonce={nonce}>{children}</ThemeProvider>
      </body>
    </html>
  )
}
