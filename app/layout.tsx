import type { Metadata } from "next"
import type React from "react"
import { Inter } from "next/font/google"
import Inactivity from "@/components/inactivity"
import { ThemeProvider } from "@/components/theme-provider"
import "./globals.css"

const inter = Inter({ subsets: ["latin"] })

export const metadata: Metadata = {
  title: "Vault",
  description: "Vault storage for files",
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={inter.className}>
        <Inactivity />
        <ThemeProvider>{children}</ThemeProvider>
      </body>
    </html>
  )
}
