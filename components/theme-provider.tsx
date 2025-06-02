"use client"

import type React from "react"

import { NextUIProvider } from "@nextui-org/react"
import { ThemeProvider as NextThemesProvider } from "next-themes"
import { useRouter } from "next/navigation"

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter()

  return (
    <NextUIProvider navigate={router.push}>
      <NextThemesProvider attribute="class" defaultTheme="dark" themes={["light", "dark"]} enableSystem={false}>
        {children}
      </NextThemesProvider>
    </NextUIProvider>
  )
}
