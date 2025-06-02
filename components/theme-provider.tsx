"use client"

import type React from "react"

import { HeroUIProvider } from "@heroui/react"
import { ThemeProvider as NextThemesProvider } from "next-themes"
import { useRouter } from "next/navigation"

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter()

  return (
    <HeroUIProvider navigate={router.push}>
      <NextThemesProvider
        attribute="class"
        defaultTheme="dark"
        themes={["light", "dark"]}
        enableSystem={false}
      >
        {children}
      </NextThemesProvider>
    </HeroUIProvider>
  )
}
