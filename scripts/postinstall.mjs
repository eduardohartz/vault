#!/usr/bin/env node
/**
 * Regenerate the Prisma client after an install.
 *
 * The generated client lives inside node_modules, so every `pnpm install`
 * removes it. Without this the project typechecks fine until you reinstall,
 * then fails with a confusing "@prisma/client has no exported member
 * PrismaClient" that looks like a broken upgrade rather than a missing step.
 *
 * Skipped when the schema is not present, so an install in a context that has
 * only package.json (the Docker deps stage installs before copying prisma/)
 * succeeds instead of failing on a file it does not have yet.
 */
import { spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import process from "node:process"

if (!existsSync("prisma/schema.prisma")) {
  console.warn("postinstall: no prisma/schema.prisma yet, skipping client generation")
  process.exit(0)
}

const result = spawnSync("prisma", ["generate"], { stdio: "inherit", shell: true })
process.exit(result.status ?? 1)
