/**
 * Destructive database reset.
 *
 * This was previously wired up as `prisma.seed`, meaning `prisma db seed`
 * would delete every user, file and share — and the file it pointed at used
 * ESM syntax with a .cjs extension, so it could never actually run. It is now
 * an explicitly named script behind a confirmation flag.
 *
 * Encrypted blobs on disk are NOT removed by this script; clear
 * ENCRYPTED_FILES_DIR separately if you want a truly clean slate.
 *
 *   CONFIRM_RESET=yes npm run db:reset
 */
import { PrismaClient } from "@prisma/client"

if (process.env.CONFIRM_RESET !== "yes") {
  console.error("Refusing to wipe the database. Re-run with CONFIRM_RESET=yes if you are sure.")
  process.exit(1)
}

const prisma = new PrismaClient()

async function main() {
  // Sessions, files and shares all cascade from users.
  const { count } = await prisma.user.deleteMany()
  await prisma.challenge.deleteMany()
  console.warn(`Deleted ${count} user(s) and all dependent records.`)
  console.warn("Encrypted files on disk were not touched.")
}

main()
  .catch((error) => {
    console.error(error)
    process.exitCode = 1
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
