import { defineConfig } from "prisma/config"

/**
 * Prisma 7 moved the datasource URL out of schema.prisma.
 *
 * Migration and introspection commands read the connection string from here;
 * the runtime client gets it through a driver adapter instead (see lib/db.ts).
 *
 * The datasource is attached only when DATABASE_URL is actually set. Prisma's
 * `env()` helper throws the moment the config is loaded, which would break
 * `prisma generate` — that runs at Docker build time, where there is no
 * database and none is needed.
 */
export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: {
    path: "prisma/migrations",
  },
  ...(process.env.DATABASE_URL
    ? { datasource: { url: process.env.DATABASE_URL } }
    : {}),
})
