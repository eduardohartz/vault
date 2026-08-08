import { PrismaPg } from "@prisma/adapter-pg"
import { PrismaClient } from "@prisma/client"

/**
 * Prisma 7 no longer reads the connection string from schema.prisma. The client
 * is constructed with a driver adapter instead, which means the connection
 * string is needed at construction time rather than at first query.
 *
 * That matters for the build: Next imports every route module to collect page
 * data, and there is no DATABASE_URL at build time. Constructing eagerly failed
 * the build outright, so the real client is created on first property access
 * and the error surfaces at request time, where it can be handled.
 */
const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined
}

function createClient(): PrismaClient {
  const connectionString = process.env.DATABASE_URL

  if (!connectionString) {
    throw new Error("DATABASE_URL is not set")
  }

  return new PrismaClient({ adapter: new PrismaPg({ connectionString }) })
}

function getClient(): PrismaClient {
  if (!globalForPrisma.prisma) {
    globalForPrisma.prisma = createClient()
  }
  return globalForPrisma.prisma
}

export const prisma: PrismaClient = new Proxy({} as PrismaClient, {
  get: (_target, property, receiver) => Reflect.get(getClient(), property, receiver),
  has: (_target, property) => property in getClient(),
  ownKeys: () => Reflect.ownKeys(getClient()),
  getOwnPropertyDescriptor: (_target, property) => {
    const descriptor = Reflect.getOwnPropertyDescriptor(getClient(), property)
    return descriptor && { ...descriptor, configurable: true }
  },
})
