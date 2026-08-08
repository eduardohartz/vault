import { describe, expect, it } from "vitest"
import { BufferHelper } from "@/lib/buffer-helper"
import { CryptoManager } from "@/lib/crypto-manager"
import { KeyHelper } from "@/lib/key-helper"

const seedFrom = (byte: number) => {
  const seed = new Uint8Array(64).fill(byte)
  return seed.buffer as ArrayBuffer
}

describe("deterministic key generation", () => {
  it("derives the same key pair from the same seed", () => {
    const a = CryptoManager.generateKeyPair(seedFrom(0x11))
    const b = CryptoManager.generateKeyPair(seedFrom(0x11))

    expect(a.privateKey).toBe(b.privateKey)
    expect(a.publicKey?.x).toBe(b.publicKey?.x)
    expect(a.publicKey?.y).toBe(b.publicKey?.y)
  })

  it("derives different key pairs from different seeds", () => {
    const a = CryptoManager.generateKeyPair(seedFrom(0x11))
    const b = CryptoManager.generateKeyPair(seedFrom(0x22))

    expect(a.privateKey).not.toBe(b.privateKey)
  })

  it("produces a public key that is on the curve", () => {
    const { publicKey } = CryptoManager.generateKeyPair(seedFrom(0x33))
    expect(BufferHelper.isOnCurve(publicKey)).toBe(true)
  })

  it("rejects a seed that is not 64 bytes", () => {
    expect(() => CryptoManager.generateKeyPair(new Uint8Array(32).buffer as ArrayBuffer)).toThrow("Seed must be a 64-byte ArrayBuffer")
  })
})

describe("pkcs8 import determinism", () => {
  const convert = (privateKey: bigint, publicKey: NonNullable<ReturnType<typeof CryptoManager.generateKeyPair>["publicKey"]>) =>
    new Promise<{ success: boolean, key?: CryptoKey, error?: string }>((resolve) => {
      KeyHelper.convertStandardPKCS8(privateKey, publicKey, resolve)
    })

  it("imports the private key as non-extractable", async () => {
    // The property that stops a malicious extension lifting the master key
    // with a single exportKey call.
    const { privateKey, publicKey } = CryptoManager.generateKeyPair(seedFrom(0x44))
    const result = await convert(privateKey, publicKey!)

    expect(result.success).toBe(true)
    expect(result.key!.extractable).toBe(false)
    await expect(crypto.subtle.exportKey("jwk", result.key!)).rejects.toThrow()
  })

  it("verifies the imported key carries the deterministic scalar", async () => {
    const { privateKey, publicKey } = CryptoManager.generateKeyPair(seedFrom(0x44))
    const result = await convert(privateKey, publicKey!)

    expect(await KeyHelper.derivesExpectedPoint(result.key!, publicKey!)).toBe(true)
  })

  it("produces interchangeable keys across repeated conversions", async () => {
    const { privateKey, publicKey } = CryptoManager.generateKeyPair(seedFrom(0x55))

    const a = await convert(privateKey, publicKey!)
    const b = await convert(privateKey, publicKey!)

    // Cannot compare JWKs any more, so compare what the keys compute:
    // deriveBits works on non-extractable keys.
    const bitsOf = async (key: CryptoKey) => {
      const raw = await crypto.subtle.deriveBits({ name: "ECDH", public: (await KeyHelper.convertKeys(privateKey, publicKey)).publicKey.key! }, key, null)
      return Buffer.from(new Uint8Array(raw)).toString("hex")
    }

    expect(await bitsOf(a.key!)).toBe(await bitsOf(b.key!))
  })

  it("detects a key that does not carry the expected scalar", async () => {
    const { privateKey, publicKey } = CryptoManager.generateKeyPair(seedFrom(0x66))
    const other = CryptoManager.generateKeyPair(seedFrom(0x77))
    const result = await convert(privateKey, publicKey!)

    // The check that makes the Safari template fallback impossible: a randomly
    // generated key can no longer masquerade as the derived one.
    expect(await KeyHelper.derivesExpectedPoint(result.key!, other.publicKey!)).toBe(false)
  })
})

describe("self ECDH vault key", () => {
  it("derives the same AES key on every login for the same seed", async () => {
    const derive = async () => {
      const { privateKey, publicKey } = CryptoManager.generateKeyPair(seedFrom(0x88))
      const keys = await KeyHelper.convertKeys(privateKey, publicKey)
      return CryptoManager.deriveECDHKey(keys.privateKey.key!, keys.publicKey.key!)
    }

    // Non-extractable, so equality is shown by one key decrypting the other's
    // output — which is the property that actually matters for a vault.
    const a = await derive()
    const b = await derive()

    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, a, new TextEncoder().encode("same key"))

    expect(new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, b, ciphertext))).toBe("same key")
  })

  it("is not extractable", async () => {
    const { privateKey, publicKey } = CryptoManager.generateKeyPair(seedFrom(0x99))
    const keys = await KeyHelper.convertKeys(privateKey, publicKey)
    const vaultKey = await CryptoManager.deriveECDHKey(keys.privateKey.key!, keys.publicKey.key!)

    expect(vaultKey.extractable).toBe(false)
    await expect(crypto.subtle.exportKey("raw", vaultKey)).rejects.toThrow()
  })
})
