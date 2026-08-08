import { describe, expect, it } from "vitest"
import { BufferHelper } from "@/lib/buffer-helper"
import { CryptoManager } from "@/lib/crypto-manager"

describe("base64url round trip", () => {
  it("round trips arbitrary bytes", () => {
    for (const len of [0, 1, 2, 3, 31, 32, 33, 1000]) {
      const bytes = crypto.getRandomValues(new Uint8Array(len))
      const encoded = BufferHelper.bytesToBase64Url(bytes)
      expect(Array.from(BufferHelper.base64UrlToBytes(encoded))).toEqual(Array.from(bytes))
    }
  })

  it("emits no URL-hostile characters", () => {
    for (let i = 0; i < 200; i++) {
      const encoded = BufferHelper.bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)))
      expect(encoded).not.toMatch(/[+/=]/)
    }
  })

  it("rejects invalid input instead of silently decoding it", () => {
    expect(() => BufferHelper.base64UrlToBytes("not valid!!")).toThrow()
  })
})

describe("share keys", () => {
  it("generates a distinct key every time", () => {
    const keys = new Set(Array.from({ length: 500 }, () => CryptoManager.generateShareKey()))
    expect(keys.size).toBe(500)
  })

  it("generates 32 bytes of key material", () => {
    expect(BufferHelper.base64UrlToBytes(CryptoManager.generateShareKey()).length).toBe(32)
  })

  // Derived keys are non-extractable so a browser extension cannot lift them,
  // which means tests compare them by behaviour rather than by raw bytes.
  const interchangeable = async (a: CryptoKey, b: CryptoKey) => {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, a, new TextEncoder().encode("probe"))
    try {
      return new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, b, ciphertext)) === "probe"
    } catch {
      return false
    }
  }

  it("is not extractable", async () => {
    const key = await CryptoManager.deriveShareKey(CryptoManager.generateShareKey(), crypto.getRandomValues(new Uint8Array(16)))

    expect(key.extractable).toBe(false)
    await expect(crypto.subtle.exportKey("raw", key)).rejects.toThrow()
  })

  it("derives the same AES key from the same share key and salt", async () => {
    const shareKey = CryptoManager.generateShareKey()
    const salt = crypto.getRandomValues(new Uint8Array(16))

    expect(await interchangeable(
      await CryptoManager.deriveShareKey(shareKey, salt),
      await CryptoManager.deriveShareKey(shareKey, salt),
    )).toBe(true)
  })

  it("derives different keys for different salts", async () => {
    const shareKey = CryptoManager.generateShareKey()

    expect(await interchangeable(
      await CryptoManager.deriveShareKey(shareKey, crypto.getRandomValues(new Uint8Array(16))),
      await CryptoManager.deriveShareKey(shareKey, crypto.getRandomValues(new Uint8Array(16))),
    )).toBe(false)
  })

  it("rejects a share key that is not 32 bytes", async () => {
    const short = BufferHelper.bytesToBase64Url(new Uint8Array(16))
    await expect(CryptoManager.deriveShareKey(short, new Uint8Array(16))).rejects.toThrow("Invalid share key")
  })

  it("encrypts and decrypts a round trip through a share key", async () => {
    const shareKey = CryptoManager.generateShareKey()
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const key = await CryptoManager.deriveShareKey(shareKey, salt)

    const plaintext = new TextEncoder().encode("vault contents")
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext)

    const recovered = await CryptoManager.decryptFile(ciphertext, key, iv)
    expect(new TextDecoder().decode(recovered)).toBe("vault contents")
  })

  it("fails to decrypt with a different share key", async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const key = await CryptoManager.deriveShareKey(CryptoManager.generateShareKey(), salt)
    const wrong = await CryptoManager.deriveShareKey(CryptoManager.generateShareKey(), salt)

    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode("secret"))

    await expect(CryptoManager.decryptFile(ciphertext, wrong, iv)).rejects.toThrow()
  })
})
