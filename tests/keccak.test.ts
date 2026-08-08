import { keccak256 as referenceKeccak256 } from "js-sha3"
import { describe, expect, it } from "vitest"
import { KeccakHelper } from "@/lib/keccak-helper"
import { LegacyKeccakHelper } from "@/lib/keccak-helper-legacy"

const strip = (s: string | null) => (s ?? "").replace(/^0x/, "")
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex")

// Official Keccak-256 vectors (pre-NIST padding, as used by Ethereum).
const VECTORS: [string, string][] = [
  ["", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"],
  ["abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"],
  ["hello", "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"],
  [
    "The quick brown fox jumps over the lazy dog",
    "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15",
  ],
]

describe("keccak-256", () => {
  it.each(VECTORS)("matches the official vector for %o", (input, expected) => {
    expect(strip(KeccakHelper.strKeccak256(input))).toBe(expected)
  })

  // Exercises the multi-block path (rate is 136 bytes for Keccak-256), where
  // the original refactor lost the block offset entirely.
  it.each([1, 135, 136, 137, 200, 500])("agrees with js-sha3 at length %i", (len) => {
    const input = "a".repeat(len)
    expect(strip(KeccakHelper.strKeccak256(input))).toBe(referenceKeccak256(input))
  })

  it("binds message length into the digest (no trailing-zero collisions)", () => {
    const a = strip(KeccakHelper.strictHexKeccak256("41"))
    const b = strip(KeccakHelper.strictHexKeccak256("4100"))
    const c = strip(KeccakHelper.strictHexKeccak256("41000000"))

    expect(a).not.toBe(b)
    expect(b).not.toBe(c)
    expect(a).not.toBe(c)
  })

  it("preserves every bit of the first byte", () => {
    // The broken implementation OR-ed the padding bit into byte 0, collapsing
    // 256 distinct inputs down to 128 distinct digests.
    const digests = new Set<string>()
    for (let i = 0; i < 256; i++) {
      const m = new Uint8Array(32).fill(0xAA)
      m[0] = i
      digests.add(strip(KeccakHelper.strictHexKeccak256(hex(m))))
    }
    expect(digests.size).toBe(256)
  })

  it("returns null for odd-length hex input", () => {
    expect(KeccakHelper.strictHexKeccak256("abc")).toBeNull()
  })

  it("accepts a 0x prefix", () => {
    expect(strip(KeccakHelper.strictHexKeccak256("0x41"))).toBe(
      strip(KeccakHelper.strictHexKeccak256("41")),
    )
  })
})

describe("legacy keccak (v1 vaults)", () => {
  it("is retained unchanged so v1 vaults stay decryptable", () => {
    // These are the values the broken implementation produced. They are wrong
    // as Keccak-256, but v1 keys were derived from them, so they must not move.
    expect(strip(LegacyKeccakHelper.strKeccak256("abc"))).toBe(
      "95492df19ab10438e978bcd46275c53d2a239fa7267628f56ed7452b11df8e61",
    )
    expect(strip(LegacyKeccakHelper.strKeccak256("hello"))).toBe(
      "bb3f60abeae3bd3d0a3e5896f1dfe735aeb9eb84434d23ae70d418ac53265c30",
    )
  })

  it("differs from the corrected implementation", () => {
    expect(strip(LegacyKeccakHelper.strKeccak256("abc"))).not.toBe(
      strip(KeccakHelper.strKeccak256("abc")),
    )
  })
})
