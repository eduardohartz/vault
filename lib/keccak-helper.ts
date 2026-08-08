import { keccak256 as sha3Keccak256 } from "js-sha3"

/**
 * Keccak-256, backed by js-sha3.
 *
 * This replaces a hand-rolled implementation that did not match the published
 * Keccak-256 vectors and produced trivial collisions. The broken version is
 * preserved verbatim in keccak-helper-legacy.ts because v1 vault keys were
 * derived through it; see that file's header.
 *
 * Every method returns a `0x`-prefixed lowercase hex digest, matching the
 * previous API so call sites are unchanged.
 */
export class KeccakHelper {
  /** Hash raw bytes. This is the preferred entry point. */
  static bytesKeccak256(bytes: Uint8Array): string {
    return `0x${sha3Keccak256(bytes)}`
  }

  /** Hash the UTF-8 encoding of a string. */
  static strKeccak256(str: string): string {
    return `0x${sha3Keccak256(str)}`
  }

  /**
   * Hash a hex-encoded byte string. Returns null when the input is not valid
   * hex, rather than silently falling back to hashing it as text — a silent
   * fallback would make two different inputs derive the same key material.
   */
  static strictHexKeccak256(hexStr: string): string | null {
    const bytes = KeccakHelper.parseHex(hexStr)
    if (!bytes) {
      return null
    }
    return KeccakHelper.bytesKeccak256(bytes)
  }

  /**
   * Hash a hex string if it parses as hex, otherwise hash it as UTF-8 text.
   * Kept for compatibility; prefer bytesKeccak256 or strictHexKeccak256, which
   * are unambiguous about how the input is interpreted.
   */
  static keccak256(hexStr: string): string {
    const bytes = KeccakHelper.parseHex(hexStr)
    return bytes ? KeccakHelper.bytesKeccak256(bytes) : KeccakHelper.strKeccak256(hexStr)
  }

  private static parseHex(hexStr: string): Uint8Array | null {
    const cleaned = hexStr.startsWith("0x") || hexStr.startsWith("0X") ? hexStr.slice(2) : hexStr

    if (cleaned.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(cleaned)) {
      return null
    }

    const bytes = new Uint8Array(cleaned.length / 2)
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Number.parseInt(cleaned.slice(i * 2, i * 2 + 2), 16)
    }
    return bytes
  }
}
