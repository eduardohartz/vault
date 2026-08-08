import type { Point } from "./buffer-helper"
import { BufferHelper } from "./buffer-helper"
import { KeccakHelper } from "./keccak-helper"
import { LegacyKeccakHelper } from "./keccak-helper-legacy"

/**
 * Key derivation version.
 *
 * v1 derived the HKDF salt through a hand-rolled Keccak that was not actually
 * Keccak-256. v2 uses the corrected implementation. The version is stored per
 * user so that v1 vaults remain decryptable — bumping a user to v2 changes
 * their salt, seed, and private key, which would orphan every file they own.
 */
export const CURRENT_KEY_VERSION = 2

export class CryptoManager {
  private static readonly HKDF_INFO = new TextEncoder().encode("EduardoVaultHKDFVerySecretInfo")
  private static readonly SHARE_KEY_INFO = new TextEncoder().encode("EduardoVaultShareKeyVerySecretInfo")
  // Domain separation for the vault key, so it can never coincide with a key
  // derived for any other purpose from the same secret.
  private static readonly VAULT_KEY_INFO = new TextEncoder().encode("EduardoVaultContentKey")

  static readonly P = BigInt("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
  static readonly A = BigInt("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC")
  static readonly B = BigInt("0x051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00")
  static readonly GX = BigInt("0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66")
  static readonly GY = BigInt("0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650")
  static readonly N = BigInt("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409")

  // Get PRF output from authentication
  static async getPRFOutput(assertion: PublicKeyCredential): Promise<Uint8Array<ArrayBuffer>> {
    const ext_results = assertion.getClientExtensionResults()
    let prfBuff

    if (BufferHelper.hasProperty(ext_results) && BufferHelper.hasProperty(ext_results.prf?.results) && BufferHelper.hasProperty(ext_results.prf?.results?.first)) {
      const prfResult = ext_results.prf?.results?.first
      if (prfResult) {
        prfBuff = new Uint8Array(prfResult as ArrayBuffer)
      }
    }

    if (!prfBuff) {
      throw new Error("PRF output not found in assertion extensions")
    }

    return prfBuff
  }

  // Convert PRF output to CryptoKey for HKDF
  static async generateHKDFKey(prfOutput: BufferSource): Promise<CryptoKey> {
    return globalThis.crypto.subtle.importKey("raw", prfOutput, { name: "HKDF" }, false, ["deriveKey", "deriveBits"])
  }

  // Generate new seed from PRF key
  static async generateNewSeed(seedName: string = "", prfBuff: Uint8Array<ArrayBuffer>, HKDFKey: CryptoKey, keyVersion: number = CURRENT_KEY_VERSION): Promise<ArrayBuffer> {
    const slicedBuff = prfBuff.slice(0, 32)

    let salt: string | null
    if (keyVersion === 1) {
      // Reproduce v1 byte for byte, including the broken hash. See
      // keccak-helper-legacy.ts.
      salt = LegacyKeccakHelper.strictHexKeccak256(BufferHelper.bufferToHex(slicedBuff) + seedName)
    } else {
      // v2 hashes raw bytes directly rather than round-tripping through a hex
      // string, so there is no ambiguity about how the input is interpreted.
      const nameBytes = new TextEncoder().encode(seedName)
      const combined = new Uint8Array(slicedBuff.length + nameBytes.length)
      combined.set(slicedBuff)
      combined.set(nameBytes, slicedBuff.length)
      salt = KeccakHelper.bytesKeccak256(combined)
    }

    if (!salt || salt.length < 64) {
      throw new Error("Invalid salt generated from PRF output")
    }

    const saltBuffer = BufferHelper.hexToArrayBuffer(salt) as ArrayBuffer

    const seed = await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: saltBuffer,
        info: this.HKDF_INFO,
      },
      HKDFKey,
      512,
    )
    return seed
  }

  // Generate deterministic ECDH key pair from seed
  static generateKeyPair(seed: ArrayBuffer): {
    privateKey: bigint
    publicKey: Point | null
  } {
    if (!(seed instanceof ArrayBuffer) || seed.byteLength !== 64) {
      throw new Error("Seed must be a 64-byte ArrayBuffer")
    }

    const seedView = new Uint8Array(seed)
    let privateKey = BigInt(0)

    for (let i = 0; i < seedView.length; i++) {
      privateKey = (privateKey << BigInt(8)) | BigInt(seedView[i])
    }

    const mask = (BigInt(1) << BigInt(521)) - BigInt(1)
    privateKey = privateKey & mask

    privateKey = (privateKey % (this.N - BigInt(1))) + BigInt(1)

    const publicKey = BufferHelper.scalarMul(privateKey, {
      x: this.GX,
      y: this.GY,
    })

    if (!BufferHelper.isOnCurve(publicKey)) {
      throw new Error("Generated public key is not on curve")
    }

    return { privateKey, publicKey }
  }

  /**
   * Derive the vault's AES-GCM key from the user's own ECDH key pair.
   *
   * The shared secret is passed through HKDF rather than used directly.
   * WebCrypto's `deriveKey` for ECDH takes the *leftmost* bytes of the raw
   * shared secret Z, and for P-521 that is a problem: Z is the x-coordinate
   * encoded in ceil(521/8) = 66 bytes, but x < 2^521, so the top 7 bits of
   * Z[0] are always zero. Measured over 300 derivations, byte 0 of the
   * resulting key only ever took the values 0x00 and 0x01 — about 1 bit
   * instead of 8, leaving roughly 249 bits of key material rather than 256.
   *
   * 249 bits is not a practical weakness, but feeding a key-agreement output
   * straight into a cipher is exactly what NIST SP 800-56C's key-derivation
   * step exists to avoid, and it costs nothing to do properly.
   */
  static async deriveECDHKey(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey> {
    // `null` means "the whole field element" and is the only correct value
    // here. Passing a bit count truncates from the END: deriveBits(..., 521)
    // returns the leading 521 bits of the 66-byte encoding, which keeps 7
    // leading zero bits and silently discards 7 real low-order bits of x.
    // Verified: with 521 the final byte comes back 0x80, with null it is the
    // true value. 528 happens to work in Chrome and Node but exceeds the field
    // size, so it is not portable.
    const sharedSecret = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, null)

    // Guard against a platform disagreeing about what "the full field element"
    // means. A shorter or longer secret would still derive *a* key, just a
    // different one — so the same passkey would open the vault in one browser
    // and not another. Failing loudly beats silently orphaning someone's files.
    if (sharedSecret.byteLength !== 66) {
      throw new Error(`Unexpected ECDH shared secret length: ${sharedSecret.byteLength} bytes (expected 66 for P-521)`)
    }

    const hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, { name: "HKDF" }, false, ["deriveKey"])

    return await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(),
        info: this.VAULT_KEY_INFO,
      },
      hkdfKey,
      {
        name: "AES-GCM",
        length: 256,
      },
      // Non-extractable. A malicious browser extension runs in the page's own
      // JS context — page CSP does not apply to it — so an extractable key
      // could be lifted with one exportKey call and used to decrypt every
      // backup of this vault forever, offline. Non-extractable narrows that to
      // "can use the key while this tab is open", which dies with the tab.
      false,
      ["encrypt", "decrypt"],
    )
  }

  /**
   * Generate a fresh random key for a single share.
   *
   * Previously this hashed the user's master key, producing one share key that
   * was identical for every file the user ever shared and could never be
   * rotated — disclosing it for one file exposed all of them. Each share now
   * gets independent key material, so revoking a share is just deleting it.
   *
   * The key is never sent to the server; it exists only in the sender's browser
   * until they hand it to the recipient out of band.
   */
  static generateShareKey(): string {
    return BufferHelper.bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)))
  }

  /** Derive the AES-GCM key for a share from its key and a per-item salt. */
  static async deriveShareKey(shareKey: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
    const shareKeyBytes = BufferHelper.base64UrlToBytes(shareKey)

    if (shareKeyBytes.length !== 32) {
      throw new Error("Invalid share key")
    }

    const baseKey = await crypto.subtle.importKey("raw", shareKeyBytes, { name: "HKDF" }, false, ["deriveKey"])
    return await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        salt,
        info: this.SHARE_KEY_INFO,
        hash: "SHA-256",
      },
      baseKey,
      {
        name: "AES-GCM",
        length: 256,
      },
      // Non-extractable, for the same reason as the vault key above. The share
      // key string itself is what the sender passes to a recipient; the derived
      // AES key never needs to leave the browser.
      false,
      ["encrypt", "decrypt"],
    )
  }

  // Encrypt file (or an already-decrypted buffer) with a derived key
  static async encryptFile(
    file: File | ArrayBuffer,
    encryptionKey: CryptoKey,
  ): Promise<{
    encryptedData: ArrayBuffer
    iv: Uint8Array<ArrayBuffer>
  }> {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const fileBuffer = file instanceof File ? await file.arrayBuffer() : file
    const encryptedData = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, fileBuffer)

    return { encryptedData, iv }
  }

  // Decrypt file with derived key
  static async decryptFile(encryptedData: ArrayBuffer, encryptionKey: CryptoKey, iv: Uint8Array<ArrayBuffer>): Promise<ArrayBuffer> {
    return crypto.subtle.decrypt({ name: "AES-GCM", iv }, encryptionKey, encryptedData)
  }

  // Encrypt filename
  static async encryptFilename(
    filename: string,
    key: CryptoKey,
  ): Promise<{
    encryptedName: string
    iv: Uint8Array<ArrayBuffer>
  }> {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const nameBuffer = new TextEncoder().encode(filename)

    const encryptedBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, nameBuffer)

    return {
      encryptedName: btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer))),
      iv,
    }
  }

  // Decrypt filename
  static async decryptFilename(encryptedName: string, key: CryptoKey, iv: Uint8Array<ArrayBuffer>): Promise<string> {
    const encryptedBuffer = Uint8Array.from(atob(encryptedName), (c) => c.charCodeAt(0))

    const decryptedBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedBuffer)

    return new TextDecoder().decode(decryptedBuffer)
  }
}
