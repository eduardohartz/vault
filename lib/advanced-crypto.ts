import type { Point } from "./buffer-helper"
import { BufferHelper } from "./buffer-helper"
import { KeccakHelper } from "./keccak-helper"

export class AdvancedCryptoManager {
  private static readonly HKDF_INFO = new TextEncoder().encode("FileManager-HKDF-Info-v1")
  private static readonly SHARE_KEY_INFO = new TextEncoder().encode("FileManager-ShareKey-v1")
  private static readonly SHARE_SALT = "FileManager-ShareSalt-v1"

  static readonly P = BigInt("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
  static readonly A = BigInt("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC")
  static readonly B = BigInt("0x051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00")
  static readonly GX = BigInt("0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66")
  static readonly GY = BigInt("0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650")
  static readonly N = BigInt("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409")

  // Get PRF output from authentication
  static async getPRFOutput(assertion: PublicKeyCredential): Promise<Uint8Array> {
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
    return self.crypto.subtle.importKey("raw", prfOutput, { name: "HKDF" }, false, ["deriveKey", "deriveBits"])
  }

  // Generate new seed from PRF key
  static async generateNewSeed(seedName: string = "", prfBuff: Uint8Array, HKDFKey: CryptoKey): Promise<ArrayBuffer> {
    const slicedBuff = prfBuff.slice(0, 32)

    const salt = KeccakHelper.strictHexKeccak256(BufferHelper.bufferToHex(slicedBuff) + seedName)

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

  static async deriveECDHKey(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey> {
    return await crypto.subtle.deriveKey(
      {
        name: "ECDH",
        public: publicKey,
      },
      privateKey,
      {
        name: "AES-GCM",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"],
    )
  }

  static async deriveECDHKeyFromShared(shareKey: string, salt: Uint8Array): Promise<CryptoKey> {
    const shareKeyBytes = Uint8Array.from(atob(shareKey), (c) => c.charCodeAt(0))

    const baseKey = await crypto.subtle.importKey("raw", shareKeyBytes, { name: "HKDF" }, false, ["deriveKey"])
    return await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        salt,
        info: new Uint8Array(),
        hash: "SHA-256",
      },
      baseKey,
      {
        name: "AES-GCM",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"],
    )
  }

  static async generateShareKey(aesKey: CryptoKey): Promise<string> {
    const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", aesKey))

    const domainSeparator = this.SHARE_KEY_INFO
    const combinedData = new Uint8Array(rawKey.length + domainSeparator.length)
    combinedData.set(rawKey)
    combinedData.set(domainSeparator, rawKey.length)

    const hashBuffer = await crypto.subtle.digest("SHA-256", combinedData)

    return Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  }

  // Encrypt file with derived key
  static async encryptFileAdvanced(
    file: File | ArrayBuffer,
    encryptionKey: CryptoKey,
  ): Promise<{
      encryptedData: ArrayBuffer
      iv: Uint8Array
    }> {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const fileBuffer = file instanceof File ? await file.arrayBuffer() : file

    const encryptedData = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, fileBuffer)

    return { encryptedData, iv }
  }

  // Decrypt file with derived key
  static async decryptFileAdvanced(encryptedData: ArrayBuffer, encryptionKey: CryptoKey, iv: Uint8Array): Promise<ArrayBuffer> {
    return crypto.subtle.decrypt({ name: "AES-GCM", iv }, encryptionKey, encryptedData)
  }

  // Encrypt filename
  static async encryptFilename(
    filename: string,
    key: CryptoKey,
  ): Promise<{
      encryptedName: string
      iv: Uint8Array
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
  static async decryptFilename(encryptedName: string, key: CryptoKey, iv: Uint8Array): Promise<string> {
    const encryptedBuffer = Uint8Array.from(atob(encryptedName), (c) => c.charCodeAt(0))

    const decryptedBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedBuffer)

    return new TextDecoder().decode(decryptedBuffer)
  }
}
