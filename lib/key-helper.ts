import type { Point } from "./buffer-helper"
import { BufferHelper } from "./buffer-helper"
import { CryptoManager } from "./crypto-manager"

export class KeyHelper {
  static async convertKeys(
    privateKey: bigint,
    publicKey: Point | null,
  ): Promise<{
    privateKey: {
      success: boolean
      key?: CryptoKey
      pkcs8Buffer?: ArrayBuffer
      error?: string
      warning?: string
    }
    publicKey: {
      success: boolean
      key?: CryptoKey
      rawBuffer?: ArrayBuffer
      error?: string
    }
  }> {
    return new Promise((resolve) => {
      if (!publicKey) {
        return resolve({
          privateKey: {
            success: false,
            error: "Public key is required for conversion",
          },
          publicKey: {
            success: false,
            error: "Public key is required for conversion",
          },
        })
      }

      KeyHelper.convertToPKCS8(privateKey, publicKey, (privateResult) => {
        KeyHelper.convertPublicKeyToRaw(publicKey, (publicResult) => {
          resolve({
            privateKey: privateResult,
            publicKey: publicResult,
          })
        })
      })
    })
  }

  static convertToPKCS8(privateKey: bigint, publicKey: Point, inner_cb: (result: { success: boolean, key?: CryptoKey, pkcs8Buffer?: ArrayBuffer, error?: string, warning?: string }) => void): void {
    const userAgent = typeof navigator === "undefined" ? "" : navigator.userAgent
    const isSafari = /^(?:(?!chrome|android).)*safari/i.test(userAgent)

    if (isSafari) {
      KeyHelper.convertSafariPKCS8Deterministic(privateKey, publicKey, inner_cb)
    } else {
      KeyHelper.convertStandardPKCS8(privateKey, publicKey, inner_cb)
    }
  }

  static convertStandardPKCS8(privateKey: bigint, publicKey: Point, inner_cb: (result: { success: boolean, key?: CryptoKey, pkcs8Buffer?: ArrayBuffer, error?: string }) => void): void {
    const calculateLength = (length: number): Uint8Array => {
      if (length < 128) {
        return new Uint8Array([length])
      } else if (length < 256) {
        return new Uint8Array([0x81, length])
      }
      return new Uint8Array([0x82, (length >> 8) & 0xFF, length & 0xFF])
    }

    const privateKeyBytes = KeyHelper.bigintToBytes(privateKey, 66)

    const curveOid = new Uint8Array([0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23])
    const ecPublicKeyOid = new Uint8Array([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
    const version = new Uint8Array([0x02, 0x01, 0x00])

    const algorithmSequenceContent = new Uint8Array([...ecPublicKeyOid, ...curveOid])
    const algoIdLength = calculateLength(algorithmSequenceContent.length)
    const algorithmIdentifier = new Uint8Array([0x30, ...algoIdLength, ...algorithmSequenceContent])

    const privateKeyOctet = new Uint8Array([0x04, 0x42, ...privateKeyBytes])
    const parameters = new Uint8Array([0xA0, 0x07, ...curveOid])
    const ecKeySequenceContent = new Uint8Array([0x02, 0x01, 0x01, ...privateKeyOctet, ...parameters])
    const ecKeyLength = calculateLength(ecKeySequenceContent.length)
    const ecPrivateKey = new Uint8Array([0x30, ...ecKeyLength, ...ecKeySequenceContent])

    const ecKeyWrapperLength = calculateLength(ecPrivateKey.length)
    const wrappedEcKey = new Uint8Array([0x04, ...ecKeyWrapperLength, ...ecPrivateKey])

    const pkcs8Content = new Uint8Array([...version, ...algorithmIdentifier, ...wrappedEcKey])
    const pkcs8Length = calculateLength(pkcs8Content.length)
    const pkcs8Key = new Uint8Array([0x30, ...pkcs8Length, ...pkcs8Content])

    crypto.subtle
      // extractable: false — see derivesExpectedPoint for how determinism is
      // still verified without ever holding an exportable private key.
      .importKey("pkcs8", pkcs8Key.buffer as ArrayBuffer, { name: "ECDH", namedCurve: "P-521" }, false, ["deriveKey", "deriveBits"])
      .then(async (key) => {
        if (!(await KeyHelper.derivesExpectedPoint(key, publicKey))) {
          inner_cb({ success: false, error: "Imported key is not deterministic — refusing to derive a key that cannot be recovered" })
          return
        }
        inner_cb({ success: true, key, pkcs8Buffer: pkcs8Key.buffer as ArrayBuffer })
      })
      .catch((error: any) => {
        inner_cb({ success: false, error: error?.message ?? String(error) })
      })
  }

  /**
   * Safari rejects the hand-built PKCS#8 DER that other engines accept, so the
   * deterministic scalar is patched into a template exported from a generated
   * key instead.
   *
   * Every failure path here MUST be fatal. An earlier version fell back to the
   * randomly generated template key and reported success with a `warning` that
   * no caller read — so a Safari user could encrypt and upload files under a
   * key that existed only in that tab's memory, and lose every one of them on
   * the next login. Losing access to the vault is strictly better than silently
   * writing files nobody can ever read.
   */
  static convertSafariPKCS8Deterministic(privateKey: bigint, publicKey: Point, inner_cb: (result: { success: boolean, key?: CryptoKey, pkcs8Buffer?: ArrayBuffer, error?: string, warning?: string }) => void): void {
    const fail = (error: string) => inner_cb({ success: false, error })

    void (async () => {
      try {
        // This throwaway pair only supplies DER structure; it is discarded and
        // never used for encryption, so its extractability is irrelevant —
        // exporting it is the whole point.
        const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-521" }, true, ["deriveKey", "deriveBits"])
        const pkcs8Template = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey))

        const privateKeyBytes = KeyHelper.bigintToBytes(privateKey, 66)

        const publicKeyBytes = new Uint8Array(133)
        publicKeyBytes[0] = 0x04
        publicKeyBytes.set(KeyHelper.bigintToBytes(publicKey.x, 66), 1)
        publicKeyBytes.set(KeyHelper.bigintToBytes(publicKey.y, 66), 67)

        const modifiedTemplate = new Uint8Array(pkcs8Template)

        if (!KeyHelper.findAndReplaceKey(modifiedTemplate, privateKeyBytes)) {
          fail("Could not locate the private scalar in the PKCS#8 template")
          return
        }

        if (!KeyHelper.findAndReplacePublicKey(modifiedTemplate, publicKeyBytes)) {
          fail("Could not locate the public key in the PKCS#8 template")
          return
        }

        const key = await crypto.subtle.importKey("pkcs8", modifiedTemplate.buffer as ArrayBuffer, { name: "ECDH", namedCurve: "P-521" }, false, ["deriveKey", "deriveBits"])

        // Confirm the imported key really carries the deterministic scalar and
        // not the generated one. Without this the patch could silently no-op
        // and Safari users would encrypt under a key lost on reload.
        if (!(await KeyHelper.derivesExpectedPoint(key, publicKey))) {
          fail("Imported key is not deterministic — refusing to derive a key that cannot be recovered")
          return
        }

        inner_cb({ success: true, key, pkcs8Buffer: modifiedTemplate.buffer as ArrayBuffer })
      } catch (error: any) {
        fail(error?.message ?? String(error))
      }
    })()
  }

  /** Big-endian fixed-width serialisation of a bigint. */
  static bigintToBytes(value: bigint, length: number): Uint8Array<ArrayBuffer> {
    const bytes = new Uint8Array(length)
    let temp = value
    for (let i = length - 1; i >= 0; i--) {
      bytes[i] = Number(temp & BigInt(0xFF))
      temp >>= BigInt(8)
    }
    return bytes
  }

  /**
   * Verify an imported private key really carries the scalar we derived,
   * without ever making it extractable.
   *
   * The earlier version exported the JWK and compared `d`, which forced the
   * private key to be extractable — and an extractable key can be lifted by any
   * browser extension with one `exportKey` call, since page CSP does not
   * constrain extensions. Instead this performs ECDH against the curve
   * generator: ECDH(d, G) yields the x-coordinate of d·G, which must equal the
   * public point we computed with our own scalar multiplication. `deriveBits`
   * works on non-extractable keys, so nothing exportable is ever created.
   *
   * Only x is recoverable this way, so d and n−d both pass. That is harmless
   * here: the vault key is ECDH(d, d·G) = x(d²·G), and (n−d) yields the same
   * x. The check's actual job is catching a *random* key substituted for the
   * derived one, which this detects.
   */
  static async derivesExpectedPoint(privateKey: CryptoKey, expected: Point): Promise<boolean> {
    try {
      const generator = new Uint8Array(133)
      generator[0] = 0x04
      generator.set(KeyHelper.bigintToBytes(CryptoManager.GX, 66), 1)
      generator.set(KeyHelper.bigintToBytes(CryptoManager.GY, 66), 67)

      const generatorKey = await crypto.subtle.importKey("raw", generator.buffer as ArrayBuffer, { name: "ECDH", namedCurve: "P-521" }, false, [])
      // null, not 521 — a bit count truncates the low-order bits of x and the
      // comparison below would never match. See deriveECDHKey.
      const derived = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: generatorKey }, privateKey, null))

      return BufferHelper.bufferToHex(derived) === BufferHelper.bufferToHex(KeyHelper.bigintToBytes(expected.x, 66))
    } catch {
      return false
    }
  }

  static findAndReplaceKey(template: Uint8Array, newKey: Uint8Array): boolean {
    for (let i = 0; i < template.length - 68; i++) {
      if (template[i] === 0x04 && template[i + 1] === 0x42) {
        for (let j = 0; j < 66; j++) {
          template[i + 2 + j] = newKey[j]
        }
        return true
      }
    }
    return false
  }

  static findAndReplacePublicKey(template: Uint8Array, newKey: Uint8Array): boolean {
    for (let i = 0; i < template.length - 3; i++) {
      if (template[i] === 0xA1) {
        let j = i + 1
        while (j < template.length && template[j] !== 0x03) {
          j++
        }

        if (j < template.length) {
          j++
          while (j < template.length && template[j] & 0x80) {
            j++
          }
          j++

          if (j < template.length && template[j] === 0x00) {
            j++
            if (j < template.length && template[j] === 0x04) {
              for (let k = 0; k < newKey.length; k++) {
                if (j + k < template.length) {
                  template[j + k] = newKey[k]
                }
              }
              return true
            }
          }
        }
      }
    }
    return false
  }

  static convertPublicKeyToRaw(publicKey: { x: bigint, y: bigint }, inner_cb: (result: { success: boolean, key?: CryptoKey, rawBuffer?: ArrayBuffer, error?: string }) => void): void {
    const rawPublicKey = new Uint8Array(133)
    rawPublicKey[0] = 0x04
    rawPublicKey.set(KeyHelper.bigintToBytes(publicKey.x, 66), 1)
    rawPublicKey.set(KeyHelper.bigintToBytes(publicKey.y, 66), 67)

    // The previous try/catch could not catch an importKey rejection, so a
    // failure here left the callback pending and the UI spinning forever.
    crypto.subtle
      .importKey("raw", rawPublicKey.buffer as ArrayBuffer, { name: "ECDH", namedCurve: "P-521" }, true, [])
      .then((key) => {
        inner_cb({ success: true, key, rawBuffer: rawPublicKey.buffer as ArrayBuffer })
      })
      .catch((error: any) => {
        inner_cb({ success: false, error: error?.message ?? String(error) })
      })
  }
}
