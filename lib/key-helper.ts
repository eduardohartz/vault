import type { Point } from "./buffer-helper"
import { CryptoManager } from "./crypto-manager"
import { BufferHelper } from "./buffer-helper"

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

      this.convertToPKCS8(privateKey, (privateResult) => {
        this.convertPublicKeyToRaw(publicKey, (publicResult) => {
          resolve({
            privateKey: privateResult,
            publicKey: publicResult,
          })
        })
      })
    })
  }

  static convertToPKCS8(privateKey: bigint, inner_cb: (result: { success: boolean; key?: CryptoKey; pkcs8Buffer?: ArrayBuffer; error?: string; warning?: string }) => void): void {
    const isSafari = /^(?:(?!chrome|android).)*safari/i.test(navigator.userAgent)

    if (isSafari) {
      this.convertSafariPKCS8Deterministic(privateKey, inner_cb)
    } else {
      this.convertStandardPKCS8(privateKey, inner_cb)
    }
  }

  static convertStandardPKCS8(privateKey: bigint, inner_cb: (result: { success: boolean; key?: CryptoKey; pkcs8Buffer?: ArrayBuffer; error?: string }) => void): void {
    const calculateLength = (length: number): Uint8Array => {
      if (length < 128) {
        return new Uint8Array([length])
      } else if (length < 256) {
        return new Uint8Array([0x81, length])
      }
      return new Uint8Array([0x82, (length >> 8) & 0xff, length & 0xff])
    }

    const privateKeyBytes = new Uint8Array(66)
    let temp = privateKey
    for (let i = privateKeyBytes.length - 1; i >= 0; i--) {
      privateKeyBytes[i] = Number(temp & BigInt(0xff))
      temp = temp >> BigInt(8)
    }

    const curveOid = new Uint8Array([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23])
    const ecPublicKeyOid = new Uint8Array([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])
    const version = new Uint8Array([0x02, 0x01, 0x00])

    const algorithmSequenceContent = new Uint8Array([...ecPublicKeyOid, ...curveOid])
    const algoIdLength = calculateLength(algorithmSequenceContent.length)
    const algorithmIdentifier = new Uint8Array([0x30, ...algoIdLength, ...algorithmSequenceContent])

    const privateKeyOctet = new Uint8Array([0x04, 0x42, ...privateKeyBytes])
    const parameters = new Uint8Array([0xa0, 0x07, ...curveOid])
    const ecKeySequenceContent = new Uint8Array([0x02, 0x01, 0x01, ...privateKeyOctet, ...parameters])
    const ecKeyLength = calculateLength(ecKeySequenceContent.length)
    const ecPrivateKey = new Uint8Array([0x30, ...ecKeyLength, ...ecKeySequenceContent])

    const ecKeyWrapperLength = calculateLength(ecPrivateKey.length)
    const wrappedEcKey = new Uint8Array([0x04, ...ecKeyWrapperLength, ...ecPrivateKey])

    const pkcs8Content = new Uint8Array([...version, ...algorithmIdentifier, ...wrappedEcKey])
    const pkcs8Length = calculateLength(pkcs8Content.length)
    const pkcs8Key = new Uint8Array([0x30, ...pkcs8Length, ...pkcs8Content])

    try {
      crypto.subtle
        .importKey("pkcs8", pkcs8Key.buffer, { name: "ECDH", namedCurve: "P-521" }, true, ["deriveKey", "deriveBits"])
        .then((key) => {
          inner_cb({ success: true, key, pkcs8Buffer: pkcs8Key.buffer })
        })
        .catch((error) => {
          inner_cb({ success: false, error: error.message })
        })
    } catch (error: any) {
      inner_cb({ success: false, error: error.message })
    }
  }

  static convertSafariPKCS8Deterministic(privateKey: bigint, inner_cb: (result: { success: boolean; key?: CryptoKey; pkcs8Buffer?: ArrayBuffer; error?: string; warning?: string }) => void): void {
    try {
      crypto.subtle
        .generateKey({ name: "ECDH", namedCurve: "P-521" }, true, ["deriveKey", "deriveBits"])
        .then((keyPair) => {
          crypto.subtle
            .exportKey("pkcs8", keyPair.privateKey)
            .then((exportedKey) => {
              const pkcs8Template = new Uint8Array(exportedKey)

              const privateKeyBytes = new Uint8Array(66)
              let temp = privateKey
              for (let i = privateKeyBytes.length - 1; i >= 0; i--) {
                privateKeyBytes[i] = Number(temp & BigInt(0xff))
                temp = temp >> BigInt(8)
              }

              const publicKey = BufferHelper.scalarMul(privateKey, {
                x: CryptoManager.GX,
                y: CryptoManager.GY,
              })

              if (!publicKey) {
                return false
              }

              const xBytes = new Uint8Array(66)
              let tempX = publicKey.x
              for (let i = xBytes.length - 1; i >= 0; i--) {
                xBytes[i] = Number(tempX & BigInt(0xff))
                tempX = tempX >> BigInt(8)
              }

              const yBytes = new Uint8Array(66)
              let tempY = publicKey.y
              for (let i = yBytes.length - 1; i >= 0; i--) {
                yBytes[i] = Number(tempY & BigInt(0xff))
                tempY = tempY >> BigInt(8)
              }

              const publicKeyBytes = new Uint8Array(133)
              publicKeyBytes[0] = 0x04
              publicKeyBytes.set(xBytes, 1)
              publicKeyBytes.set(yBytes, 67)

              const modifiedTemplate = new Uint8Array(pkcs8Template)
              this.findAndReplaceKey(modifiedTemplate, privateKeyBytes)
              this.findAndReplacePublicKey(modifiedTemplate, publicKeyBytes)

              crypto.subtle
                .importKey("pkcs8", modifiedTemplate.buffer, { name: "ECDH", namedCurve: "P-521" }, true, ["deriveKey", "deriveBits"])
                .then((key) => {
                  inner_cb({
                    success: true,
                    key,
                    pkcs8Buffer: modifiedTemplate.buffer,
                  })
                })
                .catch((error) => {
                  crypto.subtle
                    .importKey("pkcs8", pkcs8Template.buffer, { name: "ECDH", namedCurve: "P-521" }, true, ["deriveKey", "deriveBits"])
                    .then((key) => {
                      inner_cb({
                        success: true,
                        key,
                        pkcs8Buffer: pkcs8Template.buffer,
                        warning: "Using template key (non-deterministic)",
                      })
                    })
                    .catch((fallbackError: any) => {
                      inner_cb({
                        success: false,
                        error: `${error.message} / ${fallbackError.message}`,
                      })
                    })
                })
            })
            .catch((error) => {
              inner_cb({ success: false, error: error.message })
            })
        })
        .catch((error) => {
          inner_cb({ success: false, error: error.message })
        })
    } catch (error: any) {
      inner_cb({ success: false, error: error.message })
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
      if (template[i] === 0xa1) {
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

  static convertPublicKeyToRaw(publicKey: { x: bigint; y: bigint }, inner_cb: (result: { success: boolean; key?: CryptoKey; rawBuffer?: ArrayBuffer; error?: string }) => void): void {
    const xBytes = new Uint8Array(66)
    let tempX = publicKey.x
    for (let i = xBytes.length - 1; i >= 0; i--) {
      xBytes[i] = Number(tempX & BigInt(0xff))
      tempX = tempX >> BigInt(8)
    }

    const yBytes = new Uint8Array(66)
    let tempY = publicKey.y
    for (let i = yBytes.length - 1; i >= 0; i--) {
      yBytes[i] = Number(tempY & BigInt(0xff))
      tempY = tempY >> BigInt(8)
    }

    const rawPublicKey = new Uint8Array(133)
    rawPublicKey[0] = 0x04
    rawPublicKey.set(xBytes, 1)
    rawPublicKey.set(yBytes, 67)

    try {
      crypto.subtle.importKey("raw", rawPublicKey.buffer, { name: "ECDH", namedCurve: "P-521" }, true, []).then((key) => {
        inner_cb({ success: true, key, rawBuffer: rawPublicKey.buffer })
      })
    } catch (error: any) {
      inner_cb({ success: false, error: error.message })
    }
  }
}
