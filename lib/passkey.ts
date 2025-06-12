import { keccak256 } from "js-sha3"

export class PasskeyManager {
  private static rpId = typeof window !== "undefined" ? window.location.hostname : "localhost"
  private static rpName = "Vault"

  static async isSupported(): Promise<boolean> {
    if (typeof window === "undefined") {
      return false
    }
    return !!(window.navigator?.credentials && window.PublicKeyCredential)
  }

  static async isPRFSupported(): Promise<boolean> {
    if (typeof window === "undefined") {
      return false
    }

    try {
      if (!window.PublicKeyCredential) {
        return false
      }

      const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
      if (!available) {
        return false
      }

      const capabilities = await PublicKeyCredential.getClientCapabilities()

      if (capabilities["extension:prf"] === false || !capabilities["extension:prf"]) {
        return false
      }

      return true
    } catch (error) {
      console.warn("PRF support check failed:", error)
      return false
    }
  }

  static async register(username: string): Promise<PublicKeyCredential> {
    if (typeof window === "undefined") {
      throw new TypeError("Passkey registration only available in browser")
    }

    const challenge = crypto.getRandomValues(new Uint8Array(16)).buffer
    const userId = crypto.getRandomValues(new Uint8Array(32))

    const credential = (await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: {
          id: this.rpId,
          name: this.rpName,
        },
        user: {
          id: userId,
          name: username,
          displayName: username,
        },
        pubKeyCredParams: [
          { alg: -7, type: "public-key" },
          { alg: -257, type: "public-key" },
        ],
        authenticatorSelection: {
          residentKey: "required",
        },
        timeout: 60000,
        attestation: "direct",
        extensions: { prf: {} },
      },
    })) as PublicKeyCredential

    if (!credential.id) {
      throw new Error("Failed to create credential")
    }

    return credential
  }

  static async authenticate(): Promise<PublicKeyCredential> {
    if (typeof window === "undefined") {
      throw new TypeError("Passkey authentication only available in browser")
    }

    const challenge = crypto.getRandomValues(new Uint8Array(16)).buffer

    const input = "filekey_security_key_wallet_first"
    const hashHex: string = keccak256(input)
    const buffer: ArrayBufferLike = (hexToArrayBuffer(keccak256(input), Uint8Array) as Uint8Array).buffer

    const credential = (await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId: this.rpId,
        userVerification: "required",
        timeout: 60000,
        extensions: {
          prf: {
            eval: {
              first: buffer as ArrayBuffer,
            },
          },
        },
      },
    })) as PublicKeyCredential

    if (!credential) {
      throw new Error("Failed to authenticate")
    }

    return credential
  }
}

function hexStringToHexNumber(hex_str: string) {
  if (new RegExp(/0x/i).test(hex_str.substring(0, 2))) {
    return hex_str.substring(2)
  } else {
    return hex_str
  }
}

function hexToArrayBuffer<T extends ArrayBufferView = Uint8Array>(hexStr: string, bufferType?: { new (array: number[]): T }): ArrayBuffer | T {
  const cleanedHex = hexStringToHexNumber(hexStr)

  const ret: number[] = []
  for (let i = 0; i < cleanedHex.length / 2; i++) {
    const x = i * 2
    const n = Number.parseInt(cleanedHex.substr(x, 2), 16)
    ret.push(n)
  }

  return bufferType ? new bufferType(ret) : new Uint8Array(ret).buffer
}
