import { keccak256 } from "js-sha3"
import { BufferHelper } from "./buffer-helper"

/**
 * Browser-side WebAuthn.
 *
 * Challenges now come from the server and the resulting credential is sent
 * back for verification. Previously the challenge was generated here and the
 * assertion never left the browser, so the server had no way to tell a real
 * passkey from a fabricated login request.
 *
 * The PRF extension is still driven from this file rather than through a
 * WebAuthn helper library, because PRF results are raw ArrayBuffers that do
 * not survive the libraries' JSON serialisation.
 */

/**
 * Fixed PRF evaluation input.
 *
 * Hashed with js-sha3, which has always been correct — deliberately not the
 * project's own Keccak helper. Changing this value changes every derived key,
 * so it must stay exactly as it is.
 */
const PRF_EVAL_INPUT = keccak256("very_secret_input_for_prf_abcdef1234567890")

type CreationOptionsJSON = {
  challenge: string
  rp: { id?: string, name: string }
  user: { id: string, name: string, displayName: string }
  pubKeyCredParams: { alg: number, type: "public-key" }[]
  timeout?: number
  attestation?: AttestationConveyancePreference
  authenticatorSelection?: AuthenticatorSelectionCriteria
  excludeCredentials?: { id: string, type: "public-key", transports?: AuthenticatorTransport[] }[]
}

type RequestOptionsJSON = {
  challenge: string
  rpId?: string
  timeout?: number
  userVerification?: UserVerificationRequirement
  allowCredentials?: { id: string, type: "public-key", transports?: AuthenticatorTransport[] }[]
}

function toBuffer(base64url: string): ArrayBuffer {
  const bytes = BufferHelper.base64UrlToBytes(base64url)
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
}

function fromBuffer(buffer: ArrayBuffer | null): string {
  return buffer ? BufferHelper.bytesToBase64Url(new Uint8Array(buffer)) : ""
}

export class PasskeyManager {
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

      if (!(await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable())) {
        return false
      }

      // getClientCapabilities is not available everywhere. When it is missing
      // we cannot rule PRF out, so we let registration try and fail loudly
      // rather than blocking a browser that would have worked.
      if (typeof PublicKeyCredential.getClientCapabilities !== "function") {
        return true
      }

      const capabilities = await PublicKeyCredential.getClientCapabilities()
      return capabilities["extension:prf"] !== false
    } catch (error) {
      console.warn("PRF support check failed:", error)
      return false
    }
  }

  /** Is this page in a context where WebAuthn can run at all? */
  static isSecureContextAvailable(): boolean {
    if (typeof window === "undefined") {
      return false
    }
    return window.isSecureContext
  }

  static async register(options: CreationOptionsJSON): Promise<PublicKeyCredential> {
    if (typeof window === "undefined") {
      throw new TypeError("Passkey registration only available in browser")
    }

    const credential = (await navigator.credentials.create({
      publicKey: {
        ...options,
        challenge: toBuffer(options.challenge),
        user: {
          ...options.user,
          id: toBuffer(options.user.id),
        },
        excludeCredentials: options.excludeCredentials?.map((cred) => ({
          ...cred,
          id: toBuffer(cred.id),
        })),
        extensions: { prf: {} },
      },
    })) as PublicKeyCredential | null

    if (!credential) {
      throw new Error("Failed to create credential")
    }

    return credential
  }

  static async authenticate(options: RequestOptionsJSON): Promise<PublicKeyCredential> {
    if (typeof window === "undefined") {
      throw new TypeError("Passkey authentication only available in browser")
    }

    const credential = (await navigator.credentials.get({
      publicKey: {
        ...options,
        challenge: toBuffer(options.challenge),
        allowCredentials: options.allowCredentials?.map((cred) => ({
          ...cred,
          id: toBuffer(cred.id),
        })),
        extensions: {
          prf: {
            eval: {
              first: BufferHelper.hexToArrayBuffer(PRF_EVAL_INPUT) as ArrayBuffer,
            },
          },
        },
      },
    })) as PublicKeyCredential | null

    if (!credential) {
      throw new Error("Failed to authenticate")
    }

    return credential
  }

  /** Serialise a registration credential for @simplewebauthn/server. */
  static serializeRegistration(credential: PublicKeyCredential) {
    const response = credential.response as AuthenticatorAttestationResponse

    return {
      id: credential.id,
      rawId: fromBuffer(credential.rawId),
      type: credential.type,
      clientExtensionResults: {},
      response: {
        clientDataJSON: fromBuffer(response.clientDataJSON),
        attestationObject: fromBuffer(response.attestationObject),
        transports: typeof response.getTransports === "function" ? response.getTransports() : undefined,
      },
    }
  }

  /** Serialise an authentication assertion for @simplewebauthn/server. */
  static serializeAuthentication(credential: PublicKeyCredential) {
    const response = credential.response as AuthenticatorAssertionResponse

    return {
      id: credential.id,
      rawId: fromBuffer(credential.rawId),
      type: credential.type,
      clientExtensionResults: {},
      response: {
        clientDataJSON: fromBuffer(response.clientDataJSON),
        authenticatorData: fromBuffer(response.authenticatorData),
        signature: fromBuffer(response.signature),
        userHandle: response.userHandle ? fromBuffer(response.userHandle) : undefined,
      },
    }
  }
}
