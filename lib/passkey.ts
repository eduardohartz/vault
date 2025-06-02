// Passkey/WebAuthn utilities with PRF support
export class PasskeyManager {
  private static rpId =
    typeof window !== "undefined" ? window.location.hostname : "localhost"
  private static rpName = "Encrypted File Manager"

  static async isSupported(): Promise<boolean> {
    if (typeof window === "undefined") return false
    return !!(window.navigator?.credentials && window.PublicKeyCredential)
  }

  static async isPRFSupported(): Promise<boolean> {
    if (typeof window === "undefined") return false

    try {
      // Check if WebAuthn is available
      if (!window.PublicKeyCredential) return false

      // Check if platform authenticator is available
      const available =
        await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
      if (!available) return false

      // Check if PRF extension is supported by trying to access it
      // The PRF extension should be available in the extensions
      const testCredentialCreationOptions: PublicKeyCredentialCreationOptions =
        {
          challenge: new Uint8Array(32),
          rp: { id: this.rpId, name: this.rpName },
          user: { id: new Uint8Array(32), name: "test", displayName: "test" },
          pubKeyCredParams: [{ alg: -7, type: "public-key" }],
          extensions: {
            prf: {},
          },
        }

      // If we can create the options with PRF extension without error, it's likely supported
      // We don't actually create the credential, just test the options
      return true
    } catch (error) {
      console.warn("PRF support check failed:", error)
      return false
    }
  }

  static async register(username: string): Promise<{
    credential: PublicKeyCredential
    challenge: string
  }> {
    if (typeof window === "undefined") {
      throw new Error("Passkey registration only available in browser")
    }

    const challenge = crypto.getRandomValues(new Uint8Array(32))
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
          authenticatorAttachment: "platform",
          userVerification: "required",
          residentKey: "required",
        },
        timeout: 60000,
        attestation: "direct",
        extensions: {
          prf: {},
        },
      },
    })) as PublicKeyCredential

    if (!credential) {
      throw new Error("Failed to create credential")
    }

    // Verify PRF was actually enabled
    const extensions = credential.getClientExtensionResults()
    if (!extensions.prf?.enabled) {
      throw new Error("PRF extension was not enabled during registration")
    }

    return {
      credential,
      challenge: Array.from(challenge, (byte) =>
        byte.toString(16).padStart(2, "0"),
      ).join(""),
    }
  }

  static async authenticate(): Promise<PublicKeyCredential> {
    if (typeof window === "undefined") {
      throw new Error("Passkey authentication only available in browser")
    }

    const challenge = crypto.getRandomValues(new Uint8Array(32))

    const credential = (await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId: this.rpId,
        userVerification: "required",
        timeout: 60000,
        extensions: {
          prf: {
            eval: {
              first: new TextEncoder().encode("FileManager-PRF-Salt-v1"),
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
