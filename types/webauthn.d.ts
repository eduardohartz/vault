/**
 * Declaration merging for the WebAuthn PRF extension, which the bundled DOM
 * types do not yet describe.
 *
 * These MUST be `interface`, not `type`. Only interfaces merge with existing
 * declarations; a type alias would shadow the DOM's own PublicKeyCredential
 * rather than extend it, which quietly breaks every PRF call site.
 */

/* eslint-disable ts/consistent-type-definitions, ts/method-signature-style */

interface AuthenticationExtensionsClientInputs {
  prf?: {
    eval?: {
      first: BufferSource
      second?: BufferSource
    }
    evalByCredential?: Record<
      string,
      {
        first: BufferSource
        second?: BufferSource
      }
    >
  }
}

interface AuthenticationExtensionsClientOutputs {
  prf?: {
    enabled?: boolean
    results?: {
      first?: ArrayBuffer
      second?: ArrayBuffer
    }
  }
}

interface PublicKeyCredential {
  getClientExtensionResults(): AuthenticationExtensionsClientOutputs
}

interface PublicKeyCredentialCreationOptions {
  extensions?: AuthenticationExtensionsClientInputs
}

interface PublicKeyCredentialRequestOptions {
  extensions?: AuthenticationExtensionsClientInputs
}
