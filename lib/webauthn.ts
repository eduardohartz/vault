import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server"
import { randomBytes } from "node:crypto"
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server"
import { prisma } from "./db"
import { getAllowedOrigins, getRpId, getRpName } from "./env"

/**
 * Server-side WebAuthn.
 *
 * The previous implementation generated the challenge in the browser and
 * "verified" a login by looking up the credential id and a derived public key
 * in the database — no signature, origin, RP ID, or challenge was ever checked,
 * so possession of the passkey was never actually proven to the server.
 *
 * Challenges are stored server-side, single use, and expire quickly.
 */

const CHALLENGE_TTL_MS = 5 * 60 * 1000

type RequestLike = { url: string, headers: Headers }

async function storeChallenge(challenge: string, type: "registration" | "authentication", username?: string): Promise<void> {
  await prisma.challenge.create({
    data: {
      challenge,
      type,
      username: username ?? null,
      expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
    },
  })
}

/**
 * Fetch and immediately delete a challenge. Deleting on read is what makes an
 * assertion single-use: a replayed response finds nothing and is rejected.
 */
async function consumeChallenge(challenge: string, type: "registration" | "authentication"): Promise<{ username: string | null } | null> {
  const record = await prisma.challenge.findUnique({ where: { challenge } })

  if (!record) {
    return null
  }

  await prisma.challenge.delete({ where: { id: record.id } }).catch(() => {})

  if (record.type !== type || record.expiresAt.getTime() <= Date.now()) {
    return null
  }

  return { username: record.username }
}

export async function buildRegistrationOptions(request: RequestLike, username: string) {
  const options = await generateRegistrationOptions({
    rpName: getRpName(),
    rpID: getRpId(request),
    userName: username,
    // Without this the authenticator's save prompt shows a blank name.
    userDisplayName: username,
    userID: new Uint8Array(randomBytes(32)),
    // Attestation was previously requested as "direct" but never verified,
    // which only added a scarier browser prompt for no security benefit.
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
    },
    supportedAlgorithmIDs: [-7, -257],
  })

  await storeChallenge(options.challenge, "registration", username)

  return options
}

export async function buildAuthenticationOptions(request: RequestLike) {
  const options = await generateAuthenticationOptions({
    rpID: getRpId(request),
    userVerification: "required",
  })

  await storeChallenge(options.challenge, "authentication")

  return options
}

export async function verifyRegistration(request: RequestLike, response: RegistrationResponseJSON, expectedChallenge: string) {
  const challenge = await consumeChallenge(expectedChallenge, "registration")

  if (!challenge) {
    return { verified: false as const, reason: "Challenge is unknown, already used, or expired" }
  }

  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: getAllowedOrigins(request),
    expectedRPID: getRpId(request),
    requireUserVerification: true,
  })

  if (!verification.verified || !verification.registrationInfo) {
    return { verified: false as const, reason: "Registration could not be verified" }
  }

  return {
    verified: true as const,
    username: challenge.username,
    credential: verification.registrationInfo.credential,
  }
}

export async function verifyAuthentication(request: RequestLike, response: AuthenticationResponseJSON, expectedChallenge: string) {
  const challenge = await consumeChallenge(expectedChallenge, "authentication")

  if (!challenge) {
    return { verified: false as const, reason: "Challenge is unknown, already used, or expired" }
  }

  const user = await prisma.user.findUnique({ where: { credentialId: response.id } })

  if (!user) {
    return { verified: false as const, reason: "Unknown credential" }
  }

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin: getAllowedOrigins(request),
    expectedRPID: getRpId(request),
    requireUserVerification: true,
    credential: {
      id: user.credentialId,
      publicKey: new Uint8Array(user.credentialPublicKey),
      counter: user.counter,
      transports: user.transports as any,
    },
  })

  if (!verification.verified) {
    return { verified: false as const, reason: "Assertion could not be verified" }
  }

  const { newCounter } = verification.authenticationInfo

  // A counter that fails to advance can indicate a cloned authenticator.
  // Authenticators that always report 0 are permitted, as the spec allows.
  if (newCounter === 0 && user.counter === 0) {
    // Authenticator does not implement a signature counter; nothing to check.
  } else if (newCounter <= user.counter) {
    return { verified: false as const, reason: "Signature counter did not increase" }
  }

  await prisma.user.update({
    where: { id: user.id },
    data: { counter: newCounter },
  })

  return { verified: true as const, user }
}
