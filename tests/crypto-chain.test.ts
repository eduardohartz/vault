import { describe, expect, it } from "vitest"
import { BufferHelper } from "@/lib/buffer-helper"
import { CryptoManager } from "@/lib/crypto-manager"
import { KeyHelper } from "@/lib/key-helper"

/**
 * End-to-end verification of the encryption chain, step by step:
 *
 *   passkey PRF -> HKDF seed -> P-521 scalar -> public point -> PKCS#8 import
 *   -> ECDH -> AES-GCM -> ciphertext, and the parallel share-key path.
 *
 * Each stage is checked against an independent reference wherever one exists:
 * FIPS 186-4 for the curve, algebraic identities for the group law, and
 * WebCrypto's own key derivation for the hand-rolled scalar multiplication.
 */

const { P, A, B, GX, GY, N } = CryptoManager
const G = { x: GX, y: GY }
const mod = (x: bigint, m: bigint) => ((x % m) + m) % m
const randScalar = () => mod(BigInt(`0x${Buffer.from(crypto.getRandomValues(new Uint8Array(66))).toString("hex")}`), N - 1n) + 1n

describe("step 1: P-521 domain parameters", () => {
  // Transcribed independently from FIPS 186-4 D.1.2.5.
  it("p is 2^521 - 1", () => {
    expect(P).toBe((1n << 521n) - 1n)
  })

  it("a is -3 mod p, as all NIST prime curves are", () => {
    expect(A).toBe(P - 3n)
  })

  it("b matches FIPS 186-4", () => {
    expect(B).toBe(BigInt("0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"))
  })

  it("the generator matches FIPS 186-4", () => {
    expect(GX).toBe(BigInt("0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"))
    expect(GY).toBe(BigInt("0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"))
  })

  it("the group order matches FIPS 186-4", () => {
    expect(N).toBe(BigInt("0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"))
  })

  it("the generator lies on the curve and the curve is non-singular", () => {
    expect(mod(GY * GY, P)).toBe(mod(GX * GX * GX + A * GX + B, P))
    expect(mod(4n * A * A * A + 27n * B * B, P)).not.toBe(0n)
  })
})

describe("step 2: elliptic curve group law", () => {
  it("n*G is the point at infinity", () => {
    expect(BufferHelper.scalarMul(N, G)).toBeNull()
  })

  it("0*G is the point at infinity", () => {
    expect(BufferHelper.scalarMul(0n, G)).toBeNull()
  })

  it("1*G is G", () => {
    expect(BufferHelper.scalarMul(1n, G)).toEqual(G)
  })

  it("2*G equals G+G", () => {
    expect(BufferHelper.scalarMul(2n, G)).toEqual(BufferHelper.pointAdd(G, G))
  })

  it("(n+1)*G wraps back to G", () => {
    expect(BufferHelper.scalarMul(N + 1n, G)).toEqual(G)
  })

  it("p + (-P) is the point at infinity", () => {
    expect(BufferHelper.pointAdd(G, { x: G.x, y: P - G.y })).toBeNull()
  })

  it("scalar multiplication is a homomorphism: (a+b)G == aG + bG", () => {
    for (let i = 0; i < 10; i++) {
      const a = randScalar()
      const b = randScalar()
      expect(BufferHelper.scalarMul(mod(a + b, N), G)).toEqual(
        BufferHelper.pointAdd(BufferHelper.scalarMul(a, G), BufferHelper.scalarMul(b, G)),
      )
    }
  })

  it("point addition is associative", () => {
    for (let i = 0; i < 5; i++) {
      const aG = BufferHelper.scalarMul(randScalar(), G)
      const bG = BufferHelper.scalarMul(randScalar(), G)
      expect(BufferHelper.pointAdd(BufferHelper.pointAdd(aG, bG), G)).toEqual(
        BufferHelper.pointAdd(aG, BufferHelper.pointAdd(bG, G)),
      )
    }
  })

  it("every derived point lies on the curve", () => {
    for (let i = 0; i < 10; i++) {
      expect(BufferHelper.isOnCurve(BufferHelper.scalarMul(randScalar(), G))).toBe(true)
    }
  })

  it("isOnCurve rejects a point that is not on the curve", () => {
    expect(BufferHelper.isOnCurve({ x: GX, y: GY + 1n })).toBe(false)
  })
})

describe("step 3: modular inverse", () => {
  it("a * modInv(a, p) == 1", () => {
    for (let i = 0; i < 50; i++) {
      const a = randScalar()
      expect((a * BufferHelper.modInv(a, P)) % P).toBe(1n)
    }
  })

  it("modInv(1, p) is 1", () => {
    expect(BufferHelper.modInv(1n, P)).toBe(1n)
  })

  it("modInv(0, p) throws rather than returning garbage", () => {
    expect(() => BufferHelper.modInv(0n, P)).toThrow("Modular inverse does not exist")
  })
})

describe("step 4: scalar multiplication vs WebCrypto", () => {
  // The strongest available check on the hand-rolled EC arithmetic. WebCrypto
  // picks d and computes d*G itself; we then check our own scalarMul lands on
  // the same point. Deliberately independent of the app's PKCS#8 builder, so a
  // failure here points at the curve maths and nothing else.
  const toBigInt = (b64url: string) => BigInt(`0x${Buffer.from(BufferHelper.base64UrlToBytes(b64url)).toString("hex")}`)

  it("agrees with WebCrypto's own public key derivation", async () => {
    for (let i = 0; i < 8; i++) {
      const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-521" }, true, ["deriveBits"])) as CryptoKeyPair
      const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey)

      const own = BufferHelper.scalarMul(toBigInt(jwk.d!), G)!

      expect(own.x).toBe(toBigInt(jwk.x!))
      expect(own.y).toBe(toBigInt(jwk.y!))
    }
  })

  it("the app's import path lands on the same point as our arithmetic", async () => {
    // Equivalent assurance for the key the app actually uses, without ever
    // making it extractable: ECDH against the generator recovers x(d*G).
    const { privateKey, publicKey } = CryptoManager.generateKeyPair(crypto.getRandomValues(new Uint8Array(64)).buffer as ArrayBuffer)
    const keys = await KeyHelper.convertKeys(privateKey, publicKey)

    expect(keys.privateKey.success).toBe(true)
    expect(await KeyHelper.derivesExpectedPoint(keys.privateKey.key!, publicKey!)).toBe(true)
  })
})

describe("step 5: seed to private scalar", () => {
  const seedOf = (fill: number) => new Uint8Array(64).fill(fill).buffer as ArrayBuffer

  it("keeps the scalar inside [1, n-1]", () => {
    for (const fill of [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF]) {
      const { privateKey } = CryptoManager.generateKeyPair(seedOf(fill))
      expect(privateKey).toBeGreaterThanOrEqual(1n)
      expect(privateKey).toBeLessThan(N)
    }
  })

  it("never yields the point at infinity", () => {
    for (const fill of [0x00, 0xFF]) {
      expect(CryptoManager.generateKeyPair(seedOf(fill)).publicKey).not.toBeNull()
    }
  })

  it("an all-zero seed still produces a usable scalar", () => {
    // Worth pinning: scalar 0 would be invalid, and the +1 is what prevents it.
    expect(CryptoManager.generateKeyPair(seedOf(0x00)).privateKey).toBe(1n)
  })

  it("distinct seeds give distinct scalars", () => {
    // Kept small deliberately: each call runs a full scalar multiplication, and
    // a collision here would be systematic rather than rare, so more samples
    // buy nothing but wall time.
    const samples = 12
    const seen = new Set<bigint>()
    for (let i = 0; i < samples; i++) {
      const seed = crypto.getRandomValues(new Uint8Array(64))
      seen.add(CryptoManager.generateKeyPair(seed.buffer as ArrayBuffer).privateKey)
    }
    expect(seen.size).toBe(samples)
  })

  it("a one-bit seed change changes the scalar", () => {
    const a = new Uint8Array(64).fill(0x5A)
    const b = new Uint8Array(64).fill(0x5A)
    b[63] ^= 0x01
    expect(CryptoManager.generateKeyPair(a.buffer as ArrayBuffer).privateKey)
      .not
      .toBe(CryptoManager.generateKeyPair(b.buffer as ArrayBuffer).privateKey)
  })
})

describe("step 6: PRF to seed (HKDF)", () => {
  const deriveSeed = async (prf: Uint8Array<ArrayBuffer>, version = 2) => {
    const key = await CryptoManager.generateHKDFKey(prf)
    return new Uint8Array(await CryptoManager.generateNewSeed("", prf, key, version))
  }

  it("produces exactly 64 bytes", async () => {
    expect((await deriveSeed(new Uint8Array(32).fill(7))).length).toBe(64)
  })

  it("is deterministic for the same PRF output", async () => {
    const prf = crypto.getRandomValues(new Uint8Array(32))
    expect(Array.from(await deriveSeed(prf))).toEqual(Array.from(await deriveSeed(prf)))
  })

  it("differs for different PRF outputs", async () => {
    const a = await deriveSeed(new Uint8Array(32).fill(1))
    const b = await deriveSeed(new Uint8Array(32).fill(2))
    expect(Array.from(a)).not.toEqual(Array.from(b))
  })

  it("v1 and v2 derive different seeds from the same PRF output", async () => {
    // This is exactly why keyVersion exists: the corrected hash moves the salt.
    const prf = new Uint8Array(32).fill(0x42)
    expect(Array.from(await deriveSeed(prf, 1))).not.toEqual(Array.from(await deriveSeed(prf, 2)))
  })

  it("a one-bit PRF change changes the seed", async () => {
    const a = new Uint8Array(32).fill(0xAA)
    const b = new Uint8Array(32).fill(0xAA)
    b[0] ^= 0x01
    expect(Array.from(await deriveSeed(a))).not.toEqual(Array.from(await deriveSeed(b)))
  })
})

describe("step 7: ECDH vault key", () => {
  const keyPairFor = async (seed: ArrayBuffer) => {
    const { privateKey, publicKey } = CryptoManager.generateKeyPair(seed)
    return KeyHelper.convertKeys(privateKey, publicKey)
  }

  const vaultKeyFor = async (seedFill: number) => {
    const keys = await keyPairFor(new Uint8Array(64).fill(seedFill).buffer as ArrayBuffer)
    return CryptoManager.deriveECDHKey(keys.privateKey.key!, keys.publicKey.key!)
  }

  /** Non-extractable keys can only be compared by what they compute. */
  const interchangeable = async (a: CryptoKey, b: CryptoKey) => {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, a, new TextEncoder().encode("probe"))
    try {
      return new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, b, ciphertext)) === "probe"
    } catch {
      return false
    }
  }

  it("derives a 256-bit AES-GCM key", async () => {
    const key = await vaultKeyFor(0x11)
    expect(key.algorithm.name).toBe("AES-GCM")
    expect((key.algorithm as AesKeyAlgorithm).length).toBe(256)
  })

  it("is not extractable", async () => {
    // The whole point of this hardening: an extension running in the page
    // context cannot lift the vault key, only borrow it while the tab lives.
    const key = await vaultKeyFor(0x11)
    expect(key.extractable).toBe(false)
    await expect(crypto.subtle.exportKey("raw", key)).rejects.toThrow()
  })

  it("is stable across repeated derivations", async () => {
    expect(await interchangeable(await vaultKeyFor(0x22), await vaultKeyFor(0x22))).toBe(true)
  })

  it("differs between users", async () => {
    expect(await interchangeable(await vaultKeyFor(0x33), await vaultKeyFor(0x44))).toBe(false)
  })

  it("runs the ECDH output through a KDF instead of using it raw", async () => {
    // Regression guard for the leading-byte defect below. Cannot compare key
    // bytes any more, so compare against a key derived the old way: if the
    // HKDF step were dropped, these two would be the same key.
    const keys = await keyPairFor(crypto.getRandomValues(new Uint8Array(64)).buffer as ArrayBuffer)

    const withKdf = await CryptoManager.deriveECDHKey(keys.privateKey.key!, keys.publicKey.key!)
    const rawEcdh = await crypto.subtle.deriveKey(
      { name: "ECDH", public: keys.publicKey.key! },
      keys.privateKey.key!,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    )

    expect(await interchangeable(withKdf, rawEcdh)).toBe(false)
  })

  it("documents why: raw P-521 ECDH output has a structurally fixed leading byte", async () => {
    // Not testing app code — pinning the platform behaviour that motivated the
    // KDF. Z is x encoded in ceil(521/8) = 66 bytes while x < 2^521, so the top
    // 7 bits of Z[0] are always zero and deriveKey takes Z's leftmost bytes.
    const leading = new Set<number>()
    for (let i = 0; i < 24; i++) {
      const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-521" }, true, ["deriveKey"])) as CryptoKeyPair
      const raw = await crypto.subtle.deriveKey(
        { name: "ECDH", public: pair.publicKey },
        pair.privateKey,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
      )
      leading.add(new Uint8Array(await crypto.subtle.exportKey("raw", raw))[0])
    }

    // Only 0x00 and 0x01 are reachable — roughly 1 bit where there should be 8.
    expect([...leading].every((b) => b === 0x00 || b === 0x01)).toBe(true)
  })

  it("deriveBits must request the whole field element, not a bit count", async () => {
    // deriveBits(..., 521) truncates the LOW-order bits: the final byte comes
    // back masked to 0x80. Passing null returns the true shared secret. This
    // pins the distinction so nobody "tidies" null into a number.
    const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-521" }, true, ["deriveBits"])) as CryptoKeyPair

    const full = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pair.publicKey }, pair.privateKey, null))
    const truncated = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pair.publicKey }, pair.privateKey, 521))

    expect(full.length).toBe(66)
    expect(truncated.length).toBe(66)
    expect(truncated[65] & 0x7F).toBe(0)
    expect(Array.from(full)).not.toEqual(Array.from(truncated))
  })
})

describe("step 8: AES-GCM", () => {
  const key = async () => crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]) as Promise<CryptoKey>

  it("round trips file content", async () => {
    const k = await key()
    const data = crypto.getRandomValues(new Uint8Array(4096))
    const { encryptedData, iv } = await CryptoManager.encryptFile(data.buffer as ArrayBuffer, k)
    expect(Array.from(new Uint8Array(await CryptoManager.decryptFile(encryptedData, k, iv)))).toEqual(Array.from(data))
  })

  it("round trips an empty file", async () => {
    const k = await key()
    const { encryptedData, iv } = await CryptoManager.encryptFile(new ArrayBuffer(0), k)
    expect(encryptedData.byteLength).toBe(16) // tag only
    expect((await CryptoManager.decryptFile(encryptedData, k, iv)).byteLength).toBe(0)
  })

  it("ciphertext is exactly plaintext + 16, which the upload route relies on", async () => {
    const k = await key()
    for (const size of [0, 1, 15, 16, 17, 1000]) {
      const { encryptedData } = await CryptoManager.encryptFile(new ArrayBuffer(size), k)
      expect(encryptedData.byteLength).toBe(size + 16)
    }
  })

  it("uses a fresh IV every time", async () => {
    const k = await key()
    const ivs = new Set<string>()
    for (let i = 0; i < 200; i++) {
      const { iv } = await CryptoManager.encryptFile(new ArrayBuffer(1), k)
      ivs.add(Buffer.from(iv).toString("hex"))
    }
    expect(ivs.size).toBe(200)
  })

  it("rejects tampered ciphertext", async () => {
    const k = await key()
    const { encryptedData, iv } = await CryptoManager.encryptFile(new TextEncoder().encode("secret").buffer as ArrayBuffer, k)
    const tampered = new Uint8Array(encryptedData)
    tampered[0] ^= 0x01
    await expect(CryptoManager.decryptFile(tampered.buffer as ArrayBuffer, k, iv)).rejects.toThrow()
  })

  it("rejects a tampered IV", async () => {
    const k = await key()
    const { encryptedData, iv } = await CryptoManager.encryptFile(new TextEncoder().encode("secret").buffer as ArrayBuffer, k)
    const badIv = new Uint8Array(iv)
    badIv[0] ^= 0x01
    await expect(CryptoManager.decryptFile(encryptedData, k, badIv)).rejects.toThrow()
  })

  it("round trips filenames including unicode", async () => {
    const k = await key()
    for (const name of ["report.pdf", "", "  spaces  .txt", "文件名.txt", "🔐 secret.zip", "a".repeat(500)]) {
      const { encryptedName, iv } = await CryptoManager.encryptFilename(name, k)
      expect(await CryptoManager.decryptFilename(encryptedName, k, iv)).toBe(name)
    }
  })
})

describe("step 9: encoding", () => {
  it("base64 round trips, including sizes that break naive spread encoding", async () => {
    // getRandomValues caps at 65536 bytes per call, so fill larger buffers in chunks.
    const randomBytes = (size: number) => {
      const out = new Uint8Array(size)
      for (let i = 0; i < size; i += 65536) {
        crypto.getRandomValues(out.subarray(i, Math.min(i + 65536, size)))
      }
      return out
    }

    for (const size of [0, 1, 1024, 0x8000, 0x8001, 500_000]) {
      const bytes = randomBytes(size)
      const encoded = BufferHelper.bytesToBase64(bytes)
      expect(Array.from(Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0)))).toEqual(Array.from(bytes))
    }
  })

  it("agrees with Buffer's base64 encoder", () => {
    for (let i = 0; i < 20; i++) {
      const bytes = crypto.getRandomValues(new Uint8Array(i * 37))
      expect(BufferHelper.bytesToBase64(bytes)).toBe(Buffer.from(bytes).toString("base64"))
    }
  })

  it("hexToArrayBuffer decodes the 0x-prefixed keccak salt to 32 bytes", () => {
    const salt = `0x${"ab".repeat(32)}`
    const buf = BufferHelper.hexToArrayBuffer(salt) as ArrayBuffer
    expect(buf.byteLength).toBe(32)
    expect(new Uint8Array(buf)[0]).toBe(0xAB)
  })

  it("bufferToHex round trips through hexToArrayBuffer", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(64))
    const hex = BufferHelper.bufferToHex(bytes)
    expect(Array.from(new Uint8Array(BufferHelper.hexToArrayBuffer(hex) as ArrayBuffer))).toEqual(Array.from(bytes))
  })
})

describe("full chain: passkey PRF to ciphertext and back", () => {
  const login = async (prf: Uint8Array<ArrayBuffer>, keyVersion = 2) => {
    const hkdfKey = await CryptoManager.generateHKDFKey(prf)
    const seed = await CryptoManager.generateNewSeed("", prf, hkdfKey, keyVersion)
    const { privateKey, publicKey } = CryptoManager.generateKeyPair(seed)
    const keys = await KeyHelper.convertKeys(privateKey, publicKey)
    return CryptoManager.deriveECDHKey(keys.privateKey.key!, keys.publicKey.key!)
  }

  it("a file encrypted in one session decrypts in the next", async () => {
    const prf = crypto.getRandomValues(new Uint8Array(32))
    const plaintext = crypto.getRandomValues(new Uint8Array(10_000))

    const { encryptedData, iv } = await CryptoManager.encryptFile(plaintext.buffer as ArrayBuffer, await login(prf))
    const recovered = await CryptoManager.decryptFile(encryptedData, await login(prf), iv)

    expect(Array.from(new Uint8Array(recovered))).toEqual(Array.from(plaintext))
  })

  it("a different passkey cannot decrypt the file", async () => {
    const plaintext = new TextEncoder().encode("private").buffer as ArrayBuffer
    const { encryptedData, iv } = await CryptoManager.encryptFile(plaintext, await login(crypto.getRandomValues(new Uint8Array(32))))
    await expect(CryptoManager.decryptFile(encryptedData, await login(crypto.getRandomValues(new Uint8Array(32))), iv)).rejects.toThrow()
  })

  it("a v1 vault key cannot decrypt a v2 vault, and vice versa", async () => {
    const prf = crypto.getRandomValues(new Uint8Array(32))
    const plaintext = new TextEncoder().encode("v1 data").buffer as ArrayBuffer

    const { encryptedData, iv } = await CryptoManager.encryptFile(plaintext, await login(prf, 1))
    await expect(CryptoManager.decryptFile(encryptedData, await login(prf, 2), iv)).rejects.toThrow()
    // ...but the v1 key still opens it, which is what keeps old vaults recoverable.
    expect(new TextDecoder().decode(await CryptoManager.decryptFile(encryptedData, await login(prf, 1), iv))).toBe("v1 data")
  })
})

describe("full chain: sharing", () => {
  it("a recipient with the share key recovers the exact file and name", async () => {
    const shareKey = CryptoManager.generateShareKey()
    const plaintext = crypto.getRandomValues(new Uint8Array(5000))

    // Sender
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const nameSalt = crypto.getRandomValues(new Uint8Array(16))
    const { encryptedData, iv } = await CryptoManager.encryptFile(plaintext.buffer as ArrayBuffer, await CryptoManager.deriveShareKey(shareKey, salt))
    const { encryptedName, iv: nameIv } = await CryptoManager.encryptFilename("holiday.zip", await CryptoManager.deriveShareKey(shareKey, nameSalt))

    // Recipient
    const recovered = await CryptoManager.decryptFile(encryptedData, await CryptoManager.deriveShareKey(shareKey, salt), iv)
    const name = await CryptoManager.decryptFilename(encryptedName, await CryptoManager.deriveShareKey(shareKey, nameSalt), nameIv)

    expect(Array.from(new Uint8Array(recovered))).toEqual(Array.from(plaintext))
    expect(name).toBe("holiday.zip")
  })

  it("the file key and the filename key are independent", async () => {
    const shareKey = CryptoManager.generateShareKey()

    const fileKey = await CryptoManager.deriveShareKey(shareKey, crypto.getRandomValues(new Uint8Array(16)))
    const nameKey = await CryptoManager.deriveShareKey(shareKey, crypto.getRandomValues(new Uint8Array(16)))

    // Non-extractable, so independence is shown by one failing to open the
    // other's ciphertext.
    const { encryptedData, iv } = await CryptoManager.encryptFile(new TextEncoder().encode("file body").buffer as ArrayBuffer, fileKey)
    await expect(CryptoManager.decryptFile(encryptedData, nameKey, iv)).rejects.toThrow()
  })

  it("one share's key cannot open another share", async () => {
    // The property the old user-wide share key did not have.
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const a = await CryptoManager.deriveShareKey(CryptoManager.generateShareKey(), salt)
    const b = await CryptoManager.deriveShareKey(CryptoManager.generateShareKey(), salt)

    const { encryptedData, iv } = await CryptoManager.encryptFile(new TextEncoder().encode("share A").buffer as ArrayBuffer, a)
    await expect(CryptoManager.decryptFile(encryptedData, b, iv)).rejects.toThrow()
  })

  it("a share key is independent of the sender's vault key", async () => {
    // Sharing a file must not expose the vault master key, and a share
    // recipient must not be able to open anything else the vault holds.
    const prf = crypto.getRandomValues(new Uint8Array(32))
    const hkdfKey = await CryptoManager.generateHKDFKey(prf)
    const seed = await CryptoManager.generateNewSeed("", prf, hkdfKey, 2)
    const { privateKey, publicKey } = CryptoManager.generateKeyPair(seed)
    const keys = await KeyHelper.convertKeys(privateKey, publicKey)
    const vaultKey = await CryptoManager.deriveECDHKey(keys.privateKey.key!, keys.publicKey.key!)

    const shareDerived = await CryptoManager.deriveShareKey(CryptoManager.generateShareKey(), crypto.getRandomValues(new Uint8Array(16)))

    const { encryptedData, iv } = await CryptoManager.encryptFile(new TextEncoder().encode("vault file").buffer as ArrayBuffer, vaultKey)
    await expect(CryptoManager.decryptFile(encryptedData, shareDerived, iv)).rejects.toThrow()
  })
})
