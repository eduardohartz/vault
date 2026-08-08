/**
 * DO NOT "FIX" THIS FILE.
 *
 * This is the original hand-rolled Keccak that shipped in v1 of the vault. It
 * is NOT Keccak-256: a `var` -> `let` refactor of the upstream js-sha3 code
 * left `lastByteIndex` pinned to the block start, so the padding byte lands at
 * offset 0 instead of at the end of the message. Consequences:
 *
 *   - "abc" and "hello" do not match the published Keccak-256 vectors.
 *   - Message length is not bound in: [0x41] and [0x41,0x00] collide.
 *   - The padding OR-s 1 into byte 0, so 256 distinct 32-byte inputs collapse
 *     to 128 distinct digests.
 *
 * It is retained verbatim for one reason only: v1 encryption keys were derived
 * through it, so changing a single byte here would make every existing v1
 * vault permanently undecryptable. New keys use `KeccakHelper` (keyVersion 2).
 *
 * See tests/keccak.test.ts, which pins this implementation's wrong-but-required
 * output alongside the corrected one.
 */
export class LegacyKeccakHelper {
  static readonly HEX_CHARS: string[] = "0123456789abcdef".split("")
  static readonly KECCAK_PADDING: number[] = [1, 256, 65536, 16777216]
  static readonly SHIFT: number[] = [0, 8, 16, 24]
  static readonly RC: number[] = [
    1,
    0,
    32898,
    0,
    32906,
    2147483648,
    2147516416,
    2147483648,
    32907,
    0,
    2147483649,
    0,
    2147516545,
    2147483648,
    32777,
    2147483648,
    138,
    0,
    136,
    0,
    2147516425,
    0,
    2147483658,
    0,
    2147516555,
    0,
    139,
    2147483648,
    32905,
    2147483648,
    32771,
    2147483648,
    32770,
    2147483648,
    128,
    2147483648,
    32778,
    0,
    2147483658,
    2147483648,
    2147516545,
    2147483648,
    32896,
    2147483648,
    2147483649,
    0,
    2147516424,
    2147483648,
  ]

  static keccak256(hexStr: string): string {
    return LegacyKeccakHelper.lazyKeccak(256, hexStr)
  }

  static strictHexKeccak256(hexStr: string): string | null {
    return LegacyKeccakHelper.strictHexKeccak(256, hexStr)
  }

  static strKeccak256(str: string): string {
    return LegacyKeccakHelper.strKeccak(256, str)
  }

  static keccak(bits: number, message: number[]): string {
    return LegacyKeccakHelper.update(LegacyKeccakHelper.createKeccakState(bits), message)
  }

  static createKeccakState(bits: number): LegacyKeccakState {
    const s = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    return {
      blocks: [],
      reset: true,
      block: 0,
      start: 0,
      blockCount: (1600 - (bits << 1)) >> 5,
      outputBlocks: bits >> 5,
      s: [...s, ...s, ...s, ...s, ...s],
      lastByteIndex: 0,
    }
  }

  static update(state: LegacyKeccakState, message: number[]): string {
    const { blocks, blockCount, outputBlocks, s } = state
    let { reset, block, start } = state
    const byteCount = blockCount << 2
    let index = 0

    while (index < message.length) {
      if (reset) {
        reset = false
        blocks[0] = block
        for (let i = 1; i < blockCount + 1; ++i) {
          blocks[i] = 0
        }
      }

      for (let i = start; index < message.length && i < byteCount; ++index) {
        blocks[i >> 2] |= message[index] << LegacyKeccakHelper.SHIFT[i++ & 3]
      }

      state.lastByteIndex = start
      if (start >= byteCount) {
        state.start = start - byteCount
        state.block = blocks[blockCount]

        for (let i = 0; i < blockCount; ++i) {
          s[i] ^= blocks[i]
        }

        LegacyKeccakHelper.f(s)
        reset = true
      } else {
        state.start = start
      }
    }

    const i = state.lastByteIndex
    blocks[i >> 2] |= LegacyKeccakHelper.KECCAK_PADDING[i & 3]

    if (state.lastByteIndex === byteCount) {
      blocks[0] = blocks[blockCount]
      for (let i = 1; i < blockCount + 1; ++i) {
        blocks[i] = 0
      }
    }

    blocks[blockCount - 1] |= 0x80000000

    for (let i = 0; i < blockCount; ++i) {
      s[i] ^= blocks[i]
    }

    LegacyKeccakHelper.f(s)

    let hex = ""
    let j = 0

    while (j < outputBlocks) {
      for (let i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
        const block = s[i]
        hex +=
          LegacyKeccakHelper.HEX_CHARS[(block >> 4) & 0x0F] +
          LegacyKeccakHelper.HEX_CHARS[block & 0x0F] +
          LegacyKeccakHelper.HEX_CHARS[(block >> 12) & 0x0F] +
          LegacyKeccakHelper.HEX_CHARS[(block >> 8) & 0x0F] +
          LegacyKeccakHelper.HEX_CHARS[(block >> 20) & 0x0F] +
          LegacyKeccakHelper.HEX_CHARS[(block >> 16) & 0x0F] +
          LegacyKeccakHelper.HEX_CHARS[(block >> 28) & 0x0F] +
          LegacyKeccakHelper.HEX_CHARS[(block >> 24) & 0x0F]
      }

      if (j % blockCount === 0) {
        LegacyKeccakHelper.f(s)
      }
    }

    return `0x${hex}`
  }

  static f(s: number[]): void {
    let h, l, n
    let c0, c1, c2, c3, c4, c5, c6, c7, c8, c9
    let b0,
      b1,
      b2,
      b3,
      b4,
      b5,
      b6,
      b7,
      b8,
      b9,
      b10,
      b11,
      b12,
      b13,
      b14,
      b15,
      b16,
      b17,
      b18,
      b19,
      b20,
      b21,
      b22,
      b23,
      b24,
      b25,
      b26,
      b27,
      b28,
      b29,
      b30,
      b31,
      b32,
      b33,
      b34,
      b35,
      b36,
      b37,
      b38,
      b39,
      b40,
      b41,
      b42,
      b43,
      b44,
      b45,
      b46,
      b47,
      b48,
      b49

    for (n = 0; n < 48; n += 2) {
      c0 = s[0] ^ s[10] ^ s[20] ^ s[30] ^ s[40]
      c1 = s[1] ^ s[11] ^ s[21] ^ s[31] ^ s[41]
      c2 = s[2] ^ s[12] ^ s[22] ^ s[32] ^ s[42]
      c3 = s[3] ^ s[13] ^ s[23] ^ s[33] ^ s[43]
      c4 = s[4] ^ s[14] ^ s[24] ^ s[34] ^ s[44]
      c5 = s[5] ^ s[15] ^ s[25] ^ s[35] ^ s[45]
      c6 = s[6] ^ s[16] ^ s[26] ^ s[36] ^ s[46]
      c7 = s[7] ^ s[17] ^ s[27] ^ s[37] ^ s[47]
      c8 = s[8] ^ s[18] ^ s[28] ^ s[38] ^ s[48]
      c9 = s[9] ^ s[19] ^ s[29] ^ s[39] ^ s[49]

      h = c8 ^ ((c2 << 1) | (c3 >>> 31))
      l = c9 ^ ((c3 << 1) | (c2 >>> 31))
      s[0] ^= h
      s[1] ^= l
      s[10] ^= h
      s[11] ^= l
      s[20] ^= h
      s[21] ^= l
      s[30] ^= h
      s[31] ^= l
      s[40] ^= h
      s[41] ^= l

      h = c0 ^ ((c4 << 1) | (c5 >>> 31))
      l = c1 ^ ((c5 << 1) | (c4 >>> 31))
      s[2] ^= h
      s[3] ^= l
      s[12] ^= h
      s[13] ^= l
      s[22] ^= h
      s[23] ^= l
      s[32] ^= h
      s[33] ^= l
      s[42] ^= h
      s[43] ^= l

      h = c2 ^ ((c6 << 1) | (c7 >>> 31))
      l = c3 ^ ((c7 << 1) | (c6 >>> 31))
      s[4] ^= h
      s[5] ^= l
      s[14] ^= h
      s[15] ^= l
      s[24] ^= h
      s[25] ^= l
      s[34] ^= h
      s[35] ^= l
      s[44] ^= h
      s[45] ^= l

      h = c4 ^ ((c8 << 1) | (c9 >>> 31))
      l = c5 ^ ((c9 << 1) | (c8 >>> 31))
      s[6] ^= h
      s[7] ^= l
      s[16] ^= h
      s[17] ^= l
      s[26] ^= h
      s[27] ^= l
      s[36] ^= h
      s[37] ^= l
      s[46] ^= h
      s[47] ^= l

      h = c6 ^ ((c0 << 1) | (c1 >>> 31))
      l = c7 ^ ((c1 << 1) | (c0 >>> 31))
      s[8] ^= h
      s[9] ^= l
      s[18] ^= h
      s[19] ^= l
      s[28] ^= h
      s[29] ^= l
      s[38] ^= h
      s[39] ^= l
      s[48] ^= h
      s[49] ^= l

      b0 = s[0]
      b1 = s[1]
      b32 = (s[11] << 4) | (s[10] >>> 28)
      b33 = (s[10] << 4) | (s[11] >>> 28)
      b14 = (s[20] << 3) | (s[21] >>> 29)
      b15 = (s[21] << 3) | (s[20] >>> 29)
      b46 = (s[31] << 9) | (s[30] >>> 23)
      b47 = (s[30] << 9) | (s[31] >>> 23)
      b28 = (s[40] << 18) | (s[41] >>> 14)
      b29 = (s[41] << 18) | (s[40] >>> 14)
      b20 = (s[2] << 1) | (s[3] >>> 31)
      b21 = (s[3] << 1) | (s[2] >>> 31)
      b2 = (s[13] << 12) | (s[12] >>> 20)
      b3 = (s[12] << 12) | (s[13] >>> 20)
      b34 = (s[22] << 10) | (s[23] >>> 22)
      b35 = (s[23] << 10) | (s[22] >>> 22)
      b16 = (s[33] << 13) | (s[32] >>> 19)
      b17 = (s[32] << 13) | (s[33] >>> 19)
      b48 = (s[42] << 2) | (s[43] >>> 30)
      b49 = (s[43] << 2) | (s[42] >>> 30)
      b40 = (s[5] << 30) | (s[4] >>> 2)
      b41 = (s[4] << 30) | (s[5] >>> 2)
      b22 = (s[14] << 6) | (s[15] >>> 26)
      b23 = (s[15] << 6) | (s[14] >>> 26)
      b4 = (s[25] << 11) | (s[24] >>> 21)
      b5 = (s[24] << 11) | (s[25] >>> 21)
      b36 = (s[34] << 15) | (s[35] >>> 17)
      b37 = (s[35] << 15) | (s[34] >>> 17)
      b18 = (s[45] << 29) | (s[44] >>> 3)
      b19 = (s[44] << 29) | (s[45] >>> 3)
      b10 = (s[6] << 28) | (s[7] >>> 4)
      b11 = (s[7] << 28) | (s[6] >>> 4)
      b42 = (s[17] << 23) | (s[16] >>> 9)
      b43 = (s[16] << 23) | (s[17] >>> 9)
      b24 = (s[26] << 25) | (s[27] >>> 7)
      b25 = (s[27] << 25) | (s[26] >>> 7)
      b6 = (s[36] << 21) | (s[37] >>> 11)
      b7 = (s[37] << 21) | (s[36] >>> 11)
      b38 = (s[47] << 24) | (s[46] >>> 8)
      b39 = (s[46] << 24) | (s[47] >>> 8)
      b30 = (s[8] << 27) | (s[9] >>> 5)
      b31 = (s[9] << 27) | (s[8] >>> 5)
      b12 = (s[18] << 20) | (s[19] >>> 12)
      b13 = (s[19] << 20) | (s[18] >>> 12)
      b44 = (s[29] << 7) | (s[28] >>> 25)
      b45 = (s[28] << 7) | (s[29] >>> 25)
      b26 = (s[38] << 8) | (s[39] >>> 24)
      b27 = (s[39] << 8) | (s[38] >>> 24)
      b8 = (s[48] << 14) | (s[49] >>> 18)
      b9 = (s[49] << 14) | (s[48] >>> 18)

      s[0] = b0 ^ (~b2 & b4)
      s[1] = b1 ^ (~b3 & b5)
      s[10] = b10 ^ (~b12 & b14)
      s[11] = b11 ^ (~b13 & b15)
      s[20] = b20 ^ (~b22 & b24)
      s[21] = b21 ^ (~b23 & b25)
      s[30] = b30 ^ (~b32 & b34)
      s[31] = b31 ^ (~b33 & b35)
      s[40] = b40 ^ (~b42 & b44)
      s[41] = b41 ^ (~b43 & b45)
      s[2] = b2 ^ (~b4 & b6)
      s[3] = b3 ^ (~b5 & b7)
      s[12] = b12 ^ (~b14 & b16)
      s[13] = b13 ^ (~b15 & b17)
      s[22] = b22 ^ (~b24 & b26)
      s[23] = b23 ^ (~b25 & b27)
      s[32] = b32 ^ (~b34 & b36)
      s[33] = b33 ^ (~b35 & b37)
      s[42] = b42 ^ (~b44 & b46)
      s[43] = b43 ^ (~b45 & b47)
      s[4] = b4 ^ (~b6 & b8)
      s[5] = b5 ^ (~b7 & b9)
      s[14] = b14 ^ (~b16 & b18)
      s[15] = b15 ^ (~b17 & b19)
      s[24] = b24 ^ (~b26 & b28)
      s[25] = b25 ^ (~b27 & b29)
      s[34] = b34 ^ (~b36 & b38)
      s[35] = b35 ^ (~b37 & b39)
      s[44] = b44 ^ (~b46 & b48)
      s[45] = b45 ^ (~b47 & b49)
      s[6] = b6 ^ (~b8 & b0)
      s[7] = b7 ^ (~b9 & b1)
      s[16] = b16 ^ (~b18 & b10)
      s[17] = b17 ^ (~b19 & b11)
      s[26] = b26 ^ (~b28 & b20)
      s[27] = b27 ^ (~b29 & b21)
      s[36] = b36 ^ (~b38 & b30)
      s[37] = b37 ^ (~b39 & b31)
      s[46] = b46 ^ (~b48 & b40)
      s[47] = b47 ^ (~b49 & b41)
      s[8] = b8 ^ (~b0 & b2)
      s[9] = b9 ^ (~b1 & b3)
      s[18] = b18 ^ (~b10 & b12)
      s[19] = b19 ^ (~b11 & b13)
      s[28] = b28 ^ (~b20 & b22)
      s[29] = b29 ^ (~b21 & b23)
      s[38] = b38 ^ (~b30 & b32)
      s[39] = b39 ^ (~b31 & b33)
      s[48] = b48 ^ (~b40 & b42)
      s[49] = b49 ^ (~b41 & b43)

      s[0] ^= LegacyKeccakHelper.RC[n]
      s[1] ^= LegacyKeccakHelper.RC[n + 1]
    }
  }

  static strictHexKeccak(bits: number, hex: string): string | null {
    if (hex.length % 2 !== 0) {
      return null
    }
    if (hex.startsWith("0x")) {
      hex = hex.slice(2)
    }

    const msg: number[] = []
    for (let i = 0; i < hex.length; i += 2) {
      const newStr = Number.parseInt(hex.slice(i, i + 2), 16)
      if (newStr > 255) {
        return LegacyKeccakHelper.strKeccak(bits, hex)
      }
      msg.push(newStr)
    }
    return LegacyKeccakHelper.keccak(bits, msg)
  }

  static lazyKeccak(bits: number, hex: string): string {
    if (hex.length % 2 !== 0) {
      return LegacyKeccakHelper.strKeccak(bits, hex)
    }
    if (hex.startsWith("0x")) {
      hex = hex.slice(2)
    }

    const msg: number[] = []
    for (let i = 0; i < hex.length; i += 2) {
      const newStr = Number.parseInt(hex.slice(i, i + 2), 16)
      if (Number.isNaN(newStr) || newStr > 255) {
        return LegacyKeccakHelper.strKeccak(bits, hex)
      }
      msg.push(newStr)
    }
    return LegacyKeccakHelper.keccak(bits, msg)
  }

  static strKeccak(bits: number, str: string): string {
    const textEncoder = new TextEncoder()
    const msg: number[] = Array.from(textEncoder.encode(str))
    return LegacyKeccakHelper.keccak(bits, msg)
  }
}

type LegacyKeccakState = {
  blocks: number[]
  reset: boolean
  block: number
  start: number
  blockCount: number
  outputBlocks: number
  s: number[]
  lastByteIndex: number
}
