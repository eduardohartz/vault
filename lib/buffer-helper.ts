import { AdvancedCryptoManager } from "./advanced-crypto"

export type Point = { x: bigint, y: bigint }

export class BufferHelper {
  static convertBufferType<T extends ArrayBufferView>(sourceBuff: ArrayBufferView, OutputType: new (buffer: ArrayBuffer) => T): T {
    const buffer = new ArrayBuffer(sourceBuff.byteLength)
    const SourceType = this.getBufferTypedArrayConstructor(Object.prototype.toString.call(sourceBuff))
    const sourceView = new SourceType(buffer)
    sourceView.set(sourceBuff as any)
    return new OutputType(buffer)
  }

  static toArrayBuffer(input: BufferSource): ArrayBuffer {
    if (input instanceof ArrayBuffer) {
      return input
    }

    if (ArrayBuffer.isView(input)) {
      return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength) as ArrayBuffer
    }

    throw new TypeError("Input must be a BufferSource (ArrayBuffer or TypedArray)")
  }

  static bufferPush(source_buff: ArrayBufferView, new_values: number): ArrayBufferView {
    const Source_buff_type = this.getBufferTypedArrayConstructor(Object.prototype.toString.call(source_buff))
    const new_ab = new Source_buff_type((source_buff as any).length + 1)
    new_ab.set(source_buff as any, 0)
    new_ab[new_ab.length - 1] = new_values
    return new_ab
  }

  static getBufferTypedArrayConstructor(tag: string): any {
    const typeName = tag.substring(8, tag.length - 1)
    const ctor = (globalThis as any)[typeName]
    if (ctor && typeof ctor === "function") {
      return ctor
    }
    throw new TypeError(`Invalid typed array type tag: ${tag}`)
  }

  static bufferToHex(buffer: Uint8Array): string {
    const table = "0123456789abcdef"
    const output = Array.from({ length: buffer.length * 2 })

    for (let i = 0; i < buffer.length; ++i) {
      const byte = buffer[i]
      output[2 * i] = table[(byte >> 4) & 0x0F]
      output[2 * i + 1] = table[byte & 0x0F]
    }

    return output.join("")
  }

  static hexStringToHexNumber(hexStr: string): string {
    if (/0x/i.test(hexStr.substring(0, 2))) {
      return hexStr.substring(2)
    }
    return hexStr
  }

  static hexToArrayBuffer(hexStr: string, BufferType: any = null): ArrayBuffer | ArrayBufferView {
    hexStr = this.hexStringToHexNumber(hexStr)

    const ret: number[] = []
    for (let i = 0; i < hexStr.length / 2; i++) {
      const x = i * 2
      const n = Number.parseInt(hexStr.substr(x, 2), 16)
      ret.push(n)
    }

    if (BufferType) {
      return new BufferType(ret)
    }
    return new Uint8Array(ret).buffer
  }

  static hasProperty(prop: unknown): boolean {
    return prop !== "" && prop !== null && prop !== undefined
  }

  static modAdd(a: bigint, b: bigint, m: bigint): bigint {
    return ((a % m) + (b % m)) % m
  }

  static modSub(a: bigint, b: bigint, m: bigint): bigint {
    return ((a % m) - (b % m) + m) % m
  }

  static modMul(a: bigint, b: bigint, m: bigint): bigint {
    return ((a % m) * (b % m)) % m
  }

  static modInv(a: bigint, m: bigint): bigint {
    const egcd = (a: bigint, b: bigint): [bigint, bigint, bigint] => {
      if (a === BigInt(0)) {
        return [b, BigInt(0), BigInt(1)]
      }
      const [g, x, y] = egcd(b % a, a)
      return [g, y - (b / a) * x, x]
    }

    const [g, x] = egcd(a, m)
    if (g !== BigInt(1)) {
      throw new Error("Modular inverse does not exist")
    }
    return ((x % m) + m) % m
  }

  static isOnCurve(point: Point | null): boolean {
    if (point === null) {
      return true
    }
    const { x, y } = point
    const { P, A, B } = AdvancedCryptoManager

    const left = this.modMul(y, y, P)
    const x2 = this.modMul(x, x, P)
    const x3 = this.modMul(x2, x, P)
    const ax = this.modMul(A, x, P)
    const right = this.modAdd(this.modAdd(x3, ax, P), B, P)

    return left === right
  }

  static pointAdd(P1: Point | null, P2: Point | null): Point | null {
    const { P } = AdvancedCryptoManager

    if (P1 === null) {
      return P2
    }
    if (P2 === null) {
      return P1
    }

    if (P1.x === P2.x) {
      if (P1.y === P2.y) {
        return this.pointDouble(P1)
      }
      return null
    }

    const slope = this.modMul(this.modSub(P2.y, P1.y, P), this.modInv(this.modSub(P2.x, P1.x, P), P), P)

    const x3 = this.modSub(this.modSub(this.modMul(slope, slope, P), P1.x, P), P2.x, P)
    const y3 = this.modSub(this.modMul(slope, this.modSub(P1.x, x3, P), P), P1.y, P)

    const result: Point = { x: x3, y: y3 }
    if (!this.isOnCurve(result)) {
      throw new Error("Resulting point not on curve")
    }
    return result
  }

  static pointDouble(P: Point | null): Point | null {
    if (P === null) {
      return null
    }
    const { x, y } = P
    const { A, P: mod } = AdvancedCryptoManager

    const slope = this.modMul(this.modAdd(this.modMul(BigInt(3), this.modMul(x, x, mod), mod), A, mod), this.modInv(this.modMul(BigInt(2), y, mod), mod), mod)

    const x3 = this.modSub(this.modMul(slope, slope, mod), this.modMul(BigInt(2), x, mod), mod)
    const y3 = this.modSub(this.modMul(slope, this.modSub(x, x3, mod), mod), y, mod)

    const result: Point = { x: x3, y: y3 }
    if (!this.isOnCurve(result)) {
      throw new Error("Resulting point not on curve")
    }
    return result
  }

  static scalarMul(k: bigint, point: Point): Point | null {
    let result: Point | null = null
    let addend: Point | null = point

    while (k > 0) {
      if ((k & BigInt(1)) === BigInt(1)) {
        result = this.pointAdd(result, addend)
      }
      addend = this.pointDouble(addend)
      k >>= BigInt(1)
    }

    return result
  }
}
