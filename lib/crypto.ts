export class CryptoManager {
  private static async deriveKey(
    password: string,
    salt: Uint8Array,
  ): Promise<CryptoKey> {
    const encoder = new TextEncoder()
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"],
    )

    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    )
  }

  static async encryptFile(
    file: File,
    password: string,
  ): Promise<{
    encryptedData: ArrayBuffer
    salt: Uint8Array
    iv: Uint8Array
  }> {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const key = await this.deriveKey(password, salt)

    const fileBuffer = await file.arrayBuffer()
    const encryptedData = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      fileBuffer,
    )

    return { encryptedData, salt, iv }
  }

  static async decryptFile(
    encryptedData: ArrayBuffer,
    password: string,
    salt: Uint8Array,
    iv: Uint8Array,
  ): Promise<ArrayBuffer> {
    const key = await this.deriveKey(password, salt)

    return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedData)
  }

  static async encryptData(
    data: string,
    password: string,
  ): Promise<{
    encryptedData: string
    salt: string
    iv: string
  }> {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const key = await this.deriveKey(password, salt)

    const encoder = new TextEncoder()
    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      encoder.encode(data),
    )

    return {
      encryptedData: btoa(
        String.fromCharCode(...new Uint8Array(encryptedBuffer)),
      ),
      salt: btoa(String.fromCharCode(...salt)),
      iv: btoa(String.fromCharCode(...iv)),
    }
  }

  static async decryptData(
    encryptedData: string,
    password: string,
    salt: string,
    iv: string,
  ): Promise<string> {
    const saltBytes = Uint8Array.from(atob(salt), (c) => c.charCodeAt(0))
    const ivBytes = Uint8Array.from(atob(iv), (c) => c.charCodeAt(0))
    const encryptedBytes = Uint8Array.from(atob(encryptedData), (c) =>
      c.charCodeAt(0),
    )

    const key = await this.deriveKey(password, saltBytes)
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBytes },
      key,
      encryptedBytes,
    )

    const decoder = new TextDecoder()
    return decoder.decode(decryptedBuffer)
  }
}
