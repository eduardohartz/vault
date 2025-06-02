declare global {
  var registeredUsers:
    | Array<{
        id: string
        username: string
        credentialId: string
        publicKey: string
      }>
    | undefined

  var files:
    | Array<{
        id: string
        name: string
        size: number
        encryptedData: string
        salt: string
        iv: string
        uploadedAt: string
        userId: string
      }>
    | undefined
}

export {}
