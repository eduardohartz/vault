"use client"

import type React from "react"

import {
  Button,
  Card,
  CardBody,
  CardHeader,
  Chip,
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownTrigger,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Progress,
  Spinner,
  useDisclosure,
} from "@heroui/react"
import { Copy, Download, FileIcon, Link, LogOut, Moon, MoreVertical, Share, ShareIcon as ShareOff, Shield, Sun, Trash2, Upload } from "lucide-react"
import { useTheme } from "next-themes"
import { useEffect, useRef, useState } from "react"
import AlertModal from "@/components/alert-modal"
import ShareConfirmationModal from "@/components/share-confirmation-modal"
import { CryptoManager } from "@/lib/crypto-manager"

type FileManagerProps = {
  user: {
    id: string
    username: string
    shareKey: string
    privateKey: any
    publicKey: any
  }
  onLogout: () => void
}

type FileItem = {
  id: string
  encryptedName: string
  originalSize: number
  encryptedPath: string
  salt: string
  iv: string
  nameSalt: string
  nameIv: string
  uploadedAt: string
  userId: string
  decryptedName?: string
  isShared?: boolean
}

type ShareInfo = {
  id: string
  shareToken: string
  createdAt: string
  expiresAt: string | null
}

export default function FileManager({ user, onLogout }: FileManagerProps) {
  const [files, setFiles] = useState<FileItem[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [isUploading, setIsUploading] = useState(false)
  const [selectedFile, setSelectedFile] = useState<FileItem | null>(null)
  const [shareUrl, setShareUrl] = useState("")
  const [shareInfo, setShareInfo] = useState<ShareInfo | null>(null)
  const [showShareKey, setShowShareKey] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const { theme, setTheme } = useTheme()

  const { isOpen: isDeleteOpen, onOpen: onDeleteOpen, onClose: onDeleteClose } = useDisclosure()
  const { isOpen: isShareOpen, onOpen: onShareOpen, onClose: onShareClose } = useDisclosure()
  const { isOpen: isShareConfirmOpen, onOpen: onShareConfirmOpen, onClose: onShareConfirmClose } = useDisclosure()
  const { isOpen: isAlertOpen, onOpen: onAlertOpen, onClose: onAlertClose } = useDisclosure()
  const [alertConfig, setAlertConfig] = useState({
    title: "",
    message: "",
    type: "info" as "success" | "error" | "warning" | "info",
  })

  const showAlert = (title: string, message: string, type: "success" | "error" | "warning" | "info" = "info") => {
    setAlertConfig({ title, message, type })
    onAlertOpen()
  }

  const loadFiles = async () => {
    try {
      const response = await fetch(`/api/files?userId=${user.id}`)
      const data = await response.json()

      if (response.ok) {
        const filesWithDecryptedNames = await Promise.all(
          data.files.map(async (file: FileItem) => {
            try {
              const nameIv = Uint8Array.from(atob(file.nameIv), (c) => c.charCodeAt(0))
              const key = await CryptoManager.deriveECDHKey(user.privateKey.key, user.publicKey.key)
              const decryptedName = await CryptoManager.decryptFilename(file.encryptedName, key, nameIv)

              const shareResponse = await fetch(`/api/files/${file.id}/share?userId=${user.id}`)
              const shareData = await shareResponse.json()

              return {
                ...file,
                decryptedName,
                isShared: shareData,
              }
            } catch {
              return {
                ...file,
                decryptedName: "[Decryption Failed]",
                isShared: false,
              }
            }
          }),
        )

        setFiles(filesWithDecryptedNames)
      } else {
        throw new Error("Failed to load files")
      }
    } catch {
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    loadFiles()
  }, [user.id])

  const handleLogout = () => {
    localStorage.clear()
    sessionStorage.clear()

    setFiles([])
    setSelectedFile(null)
    setShareUrl("")
    setShareInfo(null)
    setShowShareKey(false)

    if (fileInputRef.current) {
      fileInputRef.current.value = ""
    }

    onLogout()

    showAlert("Logged Out", "All local data has been cleared. You have been successfully logged out.", "success")
  }

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) {
      return
    }

    setIsUploading(true)
    setUploadProgress(0)

    try {
      const salt = crypto.getRandomValues(new Uint8Array(16))
      const nameSalt = crypto.getRandomValues(new Uint8Array(16))

      setUploadProgress(10)

      const key = await CryptoManager.deriveECDHKey(user.privateKey.key, user.publicKey.key)

      setUploadProgress(25)

      const { encryptedData, iv } = await CryptoManager.encryptFile(file, key)

      setUploadProgress(50)

      const { encryptedName, iv: nameIv } = await CryptoManager.encryptFilename(file.name, key)

      setUploadProgress(75)

      const encryptedBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedData)))
      const ivBase64 = btoa(String.fromCharCode(...iv))
      const saltBase64 = btoa(String.fromCharCode(...salt))
      const nameIvBase64 = btoa(String.fromCharCode(...nameIv))
      const nameSaltBase64 = btoa(String.fromCharCode(...nameSalt))

      const formData = new FormData()
      formData.append("encryptedData", encryptedBase64)
      formData.append("iv", ivBase64)
      formData.append("salt", saltBase64)
      formData.append("encryptedName", encryptedName)
      formData.append("nameIv", nameIvBase64)
      formData.append("nameSalt", nameSaltBase64)
      formData.append("originalSize", file.size.toString())
      formData.append("userId", user.id)

      const response = await fetch("/api/files", {
        method: "POST",
        body: formData,
      })

      setUploadProgress(100)

      if (response.ok) {
        await loadFiles()
        showAlert("Upload Successful", `"${file.name}" has been encrypted and uploaded successfully.`, "success")
      } else {
        throw new Error("Upload failed")
      }
    } catch (e) {
      console.error("File upload error:", e)
      showAlert("Upload Failed", "Failed to upload file. Please try again.", "error")
    } finally {
      setIsUploading(false)
      setUploadProgress(0)
      if (fileInputRef.current) {
        fileInputRef.current.value = ""
      }
    }
  }

  const handleFileDownload = async (file: FileItem) => {
    try {
      const response = await fetch(`/api/files/${file.id}?userId=${user.id}`)
      const data = await response.json()

      if (!response.ok) {
        throw new Error("Failed to fetch file")
      }

      const fileData = data.file

      const encryptedData = Uint8Array.from(atob(fileData.encryptedData), (c) => c.charCodeAt(0))
      const iv = Uint8Array.from(atob(fileData.iv), (c) => c.charCodeAt(0))

      const key = await CryptoManager.deriveECDHKey(user.privateKey.key, user.publicKey.key)

      const decryptedData = await CryptoManager.decryptFile(encryptedData.buffer, key, iv)

      const blob = new Blob([decryptedData])
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = file.decryptedName || "download"
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      showAlert("Download Complete", `"${file.decryptedName}" has been downloaded successfully.`, "success")
    } catch {
      showAlert("Download Failed", "Failed to decrypt and download file.", "error")
    }
  }

  const getFile = async (file: FileItem) => {
    try {
      const response = await fetch(`/api/files/${file.id}?userId=${user.id}`)
      const data = await response.json()

      if (!response.ok) {
        throw new Error("Failed to fetch file")
      }

      const fileData = data.file
      const encryptedData = Uint8Array.from(atob(fileData.encryptedData), (c) => c.charCodeAt(0))
      const iv = Uint8Array.from(atob(fileData.iv), (c) => c.charCodeAt(0))

      const key = await CryptoManager.deriveECDHKey(user.privateKey.key, user.publicKey.key)
      const decryptedData = await CryptoManager.decryptFile(encryptedData.buffer, key, iv)

      const decryptedFile = new File([decryptedData], file.decryptedName || "download", { type: "application/octet-stream" })
      return decryptedFile
    } catch {
      showAlert("Decryption Failed", "Failed to decrypt file.", "error")
    }
  }

  const handleFileShare = async (file: FileItem) => {
    if (file.isShared) {
      try {
        const response = await fetch(`/api/files/${file.id}/share?userId=${user.id}`)
        const data = await response.json()

        if (response.ok && data.shares.length > 0) {
          const baseUrl = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000"
          setShareUrl(`${baseUrl}/share/${data.shareToken}`)
          setShareInfo(data)
          setSelectedFile(file)
          onShareOpen()
        }
      } catch {
        showAlert("Share Failed", "Failed to get share link.", "error")
      }
    } else {
      setSelectedFile(file)
      onShareConfirmOpen()
    }
  }

  const handleShareConfirm = async (expiryMinutes: number | null, shareKey: string) => {
    if (!selectedFile) {
      return
    }

    try {
      const expiresAt = expiryMinutes ? new Date(Date.now() + expiryMinutes * 60 * 1000).toISOString() : null

      const file = await getFile(selectedFile)

      if (!file) {
        throw new Error("Failed to retrieve file for sharing")
      }

      const salt = crypto.getRandomValues(new Uint8Array(16))
      const nameSalt = crypto.getRandomValues(new Uint8Array(16))
      const key = await CryptoManager.deriveECDHKeyFromShared(shareKey.trim(), salt)
      const nameKey = await CryptoManager.deriveECDHKeyFromShared(shareKey.trim(), nameSalt)

      const { encryptedData, iv } = await CryptoManager.encryptFile(file, key)

      const { encryptedName, iv: nameIv } = await CryptoManager.encryptFilename(file.name, nameKey)

      const encryptedBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedData)))
      const ivBase64 = btoa(String.fromCharCode(...iv))
      const saltBase64 = btoa(String.fromCharCode(...salt))
      const nameIvBase64 = btoa(String.fromCharCode(...nameIv))
      const nameSaltBase64 = btoa(String.fromCharCode(...nameSalt))

      const formData = new FormData()
      formData.append("encryptedData", encryptedBase64)
      formData.append("iv", ivBase64)
      formData.append("salt", saltBase64)
      formData.append("encryptedName", encryptedName)
      formData.append("nameIv", nameIvBase64)
      formData.append("nameSalt", nameSaltBase64)
      formData.append("originalSize", file.size.toString())
      formData.append("userId", user.id)
      formData.append("expiresAt", expiresAt || "")

      const response = await fetch(`/api/files/${selectedFile.id}/share`, {
        method: "POST",
        body: formData,
      })

      const data = await response.json()

      if (response.ok) {
        setShareUrl(data.shareUrl)
        setShareInfo({
          id: "new",
          shareToken: data.shareToken,
          createdAt: new Date().toISOString(),
          expiresAt,
        })
        onShareOpen()
        await loadFiles()
        showAlert("Share Created", "Share link created successfully!", "success")
      } else {
        throw new Error("Failed to create share")
      }
    } catch {
      showAlert("Share Failed", "Failed to create share link.", "error")
    }
  }

  const handleUnshare = async (file: FileItem) => {
    try {
      const response = await fetch(`/api/files/${file.id}/share`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId: user.id }),
      })

      if (response.ok) {
        await loadFiles()
        showAlert("Unshared Successfully", `"${file.decryptedName}" is no longer shared.`, "success")
      } else {
        throw new Error("Failed to unshare file")
      }
    } catch {
      showAlert("Unshare Failed", "Failed to unshare file.", "error")
    }
  }

  const handleFileDelete = async (fileId: string) => {
    try {
      const response = await fetch(`/api/files/${fileId}?userId=${user.id}`, {
        method: "DELETE",
      })

      if (response.ok) {
        await loadFiles()
        onDeleteClose()
        showAlert("File Deleted", "File has been permanently deleted.", "success")
      } else {
        throw new Error("Delete failed")
      }
    } catch {
      showAlert("Delete Failed", "Failed to delete file.", "error")
    }
  }

  const copyToClipboard = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text)
      showAlert("Copied!", `${label} copied to clipboard.`, "success")
    } catch {
      showAlert("Copy Failed", `Failed to copy ${label}.`, "error")
    }
  }

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) {
      return "0 Bytes"
    }
    const k = 1024
    const sizes = ["Bytes", "KB", "MB", "GB"]
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${Number.parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    })
  }

  return (
    <div className="bg-background min-h-screen">
      <div className="bg-content1 border-divider border-b">
        <div className="mx-auto px-4 sm:px-6 lg:px-8 max-w-7xl">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-3">
              <Shield className="w-6 h-6 text-primary" />
              <h1 className="font-semibold text-xl">Eduardo's Vault</h1>
            </div>

            <div className="flex items-center space-x-3">
              <Chip variant="flat" color="primary" size="sm">
                {user.username}
              </Chip>

              <Dropdown>
                <DropdownTrigger>
                  <Button isIconOnly variant="ghost">
                    <MoreVertical className="w-4 h-4" />
                  </Button>
                </DropdownTrigger>
                <DropdownMenu>
                  <DropdownItem key="share-key" startContent={<Copy className="w-4 h-4" />} onPress={() => setShowShareKey(!showShareKey)}>
                    {showShareKey ? "Hide Share Key" : "Show Share Key"}
                  </DropdownItem>
                  <DropdownItem key="copy-share-key" startContent={<Share className="w-4 h-4" />} onPress={() => copyToClipboard(user.shareKey, "Share key")}>
                    Copy Share Key
                  </DropdownItem>
                </DropdownMenu>
              </Dropdown>

              <Button isIconOnly variant="ghost" onPress={() => setTheme(theme === "dark" ? "light" : "dark")}>
                {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
              </Button>

              <Button variant="ghost" onPress={handleLogout} startContent={<LogOut className="w-4 h-4" />}>
                Logout
              </Button>
            </div>
          </div>
        </div>
      </div>

      <div className="mx-auto px-4 sm:px-6 lg:px-8 py-8 max-w-7xl">
        {showShareKey && (
          <Card className="mb-6">
            <CardHeader>
              <h2 className="font-semibold text-lg">Your Share Key</h2>
            </CardHeader>
            <CardBody>
              <div className="flex items-center space-x-2">
                <code className="flex-1 bg-default-100 p-2 rounded text-sm break-all">{user.shareKey}</code>
                <Button size="sm" onPress={() => copyToClipboard(user.shareKey, "Share key")} startContent={<Copy className="w-4 h-4" />}>
                  Copy
                </Button>
              </div>
              <p className="mt-2 text-default-600 text-sm">Share this key with others to allow them to decrypt files you share with them.</p>
            </CardBody>
          </Card>
        )}

        <Card className="mb-6">
          <CardHeader>
            <h2 className="font-semibold text-lg">Upload Files</h2>
          </CardHeader>
          <CardBody>
            <div className="flex items-center space-x-4">
              <input ref={fileInputRef} type="file" onChange={handleFileUpload} className="hidden" disabled={isUploading} />

              <Button color="primary" onPress={() => fileInputRef.current?.click()} isDisabled={isUploading} startContent={<Upload className="w-4 h-4" />}>
                Choose File
              </Button>

              {isUploading && (
                <div className="flex-1 max-w-xs">
                  <Progress value={uploadProgress} color="primary" size="sm" showValueLabel />
                </div>
              )}
            </div>

            <p className="mt-2 text-default-600 text-sm">🔒 Files are end-to-end encrypted</p>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <h2 className="font-semibold text-lg">Your Files ({files.length})</h2>
          </CardHeader>
          <CardBody>
            {isLoading ? (
              <div className="py-8 text-center">
                <Spinner size="lg" />
              </div>
            ) : files.length === 0 ? (
              <div className="py-8 text-default-500 text-center">No files uploaded yet</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-divider border-b">
                      <th className="px-4 py-3 font-medium text-left">NAME</th>
                      <th className="px-4 py-3 font-medium text-left">SIZE</th>
                      <th className="px-4 py-3 font-medium text-left">UPLOADED</th>
                      <th className="px-4 py-3 font-medium text-left">STATUS</th>
                      <th className="px-4 py-3 font-medium text-right">ACTIONS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {files.map((file) => (
                      <tr key={file.id} className="border-divider border-b">
                        <td className="px-4 py-3">
                          <div className="flex items-center space-x-2">
                            <FileIcon className="w-4 h-4 text-default-400" />
                            <span className="font-medium">{file.decryptedName}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3">{formatFileSize(file.originalSize)}</td>
                        <td className="px-4 py-3">{formatDate(file.uploadedAt)}</td>
                        <td className="px-4 py-3">
                          {file.isShared ? (
                            <Chip size="sm" color="success" variant="flat">
                              Shared
                            </Chip>
                          ) : (
                            <Chip size="sm" color="default" variant="flat">
                              Private
                            </Chip>
                          )}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <div className="flex justify-end space-x-2">
                            <Button isIconOnly size="sm" variant="light" onPress={() => handleFileDownload(file)} aria-label="Download">
                              <Download className="w-4 h-4" />
                            </Button>
                            {file.isShared ? (
                              <Dropdown>
                                <DropdownTrigger>
                                  <Button isIconOnly size="sm" variant="light" color="success" aria-label="Share options">
                                    <Share className="w-4 h-4" />
                                  </Button>
                                </DropdownTrigger>
                                <DropdownMenu>
                                  <DropdownItem key="view-share" startContent={<Share className="w-4 h-4" />} onPress={() => handleFileShare(file)}>
                                    View Share Link
                                  </DropdownItem>
                                  <DropdownItem key="unshare" startContent={<ShareOff className="w-4 h-4" />} className="text-danger" color="danger" onPress={() => handleUnshare(file)}>
                                    Unshare File
                                  </DropdownItem>
                                </DropdownMenu>
                              </Dropdown>
                            ) : (
                              <Button isIconOnly size="sm" variant="light" color="secondary" onPress={() => handleFileShare(file)} aria-label="Share">
                                <Share className="w-4 h-4" />
                              </Button>
                            )}
                            <Button
                              isIconOnly
                              size="sm"
                              variant="light"
                              color="danger"
                              onPress={() => {
                                setSelectedFile(file)
                                onDeleteOpen()
                              }}
                              aria-label="Delete"
                            >
                              <Trash2 className="w-4 h-4" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardBody>
        </Card>
      </div>

      <Modal isOpen={isDeleteOpen} onClose={onDeleteClose}>
        <ModalContent>
          <ModalHeader>Delete File</ModalHeader>
          <ModalBody>
            <p>
              Are you sure you want to delete <strong>"{selectedFile?.decryptedName}"</strong>?
            </p>
            <p className="text-default-600 text-sm">This action cannot be undone and will also remove any shared links.</p>
          </ModalBody>
          <ModalFooter>
            <Button variant="ghost" onPress={onDeleteClose}>
              Cancel
            </Button>
            <Button color="danger" onPress={() => selectedFile && handleFileDelete(selectedFile.id)}>
              Delete
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      <ShareConfirmationModal isOpen={isShareConfirmOpen} onClose={onShareConfirmClose} onConfirm={handleShareConfirm} fileName={selectedFile?.decryptedName || ""} userShareKey={user.shareKey} />

      <Modal isOpen={isShareOpen} onClose={onShareClose}>
        <ModalContent>
          <ModalHeader>Share "{selectedFile?.decryptedName}"</ModalHeader>
          <ModalBody>
            <p className="mb-4">
              {shareInfo && shareInfo.id === "new"
                ? "Your file has been shared! Send both the link and your share key to the recipient."
                : "This file is already shared. You can copy the existing share link below."}
            </p>

            <div className="space-y-4">
              <div>
                <label className="font-medium text-sm">Share Link:</label>
                <div className="flex items-center space-x-2 mt-1">
                  <Input value={shareUrl} readOnly size="sm" startContent={<Link className="w-4 h-4" />} />
                  <Button size="sm" onPress={() => copyToClipboard(shareUrl, "Share link")}>
                    Copy
                  </Button>
                </div>
              </div>

              <div>
                <label className="font-medium text-sm">Your Share Key:</label>
                <div className="flex items-center space-x-2 mt-1">
                  <Input value={user.shareKey} readOnly size="sm" startContent={<Shield className="w-4 h-4" />} />
                  <Button size="sm" onPress={() => copyToClipboard(user.shareKey, "Share key")}>
                    Copy
                  </Button>
                </div>
              </div>
            </div>

            <div className="bg-warning/10 mt-4 p-3 border border-warning/20 rounded-lg">
              <p className="text-warning text-sm">⚠️ Both the link AND your share key are required to decrypt the file. Make sure to send both to the recipient through secure channels.</p>
            </div>

            {shareInfo && (
              <div className="mt-4">
                <p className="mb-2 font-medium text-sm">Share Details:</p>
                <div className="text-default-600 text-xs">
                  <p>
                    Created:
                    {formatDate(shareInfo.createdAt)}
                  </p>
                  <p>
                    Expires:
                    {shareInfo.expiresAt ? formatDate(shareInfo.expiresAt) : "Never"}
                  </p>
                </div>
              </div>
            )}
          </ModalBody>
          <ModalFooter>
            <Button color="primary" onPress={onShareClose}>
              Done
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      <AlertModal isOpen={isAlertOpen} onClose={onAlertClose} title={alertConfig.title} message={alertConfig.message} type={alertConfig.type} />
    </div>
  )
}
