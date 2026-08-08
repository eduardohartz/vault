"use client"

import type React from "react"
import type { AuthenticatedUser } from "@/components/auth-page"
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
import { Copy, Download, FileIcon, FileLock2, Link as LinkIcon, LogOut, Moon, MoreVertical, Share, ShareIcon as ShareOff, Shield, Sun, Trash2, Upload } from "lucide-react"
import { useTheme } from "next-themes"
import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react"
import AlertModal from "@/components/alert-modal"
import ShareConfirmationModal from "@/components/share-confirmation-modal"
import { BufferHelper } from "@/lib/buffer-helper"
import { CryptoManager } from "@/lib/crypto-manager"
import { endSession } from "@/lib/session-client"

type FileManagerProps = {
  user: AuthenticatedUser
  onLogout: () => void
}

type ShareSummary = {
  shareToken: string
  expiresAt: string | null
  createdAt: string
}

type FileItem = {
  id: string
  encryptedName: string
  originalSize: number
  iv: string
  nameIv: string
  uploadedAt: string
  isShared: boolean
  share: ShareSummary | null
  decryptedName?: string
}

const toBytes = (base64: string) => Uint8Array.from(atob(base64), (c) => c.charCodeAt(0))

export default function FileManager({ user, onLogout }: FileManagerProps) {
  const [files, setFiles] = useState<FileItem[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [isUploading, setIsUploading] = useState(false)
  const [selectedFile, setSelectedFile] = useState<FileItem | null>(null)
  const [shareUrl, setShareUrl] = useState("")
  const [newShareKey, setNewShareKey] = useState<string | null>(null)
  const [pendingShareKey, setPendingShareKey] = useState<string>("")
  const fileInputRef = useRef<HTMLInputElement>(null)
  const { theme, setTheme } = useTheme()
  const shareLinkId = useId()
  const shareKeyId = useId()

  const { isOpen: isDeleteOpen, onOpen: onDeleteOpen, onClose: onDeleteClose } = useDisclosure()
  const { isOpen: isDeleteAccountOpen, onOpen: onDeleteAccountOpen, onClose: onDeleteAccountClose } = useDisclosure()
  const { isOpen: isShareOpen, onOpen: onShareOpen, onClose: onShareClose } = useDisclosure()
  const { isOpen: isShareConfirmOpen, onOpen: onShareConfirmOpen, onClose: onShareConfirmClose } = useDisclosure()
  const { isOpen: isAlertOpen, onOpen: onAlertOpen, onClose: onAlertClose } = useDisclosure()
  const [alertConfig, setAlertConfig] = useState({
    title: "",
    message: "",
    type: "info" as "success" | "error" | "warning" | "info",
  })

  const showAlert = useCallback(
    (title: string, message: string, type: "success" | "error" | "warning" | "info" = "info") => {
      setAlertConfig({ title, message, type })
      onAlertOpen()
    },
    [onAlertOpen],
  )

  // Derive the vault key once. It was previously re-derived for every file on
  // every render path, which is pure ECDH work repeated for no benefit.
  const vaultKeyPromise = useMemo(
    () => CryptoManager.deriveECDHKey(user.privateKey, user.publicKey),
    [user.privateKey, user.publicKey],
  )

  /**
   * Any request may come back 401 if the server session expired on its own TTL
   * or was revoked from another tab. Lock immediately rather than leaving an
   * unlocked-looking vault whose every action silently fails — the keys in
   * memory are useless without a session, but the decrypted filenames on screen
   * are not nothing.
   */
  const apiFetch = useCallback(async (input: string, init?: RequestInit): Promise<Response> => {
    const response = await fetch(input, init)

    if (response.status === 401) {
      onLogout()
      throw new Error("Your session has expired. Please sign in again.")
    }

    return response
  }, [onLogout])

  const loadFiles = useCallback(async () => {
    setLoadError(null)

    try {
      const response = await apiFetch("/api/files")
      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error ?? "Failed to load files")
      }

      const key = await vaultKeyPromise

      const decrypted = await Promise.all(
        (data.files as FileItem[]).map(async (file) => {
          try {
            return {
              ...file,
              decryptedName: await CryptoManager.decryptFilename(file.encryptedName, key, toBytes(file.nameIv)),
            }
          } catch {
            return { ...file, decryptedName: "[Decryption failed]" }
          }
        }),
      )

      setFiles(decrypted)
    } catch (error) {
      // Previously an empty catch block: a failed load rendered an empty vault,
      // indistinguishable from actually having no files.
      console.error("Failed to load files:", error)
      setLoadError(error instanceof Error ? error.message : "Failed to load files")
    } finally {
      setIsLoading(false)
    }
  }, [vaultKeyPromise, apiFetch])

  useEffect(() => {
    void loadFiles()
  }, [loadFiles])

  const handleLogout = useCallback(async () => {
    // Shared with SessionGuard, so a manual logout and an automatic one revoke
    // the session identically and neither fires twice.
    await endSession()
    sessionStorage.clear()
    onLogout()
  }, [onLogout])

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) {
      return
    }

    setIsUploading(true)
    setUploadProgress(0)

    try {
      const key = await vaultKeyPromise
      setUploadProgress(20)

      const { encryptedData, iv } = await CryptoManager.encryptFile(file, key)
      setUploadProgress(55)

      const { encryptedName, iv: nameIv } = await CryptoManager.encryptFilename(file.name, key)
      setUploadProgress(80)

      const formData = new FormData()
      formData.append("encryptedData", BufferHelper.bytesToBase64(new Uint8Array(encryptedData)))
      formData.append("iv", BufferHelper.bytesToBase64(iv))
      formData.append("encryptedName", encryptedName)
      formData.append("nameIv", BufferHelper.bytesToBase64(nameIv))
      formData.append("originalSize", file.size.toString())

      const response = await apiFetch("/api/files", { method: "POST", body: formData })
      const data = await response.json()
      setUploadProgress(100)

      if (!response.ok) {
        throw new Error(data.error ?? "Upload failed")
      }

      await loadFiles()
      showAlert("Upload Successful", `"${file.name}" has been encrypted and uploaded.`, "success")
    } catch (error) {
      console.error("File upload error:", error)
      showAlert("Upload Failed", error instanceof Error ? error.message : "Failed to upload file.", "error")
    } finally {
      setIsUploading(false)
      setUploadProgress(0)
      if (fileInputRef.current) {
        fileInputRef.current.value = ""
      }
    }
  }

  const fetchAndDecrypt = useCallback(
    async (file: FileItem): Promise<ArrayBuffer> => {
      const response = await apiFetch(`/api/files/${file.id}`)
      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error ?? "Failed to fetch file")
      }

      const key = await vaultKeyPromise
      return CryptoManager.decryptFile(toBytes(data.file.encryptedData).buffer as ArrayBuffer, key, toBytes(data.file.iv))
    },
    [vaultKeyPromise, apiFetch],
  )

  const triggerDownload = (data: BlobPart, name: string) => {
    const url = URL.createObjectURL(new Blob([data]))
    const anchor = document.createElement("a")
    anchor.href = url
    anchor.download = name
    document.body.appendChild(anchor)
    anchor.click()
    document.body.removeChild(anchor)
    URL.revokeObjectURL(url)
  }

  const handleFileDownload = async (file: FileItem) => {
    try {
      triggerDownload(await fetchAndDecrypt(file), file.decryptedName || "download")
      showAlert("Download Complete", `"${file.decryptedName}" has been downloaded.`, "success")
    } catch (error) {
      console.error("Download failed:", error)
      showAlert("Download Failed", error instanceof Error ? error.message : "Failed to decrypt and download file.", "error")
    }
  }

  const handleFileShare = (file: FileItem) => {
    setSelectedFile(file)

    if (file.isShared && file.share) {
      // The per-share key is generated in the browser and never stored, so an
      // existing share can show its link but not its key.
      setShareUrl(`${window.location.origin}/share/${file.share.shareToken}`)
      setNewShareKey(null)
      onShareOpen()
      return
    }

    // A fresh random key per share, generated as the modal opens. Every share
    // used to reuse one key derived from the user's master key, so handing it to
    // one recipient exposed every file they had ever shared or would share.
    setPendingShareKey(CryptoManager.generateShareKey())
    onShareConfirmOpen()
  }

  const handleShareConfirm = async (expiryMinutes: number | null) => {
    const shareKey = pendingShareKey
    if (!selectedFile) {
      return
    }

    try {
      const plaintext = await fetchAndDecrypt(selectedFile)

      const salt = crypto.getRandomValues(new Uint8Array(16))
      const nameSalt = crypto.getRandomValues(new Uint8Array(16))
      const fileKey = await CryptoManager.deriveShareKey(shareKey, salt)
      const nameKey = await CryptoManager.deriveShareKey(shareKey, nameSalt)

      const { encryptedData, iv } = await CryptoManager.encryptFile(plaintext, fileKey)
      const { encryptedName, iv: nameIv } = await CryptoManager.encryptFilename(selectedFile.decryptedName || "shared-file", nameKey)

      const formData = new FormData()
      formData.append("encryptedData", BufferHelper.bytesToBase64(new Uint8Array(encryptedData)))
      formData.append("iv", BufferHelper.bytesToBase64(iv))
      formData.append("salt", BufferHelper.bytesToBase64(salt))
      formData.append("encryptedName", encryptedName)
      formData.append("nameIv", BufferHelper.bytesToBase64(nameIv))
      formData.append("nameSalt", BufferHelper.bytesToBase64(nameSalt))
      formData.append("originalSize", plaintext.byteLength.toString())
      if (expiryMinutes) {
        formData.append("expiresAt", new Date(Date.now() + expiryMinutes * 60 * 1000).toISOString())
      }

      const response = await apiFetch(`/api/files/${selectedFile.id}/share`, { method: "POST", body: formData })
      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error ?? "Failed to create share")
      }

      setShareUrl(data.shareUrl)
      setNewShareKey(shareKey)
      onShareOpen()
      await loadFiles()
    } catch (error) {
      console.error("Share creation error:", error)
      showAlert("Share Failed", error instanceof Error ? error.message : "Failed to create share link.", "error")
    }
  }

  const handleUnshare = async (file: FileItem) => {
    try {
      const response = await apiFetch(`/api/files/${file.id}/share`, { method: "DELETE" })

      if (!response.ok) {
        throw new Error((await response.json()).error ?? "Failed to unshare file")
      }

      await loadFiles()
      showAlert("Unshared", `"${file.decryptedName}" is no longer shared.`, "success")
    } catch (error) {
      console.error("Unshare failed:", error)
      showAlert("Unshare Failed", error instanceof Error ? error.message : "Failed to unshare file.", "error")
    }
  }

  const handleFileDelete = async (fileId: string) => {
    try {
      const response = await apiFetch(`/api/files/${fileId}`, { method: "DELETE" })

      if (!response.ok) {
        throw new Error((await response.json()).error ?? "Delete failed")
      }

      await loadFiles()
      onDeleteClose()
      showAlert("File Deleted", "File has been permanently deleted.", "success")
    } catch (error) {
      console.error("Delete failed:", error)
      showAlert("Delete Failed", error instanceof Error ? error.message : "Failed to delete file.", "error")
    }
  }

  const handleAccountDelete = async () => {
    onDeleteAccountClose()
    try {
      const response = await apiFetch("/api/auth/delete", { method: "DELETE" })

      if (!response.ok) {
        throw new Error((await response.json()).error ?? "Failed to delete account")
      }

      await handleLogout()
    } catch (error) {
      console.error("Account deletion failed:", error)
      showAlert("Delete Failed", error instanceof Error ? error.message : "Failed to delete account.", "error")
    }
  }

  const copyToClipboard = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text)
      showAlert("Copied", `${label} copied to clipboard.`, "success")
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
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1)
    return `${Number.parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`
  }

  const formatDate = (value: string | null) => {
    if (!value) {
      return "Never"
    }
    const date = new Date(value)
    return Number.isNaN(date.getTime())
      ? "Unknown"
      : date.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
  }

  const isExpired = (share: ShareSummary | null) => Boolean(share?.expiresAt && new Date(share.expiresAt).getTime() <= Date.now())

  return (
    <div className="bg-background min-h-screen">
      <header className="bg-content1 border-divider border-b">
        <div className="mx-auto px-4 sm:px-6 lg:px-8 max-w-7xl">
          <div className="flex flex-wrap justify-between items-center gap-2 py-3">
            <div className="flex items-center space-x-3">
              <Shield aria-hidden="true" className="w-6 h-6 text-primary" />
              <h1 className="font-semibold text-lg sm:text-xl">Vault</h1>
            </div>

            <div className="flex items-center gap-2">
              <Chip variant="flat" color="primary" size="sm">
                {user.username}
              </Chip>

              <Button
                isIconOnly
                variant="ghost"
                className="min-w-11 min-h-11"
                aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
                onPress={() => setTheme(theme === "dark" ? "light" : "dark")}
              >
                {theme === "dark" ? <Sun aria-hidden="true" className="w-4 h-4" /> : <Moon aria-hidden="true" className="w-4 h-4" />}
              </Button>

              <Button variant="ghost" className="hidden sm:flex min-h-11" onPress={handleLogout} startContent={<LogOut aria-hidden="true" className="w-4 h-4" />}>
                Logout
              </Button>

              <Dropdown>
                <DropdownTrigger>
                  <Button isIconOnly variant="ghost" className="min-w-11 min-h-11" aria-label="Account menu">
                    <MoreVertical aria-hidden="true" className="w-4 h-4" />
                  </Button>
                </DropdownTrigger>
                <DropdownMenu aria-label="Account actions">
                  <DropdownItem key="logout" className="sm:hidden" startContent={<LogOut aria-hidden="true" className="w-4 h-4" />} onPress={handleLogout}>
                    Logout
                  </DropdownItem>
                  <DropdownItem
                    key="delete-account"
                    startContent={<Trash2 aria-hidden="true" className="w-4 h-4" />}
                    onPress={onDeleteAccountOpen}
                    color="danger"
                    className="text-danger"
                  >
                    Delete Account
                  </DropdownItem>
                </DropdownMenu>
              </Dropdown>
            </div>
          </div>
        </div>
      </header>

      <main className="mx-auto px-4 sm:px-6 lg:px-8 py-8 max-w-7xl">
        <Card className="mb-6 p-1">
          <CardHeader className="flex sm:flex-row flex-col justify-between items-start sm:items-center gap-4">
            <div className="flex flex-col items-start">
              <h2 className="font-semibold text-lg">Upload Files</h2>
              <div className="flex items-center space-x-1 mt-1">
                <FileLock2 aria-hidden="true" className="w-4 h-4" />
                <p className="text-default-600 text-sm">Files are end-to-end encrypted</p>
              </div>
            </div>

            <div className="flex sm:flex-row flex-col items-stretch sm:items-center gap-3 w-full sm:w-auto">
              <input ref={fileInputRef} type="file" onChange={handleFileUpload} className="hidden" disabled={isUploading} aria-label="Choose a file to upload" />

              {isUploading && (
                <div className="w-full sm:w-72">
                  <Progress value={uploadProgress} color="primary" size="sm" showValueLabel aria-label="Upload progress" />
                </div>
              )}

              <Button
                color="primary"
                className="w-full sm:w-auto min-h-11"
                onPress={() => fileInputRef.current?.click()}
                isDisabled={isUploading}
                startContent={<Upload aria-hidden="true" className="w-4 h-4" />}
              >
                Choose File
              </Button>
            </div>
          </CardHeader>
        </Card>

        <Card>
          <CardHeader className="flex flex-wrap justify-between items-center gap-2 px-5 border-divider border-b">
            <h2 className="font-semibold text-md">
              Vault Files (
              {files.length}
              )
            </h2>
            <p className="text-md">{formatFileSize(files.reduce((sum, file) => sum + file.originalSize, 0))}</p>
          </CardHeader>
          <CardBody className="bg-foreground-100/50 m-3 sm:m-5 pt-0 rounded-lg">
            {isLoading ? (
              <div className="py-8 text-center">
                <Spinner size="lg" label="Loading your files" />
              </div>
            ) : loadError ? (
              <div className="py-8 text-center">
                <p className="mb-3 text-danger">{loadError}</p>
                <Button
                  className="min-h-11"
                  onPress={() => {
                    setIsLoading(true)
                    void loadFiles()
                  }}
                >
                  Try again
                </Button>
              </div>
            ) : files.length === 0 ? (
              <div className="py-8 text-default-500 text-center">No files uploaded yet</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px]">
                  <caption className="sr-only">Your encrypted files</caption>
                  <thead>
                    <tr className="border-divider border-b">
                      <th scope="col" className="px-4 py-3 font-medium text-left">Name</th>
                      <th scope="col" className="px-4 py-3 font-medium text-left">Size</th>
                      <th scope="col" className="px-4 py-3 font-medium text-left">Uploaded</th>
                      <th scope="col" className="px-4 py-3 font-medium text-left">Status</th>
                      <th scope="col" className="px-4 py-3 font-medium text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {files.map((file) => (
                      <tr key={file.id} className="border-divider border-b">
                        <td className="px-4 py-3">
                          <div className="flex items-center space-x-2">
                            <FileIcon aria-hidden="true" className="w-4 h-4 text-default-400" />
                            <span className="font-medium">{file.decryptedName}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3">{formatFileSize(file.originalSize)}</td>
                        <td className="px-4 py-3">{formatDate(file.uploadedAt)}</td>
                        <td className="px-4 py-3">
                          {file.isShared ? (
                            <Chip size="sm" color={isExpired(file.share) ? "warning" : "success"} variant="flat">
                              {isExpired(file.share) ? "Shared (expired)" : "Shared"}
                            </Chip>
                          ) : (
                            <Chip size="sm" color="default" variant="flat">
                              Private
                            </Chip>
                          )}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <div className="flex justify-end gap-1">
                            <Button
                              isIconOnly
                              variant="light"
                              className="min-w-11 min-h-11"
                              onPress={() => handleFileDownload(file)}
                              aria-label={`Download ${file.decryptedName}`}
                            >
                              <Download aria-hidden="true" className="w-4 h-4" />
                            </Button>

                            {file.isShared ? (
                              <Dropdown>
                                <DropdownTrigger>
                                  <Button
                                    isIconOnly
                                    variant="light"
                                    color="success"
                                    className="min-w-11 min-h-11"
                                    aria-label={`Share options for ${file.decryptedName}`}
                                  >
                                    <Share aria-hidden="true" className="w-4 h-4" />
                                  </Button>
                                </DropdownTrigger>
                                <DropdownMenu aria-label={`Share actions for ${file.decryptedName}`}>
                                  <DropdownItem key="view-share" startContent={<Share aria-hidden="true" className="w-4 h-4" />} onPress={() => handleFileShare(file)}>
                                    View Share Link
                                  </DropdownItem>
                                  <DropdownItem
                                    key="unshare"
                                    startContent={<ShareOff aria-hidden="true" className="w-4 h-4" />}
                                    className="text-danger"
                                    color="danger"
                                    onPress={() => handleUnshare(file)}
                                  >
                                    Unshare File
                                  </DropdownItem>
                                </DropdownMenu>
                              </Dropdown>
                            ) : (
                              <Button
                                isIconOnly
                                variant="light"
                                className="min-w-11 min-h-11"
                                onPress={() => handleFileShare(file)}
                                aria-label={`Share ${file.decryptedName}`}
                              >
                                <Share aria-hidden="true" className="w-4 h-4" />
                              </Button>
                            )}

                            <Button
                              isIconOnly
                              variant="light"
                              color="danger"
                              className="min-w-11 min-h-11"
                              onPress={() => {
                                setSelectedFile(file)
                                onDeleteOpen()
                              }}
                              aria-label={`Delete ${file.decryptedName}`}
                            >
                              <Trash2 aria-hidden="true" className="w-4 h-4" />
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
      </main>

      <Modal isOpen={isDeleteOpen} onClose={onDeleteClose}>
        <ModalContent>
          <ModalHeader>Delete File</ModalHeader>
          <ModalBody>
            <p>
              Are you sure you want to delete
              {" "}
              <strong>{selectedFile?.decryptedName}</strong>
              ?
            </p>
            <p className="text-default-600 text-sm">This cannot be undone and will also remove any share link.</p>
          </ModalBody>
          <ModalFooter>
            <Button variant="ghost" className="min-h-11" onPress={onDeleteClose}>
              Cancel
            </Button>
            <Button color="danger" className="min-h-11" onPress={() => selectedFile && handleFileDelete(selectedFile.id)}>
              Delete
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      <ShareConfirmationModal
        isOpen={isShareConfirmOpen}
        onClose={onShareConfirmClose}
        onConfirm={handleShareConfirm}
        fileName={selectedFile?.decryptedName || ""}
        shareKey={pendingShareKey}
      />

      <Modal isOpen={isShareOpen} onClose={onShareClose} scrollBehavior="inside">
        <ModalContent>
          <ModalHeader>
            Share "
            {selectedFile?.decryptedName}
            "
          </ModalHeader>
          <ModalBody>
            <div className="space-y-4">
              <Input
                id={shareLinkId}
                label="Share link"
                value={shareUrl}
                readOnly
                size="sm"
                startContent={<LinkIcon aria-hidden="true" className="w-4 h-4" />}
                endContent={(
                  <Button isIconOnly size="sm" variant="light" aria-label="Copy share link" onPress={() => copyToClipboard(shareUrl, "Share link")}>
                    <Copy aria-hidden="true" className="w-4 h-4" />
                  </Button>
                )}
              />

              {newShareKey ? (
                <>
                  <Input
                    id={shareKeyId}
                    label="Share key"
                    value={newShareKey}
                    readOnly
                    size="sm"
                    className="font-mono"
                    startContent={<Shield aria-hidden="true" className="w-4 h-4" />}
                    endContent={(
                      <Button isIconOnly size="sm" variant="light" aria-label="Copy share key" onPress={() => copyToClipboard(newShareKey, "Share key")}>
                        <Copy aria-hidden="true" className="w-4 h-4" />
                      </Button>
                    )}
                  />
                  <div className="bg-warning/10 p-3 border border-warning/20 rounded-lg">
                    <p className="text-warning text-sm">
                      Copy this key now — it is never sent to the server and cannot be shown again. Send it to the recipient separately from the link; both are required to decrypt the file.
                    </p>
                  </div>
                </>
              ) : (
                <div className="bg-default-100 p-3 rounded-lg">
                  <p className="text-default-600 text-sm">
                    This file is already shared. Its share key was shown only when the link was created and is not stored anywhere. If you no longer have it, unshare the file and create a new link.
                  </p>
                </div>
              )}

              {selectedFile?.share && (
                <div className="text-default-600 text-xs">
                  <p>
                    Created:
                    {" "}
                    {formatDate(selectedFile.share.createdAt)}
                  </p>
                  <p>
                    Expires:
                    {" "}
                    {formatDate(selectedFile.share.expiresAt)}
                  </p>
                </div>
              )}
            </div>
          </ModalBody>
          <ModalFooter>
            <Button color="primary" className="min-h-11" onPress={onShareClose}>
              Done
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      <AlertModal isOpen={isAlertOpen} onClose={onAlertClose} title={alertConfig.title} message={alertConfig.message} type={alertConfig.type} />

      <Modal isOpen={isDeleteAccountOpen} onClose={onDeleteAccountClose} placement="center" backdrop="opaque">
        <ModalContent>
          <ModalHeader>Delete Account</ModalHeader>
          <ModalBody>
            <p>Are you sure you want to delete your account and all files? This cannot be undone.</p>
          </ModalBody>
          <ModalFooter>
            <Button color="primary" className="min-h-11" onPress={onDeleteAccountClose}>
              Cancel
            </Button>
            <Button color="danger" className="min-h-11" onPress={handleAccountDelete}>
              Confirm
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </div>
  )
}
