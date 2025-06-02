"use client"

import { useState, useEffect } from "react"
import { useParams } from "next/navigation"
import {
  Card,
  CardBody,
  CardHeader,
  Button,
  Spinner,
  Input,
  useDisclosure,
} from "@heroui/react"
import { Download, Shield, FileIcon, Key, AlertTriangle } from "lucide-react"
import { AdvancedCryptoManager } from "@/lib/advanced-crypto"
import AlertModal from "@/components/alert-modal"

interface SharedFileData {
  file: {
    id: string
    encryptedName: string
    nameIv: string
    nameSalt: string
    originalSize: number
    encryptedData: string
    iv: string
    salt: string
    uploadedAt: string
  }
  expiresAt: string | null
}

export default function SharePage() {
  const params = useParams()
  const token = params.token as string

  const [fileData, setFileData] = useState<SharedFileData | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState("")
  const [shareKey, setShareKey] = useState("")
  const [decryptedName, setDecryptedName] = useState("")
  const [isDecrypting, setIsDecrypting] = useState(false)

  const {
    isOpen: isAlertOpen,
    onOpen: onAlertOpen,
    onClose: onAlertClose,
  } = useDisclosure()
  const [alertConfig, setAlertConfig] = useState({
    title: "",
    message: "",
    type: "info" as "success" | "error" | "warning" | "info",
  })

  useEffect(() => {
    loadSharedFile()
  }, [token])

  const showAlert = (
    title: string,
    message: string,
    type: "success" | "error" | "warning" | "info" = "info",
  ) => {
    setAlertConfig({ title, message, type })
    onAlertOpen()
  }

  const loadSharedFile = async () => {
    try {
      const response = await fetch(`/api/share/${token}`)
      const data = await response.json()

      if (response.ok) {
        setFileData(data)
      } else {
        setError(data.error || "Failed to load shared file")
      }
    } catch (error) {
      setError("Failed to load shared file")
      console.error("Share load error:", error)
    } finally {
      setIsLoading(false)
    }
  }

  const decryptFileName = async () => {
    if (!fileData || !shareKey.trim()) {
      showAlert(
        "Missing Share Key",
        "Please enter the share key to decrypt the filename.",
        "warning",
      )
      return
    }

    try {
      setIsDecrypting(true)

      const nameSalt = Uint8Array.from(atob(fileData.file.nameSalt), (c) =>
        c.charCodeAt(0),
      )
      const nameIv = Uint8Array.from(atob(fileData.file.nameIv), (c) =>
        c.charCodeAt(0),
      )

      const nameKey = await AdvancedCryptoManager.deriveFileKeyFromShareKey(
        shareKey.trim(),
        nameSalt,
      )
      const name = await AdvancedCryptoManager.decryptFilename(
        fileData.file.encryptedName,
        nameKey,
        nameIv,
      )

      setDecryptedName(name)
      showAlert("Success", "Filename decrypted successfully!", "success")
    } catch (error) {
      console.error("Filename decryption error:", error)
      showAlert(
        "Decryption Failed",
        "Invalid share key or corrupted filename data.",
        "error",
      )
    } finally {
      setIsDecrypting(false)
    }
  }

  const downloadFile = async () => {
    if (!fileData || !shareKey.trim()) {
      showAlert(
        "Missing Share Key",
        "Please enter the share key to download the file.",
        "warning",
      )
      return
    }

    try {
      setIsDecrypting(true)

      const encryptedData = Uint8Array.from(
        atob(fileData.file.encryptedData),
        (c) => c.charCodeAt(0),
      )
      const iv = Uint8Array.from(atob(fileData.file.iv), (c) => c.charCodeAt(0))
      const salt = Uint8Array.from(atob(fileData.file.salt), (c) =>
        c.charCodeAt(0),
      )

      const fileKey = await AdvancedCryptoManager.deriveFileKeyFromShareKey(
        shareKey.trim(),
        salt,
      )

      const decryptedData = await AdvancedCryptoManager.decryptFileAdvanced(
        encryptedData.buffer,
        fileKey,
        iv,
      )

      let fileName = decryptedName
      if (!fileName) {
        try {
          const nameSalt = Uint8Array.from(atob(fileData.file.nameSalt), (c) =>
            c.charCodeAt(0),
          )
          const nameIv = Uint8Array.from(atob(fileData.file.nameIv), (c) =>
            c.charCodeAt(0),
          )
          const nameKey = await AdvancedCryptoManager.deriveFileKeyFromShareKey(
            shareKey.trim(),
            nameSalt,
          )
          fileName = await AdvancedCryptoManager.decryptFilename(
            fileData.file.encryptedName,
            nameKey,
            nameIv,
          )
          setDecryptedName(fileName)
        } catch {
          fileName = "shared-file"
        }
      }

      const blob = new Blob([decryptedData])
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = fileName
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      showAlert(
        "Download Complete",
        `Successfully downloaded "${fileName}"`,
        "success",
      )
    } catch (error) {
      console.error("Download error:", error)
      showAlert(
        "Download Failed",
        "Invalid share key or corrupted file data.",
        "error",
      )
    } finally {
      setIsDecrypting(false)
    }
  }

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return "0 Bytes"
    const k = 1024
    const sizes = ["Bytes", "KB", "MB", "GB"]
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return (
      Number.parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i]
    )
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

  const formatExpiryDate = () => {
    if (!fileData?.expiresAt) return "Never"
    return formatDate(fileData.expiresAt)
  }

  if (isLoading) {
    return (
      <div className="flex justify-center items-center bg-background min-h-screen">
        <Spinner size="lg" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex justify-center items-center bg-background p-4 min-h-screen">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <h1 className="font-bold text-danger text-2xl">Share Not Found</h1>
          </CardHeader>
          <CardBody className="text-center">
            <p className="text-default-600">{error}</p>
          </CardBody>
        </Card>
      </div>
    )
  }

  return (
    <div className="bg-background p-4 min-h-screen">
      <div className="mx-auto max-w-2xl">
        <Card>
          <CardHeader className="text-center">
            <div className="flex justify-center mb-4">
              <div className="bg-primary/10 p-3 rounded-full">
                <Shield className="w-8 h-8 text-primary" />
              </div>
            </div>
            <h1 className="font-bold text-2xl">Shared File</h1>
            {fileData?.expiresAt && (
              <p className="text-default-500 text-sm">
                Expires: {formatExpiryDate()}
              </p>
            )}
          </CardHeader>

          <CardBody className="space-y-6">
            <div className="bg-default-50 dark:bg-default-100 p-4 rounded-lg">
              <div className="flex items-center space-x-3 mb-3">
                <FileIcon className="w-6 h-6 text-default-400" />
                <div>
                  <p className="font-medium">
                    {decryptedName || "[Enter share key to decrypt filename]"}
                  </p>
                  <p className="text-default-600 text-sm">
                    {formatFileSize(fileData?.file.originalSize || 0)} •
                    Uploaded {formatDate(fileData?.file.uploadedAt || "")}
                  </p>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block mb-2 font-medium text-sm">
                  Share Key
                </label>
                <Input
                  placeholder="Enter the share key provided by the sender"
                  value={shareKey}
                  onChange={(e) => setShareKey(e.target.value)}
                  startContent={<Key className="w-4 h-4 text-default-400" />}
                  type="password"
                />
              </div>

              <div className="flex gap-3">
                <Button
                  color="secondary"
                  variant="flat"
                  onPress={decryptFileName}
                  isLoading={isDecrypting}
                  isDisabled={!shareKey.trim()}
                  className="flex-1"
                >
                  Decrypt Filename
                </Button>
                <Button
                  color="primary"
                  onPress={downloadFile}
                  isLoading={isDecrypting}
                  isDisabled={!shareKey.trim()}
                  startContent={
                    !isDecrypting && <Download className="w-4 h-4" />
                  }
                  className="flex-1"
                >
                  {isDecrypting ? "Decrypting..." : "Download File"}
                </Button>
              </div>
            </div>

            <div className="bg-warning/10 p-3 border border-warning/20 rounded-lg">
              <div className="flex items-start space-x-2">
                <AlertTriangle className="mt-0.5 w-5 h-5 text-warning" />
                <div>
                  <p className="font-medium text-warning text-sm">
                    Security Notice
                  </p>
                  <p className="mt-1 text-warning text-xs">
                    This file is encrypted end-to-end. You need the correct
                    share key to decrypt it. Never share your keys with
                    untrusted parties.
                  </p>
                </div>
              </div>
            </div>
          </CardBody>
        </Card>
      </div>

      <AlertModal
        isOpen={isAlertOpen}
        onClose={onAlertClose}
        title={alertConfig.title}
        message={alertConfig.message}
        type={alertConfig.type}
      />
    </div>
  )
}
