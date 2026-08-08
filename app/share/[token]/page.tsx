"use client"

import { Button, Card, CardBody, CardHeader, Input, Spinner, useDisclosure } from "@heroui/react"
import { AlertTriangle, Download, FileIcon, Key, Shield } from "lucide-react"
import { useParams } from "next/navigation"
import { useCallback, useEffect, useId, useState } from "react"
import AlertModal from "@/components/alert-modal"
import { CryptoManager } from "@/lib/crypto-manager"

type SharedFileData = {
  id: string
  salt: string
  expiresAt: string | null
  iv: string
  encryptedName: string
  nameIv: string
  nameSalt: string
  originalSize: number
  encryptedData: string
  createdAt: string
}

const toBytes = (base64: string) => Uint8Array.from(atob(base64), (c) => c.charCodeAt(0))

export default function SharePage() {
  const params = useParams()
  const token = params.token as string
  const shareKeyId = useId()

  const [fileData, setFileData] = useState<SharedFileData | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState("")
  const [shareKey, setShareKey] = useState("")
  const [decryptedName, setDecryptedName] = useState("")
  const [isDecrypting, setIsDecrypting] = useState(false)

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

  useEffect(() => {
    let cancelled = false

    const load = async () => {
      try {
        const response = await fetch(`/api/share/${token}`)
        const data = await response.json()

        if (cancelled) {
          return
        }

        if (response.ok) {
          setFileData(data)
        } else {
          setError(data.error || "Failed to load shared file")
        }
      } catch {
        if (!cancelled) {
          setError("Failed to load shared file")
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false)
        }
      }
    }

    void load()
    return () => {
      cancelled = true
    }
  }, [token])

  const decryptName = useCallback(
    async (data: SharedFileData, key: string) => {
      const nameKey = await CryptoManager.deriveShareKey(key, toBytes(data.nameSalt))
      return CryptoManager.decryptFilename(data.encryptedName, nameKey, toBytes(data.nameIv))
    },
    [],
  )

  const handleDecryptName = async () => {
    if (!fileData || !shareKey.trim()) {
      showAlert("Missing Share Key", "Please enter the share key to decrypt the filename.", "warning")
      return
    }

    setIsDecrypting(true)
    try {
      setDecryptedName(await decryptName(fileData, shareKey.trim()))
      showAlert("Success", "Filename decrypted successfully.", "success")
    } catch {
      showAlert("Decryption Failed", "Invalid share key, or the filename data is corrupted.", "error")
    } finally {
      setIsDecrypting(false)
    }
  }

  const handleDownload = async () => {
    if (!fileData || !shareKey.trim()) {
      showAlert("Missing Share Key", "Please enter the share key to download the file.", "warning")
      return
    }

    setIsDecrypting(true)
    try {
      const key = shareKey.trim()
      const fileKey = await CryptoManager.deriveShareKey(key, toBytes(fileData.salt))
      const decrypted = await CryptoManager.decryptFile(toBytes(fileData.encryptedData).buffer as ArrayBuffer, fileKey, toBytes(fileData.iv))

      let fileName = decryptedName
      if (!fileName) {
        try {
          fileName = await decryptName(fileData, key)
          setDecryptedName(fileName)
        } catch {
          fileName = "shared-file"
        }
      }

      const url = URL.createObjectURL(new Blob([decrypted]))
      const anchor = document.createElement("a")
      anchor.href = url
      anchor.download = fileName
      document.body.appendChild(anchor)
      anchor.click()
      document.body.removeChild(anchor)
      URL.revokeObjectURL(url)

      showAlert("Download Complete", `Successfully downloaded "${fileName}".`, "success")
    } catch {
      showAlert("Download Failed", "Invalid share key, or the file data is corrupted.", "error")
    } finally {
      setIsDecrypting(false)
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

  if (isLoading) {
    return (
      <div className="flex justify-center items-center bg-background min-h-screen">
        <Spinner size="lg" label="Loading shared file" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex justify-center items-center bg-background p-4 min-h-screen">
        <Card className="p-2 w-full max-w-md">
          <CardHeader className="border-divider border-b text-center">
            <h1 className="font-bold text-danger text-xl">Share Not Available</h1>
          </CardHeader>
          <CardBody className="text-center">
            <p className="py-3 text-default-600">{error}</p>
          </CardBody>
        </Card>
      </div>
    )
  }

  return (
    <div className="bg-background px-4 py-8 sm:py-10 min-h-screen">
      <div className="mx-auto max-w-2xl">
        <Card>
          <CardHeader className="flex flex-wrap justify-between items-center gap-2">
            <div className="flex items-center space-x-2">
              <div className="bg-primary/10 p-3 rounded-full">
                <Shield aria-hidden="true" className="w-8 h-8 text-primary" />
              </div>
              <h1 className="font-bold text-2xl">Shared File</h1>
            </div>
            {fileData?.expiresAt && (
              <p className="text-default-500 text-sm">
                Expires:
                {" "}
                {formatDate(fileData.expiresAt)}
              </p>
            )}
          </CardHeader>

          <CardBody className="space-y-6">
            <div className="bg-default-50 dark:bg-default-100 p-4 rounded-lg">
              <div className="flex items-center space-x-3">
                <FileIcon aria-hidden="true" className="w-6 h-6 text-default-400" />
                <div>
                  <p className="font-medium">{decryptedName || "[Enter share key to decrypt filename]"}</p>
                  <p className="text-default-600 text-sm">
                    {formatFileSize(fileData?.originalSize || 0)}
                    {" • Shared "}
                    {formatDate(fileData?.createdAt ?? null)}
                  </p>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <Input
                id={shareKeyId}
                label="Share key"
                placeholder="Enter the share key provided by the sender"
                value={shareKey}
                onValueChange={setShareKey}
                startContent={<Key aria-hidden="true" className="w-4 h-4 text-default-400" />}
                type="password"
                autoComplete="off"
              />

              <div className="flex sm:flex-row flex-col gap-3">
                <Button
                  color="secondary"
                  variant="flat"
                  onPress={handleDecryptName}
                  isLoading={isDecrypting}
                  isDisabled={!shareKey.trim()}
                  className="flex-1 min-h-11"
                >
                  Decrypt Filename
                </Button>
                <Button
                  color="primary"
                  onPress={handleDownload}
                  isLoading={isDecrypting}
                  isDisabled={!shareKey.trim()}
                  startContent={!isDecrypting && <Download aria-hidden="true" className="w-4 h-4" />}
                  className="flex-1 min-h-11"
                >
                  {isDecrypting ? "Decrypting…" : "Download File"}
                </Button>
              </div>
            </div>

            <div className="bg-warning/10 p-3 border border-warning/20 rounded-lg">
              <div className="flex items-start space-x-2">
                <AlertTriangle aria-hidden="true" className="mt-0.5 w-5 h-5 text-warning" />
                <div>
                  <p className="font-medium text-warning text-sm">Security Notice</p>
                  <p className="mt-1 text-warning text-xs">
                    This file is encrypted end to end and is decrypted in your browser. The share key is never sent to the server.
                  </p>
                </div>
              </div>
            </div>
          </CardBody>
        </Card>
      </div>

      <AlertModal isOpen={isAlertOpen} onClose={onAlertClose} title={alertConfig.title} message={alertConfig.message} type={alertConfig.type} />
    </div>
  )
}
