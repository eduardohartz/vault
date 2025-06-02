"use client"

import { useState, useEffect } from "react"
import {
  Modal,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalFooter,
  Button,
  RadioGroup,
  Radio,
  Input,
} from "@heroui/react"
import { Copy } from "lucide-react"

interface ShareConfirmationModalProps {
  isOpen: boolean
  onClose: () => void
  onConfirm: (expiryMinutes: number | null, shareKey: string) => void
  fileName: string
  userShareKey: string
}

export default function ShareConfirmationModal({
  isOpen,
  onClose,
  onConfirm,
  fileName,
  userShareKey,
}: ShareConfirmationModalProps) {
  const [expiry, setExpiry] = useState<string>("never")
  const [shareKey, setShareKey] = useState<string>(userShareKey)

  useEffect(() => {
    setShareKey(userShareKey)
  }, [userShareKey])

  const handleConfirm = () => {
    let expiryMinutes: number | null = null

    switch (expiry) {
      case "10min":
        expiryMinutes = 10
        break
      case "1hour":
        expiryMinutes = 60
        break
      case "1day":
        expiryMinutes = 60 * 24
        break
      case "30days":
        expiryMinutes = 60 * 24 * 30
        break
      case "1year":
        expiryMinutes = 60 * 24 * 365
        break
      default:
        expiryMinutes = null
    }

    onConfirm(expiryMinutes, shareKey)
    onClose()
  }

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(shareKey)
    } catch (error) {
      console.error("Failed to copy:", error)
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose}>
      <ModalContent>
        <ModalHeader>Share "{fileName}"</ModalHeader>
        <ModalBody>
          <p className="mb-4">
            Choose how long this share link should be valid:
          </p>

          <RadioGroup value={expiry} onValueChange={setExpiry}>
            <Radio value="10min">10 minutes</Radio>
            <Radio value="1hour">1 hour</Radio>
            <Radio value="1day">1 day</Radio>
            <Radio value="30days">30 days</Radio>
            <Radio value="1year">1 year</Radio>
            <Radio value="never">Never expires</Radio>
          </RadioGroup>

          <div className="mt-4">
            <p className="mb-2 font-medium text-sm">Share Key:</p>
            <div className="flex space-x-2">
              <Input
                value={shareKey}
                readOnly
                size="sm"
                className="font-mono"
                description="This key will be needed to decrypt the file"
              />
              <Button isIconOnly size="sm" onPress={copyToClipboard}>
                <Copy className="w-4 h-4" />
              </Button>
            </div>
            <p className="mt-1 text-default-500 text-xs">
              Share this key with the recipient. It cannot be recovered later.
            </p>
          </div>
        </ModalBody>
        <ModalFooter>
          <Button variant="ghost" onPress={onClose}>
            Cancel
          </Button>
          <Button
            color="primary"
            onPress={handleConfirm}
            isDisabled={!shareKey}
          >
            Create Share Link
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  )
}
