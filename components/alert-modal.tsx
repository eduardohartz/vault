"use client"

import {
  Modal,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalFooter,
  Button,
} from "@heroui/react"
import { CheckCircle, XCircle, AlertTriangle, Info } from "lucide-react"

interface AlertModalProps {
  isOpen: boolean
  onClose: () => void
  title: string
  message: string
  type: "success" | "error" | "warning" | "info"
}

export default function AlertModal({
  isOpen,
  onClose,
  title,
  message,
  type,
}: AlertModalProps) {
  const getIcon = () => {
    switch (type) {
      case "success":
        return <CheckCircle className="w-6 h-6 text-success" />
      case "error":
        return <XCircle className="w-6 h-6 text-danger" />
      case "warning":
        return <AlertTriangle className="w-6 h-6 text-warning" />
      default:
        return <Info className="w-6 h-6 text-primary" />
    }
  }

  const getColor = () => {
    switch (type) {
      case "success":
        return "success"
      case "error":
        return "danger"
      case "warning":
        return "warning"
      default:
        return "primary"
    }
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      placement="center"
      backdrop="opaque"
    >
      <ModalContent>
        <ModalHeader className="flex items-center gap-2">
          {getIcon()}
          {title}
        </ModalHeader>
        <ModalBody>
          <p>{message}</p>
        </ModalBody>
        <ModalFooter>
          <Button color={getColor() as any} onPress={onClose}>
            OK
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  )
}
