"use client"

import { useState, useEffect } from "react"
import {
  Card,
  CardBody,
  CardHeader,
  Button,
  Input,
  Spinner,
  useDisclosure,
} from "@nextui-org/react"
import { PasskeyManager } from "@/lib/passkey"
import { AdvancedCryptoManager } from "@/lib/advanced-crypto"
import { Shield, Key, Moon, Sun } from "lucide-react"
import { useTheme } from "next-themes"
import AlertModal from "@/components/alert-modal"

interface AuthPageProps {
  onAuthenticated: (user: {
    id: string
    username: string
    shareKey: string
    privateKeyRaw: Uint8Array
  }) => void
}

export default function AuthPage({ onAuthenticated }: AuthPageProps) {
  const [isLoading, setIsLoading] = useState(true)
  const [username, setUsername] = useState("")
  const [userExists, setUserExists] = useState(false)
  const [canRegister, setCanRegister] = useState(false)
  const [isProcessing, setIsProcessing] = useState(false)
  const [error, setError] = useState("")
  const [isSupported, setIsSupported] = useState(false)
  const [hasCheckedUsername, setHasCheckedUsername] = useState(false)
  const [debugInfo, setDebugInfo] = useState("")
  const { theme, setTheme } = useTheme()

  // Alert modal
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
    checkPasskeySupport()
    setIsLoading(false)
  }, [])

  const showAlert = (
    title: string,
    message: string,
    type: "success" | "error" | "warning" | "info" = "info",
  ) => {
    setAlertConfig({ title, message, type })
    onAlertOpen()
  }

  const checkPasskeySupport = async () => {
    const supported = await PasskeyManager.isSupported()
    const prfSupported = await PasskeyManager.isPRFSupported()
    setIsSupported(supported && prfSupported)
    setDebugInfo(`Passkey: ${supported}, PRF: ${prfSupported}`)
  }

  const checkUsername = async () => {
    if (!username.trim()) {
      showAlert("Missing Username", "Please enter a username", "warning")
      return
    }

    setIsLoading(true)
    setError("")

    try {
      const response = await fetch("/api/auth/check-username", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim() }),
      })

      const data = await response.json()

      if (response.ok) {
        setUserExists(data.exists)
        setCanRegister(data.canRegister)
        setHasCheckedUsername(true)

        if (!data.exists && !data.canRegister) {
          showAlert(
            "Registration Limit Reached",
            `Maximum number of users (${data.maxUsers}) reached. Cannot create new accounts.`,
            "error",
          )
        }
      } else {
        showAlert("Error", data.error || "Failed to check username", "error")
      }
    } catch (error) {
      showAlert("Error", "Failed to check username. Please try again.", "error")
      console.error("Username check error:", error)
    } finally {
      setIsLoading(false)
    }
  }

  const handleRegister = async () => {
    setIsProcessing(true)
    setError("")
    setDebugInfo("Starting registration...")

    try {
      // Step 1: Create passkey with PRF
      setDebugInfo("Creating passkey with PRF...")
      const { credential } = await PasskeyManager.register(username.trim())
      setDebugInfo(`Passkey created: ${credential.id}`)

      // Step 2: Get PRF output by authenticating with the new credential
      setDebugInfo("Getting PRF output from new credential...")
      const credentialIdArray = new Uint8Array(credential.rawId)
      const credentialIdString = Array.from(credentialIdArray, (byte) =>
        String.fromCharCode(byte),
      ).join("")

      // Authenticate immediately to get PRF output
      const prfOutput = await AdvancedCryptoManager.generatePRFOutput(
        credentialIdString,
      )
      setDebugInfo("PRF output obtained successfully")

      // Step 3: Generate deterministic keys
      setDebugInfo("Generating deterministic encryption keys...")
      const hkdfSeed = await AdvancedCryptoManager.generateHKDFSeed(prfOutput)
      const { privateKey, publicKey, privateKeyRaw, publicKeyRaw } =
        await AdvancedCryptoManager.generateECDHKeyPair(hkdfSeed)

      // Export public key for server storage
      const publicKeyExported = await crypto.subtle.exportKey("raw", publicKey)
      const publicKeyBase64 = btoa(
        String.fromCharCode(...new Uint8Array(publicKeyExported)),
      )

      // Generate share key from private key (NEVER send to server)
      const shareKey = await AdvancedCryptoManager.generateShareKey(
        privateKeyRaw,
      )

      setDebugInfo("Keys generated successfully")

      // Step 4: Register with server - send PUBLIC key only
      setDebugInfo("Registering with server...")
      const response = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: username.trim(),
          credentialId: credential.id,
          publicKey: publicKeyBase64,
        }),
      })

      const data = await response.json()

      if (data.success) {
        setDebugInfo("Registration successful!")
        onAuthenticated({
          id: data.userId,
          username: username.trim(),
          shareKey,
          privateKeyRaw,
        })
      } else {
        showAlert(
          "Registration Failed",
          data.error || "Registration failed",
          "error",
        )
        setDebugInfo(`Registration failed: ${data.error}`)
      }
    } catch (error) {
      showAlert(
        "Registration Failed",
        "Failed to create passkey or generate keys. PRF support required.",
        "error",
      )
      setDebugInfo(`Error: ${error}`)
      console.error("Registration error:", error)
    } finally {
      setIsProcessing(false)
    }
  }

  const handleLogin = async () => {
    setIsProcessing(true)
    setError("")
    setDebugInfo("Starting login...")

    try {
      setDebugInfo("Authenticating with passkey...")
      const credential = await PasskeyManager.authenticate()
      setDebugInfo(`Authenticated: ${credential.id}`)

      // Generate keys from PRF (NO FALLBACKS)
      setDebugInfo("Regenerating keys from PRF...")
      const prfOutput = await AdvancedCryptoManager.generatePRFOutput(
        credential.id,
      )
      const hkdfSeed = await AdvancedCryptoManager.generateHKDFSeed(prfOutput)
      const { privateKey, privateKeyRaw } =
        await AdvancedCryptoManager.generateECDHKeyPair(hkdfSeed)

      // Generate share key from private key
      const shareKey = await AdvancedCryptoManager.generateShareKey(
        privateKeyRaw,
      )

      setDebugInfo("Logging in with server...")
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          credentialId: credential.id,
        }),
      })

      const data = await response.json()

      if (data.success) {
        setDebugInfo("Login successful!")
        onAuthenticated({
          id: data.user.id,
          username: data.user.username,
          shareKey,
          privateKeyRaw,
        })
      } else {
        showAlert(
          "Authentication Failed",
          data.error || "Authentication failed",
          "error",
        )
        setDebugInfo(`Login failed: ${data.error}`)
      }
    } catch (error) {
      showAlert(
        "Authentication Failed",
        "Authentication failed. PRF support required.",
        "error",
      )
      setDebugInfo(`Error: ${error}`)
      console.error("Login error:", error)
    } finally {
      setIsProcessing(false)
    }
  }

  const resetForm = () => {
    setUsername("")
    setUserExists(false)
    setCanRegister(false)
    setHasCheckedUsername(false)
    setError("")
    setDebugInfo("")
  }

  if (isLoading) {
    return (
      <div className="flex justify-center items-center bg-background min-h-screen">
        <Spinner size="lg" />
      </div>
    )
  }

  if (!isSupported) {
    return (
      <div className="flex justify-center items-center bg-background p-4 min-h-screen">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <h1 className="font-bold text-danger text-2xl">
              PRF Not Supported
            </h1>
          </CardHeader>
          <CardBody className="text-center">
            <p className="mb-4 text-default-600">
              Your browser doesn't support WebAuthn PRF extension. This system
              requires PRF support for secure key derivation.
            </p>
            <p className="text-default-400 text-xs">{debugInfo}</p>
            <p className="mt-2 text-default-400 text-xs">
              Try using Chrome/Edge with Windows Hello or Safari with Touch
              ID/Face ID.
            </p>
          </CardBody>
        </Card>
      </div>
    )
  }

  return (
    <div className="flex justify-center items-center bg-background p-4 min-h-screen">
      <div className="top-4 right-4 absolute">
        <Button
          isIconOnly
          variant="ghost"
          onPress={() => setTheme(theme === "dark" ? "light" : "dark")}
        >
          {theme === "dark" ? (
            <Sun className="w-5 h-5" />
          ) : (
            <Moon className="w-5 h-5" />
          )}
        </Button>
      </div>

      <Card className="w-full max-w-md">
        <CardHeader className="pb-2 text-center">
          <div className="flex justify-center mb-4">
            <div className="bg-primary/10 p-3 rounded-full">
              <Shield className="w-8 h-8 text-primary" />
            </div>
          </div>
          <h1 className="font-bold text-2xl">File Manager</h1>
        </CardHeader>

        <CardBody className="pt-2">
          {!hasCheckedUsername ? (
            <>
              <div className="mb-4">
                <Input
                  label="Username"
                  placeholder="Enter your username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  startContent={<Key className="w-4 h-4 text-default-400" />}
                  isDisabled={isLoading}
                  onKeyDown={(e) => e.key === "Enter" && checkUsername()}
                />
              </div>

              <Button
                color="primary"
                size="lg"
                className="w-full"
                onPress={checkUsername}
                isLoading={isLoading}
                isDisabled={!username.trim()}
              >
                Continue
              </Button>
            </>
          ) : (
            <>
              <div className="bg-default-50 dark:bg-default-100 mb-4 p-3 rounded-lg">
                <p className="text-sm">
                  <strong>Username:</strong> {username}
                </p>
                <Button
                  size="sm"
                  variant="light"
                  onPress={resetForm}
                  className="mt-2"
                >
                  Change Username
                </Button>
              </div>

              {userExists ? (
                <Button
                  color="primary"
                  size="lg"
                  className="w-full"
                  onPress={handleLogin}
                  isLoading={isProcessing}
                  startContent={!isProcessing && <Shield className="w-4 h-4" />}
                >
                  {isProcessing ? "Authenticating..." : "Login with Passkey"}
                </Button>
              ) : canRegister ? (
                <Button
                  color="primary"
                  size="lg"
                  className="w-full"
                  onPress={handleRegister}
                  isLoading={isProcessing}
                  startContent={!isProcessing && <Shield className="w-4 h-4" />}
                >
                  {isProcessing ? "Creating Passkey..." : "Create Passkey"}
                </Button>
              ) : (
                <Button color="danger" size="lg" className="w-full" isDisabled>
                  Registration Unavailable
                </Button>
              )}
            </>
          )}

          {error && (
            <div className="bg-danger/10 mt-4 p-3 border border-danger/20 rounded-lg">
              <p className="text-danger text-sm">{error}</p>
            </div>
          )}

          {debugInfo && (
            <div className="bg-default-100 dark:bg-default-50 mt-2 p-2 rounded text-default-600 text-xs">
              Debug: {debugInfo}
            </div>
          )}
        </CardBody>
      </Card>

      {/* Alert Modal */}
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
