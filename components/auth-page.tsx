"use client"

import { useState, useEffect, SetStateAction } from "react"
import {
  Card,
  CardBody,
  CardHeader,
  Button,
  Input,
  Spinner,
  useDisclosure,
} from "@heroui/react"
import { PasskeyManager } from "@/lib/passkey"
import { AdvancedCryptoManager } from "@/lib/advanced-crypto"
import { Shield, Key, Moon, Sun, CheckCircle } from "lucide-react"
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
  const [registrationStep, setRegistrationStep] = useState<
    "check" | "passkey-created" | "complete"
  >("check")
  const [credentialId, setCredentialId] = useState<string>("")
  const { theme, setTheme } = useTheme()

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

  const handleCreatePasskey = async () => {
    setIsProcessing(true)
    setError("")
    setDebugInfo("Creating passkey...")

    try {
      const { credential } = await PasskeyManager.register(username.trim())
      setDebugInfo(`Passkey created: ${credential.id}`)

      console.log(
        credential.getClientExtensionResults(),
        credential.getClientExtensionResults().prf,
      )

      if (credential.getClientExtensionResults().prf?.enabled !== true) {
        throw new Error("PRF extension not enabled")
      }

      // Store credential ID for the next step
      setCredentialId(credential.id)
      setRegistrationStep("passkey-created")

      showAlert(
        "Passkey Created",
        "Your passkey has been created successfully! Now we'll set up your encryption keys.",
        "success",
      )
    } catch (error) {
      showAlert(
        "Passkey Creation Failed",
        "Failed to create passkey. Please try again.",
        "error",
      )
      setDebugInfo(`Error: ${error}`)
      console.error("Passkey creation error:", error)
    } finally {
      setIsProcessing(false)
    }
  }

  const handleCompleteRegistration = async () => {
    setIsProcessing(true)
    setError("")
    setDebugInfo("Authenticating with new passkey to generate keys...")

    try {
      // Add a small delay to ensure the passkey is properly registered
      await new Promise((resolve) => setTimeout(resolve, 1000))

      // Authenticate with the newly created passkey to get PRF
      const credential = await PasskeyManager.authenticate()
      setDebugInfo(`Authenticated: ${credential.id}`)

      // Verify this is the same credential we just created
      if (credential.id !== credentialId) {
        throw new Error("Authenticated with different credential than expected")
      }

      setDebugInfo("Generating encryption keys from PRF...")
      const prfOutput = await AdvancedCryptoManager.getPRFOutput(credential)

      const hkdfSeed = await AdvancedCryptoManager.generateHKDFSeed(prfOutput)
      const { privateKey, publicKey, privateKeyRaw, publicKeyRaw } =
        await AdvancedCryptoManager.generateECDHKeyPair(hkdfSeed)

      const publicKeyExported = await crypto.subtle.exportKey("raw", publicKey)
      const publicKeyBase64 = btoa(
        String.fromCharCode(...new Uint8Array(publicKeyExported)),
      )

      const shareKey = await AdvancedCryptoManager.generateShareKey(
        privateKeyRaw,
      )

      setDebugInfo("Keys generated successfully")

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
        setRegistrationStep("complete")
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
        "Failed to authenticate with new passkey or generate keys.",
        "error",
      )
      setDebugInfo(`Error: ${error}`)
      console.error("Registration completion error:", error)

      // Reset to allow retry
      setRegistrationStep("check")
      setCredentialId("")
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

      setDebugInfo("Regenerating keys from PRF...")
      const prfOutput = await AdvancedCryptoManager.getPRFOutput(credential)
      const hkdfSeed = await AdvancedCryptoManager.generateHKDFSeed(prfOutput)
      const { privateKey, privateKeyRaw } =
        await AdvancedCryptoManager.generateECDHKeyPair(hkdfSeed)

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
    setRegistrationStep("check")
    setCredentialId("")
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
          <div className="flex justify-center items-center gap-1">
            <div className="bg-primary/10 p-3 rounded-full">
              <Shield className="w-8 h-8 text-primary" />
            </div>
            <h1 className="font-bold text-xl">Vault</h1>
          </div>
        </CardHeader>

        <CardBody className="pt-2">
          {!hasCheckedUsername ? (
            <>
              <div className="mb-4">
                <Input
                  label="Username"
                  placeholder="Enter your username"
                  value={username}
                  onChange={(e: {
                    target: { value: SetStateAction<string> }
                  }) => setUsername(e.target.value)}
                  startContent={<Key className="w-4 h-4 text-default-400" />}
                  isDisabled={isLoading}
                  onKeyDown={(e: { key: string }) =>
                    e.key === "Enter" && checkUsername()
                  }
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
                <>
                  {registrationStep === "check" && (
                    <Button
                      color="primary"
                      size="lg"
                      className="w-full"
                      onPress={handleCreatePasskey}
                      isLoading={isProcessing}
                      startContent={
                        !isProcessing && <Shield className="w-4 h-4" />
                      }
                    >
                      {isProcessing ? "Creating Passkey..." : "Create Passkey"}
                    </Button>
                  )}

                  {registrationStep === "passkey-created" && (
                    <div className="space-y-4">
                      <div className="bg-success/10 p-3 border border-success/20 rounded-lg">
                        <div className="flex items-center space-x-2">
                          <CheckCircle className="w-5 h-5 text-success" />
                          <p className="font-medium text-success text-sm">
                            Passkey Created Successfully!
                          </p>
                        </div>
                        <p className="mt-1 text-success text-xs">
                          Now we'll authenticate with your new passkey to set up
                          encryption keys.
                        </p>
                      </div>

                      <Button
                        color="primary"
                        size="lg"
                        className="w-full"
                        onPress={handleCompleteRegistration}
                        isLoading={isProcessing}
                        startContent={
                          !isProcessing && <Key className="w-4 h-4" />
                        }
                      >
                        {isProcessing
                          ? "Setting up encryption..."
                          : "Complete Account Setup"}
                      </Button>
                    </div>
                  )}
                </>
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
