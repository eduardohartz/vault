"use client"

import { Button, Card, CardBody, CardHeader, Input, Spinner, useDisclosure } from "@heroui/react"
import { AlertTriangle, Key, Moon, Shield, Sun } from "lucide-react"
import { useTheme } from "next-themes"
import { useCallback, useEffect, useState } from "react"
import AlertModal from "@/components/alert-modal"
import { CryptoManager } from "@/lib/crypto-manager"
import { KeyHelper } from "@/lib/key-helper"
import { PasskeyManager } from "@/lib/passkey-manager"
import { wipe } from "@/lib/session-client"

export type AuthenticatedUser = {
  id: string
  username: string
  privateKey: CryptoKey
  publicKey: CryptoKey
}

type AuthPageProps = {
  onAuthenticated: (user: AuthenticatedUser) => void
}

type Support =
  | { state: "checking" }
  | { state: "insecure" }
  | { state: "unsupported" }
  | { state: "ok" }

export default function AuthPage({ onAuthenticated }: AuthPageProps) {
  const [support, setSupport] = useState<Support>({ state: "checking" })
  const [username, setUsername] = useState("")
  const [mode, setMode] = useState<"choose" | "register">("choose")
  const [canRegister, setCanRegister] = useState(false)
  const [isProcessing, setIsProcessing] = useState(false)
  const { theme, setTheme } = useTheme()

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

    const check = async () => {
      // WebAuthn only runs in a secure context. Reporting this as "PRF not
      // supported" used to send self-hosters chasing a browser problem when
      // the real cause was serving the app over plain HTTP.
      if (!PasskeyManager.isSecureContextAvailable()) {
        if (!cancelled) {
          setSupport({ state: "insecure" })
        }
        return
      }

      const supported = (await PasskeyManager.isSupported()) && (await PasskeyManager.isPRFSupported())

      try {
        const response = await fetch("/api/auth/session")
        const data = await response.json()
        if (!cancelled) {
          setCanRegister(Boolean(data.canRegister))
        }
      } catch {
        // Non-fatal: the register button simply stays hidden.
      }

      if (!cancelled) {
        setSupport({ state: supported ? "ok" : "unsupported" })
      }
    }

    void check()
    return () => {
      cancelled = true
    }
  }, [])

  /**
   * Run a passkey assertion, verify it server-side, and derive the vault keys
   * from its PRF output. The server decides the key derivation version, so an
   * existing v1 vault keeps deriving the keys its files were encrypted with.
   */
  const authenticateAndDeriveKeys = useCallback(async (): Promise<AuthenticatedUser> => {
    const optionsResponse = await fetch("/api/auth/login/options", { method: "POST" })
    if (!optionsResponse.ok) {
      throw new Error((await optionsResponse.json()).error ?? "Could not start sign-in")
    }
    const { options } = await optionsResponse.json()

    const credential = await PasskeyManager.authenticate(options)
    const prfBuff = await CryptoManager.getPRFOutput(credential)

    const verifyResponse = await fetch("/api/auth/login/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challenge: options.challenge,
        response: PasskeyManager.serializeAuthentication(credential),
      }),
    })

    const verified = await verifyResponse.json()
    if (!verifyResponse.ok || !verified.success) {
      throw new Error(verified.error ?? "Authentication failed")
    }

    let hkdfSeed: ArrayBuffer
    try {
      const HKDFKey = await CryptoManager.generateHKDFKey(prfBuff)
      hkdfSeed = await CryptoManager.generateNewSeed("", prfBuff, HKDFKey, verified.user.keyVersion)
    } finally {
      // The PRF output is the root of the whole key chain — everything
      // rederives from it — so it should not outlive the derivation. Best
      // effort: the engine may already have copied it, and the buffer inside
      // the assertion is not ours to clear.
      wipe(prfBuff)
    }

    const { privateKey, publicKey } = CryptoManager.generateKeyPair(hkdfSeed)
    const keys = await KeyHelper.convertKeys(privateKey, publicKey)

    if (!keys.privateKey.success || !keys.publicKey.success || !keys.privateKey.key || !keys.publicKey.key) {
      // Surfaced rather than swallowed: this is the path that used to fall back
      // to a random key on Safari and silently orphan every uploaded file.
      throw new Error(keys.privateKey.error ?? keys.publicKey.error ?? "Could not derive your encryption keys")
    }

    return {
      id: verified.user.id,
      username: verified.user.username,
      privateKey: keys.privateKey.key,
      publicKey: keys.publicKey.key,
    }
  }, [])

  const handleLogin = async () => {
    setIsProcessing(true)
    try {
      onAuthenticated(await authenticateAndDeriveKeys())
    } catch (error) {
      showAlert("Sign-in Failed", error instanceof Error ? error.message : "Authentication failed.", "error")
    } finally {
      setIsProcessing(false)
    }
  }

  const handleRegister = async () => {
    const trimmed = username.trim()
    if (!trimmed) {
      showAlert("Missing Username", "Please enter a username.", "warning")
      return
    }

    setIsProcessing(true)
    try {
      const optionsResponse = await fetch("/api/auth/register/options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: trimmed }),
      })

      const optionsData = await optionsResponse.json()
      if (!optionsResponse.ok) {
        throw new Error(optionsData.error ?? "Could not start registration")
      }

      const credential = await PasskeyManager.register(optionsData.options)

      if (credential.getClientExtensionResults().prf?.enabled !== true) {
        throw new Error("Your authenticator did not enable the PRF extension, which this vault requires for encryption.")
      }

      const verifyResponse = await fetch("/api/auth/register/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          challenge: optionsData.options.challenge,
          response: PasskeyManager.serializeRegistration(credential),
        }),
      })

      const verified = await verifyResponse.json()
      if (!verifyResponse.ok || !verified.success) {
        throw new Error(verified.error ?? "Registration failed")
      }

      // PRF output is only returned by an assertion, so a second ceremony is
      // needed before any key material exists.
      onAuthenticated(await authenticateAndDeriveKeys())
    } catch (error) {
      showAlert("Registration Failed", error instanceof Error ? error.message : "Registration failed.", "error")
    } finally {
      setIsProcessing(false)
    }
  }

  if (support.state === "checking") {
    return (
      <div className="flex justify-center items-center bg-background min-h-screen">
        <Spinner size="lg" label="Checking browser support" />
      </div>
    )
  }

  if (support.state === "insecure" || support.state === "unsupported") {
    const insecure = support.state === "insecure"
    return (
      <div className="flex justify-center items-center bg-background p-4 min-h-screen">
        <Card className="p-2 w-full max-w-md">
          <CardHeader className="border-divider border-b text-center">
            <h1 className="font-bold text-danger text-xl">{insecure ? "HTTPS Required" : "PRF Not Supported"}</h1>
          </CardHeader>
          <CardBody className="text-left">
            {insecure ? (
              <>
                <p className="py-3 text-default-600 text-center">
                  Passkeys only work in a secure context. Serve this vault over HTTPS, or reach it at
                  {" "}
                  <code className="bg-default-100 px-1 rounded">localhost</code>
                  .
                </p>
                <p className="mt-2 text-default-400 text-xs">
                  Put a reverse proxy with a TLS certificate in front of the container, or run
                  {" "}
                  <code className="bg-default-100 px-1 rounded">npm run dev</code>
                  {" "}
                  which serves HTTPS locally.
                </p>
              </>
            ) : (
              <>
                <p className="py-3 text-default-600 text-center">
                  Your browser or authenticator doesn't support the WebAuthn PRF extension, which this vault requires to derive encryption keys.
                </p>
                <p className="mt-2 text-default-400 text-xs">Try Chrome, Edge or Firefox with Windows Hello, or Safari with Touch ID / Face ID.</p>
              </>
            )}
          </CardBody>
        </Card>
      </div>
    )
  }

  return (
    <div className="flex flex-col justify-center items-center gap-6 bg-background px-4 py-10 min-h-screen">
      <div className="top-4 right-4 absolute">
        <Button
          isIconOnly
          variant="ghost"
          className="min-w-11 min-h-11"
          aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          onPress={() => setTheme(theme === "dark" ? "light" : "dark")}
        >
          {theme === "dark" ? <Sun aria-hidden="true" className="w-5 h-5" /> : <Moon aria-hidden="true" className="w-5 h-5" />}
        </Button>
      </div>

      <Card className="p-1 rounded-medium w-full max-w-md">
        <CardHeader className="pb-2 text-center">
          <div className="flex justify-center items-center gap-2">
            <div className="bg-primary/10 p-3 rounded-full">
              <Shield aria-hidden="true" className="w-8 h-8 text-primary" />
            </div>
            <div className="flex flex-col items-start">
              <h1 className="font-bold text-xl">Vault</h1>
              <h2 className="text-default-500 text-sm">Sign in or create an account</h2>
            </div>
          </div>
        </CardHeader>

        <CardBody className="flex flex-col gap-3 pt-2 pb-4">
          {mode === "choose" ? (
            <>
              <Button
                color="primary"
                size="lg"
                className="w-full min-h-11"
                onPress={handleLogin}
                isLoading={isProcessing}
                startContent={!isProcessing && <Shield aria-hidden="true" className="w-4 h-4" />}
              >
                {isProcessing ? "Authenticating…" : "Sign in with passkey"}
              </Button>

              {canRegister ? (
                <Button variant="ghost" size="lg" className="w-full min-h-11" isDisabled={isProcessing} onPress={() => setMode("register")}>
                  Create an account
                </Button>
              ) : (
                <p className="text-default-500 text-xs text-center">This vault is not accepting new accounts.</p>
              )}
            </>
          ) : (
            <>
              <Input
                label="Username"
                placeholder="Choose a username"
                value={username}
                onValueChange={setUsername}
                startContent={<Key aria-hidden="true" className="w-4 h-5 text-default-400" />}
                isDisabled={isProcessing}
                description="Letters, numbers, dot, underscore or hyphen."
                onKeyDown={(e) => e.key === "Enter" && !isProcessing && handleRegister()}
              />

              <Button
                color="primary"
                size="lg"
                className="w-full min-h-11"
                onPress={handleRegister}
                isLoading={isProcessing}
                isDisabled={!username.trim()}
                startContent={!isProcessing && <Shield aria-hidden="true" className="w-4 h-4" />}
              >
                {isProcessing ? "Creating account…" : "Create passkey and account"}
              </Button>

              <Button variant="ghost" className="w-full min-h-11" isDisabled={isProcessing} onPress={() => setMode("choose")}>
                Back
              </Button>
            </>
          )}
        </CardBody>
      </Card>

      <div className="bg-warning/10 p-3 border border-warning/20 rounded-lg w-full max-w-md">
        <div className="flex items-start space-x-2">
          <AlertTriangle aria-hidden="true" className="mt-0.5 min-w-4 min-h-4 text-warning" />
          <div>
            <p className="font-medium text-warning text-sm">Security Notice</p>
            <p className="mt-1 text-warning text-xs">
              Your browser and passkey provider must support PRF. Encryption keys are non-extractable and never leave this tab, but a browser extension with access to site data still runs alongside them — use a browser profile with no extensions installed for anything sensitive.
            </p>
          </div>
        </div>
      </div>

      <AlertModal isOpen={isAlertOpen} onClose={onAlertClose} title={alertConfig.title} message={alertConfig.message} type={alertConfig.type} />
    </div>
  )
}
