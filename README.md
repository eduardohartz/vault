# 🔒 Vault

**A self-hostable, end-to-end encrypted file vault protected by passkeys**

Vault is inspired by [FileKey](https://filekey.app) but designed for self-hosting, with all files stored on your own backend.

---

## ⚠️ Upgrading from an earlier version

**Export your files before upgrading. Existing accounts and files cannot be migrated.**

Two changes make the break unavoidable:

1. Sign-in now verifies the passkey signature server-side, which requires the credential's public key. Earlier versions never stored it, so existing accounts cannot be authenticated and must be recreated.
2. Key derivation used a hand-rolled Keccak implementation that did not match Keccak-256 (it produced collisions and failed the published test vectors). It is fixed, which changes every derived key.

Run the old version, download everything, then upgrade and re-register. The broken hash is preserved in `lib/keccak-helper-legacy.ts` and selected by the per-user `keyVersion` column, so v1 derivation stays reproducible for manual recovery from an old database.

---

## 🚀 Features

- 🔐 End-to-end encryption — files are encrypted and decrypted only in your browser
- 🧩 Passkey authentication with server-side WebAuthn verification, no passwords
- 💾 Files stored on your own backend
- ⤴️ Share a file with a link plus a per-share key that never reaches the server
- 🏠 Self-hostable with Docker

---

## 📋 Requirements

- Docker and Docker Compose
- **HTTPS.** Passkeys only work in a [secure context](https://developer.mozilla.org/docs/Web/Security/Secure_Contexts). Anything other than `localhost` needs a real TLS certificate — put a reverse proxy (Caddy, nginx, Traefik) in front of the container. Over plain HTTP the app will tell you HTTPS is required.
- A browser and authenticator supporting the WebAuthn **PRF** extension: Chrome, Edge or Firefox with Windows Hello, or Safari with Touch ID / Face ID.

---

## 🛠️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/eduardohartz/vault.git
cd vault
```

### 2. Copy the example environment file

```bash
cp .env.example .env
```

### 3. Configure environment variables

Open `.env` and set at least:

| Variable | Purpose |
| --- | --- |
| `APP_URL` | Public URL users reach the vault on. WebAuthn verifies assertions against this origin and share links are built from it, so it must match what the browser sees. |
| `POSTGRES_PASSWORD` | Change this before deploying. |
| `MAX_USERS` | How many accounts may exist. Registration is refused past this. |
| `MAX_FILE_SIZE_BYTES` | Per-file upload ceiling. Default 100 MB. |
| `MAX_USER_QUOTA_BYTES` | Per-user storage quota. Default 1 GB. |
| `SESSION_TTL_MINUTES` | How long a sign-in lasts before the passkey is needed again. Default 60. |
| `WEBAUTHN_RP_ID` | Optional. Defaults to `APP_URL`'s hostname, which is normally correct. |

### 4. Build and start

```bash
docker compose up -d --build
```

Database migrations run automatically on startup.

### 5. Open your vault

Visit `APP_URL` (or `http://localhost:3000` if that is what you configured).

---

## 🤝 Sharing

Creating a share generates a **random key for that share only**. The key is generated in your browser, never sent to the server, and shown once.

Send the link and the key through **different channels** — anyone with both can decrypt the file. If you lose the key, unshare the file and create a new link.

Shares can be set to expire. Expired shares are deleted, ciphertext included.

---

## 🧑‍💻 Development

This project uses **pnpm**. The version is pinned in `package.json`'s `packageManager` field, so `corepack enable` gets you the exact one CI and the Docker build use.

```bash
corepack enable
pnpm install
pnpm exec prisma migrate dev
pnpm dev
```

`pnpm dev` serves HTTPS locally, which passkeys require.

```bash
pnpm verify
```

Runs typecheck, lint and tests. To wipe the database (destructive, guarded):

```bash
CONFIRM_RESET=yes pnpm db:reset
```

## Disclaimer:
I'm obviously not liable for the security of this software, when I made this, I got most of the very complex encryption code from FileKey, then made the rest myself, no security expert has checked the validity of the code, and while I trust it's secure, you probably shouldn't, since im a high schooler.
