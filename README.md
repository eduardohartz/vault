Warning: As of now, some salts/other site specific information is hardcoded, no secrets are hard coded, so it's safe to use, but maybe hold off on it until I move everything to env variables

# 🔒 Vault  
**A self-hostable, end-to-end encrypted file vault powered by passkeys**

Vault is inspired by [FileKey](https://filekey.app) but designed for self-hosting, with all files securely stored on your own backend.

---

## 🚀 Features
- 🔐 End-to-end encryption using modern cryptography  
- 🧩 Passkey-based authentication (no passwords)  
- 💾 Backend-stored files for complete control
- ⤴️ Share files with a share link and key
- 🏠 Fully self-hostable with Docker  

---

## 🛠️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/eduardohartz/vault.git
cd vault
```

### 1. Copy the example environment file
```bash
cp .env.example .env
```

### 3. Configure environment variables
Open .env in your editor and adjust the settings as needed

### 4. Build and start the containers
```bash
docker compose build
docker compose up -d
```
### 5. Access your vault
Once running, open your browser and visit:
`http://localhost:3000` (or your configured port)
