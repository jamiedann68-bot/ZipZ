# ZipZ ⚡
**High-Performance, Secure, and AI-Optimized Zstandard Archiver**

ZipZ is a modern CLI utility designed to replace `tar` and `gzip` for the **Neurons/Nexus** ecosystem. It combines the speed of **Zstandard**, the security of **AES-256-GCM**, and the automation of **Rclone** into a single, intuitive interface.

## 🚀 Why ZipZ?
- **420% Faster than Gzip**: Optimized Zstd engine beats traditional compression in both speed and efficiency.
- **AEAD Security**: Built-in AES-256-GCM authenticated encryption (Privacy + Integrity).
- **Auto-Sync**: Push archives directly to the cloud (Google Drive, S3, etc.) via Rclone.
- **Self-Verifying**: Automatic SHA-256 sidecar generation for every archive.
- **AI-Ready**: Simple, consistent CLI verbs designed for both humans and AI agents.

## 📦 Installation
ZipZ is already installed globally on this system. You can call it from any directory:
```bash
# Verify installation
zipz --help
```
*Script location: `/usr/local/bin/zipz` -> `/home/kaung/Desktop/nexus/zipz.py`*

## 🛠️ Usage

### 1. Compress
```bash
# Standard compression
zipz compress my_folder

# Secure encryption (prompts for password)
zipz compress private_data -p

# Multi-threaded compression with cloud sync
zipz compress logs -j 4 -r my-drive:backups
```

### 2. Decompress
```bash
zipz decompress secure_backup.zz -o extracted_folder/
```

### 3. List & Verify
```bash
# List contents (supports encrypted archives)
zipz list secret.zz

# Verify integrity via SHA-256 sidecar
zipz verify secret.zz
```

## 📄 Automation
ZipZ supports `.zipzignore` files. Place a `.zipzignore` in your source folder to exclude patterns (similar to `.gitignore`):
```text
# .zipzignore example
node_modules/
*.tmp
.git/
```

## ☁️ Cloud Sync Setup (Rclone)
ZipZ uses **Rclone** for cloud transfers. To set it up:

1. **Install Rclone**: `sudo apt install rclone` (or your OS equivalent).
2. **Configure Remote**: Run `rclone config` and follow the prompts to add your provider (Google Drive, S3, Dropbox, etc.). 
3. **Note your Remote Name**: If you named your remote `my-drive`, you can push archives instantly:
   ```bash
   zipz compress my_data -r my-drive:backups/
   ```

## 🏗️ Technical Specs
- **Encryption**: AES-256-GCM (Authenticated Encryption with Associated Data).
- **Key Derivation**: PBKDF2-HMAC-SHA256 (100,000 iterations).
- **Compression**: Meta Zstandard (Zstd).
- **Bundling**: PAX-format Tar (Supports modern file features & symlinks).

---
*Built for the Nexus Workspace within the Neurons Ecosystem.*
