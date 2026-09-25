#!/usr/bin/env bash
# ==============================================================================
# Secure Upload Gateway — Local Development Secret Generator
# ==============================================================================
# Generates local-development secret files required by Docker Compose and the
# gateway configuration loader.
#
# INVARIANTS:
# 1. Uses cryptographically secure randomness (OpenSSL or Node.js crypto fallback).
# 2. Never prints generated secret values to stdout or stderr.
# 3. Sets restrictive filesystem permissions (0700 on dir, 0600 on files) where supported.
# 4. Fails immediately on any error (set -euo pipefail).
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SECRETS_DIR="${1:-$REPO_ROOT/secrets}"

# Ensure secrets directory exists with restrictive permissions
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR" 2>/dev/null || true

# Determine cryptographic generator
USE_OPENSSL=0
USE_NODE=0

if command -v openssl >/dev/null 2>&1; then
  USE_OPENSSL=1
elif command -v node >/dev/null 2>&1; then
  USE_NODE=1
else
  echo "[gen-secrets] ERROR: Neither 'openssl' nor 'node' is available to generate cryptographic material." >&2
  exit 1
fi

# 1. Generate PEPPER (32 bytes = 64 hex characters, min 256 bits entropy)
if [ ! -f "$SECRETS_DIR/pepper" ]; then
  if [ "$USE_OPENSSL" -eq 1 ]; then
    openssl rand -hex 32 > "$SECRETS_DIR/pepper"
  else
    node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('hex'))" > "$SECRETS_DIR/pepper"
  fi
fi

# 2. Generate KEK (Key Encryption Key: 32 bytes = 64 hex characters for AES-256 KeyWrap)
if [ ! -f "$SECRETS_DIR/kek" ]; then
  if [ "$USE_OPENSSL" -eq 1 ]; then
    openssl rand -hex 32 > "$SECRETS_DIR/kek"
  else
    node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('hex'))" > "$SECRETS_DIR/kek"
  fi
fi

# 3. Generate JWT Ed25519 Keypair (PKCS#8 PEM private key and SPKI PEM public key)
if [ ! -f "$SECRETS_DIR/jwt_private_key.pem" ] && [ ! -f "$SECRETS_DIR/jwt_private_key" ]; then
  if [ "$USE_OPENSSL" -eq 1 ]; then
    openssl genpkey -algorithm ed25519 -out "$SECRETS_DIR/jwt_private_key.pem" 2>/dev/null
    openssl pkey -in "$SECRETS_DIR/jwt_private_key.pem" -pubout -out "$SECRETS_DIR/jwt_public_key.pem" 2>/dev/null
  else
    node -e "
      const { generateKeyPairSync } = require('node:crypto');
      const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        publicKeyEncoding: { type: 'spki', format: 'pem' }
      });
      require('node:fs').writeFileSync(process.argv[1], privateKey);
      require('node:fs').writeFileSync(process.argv[2], publicKey);
    " "$SECRETS_DIR/jwt_private_key.pem" "$SECRETS_DIR/jwt_public_key.pem"
  fi
  cp "$SECRETS_DIR/jwt_private_key.pem" "$SECRETS_DIR/jwt_private_key"
fi

# 4. Generate Audit Checkpoint Signing Ed25519 Keypair
if [ ! -f "$SECRETS_DIR/checkpoint_private_key.pem" ] && [ ! -f "$SECRETS_DIR/checkpoint_private_key" ]; then
  if [ "$USE_OPENSSL" -eq 1 ]; then
    openssl genpkey -algorithm ed25519 -out "$SECRETS_DIR/checkpoint_private_key.pem" 2>/dev/null
    openssl pkey -in "$SECRETS_DIR/checkpoint_private_key.pem" -pubout -out "$SECRETS_DIR/checkpoint_public_key.pem" 2>/dev/null
  else
    node -e "
      const { generateKeyPairSync } = require('node:crypto');
      const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        publicKeyEncoding: { type: 'spki', format: 'pem' }
      });
      require('node:fs').writeFileSync(process.argv[1], privateKey);
      require('node:fs').writeFileSync(process.argv[2], publicKey);
    " "$SECRETS_DIR/checkpoint_private_key.pem" "$SECRETS_DIR/checkpoint_public_key.pem"
  fi
  cp "$SECRETS_DIR/checkpoint_private_key.pem" "$SECRETS_DIR/checkpoint_private_key"
fi

# 5. Generate Database Password (matches docker-compose local dev password)
if [ ! -f "$SECRETS_DIR/db_password" ]; then
  printf 'sug_dev_password' > "$SECRETS_DIR/db_password"
fi

# 6. Generate AWS Secret Access Key (Local development placeholder or test key)
if [ ! -f "$SECRETS_DIR/aws_secret_access_key" ]; then
  if [ "$USE_OPENSSL" -eq 1 ]; then
    openssl rand -base64 30 > "$SECRETS_DIR/aws_secret_access_key"
  else
    node -e "process.stdout.write(require('node:crypto').randomBytes(30).toString('base64'))" > "$SECRETS_DIR/aws_secret_access_key"
  fi
fi

# Restrict file permissions where supported
chmod 600 "$SECRETS_DIR"/* 2>/dev/null || true

echo "Generated local development secrets under $SECRETS_DIR"
