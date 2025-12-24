#!/bin/bash

# =============================================================================
# Generate RSA Key Pair for JWT Signing
# =============================================================================

set -euo pipefail

# Configuration
KEY_DIR="${KEY_DIR:-./keys}"
KEY_SIZE="${KEY_SIZE:-4096}"
PRIVATE_KEY="${KEY_DIR}/private.pem"
PUBLIC_KEY="${KEY_DIR}/public.pem"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Prism JWT Key Generation ===${NC}"
echo ""

# Create keys directory if it doesn't exist
if [ ! -d "$KEY_DIR" ]; then
    echo -e "${YELLOW}Creating keys directory: ${KEY_DIR}${NC}"
    mkdir -p "$KEY_DIR"
fi

# Check if keys already exist
if [ -f "$PRIVATE_KEY" ] || [ -f "$PUBLIC_KEY" ]; then
    echo -e "${YELLOW}Warning: Keys already exist in ${KEY_DIR}${NC}"
    read -p "Do you want to overwrite them? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}Aborted.${NC}"
        exit 1
    fi
fi

# Generate private key
echo -e "${GREEN}Generating ${KEY_SIZE}-bit RSA private key...${NC}"
openssl genrsa -out "$PRIVATE_KEY" "$KEY_SIZE" 2>/dev/null

# Generate public key from private key
echo -e "${GREEN}Extracting public key...${NC}"
openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY" 2>/dev/null

# Set secure permissions
echo -e "${GREEN}Setting secure permissions...${NC}"
chmod 600 "$PRIVATE_KEY"
chmod 644 "$PUBLIC_KEY"

# Verify keys
echo -e "${GREEN}Verifying key pair...${NC}"
if openssl rsa -in "$PRIVATE_KEY" -check -noout 2>/dev/null; then
    echo -e "${GREEN}Private key is valid.${NC}"
else
    echo -e "${RED}Private key validation failed!${NC}"
    exit 1
fi

# Display key information
echo ""
echo -e "${GREEN}=== Key Generation Complete ===${NC}"
echo ""
echo "Private key: $PRIVATE_KEY"
echo "Public key:  $PUBLIC_KEY"
echo "Key size:    $KEY_SIZE bits"
echo ""
echo -e "${YELLOW}Important:${NC}"
echo "- Keep the private key secure and never commit it to version control"
echo "- The public key can be distributed for token verification"
echo "- Rotate keys periodically for security"
echo ""

# Show fingerprint
echo "Public key fingerprint (SHA256):"
openssl rsa -in "$PRIVATE_KEY" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $2}'
