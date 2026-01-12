#!/usr/bin/env bash
#
# Run once after cloning
# macOS and Linux compatible, idempotent, colored line-level output
# Automatically sets up pre-commit hook

set -Eeuo pipefail

# Create secure temporary directory and ensure cleanup on exit
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# ---------- Colors ----------
RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'

fail() {
  echo -e "${RED}❌ PRE-COMMIT BLOCKED${RESET}"
  echo -e "${RED}$1${RESET}"
  exit 1
}

echo -e "${YELLOW}⚡ Setting up STRICT MODE pre-commit hook...${RESET}"

# ---------- Platform ----------
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
  darwin) OS="darwin" ;;
  linux) OS="linux" ;;
  *) fail "Unsupported operating system: $OS (only darwin and linux are supported)" ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) fail "Unsupported architecture: $ARCH" ;;
esac

# ---------- Paths ----------
GITLEAKS_BIN_DIR=".gitleaks/bin"
GITLEAKS_BIN="$GITLEAKS_BIN_DIR/gitleaks"
VERSION_FILE="$GITLEAKS_BIN_DIR/VERSION"
HOOK_FILE=".git/hooks/pre-commit"

mkdir -p "$GITLEAKS_BIN_DIR" ".git/hooks"

# ---------- Fetch latest version ----------
LATEST_VERSION="$(
  curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
  | grep '"tag_name"' | head -n1 | cut -d'"' -f4
)" || fail "Unable to reach GitHub API to fetch Gitleaks version"

[ -n "$LATEST_VERSION" ] || fail "Empty Gitleaks version received"

CACHED_VERSION=""
[ -f "$VERSION_FILE" ] && CACHED_VERSION="$(cat "$VERSION_FILE")"

# ---------- Install or update Gitleaks ----------
if [ ! -x "$GITLEAKS_BIN" ] || [ "$CACHED_VERSION" != "$LATEST_VERSION" ]; then
  echo -e "${YELLOW}📥 Installing or updating Gitleaks...${RESET}"

  if [ -x "$GITLEAKS_BIN" ]; then
    echo -e "${YELLOW}ℹ New Gitleaks version detected: ${CACHED_VERSION} → ${LATEST_VERSION}${RESET}"
  else
    echo -e "${YELLOW}ℹ Gitleaks not found locally. Installing version ${LATEST_VERSION}${RESET}"
  fi

  ASSET="gitleaks_${LATEST_VERSION#v}_${OS}_${ARCH}.tar.gz"
  URL="https://github.com/gitleaks/gitleaks/releases/download/${LATEST_VERSION}/${ASSET}"
  TMP="$TMP_DIR/$ASSET"

  curl -fsSL "$URL" -o "$TMP" || fail "Failed to download Gitleaks binary"
  tar -xzf "$TMP" -C "$GITLEAKS_BIN_DIR" || fail "Failed to extract Gitleaks archive"
  chmod +x "$GITLEAKS_BIN" || fail "Failed to make Gitleaks executable"
  echo "$LATEST_VERSION" > "$VERSION_FILE"

  echo -e "${GREEN}✅ Gitleaks ${LATEST_VERSION} installed${RESET}"
else
  echo -e "${GREEN}✔ Gitleaks is up-to-date (version ${CACHED_VERSION})${RESET}"
fi

# ---------- Validate binary ----------
"$GITLEAKS_BIN" version >/dev/null 2>&1 || fail "Gitleaks binary is not executable or corrupted"

# ---------- Install STRICT MODE pre-commit hook ----------
# Check if hook already contains Gitleaks logic
if [ -f "$HOOK_FILE" ]; then
  if grep -q "GITLEAKS_BIN=.*gitleaks" "$HOOK_FILE"; then
    echo -e "${GREEN}✔ Pre-commit hook with Gitleaks already installed${RESET}"
  else
    fail "Pre-commit hook already exists without Gitleaks logic.\nPlease manually merge the Gitleaks hook or remove $HOOK_FILE and re-run this script."
  fi
else
  cat > "$HOOK_FILE" << 'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'

fail() {
  echo -e "${RED}❌ PRE-COMMIT BLOCKED${RESET}"
  echo -e "${RED}$1${RESET}"
  exit 1
}

GITLEAKS_BIN=".gitleaks/bin/gitleaks"

STAGED_FILES="$(git diff --cached --name-only --diff-filter=ACMR)"
if [ -z "$STAGED_FILES" ]; then
  echo -e "${GREEN}✔ No staged files to scan${RESET}"
  exit 0
fi

# Optional .gitleaksignore
IGNORE_ARGS=()
if [ -f ".gitleaksignore" ]; then
  IGNORE_ARGS+=(--gitleaks-ignore-path=.gitleaksignore)
  echo -e "${YELLOW}ℹ Using .gitleaksignore${RESET}"
fi

set +e
# Use parameter expansion to safely handle empty array with set -u
RAW_OUTPUT="$("$GITLEAKS_BIN" protect --staged -v ${IGNORE_ARGS[@]+"${IGNORE_ARGS[@]}"} 2>&1)"
SCAN_EXIT=$?
set -e

if [ "$SCAN_EXIT" -gt 1 ]; then
  fail "Gitleaks execution error:\n$RAW_OUTPUT"
fi

if [ "$SCAN_EXIT" -eq 1 ]; then
  echo -e "${RED}❌ SECRETS DETECTED${RESET}"
  echo "──────────────────── DETAILS ────────────────────"

  # Pretty-print output line by line with colors using shell parameter expansion
  echo "$RAW_OUTPUT" | while IFS=: read -r file rest; do
    echo -e "${YELLOW}${file}${RESET}:${RED}${rest}${RESET}"
  done

  echo "─────────────────────────────────────────────────"
  fail "Remove or rotate secrets before committing"
fi

echo -e "${GREEN}✅ Secret scan passed${RESET}"
exit 0
EOF

  chmod +x "$HOOK_FILE"
  echo -e "${GREEN}✅ Pre-commit hook installed at $HOOK_FILE${RESET}"
fi

echo -e "${GREEN}🎉 Setup complete! Pre-commit hook will run automatically on commits.${RESET}"