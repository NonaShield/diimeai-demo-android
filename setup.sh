#!/usr/bin/env bash
# =============================================================================
# DiimeAI Demo App — Setup Script
#
# Automates every blocker that can be scripted:
#   1. Generates the Android release keystore
#   2. Computes EXPECTED_CERT_HASH (Base64 SHA-256 of release cert DER bytes)
#   3. Builds the NonaShield SDK AAR and publishes to Maven Local
#   4. Writes a local .env file with signing variables for Gradle
#   5. Builds the debug APK (ready to install on device/emulator)
#
# What this script CANNOT do (requires your accounts — see PREREQUISITES.md):
#   - Register the app in Google Play Console
#   - Enable Play Integrity API in Play Console
#   - Create the Google Cloud service account or download its JSON key
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
#
# Run from the Code/app directory (where this file lives).
# =============================================================================

set -euo pipefail

# ── Colours ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
step()  { echo -e "\n${BOLD}━━━ $* ━━━${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$(cd "$SCRIPT_DIR/../payshield-kmp-sdk" && pwd)"
ENV_FILE="$SCRIPT_DIR/.signing.env"

echo -e "\n${BOLD}DiimeAI Demo App — Setup${NC}"
echo "Script dir : $SCRIPT_DIR"
echo "SDK dir    : $SDK_DIR"
echo ""

# =============================================================================
# Step 1 — Prerequisites check
# =============================================================================
step "1 / 5  Checking prerequisites"

for cmd in keytool openssl java; do
    if ! command -v "$cmd" &>/dev/null; then
        error "$cmd not found. Install JDK 17+ and OpenSSL, then rerun."
    fi
    ok "$cmd found: $(command -v $cmd)"
done

JAVA_VER=$(java -version 2>&1 | head -1 | sed 's/.*version "\([0-9]*\).*/\1/')
if [[ "$JAVA_VER" -lt 17 ]]; then
    error "Java 17+ required (found Java $JAVA_VER). Install JDK 17."
fi
ok "Java version: $JAVA_VER"

# =============================================================================
# Step 2 — Generate release keystore (skips if already exists)
# =============================================================================
step "2 / 5  Release keystore"

KEYSTORE_FILE="$SCRIPT_DIR/diimeai-release.keystore"
KEY_ALIAS="diimeai-key"

if [[ -f "$KEYSTORE_FILE" ]]; then
    ok "Keystore already exists: $KEYSTORE_FILE (skipping generation)"
else
    info "Generating release keystore..."
    echo ""
    echo -e "${YELLOW}You will be prompted for:${NC}"
    echo "  • Keystore password (store it safely — required for every release build)"
    echo "  • Key password      (can be the same as keystore password)"
    echo "  • DN fields         (organisation info — press Enter to use defaults)"
    echo ""

    read -rsp "Enter keystore password (min 6 chars): " STORE_PASS; echo
    read -rsp "Confirm keystore password: " STORE_PASS2; echo
    [[ "$STORE_PASS" == "$STORE_PASS2" ]] || error "Passwords do not match"
    [[ ${#STORE_PASS} -ge 6 ]] || error "Password must be at least 6 characters"

    read -rsp "Enter key password (or press Enter to use same password): " KEY_PASS; echo
    [[ -z "$KEY_PASS" ]] && KEY_PASS="$STORE_PASS"

    keytool -genkey -v \
        -keystore "$KEYSTORE_FILE" \
        -alias "$KEY_ALIAS" \
        -keyalg RSA \
        -keysize 2048 \
        -validity 10000 \
        -storepass "$STORE_PASS" \
        -keypass "$KEY_PASS" \
        -dname "CN=DiimeAI, OU=Mobile, O=DiimeAI, L=Bengaluru, S=Karnataka, C=IN" \
        2>/dev/null

    ok "Keystore generated: $KEYSTORE_FILE"
fi

# Re-read passwords if keystore already existed
if [[ -z "${STORE_PASS:-}" ]]; then
    read -rsp "Enter keystore password to continue: " STORE_PASS; echo
    KEY_PASS="$STORE_PASS"   # assume same; user can override below
    read -rsp "Enter key password (Enter = same as keystore): " KEY_PASS_IN; echo
    [[ -n "$KEY_PASS_IN" ]] && KEY_PASS="$KEY_PASS_IN"
fi

# =============================================================================
# Step 3 — Compute EXPECTED_CERT_HASH (Base64 SHA-256 of cert DER bytes)
# =============================================================================
step "3 / 5  Computing EXPECTED_CERT_HASH"

CERT_DER="/tmp/diimeai-release-cert.der"

keytool -exportcert \
    -keystore "$KEYSTORE_FILE" \
    -alias "$KEY_ALIAS" \
    -storepass "$STORE_PASS" \
    -file "$CERT_DER" \
    2>/dev/null

CERT_HASH=$(openssl dgst -sha256 -binary "$CERT_DER" | openssl base64)
rm -f "$CERT_DER"

ok "EXPECTED_CERT_HASH computed: $CERT_HASH"

# =============================================================================
# Step 4 — Write .signing.env (sourced by Gradle / CI)
# =============================================================================
step "4 / 5  Writing .signing.env"

cat > "$ENV_FILE" <<EOF
# DiimeAI signing env — source this before running ./gradlew assembleRelease
# SECURITY: Do NOT commit this file. It is listed in .gitignore.
export DIIMEAI_KEYSTORE_PATH="$KEYSTORE_FILE"
export DIIMEAI_KEY_ALIAS="$KEY_ALIAS"
export DIIMEAI_STORE_PASSWORD="$STORE_PASS"
export DIIMEAI_KEY_PASSWORD="$KEY_PASS"
export PAYSHIELD_EXPECTED_CERT_HASH="$CERT_HASH"

# Set these after completing the Google Cloud / Play Console steps:
# export PAYSHIELD_EXPECTED_DEX_HASH="<computed by CI post-build>"
# export PAYSHIELD_BUILD_PIPELINE_HASH="<set by CI>"
EOF

chmod 600 "$ENV_FILE"
ok ".signing.env written: $ENV_FILE"

# Ensure it's in .gitignore
if ! grep -q ".signing.env" "$SCRIPT_DIR/.gitignore" 2>/dev/null; then
    echo ".signing.env" >> "$SCRIPT_DIR/.gitignore"
    echo "diimeai-release.keystore" >> "$SCRIPT_DIR/.gitignore"
    ok "Added .signing.env and keystore to .gitignore"
fi

# =============================================================================
# Step 5 — Build NonaShield SDK AAR → Maven Local
# =============================================================================
step "5 / 5  Building NonaShield SDK"

GRADLEW="$SDK_DIR/gradlew"
if [[ ! -f "$GRADLEW" ]]; then
    warn "gradlew not found at $SDK_DIR/gradlew"
    warn "Run: cd $SDK_DIR && gradle wrapper --gradle-version 8.6"
    warn "Then rerun this script."
else
    info "Publishing android-sdk AAR to Maven Local..."
    (cd "$SDK_DIR" && ./gradlew :android-sdk:publishToMavenLocal --quiet)
    ok "SDK published to ~/.m2/repository/com/payshield/android-sdk/"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  Setup complete!${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Keystore    : $KEYSTORE_FILE"
echo "  Cert hash   : $CERT_HASH"
echo "  Signing env : $ENV_FILE"
echo ""
echo -e "${YELLOW}${BOLD}  Remaining manual steps (require Google accounts):${NC}"
echo ""
echo "  1. Play Console  → Create app with package: com.diimeai.demo"
echo "     https://play.google.com/console"
echo ""
echo "  2. Play Console  → App → Setup → App Integrity"
echo "     Click 'Link Cloud project' → note your Cloud Project Number"
echo "     Paste it into: app/app/build.gradle → PLAY_CLOUD_PROJECT_NUMBER"
echo ""
echo "  3. Cloud Console → IAM → Service Accounts → Create"
echo "     Role: Play Integrity API Verifier + Service Account Token Creator"
echo "     Keys → Add Key → JSON → Download → rename to google-service-account.json"
echo "     Upload to EC2:"
echo "       scp google-service-account.json ubuntu@<EC2_HOST>:\\"
echo "           /opt/nonashield/payshield-backend/config/"
echo "     (PLAY_INTEGRITY_PACKAGE_NAME and GOOGLE_APPLICATION_CREDENTIALS"
echo "      are already templated in ../payshield-backend/.env.demo)"
echo ""
echo -e "${YELLOW}${BOLD}  Build the debug APK:${NC}"
echo ""
echo "  source $ENV_FILE"
echo "  ./gradlew :app:assembleDebug"
echo "  adb install app/build/outputs/apk/debug/app-debug.apk"
echo ""
echo -e "${YELLOW}${BOLD}  Build the release APK:${NC}"
echo ""
echo "  source $ENV_FILE"
echo "  ./gradlew :app:assembleRelease"
echo "  adb install app/build/outputs/apk/release/app-release.apk"
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
