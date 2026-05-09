# DiimeAI Demo App — Android Prerequisites Checklist

Complete every item before building or running the app.
Items marked 🔴 are blockers — the app will crash or fail silently without them.

---

## 1. Google Play Console Setup

### 1.1  Create / verify the app 🔴
| Step | Action |
|------|--------|
| 1 | Sign in to [Google Play Console](https://play.google.com/console) |
| 2 | Create new app → Package name: `com.diimeai.demo` |
| 3 | Fill in app details (title: "DiimeAI", category: Finance) |
| 4 | Note your **App ID** (shown in the console URL: `https://play.google.com/console/u/0/developers/<devId>/app/<appId>`) |

### 1.2  Enable Play Integrity API 🔴
The `EnrollmentManager.requestPlayIntegrityToken()` call will fail with
`IntegrityErrorCode.PLAY_INTEGRITY_API_NOT_AVAILABLE` if this is not done.

| Step | Action |
|------|--------|
| 1 | Go to **Play Console → Your App → Setup → App integrity** |
| 2 | Click **"Link to a Cloud project"** |
| 3 | Select (or create) a **Google Cloud project** |
| 4 | Note the **Google Cloud Project Number** (12-digit number in Cloud Console) |
| 5 | In `app/build.gradle`, replace `YOUR_GOOGLE_CLOUD_PROJECT_NUMBER` with the actual number |
| 6 | Optionally: go to [Google Cloud Console](https://console.cloud.google.com) → APIs → Enable **Play Integrity API** |

> **Why needed?**
> EnrollmentManager calls `IntegrityManagerFactory.create(context).requestIntegrityToken()`
> with `setNonce(sha256Base64(serverNonce))`. Google's servers verify the Play Integrity
> JWS token against your registered app. The backend (`enrollment.py:_verify_play_integrity()`)
> calls `playintegrity.googleapis.com/v1/{package}:decodeIntegrityToken` to verify the token
> contains `MEETS_DEVICE_INTEGRITY` and `PLAY_RECOGNIZED`.

### 1.3  Service Account for Play Integrity backend verification 🔴
The NonaShield backend (`enrollment.py`) calls the Play Integrity API to verify tokens.

| Step | Action |
|------|--------|
| 1 | [Google Cloud Console](https://console.cloud.google.com) → IAM → Service Accounts |
| 2 | Create Service Account: `nonashield-integrity-verifier@<project>.iam.gserviceaccount.com` |
| 3 | Grant role: **Play Integrity API → Integrity Verifier** |
| 4 | Create JSON key → download `service-account.json` |
| 5 | Upload `service-account.json` to EC2: `/opt/nonashield/payshield-backend/config/` |
| 6 | Set in `.env.demo.local`: |
|   | `PLAY_INTEGRITY_PACKAGE_NAME=com.diimeai.demo` |
|   | `GOOGLE_APPLICATION_CREDENTIALS=/opt/nonashield/payshield-backend/config/service-account.json` |

---

## 2. Android Keystore (Release Signing)

### 2.1  Generate release keystore 🔴
Required for: release APK signing + `AppSignatureVerifier.enforce()` (RASP check).

```bash
# Run once — store the keystore file securely (NOT in git)
keytool -genkey -v \
  -keystore diimeai-release.keystore \
  -alias diimeai-key \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000 \
  -storepass YOUR_STORE_PASSWORD \
  -keypass YOUR_KEY_PASSWORD \
  -dname "CN=DiimeAI, OU=Mobile, O=DiimeAI Pvt Ltd, L=Bengaluru, S=Karnataka, C=IN"
```

### 2.2  Compute certificate hash for RASP check
The `AppSignatureVerifier.enforce()` compares the APK's signing cert against
`BuildConfig.EXPECTED_CERT_HASH`. Get the hash AFTER generating the keystore:

```bash
# Extract DER bytes of the certificate
keytool -exportcert \
  -keystore diimeai-release.keystore \
  -alias diimeai-key \
  -storepass YOUR_STORE_PASSWORD \
  -file release-cert.der

# Compute Base64(SHA-256) — this is what EXPECTED_CERT_HASH must contain
openssl dgst -sha256 -binary release-cert.der | base64
# Example output: "Abc123...XYZ="
```

### 2.3  Set environment variables before release build

```bash
export DIIMEAI_KEYSTORE_PATH=/path/to/diimeai-release.keystore
export DIIMEAI_KEY_ALIAS=diimeai-key
export DIIMEAI_STORE_PASSWORD=YOUR_STORE_PASSWORD
export DIIMEAI_KEY_PASSWORD=YOUR_KEY_PASSWORD

# NonaShield SDK RASP checks
export PAYSHIELD_EXPECTED_CERT_HASH="Abc123...XYZ="   # from step 2.2
# EXPECTED_DEX_HASH — computed by CI AFTER classes.dex is built (post-build step)
# PAYSHIELD_BUILD_PIPELINE_HASH — set by CI pipeline
```

---

## 3. NonaShield SDK — Local Build

The demo app depends on `com.payshield:android-sdk:1.0.0` which must be
published to Maven Local before building the demo app.

### 3.1  Build and publish SDK AAR

```bash
cd ../payshield-kmp-sdk

# Publish SDK to ~/.m2/repository (mavenLocal)
./gradlew :android-sdk:publishToMavenLocal

# Verify artifact exists
ls ~/.m2/repository/com/payshield/android-sdk/1.0.0/
# Should show: android-sdk-1.0.0.aar, android-sdk-1.0.0.pom
```

### 3.2  Build demo app

```bash
cd ../app

# Debug build (emulator / local testing)
./gradlew :app:assembleDebug

# Release build (needs signing env vars from step 2.3)
./gradlew :app:assembleRelease
```

---

## 4. Android Device / Emulator Requirements

### 4.1  Physical device requirements (for Play Integrity)

| Requirement | Why |
|-------------|-----|
| Google Play Services installed (7.0+) | `IntegrityManagerFactory.create()` requires GMS |
| Device passes Play Integrity `MEETS_DEVICE_INTEGRITY` | Backend rejects tokens without this verdict |
| Not rooted | Root detection: `MEETS_BASIC_INTEGRITY` will fail; RASP HIGH/CRITICAL signal fired |
| Not running a custom ROM | Same — `PLAY_RECOGNIZED` verdict fails on non-Play builds |
| Android 6.0+ (API 23) | `minSdk = 23` in SDK and demo app |
| StrongBox or TEE available (API 28+) | AndroidKeyStore key generated; falls back to TEE if StrongBox absent |

### 4.2  Emulator limitations

| Feature | Emulator (Google APIs) | Notes |
|---------|----------------------|-------|
| AndroidKeyStore | ✅ Works | ECDSA P-256 key generated normally |
| EncryptedSharedPreferences | ✅ Works | SecureStorage backed |
| Play Integrity attestation | ⚠️ **Returns FAIL in production mode** | Use test mode or disable in `APP_ENV=dev` |
| StrongBox | ❌ Not available | Falls back to software-backed key (insecure; only for dev) |
| RASP signals | ⚠️ Some fire by design | Emulator triggers `EmulatorFingerprintSignal` → MEDIUM risk |

**For demo on emulator:**
- Set `APP_ENV=dev` in `.env.demo.local` → backend skips Play Integrity verification
- RASP emulator signals produce MEDIUM risk (not blocking)

---

## 5. Backend Environment Variables (`.env.demo.local`)

Specific to the DiimeAI demo integration:

```bash
# Play Integrity verification (see step 1.3)
PLAY_INTEGRITY_PACKAGE_NAME=com.diimeai.demo
GOOGLE_APPLICATION_CREDENTIALS=/opt/nonashield/payshield-backend/config/service-account.json

# Apple App Attest (leave blank — Android-only demo)
APPLE_APP_ID=
APPLE_APP_ATTEST_ENV=production

# Demo mode — relaxes attestation for emulator testing
APP_ENV=demo          # Use 'production' for real device with Play Integrity
ENVIRONMENT=demo
```

---

## 6. AndroidManifest.xml — Required Declarations

These are already included in the demo app's manifest. Verify they exist:

```xml
<!-- Merged from SDK AAR — must also be in app manifest for Android 11+ -->
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"
    tools:ignore="QueryAllPackagesPermission" />

<!-- REQUIRED on Android 11+ alongside QUERY_ALL_PACKAGES -->
<queries>
    <intent>
        <action android:name="android.net.VpnService" />
    </intent>
    <intent>
        <action android:name="android.security.INSTALL_CA_CERT" />
    </intent>
</queries>
```

**Google Play Store justification for `QUERY_ALL_PACKAGES`:**
> "This app uses the NonaShield security SDK which requires enumeration of installed VPN
> and CA certificate apps to detect man-in-the-middle network attacks per OWASP MASVS-NETWORK-1.
> No user-installed app data is collected or transmitted."

---

## 7. Network Security Configuration

The demo app's `network_security_config.xml`:
- Blocks all cleartext HTTP in production.
- Allows cleartext to `10.0.2.2` / `localhost` for emulator testing.

For a production build pointing at `api.diimeai.com`, no changes are needed
(TLS 1.3 only via nginx).

---

## 8. FreeRASP (TalsecSecurity) — OPTIONAL but Recommended

The NonaShield SDK includes FreeRASP (`TalsecSecurity-Community:17.0.0`) for
25 additional RASP sensor signals. For the demo it runs automatically.

No extra setup needed — but note:
- FreeRASP detects **debuggable builds** and fires `RASP_DEV_*` signals.
- This means debug APKs on a real device will emit HIGH-risk signals.
- **Always test RASP behaviour with release APK on a physical device.**

---

## 9. Gradle Wrapper

```bash
cd app
# If gradlew is missing, generate it:
gradle wrapper --gradle-version 8.6
chmod +x gradlew
```

---

## 10. Summary — Quick Checklist

```
Pre-build (one-time):
[ ] 1. Play Console: create app with package com.diimeai.demo
[ ] 2. Play Console: enable Play Integrity API → link Cloud project
[ ] 3. Cloud Console: create service account + JSON key → upload to EC2
[ ] 4. Generate release keystore → compute EXPECTED_CERT_HASH
[ ] 5. Set PAYSHIELD_EXPECTED_CERT_HASH env var
[ ] 6. Set DIIMEAI_KEYSTORE_PATH, KEY_ALIAS, STORE_PASSWORD, KEY_PASSWORD
[ ] 7. Update PLAY_CLOUD_PROJECT_NUMBER in app/build.gradle
[ ] 8. Update .env.demo.local with PLAY_INTEGRITY_PACKAGE_NAME + service account path

SDK build:
[ ] 9.  cd payshield-kmp-sdk && ./gradlew :android-sdk:publishToMavenLocal
[ ] 10. Verify ~/.m2/repository/com/payshield/android-sdk/1.0.0/ exists

Demo app build:
[ ] 11. cd app && ./gradlew :app:assembleDebug   (emulator test)
[ ] 12. cd app && ./gradlew :app:assembleRelease  (device / Play Store)

Runtime verification:
[ ] 13. Install on physical device running Android 6+
[ ] 14. First launch: enrollment completes (check Logcat for "[DiimeApp] Enrollment succeeded")
[ ] 15. Login and initiate a payment — verify X-PayShield-Token in nginx logs
[ ] 16. Open https://api.diimeai.com/dashboard/ — verify Grafana shows the request
```

---

## 11. Troubleshooting

| Symptom | Root Cause | Fix |
|---------|-----------|-----|
| `IntegrityErrorCode.PLAY_INTEGRITY_API_NOT_AVAILABLE` | Play Integrity not enabled in Play Console | Step 1.2 |
| `Play Integrity token unavailable` | Emulator in production mode | Set `APP_ENV=dev` in backend |
| `EnrollmentResult.Failure: Backend rejected enrollment: HTTP 503` | `GOOGLE_APPLICATION_CREDENTIALS` not set | Step 1.3 |
| `EnrollmentResult.Failure: Play Integrity nonce mismatch` | SHA-256 encoding mismatch | Use `Base64.NO_WRAP` (not URL_SAFE) for nonce hash |
| `SecurityException: PayShield APK tampering detected` | `EXPECTED_CERT_HASH` mismatch | Recompute hash from current keystore (step 2.2) |
| `IllegalStateException: No active session` | Login not completed before API call | Call `DiimeApiClient.setSession()` after login |
| `NOAUTH Redis error` | Redis password not in entrypoint health check | Already fixed — pull latest backend |
| Nginx returns 444 | `server_name` mismatch | Already fixed — `api.diimeai.com` added |
| `device not found in registry` in nginx logs | Enrollment didn't write Redis keys | Already fixed in `enrollment.py` |
