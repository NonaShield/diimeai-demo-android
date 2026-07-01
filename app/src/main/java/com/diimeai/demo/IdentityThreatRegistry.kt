package com.diimeai.demo

/**
 * Identity & Account Fraud threat catalog for Tab 1 of the investor/CISO demo.
 *
 * Each threat is mapped to live SDK signal types so the table reflects real device state.
 * Protection mechanisms call out the three NonaShield identity pillars:
 *
 *   1. Hardware-bound public key — device identity stored in AndroidKeyStore TEE; cannot
 *      be extracted, copied, or transferred to another SIM. Alias: payshield_device_key.
 *   2. Signed request headers — every outbound request carries:
 *        X-PS-Nonce:        per-request UUID — replay prevention
 *        X-PS-Timestamp:    epoch seconds — staleness check (±30 s)
 *        X-PS-Request-Hash: SHA-256(METHOD|path|body) — payload binding
 *        X-Edge-Risk-Level: 0–100 fused RASP score; NGINX enforces BLOCK ≥70, STEP_UP 40-69
 *   3. Runtime signal detection — RASP signals fire in real time and are encoded into
 *      X-Edge-Risk-Level; the gateway rejects any request whose score exceeds the threshold.
 *
 * `riskScore` is the worst-case score when any listed signal is active. Shown live in the
 * table when active, hidden (–) when safe. `decision` is the enforcement at that score.
 *
 * `detailText` is the full explanation shown in the tap-to-detail dialog. It explains
 * the attack vector, which signals fire, and exactly how the three NonaShield pillars
 * neutralize the threat for this specific use case.
 */
object IdentityThreatRegistry {

    enum class Decision(val label: String, val colorHex: String) {
        BLOCK("BLOCK", "#FF3333"),
        STEP_UP("STEP UP", "#FF8800"),
    }

    data class Threat(
        val name: String,
        val protectionLine: String,   // ≤ 2 table-row lines at 8 sp
        val detailText: String,        // shown in tap-to-detail dialog
        val threatId: String,
        val severity: RaspSensorRegistry.Severity,
        val riskScore: Int,
        val decision: Decision,
        val signalTypes: List<String>,
        // True for threats whose protection is structural (KeyStore TEE / NGINX gateway),
        // not signal-driven. These show "Protected" (teal) rather than Active/Safe so an
        // investor understands the defence is always active — not conditional on signal state.
        val architectureProtected: Boolean = false,
    )

    val ALL: List<Threat> = listOf(

        Threat(
            name = "Credential Harvesting via Overlay",
            protectionLine = "🔑 HW key · 🔍 Overlay detect → X-Edge-Risk-Level: 95 → NGINX enforces BLOCK",
            detailText = """
Attack: A malicious app renders a transparent window over the payment screen, recording keystrokes and stealing credentials before they reach the bank.

How NonaShield blocks it:
The SDK raises OVERLAY_ATTACK_DETECTED the instant any non-system app creates a draw-over window during a sensitive action (PAYMENT / KYC / LOGIN). ACCESSIBILITY_GESTURE_INJECT fires if the attacker also injects synthetic touch events via Accessibility API.

These signals contribute to the X-Edge-Risk-Level header (score 95/100). The NonaShield NGINX gateway reads this header on every inbound request and returns HTTP 403 before credentials are processed — the bank server never receives the stolen data.

X-Edge-Risk-Level is not itself the blocker. It is a number (0–100) carried in the HTTP header. NGINX evaluates the number: ≥ 70 → BLOCK, 40–69 → STEP_UP, < 40 → ALLOW.
            """.trimIndent(),
            threatId = "RASP-ID-001",
            severity = RaspSensorRegistry.Severity.CRITICAL,
            riskScore = 95,
            decision = Decision.BLOCK,
            signalTypes = listOf(
                "OVERLAY_ATTACK_DETECTED",
                "MANDATE_HIJACK_CAPABLE",
                "ACCESSIBILITY_ABUSE",
                "ACCESSIBILITY_GESTURE_INJECT",
            ),
        ),

        Threat(
            name = "Reverse Engineering & App Cloning",
            protectionLine = "🔑 HW key rejects clone · 🔍 APK sig verify + RE tool thread detect",
            detailText = """
Attack: Attacker decompiles the APK with jadx/apktool, patches auth logic or injects a token-stealing SDK, and republishes it. Victims install the cloned app and unknowingly authenticate through the attacker's version.

How NonaShield blocks it:
APP_REPACKAGED fires the moment the running APK's signing certificate differs from the certificate enrolled at bank onboarding. APP_CLONE_DETECTED fires if a second app instance with the same package ID is found. RE_TOOL_THREAD_DETECTED fires if jadx, apktool, or Frida threads are present.

Hardware key defence: the private key (payshield_device_key) lives inside the AndroidKeyStore TEE. A cloned APK installed on any other device has no key — all its requests fail X-PS-Request-Hash signature verification at the gateway and return HTTP 401, regardless of whether the attacker has valid credentials.
            """.trimIndent(),
            threatId = "RASP-ID-002",
            severity = RaspSensorRegistry.Severity.CRITICAL,
            riskScore = 100,
            decision = Decision.BLOCK,
            signalTypes = listOf(
                "APP_REPACKAGED",
                "APP_CLONE_MALICIOUS",
                "APP_CLONE_DETECTED",
                "RE_TOOL_THREAD_DETECTED",
                "REFLECTION_PROTECTED_PACKAGE",
                "CLASS_COUNT_ANOMALY",
                "INJECTED_DEX_IN_PROC_MAPS",
            ),
        ),

        Threat(
            name = "Automated Emulator & Bot Attacks",
            protectionLine = "🔍 Emulator HW fingerprint detect · 📋 X-PS-Nonce prevents replay",
            detailText = """
Attack: Fraudsters run thousands of emulated devices to automate account takeover (ATO), credential stuffing, or OTP enumeration. Emulators spoof device fingerprints to evade basic checks.

How NonaShield blocks it:
EMULATOR_FINGERPRINT fires when hardware signatures (CPU, sensors, display, GSF ID) are inconsistent with a real device. EMULATOR_DETECTED is the FreeRASP deep check for Android emulator runtime characteristics.

Note — signals NOT included here to avoid debug-build false positives:
  • ATTESTATION_NO_CHAIN / ATTESTATION_UNTRUSTED — debug APKs cannot get Play Integrity
    hardware attestation by design; these fire on every debug install.
  • AUTOMATION_FRAMEWORK — Samsung One UI includes UIAutomator infrastructure that triggers
    this on real Samsung devices regardless of an attacker being present.
  • ENROLLMENT_BURST — fires on rapid reinstalls during development.
These signals are still enforced in the production SDK; they are excluded from the demo
table only to prevent false positives on development devices.

Replay defence: X-PS-Nonce is a UUID generated fresh for every request. The gateway rejects any nonce seen in the last 60 seconds, eliminating request replay attacks even if the attacker captures a legitimate request.
            """.trimIndent(),
            threatId = "RASP-ID-003",
            severity = RaspSensorRegistry.Severity.HIGH,
            riskScore = 98,
            decision = Decision.BLOCK,
            signalTypes = listOf(
                "EMULATOR_FINGERPRINT",
                "EMULATOR_DETECTED",
            ),
        ),

        Threat(
            name = "Hooking & Runtime Manipulation",
            protectionLine = "🔑 KeyStore key is hardware-bound, cannot be hooked · 🔍 Frida/Xposed/ptrace → process killed",
            detailText = """
Attack: Tools like Frida, Xposed, and Substrate attach to the running banking process and modify function return values at runtime — bypassing PIN checks, patching biometric results, or dumping decrypted session tokens from memory.

How NonaShield blocks it:
HOOKING_FRAMEWORK fires if Frida server, Xposed Module, or Substrate injection is detected in the process. PTRACE_ATTACHED fires if a debugger is actively attached via ptrace syscall. NATIVE_LIB_TAMPER fires if core native libraries are patched in memory at runtime.

On detection, the SDK terminates the process immediately (Process.killProcess). This is the only category where the SDK kills the app directly — because continued execution risks in-memory key exfiltration.

Note — signals NOT included here to avoid debug-build false positives:
  • APP_TAMPERING — FreeRASP explicitly flags debuggable=true APKs as tampered. Every debug
    build triggers this by design. It fires in production on all non-debug builds.
  • SHELL_MAPPED_IN_PROCESS / SHELL_CHILD_PROCESS_DETECTED — Samsung One UI 8 spawns shell
    child processes as part of its system services; these fire on all Samsung devices
    regardless of any attacker activity.

Hardware defence: even if an attacker delays detection, the private key never leaves the TEE. HmacSHA256 signing happens inside the KeyStore hardware boundary; the key material is never exposed to the app process.
            """.trimIndent(),
            threatId = "RASP-ID-004",
            severity = RaspSensorRegistry.Severity.CRITICAL,
            riskScore = 100,
            decision = Decision.BLOCK,
            signalTypes = listOf(
                "HOOKING_FRAMEWORK",
                "PTRACE_ATTACHED",
                "NATIVE_LIB_TAMPER",
            ),
        ),

        Threat(
            name = "Insecure Local Storage",
            protectionLine = "🔑 Device key in AndroidKeyStore TEE · 🔍 Storage tamper + SDK self-integrity",
            detailText = """
Attack: Attacker gains physical access or uses a root exploit to read the app's internal storage, extracting session tokens, cached credentials, or encryption keys stored in plain text or weakly encrypted files.

How NonaShield blocks it:
All cryptographic key material (payshield_device_key) is stored in the AndroidKeyStore hardware TEE. The key never exists as bytes accessible to the app process — signing operations happen inside the secure enclave. Cached data is encrypted with keys derived from the TEE-resident key.

LOCAL_STORAGE_TAMPERED fires if the on-device integrity database detects unexpected file modifications. SDK_SELF_TAMPER fires if the SDK's own code hash differs from the enrolled value, indicating the app binary was patched after installation.

Both signals push X-Edge-Risk-Level to 85 → NGINX enforces BLOCK on the next request.
            """.trimIndent(),
            threatId = "RASP-ID-005",
            severity = RaspSensorRegistry.Severity.CRITICAL,
            riskScore = 85,
            decision = Decision.BLOCK,
            signalTypes = listOf(
                "LOCAL_STORAGE_TAMPERED",
                "SDK_SELF_TAMPER",
            ),
        ),

        Threat(
            name = "Session Hijacking & Token Theft",
            protectionLine = "🔑 HW-bound JWT · 📋 X-PS-Nonce per request · 🔍 Device anchor mismatch",
            detailText = """
Attack: Attacker steals a valid session JWT from local storage, a network sniff, or a compromised OAuth provider, then replays it from a different device to access the victim's account.

How NonaShield blocks it:
The NonaShield JWT is hardware-bound — it is issued only to the specific device whose X-PS-Request-Hash and X-PS-Nonce match the enrolled payshield_device_key signature. Replaying the token from any other device fails the signature check at the gateway (HTTP 401).

DEVICE_ANCHOR_MISMATCH fires if the hardware identifier diverges from the one stored at session creation (device swap attack). DEVICE_ID_CHANGED fires if the Android ID or hardware ID changes since last session. DEVICE_BINDING fires for profile/account migration anomalies.

X-PS-Nonce additionally prevents replay of the request itself: each nonce is valid for only 60 seconds; replaying a captured request with the same nonce returns HTTP 409 (nonce reuse rejected).
            """.trimIndent(),
            threatId = "RASP-ID-006",
            severity = RaspSensorRegistry.Severity.HIGH,
            riskScore = 90,
            decision = Decision.BLOCK,
            signalTypes = listOf(
                "DEVICE_ANCHOR_MISMATCH",
                "DEVICE_BINDING",
                "DEVICE_ID_CHANGED",
            ),
        ),

        Threat(
            name = "Hardcoded Secrets in App",
            protectionLine = "🔑 Zero secrets in app bytecode — all in AndroidKeyStore TEE (architecture guarantee)",
            detailText = """
Attack: Developers accidentally commit API keys, private keys, or auth tokens directly in source code or resource files. Attackers decompile the APK, extract the secrets, and call bank APIs directly without the app.

How NonaShield eliminates the risk — by architecture, not by signal:
There are NO secrets anywhere in the app binary. All cryptographic operations use keys stored in the AndroidKeyStore TEE (alias: payshield_device_key). The key material never appears in the Kotlin/Java heap, DEX bytecode, or resource files — decompiling the APK yields an empty shell with no extractable secrets.

This protection is ALWAYS active regardless of device state. It is guaranteed by the key storage architecture, not by runtime detection. That is why this row shows "Protected" rather than a live signal status.

Why no live signals? All three candidate signals are false positives on debug builds:
  • OBFUSCATION_RISK — debug builds intentionally have no ProGuard/R8 obfuscation; fires on every debug install.
  • SDK_SELF_TAMPER — the SDK enrolled hash was computed for the production AAR; the debug build hash always differs.
  • ROGUE_BUILD_DETECTED — debug signing certificate never matches the production certificate enrolled in the SDK.
In production (signed release APK, ProGuard enabled), these signals are meaningful and enforced.
            """.trimIndent(),
            threatId = "RASP-ID-007",
            severity = RaspSensorRegistry.Severity.CRITICAL,
            riskScore = 0,
            decision = Decision.BLOCK,
            signalTypes = emptyList(),
            architectureProtected = true,
        ),

        Threat(
            name = "Man-in-the-Middle & Interception",
            protectionLine = "📋 X-PS-Timestamp + SHA-256 payload hash · 🔍 User CA cert + unsecured WiFi detect",
            detailText = """
Attack: Attacker installs a rogue CA certificate on the device, positions themselves between the app and the server (coffee shop WiFi, corporate proxy, malware), and intercepts or modifies API traffic.

How NonaShield blocks it:
USER_CA_CERT fires immediately when a user-installed certificate authority is found in the system trust store — the most reliable indicator of a MITM proxy being set up. UNSECURE_WIFI fires on open networks. SYSTEM_VPN fires if an unexpected VPN tunnel is active (which could route traffic to an attacker-controlled server).

Even if the attacker successfully intercepts the request, X-PS-Request-Hash makes tampering detectable: it is a SHA-256 hash of METHOD|encodedPath|queryParams|body computed from inside the SDK before transmission. Any modification of the body in transit changes the hash, and the gateway rejects the request (HTTP 400 hash mismatch).

X-PS-Timestamp (epoch seconds) prevents replaying a captured unmodified request more than 30 seconds after it was generated.
            """.trimIndent(),
            threatId = "RASP-ID-008",
            severity = RaspSensorRegistry.Severity.HIGH,
            riskScore = 82,
            decision = Decision.STEP_UP,
            signalTypes = listOf(
                "USER_CA_CERT",
                "UNSECURE_WIFI",
                "SYSTEM_VPN",
                "VPN_CONFLICT",
            ),
        ),

        Threat(
            name = "API Exploitation (Bypass App Layer)",
            protectionLine = "📋 NGINX rejects all requests without valid X-PS-Request-Hash (architecture guarantee)",
            detailText = """
Attack: Attacker reverse-engineers the API contract from network traffic or decompiled code and calls the bank's backend directly using curl / Postman — bypassing all client-side RASP checks, certificate pinning, and fraud controls embedded in the app.

How NonaShield blocks it — by gateway architecture, not by runtime signal:
The NonaShield NGINX gateway sits between the internet and the bank's core API. It validates mandatory headers on every inbound request:

  1. X-PS-Request-Hash — SHA-256(METHOD|path|body) signed with the device TEE key.
     Direct API calls cannot produce a valid hash without the hardware key.
     Result: curl/Postman calls → HTTP 401 (signature missing or invalid).

  2. X-Edge-Risk-Level — the fused RASP score from the SDK (0–100).
     Absent or spoofed values default to risk=100 → BLOCK.

  3. X-PS-Nonce — UUID unique per request.
     Replayed or missing nonces → HTTP 409 (nonce reuse rejected).

This protection is ALWAYS active at the gateway level. It is guaranteed by the NGINX enforcement architecture. That is why this row shows "Protected" rather than a live signal status.

Why no live signals? All candidate signals fire on any developer device:
  • ADB_ENABLED / DEVELOPER_MODE / USB_DEBUGGING_ACTIVE / DEVELOPER_OPTIONS_ACTIVE — these
    are ON because you need developer options to install the debug APK via ADB. They fire
    on every development device regardless of any attacker activity.
  • MAVSV_CONTROL_FAILURE — MAVSV controls include obfuscation and production build checks;
    fails on every debug build by design.
In production (developer options off, release APK from Play Store), these signals are meaningful.
            """.trimIndent(),
            threatId = "RASP-ID-009",
            severity = RaspSensorRegistry.Severity.HIGH,
            riskScore = 0,
            decision = Decision.BLOCK,
            signalTypes = emptyList(),
            architectureProtected = true,
        ),

        Threat(
            name = "SIM Swapping / SIM Jacking",
            protectionLine = "🔑 HW key is device-bound, not SIM-portable · 🔍 IMSI + eSIM OTA swap detect",
            detailText = """
Attack: Attacker convinces the telecom operator to port the victim's phone number to a new SIM they control. They then intercept SMS OTPs sent to that number and take over the bank account.

How NonaShield blocks it:
SIM_SWAP_DETECTED fires when the SIM serial number (ICCID) changes between sessions. SIM_DEACTIVATED fires when the SIM transitions to inactive state (mid-swap window). ESIM_OTA_SWAP fires when eSIM provisioning OTA commands are observed. ESIM_MANAGER_APP_DETECTED flags eSIM management apps that could perform a programmatic swap.

Critically: even a successful SIM swap cannot compromise the hardware-bound identity. The private key (payshield_device_key) lives in the device's AndroidKeyStore TEE — it is bound to the physical hardware, not the phone number. Moving the phone number to a new SIM does not transfer the key. Any session attempted from the new SIM fails X-PS-Request-Hash verification at the gateway and returns HTTP 401.

OTP interception is moot: the attacker receives the OTP, but cannot initiate a transaction from a device that lacks the enrolled hardware key.
            """.trimIndent(),
            threatId = "RASP-ID-010",
            severity = RaspSensorRegistry.Severity.CRITICAL,
            riskScore = 95,
            decision = Decision.BLOCK,
            signalTypes = listOf(
                "SIM_DEACTIVATED",
                "SIM_SWAP_DETECTED",
                "ESIM_OTA_SWAP",
                "ESIM_MANAGER_APP_DETECTED",
            ),
        ),

        Threat(
            name = "Magecart & Malicious SDKs",
            protectionLine = "🔍 Malware scan + sideload detect + device admin abuse · SMS intercept flagged pre-OTP",
            detailText = """
Attack: A Magecart-style attack embeds a malicious SDK inside a legitimate-looking app that the victim installs. The malicious SDK intercepts payment card data, OTP messages, or auth tokens and exfiltrates them to attacker infrastructure.

How NonaShield blocks it:
MALWARE_DETECTED — FreeRASP deep malware scanner identifies known malicious SDKs, code patterns, and C2 callback libraries. SIDELOAD_DETECTED fires if the app was installed from a source other than Google Play (APK sideload = high-risk vector for Magecart). DEVICE_ADMIN_ABUSE fires if any app has illegitimate device administrator rights (used by banking trojans to resist uninstall). SMS_INTERCEPT_CAPABLE fires if any installed app holds READ_SMS + RECEIVE_SMS permissions — this is flagged before an OTP is requested, not after.

The SMS_INTERCEPT_CAPABLE signal fires at session initiation (pre-OTP), giving the bank the opportunity to switch to an in-app push OTP or step up to biometric auth before the OTP is even sent, neutralising the interception attack before it begins.
            """.trimIndent(),
            threatId = "RASP-ID-011",
            severity = RaspSensorRegistry.Severity.CRITICAL,
            riskScore = 100,
            decision = Decision.BLOCK,
            signalTypes = listOf(
                "MALWARE_DETECTED",
                "SIDELOAD_DETECTED",
                "DEVICE_ADMIN_ABUSE",
                "SMS_INTERCEPT_CAPABLE",
            ),
        ),
    )
}
