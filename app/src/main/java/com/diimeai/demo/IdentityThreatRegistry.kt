package com.diimeai.demo

/**
 * Identity & Account Fraud threat catalog for Tab 1 of the investor/CISO demo.
 *
 * Each threat is mapped to live SDK signal types so the table reflects real device state.
 * Protection mechanisms call out the three NonaShield identity pillars:
 *   1. Hardware-bound public key — device identity stored in AndroidKeyStore TEE; cannot
 *      be extracted, copied, or transferred to another SIM.
 *   2. Signed request headers — X-PS-Nonce (per-request UUID), X-PS-Timestamp (epoch sec),
 *      X-PS-Request-Hash (SHA-256 of METHOD+path+body); NGINX rejects any request that
 *      omits or spoofs these headers.
 *   3. Runtime signal detection — RASP signals fire in real time; X-Edge-Risk-Level header
 *      carries the fused score to the gateway, which enforces BLOCK / STEP_UP.
 *
 * `riskScore` is the worst-case risk score the backend assigns when ANY signalType is active.
 * `decision` is the NonaShield enforcement action at that score.
 */
object IdentityThreatRegistry {

    enum class Decision(val label: String, val colorHex: String) {
        BLOCK("BLOCK", "#FF3333"),
        STEP_UP("STEP UP", "#FF8800"),
    }

    data class Threat(
        val name: String,
        val protectionLine: String,   // ≤ 2 display lines at 8 sp
        val threatId: String,
        val severity: RaspSensorRegistry.Severity,
        val riskScore: Int,
        val decision: Decision,
        val signalTypes: List<String>,
    )

    val ALL: List<Threat> = listOf(

        Threat(
            name = "Credential Harvesting via Overlay",
            protectionLine = "🔑 HW key · 🔍 Overlay/tapjacking detect → X-Edge-Risk BLOCK",
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
            protectionLine = "🔑 HW key rejects clone · 🔍 APK sig + RE tool thread detect",
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
            protectionLine = "📋 X-PS-Nonce replay-proof · 🔍 HW attest + emulator fingerprint",
            threatId = "RASP-ID-003",
            severity = RaspSensorRegistry.Severity.HIGH,
            riskScore = 98,
            decision = Decision.BLOCK,
            signalTypes = listOf(
                "ATTESTATION_NO_CHAIN",
                "ATTESTATION_UNTRUSTED",
                "EMULATOR_FINGERPRINT",
                "EMULATOR_DETECTED",
                "AUTOMATION_FRAMEWORK",
                "ENROLLMENT_BURST",
            ),
        ),

        Threat(
            name = "Hooking & Runtime Manipulation",
            protectionLine = "🔑 KeyStore key unhookable · 🔍 Frida/Xposed/ptrace → process kill",
            threatId = "RASP-ID-004",
            severity = RaspSensorRegistry.Severity.CRITICAL,
            riskScore = 100,
            decision = Decision.BLOCK,
            signalTypes = listOf(
                "HOOKING_FRAMEWORK",
                "PTRACE_ATTACHED",
                "NATIVE_LIB_TAMPER",
                "APP_TAMPERING",
                "SHELL_MAPPED_IN_PROCESS",
                "SHELL_CHILD_PROCESS_DETECTED",
            ),
        ),

        Threat(
            name = "Insecure Local Storage",
            protectionLine = "🔑 AndroidKeyStore TEE · 🔍 Storage tamper + SDK self-integrity check",
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
            protectionLine = "🔑 HW-bound JWT · 📋 X-PS-Nonce per-req · 🔍 Device anchor mismatch",
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
            name = "Hardcoded Secrets in APK",
            protectionLine = "🔑 Zero APK secrets — KeyStore only · 🔍 Rogue build detect",
            threatId = "RASP-ID-007",
            severity = RaspSensorRegistry.Severity.CRITICAL,
            riskScore = 88,
            decision = Decision.BLOCK,
            signalTypes = listOf(
                "ROGUE_BUILD_DETECTED",
                "SDK_SELF_TAMPER",
                "OBFUSCATION_RISK",
            ),
        ),

        Threat(
            name = "Man-in-the-Middle & Interception",
            protectionLine = "📋 X-PS-Timestamp + SHA-256 payload hash · 🔍 Cert pin + user CA detect",
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
            protectionLine = "📋 NGINX requires X-PS-Request-Hash + valid risk-level; direct calls → 401",
            threatId = "RASP-ID-009",
            severity = RaspSensorRegistry.Severity.HIGH,
            riskScore = 88,
            decision = Decision.BLOCK,
            signalTypes = listOf(
                "MASVS_CONTROL_FAILURE",
                "ADB_ENABLED",
                "DEVELOPER_MODE",
                "USB_DEBUGGING_ACTIVE",
                "DEVELOPER_OPTIONS_ACTIVE",
            ),
        ),

        Threat(
            name = "SIM Swapping / SIM Jacking",
            protectionLine = "🔑 HW key non-portable to new SIM · 🔍 IMSI + eSIM OTA swap detect",
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
            protectionLine = "🔍 Malware scan + sideload detect + device admin abuse; SMS intercept flagged pre-OTP",
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
