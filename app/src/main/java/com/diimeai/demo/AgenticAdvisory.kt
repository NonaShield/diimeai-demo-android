package com.diimeai.demo

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Agentic AI Root Cause Advisory engine.
 *
 * For each RASP signal type, provides a structured root-cause analysis that the
 * NonaShield SOC / CISO sees when tapping an ACTIVE identity threat row.
 *
 * Each [SignalCause] entry maps a signal type string to:
 *   - rootCause:       what technical condition triggered the signal
 *   - likelyOrigin:    real-world attacker tool or scenario
 *   - riskAssessment:  what the attacker may be doing right now
 *   - socAction:       recommended immediate SOC / enforcement response
 *
 * [buildAdvisory] assembles the formatted dialog message from the active signals
 * belonging to a given [IdentityThreatRegistry.Threat].
 */
object AgenticAdvisory {

    data class SignalCause(
        val signalType: String,
        val rootCause: String,
        val likelyOrigin: String,
        val riskAssessment: String,
        val confidence: String,   // HIGH / MEDIUM / LOW
        val socAction: String,
    )

    private val CAUSES: Map<String, SignalCause> = mapOf(

        // ── Overlay & Accessibility ──────────────────────────────────────────────
        "OVERLAY_ATTACK_DETECTED" to SignalCause(
            signalType    = "OVERLAY_ATTACK_DETECTED",
            rootCause     = "A non-system application is drawing a transparent window over the banking session, capturing screen content or intercepting touch events before they reach the app.",
            likelyOrigin  = "Banking trojan (BankBot, Anubis, Cerberus variant) or credential-harvesting overlay app",
            riskAssessment = "Credentials entered on this screen may be captured by the attacker's overlay before reaching the bank's secure input field.",
            confidence    = "HIGH",
            socAction     = "Block transaction immediately. Flag account for 24-hour monitoring. Prompt user to uninstall unknown overlay apps.",
        ),
        "MANDATE_HIJACK_CAPABLE" to SignalCause(
            signalType    = "MANDATE_HIJACK_CAPABLE",
            rootCause     = "An installed app holds SYSTEM_ALERT_WINDOW (draw-over-apps) permission AND has an active running service — the precondition for UI redress / clickjacking on mandate approval screens.",
            likelyOrigin  = "Potentially malicious app pre-positioned to hijack the next mandate or payment approval tap",
            riskAssessment = "User may unknowingly approve a fraudulent mandate believing they are interacting with the genuine bank UI.",
            confidence    = "MEDIUM",
            socAction     = "Step-up authentication required. Log mandate approval with extra evidence. Advise user to review installed apps.",
        ),
        "ACCESSIBILITY_ABUSE" to SignalCause(
            signalType    = "ACCESSIBILITY_ABUSE",
            rootCause     = "An Accessibility Service with broad privileges (perform gestures, read screen content, observe windows) is active and not on the bank's trusted app whitelist.",
            likelyOrigin  = "Spyware or Remote Access Trojan (RAT) using Android Accessibility to observe and control the device remotely",
            riskAssessment = "Attacker may have full read/write access to screen content and can inject taps — functionally equivalent to remote device control.",
            confidence    = "HIGH",
            socAction     = "Block session. Terminate transaction. Report to security team for device investigation.",
        ),
        "ACCESSIBILITY_GESTURE_INJECT" to SignalCause(
            signalType    = "ACCESSIBILITY_GESTURE_INJECT",
            rootCause     = "An Accessibility Service is actively dispatching synthetic gesture events into this application's window.",
            likelyOrigin  = "Bot framework or RAT performing automated button taps on behalf of a remote attacker",
            riskAssessment = "Actions being taken in this session may not originate from the legitimate user — the device may be under remote control.",
            confidence    = "HIGH",
            socAction     = "Reject all actions in this session. Require re-authentication from a clean device.",
        ),

        // ── App Integrity ────────────────────────────────────────────────────────
        "APP_REPACKAGED" to SignalCause(
            signalType    = "APP_REPACKAGED",
            rootCause     = "The running APK's code signing certificate does not match the certificate enrolled at bank onboarding. The app has been re-signed by a third party.",
            likelyOrigin  = "Attacker decompiled the APK, injected a malicious payload or credential-stealing SDK, and re-signed with their own certificate",
            riskAssessment = "This is NOT the legitimate bank app. All data entered in this session is accessible to the attacker who repackaged it.",
            confidence    = "HIGH",
            socAction     = "Block session immediately. Invalidate all tokens for this account. Alert the user to download only from the official Play Store.",
        ),
        "APP_CLONE_MALICIOUS" to SignalCause(
            signalType    = "APP_CLONE_MALICIOUS",
            rootCause     = "A second instance of this app with identical package name but different certificate is installed alongside the genuine app.",
            likelyOrigin  = "Clone app from unofficial source, or dual-space/parallel-space app used to run a modified version of the bank app",
            riskAssessment = "Transactions conducted in the cloned app bypass all genuine security controls.",
            confidence    = "HIGH",
            socAction     = "Block. Require uninstallation of clone before re-enabling the account.",
        ),
        "APP_CLONE_DETECTED" to SignalCause(
            signalType    = "APP_CLONE_DETECTED",
            rootCause     = "Multiple app instances with this package ID detected. May be running in a Dual Space / Parallel Space container.",
            likelyOrigin  = "Dual-space apps (VMOS, Virtual Android) used to compartmentalise a modified banking app away from device security scanning",
            riskAssessment = "The active session may be from the containerised clone rather than the genuine production app.",
            confidence    = "MEDIUM",
            socAction     = "Step-up auth. Verify session is from the enrolled device fingerprint.",
        ),

        // ── Emulator / Bot ───────────────────────────────────────────────────────
        "EMULATOR_FINGERPRINT" to SignalCause(
            signalType    = "EMULATOR_FINGERPRINT",
            rootCause     = "Device hardware profile (CPU model, sensor set, display DPI, GSF Android ID, build fingerprint) is inconsistent with a genuine Android device.",
            likelyOrigin  = "Android emulator (AVD/Genymotion/NoxPlayer/LDPlayer) or cloud device farm with spoofed hardware identifiers",
            riskAssessment = "This session is likely automated. Attacker may be running credential-stuffing or OTP-enumeration scripts at scale.",
            confidence    = "HIGH",
            socAction     = "Block session. Flag originating IP/account for bulk-automation investigation.",
        ),
        "EMULATOR_DETECTED" to SignalCause(
            signalType    = "EMULATOR_DETECTED",
            rootCause     = "Android runtime characteristics indicate an emulated environment: QEMU artefacts, goldfish kernel properties, or emulator build prop values detected.",
            likelyOrigin  = "Android Studio AVD, rooted emulator, or cloud test-farm device used for automated fraud",
            riskAssessment = "Account takeover bot conducting automated login attempts or payment approvals.",
            confidence    = "HIGH",
            socAction     = "Block session. Add device fingerprint to deny-list. Trigger CAPTCHA challenge.",
        ),
        "AUTOMATION_FRAMEWORK" to SignalCause(
            signalType    = "AUTOMATION_FRAMEWORK",
            rootCause     = "An active UiAutomation connection or instrumentation test runner is bound to the process. On Samsung One UI, this can also be triggered by Samsung's system diagnostic and Smart Switch services which register UiAutomation accessibility connections.",
            likelyOrigin  = "On developer devices: Samsung system services (Smart Switch, Device Care). On production devices: Appium/UIAutomator-based bot framework or automated test harness used for fraud",
            riskAssessment = "On a production non-developer device this signal indicates automated script execution against the banking app.",
            confidence    = "MEDIUM",
            socAction     = "Verify device is not a developer/test device. On production devices: block and investigate.",
        ),

        // ── Hooking & Runtime ────────────────────────────────────────────────────
        "HOOKING_FRAMEWORK" to SignalCause(
            signalType    = "HOOKING_FRAMEWORK",
            rootCause     = "Frida or Xposed is injected — a hooking tool is intercepting app function calls in real time.",
            likelyOrigin  = "Attacker using Frida/Xposed to bypass PIN or biometric checks, or to steal session tokens",
            riskAssessment = "Every function call in the app — login, payment approval, encryption — can be watched or altered.",
            confidence    = "HIGH",
            socAction     = "SDK terminated the session. Invalidate all active sessions for this account.",
        ),
        "PTRACE_ATTACHED" to SignalCause(
            signalType    = "PTRACE_ATTACHED",
            rootCause     = "A debugger is attached to the app — by design this gives read/write access to every byte in memory.",
            likelyOrigin  = "ADB debugger (developer device) or malware reading decrypted keys and tokens from memory",
            riskAssessment = "Session tokens, PINs, and crypto keys are readable from app memory in plain text.",
            confidence    = "HIGH",
            socAction     = "SDK terminated the session. Treat all data from this session as compromised.",
        ),
        "NATIVE_LIB_TAMPER" to SignalCause(
            signalType    = "NATIVE_LIB_TAMPER",
            rootCause     = "Security libraries were swapped at runtime — the in-memory binary differs from the signed original.",
            likelyOrigin  = "LD_PRELOAD injection or Frida hook replacing native cert pinning or key derivation code",
            riskAssessment = "Certificate pinning and key checks may have been silently replaced with attacker-controlled code.",
            confidence    = "HIGH",
            socAction     = "SDK terminated the session. Require device re-enrollment before allowing access.",
        ),
        "APP_TAMPERING" to SignalCause(
            signalType    = "APP_TAMPERING",
            rootCause     = "APK integrity check failed — on debug builds this fires because debuggable=true is treated as tampered, by design.",
            likelyOrigin  = "On debug builds: expected developer signal. On production: attacker patched DEX bytecode after signing.",
            riskAssessment = "On production: app code modified post-signing. Core security logic may be bypassed.",
            confidence    = "HIGH",
            socAction     = "On production: block immediately. Require reinstall from Play Store.",
        ),

        // ── Device Integrity ─────────────────────────────────────────────────────
        "ROOT_OR_JAILBREAK" to SignalCause(
            signalType    = "ROOT_OR_JAILBREAK",
            rootCause     = "Device has a rooted or unlocked bootloader, giving any process root-level access to system files, other app data, and hardware resources.",
            likelyOrigin  = "Magisk, KernelSU, APatch, or unlocked bootloader — may be attacker-controlled or user-modified device",
            riskAssessment = "All app data, including session tokens and cached credentials, is accessible to any other root-capable app on the device.",
            confidence    = "HIGH",
            socAction     = "Block financial transactions. Advisory: proceed at reduced limit with mandatory step-up.",
        ),
        "DEBUGGER_DETECTED" to SignalCause(
            signalType    = "DEBUGGER_DETECTED",
            rootCause     = "A Java debugger (JDWP) is attached to this process, enabling step-through execution, variable inspection, and breakpoint setting.",
            likelyOrigin  = "Android Studio debugger via ADB, or attacker using jdb to reverse-engineer authentication flow at runtime",
            riskAssessment = "Attacker can pause execution at any point and inspect the full application state.",
            confidence    = "HIGH",
            socAction     = "SDK has terminated the process.",
        ),

        // ── Session & Token ──────────────────────────────────────────────────────
        "DEVICE_ANCHOR_MISMATCH" to SignalCause(
            signalType    = "DEVICE_ANCHOR_MISMATCH",
            rootCause     = "The hardware device identifier used to anchor this session has changed since the session token was issued, indicating the token is being replayed from a different physical device.",
            likelyOrigin  = "Stolen JWT being used on attacker's own device, or device ID spoofing tool",
            riskAssessment = "Session token theft confirmed. Attacker is attempting to access the account from an unenrolled device.",
            confidence    = "HIGH",
            socAction     = "Invalidate session immediately. Force re-authentication with hardware key on the enrolled device.",
        ),
        "DEVICE_ID_CHANGED" to SignalCause(
            signalType    = "DEVICE_ID_CHANGED",
            rootCause     = "The Android device identifier (Android ID or hardware serial) has changed since the last authenticated session.",
            likelyOrigin  = "Device ID spoofing app, factory reset followed by re-enrollment attempt, or ATO using a different device with the same credentials",
            riskAssessment = "This may be a new/replaced device (legitimate) or an account takeover attempt using stolen credentials on a different device.",
            confidence    = "MEDIUM",
            socAction     = "Require device re-enrollment with biometric verification. Notify user of new device login.",
        ),
        "DEVICE_BINDING" to SignalCause(
            signalType    = "DEVICE_BINDING",
            rootCause     = "Device fingerprint binding anomaly detected — the enrolled device profile does not match the current runtime hardware profile.",
            likelyOrigin  = "Profile migration, device clone, or virtual Android environment (VMOS)",
            riskAssessment = "Session may not originate from the enrolled physical device.",
            confidence    = "MEDIUM",
            socAction     = "Step-up authentication. Re-verify device enrollment.",
        ),

        // ── SIM ─────────────────────────────────────────────────────────────────
        "SIM_SWAP_DETECTED" to SignalCause(
            signalType    = "SIM_SWAP_DETECTED",
            rootCause     = "The SIM card ICCID (serial number) or IMSI has changed since the last authenticated session. A different SIM is now in the device.",
            likelyOrigin  = "SIM swap attack: attacker convinced telecom operator to port the victim's number to an attacker-controlled SIM",
            riskAssessment = "Attacker now receives all SMS OTPs sent to this phone number. Traditional OTP-based 2FA is fully bypassed.",
            confidence    = "HIGH",
            socAction     = "Block OTP delivery to this number. Require alternative step-up (in-app hardware key). Alert fraud team immediately.",
        ),
        "SIM_DEACTIVATED" to SignalCause(
            signalType    = "SIM_DEACTIVATED",
            rootCause     = "The primary SIM has entered a deactivated state — the mid-swap window where the old SIM goes offline before the new SIM activates.",
            likelyOrigin  = "SIM swap in progress at the telecom operator",
            riskAssessment = "Within minutes, the attacker's SIM will receive all SMS OTPs for this number.",
            confidence    = "HIGH",
            socAction     = "Freeze account. Block all SMS-based OTP delivery. Alert user via registered email.",
        ),
        "ESIM_OTA_SWAP" to SignalCause(
            signalType    = "ESIM_OTA_SWAP",
            rootCause     = "eSIM OTA (Over-The-Air) provisioning commands were observed — an eSIM profile is being downloaded or activated.",
            likelyOrigin  = "eSIM SIM swap: attacker requested remote eSIM provisioning to receive the victim's number on their device",
            riskAssessment = "Attacker's device is being provisioned to receive SMS OTPs sent to the victim's number.",
            confidence    = "HIGH",
            socAction     = "Freeze account. Contact telecom operator to halt eSIM provisioning. Alert user.",
        ),
        "ESIM_MANAGER_APP_DETECTED" to SignalCause(
            signalType    = "ESIM_MANAGER_APP_DETECTED",
            rootCause     = "An eSIM management application with the ability to provision, swap, or delete eSIM profiles is installed and active.",
            likelyOrigin  = "Attacker-installed eSIM management app, or carrier-provided app being misused for SIM swap",
            riskAssessment = "Precondition for programmatic eSIM swap is in place on this device.",
            confidence    = "MEDIUM",
            socAction     = "Flag account. Monitor for SIM change events. Prompt user to verify eSIM apps.",
        ),

        // ── Network ──────────────────────────────────────────────────────────────
        "USER_CA_CERT" to SignalCause(
            signalType    = "USER_CA_CERT",
            rootCause     = "A user-installed (non-system) Certificate Authority is in the device trust store. This is the standard setup for a TLS MITM proxy.",
            likelyOrigin  = "Attacker has installed a proxy CA (Burp Suite, Charles Proxy, mitmproxy) to intercept and decrypt TLS traffic",
            riskAssessment = "All HTTPS traffic from this device may be decrypted and read by the owner of the installed CA, even if the app uses certificate pinning at the SDK layer.",
            confidence    = "HIGH",
            socAction     = "Step-up auth. Warn user to remove untrusted CA. Consider blocking until CA is removed.",
        ),
        "UNSECURE_WIFI" to SignalCause(
            signalType    = "UNSECURE_WIFI",
            rootCause     = "Device is connected to an open WiFi network with no WPA2/WPA3 encryption.",
            likelyOrigin  = "Public WiFi hotspot (café, airport, hotel) — anyone on the same network can perform passive traffic analysis or ARP spoofing",
            riskAssessment = "Network-layer MITM is possible. Traffic may be observable to other network participants.",
            confidence    = "MEDIUM",
            socAction     = "Advisory warning to user. Step-up auth for high-value transactions.",
        ),
        "VPN_CONFLICT" to SignalCause(
            signalType    = "VPN_CONFLICT",
            rootCause     = "A VPN app is active that conflicts with the bank's expected network path or is categorised as a high-risk anonymisation service.",
            likelyOrigin  = "Geo-spoofing VPN used to bypass location-based fraud controls, or attacker routing traffic through a proxy VPN",
            riskAssessment = "Transaction geo-location signals are unreliable. Velocity checks based on location are bypassed.",
            confidence    = "MEDIUM",
            socAction     = "Step-up auth. Apply geo-independent risk scoring.",
        ),

        // ── Malware ──────────────────────────────────────────────────────────────
        "MALWARE_DETECTED" to SignalCause(
            signalType    = "MALWARE_DETECTED",
            rootCause     = "FreeRASP deep malware scan identified an installed application matching known malicious SDK signatures, C2 callback patterns, or banking trojan code.",
            likelyOrigin  = "Banking trojan (Anubis, BankBot, SharkBot, Cerberus, Alien variant) installed from sideload or compromised app store",
            riskAssessment = "Malware on device can intercept credentials, OTPs, push notifications, and overlay legitimate UI. Device is under active compromise.",
            confidence    = "HIGH",
            socAction     = "Block all transactions. Force logout. Require clean device re-enrollment. Alert fraud team.",
        ),
        "SIDELOAD_DETECTED" to SignalCause(
            signalType    = "SIDELOAD_DETECTED",
            rootCause     = "The application was installed from a source other than Google Play Store — sideloaded via ADB or downloaded directly as an APK.",
            likelyOrigin  = "Unofficial APK mirror, phishing page distributing fake bank app, or attacker-controlled distribution channel",
            riskAssessment = "Sideloaded APKs bypass Google Play Protect malware scanning. This may be a modified or fake version of the bank app.",
            confidence    = "HIGH",
            socAction     = "Block. Require reinstall from official Play Store.",
        ),
        "SMS_INTERCEPT_CAPABLE" to SignalCause(
            signalType    = "SMS_INTERCEPT_CAPABLE",
            rootCause     = "An installed app holds both READ_SMS and RECEIVE_SMS permissions — the minimum capability required to silently intercept and forward OTP messages without user awareness.",
            likelyOrigin  = "Banking trojan, spyware, or stalkerware pre-positioned to steal OTPs before they are read by the user",
            riskAssessment = "Any OTP sent via SMS to this device may be forwarded to an attacker before the user sees it.",
            confidence    = "HIGH",
            socAction     = "Switch OTP delivery to in-app push (hardware key verified). Do not send SMS OTP to this device.",
        ),
        "DEVICE_ADMIN_ABUSE" to SignalCause(
            signalType    = "DEVICE_ADMIN_ABUSE",
            rootCause     = "An application has been granted Device Administrator rights — enabling it to enforce policies, wipe the device, lock the screen, and resist uninstallation.",
            likelyOrigin  = "Banking trojan using Device Admin to make itself impossible to uninstall (common Anubis/Cerberus technique)",
            riskAssessment = "Malware has entrenched itself with OS-level privileges. Standard uninstall will fail. Device may be under persistent attacker control.",
            confidence    = "HIGH",
            socAction     = "Block device. Alert user. Provide instructions to remove Device Admin privileges before uninstall.",
        ),
    )

    /**
     * Builds the full Agentic AI Root Cause Advisory text for the given [threat]
     * based on which of its [IdentityThreatRegistry.Threat.signalTypes] are currently active.
     */
    fun buildAdvisory(
        threat: IdentityThreatRegistry.Threat,
        activeSignals: List<String>,
    ): String {
        val ts = SimpleDateFormat("HH:mm:ss 'IST'  dd-MMM-yyyy", Locale.getDefault()).format(Date())
        val overallConfidence = when {
            activeSignals.any { CAUSES[it]?.confidence == "HIGH" } -> "HIGH"
            activeSignals.any { CAUSES[it]?.confidence == "MEDIUM" } -> "MEDIUM"
            else -> "LOW"
        }

        return buildString {
            append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
            append("🤖  NonaShield Agentic AI\n")
            append("     Root Cause Advisory\n")
            append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
            append("Threat:      ${threat.name}\n")
            append("Threat ID:   ${threat.threatId}\n")
            append("Analysis:    $ts\n")
            append("Confidence:  $overallConfidence\n")
            append("Risk Score:  ${threat.riskScore} / 100\n\n")

            append("──── Active Signal Analysis ────\n\n")
            for (sig in activeSignals) {
                val cause = CAUSES[sig]
                if (cause != null) {
                    append("▶ ${cause.signalType}\n")
                    append("  Confidence:  ${cause.confidence}\n")
                    append("  Root Cause:\n    ${cause.rootCause}\n")
                    append("  Likely Origin:\n    ${cause.likelyOrigin}\n")
                    append("  Risk Assessment:\n    ${cause.riskAssessment}\n\n")
                } else {
                    append("▶ $sig\n")
                    append("  [Advisory not yet catalogued for this signal]\n\n")
                }
            }

            append("──── Advisory Summary ────\n")
            val allActions = activeSignals.mapNotNull { CAUSES[it]?.socAction }.toSet()
            if (allActions.isNotEmpty()) {
                allActions.forEach { action -> append("• $action\n") }
            } else {
                append("• Monitor and log. No immediate action required.\n")
            }

            append("\n──── NonaShield Enforcement ────\n")
            append("  X-Edge-Risk-Level: ${threat.riskScore} / 100\n")
            append("  Gateway decision:  ${threat.decision.label}\n")
            append("  Hardware key:      payshield_device_key (TEE)\n")
            append("  All transactions from this device are blocked\n")
            append("  until signals clear.\n")
        }
    }
}
