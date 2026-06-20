package com.diimeai.demo.security

import java.util.concurrent.ConcurrentHashMap

/**
 * Session-wide in-memory RASP signal state.
 *
 * Written by DiimeApp's SDK signal sink whenever any of the 41 RASP signals
 * fires.  All signals are now event-driven (OS callbacks in DiimeApp); there
 * is no polling loop.
 *
 * Two signal categories:
 *
 * PERSISTENT — static device conditions that remain active for the full app
 * session. Examples: sideloaded banking trojan, rogue device admin, Frida/Xposed
 * active. These are ONLY cleared when the OS explicitly confirms the condition
 * is gone (package uninstalled, accessibility disabled).  A 30s TTL would let
 * an active banking trojan silently "expire" while the user is still in the app.
 *
 * TRANSIENT — dynamic conditions that can appear and disappear rapidly. Examples:
 * screen recording, VPN connection, active phone call. Cleared immediately when
 * the OS reports the condition resolved, and also expire after [TRANSIENT_TTL_MS]
 * as a safety net for the rare case where the OS clear callback is missed.
 *
 * Read by:
 *   - PaymentActivity — blocks payment if screen-capture or malware threat is active
 *   - TrustDashboardActivity — reflects live signal state in all RASP rows
 */
object RaspSignalState {

    private const val TRANSIENT_TTL_MS = 30_000L

    // Static/persistent device conditions — active for the entire app session.
    // Cleared only by OS confirmation (package removed, accessibility disabled, etc.)
    private val PERSISTENT_TYPES = setOf(
        "SIDELOAD_DETECTED",      // banking trojan installed via WhatsApp/Telegram/unknown
        "DEVICE_ADMIN_ABUSE",     // rogue app holds device admin (blocks uninstall)
        "SMS_INTERCEPT_CAPABLE",  // READ_SMS + Accessibility combo — OTP interception ready
        "HOOKING_FRAMEWORK",      // Frida/Xposed/LSPosed active in process
        "MALWARE_DETECTED",       // FreeRASP Talsec known-malware database hit
        "ACCESSIBILITY_ABUSE",    // rogue accessibility service active (cleared when disabled)
        "ROGUE_HCE_APP",          // rogue NFC HCE payment app installed
        "APP_REPACKAGED",         // APK signature mismatch — tampered binary
        "NATIVE_LIB_TAMPER",      // native library integrity failure
        "SDK_SELF_TAMPER",        // SDK self-tamper detected
    )

    // Persistent: no expiry — active until explicitly cleared by OS event
    private val persistentSignals = ConcurrentHashMap<String, Long>()

    // Transient: expires after TRANSIENT_TTL_MS if OS clear callback is missed
    private val activeSignals = ConcurrentHashMap<String, Long>()

    fun record(signalType: String) {
        if (signalType in PERSISTENT_TYPES) {
            persistentSignals[signalType] = System.currentTimeMillis()
        } else {
            activeSignals[signalType] = System.currentTimeMillis()
        }
    }

    fun clear(signalType: String) {
        persistentSignals.remove(signalType)
        activeSignals.remove(signalType)
    }

    fun isActive(signalType: String): Boolean {
        if (persistentSignals.containsKey(signalType)) return true
        val ts = activeSignals[signalType] ?: return false
        return if (System.currentTimeMillis() - ts <= TRANSIENT_TTL_MS) true
        else { activeSignals.remove(signalType); false }
    }

    fun isAnyActive(vararg signalTypes: String): Boolean =
        signalTypes.any { isActive(it) }

    fun hasScreenCaptureThreat(): Boolean =
        isAnyActive("SCREEN_MIRRORING", "SCREEN_RECORDING_ACTIVE", "SCREENSHOT")

    fun hasVpnThreat(): Boolean = isActive("VPN_CONFLICT")

    fun hasMalwareThreat(): Boolean =
        isAnyActive(
            "SIDELOAD_DETECTED",
            "DEVICE_ADMIN_ABUSE",
            "SMS_INTERCEPT_CAPABLE",
            "HOOKING_FRAMEWORK",
            "MALWARE_DETECTED",
        )

    fun activeCount(): Int =
        persistentSignals.size + activeSignals.keys.count { isActive(it) }
}
