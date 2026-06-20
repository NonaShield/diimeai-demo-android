package com.diimeai.demo.security

import java.util.concurrent.ConcurrentHashMap

/**
 * Session-wide in-memory RASP signal state.
 *
 * Written by DiimeApp's SDK signal sink on every orchestrator evaluation.
 * Dynamic threats (display, VPN, accessibility) are cleared immediately via
 * [clear] when the OS notifies the condition has resolved.  Static threats
 * (root, SELinux, etc.) expire via [SIGNAL_TTL_MS] after the 60-second
 * periodic scan stops re-recording them.
 *
 * Read by:
 *   - PaymentActivity — blocks payment if a screen-capture threat is active
 *   - TrustDashboardActivity — reflects live signal state in the RASP rows
 */
object RaspSignalState {

    private const val SIGNAL_TTL_MS = 75_000L  // 60s eval cycle + 15s grace

    private val activeSignals = ConcurrentHashMap<String, Long>()

    fun record(signalType: String) {
        activeSignals[signalType] = System.currentTimeMillis()
    }

    fun clear(signalType: String) {
        activeSignals.remove(signalType)
    }

    fun isActive(signalType: String): Boolean {
        val ts = activeSignals[signalType] ?: return false
        return if (System.currentTimeMillis() - ts <= SIGNAL_TTL_MS) true
        else { activeSignals.remove(signalType); false }
    }

    fun isAnyActive(vararg signalTypes: String): Boolean =
        signalTypes.any { isActive(it) }

    fun hasScreenCaptureThreat(): Boolean =
        isAnyActive("SCREEN_MIRRORING", "SCREEN_RECORDING_ACTIVE", "SCREENSHOT")

    fun hasVpnThreat(): Boolean = isActive("VPN_CONFLICT")

    fun activeCount(): Int = activeSignals.keys.count { isActive(it) }
}
