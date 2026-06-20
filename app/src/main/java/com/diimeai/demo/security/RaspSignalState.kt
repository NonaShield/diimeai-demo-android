package com.diimeai.demo.security

import java.util.concurrent.ConcurrentHashMap

/**
 * Session-wide in-memory RASP signal state.
 *
 * Populated by DiimeApp's SDK signal sink every time the orchestrator runs
 * (every 10 seconds). Read by:
 *   - PaymentActivity — blocks payment if a screen-capture threat is active
 *   - TrustDashboardActivity — reflects live signal state in the RASP rows
 *
 * Signals expire after [SIGNAL_TTL_MS] so that cleared conditions (VPN
 * disconnected, screen recording stopped) are reflected within one cycle.
 */
object RaspSignalState {

    private const val SIGNAL_TTL_MS = 15_000L  // 10s eval cycle + 5s grace

    private val activeSignals = ConcurrentHashMap<String, Long>()

    fun record(signalType: String) {
        activeSignals[signalType] = System.currentTimeMillis()
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
