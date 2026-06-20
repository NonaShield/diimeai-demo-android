package com.diimeai.demo.security

import java.util.concurrent.ConcurrentHashMap

/**
 * Session-wide in-memory RASP signal state.
 *
 * Written by DiimeApp's SDK signal sink whenever any of the 41 RASP signals
 * fires.  All signals are now event-driven (OS callbacks in DiimeApp); there
 * is no polling loop.  Dynamic conditions (VPN, display, call, camera) are
 * cleared immediately via [clear] when the OS confirms they have resolved.
 * Static conditions (root, SELinux, ptrace…) expire via [SIGNAL_TTL_MS]
 * after the app-foreground re-evaluation stops recording them.
 *
 * Read by:
 *   - PaymentActivity — blocks payment if a screen-capture threat is active
 *   - TrustDashboardActivity — reflects live signal state in the RASP rows
 */
object RaspSignalState {

    // No polling loop → TTL only needs to cover the gap between the threat
    // condition resolving and the next app-foreground re-evaluation.
    // 30s is ample: users typically bring the app to foreground within seconds.
    private const val SIGNAL_TTL_MS = 30_000L

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
