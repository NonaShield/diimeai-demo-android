package com.diimeai.demo.biometrics

import android.content.Context
import android.view.MotionEvent
import com.payshield.sdk.signal.BehavioralBiometricsCollector
import com.payshield.sdk.signal.BiometricMetrics
import com.payshield.sdk.signal.BiometricProfile

/**
 * Demo app wrapper around [BehavioralBiometricsCollector].
 *
 * Manages two sessions for Demo 5 — Social Engineering:
 *
 *   ┌────────────────────────────────────────────────────────────────────┐
 *   │  Session A (first user):                                           │
 *   │    - Calibration window builds behavioral baseline (10 touches)    │
 *   │    - baseline is saved when "Switch User" is tapped               │
 *   │                                                                    │
 *   │  Session B (attacker / switched user):                             │
 *   │    - Fresh sample collection starts                               │
 *   │    - Each touch is compared against saved Session A baseline       │
 *   │    - Deviation score visible in real-time to investor              │
 *   │    - ≥ 3 channels deviate → USR_BEH_012 SOCIAL_ENGINEERING_BIO   │
 *   └────────────────────────────────────────────────────────────────────┘
 *
 * Usage:
 *   BehavioralMonitor.start(context)           // in Activity.onCreate()
 *   BehavioralMonitor.record(event)            // in dispatchTouchEvent()
 *   BehavioralMonitor.saveBaseline()           // before switchToUser()
 *   BehavioralMonitor.enterComparisonMode()    // after switchToUser()
 *   BehavioralMonitor.stop()                   // in Activity.onDestroy()
 */
object BehavioralMonitor {

    // ── Active collector (replaced on new session) ────────────────────────────
    private var collector: BehavioralBiometricsCollector? = null

    // ── First-user baseline (saved at Switch User time) ───────────────────────
    var savedBaseline: BiometricProfile? = null
        private set

    /**
     * True once [enterComparisonMode] has been called — indicates that the
     * deviation score is now comparing a NEW user against the saved baseline.
     */
    @Volatile
    var isComparisonMode: Boolean = false
        private set

    // ─────────────────────────────────────────────────────────────────────────

    fun start(context: Context) {
        collector = BehavioralBiometricsCollector(context).also { it.startSession() }
    }

    fun stop() {
        collector?.stopSession()
    }

    /**
     * Feed a raw touch event to the collector.
     * Call this from [PaymentActivity.dispatchTouchEvent].
     */
    fun record(event: MotionEvent) {
        collector?.recordTouch(event)
    }

    /**
     * Lock in the current session's baseline as the first-user profile.
     * Call immediately before "Switch User" is executed.
     */
    fun saveBaseline() {
        savedBaseline = collector?.baseline
    }

    /**
     * Switch to comparison mode — the NEXT session's data will be scored
     * against [savedBaseline].  Resets sample buffers but keeps sensor listeners.
     */
    fun enterComparisonMode() {
        isComparisonMode = true
        collector?.resetSamples()   // clear samples — sensor listeners remain active
    }

    /**
     * Live metrics snapshot.  Returns null if no session is active.
     * [BiometricMetrics.deviationScore] is non-zero only when
     * [isComparisonMode] is true and [savedBaseline] is set.
     */
    fun currentMetrics(): BiometricMetrics? {
        val base = savedBaseline
        if (!isComparisonMode || base == null) {
            // Not in comparison mode — return raw metrics without deviation scores
            return collector?.currentMetrics()
        }

        // Override the collector's internal baseline with the saved cross-session one
        // We do this by injecting the saved baseline before calling currentMetrics.
        return collector?.currentMetricsAgainstBaseline(base)
    }

    /**
     * 0.0–1.0 deviation score of the current user vs. the saved first-user baseline.
     * Only meaningful when [isComparisonMode] is true and baseline is loaded.
     */
    fun deviationScore(): Float = currentMetrics()?.deviationScore ?: 0f

    /**
     * Full reset — clears baseline and exits comparison mode.
     * Use when the user logs out completely.
     */
    fun fullReset() {
        collector?.resetSamples()
        savedBaseline = null
        isComparisonMode = false
    }

    /**
     * Human-readable summary of which channels are deviating.
     * Used by the demo app's behavioral panel and alert dialogs.
     */
    fun buildDeviationSummary(): DeviationSummary {
        val m = currentMetrics() ?: return DeviationSummary.empty()
        return DeviationSummary(
            pressure    = ChannelStatus("Pressure",     m.pressure,       m.pressureDev),
            fingerSize  = ChannelStatus("Finger Size",  m.fingerMajor,    m.fingerDev),
            swipe       = ChannelStatus("Swipe Speed",  m.swipeVelocity,  m.velocityDev),
            hesitation  = ChannelStatus("Hesitation",   m.hesitationMs.toFloat(), m.hesitationDev),
            posture     = ChannelStatus("Phone Hold",   m.holdingPitch,   m.postureDev),
            grip        = ChannelStatus("Grip Stability",m.gripVariance,  m.gripDev),
            composite   = m.deviationScore,
            isCalibrated = m.isCalibrated,
            calibrationPct = m.calibrationPct
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Data types for the demo app UI
// ─────────────────────────────────────────────────────────────────────────────

data class ChannelStatus(
    val name:      String,
    val value:     Float,
    val deviation: Float        // 0.0–1.0
) {
    val isDeviated: Boolean get() = deviation > BehavioralBiometricsCollector.CHANNEL_DEV_THRESHOLD
    val deviationPct: Int   get() = (deviation * 100).toInt()
    val statusIcon: String  get() = when {
        deviation > 0.65f -> "🔴"
        deviation > 0.45f -> "🟡"
        else              -> "🟢"
    }
}

data class DeviationSummary(
    val pressure:    ChannelStatus,
    val fingerSize:  ChannelStatus,
    val swipe:       ChannelStatus,
    val hesitation:  ChannelStatus,
    val posture:     ChannelStatus,
    val grip:        ChannelStatus,
    val composite:   Float,
    val isCalibrated: Boolean,
    val calibrationPct: Int
) {
    val deviatingChannels: List<ChannelStatus>
        get() = listOf(pressure, fingerSize, swipe, hesitation, posture, grip)
            .filter { it.isDeviated }

    val compositePct: Int get() = (composite * 100).toInt()
    val riskLabel: String get() = when {
        composite > 0.65f -> "HIGH RISK"
        composite > 0.40f -> "ELEVATED"
        composite > 0.20f -> "MEDIUM"
        else              -> "NORMAL"
    }
    val riskColor: Int get() = when {
        composite > 0.65f -> 0xFFE02020.toInt()
        composite > 0.40f -> 0xFFFF8800.toInt()
        composite > 0.20f -> 0xFFF2CC0C.toInt()
        else              -> 0xFF00AA44.toInt()
    }

    companion object {
        fun empty() = DeviationSummary(
            ChannelStatus("Pressure", 0f, 0f),
            ChannelStatus("Finger Size", 0f, 0f),
            ChannelStatus("Swipe Speed", 0f, 0f),
            ChannelStatus("Hesitation", 0f, 0f),
            ChannelStatus("Phone Hold", 0f, 0f),
            ChannelStatus("Grip Stability", 0f, 0f),
            composite = 0f,
            isCalibrated = false,
            calibrationPct = 0
        )
    }
}
