package com.diimeai.demo

import com.payshield.sdk.BehaviourParam
import com.payshield.sdk.BehaviourStatus
import com.payshield.sdk.PayShieldSDK

/**
 * The demo's behaviour panel, read only from the SDK's public API: [PayShieldSDK.getBehaviourParams] and
 * [PayShieldSDK.getBehaviourBaselineProgressPct]. The SDK captures touch, keystroke and motion data on every
 * screen by itself and sends it to the backend (SOC dashboard); the app only displays what the SDK reports.
 */
object DemoBehaviour {

    /** Panel rows -> the SDK parameter each row shows. */
    const val PRESSURE = "Touch Pressure"
    const val FINGER_SIZE = "Contact Area"
    const val SWIPE = "Swipe Velocity"
    const val HESITATION = "Tap Interval"
    const val POSTURE = "Hold Tilt (Pitch)"
    const val GRIP = "Grip Yaw"
    const val TREMOR = "Hand Tremor Freq"
    const val JITTER = "Micro-movement"
    const val CURVATURE = "Swipe Linearity"

    data class Snapshot(
        val baselinePct: Int,
        val params: Map<String, BehaviourParam>,
        /** Mean deviation (0..1) over the parameters the SDK is measuring live. */
        val composite: Float,
        val anomalies: List<BehaviourParam>,
    ) {
        val baselineReady: Boolean get() = baselinePct >= 100
        val compositePct: Int get() = (composite * 100).toInt().coerceIn(0, 100)
    }

    fun snapshot(): Snapshot {
        val params = runCatching { PayShieldSDK.getBehaviourParams() }.getOrDefault(emptyList())
        val live = params.filter { it.isLive }
        val composite = if (live.isEmpty()) 0f else live.map { it.deviationScore }.average().toFloat()
        return Snapshot(
            baselinePct = runCatching { PayShieldSDK.getBehaviourBaselineProgressPct() }.getOrDefault(0),
            params = params.associateBy { it.name },
            composite = composite,
            anomalies = live.filter { it.status == BehaviourStatus.ANOMALY },
        )
    }

    fun icon(p: BehaviourParam?): String = when (p?.status) {
        BehaviourStatus.ANOMALY -> "🔴"
        BehaviourStatus.DRIFT -> "🟡"
        else -> "🟢"
    }

    /** "🟢 1.23" before the baseline is ready; "🟡 1.23  Δ34%" once it is. */
    fun row(s: Snapshot, name: String): String {
        val p = s.params[name] ?: return "🟢 –"
        if (!s.baselineReady) return "🟢 ${p.actual}"
        val pct = (p.deviationScore * 100).toInt()
        return if (pct > 0) "${icon(p)} ${p.actual}  Δ$pct%" else "${icon(p)} ${p.actual}"
    }

    /** Risk tier from the SDK's public risk score (0 / 30 / 60 bands, same as the edge header). */
    fun riskTier(): String {
        val score = runCatching { PayShieldSDK.getRiskScore() }.getOrDefault(0)
        return when {
            score >= 60 -> "HIGH"
            score >= 30 -> "MEDIUM"
            else -> "LOW"
        }
    }
}
