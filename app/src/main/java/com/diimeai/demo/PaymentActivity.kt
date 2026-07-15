package com.diimeai.demo

import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.hardware.display.DisplayManager
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.MotionEvent
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.diimeai.demo.databinding.ActivityPaymentBinding
import com.diimeai.demo.network.DiimeApiClient
import com.diimeai.demo.network.EvidenceReceipt
import com.diimeai.demo.network.PaymentResult
import com.payshield.android.edge.EdgeRiskEnforcer
import com.payshield.sdk.PayShieldSDK
import com.payshield.sdk.policy.PolicyDecision
import com.payshield.sdk.behavioral.BehavioralCaptureManager
import com.payshield.sdk.behavioral.BehavioralSessionManager
import com.payshield.sdk.behavioral.BiometricChannelStatus
import com.payshield.sdk.behavioral.BiometricDeviationSummary
import com.payshield.sdk.behavioral.BehavioralTelemetrySender
import com.payshield.sdk.behavioral.KeystrokeDynamicsCapture
import com.payshield.sdk.enrollment.EnrollmentState
import com.payshield.sdk.signal.EdgeSignal
import com.payshield.sdk.token.SessionHolder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Banking home screen â€” real-time RASP protection active throughout.
 *
 * Passive protection layers (zero UX friction):
 *   - Behavioral biometrics: 6-channel passive capture on every touch
 *   - Screen capture / mirroring: DisplayManager + SDK continuous scan
 *   - SIM swap: SIM fingerprint vs. KYC-enrolled fingerprint
 *   - RASP gate: EdgeRiskEnforcer.assertAllowed() before every payment
 *   - Behavioral telemetry: sent to backend before payment decision
 */
class PaymentActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "PaymentActivity"

        const val EXTRA_USER_ID   = "USER_ID"
        const val EXTRA_PREV_USER = "PREV_USER_ID"   // set by SDK on biometric mismatch detection

        /** Refresh the behavioral panel every 500 ms even without touch events. */
        private const val BIO_REFRESH_MS = 500L

        /** Number of payment interactions to capture before locking the biometric baseline. */
        private const val BASELINE_PAYMENTS = 5
    }

    private lateinit var binding: ActivityPaymentBinding

    // â”€â”€ Behavioral SDK (NonaShield 11-field telemetry) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    //
    // [keystrokeDynamics] captures typing rhythm on amount, recipient, note fields.
    // [captureManager]    captures touch pressure, velocity, hesitation, scroll
    //                     velocity, orientation changes, and navigation events.
    //
    // Both are attached in [onResume] and detached in [onPause].
    // [BehavioralTelemetrySender.send] is called inside [initiatePayment] before
    // the backend API call so the backend decision includes behavioral context.
    //
    // Bridge: routes [com.payshield.sdk.signal.SignalSink] (SDK internal interface)
    // to [DiimeApiClient.signalSink] ([com.payshield.android.sdk.SignalSink]).
    private val behavioralSink = object : com.payshield.sdk.signal.SignalSink {
        override fun emit(signal: EdgeSignal) {
            DiimeApiClient.signalSink?.onSignalsCollected(listOf(signal))
        }
        override fun onBlock(reason: String) {
            DiimeApiClient.signalSink?.onBlock(reason)
        }
    }

    private val keystrokeDynamics = KeystrokeDynamicsCapture()

    private val captureManager by lazy {
        BehavioralCaptureManager(
            sink              = behavioralSink,
            sessionId         = resolveSessionId(),
            keystrokeDynamics = keystrokeDynamics
        )
    }

    /** Resolves the active session ID from SessionHolder, or falls back to a local timestamp. */
    private fun resolveSessionId(): String =
        runCatching { SessionHolder.requireSession().sessionId }
            .getOrElse { "payment_${System.currentTimeMillis()}" }

    // â”€â”€ Session state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    private var currentUserId:  String = ""
    private var previousUserId: String? = null

    // â”€â”€ Demo 2 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    private var lastReceiptUrl: String = ""
    private var lastDecisionId: String = ""

    // When true, the next initiatePayment() call bypasses soft RASP/biometric/SIM gates
    // and displays the immutable audit proof (nonce, device key, timestamp) on success.
    // Set by btnAttestAndPay; cleared after the payment completes (success or failure).
    private var isDemoAttestationMode = false

    // When true, the companion screen-share advisory has been acknowledged by the user
    // ("Proceed Anyway").  The companion check in initiatePayment() is skipped exactly once;
    // the flag is cleared when initiatePayment() is called again.
    private var companionShareAcknowledged = false

    // â”€â”€ Biometric baseline: locked after BASELINE_PAYMENTS payment taps â”€â”€â”€â”€â”€â”€â”€
    // Counter increments on every Send Payment tap regardless of validation result.
    // At tap #BASELINE_PAYMENTS the profile is saved and comparison mode activates.
    // Reset to 0 on logout/fullReset.
    private var paymentTapCount = 0

    // â”€â”€ Biometric panel refresh â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    private val handler = Handler(Looper.getMainLooper())
    private val bioRefreshRunnable = object : Runnable {
        override fun run() {
            refreshBiometricPanel()
            refreshThreatTicker()
            handler.postDelayed(this, BIO_REFRESH_MS)
        }
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Lifecycle
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityPaymentBinding.inflate(layoutInflater)
        setContentView(binding.root)

        currentUserId  = intent.getStringExtra(EXTRA_USER_ID)   ?: "User"
        previousUserId = intent.getStringExtra(EXTRA_PREV_USER)

        binding.tvWelcome.text = "Welcome, $currentUserId"
        EnrollmentState.load()?.let { binding.tvDeviceId.text = "Device: ${it.deviceId.take(16)}â€¦" }
        updateRiskBadge()

        // â”€â”€ Demo 5: Start behavioral biometrics session â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if (previousUserId != null) {
            // Session B â€” score against Session A baseline.  Wire sink so that
            // BEHAVIORAL_BIOMETRIC_MISMATCH / SOCIAL_ENGINEERING_BIOMETRIC appear in ticker.
            BehavioralSessionManager.enterComparisonMode(behavioralSink)
            showSocialEngineeringWarning(previousUserId!!)
            binding.rowDeviationBar.visibility = View.VISIBLE
        } else {
            // Session A â€” build user baseline.  Wire sink so per-channel MEDIUM signals
            // are also emitted once comparison mode kicks in after 5 payments.
            BehavioralSessionManager.start(this, behavioralSink)
        }

        // Button wiring
        binding.btnSendPayment.setOnClickListener  { initiatePayment() }
        binding.btnAttestAndPay.setOnClickListener { isDemoAttestationMode = true; initiatePayment() }
        binding.btnViewProof.setOnClickListener    { openReceipt() }
        binding.btnEnrollKyc.setOnClickListener   { promptKycEnrollment() }
        binding.btnLogout.setOnClickListener      { logout() }
        binding.btnSocDashboard.setOnClickListener {
            startActivity(Intent(Intent.ACTION_VIEW,
                Uri.parse("https://api.diimeai.com/dashboard")))
        }
    }

    override fun onResume() {
        super.onResume()
        updateRiskBadge()
        updateKycButtonLabel()
        handler.post(bioRefreshRunnable)

        // â”€â”€ Behavioral: attach capture on every screen entry â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // keystrokeDynamics wraps amount / recipient / note EditText fields.
        // captureManager transparently intercepts all touch events on the root view.
        keystrokeDynamics.attachToRoot(binding.root)
        captureManager.attachTo(binding.root)
        // Record this screen entry as a transition â€” dwell-time measurement starts.
        captureManager.sessionFlowAnalyzer.onScreenTransition()
    }

    private fun updateKycButtonLabel() {
        binding.btnEnrollKyc.text = "ðŸªª  Verify Identity"
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(bioRefreshRunnable)
        keystrokeDynamics.detachFromRoot()
        captureManager.detachFrom(binding.root)
    }

    override fun onDestroy() {
        super.onDestroy()
        if (previousUserId == null) {
            // Only stop sensors if this is session A (session B borrows them)
            BehavioralSessionManager.stop()
        }
    }

    /**
     * Called when device is rotated (requires android:configChanges="orientation|screenSize"
     * in AndroidManifest.xml â€” the activity is NOT recreated on rotation).
     *
     * Increments [BehavioralFeatures.screenOrientationChanges] â€” backend field
     * [screen_orientation_changes] in BehavioralFeaturesPayload.
     */
    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        captureManager.recordOrientationChange(newConfig)
    }

    /**
     * Intercept system back press to record it in SessionFlowAnalyzer.
     *
     * [BehavioralFeatures.backtrackCount] is incremented â€” elevated back navigation
     * during payment correlates with hesitant / coached user behaviour (Romance Fraud).
     */
    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        captureManager.sessionFlowAnalyzer.onBackNavigation()
        @Suppress("DEPRECATION")
        super.onBackPressed()
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Touch routing â†’ BehavioralBiometricsCollector + BehavioralCaptureManager
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        // Feed every touch event to the behavioral engine (passive â€” no UX impact)
        BehavioralSessionManager.record(event)
        // Refresh panel immediately on UP events (gesture completed)
        if (event.actionMasked == MotionEvent.ACTION_UP) {
            handler.post { refreshBiometricPanel() }
        }
        return super.dispatchTouchEvent(event)
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Live RASP threat ticker
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


    // Track last rendered set to avoid rebuilding the list on every 500ms tick
    private var lastRenderedThreatTypes: List<String> = emptyList()

    private fun refreshThreatTicker() {
        val signals = synchronized(DiimeApp.recentRaspSignals) {
            // Prune signals whose condition has resolved (TTL expired or OS clear callback fired).
            // Without this, the ticker keeps showing WhatsApp screen-share signals indefinitely
            // after the WhatsApp session closes â€” SignalStateManager knows they're gone but the
            // display buffer never removes them.
            DiimeApp.recentRaspSignals.removeAll { signal ->
                !PayShieldSDK.isSignalActive(signal.type)
            }
            DiimeApp.recentRaspSignals.toList()
        }
        // Newest last â†’ show newest at top
        val ordered = signals.reversed()
        val types = ordered.map { it.type }
        if (types == lastRenderedThreatTypes) return   // nothing changed
        lastRenderedThreatTypes = types

        val hasSignals = ordered.isNotEmpty()
        binding.tvNoThreatsDetected.visibility = if (hasSignals) View.GONE else View.VISIBLE
        binding.llRaspAlertList.visibility     = if (hasSignals) View.VISIBLE else View.GONE
        binding.tvAlertCount.text = if (hasSignals) "${ordered.size} active" else "0 active"
        binding.tvAlertCount.setTextColor(if (hasSignals) 0xFFFF6644.toInt() else 0xFF448844.toInt())

        binding.llRaspAlertList.removeAllViews()
        ordered.forEach { signal ->
            val icon = when (signal.severity.name) {
                "CRITICAL" -> "ðŸ”´"
                "HIGH"     -> "ðŸŸ "
                "MEDIUM"   -> "ðŸŸ¡"
                else       -> "ðŸŸ¡"
            }
            val name = PayShieldSDK.getSignalDisplayName(signal.type)
            val tv = android.widget.TextView(this).apply {
                text = "$icon  $name"
                textSize = 12f
                setTextColor(when (signal.severity.name) {
                    "CRITICAL" -> 0xFFFF4444.toInt()
                    "HIGH"     -> 0xFFFF8844.toInt()
                    else       -> 0xFFFFCC44.toInt()
                })
                typeface = android.graphics.Typeface.MONOSPACE
                val pad = (8 * resources.displayMetrics.density).toInt()
                setPadding(0, pad / 2, 0, pad / 2)
            }
            binding.llRaspAlertList.addView(tv)
        }
    }

    // Behavioral biometrics panel
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    private fun refreshBiometricPanel() {
        val summary = BehavioralSessionManager.buildDeviationSummary()
        val inCompare = BehavioralSessionManager.isComparisonMode

        // Calibration progress bar â€” show until BASELINE_PAYMENTS taps are done
        val baselineLocked = inCompare || BehavioralSessionManager.savedBaseline != null
        if (baselineLocked) {
            binding.rowCalibration.visibility = View.GONE
        } else {
            binding.rowCalibration.visibility = View.VISIBLE
            // Progress = payment taps completed out of BASELINE_PAYMENTS
            val pct = (paymentTapCount * 100 / BASELINE_PAYMENTS).coerceIn(0, 100)
            binding.progressCalibration.progress = pct
            binding.tvCalibrationPct.text = "  ${paymentTapCount}/${BASELINE_PAYMENTS}"
        }

        // Risk badge
        when {
            inCompare -> {
                // Comparison mode: show live deviation score
                binding.tvBioRiskBadge.text = "${summary.riskLabel}  ${summary.compositePct}%"
                binding.tvBioRiskBadge.setBackgroundColor(summary.riskColor)
                binding.tvBioHint.visibility = View.GONE
            }
            baselineLocked -> {
                // Baseline saved, not yet in comparison mode (transitional â€” shouldn't linger)
                binding.tvBioRiskBadge.text = "ENROLLED USER âœ“"
                binding.tvBioRiskBadge.setBackgroundColor(0xFF00AA44.toInt())
                binding.tvBioHint.visibility = View.GONE
            }
            paymentTapCount >= BASELINE_PAYMENTS -> {
                // 5 taps done but sensor calibration not complete yet (very unlikely)
                binding.tvBioRiskBadge.text = "ENROLLINGâ€¦  touch screen"
                binding.tvBioRiskBadge.setBackgroundColor(0xFF334455.toInt())
                binding.tvBioHint.visibility = View.VISIBLE
            }
            else -> {
                // Still building: show payment count progress
                val remaining = BASELINE_PAYMENTS - paymentTapCount
                binding.tvBioRiskBadge.text = "BUILDING PROFILE: ${paymentTapCount}/${BASELINE_PAYMENTS}"
                binding.tvBioRiskBadge.setBackgroundColor(0xFF334455.toInt())
                binding.tvBioHint.text =
                    "Make $remaining more payment${if (remaining == 1) "" else "s"} to lock your biometric profile"
                binding.tvBioHint.visibility = View.VISIBLE
            }
        }

        // 7 sensor channels â€” always ðŸŸ¢ for enrolled user; show deviation only in comparison mode
        binding.tvBioPressure.text   = formatChannel(summary.pressure, inCompare)
        binding.tvBioFingerSize.text = formatChannel(summary.fingerSize, inCompare, "px")
        binding.tvBioSwipe.text      = formatChannel(summary.swipe, inCompare, "px/ms")
        binding.tvBioHesitation.text = run {
            val icon = if (inCompare) summary.hesitation.statusIcon else "ðŸŸ¢"
            val v = "${summary.hesitation.value.toLong()}ms"
            if (inCompare && summary.hesitation.deviation > 0) "$icon $v  Î”${summary.hesitation.deviationPct}%"
            else "$icon $v"
        }
        binding.tvBioPosture.text = run {
            val icon = if (inCompare) summary.posture.statusIcon else "ðŸŸ¢"
            val v = "${"%.1f".format(summary.posture.value)}Â°"
            if (inCompare && summary.posture.deviation > 0) "$icon $v  Î”${summary.posture.deviationPct}%"
            else "$icon $v"
        }
        binding.tvBioGrip.text     = formatChannel(summary.grip, inCompare)
        // Ch 7: Micro-tremor ZCR â€” shown in crossings/s
        binding.tvBioTremorZcr.text = run {
            val icon = if (inCompare) summary.tremorZcr.statusIcon else "ðŸŸ¢"
            val v    = "${"%.0f".format(summary.tremorZcr.value)} zc/s"
            if (inCompare && summary.tremorZcr.deviation > 0)
                "$icon $v  Î”${summary.tremorZcr.deviationPct}%"
            else "$icon $v"
        }

        // 2 ML channels â€” ðŸŸ¢ for enrolled user; bot-detection icons only in comparison mode
        val mlFeatures = captureManager.getLatestFeatures()
        if (mlFeatures != null) {
            val jitterIcon = if (!inCompare) "ðŸŸ¢" else when {
                mlFeatures.jitterScore < 0.001f -> "ðŸ”´"
                mlFeatures.jitterScore < 0.01f  -> "ðŸŸ¡"
                else                            -> "ðŸŸ¢"
            }
            binding.tvBioJitter.text = "$jitterIcon ${"%.4f".format(mlFeatures.jitterScore)}"

            val entropyIcon = if (!inCompare) "ðŸŸ¢" else when {
                mlFeatures.curvatureEntropy < 0.3f -> "ðŸ”´"
                mlFeatures.curvatureEntropy < 1.0f -> "ðŸŸ¡"
                else                               -> "ðŸŸ¢"
            }
            binding.tvBioCurvature.text = "$entropyIcon ${"%.2f".format(mlFeatures.curvatureEntropy)}"
        } else {
            // No touch gesture processed yet
            binding.tvBioJitter.text    = "ðŸŸ¢ â€“"
            binding.tvBioCurvature.text = "ðŸŸ¢ â€“"
        }

        // Deviation bar (comparison mode only)
        if (BehavioralSessionManager.isComparisonMode) {
            binding.rowDeviationBar.visibility = View.VISIBLE
            binding.progressDeviation.progress = summary.compositePct
            binding.progressDeviation.progressTintList =
                android.content.res.ColorStateList.valueOf(summary.riskColor)
            binding.tvDeviationPct.text = "${summary.compositePct}% deviation"
            binding.tvDeviationPct.setTextColor(summary.riskColor)

            // Channel breakdown
            val deviatingNames = summary.deviatingChannels.joinToString(" Â· ") {
                "${it.statusIcon} ${it.name} (+${it.deviationPct}%)"
            }
            binding.tvDeviationChannels.text =
                if (deviatingNames.isNotBlank()) deviatingNames
                else "  All channels within normal range"

            // Prominent "DIFFERENT USER" alarm: show banner when â‰¥ 65% deviation
            val isHighDeviation = summary.composite >= 0.65f
            binding.rowUserMismatchAlarm.visibility =
                if (isHighDeviation) View.VISIBLE else View.GONE
            if (isHighDeviation) {
                // Count the 2 ML channels (jitter, curvature) alongside the 7 sensor channels.
                val mlFlagged = mlFeatures?.let {
                    listOf(it.jitterScore < 0.001f, it.curvatureEntropy < 0.3f).count { f -> f }
                } ?: 0
                binding.tvUserMismatchDetail.text =
                    "Biometric deviation: ${summary.compositePct}%  â€¢  " +
                    "${summary.deviatingChannels.size + mlFlagged}/9 channels flagged"
            }

            // Auto-show full alert dialog when â‰¥3 channels deviate (once per session)
            if (summary.deviatingChannels.size >= 3 && !socialEngAlertShown) {
                socialEngAlertShown = true
                showBiometricSocialEngAlert(summary)
            }
        } else {
            binding.rowUserMismatchAlarm.visibility = View.GONE
        }
    }

    private var socialEngAlertShown = false

    private fun formatChannel(ch: BiometricChannelStatus, inCompare: Boolean, unit: String = ""): String {
        val value = "${"%.2f".format(ch.value)}$unit"
        return if (inCompare && ch.deviation > 0)
            "${ch.statusIcon} $value  Î”${ch.deviationPct}%"
        else
            "ðŸŸ¢ $value"
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Payment flow
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    private fun initiatePayment() {
        val amount    = binding.etAmount.text.toString().toDoubleOrNull()
        val recipient = binding.etRecipient.text.toString().trim()

        if (amount == null || amount <= 0) { binding.etAmount.error = "Enter a valid amount"; return }
        if (recipient.isBlank()) { binding.etRecipient.error = "Recipient required"; return }

        // Count only validated payment attempts for baseline building.
        // Counting before validation caused the baseline to lock on empty taps,
        // producing an empty behavioral profile and false deviation on real use.
        if (!BehavioralSessionManager.isComparisonMode &&
                BehavioralSessionManager.savedBaseline == null) {
            paymentTapCount++
            if (paymentTapCount >= BASELINE_PAYMENTS) {
                BehavioralSessionManager.saveBaseline()
                BehavioralSessionManager.enterComparisonMode(behavioralSink)
                Toast.makeText(this,
                    "âœ… Biometric profile locked â€” comparison active",
                    Toast.LENGTH_SHORT).show()
                handler.post { refreshBiometricPanel() }
            }
        }

        // Capture attestation mode on the UI thread before the coroutine captures it.
        // isDemoAttestationMode is always cleared after the payment completes.
        val isAttestation = isDemoAttestationMode

        if (!isAttestation) {
            // â”€â”€ Screen capture check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            // Three-tier logic based on who owns the virtual display:
            //
            //   COMPANION_SCREEN_SHARE_ACTIVE (MEDIUM, advisory):
            //     A verified companion app (WhatsApp Web, Telegram Desktop) is mirroring
            //     the screen.  Screen IS at risk but source is known â€” show a graceful
            //     "please pause sharing" prompt rather than a hard block.
            //
            //   hasScreenCaptureThreat() (HIGH, hard block):
            //     Unknown recorder app, hardware mirroring (Chromecast/HDMI), or
            //     multiple virtual displays â€” cannot determine ownership.
            //
            //   dm.displays.size > 1 without any SDK signal:
            //     SDK may not have had time to evaluate the new display yet (race).
            //     Fall through to the screen capture threat check â€” the next
            //     evaluateNow() triggered by onDisplayAdded will update the signal.
            val skipCompanionCheck = companionShareAcknowledged.also { companionShareAcknowledged = false }
            if (!skipCompanionCheck && PayShieldSDK.hasCompanionScreenShare()) {
                Log.w(TAG, "[RASP] Companion screen share active â€” showing advisory")
                showCompanionShareAdvisory()
                return
            }
            if (PayShieldSDK.hasScreenCaptureThreat()) {
                Log.w(TAG, "[RASP] Screen capture threat active (RASP_DEV_051)")
                showThreatBlockedDialog("RASP_DEV_051")
                return
            }
            // Raw display-count fallback â€” guards the race window between onDisplayAdded()
            // and evaluateNow() completing.  Skip entirely when the companion display was
            // acknowledged ("Proceed Anyway") or is still signalled as active: the extra
            // display IS the companion virtual display and blocking it here would contradict
            // the advisory acknowledgment and prevent payment from executing (Scenario 3).
            val companionDisplayActive = skipCompanionCheck || PayShieldSDK.hasCompanionScreenShare()
            if (!companionDisplayActive) {
                val dm = getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
                if (dm.displays.size > 1) {
                    Log.w(TAG, "[Demo4] Screen mirroring: ${dm.displays.size} displays active")
                    showThreatBlockedDialog("RASP_DEV_025")
                    return
                }
            }


            val bioDev = BehavioralSessionManager.deviationScore()













            // â”€â”€ Demo 5: Behavioral mismatch gate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            if (BehavioralSessionManager.isComparisonMode) {
                val dev = BehavioralSessionManager.deviationScore()
                if (dev > 0.55f) {
                    showBiometricPaymentBlockedDialog(dev)
                    return
                }
            }

            // â”€â”€ Local RASP gate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            try {
                EdgeRiskEnforcer.assertAllowed()
            } catch (e: SecurityException) {
                showThreatBlockedDialog(EdgeRiskEnforcer.activeHighThreat())
                return
            }
        }

        setLoading(true)
        binding.tvResult.visibility    = View.GONE
        binding.btnViewProof.visibility = View.GONE

        val noteText = binding.etNote.text.toString().trim()

        lifecycleScope.launch(Dispatchers.IO) {
            // â”€â”€ Behavioral telemetry: fail-open, never blocks the payment â”€â”€â”€â”€â”€
            val behavioralFeatures = captureManager.getLatestFeatures()
            if (behavioralFeatures != null) {
                val sessionId = resolveSessionId()
                val sessionFlow = captureManager.sessionFlowAnalyzer.build()
                val telemetryResponse = runCatching {
                    BehavioralTelemetrySender.send(
                        features            = behavioralFeatures,
                        sessionId           = sessionId,
                        tenantId            = "default",
                        action              = "PAYMENT",
                        sessionFlowFeatures = sessionFlow
                    )
                }.getOrNull()
                if (telemetryResponse != null) {
                    Log.d(TAG, "[Behavioral] telemetry action=${telemetryResponse.action} " +
                        "score=${telemetryResponse.behavioralScore} " +
                        "level=${telemetryResponse.riskLevel}")
                }
            }

            // â”€â”€ SDK checkpoint gate â€” skipped in attestation mode â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            // Attestation demo is specifically for showing telemetry proof even
            // when the SDK would normally gate the payment.
            if (!isAttestation) {
                val checkpoint = runCatching {
                    PayShieldSDK.evaluateAtCheckpoint(action = "PAYMENT")
                }.getOrNull()

                if (checkpoint != null && checkpoint.decision == PolicyDecision.DENY) {
                    withContext(Dispatchers.Main) {
                        setLoading(false)
                        showThreatBlockedDialog(checkpoint.reason ?: "PAYMENT_RISK_BLOCK")
                    }
                    return@launch
                }

                if (checkpoint != null && checkpoint.decision == PolicyDecision.STEP_UP) {
                    withContext(Dispatchers.Main) {
                        setLoading(false)
                        showPaymentRiskStepUpDialog(amount, checkpoint.reason)
                    }
                    return@launch
                }
            }

            // Allow PinningInterceptor to sign the request even when the device
            // is in a risk-blocked state (attestation demo only).
            if (isAttestation) EdgeRiskEnforcer.demoAttestationMode = true

            val result = DiimeApiClient.initiatePayment(
                amount      = amount,
                currency    = "INR",
                recipientId = recipient,
                note        = noteText
            )

            // Always clear the bypass â€” never leave it open after the request.
            if (isAttestation) EdgeRiskEnforcer.demoAttestationMode = false

            withContext(Dispatchers.Main) {
                isDemoAttestationMode = false
                setLoading(false)
                if (isAttestation && result is PaymentResult.Success) {
                    showImmutableAuditDialog(result)
                } else {
                    handlePaymentResult(result)
                }
            }
        }
    }

    private fun showImmutableAuditDialog(result: PaymentResult.Success) {
        lastReceiptUrl = result.receiptUrl
        lastDecisionId = result.decisionId

        val nonceShort  = result.nonce.take(32).let { if (result.nonce.length > 32) "${it}..." else it }
        val hashShort   = result.requestHash.take(32).let { if (result.requestHash.length > 32) "${it}..." else it }
        val keyShort    = result.deviceKeyId.take(24).let { if (result.deviceKeyId.length > 24) "${it}..." else it }
        val iso = if (result.timestampEpoch > 0L)
            java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", java.util.Locale.US)
                .apply { timeZone = java.util.TimeZone.getTimeZone("UTC") }
                .format(java.util.Date(result.timestampEpoch * 1000L))
        else "â€”"

        val msg = buildString {
            append("â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”\n")
            append("IMMUTABLE AUDIT PROOF\n")
            append("â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”\n\n")
            append("Txn ID :  ${result.transactionId}\n")
            append("Status :  ${result.status} â€” AUTHORISED\n\n")
            append("â”€â”€ Cryptographic Attestation â”€â”€\n\n")
            append("Nonce (anti-replay 256-bit):\n")
            append("  $nonceShort\n\n")
            append("Device Key (hw-bound):\n")
            append("  $keyShort\n")
            if (result.hwLevel.isNotBlank())
                append("  Backed by: ${result.hwLevel}\n")
            append("\n")
            append("Timestamp (server-aligned):\n")
            append("  $iso\n\n")
            append("Request Hash (SHA-256):\n")
            append("  $hashShort\n\n")
            append("Signing Algorithm:  ECDSA_P256\n\n")
            append("â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”\n")
            append("Every field above is ECDSA-signed\n")
            append("by the device hardware key before\n")
            append("leaving the device. A replayed or\n")
            append("spoofed nonce fails NGINX Phase-1\n")
            append("immediately. Immutable once the\n")
            append("evidence chain block is written.")
        }

        AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle("Cryptographic Attestation")
            .setMessage(msg)
            .setPositiveButton("Full Receipt") { _, _ -> openReceipt() }
            .setNegativeButton("Close", null)
            .show()

        binding.tvResult.apply {
            text = buildString {
                append("PAYMENT AUTHORISED â€” Attestation Demo\n\n")
                append("Txn ID  : ${result.transactionId}\n")
                append("Nonce   : ${result.nonce.take(16)}â€¦\n")
                append("HW Key  : ${result.hwLevel}\n")
                append("Signed  : $iso\n\n")
                append("Cryptographic proof shown above.\n")
                append("Nonce, key, timestamp are ECDSA-\n")
                append("signed â€” unspoofable + immutable.")
            }
            setTextColor(getColor(android.R.color.holo_green_dark))
            visibility = View.VISIBLE
        }
        if (result.receiptUrl.isNotBlank() || result.decisionId.isNotBlank())
            binding.btnViewProof.visibility = View.VISIBLE
    }

    private fun handlePaymentResult(result: PaymentResult) {
        when (result) {
            is PaymentResult.Success -> {
                lastReceiptUrl = result.receiptUrl
                lastDecisionId = result.decisionId
                binding.tvResult.apply {
                    text = buildString {
                        append("âœ…  Payment Authorised\n\n")
                        append("Txn ID   :  ${result.transactionId}\n")
                        append("Status   :  ${result.status}\n")
                        if (result.decisionId.isNotBlank())
                            append("Decision :  ${result.decisionId.take(18)}â€¦\n")
                        append("\nNonaShield 5-phase pipeline: PASSED\n")
                        if (BehavioralSessionManager.isComparisonMode) {
                            val dev = BehavioralSessionManager.deviationScore()
                            append("Behavioral deviation: ${"%.0f".format(dev * 100)}%")
                        }
                    }
                    setTextColor(getColor(android.R.color.holo_green_dark))
                    visibility = View.VISIBLE
                }
                if (result.receiptUrl.isNotBlank() || result.decisionId.isNotBlank())
                    binding.btnViewProof.visibility = View.VISIBLE
                Toast.makeText(this, "Payment authorised âœ“", Toast.LENGTH_SHORT).show()
            }

            is PaymentResult.StepUpRequired -> showStepUpDialog(result.challengeType)

            is PaymentResult.Blocked -> {
                val threatMsg = when {
                    result.threatType.contains("RASP_DEV_025", ignoreCase = true) ->
                        "ðŸ–¥ï¸  Screen Mirroring Detected\n\nNonashield RASP_DEV_025 detected screen casting to another device. Payment blocked."
                    result.threatType.contains("ROOT", ignoreCase = true) ->
                        "âš ï¸  Rooted Device\n\nPayments disabled on rooted devices."
                    result.threatType.contains("HOOK", ignoreCase = true) ->
                        "âš ï¸  Runtime Hook Detected\n\nCode injection framework is active."
                    result.threatType.contains("BIO", ignoreCase = true) ->
                        "ðŸ§¬  Behavioral Identity Mismatch\n\nBiometric signals do not match enrolled user."
                    else -> "ðŸš«  Blocked by NonaShield\n\n${result.reason}"
                }
                binding.tvResult.apply {
                    text = threatMsg
                    setTextColor(getColor(android.R.color.holo_red_dark))
                    visibility = View.VISIBLE
                }
            }

            is PaymentResult.Failure -> {
                binding.tvResult.apply {
                    text = "âš ï¸  Error: ${result.reason}"
                    setTextColor(getColor(android.R.color.holo_orange_dark))
                    visibility = View.VISIBLE
                }
            }
        }
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Demo 2: Non-Repudiation Receipt
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    private fun openReceipt() {
        if (lastDecisionId.isBlank() && lastReceiptUrl.isBlank()) {
            Toast.makeText(this, "No receipt â€” complete a payment first", Toast.LENGTH_SHORT).show()
            return
        }
        lifecycleScope.launch(Dispatchers.IO) {
            val receipt = if (lastDecisionId.isNotBlank())
                DiimeApiClient.getEvidenceReceipt(lastDecisionId) else null
            withContext(Dispatchers.Main) {
                if (receipt != null) showReceiptDialog(receipt)
                else if (lastReceiptUrl.isNotBlank())
                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(lastReceiptUrl)))
                else Toast.makeText(this@PaymentActivity, "Receipt not available yet", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun showReceiptDialog(receipt: EvidenceReceipt) {
        val chain = receipt.chainOfCustody.joinToString("\n") { "  $it" }
        val msg = buildString {
            append("â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”\n")
            append("ðŸ”  NON-REPUDIATION RECEIPT\n")
            append("â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”\n\n")
            append("Decision:  ${receipt.decisionId.take(24)}â€¦\n")
            append("Device:    ${receipt.deviceId.take(20)}â€¦\n")
            append("Action:    ${receipt.action}  â†’  ALLOW âœ“\n")
            append("Signed:    ${receipt.signedAtIso}\n\n")
            append("Payload Hash:\n  ${receipt.payloadHash.take(32)}â€¦\n\n")
            append("Server Sig (HMAC-SHA256):\n  ${receipt.serverSignature.take(32)}â€¦\n\n")
            append("Chain of Custody:\n$chain\n\n")
            append("Algorithm: ${receipt.signingAlgorithm}")
        }
        AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle("Cryptographic Proof")
            .setMessage(msg)
            .setPositiveButton("Open Full Receipt") { _, _ ->
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(receipt.receiptUrl)))
            }
            .setNegativeButton("Close", null)
            .show()
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Demo 4: Screen capture â€” companion advisory + threat block dialogs
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /**
     * Graceful advisory shown when COMPANION_SCREEN_SHARE_ACTIVE fires (MEDIUM).
     *
     * A verified companion app (WhatsApp Web, Telegram Desktop) is actively mirroring
     * the screen.  This is NOT a hard block â€” the source is trusted â€” but financial
     * data is visible on the external device.  We ask the user to pause sharing before
     * entering payment details.  The payment is NOT blocked; the user can dismiss and
     * proceed if they accept the risk (this matches the zero-trust advisory model: we
     * warn, the user decides, the backend records the elevated risk context).
     *
     * The companion signal clears automatically the instant they stop sharing
     * (DisplayListener.onDisplayRemoved fires â†’ SignalStateManager.clear()).
     */
    private fun showCompanionShareAdvisory() {
        AlertDialog.Builder(this)
            .setTitle("ðŸ“¡  Screen Being Shared")
            .setMessage(buildString {
                append("â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”\n")
                append("âš ï¸  ADVISORY  Â·  RASP_DEV_051\n")
                append("â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”\n\n")
                append("NonaShield detected that your screen is currently being mirrored ")
                append("via a trusted companion app (e.g. WhatsApp Web, Telegram Desktop).\n\n")
                append("Risk: The external device can see everything on your screen, including:\n")
                append("  â€¢ Payment amount and recipient\n")
                append("  â€¢ OTP codes as they appear\n")
                append("  â€¢ Account numbers and balances\n\n")
                append("Source: Verified companion app (trusted, not blocked)\n")
                append("Severity: MEDIUM  Â·  Advisory\n\n")
                append("For your security, please disconnect WhatsApp Web or close the companion\n")
                append("app before completing this payment.")
            })
            .setPositiveButton("Stop Sharing & Retry") { _, _ ->
                Toast.makeText(
                    this,
                    "Disconnect WhatsApp Web / Telegram Desktop, then tap Send Payment again.",
                    Toast.LENGTH_LONG
                ).show()
            }
            .setNeutralButton("Proceed Anyway") { _, _ ->
                // User explicitly accepts the risk â€” proceed with payment.
                // Backend receives COMPANION_SCREEN_SHARE_ACTIVE signal context and can
                // apply additional step-up or risk scoring as per its policy configuration.
                Toast.makeText(this, "Proceeding with elevated screen-share risk context", Toast.LENGTH_SHORT).show()
                companionShareAcknowledged = true
                initiatePayment()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showThreatBlockedDialog(threatId: String?) {
        val (title, message) = when {
            threatId?.contains("025") == true ->
                "ðŸ–¥ï¸  Screen Mirroring Detected" to
                    "NonaShield RASP sensor RASP_DEV_025 detected that your screen is being cast " +
                    "to another device.\n\nFinancial data would be visible to the attacker.\n\n" +
                    "Payment blocked. Disable screen mirroring and retry."
            threatId?.contains("051") == true || threatId?.contains("SCREEN_RECORDING") == true ->
                "ðŸ“±  Screen Recording Detected" to
                    "NonaShield RASP sensor RASP_DEV_051 detected active screen recording on this device.\n\n" +
                    "A recording app could capture your account details, OTP, or payment data.\n\n" +
                    "Payment blocked. Stop screen recording and retry."
            threatId?.contains("ROOT") == true ->
                "ðŸ”“  Root Detected" to "Root access detected. Payments disabled on rooted devices."
            threatId?.contains("HOOK") == true ->
                "ðŸª  Runtime Hook Detected" to "A code-injection framework is active. Payment blocked."
            threatId?.contains("VPN") == true ->
                "ðŸ”’  VPN Conflict Detected" to
                    "NonaShield RASP sensor NET_VPN_005 detected an active VPN connection.\n\n" +
                    "VPN traffic may intercept or modify payment data.\n\n" +
                    "Payment blocked. Disconnect VPN and retry."
            else ->
                "ðŸš«  Security Check Failed" to
                    "NonaShield detected a security violation. Restart the app after resolving it."
        }
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton("Contact Support") { _, _ ->
                Toast.makeText(this, "Contact your bank's fraud helpline", Toast.LENGTH_LONG).show()
            }
            .setNegativeButton("OK", null)
            .show()
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // UC-08: SIM Swap live detection dialog
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /**
     * Show the live SIM swap detection alert.
     *
     * This dialog is shown when the SIM fingerprint recorded at KYC enrollment
     * does not match the current SIM fingerprint â€” indicating a SIM swap has
     * occurred since the user enrolled.
     *
     * When biometric deviation is also elevated, the dual-signal confidence
     * reaches 1.00 (strongest possible detection â€” attacker physically has the
     * SIM AND is using a different biometric profile).
     *
     * Investor talking point:
     *   "The device just detected that the SIM card was changed since this user
     *    enrolled. In the SIM swap scenario, the attacker has ported the victim's
     *    number to their own SIM. NonaShield caught it using a cryptographic
     *    fingerprint of the SIM captured at enrollment â€” no carrier API needed."
     */
    private fun showSimSwapDialog(iccidChanged: Boolean, biometricDeviation: Float) {
        val confidence = when {
            iccidChanged && biometricDeviation > 0.30f -> 1.00f
            iccidChanged                               -> 0.70f
            else                                       -> 0.55f
        }
        val bioPct = (biometricDeviation * 100).toInt()

        AlertDialog.Builder(this)
            .setTitle("ðŸ“±  SIM Swap Detected â€” Payment Blocked")
            .setMessage(buildString {
                append("â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”\n")
                append("âš ï¸  LIVE DETECTION  Â·  SCAM_SS_001\n")
                append("â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”â”\n\n")
                append("The SIM card on this device does not match the SIM that was\n")
                append("present when this account enrolled.\n\n")
                append("Signal sources:\n")
                if (iccidChanged) {
                    append("  ðŸ”´ SIM Fingerprint: CHANGED  (MCC+MNC mismatch)\n")
                }
                if (biometricDeviation > 0.20f) {
                    append("  ðŸ”´ Behavioral deviation: $bioPct%  (6-channel biometric)\n")
                } else {
                    append("  ðŸŸ¡ Behavioral deviation: $bioPct%  (within baseline)\n")
                }
                append("\nDual-signal confidence:  ${(confidence * 100).toInt()}%\n")
                append("Threat ID:  SCAM_SS_001  Â·  sim_swap_proxy\n")
                append("Action:  BLOCK  Â·  CRITICAL\n\n")
                append("In production: payment blocked, account flagged for\n")
                append("manual review. Step-up re-enrollment required.")
            })
            .setPositiveButton("Contact Support") { _, _ ->
                Toast.makeText(this, "Contact your bank's fraud helpline", Toast.LENGTH_LONG).show()
            }
            .setNegativeButton("Close", null)
            .setCancelable(false)
            .show()
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Behavioral Identity Mismatch / Social Engineering detection
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    private fun showSocialEngineeringWarning(previousUser: String) {
        binding.cardSocialEngWarning.visibility = View.VISIBLE
        binding.tvSocialEngDetail.text =
            "Behavioral patterns do not match your enrolled profile. " +
            "Risk elevated â€” additional verification may be required."
        binding.tvRiskTier.text = "Risk: HIGH"
        binding.tvRiskTier.setBackgroundColor(getColor(android.R.color.holo_red_dark))
    }

    private fun showBiometricSocialEngAlert(summary: BiometricDeviationSummary) {
        val channels = summary.deviatingChannels
            .joinToString("\n") { "  ${it.statusIcon} ${it.name}: +${it.deviationPct}% deviation" }

        AlertDialog.Builder(this)
            .setTitle("ðŸ§¬  Social Engineering Detected")
            .setMessage(buildString {
                append("NonaShield behavioral biometrics engine has detected that the person ")
                append("currently interacting with this device does NOT match the enrolled user.\n\n")
                append("Composite identity deviation: ${summary.compositePct}%\n\n")
                append("Deviating channels (${summary.deviatingChannels.size}/6):\n")
                append(channels)
                append("\n\nThis is a strong signal of a social engineering attack â€” ")
                append("the device was handed to a different person who is attempting ")
                append("to initiate a payment.\n\n")
                append("Threat: USR_BEH_012 Â· SOCIAL_ENGINEERING_BIOMETRIC\n")
                append("Risk tier: HIGH â€” Step-up auth required")
            })
            .setPositiveButton("ðŸ”  Require Step-Up Auth") { _, _ ->
                Toast.makeText(this, "In production: OTP / biometric re-auth triggered", Toast.LENGTH_LONG).show()
            }
            .setCancelable(false)
            .show()
    }

    private fun showBiometricPaymentBlockedDialog(deviation: Float) {
        val summary = BehavioralSessionManager.buildDeviationSummary()
        AlertDialog.Builder(this)
            .setTitle("ðŸ§¬  Identity Mismatch â€” Payment Blocked")
            .setMessage(buildString {
                append("Behavioral biometrics deviation: ${"%.0f".format(deviation * 100)}%\n\n")
                append("The person currently using this device does not match the enrolled ")
                append("behavioral profile.\n\n")
                summary.deviatingChannels.forEach {
                    append("  ${it.statusIcon} ${it.name}: +${it.deviationPct}%\n")
                }
                append("\nNonaShield has blocked this payment and flagged this session ")
                append("for fraud review.")
            })
            .setPositiveButton("Contact Support") { _, _ ->
                Toast.makeText(this, "Contact your bank's fraud helpline", Toast.LENGTH_LONG).show()
            }
            .setNegativeButton("OK", null)
            .show()
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // UC-06: Identity Verification / KYC Enrollment
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    private fun promptKycEnrollment() {
        val deviceId = DiimeApp.enrollmentState?.deviceId ?: PayShieldSDK.getStableDeviceId()

        AlertDialog.Builder(this)
            .setTitle("ðŸªª  Identity Verification")
            .setMessage(buildString {
                append("Submit your identity documents for KYC verification.\n\n")
                append("  Document: Aadhaar + PAN (hashed, never stored as plaintext)\n")
                append("  Device ID: ${deviceId.take(16)}â€¦\n\n")
                append("Your biometric profile and SIM fingerprint will be captured " +
                    "at enrollment to protect against account takeover.")
            })
            .setPositiveButton("Verify Now") { _, _ ->
                performKycEnrollment("123456789012", "ABCDE1234F", deviceId)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun performKycEnrollment(aadhaar: String, pan: String, deviceId: String) {
        try {
            EdgeRiskEnforcer.assertAllowed()
        } catch (e: SecurityException) {
            binding.tvResult.text = "â›” KYC blocked â€” security risk detected\n${e.message}"
            binding.tvResult.setTextColor(getColor(android.R.color.holo_red_dark))
            binding.tvResult.visibility = View.VISIBLE
            return
        }
        setLoading(true)
        binding.tvResult.visibility = View.GONE

        lifecycleScope.launch(Dispatchers.IO) {
            val result = DiimeApiClient.submitKyc(aadhaar, pan, deviceId)
            withContext(Dispatchers.Main) {
                setLoading(false)
                showKycResult(result)
            }
        }
    }

    private fun showKycResult(result: com.diimeai.demo.network.KycResult) {
        val degree = result.enrollmentDegree

        val (statusIcon, statusColor) = when (result.status) {
            "APPROVED" -> "âœ…" to 0xFF00AA44.toInt()
            "BLOCKED"  -> "ðŸ”´" to 0xFFDD2222.toInt()
            "PENDING"  -> "â³" to 0xFFFFAA00.toInt()
            else       -> "âš ï¸" to 0xFFFF6600.toInt()
        }

        binding.tvResult.apply {
            text = buildString {
                append("$statusIcon  Identity Verification ${result.status}\n\n")
                append("KYC ID:  ${result.kycId.take(24)}â€¦\n")
                if (result.riskScore > 0) append("Risk:    ${result.riskScore}\n")
                if (result.reason.isNotBlank()) append("Reason:  ${result.reason}\n")
                when {
                    degree >= 3 -> append("\n\nAccount flagged for additional review by NonaShield fraud engine.")
                    degree == 2 -> append("\n\nAdditional verification required. Please contact your branch.")
                    else        -> append("\n\nIdentity verified. Your account is now protected.")
                }
            }
            setTextColor(when (result.status) {
                "APPROVED" -> getColor(android.R.color.holo_green_dark)
                "BLOCKED"  -> getColor(android.R.color.holo_red_dark)
                else       -> getColor(android.R.color.holo_orange_dark)
            })
            visibility = View.VISIBLE
        }
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Step-up dialog
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    private fun showStepUpDialog(challengeType: String) {
        AlertDialog.Builder(this)
            .setTitle("ðŸ”  Additional Verification Required")
            .setMessage(
                "NonaShield detected elevated risk.\n\nVerification: $challengeType\n\n" +
                "In production: OTP or biometric challenge sent to the enrolled user."
            )
            .setPositiveButton("Simulate Verify") { _, _ ->
                Toast.makeText(this, "Step-up verification â€” demo mode", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    /**
     * STEP_UP triggered by [PayShieldSDK.evaluateAtCheckpoint] (UC-PAYMENT-RISK).
     *
     * Fires when geo-velocity anomaly, high-amount + low device trust, or
     * transaction velocity exceeds the policy threshold.  In production the
     * customer's auth layer enforces an OTP/biometric challenge here.
     */
    private fun showPaymentRiskStepUpDialog(amount: Double, reason: String?) {
        val amountStr = "â‚¹${String.format("%,.0f", amount)}"
        AlertDialog.Builder(this)
            .setTitle("âš ï¸  Transaction Risk â€” Step-Up Required")
            .setMessage(
                "NonaShield has flagged this â‚¹$amountStr payment for elevated risk.\n\n" +
                "Reason: ${reason ?: "PAYMENT_RISK_STEP_UP"}\n\n" +
                "Risk factors evaluated by SDK:\n" +
                "  â€¢ Transaction amount tier (HIGH â‰¥ â‚¹1L)\n" +
                "  â€¢ Geo-velocity anomaly (impossible/high-velocity travel)\n" +
                "  â€¢ Device trust score\n" +
                "  â€¢ New beneficiary + payment velocity\n\n" +
                "In production: OTP or biometric challenge issued before proceeding.\n" +
                "RBI guideline: automatic hold on anomalous UPI/NEFT transactions."
            )
            .setPositiveButton("Simulate OTP Verify") { _, _ ->
                // Demo: proceed after simulated step-up (customer app would launch OTP screen)
                lifecycleScope.launch(Dispatchers.IO) {
                    val result = DiimeApiClient.initiatePayment(
                        amount      = amount,
                        currency    = "INR",
                        recipientId = binding.etRecipient.text.toString().trim(),
                        note        = binding.etNote.text.toString().trim()
                    )
                    withContext(Dispatchers.Main) { handlePaymentResult(result) }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Helpers
    // â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    private fun updateRiskBadge() {
        val dm = getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
        val isMirroring = dm.displays.size > 1
        val tier = if (isMirroring ||
            (BehavioralSessionManager.isComparisonMode && BehavioralSessionManager.deviationScore() > 0.55f))
            "HIGH"
        else
            EdgeRiskEnforcer.currentRiskTier()
        val label = when {
            isMirroring -> "Risk: HIGH Mirror"
            BehavioralSessionManager.isComparisonMode && tier == "HIGH" -> "Risk: HIGH Bio"

            else -> "Risk: $tier"
        }
        binding.tvRiskTier.apply {
            text = label
            setBackgroundColor(getColor(when (tier) {
                "HIGH"   -> android.R.color.holo_red_dark
                "MEDIUM" -> android.R.color.holo_orange_dark
                else     -> android.R.color.holo_green_dark
            }))
        }
    }

    private fun logout() {
        captureManager.sessionFlowAnalyzer.onScreenTransition()
        paymentTapCount = 0
        BehavioralSessionManager.fullReset()
        synchronized(DiimeApp.recentRaspSignals) { DiimeApp.recentRaspSignals.clear() }
        lastRenderedThreatTypes = emptyList()
        DiimeApiClient.clearSession()
        startActivity(Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_NEW_TASK)
        })
        finish()
    }

    private fun setLoading(loading: Boolean) {
        binding.btnSendPayment.isEnabled  = !loading
        binding.btnAttestAndPay.isEnabled = !loading
        binding.progressBar.visibility    = if (loading) View.VISIBLE else View.GONE
    }
}


