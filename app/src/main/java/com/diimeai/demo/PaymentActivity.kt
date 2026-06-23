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
import com.payshield.sdk.PayShieldEdgeInitializer
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
 * Banking home screen — real-time RASP protection active throughout.
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
    }

    private lateinit var binding: ActivityPaymentBinding

    // ── Behavioral SDK (NonaShield 11-field telemetry) ────────────────────────
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

    // ── Session state ─────────────────────────────────────────────────────────
    private var currentUserId:  String = ""
    private var previousUserId: String? = null

    // ── Demo 2 ────────────────────────────────────────────────────────────────
    private var lastReceiptUrl: String = ""
    private var lastDecisionId: String = ""

    // ── Biometric panel refresh ───────────────────────────────────────────────
    private val handler = Handler(Looper.getMainLooper())
    private val bioRefreshRunnable = object : Runnable {
        override fun run() {
            refreshBiometricPanel()
            handler.postDelayed(this, BIO_REFRESH_MS)
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lifecycle
    // ─────────────────────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityPaymentBinding.inflate(layoutInflater)
        setContentView(binding.root)

        currentUserId  = intent.getStringExtra(EXTRA_USER_ID)   ?: "User"
        previousUserId = intent.getStringExtra(EXTRA_PREV_USER)

        binding.tvWelcome.text = "Welcome, $currentUserId"
        EnrollmentState.load()?.let { binding.tvDeviceId.text = "Device: ${it.deviceId.take(16)}…" }
        updateRiskBadge()

        // ── Demo 5: Start behavioral biometrics session ───────────────────────
        if (previousUserId != null) {
            // This is Session B — comparison against Session A baseline
            BehavioralSessionManager.enterComparisonMode()
            showSocialEngineeringWarning(previousUserId!!)
            binding.rowDeviationBar.visibility = View.VISIBLE
        } else {
            // Session A — build the user baseline
            BehavioralSessionManager.start(this)
        }

        // Button wiring
        binding.btnSendPayment.setOnClickListener { initiatePayment() }
        binding.btnViewProof.setOnClickListener   { openReceipt() }
        binding.btnEnrollKyc.setOnClickListener   { promptKycEnrollment() }
        binding.btnLogout.setOnClickListener      { logout() }
    }

    override fun onResume() {
        super.onResume()
        updateRiskBadge()
        updateKycButtonLabel()
        handler.post(bioRefreshRunnable)

        // ── Behavioral: attach capture on every screen entry ───────────────────
        // keystrokeDynamics wraps amount / recipient / note EditText fields.
        // captureManager transparently intercepts all touch events on the root view.
        keystrokeDynamics.attachToRoot(binding.root)
        captureManager.attachTo(binding.root)
        // Record this screen entry as a transition — dwell-time measurement starts.
        captureManager.sessionFlowAnalyzer.onScreenTransition()
    }

    private fun updateKycButtonLabel() {
        binding.btnEnrollKyc.text = "🪪  Verify Identity"
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(bioRefreshRunnable)
        // ── Behavioral: detach listeners to avoid leaking references ───────────
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
     * in AndroidManifest.xml — the activity is NOT recreated on rotation).
     *
     * Increments [BehavioralFeatures.screenOrientationChanges] — backend field
     * [screen_orientation_changes] in BehavioralFeaturesPayload.
     */
    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        captureManager.recordOrientationChange(newConfig)
    }

    /**
     * Intercept system back press to record it in SessionFlowAnalyzer.
     *
     * [BehavioralFeatures.backtrackCount] is incremented — elevated back navigation
     * during payment correlates with hesitant / coached user behaviour (Romance Fraud).
     */
    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        captureManager.sessionFlowAnalyzer.onBackNavigation()
        @Suppress("DEPRECATION")
        super.onBackPressed()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Touch routing → BehavioralBiometricsCollector + BehavioralCaptureManager
    // ─────────────────────────────────────────────────────────────────────────

    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        // Feed every touch event to the behavioral engine (passive — no UX impact)
        BehavioralSessionManager.record(event)
        // Refresh panel immediately on UP events (gesture completed)
        if (event.actionMasked == MotionEvent.ACTION_UP) {
            handler.post { refreshBiometricPanel() }
        }
        return super.dispatchTouchEvent(event)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Behavioral biometrics panel
    // ─────────────────────────────────────────────────────────────────────────

    private fun refreshBiometricPanel() {
        val summary = BehavioralSessionManager.buildDeviationSummary()

        // Calibration row
        if (summary.isCalibrated) {
            binding.rowCalibration.visibility = View.GONE
        } else {
            binding.rowCalibration.visibility = View.VISIBLE
            binding.progressCalibration.progress = summary.calibrationPct
            binding.tvCalibrationPct.text = "  ${summary.calibrationPct}%"
        }

        // Risk badge on the biometrics card
        if (BehavioralSessionManager.isComparisonMode && summary.isCalibrated) {
            binding.tvBioRiskBadge.text = "${summary.riskLabel}  ${summary.compositePct}%"
            binding.tvBioRiskBadge.setBackgroundColor(summary.riskColor)
        } else if (summary.isCalibrated) {
            binding.tvBioRiskBadge.text = "BASELINE LOCKED ✓"
            binding.tvBioRiskBadge.setBackgroundColor(0xFF00AA44.toInt())
        } else {
            binding.tvBioRiskBadge.text = "CALIBRATING…"
            binding.tvBioRiskBadge.setBackgroundColor(0xFF444444.toInt())
        }

        // 6-channel rows
        binding.tvBioPressure.text  = formatChannel(summary.pressure)
        binding.tvBioFingerSize.text= formatChannel(summary.fingerSize,  "px")
        binding.tvBioSwipe.text     = formatChannel(summary.swipe, "px/ms")
        binding.tvBioHesitation.text= "${summary.hesitation.statusIcon} ${summary.hesitation.value.toLong()}ms" +
            if (BehavioralSessionManager.isComparisonMode && summary.hesitation.deviation > 0)
                " Δ${summary.hesitation.deviationPct}%" else ""
        binding.tvBioPosture.text   = "${summary.posture.statusIcon} ${"%.1f".format(summary.posture.value)}°" +
            if (BehavioralSessionManager.isComparisonMode && summary.posture.deviation > 0)
                " Δ${summary.posture.deviationPct}%" else ""
        binding.tvBioGrip.text      = formatChannel(summary.grip)

        // Deviation bar (comparison mode only)
        if (BehavioralSessionManager.isComparisonMode) {
            binding.rowDeviationBar.visibility = View.VISIBLE
            binding.progressDeviation.progress = summary.compositePct
            binding.progressDeviation.progressTintList =
                android.content.res.ColorStateList.valueOf(summary.riskColor)
            binding.tvDeviationPct.text = "${summary.compositePct}% deviation"
            binding.tvDeviationPct.setTextColor(summary.riskColor)

            // Channel breakdown
            val deviatingNames = summary.deviatingChannels.joinToString(" · ") {
                "${it.statusIcon} ${it.name} (+${it.deviationPct}%)"
            }
            binding.tvDeviationChannels.text =
                if (deviatingNames.isNotBlank()) deviatingNames
                else "  All channels within normal range"

            // Auto-show alert when ≥3 channels deviate (once)
            if (summary.deviatingChannels.size >= 3 && !socialEngAlertShown) {
                socialEngAlertShown = true
                showBiometricSocialEngAlert(summary)
            }
        }
    }

    private var socialEngAlertShown = false

    private fun formatChannel(ch: BiometricChannelStatus, unit: String = ""): String {
        val value = "${"%.2f".format(ch.value)}$unit"
        return if (BehavioralSessionManager.isComparisonMode && ch.deviation > 0)
            "${ch.statusIcon} $value  Δ${ch.deviationPct}%"
        else
            "${ch.statusIcon} $value"
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Payment flow
    // ─────────────────────────────────────────────────────────────────────────

    private fun initiatePayment() {
        val amount    = binding.etAmount.text.toString().toDoubleOrNull()
        val recipient = binding.etRecipient.text.toString().trim()

        if (amount == null || amount <= 0) { binding.etAmount.error = "Enter a valid amount"; return }
        if (recipient.isBlank()) { binding.etRecipient.error = "Recipient required"; return }

        // ── Screen capture check (mirroring + software recording) ─────────────
        val dm = getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
        if (dm.displays.size > 1) {
            Log.w(TAG, "[Demo4] Screen mirroring: ${dm.displays.size} displays active")
            showThreatBlockedDialog("RASP_DEV_025")
            return
        }
        // RASP_DEV_051: software screen recording detected by the continuous SDK loop
        if (PayShieldEdgeInitializer.hasScreenCaptureThreat()) {
            Log.w(TAG, "[Demo4] Screen capture threat active (RASP_DEV_051)")
            showThreatBlockedDialog("RASP_DEV_051")
            return
        }

        // ── UC-08 LIVE: SIM swap check ────────────────────────────────────────
        // Compare current SIM fingerprint against the one stored at KYC enrollment.
        // Combines with behavioral biometric deviation for dual-signal confidence.
        val simSwapSuspected = PayShieldEdgeInitializer.isSimSwapSuspected() == true
        val bioDev = BehavioralSessionManager.deviationScore()
        if (simSwapSuspected) {
            Log.w(TAG, "[UC-08] SIM swap suspected — bioDev=${(bioDev * 100).toInt()}%")
            showSimSwapDialog(iccidChanged = true, biometricDeviation = bioDev)
            // Fire live signal to backend asynchronously (don't block UI)
            val deviceId = DiimeApp.enrollmentState?.deviceId
                ?: PayShieldEdgeInitializer.getStableDeviceId()
            lifecycleScope.launch(Dispatchers.IO) {
                runCatching { DiimeApiClient.ingestLiveSimSwap(deviceId, bioDev, iccidChanged = true) }
                    .also { Log.i(TAG, "[UC-08] live ingest result: ${it.getOrNull()?.decision}") }
            }
            return
        }

        // ── Demo 5: Behavioral mismatch gate ─────────────────────────────────
        if (BehavioralSessionManager.isComparisonMode) {
            val dev = BehavioralSessionManager.deviationScore()
            if (dev > 0.55f) {
                showBiometricPaymentBlockedDialog(dev)
                return
            }
        }

        // ── Local RASP gate ───────────────────────────────────────────────────
        try {
            EdgeRiskEnforcer.assertAllowed()
        } catch (e: SecurityException) {
            showThreatBlockedDialog(EdgeRiskEnforcer.activeHighThreat())
            return
        }

        setLoading(true)
        binding.tvResult.visibility    = View.GONE
        binding.btnViewProof.visibility = View.GONE

        // Snapshot the note text on the UI thread before launching the coroutine.
        val noteText = binding.etNote.text.toString().trim()

        lifecycleScope.launch(Dispatchers.IO) {
            // ── Behavioral telemetry: send BEFORE payment so the backend decision
            //    engine has up-to-date behavioral features when it evaluates this
            //    PAYMENT action.  Fail-open — a network error here does NOT block
            //    the payment (BehavioralTelemetrySender returns null on error).
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

            val result = DiimeApiClient.initiatePayment(
                amount      = amount,
                currency    = "INR",
                recipientId = recipient,
                note        = noteText
            )
            withContext(Dispatchers.Main) {
                setLoading(false)
                handlePaymentResult(result)
            }
        }
    }

    private fun handlePaymentResult(result: PaymentResult) {
        when (result) {
            is PaymentResult.Success -> {
                lastReceiptUrl = result.receiptUrl
                lastDecisionId = result.decisionId
                binding.tvResult.apply {
                    text = buildString {
                        append("✅  Payment Authorised\n\n")
                        append("Txn ID   :  ${result.transactionId}\n")
                        append("Status   :  ${result.status}\n")
                        if (result.decisionId.isNotBlank())
                            append("Decision :  ${result.decisionId.take(18)}…\n")
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
                Toast.makeText(this, "Payment authorised ✓", Toast.LENGTH_SHORT).show()
            }

            is PaymentResult.StepUpRequired -> showStepUpDialog(result.challengeType)

            is PaymentResult.Blocked -> {
                val threatMsg = when {
                    result.threatType.contains("RASP_DEV_025", ignoreCase = true) ->
                        "🖥️  Screen Mirroring Detected\n\nNonashield RASP_DEV_025 detected screen casting to another device. Payment blocked."
                    result.threatType.contains("ROOT", ignoreCase = true) ->
                        "⚠️  Rooted Device\n\nPayments disabled on rooted devices."
                    result.threatType.contains("HOOK", ignoreCase = true) ->
                        "⚠️  Runtime Hook Detected\n\nCode injection framework is active."
                    result.threatType.contains("BIO", ignoreCase = true) ->
                        "🧬  Behavioral Identity Mismatch\n\nBiometric signals do not match enrolled user."
                    else -> "🚫  Blocked by NonaShield\n\n${result.reason}"
                }
                binding.tvResult.apply {
                    text = threatMsg
                    setTextColor(getColor(android.R.color.holo_red_dark))
                    visibility = View.VISIBLE
                }
            }

            is PaymentResult.Failure -> {
                binding.tvResult.apply {
                    text = "⚠️  Error: ${result.reason}"
                    setTextColor(getColor(android.R.color.holo_orange_dark))
                    visibility = View.VISIBLE
                }
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Demo 2: Non-Repudiation Receipt
    // ─────────────────────────────────────────────────────────────────────────

    private fun openReceipt() {
        if (lastDecisionId.isBlank() && lastReceiptUrl.isBlank()) {
            Toast.makeText(this, "No receipt — complete a payment first", Toast.LENGTH_SHORT).show()
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
            append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
            append("🔏  NON-REPUDIATION RECEIPT\n")
            append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
            append("Decision:  ${receipt.decisionId.take(24)}…\n")
            append("Device:    ${receipt.deviceId.take(20)}…\n")
            append("Action:    ${receipt.action}  →  ALLOW ✓\n")
            append("Signed:    ${receipt.signedAtIso}\n\n")
            append("Payload Hash:\n  ${receipt.payloadHash.take(32)}…\n\n")
            append("Server Sig (HMAC-SHA256):\n  ${receipt.serverSignature.take(32)}…\n\n")
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

    // ─────────────────────────────────────────────────────────────────────────
    // Demo 4: Screen Mirroring / threat-specific dialog
    // ─────────────────────────────────────────────────────────────────────────

    private fun showThreatBlockedDialog(threatId: String?) {
        val (title, message) = when {
            threatId?.contains("025") == true ->
                "🖥️  Screen Mirroring Detected" to
                    "NonaShield RASP sensor RASP_DEV_025 detected that your screen is being cast " +
                    "to another device.\n\nFinancial data would be visible to the attacker.\n\n" +
                    "Payment blocked. Disable screen mirroring and retry."
            threatId?.contains("051") == true || threatId?.contains("SCREEN_RECORDING") == true ->
                "📱  Screen Recording Detected" to
                    "NonaShield RASP sensor RASP_DEV_051 detected active screen recording on this device.\n\n" +
                    "A recording app could capture your account details, OTP, or payment data.\n\n" +
                    "Payment blocked. Stop screen recording and retry."
            threatId?.contains("ROOT") == true ->
                "🔓  Root Detected" to "Root access detected. Payments disabled on rooted devices."
            threatId?.contains("HOOK") == true ->
                "🪝  Runtime Hook Detected" to "A code-injection framework is active. Payment blocked."
            threatId?.contains("VPN") == true ->
                "🔒  VPN Conflict Detected" to
                    "NonaShield RASP sensor NET_VPN_005 detected an active VPN connection.\n\n" +
                    "VPN traffic may intercept or modify payment data.\n\n" +
                    "Payment blocked. Disconnect VPN and retry."
            else ->
                "🚫  Security Check Failed" to
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

    // ─────────────────────────────────────────────────────────────────────────
    // UC-08: SIM Swap live detection dialog
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Show the live SIM swap detection alert.
     *
     * This dialog is shown when the SIM fingerprint recorded at KYC enrollment
     * does not match the current SIM fingerprint — indicating a SIM swap has
     * occurred since the user enrolled.
     *
     * When biometric deviation is also elevated, the dual-signal confidence
     * reaches 1.00 (strongest possible detection — attacker physically has the
     * SIM AND is using a different biometric profile).
     *
     * Investor talking point:
     *   "The device just detected that the SIM card was changed since this user
     *    enrolled. In the SIM swap scenario, the attacker has ported the victim's
     *    number to their own SIM. NonaShield caught it using a cryptographic
     *    fingerprint of the SIM captured at enrollment — no carrier API needed."
     */
    private fun showSimSwapDialog(iccidChanged: Boolean, biometricDeviation: Float) {
        val confidence = when {
            iccidChanged && biometricDeviation > 0.30f -> 1.00f
            iccidChanged                               -> 0.70f
            else                                       -> 0.55f
        }
        val bioPct = (biometricDeviation * 100).toInt()

        AlertDialog.Builder(this)
            .setTitle("📱  SIM Swap Detected — Payment Blocked")
            .setMessage(buildString {
                append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                append("⚠️  LIVE DETECTION  ·  SCAM_SS_001\n")
                append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
                append("The SIM card on this device does not match the SIM that was\n")
                append("present when this account enrolled.\n\n")
                append("Signal sources:\n")
                if (iccidChanged) {
                    append("  🔴 SIM Fingerprint: CHANGED  (MCC+MNC mismatch)\n")
                }
                if (biometricDeviation > 0.20f) {
                    append("  🔴 Behavioral deviation: $bioPct%  (6-channel biometric)\n")
                } else {
                    append("  🟡 Behavioral deviation: $bioPct%  (within baseline)\n")
                }
                append("\nDual-signal confidence:  ${(confidence * 100).toInt()}%\n")
                append("Threat ID:  SCAM_SS_001  ·  sim_swap_proxy\n")
                append("Action:  BLOCK  ·  CRITICAL\n\n")
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

    // ─────────────────────────────────────────────────────────────────────────
    // Behavioral Identity Mismatch / Social Engineering detection
    // ─────────────────────────────────────────────────────────────────────────

    private fun showSocialEngineeringWarning(previousUser: String) {
        binding.cardSocialEngWarning.visibility = View.VISIBLE
        binding.tvSocialEngDetail.text =
            "Behavioral patterns do not match your enrolled profile. " +
            "Risk elevated — additional verification may be required."
        binding.tvRiskTier.text = "Risk: HIGH"
        binding.tvRiskTier.setBackgroundColor(getColor(android.R.color.holo_red_dark))
    }

    private fun showBiometricSocialEngAlert(summary: BiometricDeviationSummary) {
        val channels = summary.deviatingChannels
            .joinToString("\n") { "  ${it.statusIcon} ${it.name}: +${it.deviationPct}% deviation" }

        AlertDialog.Builder(this)
            .setTitle("🧬  Social Engineering Detected")
            .setMessage(buildString {
                append("NonaShield behavioral biometrics engine has detected that the person ")
                append("currently interacting with this device does NOT match the enrolled user.\n\n")
                append("Composite identity deviation: ${summary.compositePct}%\n\n")
                append("Deviating channels (${summary.deviatingChannels.size}/6):\n")
                append(channels)
                append("\n\nThis is a strong signal of a social engineering attack — ")
                append("the device was handed to a different person who is attempting ")
                append("to initiate a payment.\n\n")
                append("Threat: USR_BEH_012 · SOCIAL_ENGINEERING_BIOMETRIC\n")
                append("Risk tier: HIGH — Step-up auth required")
            })
            .setPositiveButton("🔐  Require Step-Up Auth") { _, _ ->
                Toast.makeText(this, "In production: OTP / biometric re-auth triggered", Toast.LENGTH_LONG).show()
            }
            .setCancelable(false)
            .show()
    }

    private fun showBiometricPaymentBlockedDialog(deviation: Float) {
        val summary = BehavioralSessionManager.buildDeviationSummary()
        AlertDialog.Builder(this)
            .setTitle("🧬  Identity Mismatch — Payment Blocked")
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

    // ─────────────────────────────────────────────────────────────────────────
    // UC-06: Identity Verification / KYC Enrollment
    // ─────────────────────────────────────────────────────────────────────────

    private fun promptKycEnrollment() {
        val deviceId = DiimeApp.enrollmentState?.deviceId ?: PayShieldEdgeInitializer.getStableDeviceId()

        AlertDialog.Builder(this)
            .setTitle("🪪  Identity Verification")
            .setMessage(buildString {
                append("Submit your identity documents for KYC verification.\n\n")
                append("  Document: Aadhaar + PAN (hashed, never stored as plaintext)\n")
                append("  Device ID: ${deviceId.take(16)}…\n\n")
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
            binding.tvResult.text = "⛔ KYC blocked — security risk detected\n${e.message}"
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
            "APPROVED" -> "✅" to 0xFF00AA44.toInt()
            "BLOCKED"  -> "🔴" to 0xFFDD2222.toInt()
            "PENDING"  -> "⏳" to 0xFFFFAA00.toInt()
            else       -> "⚠️" to 0xFFFF6600.toInt()
        }

        binding.tvResult.apply {
            text = buildString {
                append("$statusIcon  Identity Verification ${result.status}\n\n")
                append("KYC ID:  ${result.kycId.take(24)}…\n")
                if (result.riskScore.isNotBlank()) append("Risk:    ${result.riskScore}\n")
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

    // ─────────────────────────────────────────────────────────────────────────
    // Step-up dialog
    // ─────────────────────────────────────────────────────────────────────────

    private fun showStepUpDialog(challengeType: String) {
        AlertDialog.Builder(this)
            .setTitle("🔐  Additional Verification Required")
            .setMessage(
                "NonaShield detected elevated risk.\n\nVerification: $challengeType\n\n" +
                "In production: OTP or biometric challenge sent to the enrolled user."
            )
            .setPositiveButton("Simulate Verify") { _, _ ->
                Toast.makeText(this, "Step-up verification — demo mode", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private fun updateRiskBadge() {
        val dm = getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
        val isMirroring = dm.displays.size > 1
        val simSwap     = PayShieldEdgeInitializer.isSimSwapSuspected() == true
        val tier = if (isMirroring || simSwap ||
            (BehavioralSessionManager.isComparisonMode && BehavioralSessionManager.deviationScore() > 0.55f))
            "HIGH"
        else
            EdgeRiskEnforcer.currentRiskTier()
        val label = when {
            isMirroring -> "Risk: HIGH ⚠️ Mirror"
            simSwap     -> "Risk: HIGH 📱 SIM Swap"
            BehavioralSessionManager.isComparisonMode && tier == "HIGH" -> "Risk: HIGH 🧬 Bio"
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
        // Record screen exit before clearing state.
        captureManager.sessionFlowAnalyzer.onScreenTransition()
        BehavioralSessionManager.fullReset()
        DiimeApiClient.clearSession()
        startActivity(Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_NEW_TASK)
        })
        finish()
    }

    private fun setLoading(loading: Boolean) {
        binding.btnSendPayment.isEnabled = !loading
        binding.progressBar.visibility   = if (loading) View.VISIBLE else View.GONE
    }
}
