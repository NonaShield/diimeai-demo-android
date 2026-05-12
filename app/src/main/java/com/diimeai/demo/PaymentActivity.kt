package com.diimeai.demo

import android.content.Context
import android.content.Intent
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
import com.diimeai.demo.biometrics.BehavioralMonitor
import com.diimeai.demo.biometrics.DeviationSummary
import com.diimeai.demo.databinding.ActivityPaymentBinding
import com.diimeai.demo.network.DiimeApiClient
import com.diimeai.demo.network.EvidenceReceipt
import com.diimeai.demo.network.PaymentResult
import com.payshield.android.edge.EdgeRiskEnforcer
import com.payshield.sdk.enrollment.EnrollmentState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Payment screen — integrates all 4 investor demo scenarios.
 *
 *  Demo 2: Non-Repudiation   — "View Receipt" after ALLOW
 *  Demo 4: Screen Mirroring  — DisplayManager check → threat-specific dialog
 *  Demo 5: Social Engineering — live behavioral biometrics panel + user switch
 *
 *  Behavioral Biometrics (6 channels, passive, zero UX friction):
 *    1. Touch Pressure   — grip force / stress indicator
 *    2. Finger Geometry  — contact area (major/minor axis) — unique per user
 *    3. Swipe Velocity   — habitual motion speed pattern
 *    4. Hesitation       — DOWN→MOVE latency — cognitive load / uncertainty
 *    5. Phone Posture    — accelerometer pitch/roll — holding style
 *    6. Grip Stability   — gyroscope variance — fine-motor steadiness
 *
 *  On "Switch User" the baseline from Session A is saved.  Session B data is
 *  scored against it in real-time.  Investors watch the deviation bar climb as
 *  the new "user" interacts — USR_BEH_012 (SOCIAL_ENGINEERING_BIOMETRIC) fires
 *  when ≥ 3 channels deviate beyond threshold.
 */
class PaymentActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "PaymentActivity"
        private const val DASHBOARD_URL = "https://api.diimeai.com/dashboard/"

        const val EXTRA_USER_ID   = "USER_ID"
        const val EXTRA_PREV_USER = "PREV_USER_ID"   // Demo 5: set on switch

        /** Refresh the behavioral panel every 500 ms even without touch events. */
        private const val BIO_REFRESH_MS = 500L
    }

    private lateinit var binding: ActivityPaymentBinding

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
            BehavioralMonitor.enterComparisonMode()
            showSocialEngineeringWarning(previousUserId!!)
            binding.rowDeviationBar.visibility = View.VISIBLE
        } else {
            // Session A — build the user baseline
            BehavioralMonitor.start(this)
        }

        // Button wiring
        binding.btnSendPayment.setOnClickListener   { initiatePayment() }
        binding.btnViewDashboard.setOnClickListener { openDashboard() }
        binding.btnViewProof.setOnClickListener     { openReceipt() }
        binding.btnSwitchUser.setOnClickListener    { promptSwitchUser() }
        binding.btnLogout.setOnClickListener        { logout() }
    }

    override fun onResume() {
        super.onResume()
        updateRiskBadge()
        handler.post(bioRefreshRunnable)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(bioRefreshRunnable)
    }

    override fun onDestroy() {
        super.onDestroy()
        if (previousUserId == null) {
            // Only stop sensors if this is session A (session B borrows them)
            BehavioralMonitor.stop()
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Touch routing → BehavioralBiometricsCollector
    // ─────────────────────────────────────────────────────────────────────────

    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        // Feed every touch event to the behavioral engine (passive — no UX impact)
        BehavioralMonitor.record(event)
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
        val summary = BehavioralMonitor.buildDeviationSummary()

        // Calibration row
        if (summary.isCalibrated) {
            binding.rowCalibration.visibility = View.GONE
        } else {
            binding.rowCalibration.visibility = View.VISIBLE
            binding.progressCalibration.progress = summary.calibrationPct
            binding.tvCalibrationPct.text = "  ${summary.calibrationPct}%"
        }

        // Risk badge on the biometrics card
        if (BehavioralMonitor.isComparisonMode && summary.isCalibrated) {
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
            if (BehavioralMonitor.isComparisonMode && summary.hesitation.deviation > 0)
                " Δ${summary.hesitation.deviationPct}%" else ""
        binding.tvBioPosture.text   = "${summary.posture.statusIcon} ${"%.1f".format(summary.posture.value)}°" +
            if (BehavioralMonitor.isComparisonMode && summary.posture.deviation > 0)
                " Δ${summary.posture.deviationPct}%" else ""
        binding.tvBioGrip.text      = formatChannel(summary.grip)

        // Deviation bar (comparison mode only)
        if (BehavioralMonitor.isComparisonMode) {
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

    private fun formatChannel(ch: com.diimeai.demo.biometrics.ChannelStatus, unit: String = ""): String {
        val value = "${"%.2f".format(ch.value)}$unit"
        return if (BehavioralMonitor.isComparisonMode && ch.deviation > 0)
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

        // ── Demo 4: Screen mirroring direct check ─────────────────────────────
        val dm = getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
        if (dm.displays.size > 1) {
            Log.w(TAG, "[Demo4] Screen mirroring: ${dm.displays.size} displays active")
            showThreatBlockedDialog("RASP_DEV_025")
            return
        }

        // ── Demo 5: Behavioral mismatch gate ─────────────────────────────────
        if (BehavioralMonitor.isComparisonMode) {
            val dev = BehavioralMonitor.deviationScore()
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

        lifecycleScope.launch(Dispatchers.IO) {
            val result = DiimeApiClient.initiatePayment(
                amount      = amount,
                currency    = "INR",
                recipientId = recipient,
                note        = binding.etNote.text.toString().trim()
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
                        if (BehavioralMonitor.isComparisonMode) {
                            val dev = BehavioralMonitor.deviationScore()
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
            threatId?.contains("ROOT") == true ->
                "🔓  Root Detected" to "Root access detected. Payments disabled on rooted devices."
            threatId?.contains("HOOK") == true ->
                "🪝  Runtime Hook Detected" to "A code-injection framework is active. Payment blocked."
            else ->
                "🚫  Security Check Failed" to
                    "NonaShield detected a security violation. Restart the app after resolving it."
        }
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton("View SOC Dashboard") { _, _ -> openDashboard() }
            .setNegativeButton("OK", null)
            .show()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Demo 5: Social Engineering + Behavioral Biometrics
    // ─────────────────────────────────────────────────────────────────────────

    private fun showSocialEngineeringWarning(previousUser: String) {
        binding.cardSocialEngWarning.visibility = View.VISIBLE
        binding.tvSocialEngDetail.text =
            "Device ${DiimeApp.enrollmentState?.deviceId?.take(12) ?: ""}… previously registered " +
            "to a different account. Behavioral biometrics are being compared against the " +
            "original user's baseline in real-time."
        binding.tvSocialEngPreviousUser.text = "Previous account: $previousUser"
        binding.tvRiskTier.text = "Risk: HIGH"
        binding.tvRiskTier.setBackgroundColor(getColor(android.R.color.holo_red_dark))
    }

    private fun showBiometricSocialEngAlert(summary: DeviationSummary) {
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
        val summary = BehavioralMonitor.buildDeviationSummary()
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
            .setPositiveButton("View Dashboard") { _, _ -> openDashboard() }
            .setNegativeButton("OK", null)
            .show()
    }

    private fun promptSwitchUser() {
        val input = android.widget.EditText(this).apply {
            hint = "New username"
            setPadding(48, 32, 48, 32)
            setText("attacker_${System.currentTimeMillis() % 1000}")
        }
        AlertDialog.Builder(this)
            .setTitle("🔀  Switch User — Demo 5")
            .setMessage(
                "Simulate a social engineering attack:\n" +
                "same device, different account.\n\n" +
                "The behavioral biometrics baseline from the current session " +
                "will be saved. The new user's patterns will be compared " +
                "against it in real-time, deviations shown live."
            )
            .setView(input)
            .setPositiveButton("Switch") { _, _ ->
                val newUser = input.text.toString().trim().ifBlank { "attacker_user" }
                switchToUser(newUser)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun switchToUser(newUser: String) {
        val deviceId = DiimeApp.enrollmentState?.deviceId
            ?: DiimeApp.keyManager.getStableDeviceId()

        // Save the first user's behavioral baseline before the switch
        BehavioralMonitor.saveBaseline()

        DiimeApiClient.setSession(
            userId    = newUser,
            deviceId  = deviceId,
            sessionId = "sess_switch_${System.currentTimeMillis()}",
            jwt       = "eyJhbGciOiJFUzI1NiJ9.switched_user.demo"
        )

        startActivity(Intent(this, PaymentActivity::class.java).apply {
            putExtra(EXTRA_USER_ID,   newUser)
            putExtra(EXTRA_PREV_USER, currentUserId)
            addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP)
        })
        finish()
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
        val tier = if (isMirroring || (BehavioralMonitor.isComparisonMode && BehavioralMonitor.deviationScore() > 0.55f))
            "HIGH"
        else
            EdgeRiskEnforcer.currentRiskTier()
        val label = when {
            isMirroring -> "Risk: HIGH ⚠️ Mirror"
            BehavioralMonitor.isComparisonMode && tier == "HIGH" -> "Risk: HIGH 🧬 Bio"
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

    private fun openDashboard() {
        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(DASHBOARD_URL)))
    }

    private fun logout() {
        BehavioralMonitor.fullReset()
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
