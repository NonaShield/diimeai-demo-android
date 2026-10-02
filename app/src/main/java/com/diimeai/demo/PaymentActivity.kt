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
import com.diimeai.demo.databinding.ActivityPaymentBinding
import com.diimeai.demo.network.DiimeApiClient
import com.diimeai.demo.network.EvidenceReceipt
import com.diimeai.demo.network.PaymentResult
import com.payshield.sdk.PayShieldSDK
import com.payshield.sdk.policy.PolicyDecision
import com.payshield.sdk.enrollment.EnrollmentState
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
 *   - RASP gate: PayShieldSDK.assertAllowed() before every payment
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

    // ── Session state ─────────────────────────────────────────────────────────
    private var currentUserId:  String = ""
    private var previousUserId: String? = null

    // ── Demo 2 ────────────────────────────────────────────────────────────────
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

    // ── Biometric panel refresh ───────────────────────────────────────────────
    private val handler = Handler(Looper.getMainLooper())
    private val bioRefreshRunnable = object : Runnable {
        override fun run() {
            refreshBiometricPanel()
            refreshThreatTicker()
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

        // ── Demo 5: second user on the same device ────────────────────────────
        // The SDK builds the device owner's behaviour baseline by itself and compares every later session
        // against it; the panel below shows what it reports. A second user just gets the warning card.
        if (previousUserId != null) {
            showSocialEngineeringWarning(previousUserId!!)
            binding.rowDeviationBar.visibility = View.VISIBLE
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

    }

    private fun updateKycButtonLabel() {
        binding.btnEnrollKyc.text = "🪪  Verify Identity"
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(bioRefreshRunnable)
    }

    // Touches are captured by the SDK itself; the app only refreshes its panel when a gesture ends.
    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        // Refresh panel immediately on UP events (gesture completed)
        if (event.actionMasked == MotionEvent.ACTION_UP) {
            handler.post { refreshBiometricPanel() }
        }
        return super.dispatchTouchEvent(event)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Live RASP threat ticker
    // ─────────────────────────────────────────────────────────────────────────


    // Track last rendered set to avoid rebuilding the list on every 500ms tick
    private var lastRenderedThreatTypes: List<String> = emptyList()

    private fun refreshThreatTicker() {
        val signals = synchronized(DiimeApp.recentRaspSignals) {
            // Prune signals whose condition has resolved (TTL expired or OS clear callback fired).
            // Without this, the ticker keeps showing WhatsApp screen-share signals indefinitely
            // after the WhatsApp session closes — SignalStateManager knows they're gone but the
            // display buffer never removes them.
            DiimeApp.recentRaspSignals.removeAll { type ->
                !PayShieldSDK.isSignalActive(type)
            }
            DiimeApp.recentRaspSignals.toList()
        }
        // Newest last → show newest at top
        val ordered = signals.reversed()
        val types = ordered
        if (types == lastRenderedThreatTypes) return   // nothing changed
        lastRenderedThreatTypes = types

        val hasSignals = ordered.isNotEmpty()
        binding.tvNoThreatsDetected.visibility = if (hasSignals) View.GONE else View.VISIBLE
        binding.llRaspAlertList.visibility     = if (hasSignals) View.VISIBLE else View.GONE
        binding.tvAlertCount.text = if (hasSignals) "${ordered.size} active" else "0 active"
        binding.tvAlertCount.setTextColor(if (hasSignals) 0xFFFF6644.toInt() else 0xFF448844.toInt())

        binding.llRaspAlertList.removeAllViews()
        ordered.forEach { type ->
            val icon = "🟠"
            val name = PayShieldSDK.getSignalDisplayName(type)
            val tv = android.widget.TextView(this).apply {
                text = "$icon  $name"
                textSize = 12f
                setTextColor(0xFFFF8844.toInt())
                typeface = android.graphics.Typeface.MONOSPACE
                val pad = (8 * resources.displayMetrics.density).toInt()
                setPadding(0, pad / 2, 0, pad / 2)
            }
            binding.llRaspAlertList.addView(tv)
        }
    }

    // Behavioral biometrics panel
    // ─────────────────────────────────────────────────────────────────────────

    private fun refreshBiometricPanel() {
        val s = DemoBehaviour.snapshot()

        // Calibration: the SDK builds the baseline from normal use; show its progress until done.
        binding.rowCalibration.visibility = if (s.baselineReady) View.GONE else View.VISIBLE
        binding.progressCalibration.progress = s.baselinePct
        binding.tvCalibrationPct.text = "  ${s.baselinePct}%"

        when {
            !s.baselineReady -> {
                binding.tvBioRiskBadge.text = "BUILDING PROFILE: ${s.baselinePct}%"
                binding.tvBioRiskBadge.setBackgroundColor(0xFF334455.toInt())
                binding.tvBioHint.text = "Keep using the app normally to build your behaviour profile"
                binding.tvBioHint.visibility = View.VISIBLE
            }
            s.composite < 0.35f -> {
                binding.tvBioRiskBadge.text = "ENROLLED USER ✓  ${s.compositePct}%"
                binding.tvBioRiskBadge.setBackgroundColor(0xFF00AA44.toInt())
                binding.tvBioHint.visibility = View.GONE
            }
            s.composite < 0.65f -> {
                binding.tvBioRiskBadge.text = "DRIFT  ${s.compositePct}%"
                binding.tvBioRiskBadge.setBackgroundColor(0xFFCC8800.toInt())
                binding.tvBioHint.visibility = View.GONE
            }
            else -> {
                binding.tvBioRiskBadge.text = "DIFFERENT USER  ${s.compositePct}%"
                binding.tvBioRiskBadge.setBackgroundColor(0xFFCC2222.toInt())
                binding.tvBioHint.visibility = View.GONE
            }
        }

        binding.tvBioPressure.text   = DemoBehaviour.row(s, DemoBehaviour.PRESSURE)
        binding.tvBioFingerSize.text = DemoBehaviour.row(s, DemoBehaviour.FINGER_SIZE)
        binding.tvBioSwipe.text      = DemoBehaviour.row(s, DemoBehaviour.SWIPE)
        binding.tvBioHesitation.text = DemoBehaviour.row(s, DemoBehaviour.HESITATION)
        binding.tvBioPosture.text    = DemoBehaviour.row(s, DemoBehaviour.POSTURE)
        binding.tvBioGrip.text       = DemoBehaviour.row(s, DemoBehaviour.GRIP)
        binding.tvBioTremorZcr.text  = DemoBehaviour.row(s, DemoBehaviour.TREMOR)
        binding.tvBioJitter.text     = DemoBehaviour.row(s, DemoBehaviour.JITTER)
        binding.tvBioCurvature.text  = DemoBehaviour.row(s, DemoBehaviour.CURVATURE)

        if (s.baselineReady) {
            val color = when {
                s.composite < 0.35f -> 0xFF00AA44.toInt()
                s.composite < 0.65f -> 0xFFCC8800.toInt()
                else                -> 0xFFCC2222.toInt()
            }
            binding.rowDeviationBar.visibility = View.VISIBLE
            binding.progressDeviation.progress = s.compositePct
            binding.progressDeviation.progressTintList = android.content.res.ColorStateList.valueOf(color)
            binding.tvDeviationPct.text = "${s.compositePct}% deviation"
            binding.tvDeviationPct.setTextColor(color)
            binding.tvDeviationChannels.text =
                if (s.anomalies.isEmpty()) "  All channels within normal range"
                else s.anomalies.joinToString(" · ") { "🔴 ${it.name} (+${(it.deviationScore * 100).toInt()}%)" }

            val isHighDeviation = s.composite >= 0.65f
            binding.rowUserMismatchAlarm.visibility = if (isHighDeviation) View.VISIBLE else View.GONE
            if (isHighDeviation) {
                binding.tvUserMismatchDetail.text =
                    "Biometric deviation: ${s.compositePct}%  •  ${s.anomalies.size} channels flagged"
            }
            if (s.anomalies.size >= 3 && !socialEngAlertShown) {
                socialEngAlertShown = true
                showBiometricSocialEngAlert(s)
            }
        } else {
            binding.rowUserMismatchAlarm.visibility = View.GONE
        }
    }

    private var socialEngAlertShown = false

    // ─────────────────────────────────────────────────────────────────────────
    // Payment flow
    // ─────────────────────────────────────────────────────────────────────────

    private fun initiatePayment() {
        val amount    = binding.etAmount.text.toString().toDoubleOrNull()
        val recipient = binding.etRecipient.text.toString().trim()

        if (amount == null || amount <= 0) { binding.etAmount.error = "Enter a valid amount"; return }
        if (recipient.isBlank()) { binding.etRecipient.error = "Recipient required"; return }


        // Capture attestation mode on the UI thread before the coroutine captures it.
        // isDemoAttestationMode is always cleared after the payment completes.
        val isAttestation = isDemoAttestationMode

        if (!isAttestation) {
            // ── Screen capture check ──────────────────────────────────────────
            // Three-tier logic based on who owns the virtual display:
            //
            //   COMPANION_SCREEN_SHARE_ACTIVE (MEDIUM, advisory):
            //     A verified companion app (WhatsApp Web, Telegram Desktop) is mirroring
            //     the screen.  Screen IS at risk but source is known — show a graceful
            //     "please pause sharing" prompt rather than a hard block.
            //
            //   hasScreenCaptureThreat() (HIGH, hard block):
            //     Unknown recorder app, hardware mirroring (Chromecast/HDMI), or
            //     multiple virtual displays — cannot determine ownership.
            //
            //   dm.displays.size > 1 without any SDK signal:
            //     SDK may not have had time to evaluate the new display yet (race).
            //     Fall through to the screen capture threat check — the next
            //     evaluateNow() triggered by onDisplayAdded will update the signal.
            val skipCompanionCheck = companionShareAcknowledged.also { companionShareAcknowledged = false }
            if (!skipCompanionCheck && PayShieldSDK.hasCompanionScreenShare()) {
                Log.w(TAG, "[RASP] Companion screen share active — showing advisory")
                showCompanionShareAdvisory()
                return
            }
            if (PayShieldSDK.hasScreenCaptureThreat()) {
                Log.w(TAG, "[RASP] Screen capture threat active (RASP_DEV_051)")
                showThreatBlockedDialog("RASP_DEV_051")
                return
            }
            // Raw display-count fallback — guards the race window between onDisplayAdded()
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















            // ── Demo 5: Behavioral mismatch gate ──────────────────────────────
            DemoBehaviour.snapshot().let { s ->
                if (s.baselineReady && s.composite > 0.55f) {
                    showBiometricPaymentBlockedDialog(s)
                    return
                }
            }

            // ── Local RASP gate ────────────────────────────────────────────────
            try {
                PayShieldSDK.assertAllowed()
            } catch (e: SecurityException) {
                showThreatBlockedDialog(PayShieldSDK.getBlockDetails()?.threatId)
                return
            }
        }

        setLoading(true)
        binding.tvResult.visibility    = View.GONE
        binding.btnViewProof.visibility = View.GONE

        val noteText = binding.etNote.text.toString().trim()

        lifecycleScope.launch(Dispatchers.IO) {
            // Behavioral telemetry no longer sent via a dedicated /security/telemetry
            // call here -- that response was fail-open/log-only (never gated the
            // payment; evaluateAtCheckpoint below does that). Behavioral features
            // now ride the same /threats/batch flow as RASP threats, refreshed on
            // the SDK's 60s heartbeat (PayShieldEdgeInitializer) in addition to
            // every checkpoint -- same continuous-monitoring path as RASP.

            // ── SDK checkpoint gate — skipped in attestation mode ─────────────
            // Attestation demo is specifically for showing telemetry proof even
            // when the SDK would normally gate the payment.
            if (!isAttestation) {
                // Standard integration step 7: one check just before the payment, with the action name only.
                // Nothing about the amount, recipient or note is given to the SDK.
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
                        showPaymentRiskStepUpDialog(amount, checkpoint)
                    }
                    return@launch
                }
            }

            val result = DiimeApiClient.initiatePayment(
                amount      = amount,
                currency    = "INR",
                recipientId = recipient,
                note        = noteText
            )

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
        else "—"

        val msg = buildString {
            append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
            append("IMMUTABLE AUDIT PROOF\n")
            append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
            append("Txn ID :  ${result.transactionId}\n")
            append("Status :  ${result.status} — AUTHORISED\n\n")
            append("── Cryptographic Attestation ──\n\n")
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
            append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
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
                append("PAYMENT AUTHORISED — Attestation Demo\n\n")
                append("Txn ID  : ${result.transactionId}\n")
                append("Nonce   : ${result.nonce.take(16)}…\n")
                append("HW Key  : ${result.hwLevel}\n")
                append("Signed  : $iso\n\n")
                append("Cryptographic proof shown above.\n")
                append("Nonce, key, timestamp are ECDSA-\n")
                append("signed — unspoofable + immutable.")
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
                        append("✅  Payment Authorised\n\n")
                        append("Txn ID   :  ${result.transactionId}\n")
                        append("Status   :  ${result.status}\n")
                        if (result.decisionId.isNotBlank())
                            append("Decision :  ${result.decisionId.take(18)}…\n")
                        append("\nNonaShield 5-phase pipeline: PASSED\n")
                        DemoBehaviour.snapshot().let { s ->
                            if (s.baselineReady) append("Behavioral deviation: ${s.compositePct}%")
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
                        "🖥ï¸  Screen Mirroring Detected\n\nNonashield RASP_DEV_025 detected screen casting to another device. Payment blocked."
                    result.threatType.contains("ROOT", ignoreCase = true) ->
                        "⚠ï¸  Rooted Device\n\nPayments disabled on rooted devices."
                    result.threatType.contains("HOOK", ignoreCase = true) ->
                        "⚠ï¸  Runtime Hook Detected\n\nCode injection framework is active."
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
                    text = "⚠ï¸  Error: ${result.reason}"
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
    // Demo 4: Screen capture — companion advisory + threat block dialogs
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Graceful advisory shown when COMPANION_SCREEN_SHARE_ACTIVE fires (MEDIUM).
     *
     * A verified companion app (WhatsApp Web, Telegram Desktop) is actively mirroring
     * the screen.  This is NOT a hard block — the source is trusted — but financial
     * data is visible on the external device.  We ask the user to pause sharing before
     * entering payment details.  The payment is NOT blocked; the user can dismiss and
     * proceed if they accept the risk (this matches the zero-trust advisory model: we
     * warn, the user decides, the backend records the elevated risk context).
     *
     * The companion signal clears automatically the instant they stop sharing
     * (DisplayListener.onDisplayRemoved fires → SignalStateManager.clear()).
     */
    private fun showCompanionShareAdvisory() {
        AlertDialog.Builder(this)
            .setTitle("📡  Screen Being Shared")
            .setMessage(buildString {
                append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
                append("⚠ï¸  ADVISORY  ·  RASP_DEV_051\n")
                append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
                append("NonaShield detected that your screen is currently being mirrored ")
                append("via a trusted companion app (e.g. WhatsApp Web, Telegram Desktop).\n\n")
                append("Risk: The external device can see everything on your screen, including:\n")
                append("  • Payment amount and recipient\n")
                append("  • OTP codes as they appear\n")
                append("  • Account numbers and balances\n\n")
                append("Source: Verified companion app (trusted, not blocked)\n")
                append("Severity: MEDIUM  ·  Advisory\n\n")
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
                // User explicitly accepts the risk — proceed with payment.
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
                "🖥ï¸  Screen Mirroring Detected" to
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
                append("⚠ï¸  LIVE DETECTION  ·  SCAM_SS_001\n")
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

    private fun showBiometricSocialEngAlert(s: DemoBehaviour.Snapshot) {
        val channels = s.anomalies
            .joinToString("\n") { "  🔴 ${it.name}: +${(it.deviationScore * 100).toInt()}% deviation" }

        AlertDialog.Builder(this)
            .setTitle("🧬  Social Engineering Detected")
            .setMessage(buildString {
                append("NonaShield behavioral biometrics engine has detected that the person ")
                append("currently interacting with this device does NOT match the enrolled user.\n\n")
                append("Composite identity deviation: ${s.compositePct}%\n\n")
                append("Deviating channels (${s.anomalies.size}):\n")
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

    private fun showBiometricPaymentBlockedDialog(s: DemoBehaviour.Snapshot) {
        AlertDialog.Builder(this)
            .setTitle("🧬  Identity Mismatch — Payment Blocked")
            .setMessage(buildString {
                append("Behavioral biometrics deviation: ${s.compositePct}%\n\n")
                append("The person currently using this device does not match the enrolled ")
                append("behavioral profile.\n\n")
                s.anomalies.forEach {
                    append("  🔴 ${it.name}: +${(it.deviationScore * 100).toInt()}%\n")
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
        val deviceId = DiimeApp.enrollmentState?.deviceId ?: PayShieldSDK.getStableDeviceId()

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
            PayShieldSDK.assertAllowed()
        } catch (e: SecurityException) {
            binding.tvResult.text = "⛔ KYC blocked — security risk detected\n${e.message}"
            binding.tvResult.setTextColor(getColor(android.R.color.holo_red_dark))
            binding.tvResult.visibility = View.VISIBLE
            return
        }

        // NonaShield checkpoint — same call PaymentActivity.initiatePayment() already
        // makes for PAYMENT. Runs the on-device policy check AND fires the SDK's
        // parallel /api/v1/ingest call in the background (see
        // PayShieldEdgeInitializer.reportCheckpointToIngest) so this KYC action
        // reaches the real fraud/graph/compliance engine, not just the local-only
        // block flag checked above. Previously KYC had no per-action risk gate at
        // all, so an operator-issued remote force_block (or any KYC-specific
        // policy rule) could never stop enrollment.
        val checkpoint = runCatching { PayShieldSDK.evaluateAtCheckpoint(action = "KYC") }.getOrNull()
        if (checkpoint != null && checkpoint.decision == PolicyDecision.DENY) {
            binding.tvResult.text = "⛔ KYC blocked — ${checkpoint.reason}"
            binding.tvResult.setTextColor(getColor(android.R.color.holo_red_dark))
            binding.tvResult.visibility = View.VISIBLE
            return
        }
        if (checkpoint != null && checkpoint.decision == PolicyDecision.STEP_UP) {
            showStepUpDialog(checkpoint.reason)
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
            else       -> "⚠ï¸" to 0xFFFF6600.toInt()
        }

        binding.tvResult.apply {
            text = buildString {
                append("$statusIcon  Identity Verification ${result.status}\n\n")
                append("KYC ID:  ${result.kycId.take(24)}…\n")
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

    /**
     * STEP_UP triggered by [PayShieldSDK.evaluatePaymentCheckpoint] (UC-PAYMENT-RISK).
     *
     * Fires when geo-velocity anomaly, high-amount + low device trust, or
     * transaction velocity exceeds the policy threshold. When the live
     * /api/v1/ingest call issued a real TLT/AFA challenge ([hasRealChallenge]
     * below), this completes the actual RBI Mandate 2 second channel
     * (POST /api/v1/payment/confirm) instead of just re-attempting
     * /payment/initiate.
     */
    private fun showPaymentRiskStepUpDialog(
        amount:     Double,
        checkpoint: com.payshield.sdk.PayShieldCheckpoint.CheckpointResult,
    ) {
        val amountStr = "₹${String.format("%,.0f", amount)}"
        val hasRealChallenge = !checkpoint.challengeId.isNullOrBlank() &&
            !checkpoint.tlt.isNullOrBlank() && !checkpoint.afaNonce.isNullOrBlank()
        AlertDialog.Builder(this)
            .setTitle("⚠ï¸  Transaction Risk — Step-Up Required")
            .setMessage(
                "NonaShield has flagged this ₹$amountStr payment for elevated risk.\n\n" +
                "Reason: ${checkpoint.reason}\n\n" +
                "Risk factors evaluated by SDK:\n" +
                "  • Transaction amount tier (HIGH ≥ ₹1L)\n" +
                "  • Geo-velocity anomaly (impossible/high-velocity travel)\n" +
                "  • Device trust score\n" +
                "  • New beneficiary + payment velocity\n\n" +
                if (hasRealChallenge)
                    "Verify code: ${checkpoint.tltDisplay ?: "—"}\n\n" +
                    "RBI Mandate 2 (AFA): biometric-gated hardware-key signature required " +
                    "before this payment can proceed."
                else
                    "In production: OTP or biometric challenge issued before proceeding.\n" +
                    "RBI guideline: automatic hold on anomalous UPI/NEFT transactions."
            )
            .setPositiveButton(if (hasRealChallenge) "Simulate Biometric Verify" else "Simulate OTP Verify") { _, _ ->
                // Real AFA channel B (hasRealChallenge): sign SHA-256(afa_nonce|tlt|device_id)
                // with the hardware-backed device key, then POST /api/v1/payment/confirm — a
                // real host app would call BiometricPrompt here first; this demo labels the
                // button "Simulate" the same way the OTP fallback below always has, since no
                // actual biometric gate is wired into this dialog.
                // Fallback (no live challenge — offline/timed-out ingest call): re-attempt
                // /payment/initiate, same behavior this dialog had before this change.
                lifecycleScope.launch(Dispatchers.IO) {
                    val result = if (hasRealChallenge) {
                        val signature = PayShieldSDK.signAfaChallenge(
                            afaNonce = checkpoint.afaNonce!!,
                            tlt      = checkpoint.tlt!!,
                        )
                        if (signature.isBlank()) {
                            PaymentResult.Failure("Device signing failed — cannot complete step-up")
                        } else {
                            DiimeApiClient.confirmPayment(
                                challengeId  = checkpoint.challengeId!!,
                                tlt          = checkpoint.tlt!!,
                                afaSignature = signature,
                            )
                        }
                    } else {
                        DiimeApiClient.initiatePayment(
                            amount      = amount,
                            currency    = "INR",
                            recipientId = binding.etRecipient.text.toString().trim(),
                            note        = binding.etNote.text.toString().trim()
                        )
                    }
                    withContext(Dispatchers.Main) { handlePaymentResult(result) }
                }
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
        val bio = DemoBehaviour.snapshot()
        val bioHigh = bio.baselineReady && bio.composite > 0.55f
        val tier = if (isMirroring || bioHigh) "HIGH" else DemoBehaviour.riskTier()
        val label = when {
            isMirroring -> "Risk: HIGH Mirror"
            bioHigh -> "Risk: HIGH Bio"

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


