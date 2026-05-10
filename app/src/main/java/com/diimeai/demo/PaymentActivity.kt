package com.diimeai.demo

import android.content.Context
import android.content.Intent
import android.hardware.display.DisplayManager
import android.net.Uri
import android.os.Bundle
import android.util.Log
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
import com.payshield.sdk.enrollment.EnrollmentState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Payment screen — protected by the full NonaShield pipeline.
 *
 * This single screen demonstrates 4 of the 5 investor use cases:
 *
 *  ┌─────────────────────────────────────────────────────────────────────┐
 *  │  Demo 2  Non-Repudiation  — "View Receipt" button appears on ALLOW  │
 *  │  Demo 4  Screen Mirroring — threat-specific block message            │
 *  │  Demo 5  Social Eng.      — device/user mismatch banner at top       │
 *  └─────────────────────────────────────────────────────────────────────┘
 *
 *  Pipeline (every payment tap):
 *    EdgeRiskEnforcer.assertAllowed()                        ← local RASP gate
 *    OkHttp → PinningInterceptor (11 PayShield headers)
 *    nginx  5-phase Lua pipeline
 *    backend CDT composite decision  →  ALLOW / STEP_UP / DENY
 */
class PaymentActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "PaymentActivity"
        private const val DASHBOARD_URL = "https://api.diimeai.com/dashboard/"

        // Extras used when launching this Activity
        const val EXTRA_USER_ID    = "USER_ID"
        const val EXTRA_PREV_USER  = "PREV_USER_ID"   // Demo 5: set when switching user
    }

    private lateinit var binding: ActivityPaymentBinding

    // Demo 2: last receipt URL so "View Receipt" can open it
    private var lastReceiptUrl: String = ""
    private var lastDecisionId: String = ""

    // Demo 5: previous user on this device (if any)
    private var previousUserId: String? = null
    private var currentUserId: String   = ""

    // ─────────────────────────────────────────────────────────────────────────
    // Lifecycle
    // ─────────────────────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityPaymentBinding.inflate(layoutInflater)
        setContentView(binding.root)

        currentUserId  = intent.getStringExtra(EXTRA_USER_ID) ?: "User"
        previousUserId = intent.getStringExtra(EXTRA_PREV_USER)

        binding.tvWelcome.text = "Welcome, $currentUserId"

        // Show current enrollment state
        EnrollmentState.load()?.let { state ->
            binding.tvDeviceId.text = "Device: ${state.deviceId.take(16)}…"
        }

        updateRiskBadge()

        // Demo 5: show social engineering banner if this device already had another user
        if (previousUserId != null) {
            showSocialEngineeringWarning(previousUserId!!)
        }

        binding.btnSendPayment.setOnClickListener { initiatePayment() }
        binding.btnViewDashboard.setOnClickListener { openDashboard() }
        binding.btnViewProof.setOnClickListener    { openReceipt() }
        binding.btnSwitchUser.setOnClickListener   { promptSwitchUser() }
        binding.btnLogout.setOnClickListener       { logout() }
    }

    override fun onResume() {
        super.onResume()
        updateRiskBadge()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Payment flow
    // ─────────────────────────────────────────────────────────────────────────

    private fun initiatePayment() {
        val amount    = binding.etAmount.text.toString().toDoubleOrNull()
        val recipient = binding.etRecipient.text.toString().trim()

        if (amount == null || amount <= 0) {
            binding.etAmount.error = "Enter a valid amount"
            return
        }
        if (recipient.isBlank()) {
            binding.etRecipient.error = "Recipient required"
            return
        }

        // ── Demo 4: Screen mirroring direct check ────────────────────────────
        // ScreenMirroringSignal (RASP_DEV_025) checks DisplayManager at signal
        // evaluation time. We also check here so the UI shows a specific message
        // BEFORE the network call, instead of a generic "security check failed".
        val dm = getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
        if (dm.displays.size > 1) {
            Log.w(TAG, "[Demo4] Screen mirroring detected: ${dm.displays.size} displays")
            showThreatBlockedDialog("RASP_DEV_025")
            return
        }

        // ── Other active RASP threats (root, hook, etc.) ─────────────────────
        val activeThreat = EdgeRiskEnforcer.activeHighThreat()
        if (activeThreat != null) {
            showThreatBlockedDialog(activeThreat)
            return
        }

        // ── Local RASP gate (redundant with PinningInterceptor, fast path) ────
        try {
            EdgeRiskEnforcer.assertAllowed()
        } catch (e: SecurityException) {
            Log.e(TAG, "Local RASP block: ${e.message}")
            showThreatBlockedDialog(threatId = null)
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
                        append("Txn ID  :  ${result.transactionId}\n")
                        append("Status  :  ${result.status}\n")
                        if (result.decisionId.isNotBlank()) {
                            append("Decision:  ${result.decisionId.take(18)}…\n")
                        }
                        append("\nNonaShield 5-phase pipeline: PASSED")
                    }
                    setTextColor(getColor(android.R.color.holo_green_dark))
                    visibility = View.VISIBLE
                }

                // Demo 2: Show "View Non-Repudiation Receipt" only when there's a proof to show
                if (result.receiptUrl.isNotBlank() || result.decisionId.isNotBlank()) {
                    binding.btnViewProof.visibility = View.VISIBLE
                }

                Toast.makeText(this, "Payment authorised ✓", Toast.LENGTH_SHORT).show()
            }

            is PaymentResult.StepUpRequired -> {
                showStepUpDialog(result.challengeType)
            }

            is PaymentResult.Blocked -> {
                // Demo 4: use threat-specific message if we know the threat type
                val threatMsg = when {
                    result.threatType.contains("RASP_DEV_025", ignoreCase = true) ->
                        "🖥️  Screen Mirroring Detected\n\nNonaShield detected that your screen is being mirrored to another device. Payment blocked to protect your financial data."
                    result.threatType.contains("ROOT", ignoreCase = true) ->
                        "⚠️  Rooted Device Detected\n\nPayments are disabled on rooted devices per NonaShield policy."
                    result.threatType.contains("HOOK", ignoreCase = true) ->
                        "⚠️  Runtime Hook Detected\n\nA code injection framework is active. Payment blocked."
                    result.threatType.isNotBlank() ->
                        "🚫  Security Block\n\nThreat: ${result.threatType}\n${result.reason}"
                    else ->
                        "🚫  Blocked by NonaShield\n\n${result.reason}"
                }

                binding.tvResult.apply {
                    text = threatMsg
                    setTextColor(getColor(android.R.color.holo_red_dark))
                    visibility = View.VISIBLE
                }
                Log.w(TAG, "Payment blocked: ${result.reason} threat=${result.threatType}")
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
        if (lastReceiptUrl.isNotBlank()) {
            // If we have a receipt URL, first try to fetch the rich receipt dialog
            fetchAndShowReceiptDialog()
        } else {
            Toast.makeText(this, "No receipt available — complete a payment first", Toast.LENGTH_SHORT).show()
        }
    }

    private fun fetchAndShowReceiptDialog() {
        if (lastDecisionId.isBlank() && lastReceiptUrl.isBlank()) {
            Toast.makeText(this, "No decision ID available", Toast.LENGTH_SHORT).show()
            return
        }

        lifecycleScope.launch(Dispatchers.IO) {
            val receipt = if (lastDecisionId.isNotBlank()) {
                DiimeApiClient.getEvidenceReceipt(lastDecisionId)
            } else null

            withContext(Dispatchers.Main) {
                if (receipt != null) {
                    showReceiptDialog(receipt)
                } else if (lastReceiptUrl.isNotBlank()) {
                    // Fallback: open in browser
                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(lastReceiptUrl)))
                } else {
                    Toast.makeText(
                        this@PaymentActivity,
                        "Receipt not yet available — please try again",
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
        }
    }

    private fun showReceiptDialog(receipt: EvidenceReceipt) {
        val chainText = receipt.chainOfCustody.joinToString("\n") { "  $it" }

        val message = buildString {
            append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
            append("🔏  NON-REPUDIATION RECEIPT\n")
            append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
            append("Decision ID:\n  ${receipt.decisionId.take(24)}…\n\n")
            append("Device ID:\n  ${receipt.deviceId.take(20)}…\n\n")
            append("Action:  ${receipt.action}\n")
            append("Verdict: ALLOW ✓\n")
            append("Signed:  ${receipt.signedAtIso}\n\n")
            append("Payload Hash (SHA-256):\n  ${receipt.payloadHash.take(32)}…\n\n")
            append("Server Signature (HMAC-SHA256):\n  ${receipt.serverSignature.take(32)}…\n\n")
            append("Chain of Custody:\n$chainText\n\n")
            append("Algorithm: ${receipt.signingAlgorithm}\n\n")
            append("Verify at:\n  ${receipt.receiptUrl}")
        }

        AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle("Cryptographic Proof")
            .setMessage(message)
            .setPositiveButton("Open Full Receipt") { _, _ ->
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(receipt.receiptUrl)))
            }
            .setNegativeButton("Close", null)
            .show()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Demo 4: Screen Mirroring / threat-specific blocked dialog
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Show a threat-specific block dialog.
     * [threatId] is the SDK ThreatId enum name — used to produce a precise
     * human-readable message for the investor demo.
     */
    private fun showThreatBlockedDialog(threatId: String?) {
        val (title, message) = when {
            threatId?.contains("025") == true || threatId?.contains("SCREEN_MIRROR") == true ->
                "🖥️  Screen Mirroring Detected" to
                    "NonaShield RASP sensor RASP_DEV_025 detected that your screen is being cast " +
                    "to another device.\n\n" +
                    "Financial data could be captured by a remote attacker.\n\n" +
                    "Action: Payment blocked. Please disable screen mirroring and try again."

            threatId?.contains("ROOT") == true ->
                "🔓  Root / Jailbreak Detected" to
                    "This device has an unlocked bootloader or root access.\n\n" +
                    "NonaShield policy requires an unmodified OS for financial transactions."

            threatId?.contains("HOOK") == true ->
                "🪝  Runtime Hook Detected" to
                    "A code-injection framework (Frida / Xposed) is active.\n\n" +
                    "NonaShield blocked this payment to prevent credential theft."

            threatId?.contains("VPN") == true ->
                "🌐  Suspicious VPN Detected" to
                    "A VPN app combined with a user-installed CA certificate was detected.\n\n" +
                    "This combination matches common Man-in-the-Middle attack patterns."

            else ->
                "🚫  Security Check Failed" to
                    "NonaShield detected a runtime security violation on this device.\n\n" +
                    "Payment blocked. Restart the app after resolving the security issue."
        }

        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton("View SOC Dashboard") { _, _ -> openDashboard() }
            .setNegativeButton("OK", null)
            .show()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Demo 5: Social Engineering — Switch User
    // ─────────────────────────────────────────────────────────────────────────

    private fun showSocialEngineeringWarning(previousUser: String) {
        binding.cardSocialEngWarning.visibility = View.VISIBLE
        binding.tvSocialEngDetail.text =
            "This device (${DiimeApp.enrollmentState?.deviceId?.take(12) ?: "unknown"}…) " +
            "was previously used by a different account. " +
            "NonaShield has elevated the risk score to HIGH and flagged this session " +
            "for fraud review."
        binding.tvSocialEngPreviousUser.text = "Previous account: $previousUser"

        // Also raise the risk badge to HIGH immediately
        binding.tvRiskTier.apply {
            text = "Risk: HIGH"
            setBackgroundColor(getColor(android.R.color.holo_red_dark))
        }

        // Show a dialog to make it unmissable for the investor
        AlertDialog.Builder(this)
            .setTitle("⚠️  Social Engineering Alert")
            .setMessage(
                "Device  : ${DiimeApp.enrollmentState?.deviceId?.take(16) ?: "unknown"}…\n\n" +
                "Previous user: $previousUser\n" +
                "Current  user: $currentUserId\n\n" +
                "NonaShield detected that the same physical device is being used by a different " +
                "account. This is a strong signal of a SIM-swap / social engineering attack.\n\n" +
                "Risk tier elevated to HIGH. Payment requires step-up verification."
            )
            .setPositiveButton("Understood — Proceed with Step-Up") { _, _ ->
                Toast.makeText(this, "Step-up auth would be triggered in production", Toast.LENGTH_LONG).show()
            }
            .setCancelable(false)
            .show()
    }

    /**
     * Demo 5: Simulate switching to a different user account on the same device.
     * In production this would be triggered by a login from a different user
     * while the device_id remains the same — detected by DeviceSwitchDetector.
     */
    private fun promptSwitchUser() {
        val input = android.widget.EditText(this).apply {
            hint = "New username (e.g. attacker_user)"
            setPadding(48, 32, 48, 32)
            setText("attacker_${System.currentTimeMillis() % 1000}")
        }

        AlertDialog.Builder(this)
            .setTitle("🔀  Switch User (Demo 5)")
            .setMessage(
                "Simulate a social engineering attack:\n\n" +
                "Same device, different user account.\n\n" +
                "NonaShield will detect this via DeviceSwitchDetector and " +
                "elevate the risk score to HIGH."
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

        // Update session with new user — PinningInterceptor will include new uid
        val newSessionId = "sess_switch_${System.currentTimeMillis()}"
        DiimeApiClient.setSession(
            userId    = newUser,
            deviceId  = deviceId,
            sessionId = newSessionId,
            jwt       = "eyJhbGciOiJFUzI1NiJ9.switched_user.demo"
        )

        // Re-launch PaymentActivity with previous user flagged
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
                "NonaShield detected elevated risk.\n\n" +
                "Verification required: $challengeType\n\n" +
                "In production: an OTP or biometric challenge would be sent " +
                "and the payment retried with a step-up proof header."
            )
            .setPositiveButton("Simulate Verify") { _, _ ->
                Toast.makeText(this, "Step-up verification — demo mode", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // UI helpers
    // ─────────────────────────────────────────────────────────────────────────

    private fun updateRiskBadge() {
        // Demo 4: immediately show HIGH if screen mirroring is active
        val dm = getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
        val isMirroring = dm.displays.size > 1

        val tier = if (isMirroring) "HIGH" else EdgeRiskEnforcer.currentRiskTier()
        val label = if (isMirroring) "Risk: HIGH ⚠️ Mirror" else "Risk: $tier"

        binding.tvRiskTier.apply {
            text = label
            setBackgroundColor(
                getColor(when (tier) {
                    "HIGH"   -> android.R.color.holo_red_dark
                    "MEDIUM" -> android.R.color.holo_orange_dark
                    else     -> android.R.color.holo_green_dark
                })
            )
        }
    }

    private fun openDashboard() {
        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(DASHBOARD_URL)))
    }

    private fun logout() {
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
