package com.diimeai.demo

import android.content.Intent
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
import com.diimeai.demo.network.PaymentResult
import com.payshield.android.edge.EdgeRiskEnforcer
import com.payshield.sdk.enrollment.EnrollmentState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Payment screen — protected by the full NonaShield pipeline.
 *
 * This is the key integration demo for investors / customers:
 *
 *  USER taps "Send Payment"
 *    │
 *    ▼
 *  [PRE-CHECK] EdgeRiskEnforcer.assertAllowed()
 *    — If HIGH risk → SecurityException → Show blocked UI
 *    │
 *    ▼
 *  OkHttp call → PinningInterceptor
 *    — X-PayShield-Token (Base64Url canonical JSON: act, bh, did, exp, nonce, rng, sid, ts, uid)
 *    — X-PayShield-Signature (alg=ECDSA_P256;sig=...)
 *    — X-Edge-Risk-Level (0-100 fused RASP score)
 *    — X-Device-Id, X-Timestamp, X-Nonce, X-Signature, X-TS, X-NONCE, X-Edge-Nonce
 *    │
 *    ▼
 *  nginx 5-phase Lua pipeline (api.diimeai.com:8443)
 *    Phase 1: header_validator, bot_detector, geo_enrichment
 *    Phase 2: nonce_validator, payload_hash_validator, signature_verifier
 *    Phase 3: time_validator, public_key_resolver, binding_validator, decision_validator
 *    Phase 4: policy_engine, secure_forwarder
 *    Phase 5: request_filter, edge_risk_handler
 *    │
 *    ▼
 *  Backend FastAPI → CDT composite decision
 *    — 200 ALLOW → proceed
 *    — 402 STEP_UP → show OTP dialog
 *    — 403 BLOCK → show blocked UI
 */
class PaymentActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "PaymentActivity"
        private const val DASHBOARD_URL = "https://api.diimeai.com/dashboard/"
    }

    private lateinit var binding: ActivityPaymentBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityPaymentBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val userId = intent.getStringExtra("USER_ID") ?: "User"
        binding.tvWelcome.text = "Welcome, $userId"

        // Show current RASP risk tier
        updateRiskBadge()

        // Show enrollment info
        EnrollmentState.load()?.let { state ->
            binding.tvDeviceId.text = "Device: ${state.deviceId.take(12)}…"
        }

        binding.btnSendPayment.setOnClickListener { initiatePayment() }
        binding.btnViewDashboard.setOnClickListener { openDashboard() }
        binding.btnLogout.setOnClickListener { logout() }
    }

    override fun onResume() {
        super.onResume()
        updateRiskBadge()
    }

    // ─────────────────────────────────────────────────────────────────────────

    private fun initiatePayment() {
        val amount      = binding.etAmount.text.toString().toDoubleOrNull()
        val recipient   = binding.etRecipient.text.toString().trim()

        if (amount == null || amount <= 0) {
            binding.etAmount.error = "Enter a valid amount"
            return
        }
        if (recipient.isBlank()) {
            binding.etRecipient.error = "Recipient required"
            return
        }

        // ── Pre-check: local RASP gate ────────────────────────────────────────
        // EdgeRiskEnforcer.assertAllowed() throws SecurityException if the device
        // was flagged HIGH risk.  This check is redundant with PinningInterceptor
        // but provides an immediate UI response before network I/O starts.
        try {
            EdgeRiskEnforcer.assertAllowed()
        } catch (e: SecurityException) {
            Log.e(TAG, "Local RASP block: ${e.message}")
            showBlockedDialog("Device security check failed. Please restart the app.")
            return
        }

        setLoading(true)
        binding.tvResult.visibility = View.GONE

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
                binding.tvResult.apply {
                    text = "✅ Payment initiated!\nTxn ID: ${result.transactionId}\nStatus: ${result.status}"
                    setTextColor(getColor(android.R.color.holo_green_dark))
                    visibility = View.VISIBLE
                }
                Toast.makeText(this, "Payment submitted successfully", Toast.LENGTH_SHORT).show()
            }

            is PaymentResult.StepUpRequired -> {
                showStepUpDialog(result.challengeType)
            }

            is PaymentResult.Blocked -> {
                binding.tvResult.apply {
                    text = "🚫 Blocked by NonaShield\n${result.reason}"
                    setTextColor(getColor(android.R.color.holo_red_dark))
                    visibility = View.VISIBLE
                }
                Log.w(TAG, "Payment blocked: ${result.reason}")
            }

            is PaymentResult.Failure -> {
                binding.tvResult.apply {
                    text = "⚠️ Error: ${result.reason}"
                    setTextColor(getColor(android.R.color.holo_orange_dark))
                    visibility = View.VISIBLE
                }
            }
        }
    }

    private fun showStepUpDialog(challengeType: String) {
        AlertDialog.Builder(this)
            .setTitle("Additional Verification Required")
            .setMessage("NonaShield detected elevated risk.\nVerification required: $challengeType\n\n(In production this would send an OTP or biometric prompt)")
            .setPositiveButton("Verify") { _, _ ->
                // In production: launch OTP / biometric verification,
                // then retry with step-up proof header.
                Toast.makeText(this, "Step-up verification flow — demo mode", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showBlockedDialog(reason: String) {
        AlertDialog.Builder(this)
            .setTitle("Security Block")
            .setMessage(reason)
            .setPositiveButton("OK") { _, _ ->
                startActivity(Intent(this, BlockedActivity::class.java).apply {
                    putExtra(BlockedActivity.EXTRA_REASON, reason)
                })
            }
            .setCancelable(false)
            .show()
    }

    private fun updateRiskBadge() {
        val tier = EdgeRiskEnforcer.currentRiskTier()
        binding.tvRiskTier.apply {
            text = "Risk: $tier"
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
        // Opens the Grafana investor dashboard in a browser
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
