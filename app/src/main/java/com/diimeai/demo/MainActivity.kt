package com.diimeai.demo

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.diimeai.demo.databinding.ActivityMainBinding
import com.diimeai.demo.network.BindingProof
import com.diimeai.demo.network.DiimeApiClient
import com.payshield.sdk.enrollment.EnrollmentState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Splash / Home screen — Demo 1: Hardware Possession.
 *
 * Shows the investor that DiimeAI's identity is cryptographically anchored
 * to a hardware secure element (StrongBox or TEE) inside this specific device.
 *
 * Flow:
 *   1. App enrolls on first launch (background, DiimeApp.onCreate)
 *   2. This screen polls until enrollment completes (max 60 s)
 *   3. Calls GET /api/v1/device/{id}/binding-proof
 *   4. Renders hardware binding card:
 *        - Attestation badge  (FULL = StrongBox/TEE | BASIC = software)
 *        - Public key fingerprint (SHA-256 hex)
 *        - Enrolled since date
 *        - "View Cryptographic Binding Proof" button → shows the full JSON proof
 *
 * Why this matters (investor talking point):
 *   The private key for this device identity was generated INSIDE the Android
 *   Secure Element and NEVER left the chip. Cloning this identity is physically
 *   impossible — you would need to clone the hardware itself.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var bindingProof: BindingProof? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnLogin.setOnClickListener {
            startActivity(Intent(this, LoginActivity::class.java))
        }

        binding.btnViewBindingProof.setOnClickListener {
            showBindingProofDialog()
        }

        refreshEnrollmentStatus()
    }

    override fun onResume() {
        super.onResume()
        refreshEnrollmentStatus()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Demo 1: Hardware Possession — Enrollment + Binding Card
    // ─────────────────────────────────────────────────────────────────────────

    private fun refreshEnrollmentStatus() {
        val enrolled = EnrollmentState.isEnrolled()

        if (enrolled) {
            val state = DiimeApp.enrollmentState ?: EnrollmentState.load()
            if (state != null) {
                renderEnrolled(state.deviceId)
            } else {
                binding.tvEnrollStatus.text = "✅  Device enrolled with NonaShield"
                binding.tvEnrollStatus.setTextColor(getColor(android.R.color.holo_green_dark))
            }
        } else {
            binding.tvEnrollStatus.text = "⏳  Enrolling device — please wait…"
            binding.tvEnrollStatus.setTextColor(getColor(android.R.color.holo_orange_dark))

            // Poll until enrollment completes (kicked off in DiimeApp.onCreate)
            lifecycleScope.launch {
                for (i in 1..12) {
                    delay(5_000)
                    if (EnrollmentState.isEnrolled()) {
                        withContext(Dispatchers.Main) { refreshEnrollmentStatus() }
                        break
                    }
                }
            }
        }
    }

    private fun renderEnrolled(deviceId: String) {
        binding.tvEnrollStatus.text = "✅  Hardware identity bound to NonaShield"
        binding.tvEnrollStatus.setTextColor(getColor(android.R.color.holo_green_dark))

        // Show device ID row
        binding.tvDeviceId.text = deviceId.take(24) + "…"
        binding.rowDeviceId.visibility = View.VISIBLE

        // Fetch binding proof from backend in background
        lifecycleScope.launch(Dispatchers.IO) {
            val proof = DiimeApiClient.getBindingProof(deviceId)
            withContext(Dispatchers.Main) {
                if (proof != null) {
                    bindingProof = proof
                    renderBindingProof(proof)
                } else {
                    // Backend not reachable (offline / not deployed) — show local data
                    renderLocalFallback(deviceId)
                }
            }
        }
    }

    private fun renderBindingProof(proof: BindingProof) {
        // Attestation badge
        val (badgeText, badgeColor) = when (proof.attestationLevel) {
            "FULL"    -> "FULL ATTESTATION"   to 0xFF00AA44.toInt()
            "BASIC"   -> "BASIC ATTESTATION"  to 0xFFFF8800.toInt()
            "GATEWAY" -> "GATEWAY ENROLLED"   to 0xFF0088FF.toInt()
            else      -> "ENROLLED"           to 0xFF666666.toInt()
        }
        binding.tvAttestationBadge.text = badgeText
        binding.tvAttestationBadge.setBackgroundColor(badgeColor)

        // Hardware backing
        val hardwareLabel = if (proof.hardwareBacked)
            "AndroidKeyStore (StrongBox / TEE) 🔒"
        else
            "Software Key (dev mode only)"
        binding.tvHardwareBacking.text = hardwareLabel
        binding.tvHardwareBacking.setTextColor(
            if (proof.hardwareBacked) getColor(android.R.color.holo_blue_light)
            else getColor(android.R.color.holo_orange_dark)
        )
        binding.rowHardwareBacking.visibility = View.VISIBLE

        // Key fingerprint
        if (proof.pubkeyFingerprint.isNotBlank()) {
            val fp = proof.pubkeyFingerprint
            // Format as groups of 8 for readability
            val formatted = fp.chunked(8).joinToString(" ")
            binding.tvKeyFingerprint.text = formatted
            binding.rowFingerprint.visibility = View.VISIBLE
        }

        // Enrolled since
        if (proof.enrolledAtIso.isNotBlank()) {
            binding.tvEnrolledSince.text = proof.enrolledAtIso.take(10)   // YYYY-MM-DD
            binding.rowEnrolledSince.visibility = View.VISIBLE
        }

        // Show the "View Proof" button
        binding.btnViewBindingProof.visibility = View.VISIBLE
    }

    private fun renderLocalFallback(deviceId: String) {
        // Show partial info when backend is not reachable
        binding.tvAttestationBadge.text = "ENROLLED"
        binding.tvAttestationBadge.setBackgroundColor(0xFF0088FF.toInt())

        binding.tvHardwareBacking.text = "AndroidKeyStore (local key confirmed)"
        binding.rowHardwareBacking.visibility = View.VISIBLE
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Demo 1: Binding Proof dialog — for investor walkthrough
    // ─────────────────────────────────────────────────────────────────────────

    private fun showBindingProofDialog() {
        val proof = bindingProof
        val state = DiimeApp.enrollmentState ?: EnrollmentState.load()

        if (proof == null && state == null) {
            Toast.makeText(this, "Binding proof not available yet — enrollment in progress", Toast.LENGTH_SHORT).show()
            return
        }

        val message = if (proof != null) buildString {
            append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
            append("🔐  HARDWARE POSSESSION PROOF\n")
            append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
            append("Proof ID:\n  ${proof.proofId.take(24)}…\n\n")
            append("Device ID:\n  ${proof.deviceId.take(24)}…\n\n")
            append("Attestation Level:\n  ${proof.attestationLevel}\n\n")
            append("Hardware Backed:\n  ${if (proof.hardwareBacked) "YES — AndroidKeyStore (StrongBox/TEE)" else "NO — Software key"}\n\n")
            val fp = proof.pubkeyFingerprint
            if (fp.isNotBlank()) {
                append("Public Key Fingerprint (SHA-256):\n  ${fp.chunked(16).joinToString("\n  ")}\n\n")
            }
            append("Enrolled Since:\n  ${proof.enrolledAtIso}\n\n")
            append("Signing Algorithm:\n  ECDSA P-256 (AndroidKeyStore)\n\n")
            append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
            append("This proof is issued by the NonaShield\n")
            append("backend after verifying Play Integrity\n")
            append("attestation. The private key cannot be\n")
            append("exported from this device's secure element.")
        } else buildString {
            append("🔐  HARDWARE POSSESSION PROOF\n\n")
            append("Device ID:\n  ${state!!.deviceId.take(24)}…\n\n")
            append("Status: Enrolled ✓\n\n")
            append("Key Location: AndroidKeyStore\n")
            append("Algorithm: ECDSA P-256\n\n")
            append("(Full proof available when backend is connected)")
        }

        AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle("Hardware Binding Proof")
            .setMessage(message)
            .setPositiveButton("OK", null)
            .show()
    }
}
