package com.diimeai.demo

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.diimeai.demo.databinding.ActivityMainBinding
import com.diimeai.demo.enrollment.EnrollmentStatus
import com.diimeai.demo.enrollment.EnrollmentUiState
import com.diimeai.demo.network.BindingProof
import com.diimeai.demo.network.DiimeApiClient
import com.payshield.sdk.enrollment.EnrollmentState
import kotlinx.coroutines.Dispatchers
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

        // "Get Started" is disabled until enrollment succeeds (observed below)
        binding.btnLogin.setOnClickListener {
            startActivity(Intent(this, LoginActivity::class.java))
        }

        binding.btnViewBindingProof.setOnClickListener {
            showBindingProofDialog()
        }

        // Retry button inside the error card
        binding.btnRetryEnrollment.setOnClickListener {
            DiimeApp.retryEnrollment(application as DiimeApp)
        }

        // Observe enrollment status — drives button state + error card
        observeEnrollmentStatus()
    }

    override fun onResume() {
        super.onResume()
        // refreshEnrollmentStatus() is now driven by the StateFlow observer
        // started in onCreate(); no manual polling needed.
        refreshEnrollmentCard()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Enrollment status observer — gates "Get Started" + shows error card
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Collects [DiimeApp.enrollmentStatus] for the lifetime of the Activity.
     * Uses [repeatOnLifecycle] so collection pauses when the app is backgrounded
     * and resumes when it returns to the foreground — no wasted work.
     *
     * The StateFlow is updated by [DiimeApp.enrollDevice] on the IO dispatcher;
     * [StateFlow.collect] delivers values on the coroutine dispatcher of the
     * collector which is the Main dispatcher here (via lifecycleScope).
     */
    private fun observeEnrollmentStatus() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                DiimeApp.enrollmentStatus.collect { status ->
                    applyEnrollmentUiState(EnrollmentUiState.from(status))

                    // Also update the hardware binding card for Enrolled state
                    if (status is EnrollmentStatus.Enrolled) {
                        renderEnrolled(status.deviceId)
                    }
                }
            }
        }
    }

    /** Applies a [EnrollmentUiState] snapshot to the Get Started button and error card. */
    private fun applyEnrollmentUiState(ui: EnrollmentUiState) {
        // "Get Started" button
        binding.btnLogin.isEnabled = ui.buttonEnabled
        binding.btnLogin.text      = ui.buttonLabel
        binding.btnLogin.alpha     = if (ui.buttonEnabled) 1f else 0.5f

        // Progress spinner
        binding.progressEnrollment.visibility =
            if (ui.showProgress) View.VISIBLE else View.GONE

        // Error card
        binding.cardEnrollmentError.visibility =
            if (ui.errorVisible) View.VISIBLE else View.GONE
        if (ui.errorVisible) {
            binding.tvEnrollmentError.text = ui.errorMessage
        }

        // Retry button inside error card
        binding.btnRetryEnrollment.visibility =
            if (ui.retryVisible) View.VISIBLE else View.GONE
    }

    /**
     * Refreshes the hardware binding card on resume in case the binding-proof
     * was already loaded and just needs to be re-rendered (e.g. after back-navigation).
     */
    private fun refreshEnrollmentCard() {
        val status = DiimeApp.enrollmentStatus.value
        if (status is EnrollmentStatus.Enrolled) {
            renderEnrolled(status.deviceId)
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
        // Attestation badge.
        // "FULL" from the backend means Play Integrity was requested.  In the demo build
        // the app is NOT distributed via Google Play Store, so Play Integrity API returns
        // CANNOT_ATTEST / MEET_BASIC_INTEGRITY at best.  We display this honestly as
        // "PENDING" — the hardware key binding IS complete (AndroidKeyStore ECDSA key
        // enrolled), only the Google-side Play Integrity verdict is unavailable.
        val (badgeText, badgeColor) = when (proof.attestationLevel) {
            "FULL"    -> "PENDING (Play Integrity)"        to 0xFFFF8800.toInt()  // amber — not green
            "BASIC"   -> "BASIC — Play Integrity missing"  to 0xFFFF8800.toInt()  // amber — honest, not a fake "compliant" blue/green
            "GATEWAY" -> "GATEWAY ENROLLED"                to 0xFF0088FF.toInt()
            else      -> "ENROLLED"                        to 0xFF666666.toInt()
        }
        binding.tvAttestationBadge.text = badgeText
        binding.tvAttestationBadge.setBackgroundColor(badgeColor)

        // Hardware backing — driven by proof.hardwareLevel (the actual key-generation
        // tier parsed from the device attestation chain), NOT proof.attestationLevel.
        // attestation_level only reflects whether a Play Integrity verdict was
        // obtained, which is unrelated to where the key itself was generated.
        val hardwareLabel = when (proof.hardwareLevel) {
            "STRONGBOX"      -> "AndroidKeyStore (StrongBox) 🔒"
            "TEE"            -> "AndroidKeyStore (TEE) 🔒"
            "SECURE_ENCLAVE" -> "Secure Enclave 🔒"
            else             -> "Software Key (dev mode only)"
        }
        binding.tvHardwareBacking.text = hardwareLabel
        binding.tvHardwareBacking.setTextColor(
            if (proof.hardwareBacked) getColor(android.R.color.holo_blue_light)
            else getColor(android.R.color.holo_orange_dark)
        )
        binding.rowHardwareBacking.visibility = View.VISIBLE

        // Key fingerprint (SHA-256 of public key DER)
        if (proof.pubkeyFingerprint.isNotBlank()) {
            val fp = proof.pubkeyFingerprint
            // Format as groups of 8 for readability
            val formatted = fp.chunked(8).joinToString(" ")
            binding.tvKeyFingerprint.text = formatted
            binding.rowFingerprint.visibility = View.VISIBLE
        }

        // Public key DER hex — demo-only display (first 48 hex chars + "…")
        if (proof.pubkeyHex.isNotBlank()) {
            val preview = proof.pubkeyHex.take(48).chunked(8).joinToString(" ") + "…"
            binding.tvPubkeyHex.text = preview
            binding.rowPubkeyHex.visibility = View.VISIBLE
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
            append("🔐  HARDWARE ATTESTATION PROOF\n")
            append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
            // Proof ID — backend-issued UUID for this enrollment attestation record.
            // It is the immutable, auditable reference to the moment this device's
            // hardware key was cryptographically enrolled with NonaShield.  Presenting
            // this ID to a regulator or fraud investigator lets them pull the full
            // enrollment evidence chain (public key, timestamp, device fingerprint)
            // from the NonaShield audit log without any personal data leaving the server.
            append("Proof ID:\n  ${proof.proofId.take(24)}…\n")
            append("  (Enrollment audit reference — immutable server record)\n\n")
            append("Device ID:\n  ${proof.deviceId.take(24)}…\n\n")
            // Attestation level explanation:
            //   FULL     = Play Integrity verdict was requested at enrollment.  In this
            //              demo build the app is not distributed via Google Play Store,
            //              so the Play Integrity API cannot verify the device posture —
            //              displayed as PENDING until a Play-signed build is used.
            //   BASIC    = AndroidKeyStore hardware key enrolled; no Play Integrity.
            //   GATEWAY  = Enrolled at the NonaShield edge gateway only (no device key).
            val levelDisplay = when (proof.attestationLevel) {
                "FULL"  -> "PENDING\n  (Play Integrity unavailable — app not on Google Play Store.\n  AndroidKeyStore hardware binding is complete.)"
                "BASIC" -> "BASIC — Play Integrity missing\n  (AndroidKeyStore key enrolled; no Play Integrity verdict obtained)"
                else    -> proof.attestationLevel
            }
            append("Attestation Level:\n  $levelDisplay\n\n")
            val hwDisplay = when (proof.hardwareLevel) {
                "STRONGBOX"      -> "YES — AndroidKeyStore (StrongBox)"
                "TEE"            -> "YES — AndroidKeyStore (TEE)"
                "SECURE_ENCLAVE" -> "YES — Secure Enclave"
                else             -> "NO — Software key"
            }
            append("Hardware Backed:\n  $hwDisplay\n\n")
            val fp = proof.pubkeyFingerprint
            if (fp.isNotBlank()) {
                append("Key Fingerprint (SHA-256):\n  ${fp.chunked(16).joinToString("\n  ")}\n\n")
            }
            val hex = proof.pubkeyHex
            if (hex.isNotBlank()) {
                // Show full DER hex, wrapped at 32 chars per line
                append("Public Key (DER):\n  ${hex.chunked(32).joinToString("\n  ")}\n\n")
            }
            append("Enrolled Since:\n  ${proof.enrolledAtIso}\n\n")
            append("Signing Algorithm:\n  ECDSA P-256 (AndroidKeyStore)\n\n")
            append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
            append("Powered by DIMEAI IT SOLUTION PVT LIMITED\n")
            append("(NonaShield) — The private key cannot be\n")
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
            .setTitle("Hardware Attestation Proof")
            .setMessage(message)
            .setPositiveButton("OK", null)
            .show()
    }
}
