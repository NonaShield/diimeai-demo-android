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

        /** Number of payment interactions to capture before locking the biometric baseline. */
        private const val BASELINE_PAYMENTS = 5
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

    // ── Biometric baseline: locked after BASELINE_PAYMENTS payment taps ───────
    // Counter increments on every Send Payment tap regardless of validation result.
    // At tap #BASELINE_PAYMENTS the profile is saved and comparison mode activates.
    // Reset to 0 on logout/fullReset.
    private var paymentTapCount = 0

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
    // Live RASP threat ticker
    // ─────────────────────────────────────────────────────────────────────────

    private val FRIENDLY_NAMES = mapOf(
        // ── Emulator / virtual environment ───────────────────────────────────
        "EMULATOR_FINGERPRINT"         to "Emulator Detected",
        "EMULATOR_DETECTED"            to "Emulator Detected",        // FreeRASP
        // ── Screen / display ──────────────────────────────────────────────────
        "SCREEN_RECORDING_ACTIVE"      to "Screen Recording Active",
        "SCREEN_RECORDING"             to "Screen Recording Active",   // FreeRASP
        "SCREEN_MIRRORING"             to "Screen Mirroring",
        "REMOTE_DESKTOP"               to "Remote Desktop Active",
        "SCREENSHOT"                   to "Screenshot Taken",
        // ── Build / integrity ─────────────────────────────────────────────────
        "ROGUE_BUILD_DETECTED"         to "Debug / Sideloaded Build",
        "APP_REPACKAGED"               to "App Tampered (Repackaged)",
        "APP_TAMPERING"                to "App Tampered",              // FreeRASP
        "NATIVE_LIB_TAMPER"           to "Native Library Tampered",
        "SDK_SELF_TAMPER"              to "SDK Integrity Failure",
        "APP_VERSION_DOWNGRADE"        to "App Downgrade Detected",
        // ── Root / hooking ────────────────────────────────────────────────────
        "ROOT_OR_JAILBREAK"            to "Device Rooted",             // FreeRASP
        "ROOT_CLOAKING"                to "Root Cloaking (Magisk)",
        "HOOKING_FRAMEWORK"            to "Hook Framework (Frida/Xposed)",
        "PTRACE_ATTACHED"              to "Debugger Attached",
        "DEBUGGER_DETECTED"            to "Debugger Detected",         // FreeRASP
        "SHELL_CHILD_PROCESS_DETECTED" to "Shell Process Spawned",
        "SHELL_MAPPED_IN_PROCESS"      to "Shell Mapped in Process",
        "DANGEROUS_EXECUTABLE_PRESENT" to "Dangerous Executable Found",
        "SELINUX_DISABLED"             to "SELinux Disabled",
        // ── Device state ──────────────────────────────────────────────────────
        "USB_DEBUGGING_ACTIVE"         to "USB Debugging On",
        "ADB_INSTALL"                  to "ADB Debugging On",
        "DEVELOPER_OPTIONS_ACTIVE"     to "Developer Options On",
        "DEVELOPER_MODE"               to "Developer Mode On",         // FreeRASP
        "ADB_ENABLED"                  to "ADB Enabled",               // FreeRASP
        "KEYGUARD_NOT_SECURE"          to "No Screen Lock Set",
        "PASSCODE_NOT_SET"             to "No Passcode Set",           // FreeRASP
        "HW_KEYSTORE_UNAVAILABLE"      to "No Hardware Keystore",      // FreeRASP
        "ATTESTATION_NO_CHAIN"         to "Play Integrity Unavailable",
        "ATTESTATION_UNTRUSTED"        to "Play Integrity Failed",
        "DEVICE_ANCHOR_MISMATCH"       to "Device Identity Mismatch",
        "DEVICE_BINDING"               to "Device Binding Changed",    // FreeRASP
        "DEVICE_ID_CHANGED"            to "Device ID Changed",         // FreeRASP
        "MULTI_INSTANCE"               to "Multi-Instance Detected",   // FreeRASP
        "OBFUSCATION_RISK"             to "Obfuscation Risk",          // FreeRASP
        // ── Network / VPN ─────────────────────────────────────────────────────
        "VPN_CONFLICT"                 to "VPN Active",
        "SYSTEM_VPN"                   to "VPN Detected",              // FreeRASP
        "UNSECURE_WIFI"                to "Unsecured Wi-Fi",           // FreeRASP
        "TLS_PIN_MISMATCH"             to "TLS Certificate Mismatch",
        "USER_CA_CERT"                 to "User-Installed CA Cert",
        "TIME_SPOOFING"                to "System Clock Manipulated",  // FreeRASP
        "MOCK_LOCATION"                to "Mock GPS Location",
        "LOCATION_SPOOFING"            to "GPS Location Spoofed",      // FreeRASP alias
        // ── Overlay / deepfake / call ─────────────────────────────────────────
        "OVERLAY_ATTACK_DETECTED"      to "Overlay / Tapjacking Attack",
        "MANDATE_HIJACK_CAPABLE"       to "Overlay Mandate Hijack",
        "DEEPFAKE_PRECONDITION_DETECTED" to "Deepfake Precondition",
        "VIRTUAL_CAMERA_DETECTED"      to "Virtual Camera Injected",
        "CONCURRENT_VIDEO_CALL"        to "Concurrent Video Call",
        "CALL_MERGE_DETECTED"          to "Call Merge Attempt",
        "BACKGROUND_CAMERA_ACTIVE"     to "Background Camera Active",
        // ── Automation / bot ──────────────────────────────────────────────────
        "AUTOMATION_FRAMEWORK"         to "Automation Framework",      // FreeRASP
        "AUTO_CLICKER_DETECTED"        to "Auto-Clicker / Macro Bot",
        "ACCESSIBILITY_ABUSE"          to "Accessibility RAT / Bot",
        "ACCESSIBILITY_GESTURE_INJECT" to "Accessibility Gesture Inject",
        "BEHAVIORAL_BIOMETRIC_MISMATCH" to "Biometric Mismatch",
        "SOCIAL_ENGINEERING_BIOMETRIC" to "Coached / Social Engineering",
        "REFLECTION_PROTECTED_PACKAGE" to "Reflection Attack",
        "RE_TOOL_THREAD_DETECTED"      to "Reverse Engineering Thread",
        "CLASS_COUNT_ANOMALY"          to "DEX Class Anomaly",
        "INJECTED_DEX_IN_PROC_MAPS"    to "Injected DEX Detected",
        "MASVS_CONTROL_FAILURE"        to "MASVS Security Control Failed",
        // ── Malware / sideload ────────────────────────────────────────────────
        "SIDELOAD_DETECTED"            to "Sideloaded / Trojan App",
        "MALWARE_DETECTED"             to "Malware Detected",          // FreeRASP
        "UNTRUSTED_INSTALL_SOURCE"     to "Untrusted Install Source",  // FreeRASP
        "DEVICE_ADMIN_ABUSE"           to "Rogue Device Admin",
        "SMS_INTERCEPT_CAPABLE"        to "SMS OTP Interception Risk",
        "APP_CLONE_DETECTED"           to "App Cloned",
        "APP_CLONE_MALICIOUS"          to "Malicious App Clone",
        "ROMANCE_SOCIAL_APP_INSTALLED" to "Romance Scam App Installed",
        "PREDATORY_LOAN_APP"           to "Predatory Loan App",
        "PREDATORY_LOAN_APP_FULL"      to "Predatory Loan App (High Risk)",
        // ── NFC / payments ────────────────────────────────────────────────────
        "ROGUE_HCE_APP"                to "Rogue NFC Payment App",
        "NFC_RELAY_DETECTED"           to "NFC Relay Attack",
        "NFC_NO_KEYGUARD"              to "NFC Without Screen Lock",
        // ── IME / clipboard ───────────────────────────────────────────────────
        "UNTRUSTED_IME"                to "Untrusted Keyboard",
        "CLIPBOARD_SCRAPING_RISK"      to "Clipboard Scraping Risk",
        // ── SIM / identity ────────────────────────────────────────────────────
        "SIM_DEACTIVATED"              to "SIM Deactivated",
        "ESIM_OTA_SWAP"                to "eSIM Swap Attack",
        "ESIM_MANAGER_APP_DETECTED"    to "Suspicious eSIM App",
        // ── Agentic / scam ────────────────────────────────────────────────────
        "MESSAGING_APP_PRE_SESSION"    to "Scam Messaging App Active",
        "NOTIFICATION_TRIGGERED_SESSION" to "Notification-Triggered Session",
        // ── Storage / misc ────────────────────────────────────────────────────
        "LOCAL_STORAGE_TAMPERED"       to "Local Storage Tampered",
        "HIGH_RISK_PERMISSIONS"        to "High-Risk Permissions Active",
        "ENROLLMENT_BURST"             to "Enrollment Burst (Bot Risk)",
        "FREERASP_INIT_FAILED"         to "RASP Layer Unavailable",
    )

    // Track last rendered set to avoid rebuilding the list on every 500ms tick
    private var lastRenderedThreatTypes: List<String> = emptyList()

    private fun refreshThreatTicker() {
        val signals = synchronized(DiimeApp.recentRaspSignals) {
            // Prune signals whose condition has resolved (TTL expired or OS clear callback fired).
            // Without this, the ticker keeps showing WhatsApp screen-share signals indefinitely
            // after the WhatsApp session closes — SignalStateManager knows they're gone but the
            // display buffer never removes them.
            DiimeApp.recentRaspSignals.removeAll { signal ->
                !PayShieldEdgeInitializer.isSignalActive(signal.type)
            }
            DiimeApp.recentRaspSignals.toList()
        }
        // Newest last → show newest at top
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
                "CRITICAL" -> "🔴"
                "HIGH"     -> "🟠"
                "MEDIUM"   -> "🟡"
                else       -> "🟡"
            }
            val name = FRIENDLY_NAMES[signal.type] ?: signal.type
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
    // ─────────────────────────────────────────────────────────────────────────

    private fun refreshBiometricPanel() {
        val summary = BehavioralSessionManager.buildDeviationSummary()
        val inCompare = BehavioralSessionManager.isComparisonMode

        // Calibration progress bar — show until BASELINE_PAYMENTS taps are done
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
                // Baseline saved, not yet in comparison mode (transitional — shouldn't linger)
                binding.tvBioRiskBadge.text = "ENROLLED USER ✓"
                binding.tvBioRiskBadge.setBackgroundColor(0xFF00AA44.toInt())
                binding.tvBioHint.visibility = View.GONE
            }
            paymentTapCount >= BASELINE_PAYMENTS -> {
                // 5 taps done but sensor calibration not complete yet (very unlikely)
                binding.tvBioRiskBadge.text = "ENROLLING…  touch screen"
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

        // 6 sensor channels — always 🟢 for enrolled user; show deviation only in comparison mode
        binding.tvBioPressure.text   = formatChannel(summary.pressure, inCompare)
        binding.tvBioFingerSize.text = formatChannel(summary.fingerSize, inCompare, "px")
        binding.tvBioSwipe.text      = formatChannel(summary.swipe, inCompare, "px/ms")
        binding.tvBioHesitation.text = run {
            val icon = if (inCompare) summary.hesitation.statusIcon else "🟢"
            val v = "${summary.hesitation.value.toLong()}ms"
            if (inCompare && summary.hesitation.deviation > 0) "$icon $v  Δ${summary.hesitation.deviationPct}%"
            else "$icon $v"
        }
        binding.tvBioPosture.text = run {
            val icon = if (inCompare) summary.posture.statusIcon else "🟢"
            val v = "${"%.1f".format(summary.posture.value)}°"
            if (inCompare && summary.posture.deviation > 0) "$icon $v  Δ${summary.posture.deviationPct}%"
            else "$icon $v"
        }
        binding.tvBioGrip.text = formatChannel(summary.grip, inCompare)

        // 2 ML channels — 🟢 for enrolled user; bot-detection icons only in comparison mode
        val mlFeatures = captureManager.getLatestFeatures()
        if (mlFeatures != null) {
            val jitterIcon = if (!inCompare) "🟢" else when {
                mlFeatures.jitterScore < 0.001f -> "🔴"
                mlFeatures.jitterScore < 0.01f  -> "🟡"
                else                            -> "🟢"
            }
            binding.tvBioJitter.text = "$jitterIcon ${"%.4f".format(mlFeatures.jitterScore)}"

            val entropyIcon = if (!inCompare) "🟢" else when {
                mlFeatures.curvatureEntropy < 0.3f -> "🔴"
                mlFeatures.curvatureEntropy < 1.0f -> "🟡"
                else                               -> "🟢"
            }
            binding.tvBioCurvature.text = "$entropyIcon ${"%.2f".format(mlFeatures.curvatureEntropy)}"
        } else {
            // No touch gesture processed yet
            binding.tvBioJitter.text    = "🟢 –"
            binding.tvBioCurvature.text = "🟢 –"
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
            val deviatingNames = summary.deviatingChannels.joinToString(" · ") {
                "${it.statusIcon} ${it.name} (+${it.deviationPct}%)"
            }
            binding.tvDeviationChannels.text =
                if (deviatingNames.isNotBlank()) deviatingNames
                else "  All channels within normal range"

            // Prominent "DIFFERENT USER" alarm: show banner when ≥ 65% deviation
            val isHighDeviation = summary.composite >= 0.65f
            binding.rowUserMismatchAlarm.visibility =
                if (isHighDeviation) View.VISIBLE else View.GONE
            if (isHighDeviation) {
                binding.tvUserMismatchDetail.text =
                    "Biometric deviation: ${summary.compositePct}%  •  " +
                    "${summary.deviatingChannels.size}/8 channels flagged"
            }

            // Auto-show full alert dialog when ≥3 channels deviate (once per session)
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
            "${ch.statusIcon} $value  Δ${ch.deviationPct}%"
        else
            "🟢 $value"
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Payment flow
    // ─────────────────────────────────────────────────────────────────────────

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
                BehavioralSessionManager.enterComparisonMode()
                Toast.makeText(this,
                    "✅ Biometric profile locked — comparison active",
                    Toast.LENGTH_SHORT).show()
                handler.post { refreshBiometricPanel() }
            }
        }

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

            // ── SDK checkpoint gate (UC-PAYMENT-RISK) ────────────────────────
            // Customer integration: call evaluateAtCheckpoint BEFORE sending the
            // payment to the backend.  The SDK evaluates:
            //   1. RASP signal set (all 41 sensors synchronously)
            //   2. On-device behavioral biometrics (BehavioralAnomalySignal)
            //   3. Default policy (DefaultPolicyEvaluator)
            //   4. Backend behavioral confirmation (async, Dispatchers.IO)
            // STEP_UP → show OTP challenge; DENY → block; ALLOW → proceed.
            val checkpoint = runCatching {
                PayShieldSDK.evaluateAtCheckpoint(
                    context  = this@PaymentActivity,
                    action   = "PAYMENT",
                    features = behavioralFeatures
                )
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
     * STEP_UP triggered by [PayShieldSDK.evaluateAtCheckpoint] (UC-PAYMENT-RISK).
     *
     * Fires when geo-velocity anomaly, high-amount + low device trust, or
     * transaction velocity exceeds the policy threshold.  In production the
     * customer's auth layer enforces an OTP/biometric challenge here.
     */
    private fun showPaymentRiskStepUpDialog(amount: Double, reason: String?) {
        val amountStr = "₹${String.format("%,.0f", amount)}"
        AlertDialog.Builder(this)
            .setTitle("⚠️  Transaction Risk — Step-Up Required")
            .setMessage(
                "NonaShield has flagged this ₹$amountStr payment for elevated risk.\n\n" +
                "Reason: ${reason ?: "PAYMENT_RISK_STEP_UP"}\n\n" +
                "Risk factors evaluated by SDK:\n" +
                "  • Transaction amount tier (HIGH ≥ ₹1L)\n" +
                "  • Geo-velocity anomaly (impossible/high-velocity travel)\n" +
                "  • Device trust score\n" +
                "  • New beneficiary + payment velocity\n\n" +
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
        binding.btnSendPayment.isEnabled = !loading
        binding.progressBar.visibility   = if (loading) View.VISIBLE else View.GONE
    }
}
