package com.diimeai.demo

import android.app.Application
import android.content.Intent
import android.util.Log
import com.diimeai.demo.enrollment.EnrollmentStatus
import com.diimeai.demo.network.DiimeApiClient
import com.payshield.android.sdk.SignalSink
import com.payshield.sdk.enrollment.EnrollmentManager
import com.payshield.sdk.enrollment.EnrollmentResult
import com.payshield.sdk.enrollment.EnrollmentState
import com.payshield.sdk.crypto.DeviceKeyManager
import com.payshield.sdk.signal.EdgeSignal
import com.payshield.sdk.behavioral.BehavioralTelemetrySender
// ATL-2027: Autonomous Trust Layer initialisation
import com.payshield.sdk.PayShieldEdgeInitializer
import com.payshield.sdk.SdkEnvironment
import com.payshield.sdk.state.SdkState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlin.system.exitProcess

/**
 * DiimeAI Application class.
 *
 * Responsibilities (in order):
 *   1. Initialize SecureStorage (EncryptedSharedPreferences backed by AndroidKeyStore).
 *   2. Create DeviceKeyManager — generates ECDSA P-256 key in AndroidKeyStore on first run.
 *   3. Run NonaShield enrollment in background:
 *        GET  api.diimeai.com/api/v1/enroll/nonce
 *        POST api.diimeai.com/api/v1/enroll/register  (with Play Integrity token)
 *   4. Register the global SignalSink — routes RASP signals to the NonaShield backend
 *      and shows BlockedActivity when the device is flagged.
 *
 * The app starts normally even if enrollment is still in progress.
 * PinningInterceptor will retry nonce/signing until enrollment succeeds.
 */
class DiimeApp : Application() {

    companion object {
        private const val TAG = "DiimeApp"

        // Enrollment result (may be null briefly on first launch while async completes)
        @Volatile
        var enrollmentState: EnrollmentState.Enrollment? = null
            private set

        /**
         * Observable enrollment status — collected by MainActivity to gate the
         * "Get Started" button and show error messages.
         *
         * Starts as [EnrollmentStatus.Pending] on every app launch.
         * Transitions to [EnrollmentStatus.Enrolled] on success or
         * [EnrollmentStatus.Failed] on error.
         *
         * On second launch where EnrollmentState is already stored, transitions
         * directly to [EnrollmentStatus.Enrolled] without a network call.
         */
        private val _enrollmentStatus = MutableStateFlow<EnrollmentStatus>(EnrollmentStatus.Pending)
        val enrollmentStatus: StateFlow<EnrollmentStatus> = _enrollmentStatus.asStateFlow()

        /**
         * Called by MainActivity's Retry button.
         * Resets status to Pending and re-runs the enrollment coroutine.
         * Safe to call if enrollment is already running — EnrollmentManager is idempotent.
         */
        fun retryEnrollment(instance: DiimeApp) {
            _enrollmentStatus.value = EnrollmentStatus.Pending
            instance.enrollDevice()
        }
    }

    // ATL-2027: SDK state tracks PayShieldEdgeInitializer lifecycle.
    // Stored at Application scope so it survives configuration changes.
    private val sdkState = SdkState()

    // Resolved once in initPayShieldEdge() and reused throughout the Application
    // lifecycle so enrollDevice() and initPayShieldEdge() use the same environment.
    private val sdkEnvironment: SdkEnvironment by lazy {
        when (BuildConfig.SDK_ENVIRONMENT) {
            "STAGING"    -> SdkEnvironment.STAGING
            "PRODUCTION" -> SdkEnvironment.PRODUCTION
            else         -> SdkEnvironment.DEVELOPMENT
        }
    }

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()

        // CrashReportActivity runs in :crash process.  When Android starts that process
        // it also instantiates DiimeApp, but we must not initialise the SDK there.
        if (isInCrashProcess()) return

        // ── Demo crash handler — shows stack trace on-device instead of silent kill ──
        // Install FIRST so any subsequent crash in onCreate() is caught and displayed.
        installCrashHandler()

        // ── Step 1: Initialize global HTTP client ─────────────────────────────
        // DiimeApiClient sets up OkHttp with PinningInterceptor + PayShieldAuthInterceptor.
        // PinningInterceptor creates its own DeviceKeyManager internally — the customer
        // app does not hold a reference to SDK-internal key management classes.
        // Session is injected later (after login) via SessionHolder.setSession().
        // ATL-2027: PinningInterceptor reads X-DPIP-Device-Hash salt from SecureStorage
        // (via EnrollmentState.loadDpipSalt()) at request time — no salt param here.
        DiimeApiClient.init(applicationContext)

        // ── Step 3b: Wire behavioral telemetry sender ─────────────────────────
        // BehavioralTelemetrySender POSTs to /api/v1/security/telemetry at each
        // PAYMENT / KYC / LOGIN checkpoint.  Must be set before any Activity starts.
        BehavioralTelemetrySender.backendBaseUrl = BuildConfig.NONASHIELD_BASE_URL

        // ── Step 4: Register RASP signal sink ─────────────────────────────────
        // Routes all RASP signals to backend and triggers BlockedActivity on termination.
        registerSignalSink()

        // ── Step 4b: Initialize PayShield Edge (ATL-2027) ─────────────────────
        // Registers all 41 RASP signals (including the 3 new ATL-2027 deepfake signals),
        // starts AutonomousCommandReceiver (polls /api/v1/device/commands every 4.5s),
        // and fires SdkCapabilityReporter to POST the capability matrix to the backend.
        //
        // The SdkSignalSink bridge below routes com.payshield.sdk.signal.SignalSink
        // (used by SignalOrchestrator) → DiimeApiClient.signalSink (android-sdk layer).
        // This is the same bridge pattern used in LoginActivity and PaymentActivity.
        try {
            initPayShieldEdge()
        } catch (t: Throwable) {
            showCrashScreen("initPayShieldEdge() threw:\n\n${t.stackTraceToString()}")
            // Kill the main process — CrashReportActivity in :crash process survives.
            android.os.Process.killProcess(android.os.Process.myPid())
            exitProcess(1)
        }

        // ── Step 5: Enroll device in background ───────────────────────────────
        // Fast-path: EnrollmentState.isEnrolled() returns immediately if already done.
        enrollDevice()
    }

    override fun onTerminate() {
        super.onTerminate()
        // ATL-2027: stop the autonomous command polling loop cleanly.
        // onTerminate() is only guaranteed in emulators; on real devices the process
        // is killed without this hook — AutonomousCommandReceiver uses SupervisorJob
        // so it is cleaned up automatically by the OS.
        PayShieldEdgeInitializer.stopAutonomousReceiver()
        sdkState.shutdown()
    }

    // ── ATL-2027 PayShield Edge Initialisation ────────────────────────────────

    /**
     * Initialises the full PayShield signal orchestrator with all 41 RASP sensors
     * including the three new RBI/NPCI/ReBIT 2027 Autonomous Trust Layer deepfake signals.
     *
     * Also starts [AutonomousCommandReceiver] which polls the backend every 4.5s for
     * BLOCK/STEP_UP/MONITOR commands pushed by `autonomous_decision_enhancer.py`.
     *
     * The SdkSignalSink bridge delegates from the SDK's internal
     * `com.payshield.sdk.signal.SignalSink` (used by [SignalOrchestrator]) to the
     * android-sdk layer `com.payshield.android.sdk.SignalSink` (used by [DiimeApiClient]).
     *
     * Environment gating (set per buildType via SDK_ENVIRONMENT in app/build.gradle):
     *   debug   → DEVELOPMENT (no attestation enforcement, emulators allowed)
     *   staging → STAGING     (full attestation enforcement, QA / pen-test)
     *   release → PRODUCTION  (full attestation enforcement, live customers)
     */
    private fun initPayShieldEdge() {
        // Bridge: com.payshield.sdk.signal.SignalSink → DiimeApiClient.signalSink
        val sdkSignalSink = object : com.payshield.sdk.signal.SignalSink {
            override fun emit(signal: EdgeSignal) {
                // Route every RASP / ATL-2027 signal to the registered android-sdk sink.
                // SignalStateManager is updated automatically inside PayShieldEdgeInitializer.
                DiimeApiClient.signalSink?.onSignalsCollected(listOf(signal))
                Log.d(TAG, "SDK signal: ${signal.type} [${signal.threatId}] confidence=${signal.confidence}")
            }
            override fun onBlock(reason: String) {
                Log.e(TAG, "SDK block: $reason")
                DiimeApiClient.signalSink?.onBlock(reason)
            }
        }

        val orchestrator = PayShieldEdgeInitializer.initialize(
            context        = applicationContext,
            signalSink     = sdkSignalSink,
            sdkState       = sdkState,
            backendBaseUrl = BuildConfig.NONASHIELD_BASE_URL,
            // Pass null to skip FreeRASP — demo doesn't need watcher mail / cert hashes.
            // In production pass PayShieldRaspConfig(watcherMail=..., androidConfig=...).
            freeRaspConfig = null,
            // ATL-2027: Three-way attestation enforcement.
            //   DEVELOPMENT → fail open (emulators / dev devices safe)
            //   STAGING     → full enforcement (QA / pen-test / UAT)
            //   PRODUCTION  → full enforcement (live customers)
            // Set per buildType via SDK_ENVIRONMENT in app/build.gradle.
            environment    = sdkEnvironment,
            // ATL-2027: tenant identity for autonomous command receiver + capability reporter.
            // DPIP salt is NOT passed here — it is read from SecureStorage (via
            // EnrollmentState.loadDpipSalt()) by PinningInterceptor and
            // AutonomousCommandReceiver at runtime after enrollment issues it.
            tenantId       = "default"
        )

        // One-time startup evaluation — captures the device's initial RASP state.
        // All subsequent evaluations are driven by OS callbacks registered inside
        // PayShieldEdgeInitializer.registerOsEventListeners() — no polling loop.
        appScope.launch(Dispatchers.Default) {
            try { orchestrator.evaluateAll() } catch (_: Throwable) {}
        }

        Log.i(TAG, "PayShield Edge initialized (env=$sdkEnvironment, atl2027=true, " +
            "dpipSalt=${if (EnrollmentState.loadDpipSalt().isNotBlank()) "ISSUED" else "PENDING_ENROLLMENT"})")
    }

    // -------------------------------------------------------------------------

    internal fun enrollDevice() {
        // Fast path — already enrolled on a previous launch (EnrollmentState persisted)
        EnrollmentState.load()?.also { stored ->
            enrollmentState = stored
            _enrollmentStatus.value = EnrollmentStatus.Enrolled(
                deviceId  = stored.deviceId,
                sessionId = stored.sessionId
            )
            Log.i(TAG, "Device already enrolled: ${stored.deviceId}")
            return
        }

        // Background enrollment — Play Integrity request happens on Dispatchers.IO
        appScope.launch(Dispatchers.IO) {
            Log.i(TAG, "Starting device enrollment...")

            val deviceId = DeviceKeyManager().getStableDeviceId()
            val enrollmentMgr = EnrollmentManager(
                context        = applicationContext,
                keyManager     = DeviceKeyManager(),
                backendBaseUrl = BuildConfig.NONASHIELD_BASE_URL,
                // ATL-2027: pass the same environment used by PayShieldEdgeInitializer.
                // STAGING / PRODUCTION → Play Integrity failure = hard enrollment failure.
                // DEVELOPMENT → fail open (emulators / sideloaded APKs allowed).
                environment    = sdkEnvironment
            )

            when (val result = enrollmentMgr.enroll(deviceId)) {
                is EnrollmentResult.Success -> {
                    enrollmentState = EnrollmentState.load()
                    _enrollmentStatus.value = EnrollmentStatus.Enrolled(
                        deviceId  = deviceId,
                        sessionId = result.sessionId
                    )
                    Log.i(TAG, "Enrollment succeeded. deviceId=$deviceId session=${result.sessionId}")
                }
                is EnrollmentResult.Failure -> {
                    // Hard failures (integrity violations in STAGING/PRODUCTION) are not
                    // retryable — user must switch to a legitimate device.
                    val isRetryable = result.cause !is SecurityException
                    _enrollmentStatus.value = EnrollmentStatus.Failed(
                        reason      = result.reason,
                        isRetryable = isRetryable
                    )
                    Log.e(TAG, "Enrollment failed (retryable=$isRetryable): ${result.reason}", result.cause)
                }
            }
        }
    }

    // ── Demo-only crash helpers ───────────────────────────────────────────────

    private fun installCrashHandler() {
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            val sb = buildString {
                appendLine("Thread: ${thread.name}")
                appendLine()
                appendLine(throwable.stackTraceToString())
            }
            try { showCrashScreen(sb) } catch (_: Throwable) {}
            // Kill the main process so Android doesn't show "isn't responding" (ANR).
            // CrashReportActivity runs in :crash process and is unaffected by this kill.
            android.os.Process.killProcess(android.os.Process.myPid())
            exitProcess(1)
        }
    }

    private fun isInCrashProcess(): Boolean = getCurrentProcessName().endsWith(":crash")

    private fun getCurrentProcessName(): String =
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P)
            android.app.Application.getProcessName()
        else try {
            java.io.File("/proc/self/cmdline").readBytes().takeWhile { it != 0.toByte() }.toByteArray().toString(Charsets.UTF_8)
        } catch (_: Throwable) { "" }

    private fun showCrashScreen(message: String) {
        val intent = android.content.Intent(applicationContext, CrashReportActivity::class.java).apply {
            addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK or android.content.Intent.FLAG_ACTIVITY_CLEAR_TASK)
            putExtra(CrashReportActivity.EXTRA_CRASH_MESSAGE, message)
        }
        startActivity(intent)
    }

    private fun registerSignalSink() {
        DiimeApiClient.signalSink = object : SignalSink {
            override fun onSignalsCollected(signals: List<EdgeSignal>) {
                Log.w(TAG, "RASP signals collected: ${signals.map { it.type }}")
                // Signals are batched and uploaded to /api/v1/threats/batch
                // by the SDK's ThreatBuffer automatically.
            }

            override fun onBlock(reason: String) {
                Log.e(TAG, "Device BLOCKED by NonaShield: $reason")
                // Launch BlockedActivity on the main thread
                val intent = Intent(applicationContext, BlockedActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                    putExtra(BlockedActivity.EXTRA_REASON, reason)
                }
                startActivity(intent)
            }
        }
    }
}
