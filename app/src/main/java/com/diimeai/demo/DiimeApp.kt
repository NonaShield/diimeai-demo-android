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
import com.payshield.sdk.PayShieldEdgeInitializer
import com.payshield.sdk.PayShieldSDK
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
 *   2. Create DeviceKeyManager â€” generates ECDSA P-256 key in AndroidKeyStore on first run.
 *   3. Run NonaShield enrollment in background:
 *        GET  api.diimeai.com/api/v1/enroll/nonce
 *        POST api.diimeai.com/api/v1/enroll/register  (with Play Integrity token)
 *   4. Register the global SignalSink â€” routes RASP signals to the NonaShield backend
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
         * Deduped live signal list for the RASP alert ticker.
         * Keyed by signal type â€” newest signal per type wins, up to 20 unique types.
         * Written by the SDK sink; read by PaymentActivity's 500ms refresh loop.
         * The app does ZERO detection â€” only stores what the SDK already decided.
         */
        val recentRaspSignals: ArrayDeque<EdgeSignal> = ArrayDeque(20)

        /** DEBUG ONLY â€” currently foregrounded activity, used by the RASP debug popup. */
        @Volatile
        private var debugCurrentActivity: android.app.Activity? = null

        /** DEBUG ONLY â€” signal types covered by the screen-recording false-positive debug popup. */
        private val SCREEN_DEBUG_TYPES = setOf(
            "SCREEN_RECORDING", "SCREEN_RECORDING_ACTIVE",
            "COMPANION_SCREEN_SHARE_ACTIVE", "SCREEN_MIRRORING",
        )

        /**
         * DEBUG ONLY â€” shows a blocking AlertDialog with the full diagnostic context
         * for a screen-recording-related signal: which file/function emitted it, the
         * raw display dump, and any heuristic match. Lets us see the exact trigger on
         * the device screen without needing `adb logcat`. Remove once the screen
         * recording false-positive investigation is closed.
         */
        private fun showRaspDebugPopup(signal: EdgeSignal) {
            val activity = debugCurrentActivity ?: return
            val ctxDump = signal.context.entries.joinToString("\n") { (k, v) -> "$k = $v" }
            val message = "threatId=${signal.threatId}\nseverity=${signal.severity}\n\n$ctxDump"
            android.os.Handler(android.os.Looper.getMainLooper()).post {
                try {
                    android.app.AlertDialog.Builder(activity)
                        .setTitle("RASP DEBUG: ${signal.type}")
                        .setMessage(message)
                        .setPositiveButton("OK", null)
                        .setCancelable(true)
                        .show()
                } catch (_: Throwable) {
                    // Activity may have finished between the check and show() â€” fall back to Toast.
                    android.widget.Toast.makeText(
                        activity.applicationContext,
                        "RASP DEBUG ${signal.type}: ${signal.context["debug_source"] ?: "?"}",
                        android.widget.Toast.LENGTH_LONG
                    ).show()
                }
            }
        }

        /**
         * Observable enrollment status â€” collected by MainActivity to gate the
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
         * Safe to call if enrollment is already running â€” EnrollmentManager is idempotent.
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

        // â”€â”€ Demo crash handler â€” shows stack trace on-device instead of silent kill â”€â”€
        // Install FIRST so any subsequent crash in onCreate() is caught and displayed.
        installCrashHandler()

        // â”€â”€ Step 1: Initialize global HTTP client â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // DiimeApiClient sets up OkHttp with PinningInterceptor + PayShieldAuthInterceptor.
        // PinningInterceptor creates its own DeviceKeyManager internally â€” the customer
        // app does not hold a reference to SDK-internal key management classes.
        // Session is injected later (after login) via SessionHolder.setSession().
        // ATL-2027: PinningInterceptor reads X-DPIP-Device-Hash salt from SecureStorage
        // (via EnrollmentState.loadDpipSalt()) at request time â€” no salt param here.
        DiimeApiClient.init(applicationContext)

        // â”€â”€ Step 3b: Wire behavioral telemetry sender â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // BehavioralTelemetrySender POSTs to /api/v1/security/telemetry at each
        // PAYMENT / KYC / LOGIN checkpoint.  Must be set before any Activity starts.
        BehavioralTelemetrySender.backendBaseUrl = BuildConfig.NONASHIELD_BASE_URL

        // â”€â”€ DEBUG ONLY: track foreground activity so the RASP debug popup (see
        // initPayShieldEdge â†’ sdkSignalSink) can show an AlertDialog over whatever
        // screen is currently visible. Temporary instrumentation for the screen
        // recording false-positive investigation â€” safe to remove once resolved.
        if (BuildConfig.DEBUG) {
            registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
                override fun onActivityResumed(a: android.app.Activity) { debugCurrentActivity = a }
                override fun onActivityPaused(a: android.app.Activity) { if (debugCurrentActivity == a) debugCurrentActivity = null }
                override fun onActivityCreated(a: android.app.Activity, b: android.os.Bundle?) {}
                override fun onActivityStarted(a: android.app.Activity) {}
                override fun onActivityStopped(a: android.app.Activity) {}
                override fun onActivitySaveInstanceState(a: android.app.Activity, b: android.os.Bundle) {}
                override fun onActivityDestroyed(a: android.app.Activity) {}
            })
        }

        // â”€â”€ Step 4: Register RASP signal sink â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Routes all RASP signals to backend and triggers BlockedActivity on termination.
        registerSignalSink()

        // â”€â”€ Step 4b: Initialize PayShield Edge (ATL-2027) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Registers all 41 RASP signals (including the 3 new ATL-2027 deepfake signals),
        // starts AutonomousCommandReceiver (polls /api/v1/device/commands every 4.5s),
        // and fires SdkCapabilityReporter to POST the capability matrix to the backend.
        //
        // The SdkSignalSink bridge below routes com.payshield.sdk.signal.SignalSink
        // (used by SignalOrchestrator) â†’ DiimeApiClient.signalSink (android-sdk layer).
        // This is the same bridge pattern used in LoginActivity and PaymentActivity.
        try {
            initPayShieldEdge()
        } catch (t: Throwable) {
            showCrashScreen("initPayShieldEdge() threw:\n\n${t.stackTraceToString()}")
            // Kill the main process â€” CrashReportActivity in :crash process survives.
            android.os.Process.killProcess(android.os.Process.myPid())
            exitProcess(1)
        }

        // â”€â”€ Step 5: Enroll device in background â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Fast-path: EnrollmentState.isEnrolled() returns immediately if already done.
        enrollDevice()
    }

    override fun onTerminate() {
        super.onTerminate()
        // ATL-2027: stop the autonomous command polling loop cleanly.
        // onTerminate() is only guaranteed in emulators; on real devices the process
        // is killed without this hook â€” AutonomousCommandReceiver uses SupervisorJob
        // so it is cleaned up automatically by the OS.
        PayShieldSDK.stopAutonomousReceiver()
        sdkState.shutdown()
    }

    // â”€â”€ ATL-2027 PayShield Edge Initialisation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
     *   debug   â†’ DEVELOPMENT (no attestation enforcement, emulators allowed)
     *   staging â†’ STAGING     (full attestation enforcement, QA / pen-test)
     *   release â†’ PRODUCTION  (full attestation enforcement, live customers)
     */
    private fun initPayShieldEdge() {
        // Composed signal sink: routes every EdgeSignal through TWO paths simultaneously.
        //   1. PayShieldSDK.signalSink  â€” ThreatBuffer upload to /api/v1/threats/batch
        //   2. DiimeApiClient.signalSink â€” in-app alert display + live RASP ticker
        val sdkSignalSink = object : com.payshield.sdk.signal.SignalSink {
            override fun emit(signal: EdgeSignal) {
                PayShieldSDK.signalSink.emit(signal)                           // ThreatBuffer path
                DiimeApiClient.signalSink?.onSignalsCollected(listOf(signal))  // in-app alert path
                Log.d(TAG, "SDK signal: ${signal.type} [${signal.threatId}] confidence=${signal.confidence}")

                // DEBUG ONLY â€” pop up the full diagnostic context for screen-recording
                // related signals so the exact trigger is visible on-device. See
                // showRaspDebugPopup() doc comment. Remove once investigation is closed.
                if (BuildConfig.DEBUG && signal.type in SCREEN_DEBUG_TYPES) {
                    showRaspDebugPopup(signal)
                }
            }
            override fun onBlock(reason: String) {
                Log.e(TAG, "SDK block: $reason")
                DiimeApiClient.signalSink?.onBlock(reason)
            }
        }

        // Single initialize() â€” registers all 47 RASP signals once, starts
        // AutonomousCommandReceiver, runs startup evaluateAll(), registers the 10 OS
        // event listener categories, and starts the 60-second periodic sweep.
        // FreeRASP auto-starts here if already enrolled; otherwise starts on first
        // recordEnrollment() call.
        PayShieldEdgeInitializer.initialize(
            context        = applicationContext,
            signalSink     = sdkSignalSink,
            sdkState       = sdkState,
            backendBaseUrl = BuildConfig.NONASHIELD_BASE_URL,
            environment    = sdkEnvironment,
            tenantId       = "default",
        )

        // Mark PayShieldSDK as initialized so evaluateAtCheckpoint() works in
        // PaymentActivity. requireOrchestrator() resolves via internalOrchestrator
        // (set by the call above) â€” no second init, no duplicate OS listeners.
        PayShieldSDK.configure(
            backendUrl       = BuildConfig.NONASHIELD_BASE_URL,
            tenantId         = "default",
            environment      = sdkEnvironment,
            enableBehavioral = true,
        )

        Log.i(TAG, "PayShield SDK initialized (env=$sdkEnvironment, atl2027=true, " +
            "dpipSalt=${if (EnrollmentState.loadDpipSalt().isNotBlank()) "ISSUED" else "PENDING_ENROLLMENT"})")
    }

    // -------------------------------------------------------------------------

    internal fun enrollDevice() {
        // Fast path â€” already enrolled on a previous launch (EnrollmentState persisted)
        EnrollmentState.load()?.also { stored ->
            enrollmentState = stored
            _enrollmentStatus.value = EnrollmentStatus.Enrolled(
                deviceId  = stored.deviceId,
                sessionId = stored.sessionId
            )
            Log.i(TAG, "Device already enrolled: ${stored.deviceId}")
            return
        }

        // Background enrollment â€” Play Integrity request happens on Dispatchers.IO
        appScope.launch(Dispatchers.IO) {
            Log.i(TAG, "Starting device enrollment...")

            val deviceId = DeviceKeyManager().getStableDeviceId()
            val enrollmentMgr = EnrollmentManager(
                context        = applicationContext,
                keyManager     = DeviceKeyManager(),
                backendBaseUrl = BuildConfig.NONASHIELD_BASE_URL,
                // ATL-2027: pass the same environment used by PayShieldEdgeInitializer.
                // STAGING / PRODUCTION â†’ Play Integrity failure = hard enrollment failure.
                // DEVELOPMENT â†’ fail open (emulators / sideloaded APKs allowed).
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
                    // retryable â€” user must switch to a legitimate device.
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

    // â”€â”€ Demo-only crash helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        // SDK handles ThreatBuffer upload, system notifications, and in-app alerts internally.
        // Customer app only needs to handle the block event â€” show the blocked screen.
        DiimeApiClient.signalSink = object : SignalSink {
            override fun onSignalsCollected(signals: List<EdgeSignal>) {
                for (signal in signals) {
                    Log.w(TAG, "RASP: ${signal.type} [${signal.threatId}] sev=${signal.severity} conf=${signal.confidence}")
                    // Buffer for live threat ticker in PaymentActivity.
                    // Cap at 5; drop oldest when full (SDK decided these â€” app just displays).
                    synchronized(recentRaspSignals) {
                        // Replace existing entry of same type so each threat appears once
                        recentRaspSignals.removeAll { it.type == signal.type }
                        recentRaspSignals.addLast(signal)
                        while (recentRaspSignals.size > 20) recentRaspSignals.removeFirst()
                    }
                }
            }

            override fun onBlock(reason: String) {
                Log.e(TAG, "Device BLOCKED by NonaShield: $reason")
                val intent = Intent(applicationContext, BlockedActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                    putExtra(BlockedActivity.EXTRA_REASON, reason)
                }
                startActivity(intent)
            }
        }
    }
}

