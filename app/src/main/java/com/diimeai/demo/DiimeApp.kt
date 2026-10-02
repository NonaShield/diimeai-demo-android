package com.diimeai.demo

import android.app.Application
import android.content.Intent
import android.util.Log
import com.diimeai.demo.enrollment.EnrollmentStatus
import com.diimeai.demo.network.DiimeApiClient
import com.payshield.sdk.PayShieldConfig
import com.payshield.sdk.PayShieldSDK
import com.payshield.sdk.SdkEnvironment
import com.payshield.sdk.enrollment.EnrollmentCallback
import com.payshield.sdk.enrollment.EnrollmentResult
import com.payshield.sdk.enrollment.EnrollmentState
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
 * Integrates NonaShield exactly as CUSTOMER_INTEGRATION_GUIDE.md "The Standard Integration" tells every
 * customer to, so this demo exercises the same code path a customer app does:
 *   1. PayShieldSDK.initialize(context, PayShieldConfig(...))   -- here, in onCreate()
 *   2. PayShieldSDK.enroll(callback)                            -- here, right after initialize
 *   3. PayShieldSDK.onUserLogin(userId)                         -- LoginActivity, after login succeeds
 *   4. PayShieldSDK.evaluateAtCheckpoint("PAYMENT")             -- PaymentActivity, before a payment
 *
 * The demo's on-screen threat ticker and blocked screen use the SDK's public listeners
 * (addSignalStateListener, addBlockListener); the app never replaces the SDK's own signal handling.
 * The app starts normally even if enrollment is still in progress.
 */
class DiimeApp : Application() {

    companion object {
        private const val TAG = "DiimeApp"

        // Enrollment result (may be null briefly on first launch while async completes)
        @Volatile
        var enrollmentState: EnrollmentState.Enrollment? = null
            private set

        /**
         * Signal types that are active right now, for the demo's live threat ticker (newest last, max 20).
         * Fed by PayShieldSDK.addSignalStateListener -- the app does no detection of its own.
         */
        val recentRaspSignals: ArrayDeque<String> = ArrayDeque(20)

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
         * Safe to call if enrollment is already running — PayShieldSDK.enroll() is idempotent.
         */
        fun retryEnrollment(instance: DiimeApp) {
            _enrollmentStatus.value = EnrollmentStatus.Pending
            instance.enrollDevice()
        }
    }

    // Per build type (SDK_ENVIRONMENT in app/build.gradle): debug -> DEVELOPMENT, staging -> STAGING,
    // release -> PRODUCTION.
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

        // Behavioral telemetry no longer uses a dedicated /security/telemetry sender --
        // features ride the same /threats/batch flow as RASP threats instead (see
        // PayShieldEdgeInitializer's 60s heartbeat + PayShieldCheckpoint.evaluate()).

        // ── NonaShield standard integration, step 1: initialize ───────────────
        try {
            initNonaShield()
        } catch (t: Throwable) {
            showCrashScreen("PayShieldSDK.initialize() threw:\n\n${t.stackTraceToString()}")
            // Kill the main process — CrashReportActivity in :crash process survives.
            android.os.Process.killProcess(android.os.Process.myPid())
            exitProcess(1)
        }

        // ── NonaShield standard integration, step 2: enroll ───────────────────
        // Every launch; returns the stored result immediately once enrolled.
        enrollDevice()
    }

    override fun onTerminate() {
        super.onTerminate()
        // ATL-2027: stop the autonomous command polling loop cleanly.
        // onTerminate() is only guaranteed in emulators; on real devices the process
        // is killed without this hook — AutonomousCommandReceiver uses SupervisorJob
        // so it is cleaned up automatically by the OS.
        PayShieldSDK.stopAutonomousReceiver()
    }

    // ── NonaShield initialisation (standard integration) ──────────────────────

    private fun initNonaShield() {
        // autoBlockSeverity has no SDK default -- every integration must decide. Demo choice: null
        // (never block on the phone itself); blocking comes from the SOC dashboard's force_block command.
        PayShieldSDK.initialize(
            context = applicationContext,
            config = PayShieldConfig(
                backendUrl        = BuildConfig.NONASHIELD_BASE_URL,
                // The live backend's own tenant (DEFAULT_TENANT_ID=dimeai on api.diimeai.com).
                tenantId          = "dimeai",
                autoBlockSeverity = null,
                environment       = sdkEnvironment,
            ),
        )

        // Demo display only: keep the live threat ticker in step with the SDK's active signals.
        PayShieldSDK.addSignalStateListener { type, active ->
            synchronized(recentRaspSignals) {
                recentRaspSignals.remove(type)
                if (active) {
                    recentRaspSignals.addLast(type)
                    while (recentRaspSignals.size > 20) recentRaspSignals.removeFirst()
                }
            }
            Log.d(TAG, "Signal $type active=$active")
        }

        // Show the blocked screen when the device is blocked (on the phone or by the SOC).
        PayShieldSDK.addBlockListener { details ->
            Log.e(TAG, "Device BLOCKED by NonaShield: ${details.threatId} (${details.source})")
            startActivity(Intent(applicationContext, BlockedActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                putExtra(BlockedActivity.EXTRA_REASON, details.displayName)
            })
        }

        Log.i(TAG, "NonaShield initialized (env=$sdkEnvironment, " +
            "dpipSalt=${if (EnrollmentState.loadDpipSalt().isNotBlank()) "ISSUED" else "PENDING_ENROLLMENT"})")

        startBehavioralHeartbeat()
    }

    /**
     * App-level substitute for the SDK's own 60s heartbeat behavioral piggyback
     * (PayShieldEdgeInitializer.kt, Step 6b) -- that fix is source-committed in
     * the SDK repo but the SDK's CI is blocked by an org billing issue, so no
     * AAR has ever been built with it. evaluateAtCheckpoint() is already public
     * in the currently-bundled AAR and already contains the same "Path A:
     * behavioral" piggyback logic PayShieldCheckpoint.evaluate() runs on every
     * call -- calling it here periodically, app-wide, makes behavioral data
     * flow continuously like RASP does, using only the existing AAR's public
     * API. No SDK/AAR change needed. Remove once a new AAR carries the fix.
     */
    private fun startBehavioralHeartbeat() {
        appScope.launch {
            while (true) {
                kotlinx.coroutines.delay(60_000L)
                runCatching { PayShieldSDK.evaluateAtCheckpoint(action = "SESSION") }
            }
        }
    }

    // -------------------------------------------------------------------------

    internal fun enrollDevice() {
        Log.i(TAG, "Enrolling device...")
        // Standard integration, step 2. The SDK decides the device_id itself (from the hardware key) and
        // returns it in the result; it never has to be computed by the app.
        PayShieldSDK.enroll(callback = object : EnrollmentCallback {
            override fun onResult(result: EnrollmentResult) {
                when (result) {
                    is EnrollmentResult.Success -> {
                        enrollmentState = EnrollmentState.load()
                        _enrollmentStatus.value = EnrollmentStatus.Enrolled(
                            deviceId  = result.deviceId,
                            sessionId = result.sessionId
                        )
                        Log.i(TAG, "Enrollment succeeded. deviceId=${result.deviceId} session=${result.sessionId}")
                    }
                    is EnrollmentResult.Failure -> {
                        // Integrity violations in STAGING/PRODUCTION are not retryable -- the user must
                        // switch to a genuine device.
                        val isRetryable = result.cause !is SecurityException
                        _enrollmentStatus.value = EnrollmentStatus.Failed(
                            reason      = result.reason,
                            isRetryable = isRetryable
                        )
                        Log.e(TAG, "Enrollment failed (retryable=$isRetryable): ${result.reason}", result.cause)
                    }
                }
            }
        })
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
}
