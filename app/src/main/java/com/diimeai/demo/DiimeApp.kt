package com.diimeai.demo

import android.app.Application
import android.content.Intent
import android.util.Log
import com.diimeai.demo.network.DiimeApiClient
import com.payshield.android.sdk.SignalSink
import com.payshield.sdk.enrollment.EnrollmentManager
import com.payshield.sdk.enrollment.EnrollmentResult
import com.payshield.sdk.enrollment.EnrollmentState
import com.payshield.sdk.crypto.DeviceKeyManager
import com.payshield.sdk.signal.EdgeSignal
import com.payshield.sdk.storage.SecureStorage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

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

        // Singleton accessors — safe after onCreate()
        lateinit var keyManager: DeviceKeyManager
            private set

        // Enrollment result (may be null briefly on first launch while async completes)
        @Volatile
        var enrollmentState: EnrollmentState.Enrollment? = null
            private set
    }

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()

        // ── Step 1: Initialize SecureStorage ──────────────────────────────────
        // Must happen before any SecureStorage.put() / get() call.
        // Uses EncryptedSharedPreferences with AES-256-GCM master key in AndroidKeyStore.
        SecureStorage.init(applicationContext)

        // ── Step 2: Create DeviceKeyManager ───────────────────────────────────
        // Generates (or loads) an ECDSA P-256 key in AndroidKeyStore.
        // Private key NEVER leaves the secure element.
        keyManager = DeviceKeyManager()

        // ── Step 3: Initialize global HTTP client ─────────────────────────────
        // DiimeApiClient sets up OkHttp with PinningInterceptor + PayShieldAuthInterceptor.
        // Session is injected later (after login) via SessionHolder.setSession().
        DiimeApiClient.init(applicationContext, keyManager)

        // ── Step 4: Register RASP signal sink ─────────────────────────────────
        // Routes all RASP signals to backend and triggers BlockedActivity on termination.
        registerSignalSink()

        // ── Step 5: Enroll device in background ───────────────────────────────
        // Fast-path: EnrollmentState.isEnrolled() returns immediately if already done.
        enrollDevice()
    }

    // -------------------------------------------------------------------------

    private fun enrollDevice() {
        // Fast path — already enrolled on a previous launch
        EnrollmentState.load()?.also { stored ->
            enrollmentState = stored
            Log.i(TAG, "Device already enrolled: ${stored.deviceId}")
            return
        }

        // Background enrollment — Play Integrity request happens on Dispatchers.IO
        appScope.launch(Dispatchers.IO) {
            Log.i(TAG, "Starting device enrollment...")

            val deviceId = keyManager.getStableDeviceId()
            val enrollmentMgr = EnrollmentManager(
                context        = applicationContext,
                keyManager     = keyManager,
                backendBaseUrl = BuildConfig.NONASHIELD_BASE_URL
            )

            when (val result = enrollmentMgr.enroll(deviceId)) {
                is EnrollmentResult.Success -> {
                    enrollmentState = EnrollmentState.load()
                    Log.i(TAG, "Enrollment succeeded. deviceId=$deviceId session=${result.sessionId}")
                }
                is EnrollmentResult.Failure -> {
                    // Non-fatal on launch — app works in degraded mode; retry on next launch.
                    // In production: show a "secure setup required" dialog.
                    Log.e(TAG, "Enrollment failed: ${result.reason}", result.cause)
                }
            }
        }
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
