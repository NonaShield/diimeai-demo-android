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
import com.payshield.sdk.storage.SecureStorage
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

        // Singleton accessors — safe after onCreate()
        lateinit var keyManager: DeviceKeyManager
            private set

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

    // Held at Application scope so event-driven OS listeners can call evaluateAll()
    // immediately when a threat condition appears (display added, VPN connected, etc.).
    @Volatile private var raspOrchestrator: com.payshield.sdk.orchestrator.SignalOrchestrator? = null

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

        // Apply FLAG_SECURE to EVERY activity through their lifecycle — not just
        // payment / login screens.  RASP screen protection is session-wide.
        applyGlobalSecureScreen()

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
        // ATL-2027: PinningInterceptor reads X-DPIP-Device-Hash salt from SecureStorage
        // (via EnrollmentState.loadDpipSalt()) at request time — no salt param here.
        DiimeApiClient.init(applicationContext, keyManager)

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
                // Update shared signal state so PaymentActivity and TrustDashboard
                // reflect the live RASP result without waiting for a payment click.
                com.diimeai.demo.security.RaspSignalState.record(signal.type)
                // Route every RASP / ATL-2027 signal to the registered android-sdk sink.
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

        // Hold reference so event-driven OS listeners can call evaluateAll() immediately.
        raspOrchestrator = orchestrator

        // One-time startup evaluation — captures the device's initial RASP state
        // before any OS events fire.  All subsequent evaluations are triggered by
        // OS callbacks registered below — no polling loop.
        appScope.launch(Dispatchers.Default) {
            try { orchestrator.evaluateAll() } catch (_: Throwable) {}
        }

        // Wire all 41 signals to their OS callbacks — fires immediately on every threat event.
        registerEventDrivenRaspListeners()

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

            val deviceId = keyManager.getStableDeviceId()
            val enrollmentMgr = EnrollmentManager(
                context        = applicationContext,
                keyManager     = keyManager,
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

    // ── Global FLAG_SECURE ────────────────────────────────────────────────────

    // Applies FLAG_SECURE across every activity through lifecycle callbacks so
    // screen capture protection is session-wide — not tied to any one screen.
    private fun applyGlobalSecureScreen() {
        registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityCreated(activity: android.app.Activity, savedInstanceState: android.os.Bundle?) {
                com.payshield.sdk.security.SecureScreenEnforcer.apply(activity)
            }
            override fun onActivityResumed(activity: android.app.Activity) {
                com.payshield.sdk.security.SecureScreenEnforcer.apply(activity)
            }
            override fun onActivityPaused(activity: android.app.Activity) {
                com.payshield.sdk.security.SecureScreenEnforcer.lift(activity)
            }
            override fun onActivityStarted(activity: android.app.Activity) {}
            override fun onActivityStopped(activity: android.app.Activity) {}
            override fun onActivitySaveInstanceState(activity: android.app.Activity, outState: android.os.Bundle) {}
            override fun onActivityDestroyed(activity: android.app.Activity) {}
        })
    }

    // ── Event-driven RASP listeners ───────────────────────────────────────────
    //
    // All 41 signals wired to OS callbacks — no polling loop.
    // Each section documents which signals it covers and WHY that specific callback
    // is the right trigger.  When the condition clears, RaspSignalState.clear()
    // is called immediately so TrustDashboard and PaymentActivity reflect reality.
    //
    // Signal mapping:
    //  A. App foreground   → static signals (root, SELinux, ptrace, emulator, SDK tamper,
    //                         repackaged, build pipeline, device anchor, OWASP, reflection,
    //                         shell, content-provider, velocity, overlay, deepfake precondition)
    //  B. DisplayListener  → screen mirroring (5), screen recording (21), remote desktop (11)
    //  C. NetworkCallback  → VPN conflict (7)
    //  D. A11yListener     → accessibility abuse (20), SMS intercept (35)
    //  E. PACKAGE_*        → hooking FW (12), clone app (22), virtual camera (25), sideloaded (33),
    //                         device admin (34), predatory loan (37), romance (38), malware cluster
    //  F. ContentObserver  → ADB (3), developer mode (23 mock-loc), IME / untrusted keyboard (16)
    //  G. BroadcastReceiver→ keyguard (9), user CA (10), device admin (34), SIM swap (24),
    //                         NFC abuse (36), audio/call → concurrent call (30) + call merge (31)
    //  H. CameraCallback   → background camera (40), virtual camera (25)
    //  I. TelephonyCallback→ call state → concurrent video call (30), call merge (31)
    //  J. AudioMode        → VoIP in-progress → concurrent video call (30), call merge (31)
    private fun registerEventDrivenRaspListeners() {
        val handler = android.os.Handler(android.os.Looper.getMainLooper())

        fun evaluateNow(label: String) {
            Log.w(TAG, "RASP[$label] — evaluating all 41 signals immediately")
            appScope.launch(Dispatchers.Default) {
                try { raspOrchestrator?.evaluateAll() } catch (_: Throwable) {}
            }
        }

        // Android 14 (API 34) requires RECEIVER_NOT_EXPORTED or RECEIVER_EXPORTED for all
        // dynamically registered receivers. All receivers here are for system-only broadcasts
        // so RECEIVER_NOT_EXPORTED is correct — no other app should be able to send these.
        fun safeRegisterReceiver(
            receiver: android.content.BroadcastReceiver,
            filter: android.content.IntentFilter,
        ) {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(receiver, filter, android.content.Context.RECEIVER_NOT_EXPORTED)
            } else {
                @Suppress("UnspecifiedRegisterReceiverFlag")
                registerReceiver(receiver, filter)
            }
        }

        // ── A. App foreground trigger ─────────────────────────────────────────
        // Covers all "static" signals that can only change while the app is backgrounded:
        // root cloaking, SELinux, ptrace debugger, emulator fingerprint, SDK self-tamper,
        // native library integrity, StrongBox attestation, repackaged APK, build pipeline,
        // device anchor mismatch, OWASP MASVS, reflection guard, shell execution,
        // content-provider firewall, application velocity, overlay attack, deepfake precondition.
        // Fires immediately when the user brings the app back from background.
        var startedActivities = 0
        registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityStarted(activity: android.app.Activity) {
                if (++startedActivities == 1) evaluateNow("app_foreground")
            }
            override fun onActivityStopped(activity: android.app.Activity) { startedActivities-- }
            override fun onActivityCreated(activity: android.app.Activity, b: android.os.Bundle?) {}
            override fun onActivityResumed(activity: android.app.Activity) {}
            override fun onActivityPaused(activity: android.app.Activity) {}
            override fun onActivitySaveInstanceState(activity: android.app.Activity, b: android.os.Bundle) {}
            override fun onActivityDestroyed(activity: android.app.Activity) {}
        })

        // ── B. Screen mirroring / recording / remote desktop ─────────────────
        // DisplayManager fires the instant a virtual or external display is added —
        // covers ScreenMirroringSignal (5), ScreenRecordingSignal (21), RemoteDesktopSignal (11).
        (getSystemService(android.content.Context.DISPLAY_SERVICE)
                as? android.hardware.display.DisplayManager)
            ?.registerDisplayListener(
                object : android.hardware.display.DisplayManager.DisplayListener {
                    override fun onDisplayAdded(displayId: Int) {
                        if (displayId != android.view.Display.DEFAULT_DISPLAY)
                            evaluateNow("display_added id=$displayId")
                    }
                    override fun onDisplayRemoved(displayId: Int) {
                        if (displayId != android.view.Display.DEFAULT_DISPLAY) {
                            com.diimeai.demo.security.RaspSignalState.clear("SCREEN_MIRRORING")
                            com.diimeai.demo.security.RaspSignalState.clear("SCREEN_RECORDING_ACTIVE")
                            com.diimeai.demo.security.RaspSignalState.clear("REMOTE_DESKTOP")
                            Log.i(TAG, "RASP: external display removed — cleared screen signals")
                        }
                    }
                    override fun onDisplayChanged(displayId: Int) {}
                },
                handler
            )

        // ── C. VPN conflict ───────────────────────────────────────────────────
        // NetworkCallback fires the instant a VPN transport is established or lost.
        // Covers VpnConflictSignal (7).
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
            try {
                val cm = getSystemService(android.content.Context.CONNECTIVITY_SERVICE)
                        as? android.net.ConnectivityManager
                cm?.registerNetworkCallback(
                    android.net.NetworkRequest.Builder()
                        .addTransportType(android.net.NetworkCapabilities.TRANSPORT_VPN)
                        .build(),
                    object : android.net.ConnectivityManager.NetworkCallback() {
                        override fun onAvailable(network: android.net.Network) {
                            evaluateNow("vpn_connected")
                        }
                        override fun onLost(network: android.net.Network) {
                            com.diimeai.demo.security.RaspSignalState.clear("VPN_CONFLICT")
                            Log.i(TAG, "RASP: VPN disconnected — cleared VPN_CONFLICT")
                        }
                    }
                )
            } catch (_: Throwable) {}
        }

        // ── D. Accessibility / SMS intercept ─────────────────────────────────
        // AccessibilityManager fires immediately when any accessibility service is toggled.
        // Covers AccessibilityAbuseSignal (20) and SmsInterceptSignal (35).
        (getSystemService(android.content.Context.ACCESSIBILITY_SERVICE)
                as? android.view.accessibility.AccessibilityManager)
            ?.addAccessibilityStateChangeListener { enabled ->
                if (enabled) evaluateNow("accessibility_enabled")
                else {
                    // Both signals require an active accessibility service as a component.
                    // Disabling accessibility immediately breaks both conditions — clear both
                    // now rather than waiting for the next evaluateAll() OS trigger.
                    com.diimeai.demo.security.RaspSignalState.clear("ACCESSIBILITY_ABUSE")
                    com.diimeai.demo.security.RaspSignalState.clear("SMS_INTERCEPT_CAPABLE")
                    Log.i(TAG, "RASP: accessibility off — cleared ACCESSIBILITY_ABUSE + SMS_INTERCEPT_CAPABLE")
                }
            }

        // ── E. Package installs / updates / removals ──────────────────────────
        // Covers: HookingFrameworkSignal (12) — Xposed/LSPosed Manager installed
        //         AppCloneSignal (22) — Parallel Space / Dual Space app installed
        //         VirtualCameraSignal (25) — virtual camera app installed
        //         SideloadedApkSignal (33) — own app replaced by unofficial version
        //         DeviceAdminAbuseSignal (34) — banking trojan gains device admin
        //         SmsInterceptSignal (35) — SMS-capable app installed
        //         PredatoryLoanAppSignal (37) — predatory loan app installed
        //         RomanceSocialAppSignal (38) — dating app installed
        //         DeepfakePreconditionSignal (41) — voice-changer / MediaPipe app installed
        safeRegisterReceiver(
            object : android.content.BroadcastReceiver() {
                override fun onReceive(ctx: android.content.Context, intent: android.content.Intent) {
                    val pkg = intent.data?.schemeSpecificPart ?: return
                    val isUpdate = intent.getBooleanExtra(android.content.Intent.EXTRA_REPLACING, false)
                    if (intent.action == android.content.Intent.ACTION_PACKAGE_REMOVED && !isUpdate) {
                        // True uninstall (not an app update) — pre-clear persistent malware
                        // signals so evaluateAll() re-fires them only if other threats remain.
                        // EXTRA_REPLACING=true means PACKAGE_REMOVED is part of an update
                        // cycle; PACKAGE_REPLACED fires immediately after, so signals stay valid.
                        com.diimeai.demo.security.RaspSignalState.clear("SIDELOAD_DETECTED")
                        com.diimeai.demo.security.RaspSignalState.clear("DEVICE_ADMIN_ABUSE")
                        com.diimeai.demo.security.RaspSignalState.clear("SMS_INTERCEPT_CAPABLE")
                        com.diimeai.demo.security.RaspSignalState.clear("HOOKING_FRAMEWORK")
                        Log.i(TAG, "RASP: package uninstalled ($pkg) — cleared malware signals, re-evaluating")
                    }
                    evaluateNow("pkg_${intent.action?.substringAfterLast('.')} $pkg")
                }
            },
            android.content.IntentFilter().apply {
                addAction(android.content.Intent.ACTION_PACKAGE_ADDED)
                addAction(android.content.Intent.ACTION_PACKAGE_REPLACED)
                addAction(android.content.Intent.ACTION_PACKAGE_REMOVED)
                addDataScheme("package")
            }
        )

        // ── F. ContentObserver settings ───────────────────────────────────────

        // ADB enabled → AdbInstallSignal (3)
        contentResolver.registerContentObserver(
            android.provider.Settings.Global.getUriFor(android.provider.Settings.Global.ADB_ENABLED),
            false, object : android.database.ContentObserver(handler) {
                override fun onChange(selfChange: Boolean) { evaluateNow("adb_toggled") }
            }
        )

        // Developer mode → affects MockLocationSignal (23), AdbInstallSignal (3)
        contentResolver.registerContentObserver(
            android.provider.Settings.Global.getUriFor(
                android.provider.Settings.Global.DEVELOPMENT_SETTINGS_ENABLED),
            false, object : android.database.ContentObserver(handler) {
                override fun onChange(selfChange: Boolean) { evaluateNow("dev_mode_toggled") }
            }
        )

        // Default IME changed → UntrustedImeSignal (16)
        contentResolver.registerContentObserver(
            android.provider.Settings.Secure.getUriFor(
                android.provider.Settings.Secure.DEFAULT_INPUT_METHOD),
            false, object : android.database.ContentObserver(handler) {
                override fun onChange(selfChange: Boolean) { evaluateNow("ime_changed") }
            }
        )

        // Allow mock location → MockLocationSignal (23)
        @Suppress("DEPRECATION")
        contentResolver.registerContentObserver(
            android.provider.Settings.Secure.getUriFor(
                android.provider.Settings.Secure.ALLOW_MOCK_LOCATION),
            false, object : android.database.ContentObserver(handler) {
                override fun onChange(selfChange: Boolean) { evaluateNow("mock_location_setting") }
            }
        )

        // ── G. BroadcastReceiver — policy/hardware events ─────────────────────

        // Keyguard / device-admin state changed → KeyguardSignal (9), DeviceAdminAbuseSignal (34)
        // DEVICE_POLICY_MANAGER_STATE_CHANGED fires when admin sets/lifts lock requirements
        // or when a new device-admin app is activated/deactivated.
        safeRegisterReceiver(
            object : android.content.BroadcastReceiver() {
                override fun onReceive(ctx: android.content.Context, intent: android.content.Intent) {
                    evaluateNow("policy_or_keyguard_event")
                }
            },
            android.content.IntentFilter().apply {
                addAction("android.app.action.DEVICE_POLICY_MANAGER_STATE_CHANGED")
                addAction(android.content.Intent.ACTION_SCREEN_ON)
                addAction(android.content.Intent.ACTION_USER_PRESENT)
            }
        )

        // User-installed CA cert added/removed → UserCertificateSignal (10)
        safeRegisterReceiver(
            object : android.content.BroadcastReceiver() {
                override fun onReceive(ctx: android.content.Context, intent: android.content.Intent) {
                    evaluateNow("trust_store_changed")
                }
            },
            android.content.IntentFilter("android.security.action.TRUST_STORE_CHANGED")
        )

        // SIM / carrier change → SimSwapSignal (24)
        safeRegisterReceiver(
            object : android.content.BroadcastReceiver() {
                override fun onReceive(ctx: android.content.Context, intent: android.content.Intent) {
                    evaluateNow("carrier_config_changed")
                }
            },
            android.content.IntentFilter("android.telephony.action.CARRIER_CONFIG_CHANGED")
        )

        // NFC adapter state changed → NfcPaymentAbuseSignal (36)
        safeRegisterReceiver(
            object : android.content.BroadcastReceiver() {
                override fun onReceive(ctx: android.content.Context, intent: android.content.Intent) {
                    evaluateNow("nfc_adapter_state_changed")
                }
            },
            android.content.IntentFilter("android.nfc.action.ADAPTER_STATE_CHANGED")
        )

        // ── H. Camera availability → BackgroundCameraSignal (40), VirtualCameraSignal (25)
        // onCameraUnavailable fires the instant any app (including a background deepfake
        // capture app) opens any camera.  The signal class decides if it is our app.
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
            try {
                (getSystemService(android.content.Context.CAMERA_SERVICE)
                        as? android.hardware.camera2.CameraManager)
                    ?.registerAvailabilityCallback(
                        object : android.hardware.camera2.CameraManager.AvailabilityCallback() {
                            override fun onCameraUnavailable(cameraId: String) {
                                evaluateNow("camera_opened id=$cameraId")
                            }
                            override fun onCameraAvailable(cameraId: String) {
                                com.diimeai.demo.security.RaspSignalState.clear("BACKGROUND_CAMERA_ACTIVE")
                            }
                        },
                        handler
                    )
            } catch (_: Throwable) {}
        }

        // ── I. Call state → ConcurrentVideoCallSignal (30), CallMergeSignal (31)
        // TelephonyCallback (API 31+) / PhoneStateListener fires when a cellular call
        // starts or ends.  Combined with audio mode (J) this covers both cellular and
        // VoIP call scenarios.
        try {
            val tm = getSystemService(android.content.Context.TELEPHONY_SERVICE)
                    as? android.telephony.TelephonyManager
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
                tm?.registerTelephonyCallback(
                    mainExecutor,
                    object : android.telephony.TelephonyCallback(),
                            android.telephony.TelephonyCallback.CallStateListener {
                        override fun onCallStateChanged(state: Int) {
                            if (state != android.telephony.TelephonyManager.CALL_STATE_IDLE)
                                evaluateNow("call_state=$state")
                            else {
                                com.diimeai.demo.security.RaspSignalState.clear("CONCURRENT_VIDEO_CALL")
                                com.diimeai.demo.security.RaspSignalState.clear("CALL_MERGE_DETECTED")
                            }
                        }
                    }
                )
            } else {
                @Suppress("DEPRECATION")
                tm?.listen(
                    object : android.telephony.PhoneStateListener() {
                        @Deprecated("Deprecated in Java")
                        override fun onCallStateChanged(state: Int, phoneNumber: String?) {
                            if (state != android.telephony.TelephonyManager.CALL_STATE_IDLE)
                                evaluateNow("call_state=$state")
                            else {
                                com.diimeai.demo.security.RaspSignalState.clear("CONCURRENT_VIDEO_CALL")
                                com.diimeai.demo.security.RaspSignalState.clear("CALL_MERGE_DETECTED")
                            }
                        }
                    },
                    android.telephony.PhoneStateListener.LISTEN_CALL_STATE
                )
            }
        } catch (_: Throwable) {}

        // ── J. Audio mode → ConcurrentVideoCallSignal (30), CallMergeSignal (31)
        // AudioManager.MODE_IN_COMMUNICATION is set by ALL VoIP apps (WhatsApp, Zoom,
        // Telegram…) for the full duration of the call.  Fires immediately when the
        // user accepts / ends a VoIP call — no permission required.  API 31+ only;
        // older APIs are covered by the cellular PhoneStateListener above (I) plus
        // the app-foreground trigger (A) which re-evaluates AudioManager.mode on resume.
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            try {
                (getSystemService(android.content.Context.AUDIO_SERVICE)
                        as? android.media.AudioManager)
                    ?.addOnModeChangedListener(mainExecutor) { mode ->
                        if (mode == android.media.AudioManager.MODE_IN_COMMUNICATION ||
                            mode == android.media.AudioManager.MODE_IN_CALL) {
                            evaluateNow("audio_mode=$mode")
                        } else {
                            com.diimeai.demo.security.RaspSignalState.clear("CONCURRENT_VIDEO_CALL")
                            com.diimeai.demo.security.RaspSignalState.clear("CALL_MERGE_DETECTED")
                        }
                    }
            } catch (_: Throwable) {}
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
