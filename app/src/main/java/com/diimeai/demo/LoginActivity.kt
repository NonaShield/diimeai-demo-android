package com.diimeai.demo

import android.content.Intent
import android.content.res.Configuration
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.diimeai.demo.databinding.ActivityLoginBinding
import com.diimeai.demo.network.DiimeApiClient
import com.diimeai.demo.network.LoginResult
import com.payshield.android.edge.EdgeRiskEnforcer
import com.payshield.sdk.PayShieldSDK
import com.payshield.sdk.behavioral.BehavioralCaptureManager
import com.payshield.sdk.behavioral.KeystrokeDynamicsCapture
import com.payshield.sdk.signal.EdgeSignal
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Login screen.
 *
 * On success:
 *   1. Calls DiimeApiClient.setSession() — injects user identity into SessionHolder.
 *   2. PinningInterceptor now builds X-PayShield-Token with real uid/did/sid.
 *   3. Routes to PaymentActivity.
 *
 * In production: replace the mock login call with your real auth endpoint.
 * The NonaShield SDK is auth-agnostic — it protects calls AFTER you have a session.
 *
 * ─── Behavioral integration ───────────────────────────────────────────────────
 *
 * [KeystrokeDynamicsCapture] is attached to all EditText fields in [onResume] and
 * detached in [onPause].  It records timing intervals between keystrokes on the
 * username and password fields — capturing typing rhythm that feeds into the
 * social-engineering (Digital Arrest / Romance Fraud) detection pipeline.
 *
 * [BehavioralCaptureManager] is attached to the root view in [onResume] so every
 * touch gesture (taps, swipes, hesitation) is captured transparently.
 *
 * [onConfigurationChanged] calls [BehavioralCaptureManager.recordOrientationChange]
 * to increment the screen_orientation_changes counter in [BehavioralFeatures].
 *
 * Back-press calls [SessionFlowAnalyzer.onBackNavigation] to increment the
 * back_navigation_count counter — elevated back navigation correlates with coached
 * / confused users (Romance Fraud scenario).
 */
class LoginActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLoginBinding

    // ── Behavioral SDK ────────────────────────────────────────────────────────

    /**
     * Captures keystroke dynamics on the username + password fields.
     * Attached in onResume, detached in onPause.
     */
    private val keystrokeDynamics = KeystrokeDynamicsCapture()

    /**
     * Touch capture manager — records pressure, velocity, hesitation per gesture.
     * SessionFlowAnalyzer inside tracks inter-gesture intervals and navigation.
     *
     * Session ID uses a pre-login timestamp; the payload is tagged with the real
     * session ID after [DiimeApiClient.setSession] in [onLoginSuccess].
     */
    private val captureManager by lazy {
        BehavioralCaptureManager(
            sink              = behavioralSink,
            sessionId         = "pre_login_${System.currentTimeMillis()}",
            keystrokeDynamics = keystrokeDynamics
        )
    }

    /**
     * Bridges [com.payshield.sdk.signal.SignalSink] (SDK internal) to
     * [com.payshield.android.sdk.SignalSink] (public API registered in DiimeApp).
     *
     * Any behavioral anomaly signal emitted by [BehavioralCaptureManager] is
     * forwarded through [DiimeApiClient.signalSink] to the NonaShield backend.
     */
    private val behavioralSink = object : com.payshield.sdk.signal.SignalSink {
        override fun emit(signal: EdgeSignal) {
            DiimeApiClient.signalSink?.onSignalsCollected(listOf(signal))
        }
        override fun onBlock(reason: String) {
            DiimeApiClient.signalSink?.onBlock(reason)
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lifecycle
    // ─────────────────────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnSignIn.setOnClickListener { attemptLogin() }
        binding.tvSkipDemo.setOnClickListener { useDemoSession() }
    }

    override fun onResume() {
        super.onResume()
        // ── Behavioral: attach keystroke and touch capture ─────────────────────
        // attachToRoot recursively wraps all EditText descendants with timing
        // listeners — captures username and password field typing dynamics.
        keystrokeDynamics.attachToRoot(binding.root)
        // attachTo wraps the root view's OnTouchListener transparently.
        captureManager.attachTo(binding.root)
        // Mark screen entry — starts dwell-time measurement for this screen.
        captureManager.sessionFlowAnalyzer.onScreenTransition()
    }

    override fun onPause() {
        super.onPause()
        // ── Behavioral: detach to avoid leaking listeners after screen exit ────
        keystrokeDynamics.detachFromRoot()
        captureManager.detachFrom(binding.root)
    }

    /**
     * Called when the device is rotated (requires android:configChanges="orientation|screenSize"
     * in AndroidManifest.xml — the activity is NOT recreated on rotation).
     *
     * Increments [BehavioralFeatures.screenOrientationChanges] which feeds into the
     * backend's orientation_change_count field in BehavioralFeaturesPayload.
     */
    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        captureManager.recordOrientationChange(newConfig)
    }

    /**
     * Intercept system back press to record it in SessionFlowAnalyzer.
     *
     * [BehavioralFeatures.backtrackCount] is incremented — elevated backtracking
     * on the login screen correlates with hesitant / coached user behaviour.
     */
    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        captureManager.sessionFlowAnalyzer.onBackNavigation()
        @Suppress("DEPRECATION")
        super.onBackPressed()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Login flow
    // ─────────────────────────────────────────────────────────────────────────

    private fun attemptLogin() {
        val username = binding.etUsername.text.toString().trim()
        val password = binding.etPassword.text.toString()

        if (username.isBlank()) {
            binding.etUsername.error = "Username required"
            return
        }
        if (password.isBlank()) {
            binding.etPassword.error = "Password required"
            return
        }

        try {
            EdgeRiskEnforcer.assertAllowed()
        } catch (e: SecurityException) {
            Toast.makeText(this, "⛔ Login blocked — security risk detected", Toast.LENGTH_LONG).show()
            return
        }

        setLoading(true)

        lifecycleScope.launch(Dispatchers.IO) {
            val result = DiimeApiClient.login(username, password)

            withContext(Dispatchers.Main) {
                setLoading(false)
                when (result) {
                    is LoginResult.Success -> onLoginSuccess(result)
                    is LoginResult.Failure -> {
                        Toast.makeText(this@LoginActivity, result.reason, Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    private fun useDemoSession() {
        // Pre-fill demo credentials for investor demo
        binding.etUsername.setText("demo_investor")
        binding.etPassword.setText("Demo@123")
        attemptLogin()
    }

    private fun onLoginSuccess(result: LoginResult.Success) {
        val deviceId = DiimeApp.enrollmentState?.deviceId
            ?: PayShieldSDK.getStableDeviceId()

        // Inject session into NonaShield — PinningInterceptor picks it up immediately.
        DiimeApiClient.setSession(
            userId    = result.userId,
            deviceId  = deviceId,
            sessionId = result.sessionId,
            jwt       = result.jwt
        )

        Toast.makeText(this, "Welcome, ${result.userId}!", Toast.LENGTH_SHORT).show()

        // ── Behavioral: record screen transition (Login → Payment) ─────────────
        // Records the dwell time on the login screen in SessionFlowAnalyzer.
        captureManager.sessionFlowAnalyzer.onScreenTransition()

        startActivity(Intent(this, ScenarioHubActivity::class.java).apply {
            putExtra("USER_ID", result.userId)
        })
        finish()
    }

    private fun setLoading(loading: Boolean) {
        binding.btnSignIn.isEnabled = !loading
        binding.progressBar.visibility =
            if (loading) android.view.View.VISIBLE else android.view.View.GONE
    }
}


