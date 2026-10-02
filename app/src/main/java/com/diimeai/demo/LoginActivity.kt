package com.diimeai.demo

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.diimeai.demo.databinding.ActivityLoginBinding
import com.diimeai.demo.network.DiimeApiClient
import com.diimeai.demo.network.LoginResult
import com.payshield.sdk.PayShieldSDK
import com.payshield.sdk.policy.PolicyDecision
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
 * Behaviour (touch, typing rhythm, screen changes, back navigation) is captured by the SDK on every screen
 * automatically, so this screen has no capture code of its own.
 */
class LoginActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLoginBinding

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
            PayShieldSDK.assertAllowed()
        } catch (e: SecurityException) {
            Toast.makeText(this, "⛔ Login blocked — security risk detected", Toast.LENGTH_LONG).show()
            return
        }

        setLoading(true)

        lifecycleScope.launch(Dispatchers.IO) {
            // Credential-stuffing gap fix (ledger #8): fires POST /api/v1/ingest
            // with X-PS-Action=LOGIN and the typed username BEFORE the real
            // login call below -- this is what the backend's
            // check_login_action()/check_login_action_ip()/
            // check_login_action_device_distinct_users()/check_login_action_asn()
            // rate limiters actually key on. Without this call (or without
            // attemptedUserId specifically), none of those checks have any
            // real identity to rate-limit against at all -- the device's own
            // JWT only reflects whichever user last completed a REAL login,
            // which is stale/wrong at this exact moment. Same
            // runCatching {}.getOrNull() + DENY-gate pattern PaymentActivity/
            // ComplianceFragment already use for PAYMENT/KYC.
            val checkpoint = runCatching {
                PayShieldSDK.evaluateAtCheckpoint(action = "LOGIN", attemptedUserId = username)
            }.getOrNull()

            if (checkpoint != null && checkpoint.decision == PolicyDecision.DENY) {
                withContext(Dispatchers.Main) {
                    setLoading(false)
                    Toast.makeText(
                        this@LoginActivity,
                        "⛔ Login blocked — ${checkpoint.reason}",
                        Toast.LENGTH_LONG,
                    ).show()
                }
                return@launch
            }
            // STEP_UP: a real integration would show an OTP/CAPTCHA challenge
            // here (same pattern as PaymentActivity's risk step-up dialog).
            // This demo has no step-up flow on the login screen, so STEP_UP
            // is treated as advisory only and falls through to the real login.

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

        // Establish the real device JWT (iss=nonashield-device) via hardware-signed
        // /auth/device. Without this, BackendUploader falls back to the demo /auth/login
        // token (no iss claim), which /threats/batch rejects with 401 — RASP telemetry
        // never reaches the SOC dashboard even though login itself succeeds.
        PayShieldSDK.onUserLogin(result.userId)

        Toast.makeText(this, "Welcome, ${result.userId}!", Toast.LENGTH_SHORT).show()

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


