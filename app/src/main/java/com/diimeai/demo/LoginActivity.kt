package com.diimeai.demo

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.diimeai.demo.databinding.ActivityLoginBinding
import com.diimeai.demo.network.DiimeApiClient
import com.diimeai.demo.network.LoginResult
import com.payshield.sdk.PayShieldSDK
import com.payshield.sdk.policy.PolicyDecision
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume

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
            // Protect the login API: ask NonaShield BEFORE calling our own login. The action "LOGIN" is the API
            // name shown in the dashboard's Critical API section, and the typed username is what the backend's
            // login limits key on. The call waits for the answer (up to about a minute when the security team
            // has to review), and the login goes ahead only on ALLOW.
            val checkpoint = try {
                PayShieldSDK.evaluateApiCheckpoint(action = "LOGIN", attemptedUserId = username)
            } catch (e: Exception) {
                null                                   // no answer: not approved
            }

            when {
                checkpoint == null -> {
                    stopLoginWith("We could not verify this sign-in. Check your connection and try again.")
                    return@launch
                }
                checkpoint.decision == PolicyDecision.DENY -> {
                    stopLoginWith(loginDenyMessage(checkpoint.reason))
                    return@launch
                }
                checkpoint.decision == PolicyDecision.STEP_UP -> {
                    // A real app asks for its own OTP or biometric here; the demo asks for a confirmation.
                    if (!confirmStepUp()) {
                        stopLoginWith("Sign-in cancelled.")
                        return@launch
                    }
                }
            }

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

    private suspend fun stopLoginWith(message: String) = withContext(Dispatchers.Main) {
        setLoading(false)
        Toast.makeText(this@LoginActivity, message, Toast.LENGTH_LONG).show()
    }

    private fun loginDenyMessage(reason: String?): String = when (reason) {
        "soc_blocked" -> "This sign-in was blocked by security review."
        "soc_review_timeout" -> "This sign-in was not approved in time. Please try again."
        "critical_issue_enforced" -> "Sign-in is blocked because of a security issue on this device."
        "on_device_persistent_block", "backend_force_block" -> "This device is blocked."
        "verification_unavailable" -> "We could not verify this sign-in. Check your connection and try again."
        else -> "Sign-in blocked for security reasons."
    }

    private suspend fun confirmStepUp(): Boolean = withContext(Dispatchers.Main) {
        suspendCancellableCoroutine { cont ->
            AlertDialog.Builder(this@LoginActivity)
                .setTitle("Additional verification")
                .setMessage("Security needs one more check before you sign in. In your own app this is where you ask for an OTP or biometric.")
                .setCancelable(true)
                .setPositiveButton("Verify (demo)") { _, _ -> if (cont.isActive) cont.resume(true) }
                .setNegativeButton("Cancel") { _, _ -> if (cont.isActive) cont.resume(false) }
                .setOnCancelListener { if (cont.isActive) cont.resume(false) }
                .show()
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


