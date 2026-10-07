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
            val result = DiimeApiClient.login(username, password)
            when (result) {
                is LoginResult.Failure -> stopLoginWith(result.reason)
                is LoginResult.Success -> {
                    // The app's own login worked and NonaShield now knows the user. Before entering the app, ask
                    // NonaShield about this login, the same way a payment is checked. The action "LOGIN" is the API
                    // name shown in the dashboard's Critical API section. The call waits for the answer (up to about
                    // a minute when the security team has to review) and the app is entered only on ALLOW.
                    withContext(Dispatchers.Main) { startSession(result) }
                    val checkpoint = try {
                        PayShieldSDK.evaluateApiCheckpoint(action = "LOGIN", attemptedUserId = username)
                    } catch (e: Exception) {
                        null                               // no answer: not approved
                    }

                    when {
                        checkpoint == null -> denyLogin("We could not verify this sign-in. Check your connection and try again.")
                        checkpoint.decision == PolicyDecision.DENY -> denyLogin(loginDenyMessage(checkpoint.reason))
                        checkpoint.decision == PolicyDecision.STEP_UP -> {
                            // A real app asks for its own OTP or biometric here; the demo asks for a confirmation.
                            if (confirmStepUp()) enterApp(result) else denyLogin("Sign-in cancelled.")
                        }
                        else -> enterApp(result)
                    }
                }
            }
        }
    }

    private suspend fun stopLoginWith(message: String) = withContext(Dispatchers.Main) {
        setLoading(false)
        Toast.makeText(this@LoginActivity, message, Toast.LENGTH_LONG).show()
    }

    /** NonaShield did not approve this login: leave the signed-in session and stay on the login screen. */
    private suspend fun denyLogin(message: String) {
        DiimeApiClient.clearSession()
        stopLoginWith(message)
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

    /** Puts the signed-in user into the app and NonaShield (no screen change yet). */
    private fun startSession(result: LoginResult.Success) {
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
    }

    private suspend fun enterApp(result: LoginResult.Success) = withContext(Dispatchers.Main) {
        setLoading(false)
        Toast.makeText(this@LoginActivity, "Welcome, ${result.userId}!", Toast.LENGTH_SHORT).show()

        startActivity(Intent(this@LoginActivity, ScenarioHubActivity::class.java).apply {
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


