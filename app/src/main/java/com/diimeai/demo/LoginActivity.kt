package com.diimeai.demo

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.diimeai.demo.databinding.ActivityLoginBinding
import com.diimeai.demo.network.DiimeApiClient
import com.diimeai.demo.network.LoginResult
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
 */
class LoginActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLoginBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnSignIn.setOnClickListener { attemptLogin() }
        binding.tvSkipDemo.setOnClickListener { useDemoSession() }
    }

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
            ?: DiimeApp.keyManager.getStableDeviceId()

        // Inject session into NonaShield — PinningInterceptor picks it up immediately.
        DiimeApiClient.setSession(
            userId    = result.userId,
            deviceId  = deviceId,
            sessionId = result.sessionId,
            jwt       = result.jwt
        )

        Toast.makeText(this, "Welcome, ${result.userId}!", Toast.LENGTH_SHORT).show()

        startActivity(Intent(this, PaymentActivity::class.java).apply {
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
