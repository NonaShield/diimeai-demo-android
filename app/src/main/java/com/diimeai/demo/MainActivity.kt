package com.diimeai.demo

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.diimeai.demo.databinding.ActivityMainBinding
import com.payshield.sdk.enrollment.EnrollmentState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Splash / Home screen.
 *
 * Shows enrollment status and routes to Login.
 * Enrollment was kicked off in DiimeApp.onCreate(); this screen simply
 * waits for the result and shows a status indicator.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnLogin.setOnClickListener {
            startActivity(Intent(this, LoginActivity::class.java))
        }

        // Show enrollment status
        refreshEnrollmentStatus()
    }

    override fun onResume() {
        super.onResume()
        refreshEnrollmentStatus()
    }

    private fun refreshEnrollmentStatus() {
        val enrolled = EnrollmentState.isEnrolled()
        binding.tvEnrollStatus.apply {
            if (enrolled) {
                text = "✅ Device enrolled with NonaShield"
                setTextColor(getColor(android.R.color.holo_green_dark))
            } else {
                text = "⏳ Enrolling device — please wait..."
                setTextColor(getColor(android.R.color.holo_orange_dark))

                // Poll until enrollment completes (async in DiimeApp)
                lifecycleScope.launch {
                    for (i in 1..12) {   // up to 60s
                        delay(5_000)
                        if (EnrollmentState.isEnrolled()) {
                            withContext(Dispatchers.Main) { refreshEnrollmentStatus() }
                            break
                        }
                    }
                }
            }
        }

        // Show device ID
        DiimeApp.enrollmentState?.let { state ->
            binding.tvDeviceId.text = "Device: ${state.deviceId.take(16)}…"
            binding.tvDeviceId.visibility = View.VISIBLE
        }
    }
}
