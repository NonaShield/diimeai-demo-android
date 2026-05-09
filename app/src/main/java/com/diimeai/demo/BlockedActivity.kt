package com.diimeai.demo

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.diimeai.demo.databinding.ActivityBlockedBinding

/**
 * Shown when NonaShield blocks the device due to HIGH / CRITICAL risk signals.
 *
 * This screen is launched by DiimeApp.SignalSink.onBlock() and by
 * EdgeRiskEnforcer.assertAllowed() throwing SecurityException in PaymentActivity.
 *
 * In production: add a "Contact Support" button and log the event to your SOC.
 */
class BlockedActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_REASON = "block_reason"
    }

    private lateinit var binding: ActivityBlockedBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityBlockedBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val reason = intent.getStringExtra(EXTRA_REASON) ?: "Security policy violation detected"
        binding.tvBlockReason.text = reason

        // In production this button would open a support ticket / contact flow
        binding.btnContactSupport.setOnClickListener {
            // Demo: just finish
            finishAffinity()
        }
    }

    // Prevent back navigation — blocked device must contact support
    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        // Intentionally NO-OP — user cannot navigate away from block screen
    }
}
