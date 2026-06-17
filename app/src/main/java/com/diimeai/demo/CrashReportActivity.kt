package com.diimeai.demo

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

/**
 * Demo-only crash reporter. Displayed by DiimeApp's uncaught-exception handler
 * so that SDK startup failures are visible on-device rather than silently killing the app.
 *
 * Remove or gate behind BuildConfig.DEBUG before shipping to production.
 */
class CrashReportActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val crashMessage = intent.getStringExtra(EXTRA_CRASH_MESSAGE)
            ?: "No crash details available."

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#0f0f1a"))
            setPadding(dp(16), dp(40), dp(16), dp(16))
        }

        // Title
        root.addView(TextView(this).apply {
            text = "SDK Crash Report"
            textSize = 18f
            setTextColor(Color.parseColor("#ff6b6b"))
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, dp(4))
        })

        root.addView(TextView(this).apply {
            text = "Copy and share with the SDK team to diagnose."
            textSize = 12f
            setTextColor(Color.parseColor("#aaaaaa"))
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, dp(16))
        })

        // Scrollable error text
        val scroll = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f
            )
        }
        val errorText = TextView(this).apply {
            text = crashMessage
            textSize = 11f
            setTextColor(Color.parseColor("#e8e8e8"))
            typeface = Typeface.MONOSPACE
            setBackgroundColor(Color.parseColor("#0a0a14"))
            setPadding(dp(12), dp(12), dp(12), dp(12))
        }
        scroll.addView(errorText)
        root.addView(scroll)

        // Buttons row
        val btnRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = dp(12) }
        }

        btnRow.addView(Button(this).apply {
            text = "Copy"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                .apply { marginEnd = dp(8) }
            setOnClickListener {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("CrashReport", crashMessage))
                Toast.makeText(this@CrashReportActivity, "Copied to clipboard", Toast.LENGTH_SHORT).show()
            }
        })

        btnRow.addView(Button(this).apply {
            text = "Close App"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { finishAffinity() }
        })

        root.addView(btnRow)
        setContentView(root)
    }

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()

    companion object {
        const val EXTRA_CRASH_MESSAGE = "crash_message"
    }
}
