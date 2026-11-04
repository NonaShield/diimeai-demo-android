package com.diimeai.demo

import android.os.Bundle
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.payshield.sdk.consent.ConsentException
import com.payshield.sdk.consent.ConsentItem
import com.payshield.sdk.consent.PayShieldConsent
import kotlinx.coroutines.launch

/**
 * Consent demo: asks the demo server for a session through the SDK's signed client, shows the SDK's consent
 * panel, then shows the receipt hash and proof label. Withdraw and list use a dashboard session.
 *
 * Needs an android-sdk-release.aar built from the SDK branch that adds com.payshield.sdk.consent
 * (PayShieldConsent.present / withdraw / list / demoSession).
 */
class ConsentActivity : AppCompatActivity() {

    private lateinit var output: TextView
    private lateinit var presentButton: Button
    private lateinit var listButton: Button
    private lateinit var withdrawButton: Button
    private var lastItems: List<ConsentItem> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val density = resources.displayMetrics.density
        val pad = (16 * density).toInt()

        val column = LinearLayout(this)
        column.orientation = LinearLayout.VERTICAL
        column.setPadding(pad, pad, pad, pad)

        val title = TextView(this)
        title.text = "Consent"
        title.textSize = 22f
        title.setTextColor(0xFF00D4FF.toInt())
        column.addView(title)

        presentButton = Button(this)
        presentButton.text = "Show consent panel"
        presentButton.setOnClickListener { onPresent() }
        column.addView(presentButton)

        listButton = Button(this)
        listButton.text = "List my consents"
        listButton.setOnClickListener { onList() }
        column.addView(listButton)

        withdrawButton = Button(this)
        withdrawButton.text = "Withdraw first active consent"
        withdrawButton.setOnClickListener { onWithdraw() }
        column.addView(withdrawButton)

        output = TextView(this)
        output.setTextColor(0xFFDDDDDD.toInt())
        output.setPadding(0, pad, 0, 0)
        output.setTextIsSelectable(true)
        column.addView(output)

        val scroll = ScrollView(this)
        scroll.setBackgroundColor(0xFF0A0A1A.toInt())
        scroll.addView(
            column,
            ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )
        setContentView(scroll)
    }

    private fun setBusy(busy: Boolean) {
        presentButton.isEnabled = !busy
        listButton.isEnabled = !busy
        withdrawButton.isEnabled = !busy
    }

    private fun onPresent() {
        setBusy(true)
        output.text = "Starting a consent session..."
        lifecycleScope.launch {
            try {
                val session = PayShieldConsent.demoSession()
                val result = PayShieldConsent.present(this@ConsentActivity, session.sessionId)
                val receipt = result.receiptHashes.firstOrNull().orEmpty()
                val proof = proofLabelFor(receipt)
                output.text = "Saved.\nReceipt hash: $receipt\nProof label: $proof\nRecords: ${result.artefactIds.size}"
            } catch (e: ConsentException) {
                output.text = if (e.code == "CANCELLED") "Cancelled. Nothing was recorded." else "Failed: ${e.code}"
            } finally {
                setBusy(false)
            }
        }
    }

    private suspend fun proofLabelFor(receiptHash: String): String = try {
        val dashboard = PayShieldConsent.demoSession(dashboard = true)
        val items = PayShieldConsent.list(dashboard.sessionId)
        lastItems = items
        items.firstOrNull { it.receiptHash == receiptHash }?.proofLabel ?: "not listed yet"
    } catch (e: ConsentException) {
        "unavailable (${e.code})"
    }

    private fun onList() {
        setBusy(true)
        output.text = "Loading..."
        lifecycleScope.launch {
            try {
                val dashboard = PayShieldConsent.demoSession(dashboard = true)
                val items = PayShieldConsent.list(dashboard.sessionId)
                lastItems = items
                output.text = if (items.isEmpty()) {
                    "No consents on record."
                } else {
                    items.joinToString("\n\n") {
                        "${it.purposeCode}: ${it.status}\nProof: ${it.proofLabel}  Presence: ${it.userPresence ?: "-"}\n" +
                            "Receipt: ${it.receiptHash ?: "-"}"
                    }
                }
            } catch (e: ConsentException) {
                output.text = "Failed: ${e.code}"
            } finally {
                setBusy(false)
            }
        }
    }

    private fun onWithdraw() {
        setBusy(true)
        lifecycleScope.launch {
            try {
                val dashboard = PayShieldConsent.demoSession(dashboard = true)
                val items = if (lastItems.isEmpty()) PayShieldConsent.list(dashboard.sessionId) else lastItems
                val target = items.firstOrNull { it.status == "GRANTED" }
                if (target == null) {
                    output.text = "Nothing to withdraw. Grant a consent first."
                } else {
                    val result = PayShieldConsent.withdraw(dashboard.sessionId, target.purposeCode)
                    lastItems = emptyList()
                    output.text = "Withdrawn: ${target.purposeCode}\nReceipt hash: ${result.receiptHashes.firstOrNull().orEmpty()}"
                }
            } catch (e: ConsentException) {
                output.text = "Failed: ${e.code}"
            } finally {
                setBusy(false)
            }
        }
    }
}
