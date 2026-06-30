package com.diimeai.demo

import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.lifecycle.lifecycleScope
import com.payshield.sdk.PayShieldEdgeInitializer
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * RaspSensorTableActivity — live 3-column status table of every RASP sensor registered
 * by the SDK ([RaspSensorRegistry]).
 *
 * Columns: Sensor Name | Severity (Critical/High/Medium/Low) | Status (Active/Inactive).
 *
 * Status is read directly from [PayShieldEdgeInitializer.isSignalActive] every refresh
 * tick — zero simulated data, this reflects the actual current state of the device the
 * demo is running on. Built for CISO / investor walkthroughs: every row is a real,
 * independently auditable detector, not a marketing claim.
 */
class RaspSensorTableActivity : AppCompatActivity() {

    companion object {
        private const val REFRESH_INTERVAL_MS = 1_000L
    }

    private var refreshJob: Job? = null
    private lateinit var summaryView: TextView
    private lateinit var rowsContainer: LinearLayout
    private val statusViews = mutableMapOf<Int, TextView>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#0A0A1A"))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.MATCH_PARENT
            )
        }

        root.addView(buildToolbar())
        root.addView(buildSummaryBar())
        root.addView(buildHeaderRow())

        val scroll = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f
            )
        }
        rowsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }
        scroll.addView(rowsContainer)
        root.addView(scroll)

        setContentView(root)
        buildRows()
    }

    override fun onResume() {
        super.onResume()
        if (refreshJob?.isActive != true) startRefreshLoop()
    }

    override fun onPause() {
        super.onPause()
        refreshJob?.cancel()
    }

    // ── header chrome ─────────────────────────────────────────────────────────

    private fun buildToolbar(): Toolbar = Toolbar(this).apply {
        setBackgroundColor(Color.parseColor("#0D1117"))
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
        )
        val title = TextView(context).apply {
            text = "RASP Sensor Status"
            textSize = 18f
            setTextColor(Color.parseColor("#00D4FF"))
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        }
        addView(title)
        setNavigationIcon(android.R.drawable.ic_menu_revert)
        setNavigationOnClickListener { finish() }
    }

    private fun buildSummaryBar(): TextView {
        summaryView = TextView(this).apply {
            textSize = 12f
            setTextColor(Color.parseColor("#888888"))
            setPadding(20, 14, 20, 10)
            text = "Loading…"
        }
        return summaryView
    }

    private fun buildHeaderRow(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        setBackgroundColor(Color.parseColor("#0D1117"))
        setPadding(20, 10, 20, 10)
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
        )

        addView(headerCell("RASP SENSOR", 2.2f))
        addView(headerCell("SEVERITY", 1f))
        addView(headerCell("STATUS", 1f))
    }

    private fun headerCell(text: String, weight: Float): TextView = TextView(this).apply {
        this.text = text
        textSize = 11f
        setTextColor(Color.parseColor("#666666"))
        typeface = android.graphics.Typeface.DEFAULT_BOLD
        layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, weight)
    }

    // ── table rows ────────────────────────────────────────────────────────────

    private fun buildRows() {
        rowsContainer.removeAllViews()
        statusViews.clear()

        RaspSensorRegistry.ALL.forEachIndexed { index, sensor ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(20, 14, 20, 14)
                setBackgroundColor(
                    if (index % 2 == 0) Color.parseColor("#0D1117") else Color.parseColor("#0A0A1A")
                )
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }

            val nameCol = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 2.2f)
            }
            nameCol.addView(TextView(this).apply {
                text = sensor.name
                textSize = 12.5f
                setTextColor(Color.parseColor("#FFFFFF"))
            })
            nameCol.addView(TextView(this).apply {
                text = sensor.threatId
                textSize = 9.5f
                setTextColor(Color.parseColor("#555555"))
                typeface = android.graphics.Typeface.MONOSPACE
            })

            val severityView = TextView(this).apply {
                text = sensor.severity.label
                textSize = 11f
                setTextColor(Color.parseColor(sensor.severity.colorHex))
                typeface = android.graphics.Typeface.DEFAULT_BOLD
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }

            val statusView = TextView(this).apply {
                textSize = 11f
                typeface = android.graphics.Typeface.DEFAULT_BOLD
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }
            statusViews[index] = statusView

            row.addView(nameCol)
            row.addView(severityView)
            row.addView(statusView)
            rowsContainer.addView(row)
        }

        refreshStatuses()
    }

    // ── live refresh ──────────────────────────────────────────────────────────

    private fun startRefreshLoop() {
        refreshJob = lifecycleScope.launch {
            while (isActive) {
                refreshStatuses()
                delay(REFRESH_INTERVAL_MS)
            }
        }
    }

    private fun refreshStatuses() {
        var activeCount = 0
        RaspSensorRegistry.ALL.forEachIndexed { index, sensor ->
            val active = sensor.signalTypes.any { PayShieldEdgeInitializer.isSignalActive(it) }
            if (active) activeCount++
            val view = statusViews[index] ?: return@forEachIndexed
            if (active) {
                view.text = "● ACTIVE"
                view.setTextColor(Color.parseColor("#FF3333"))
            } else {
                view.text = "● Inactive"
                view.setTextColor(Color.parseColor("#00CC55"))
            }
        }

        val total = RaspSensorRegistry.ALL.size
        summaryView.text = if (activeCount == 0)
            "$total sensors monitored · all clean · live, on-device — no simulated data"
        else
            "$total sensors monitored · $activeCount ACTIVE · live, on-device — no simulated data"
        summaryView.setTextColor(
            if (activeCount == 0) Color.parseColor("#00CC55") else Color.parseColor("#FF3333")
        )
    }
}
