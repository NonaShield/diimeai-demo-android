package com.diimeai.demo

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.diimeai.demo.network.ComplianceItem
import com.diimeai.demo.network.ComplianceStatus
import com.diimeai.demo.network.DiimeApiClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Real-time compliance tab — replaces the old "Platform" tab.
 *
 * Polls GET /api/v1/dashboard/compliance every 5 s and renders 5 compliance
 * requirement cards with live status badges derived from backend telemetry.
 */
class ComplianceFragment : Fragment() {

    companion object {
        fun newInstance() = ComplianceFragment()

        private const val POLL_INTERVAL_MS = 5_000L

        private val STATUS_COLOR = mapOf(
            "COMPLIANT"     to 0xFF1B5E20.toInt(),   // deep green
            "PARTIAL"       to 0xFFE65100.toInt(),   // deep orange
            "NON_COMPLIANT" to 0xFFB71C1C.toInt(),   // deep red
            "UNKNOWN"       to 0xFF424242.toInt(),   // grey
        )
        private val STATUS_BG = mapOf(
            "COMPLIANT"     to 0xFFE8F5E9.toInt(),
            "PARTIAL"       to 0xFFFFF3E0.toInt(),
            "NON_COMPLIANT" to 0xFFFFEBEE.toInt(),
            "UNKNOWN"       to 0xFFF5F5F5.toInt(),
        )
        private val STATUS_LABEL = mapOf(
            "COMPLIANT"     to "COMPLIANT",
            "PARTIAL"       to "PARTIAL",
            "NON_COMPLIANT" to "NON-COMPLIANT",
            "UNKNOWN"       to "UNKNOWN",
        )
    }

    private lateinit var api: DiimeApiClient
    private var pollJob: Job? = null

    // View references — rebuilt on each poll
    private lateinit var tvOverallBadge: TextView
    private lateinit var tvLastUpdated:  TextView
    private lateinit var tvDataSource:   TextView
    private lateinit var cardsContainer: LinearLayout

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        api = DiimeApiClient(requireContext())

        val root = ScrollView(requireContext()).apply {
            layoutParams = ViewGroup.LayoutParams(MATCH_PARENT, MATCH_PARENT)
            setBackgroundColor(0xFFF8F9FA.toInt())
        }

        val page = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
            val p = dp(16)
            setPadding(p, p, p, p)
        }

        // ── Header ────────────────────────────────────────────────────────────
        val header = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(16)
            }
            setBackgroundColor(0xFF0D1117.toInt())
            val p = dp(16)
            setPadding(p, p, p, p)
            elevation = dp(4).toFloat()
        }

        val tvTitle = TextView(requireContext()).apply {
            text = "Cryptographic Compliance"
            textSize = 18f
            setTypeface(null, Typeface.BOLD)
            setTextColor(0xFFFFFFFF.toInt())
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(4)
            }
        }

        val tvSubtitle = TextView(requireContext()).apply {
            text = "Live telemetry — 5 regulatory requirements"
            textSize = 12f
            setTextColor(0xFF9E9E9E.toInt())
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(12)
            }
        }

        val overallRow = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
            gravity = Gravity.CENTER_VERTICAL
        }

        val tvOverallLabel = TextView(requireContext()).apply {
            text = "Overall status:"
            textSize = 13f
            setTextColor(0xFFBDBDBD.toInt())
            layoutParams = LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT).also {
                it.rightMargin = dp(8)
            }
        }

        tvOverallBadge = TextView(requireContext()).apply {
            text = "Loading…"
            textSize = 12f
            setTypeface(null, Typeface.BOLD)
            setTextColor(0xFFFFFFFF.toInt())
            setPadding(dp(8), dp(4), dp(8), dp(4))
            setBackgroundColor(0xFF616161.toInt())
        }

        val spacer = View(requireContext()).apply {
            layoutParams = LinearLayout.LayoutParams(0, 1, 1f)
        }

        tvLastUpdated = TextView(requireContext()).apply {
            text = ""
            textSize = 11f
            setTextColor(0xFF757575.toInt())
        }

        tvDataSource = TextView(requireContext()).apply {
            text = ""
            textSize = 10f
            setTextColor(0xFF616161.toInt())
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.topMargin = dp(4)
            }
        }

        overallRow.addView(tvOverallLabel)
        overallRow.addView(tvOverallBadge)
        overallRow.addView(spacer)
        overallRow.addView(tvLastUpdated)

        header.addView(tvTitle)
        header.addView(tvSubtitle)
        header.addView(overallRow)
        header.addView(tvDataSource)

        // ── Cards container ───────────────────────────────────────────────────
        cardsContainer = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }

        page.addView(header)
        page.addView(cardsContainer)
        root.addView(page)
        return root
    }

    override fun onResume() {
        super.onResume()
        startPolling()
    }

    override fun onPause() {
        super.onPause()
        pollJob?.cancel()
    }

    private fun startPolling() {
        pollJob?.cancel()
        pollJob = lifecycleScope.launch {
            while (isActive) {
                val status = withContext(Dispatchers.IO) { api.getComplianceStatus() }
                if (isActive) renderStatus(status)
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    private fun renderStatus(status: ComplianceStatus) {
        val ctx = context ?: return

        // Update header badges
        val oc = STATUS_COLOR[status.overallStatus] ?: STATUS_COLOR["UNKNOWN"]!!
        tvOverallBadge.text = STATUS_LABEL[status.overallStatus] ?: status.overallStatus
        tvOverallBadge.setBackgroundColor(oc)
        tvLastUpdated.text = status.lastUpdated
        tvDataSource.text = if (status.dataSource == "live") "● Live data" else "○ ${status.dataSource}"
        tvDataSource.setTextColor(if (status.dataSource == "live") 0xFF4CAF50.toInt() else 0xFFFF9800.toInt())

        // Rebuild all cards
        cardsContainer.removeAllViews()

        status.items.forEachIndexed { idx, item ->
            val card = buildCard(item)
            val params = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(12)
            }
            cardsContainer.addView(card, params)
        }
    }

    private fun buildCard(item: ComplianceItem): LinearLayout {
        val statusColor = STATUS_COLOR[item.status] ?: STATUS_COLOR["UNKNOWN"]!!
        val statusBg    = STATUS_BG[item.status]    ?: STATUS_BG["UNKNOWN"]!!
        val statusLabel = STATUS_LABEL[item.status] ?: item.status

        val card = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(0xFFFFFFFF.toInt())
            elevation = dp(2).toFloat()
            val p = dp(14)
            setPadding(p, p, p, p)
        }

        // ── Card header row ───────────────────────────────────────────────────
        val headerRow = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(2)
            }
            gravity = Gravity.CENTER_VERTICAL
        }

        val tvName = TextView(requireContext()).apply {
            text = item.name
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
            setTextColor(0xFF1A1A2E.toInt())
            layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
        }

        val tvStatus = TextView(requireContext()).apply {
            text = statusLabel
            textSize = 10f
            setTypeface(null, Typeface.BOLD)
            setTextColor(statusColor)
            setBackgroundColor(statusBg)
            setPadding(dp(6), dp(3), dp(6), dp(3))
        }

        headerRow.addView(tvName)
        headerRow.addView(tvStatus)

        // ── Standard badge ────────────────────────────────────────────────────
        val tvStandard = TextView(requireContext()).apply {
            text = item.standard
            textSize = 11f
            setTextColor(0xFF1565C0.toInt())
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(10)
            }
        }

        // ── Industry gap section ──────────────────────────────────────────────
        val gapSection = buildSectionBox(
            label       = "WHY CURRENT METHODS FAIL",
            labelColor  = 0xFFB71C1C.toInt(),
            bgColor     = 0xFFFFF8F8.toInt(),
            borderColor = 0xFFEF9A9A.toInt(),
            body        = item.industryGap,
        )

        // ── NS solution section ───────────────────────────────────────────────
        val solSection = buildSectionBox(
            label       = "NONASHIELD CRYPTOGRAPHIC SOLUTION",
            labelColor  = 0xFF1B5E20.toInt(),
            bgColor     = 0xFFF1F8E9.toInt(),
            borderColor = 0xFF81C784.toInt(),
            body        = item.nsSolution,
        )

        // ── Metric row ────────────────────────────────────────────────────────
        val metricRow = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.topMargin = dp(8)
            }
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(statusBg)
            val p = dp(8)
            setPadding(p, p, p, p)
        }

        val metricValue = when {
            item.metric == item.metric.toLong().toDouble() -> item.metric.toLong().toString()
            else -> String.format("%.1f", item.metric)
        }

        val tvMetric = TextView(requireContext()).apply {
            text = "$metricValue ${item.metricLabel}"
            textSize = 12f
            setTypeface(null, Typeface.BOLD)
            setTextColor(statusColor)
            layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
        }

        val tvDetail = TextView(requireContext()).apply {
            text = item.statusDetail
            textSize = 11f
            setTextColor(0xFF616161.toInt())
            layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1.5f)
            gravity = Gravity.END
        }

        metricRow.addView(tvMetric)
        metricRow.addView(tvDetail)

        card.addView(headerRow)
        card.addView(tvStandard)
        card.addView(gapSection)
        card.addView(solSection)
        card.addView(metricRow)

        return card
    }

    private fun buildSectionBox(
        label:       String,
        labelColor:  Int,
        bgColor:     Int,
        borderColor: Int,
        body:        String,
    ): LinearLayout {
        val box = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(bgColor)
            val p = dp(10)
            setPadding(p, dp(8), p, dp(8))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(6)
            }
        }

        val tvLabel = TextView(requireContext()).apply {
            text = label
            textSize = 10f
            setTypeface(null, Typeface.BOLD)
            setTextColor(labelColor)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(4)
            }
        }

        val tvBody = TextView(requireContext()).apply {
            text = body
            textSize = 12f
            setTextColor(0xFF37474F.toInt())
            lineHeight = (textSize * 1.5f).toInt()
        }

        box.addView(tvLabel)
        box.addView(tvBody)
        return box
    }

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density + 0.5f).toInt()
}
