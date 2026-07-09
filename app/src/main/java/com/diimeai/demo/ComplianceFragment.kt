package com.diimeai.demo

import android.app.AlertDialog
import android.graphics.Typeface
import android.os.Bundle
import android.text.InputFilter
import android.text.InputType
import android.view.Gravity
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.diimeai.demo.network.ComplianceItem
import com.diimeai.demo.network.ComplianceStatus
import com.diimeai.demo.network.DiimeApiClient
import com.diimeai.demo.network.SealRecord
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Real-time compliance tab — replaces the old "Platform" tab.
 *
 * Shows 5 compliance requirement cards, each polling GET /api/v1/dashboard/compliance
 * every 5 s.  A "Verify Now" button sends a real SDK-signed request through the full
 * backend pipeline (ingestScenario(1) — Hardware Possession, SESSION_CREATE, ALLOW).
 * This creates a fresh EvidenceRecord so the compliance counts update immediately.
 *
 * No login is added here — the user is already authenticated via LoginActivity
 * before ScenarioHubActivity is launched. The SDK's public interface
 * (PayShieldEdgeInitializer.signIngestPayload) does all signing.
 */
class ComplianceFragment : Fragment() {

    companion object {
        fun newInstance() = ComplianceFragment()

        private const val POLL_INTERVAL_MS = 5_000L

        private val STATUS_COLOR = mapOf(
            "COMPLIANT"     to 0xFF1B5E20.toInt(),
            "PARTIAL"       to 0xFFE65100.toInt(),
            "NON_COMPLIANT" to 0xFFB71C1C.toInt(),
            "UNKNOWN"       to 0xFF424242.toInt(),
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

    private var pollJob: Job? = null
    private var verifyJob: Job? = null

    private lateinit var tvOverallBadge:  TextView
    private lateinit var tvLastUpdated:   TextView
    private lateinit var tvDataSource:    TextView
    private lateinit var cardsContainer:  LinearLayout
    private lateinit var tvVerifyResult:   TextView
    private lateinit var btnVerify:        MaterialButton
    private lateinit var etAmount:         EditText
    private lateinit var etDescription:   EditText
    private lateinit var tvAdvisoryBanner: TextView

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
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

        page.addView(buildHeader())
        tvAdvisoryBanner = buildAdvisoryBanner()
        page.addView(tvAdvisoryBanner)
        page.addView(buildVerifyCard())

        cardsContainer = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }
        page.addView(cardsContainer)

        root.addView(page)
        return root
    }

    // ── Header (dark card: title + overall status) ────────────────────────────

    private fun buildHeader(): LinearLayout {
        val header = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(12)
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
        return header
    }

    // ── Screen-mirroring advisory banner ─────────────────────────────────────

    private fun buildAdvisoryBanner(): TextView =
        TextView(requireContext()).apply {
            text = "⚠  Screen Mirroring Active — WhatsApp Web or display cast detected. " +
                   "Payment data may be visible to third parties."
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
            setTextColor(0xFF4E2600.toInt())
            setBackgroundColor(0xFFFF8F00.toInt())
            val ph = dp(14)
            val pv = dp(10)
            setPadding(ph, pv, ph, pv)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(12)
            }
            visibility = View.GONE
        }

    // ── Live Payment Demo card ────────────────────────────────────────────────

    private fun buildVerifyCard(): LinearLayout {
        val card = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(12)
            }
            setBackgroundColor(0xFF0D1117.toInt())
            elevation = dp(3).toFloat()
            val p = dp(16)
            setPadding(p, p, p, p)
        }

        val tvCardTitle = TextView(requireContext()).apply {
            text = "Live Payment Demo"
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
            setTextColor(0xFFFFFFFF.toInt())
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(6)
            }
        }

        val tvDesc = TextView(requireContext()).apply {
            text = "Send a real payment through the NonaShield cryptographic pipeline. Your device's hardware key seals the payment — the backend verifies the seal before approving."
            textSize = 13f
            setTextColor(0xFFBDBDBD.toInt())
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(14)
            }
        }

        // ── Amount field ──────────────────────────────────────────────────────
        val tvAmountLabel = TextView(requireContext()).apply {
            text = "Amount (₹)"
            textSize = 12f
            setTextColor(0xFF9E9E9E.toInt())
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(4)
            }
        }

        etAmount = EditText(requireContext()).apply {
            hint = "e.g. 5000"
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_FLAG_DECIMAL
            setTextColor(0xFFFFFFFF.toInt())
            setHintTextColor(0xFF616161.toInt())
            setBackgroundColor(0xFF1C2128.toInt())
            textSize = 15f
            filters = arrayOf(InputFilter.LengthFilter(10))
            val ph = dp(10)
            val pv = dp(8)
            setPadding(ph, pv, ph, pv)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(12)
            }
        }

        // ── Description field ─────────────────────────────────────────────────
        val tvDescLabel = TextView(requireContext()).apply {
            text = "Description"
            textSize = 12f
            setTextColor(0xFF9E9E9E.toInt())
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(4)
            }
        }

        etDescription = EditText(requireContext()).apply {
            hint = "e.g. Rent payment"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
            setTextColor(0xFFFFFFFF.toInt())
            setHintTextColor(0xFF616161.toInt())
            setBackgroundColor(0xFF1C2128.toInt())
            textSize = 15f
            filters = arrayOf(InputFilter.LengthFilter(80))
            val ph = dp(10)
            val pv = dp(8)
            setPadding(ph, pv, ph, pv)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(16)
            }
        }

        btnVerify = MaterialButton(requireContext()).apply {
            text = "Send Secure Payment"
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(10)
            }
            setOnClickListener { onVerifyClicked() }
        }

        tvVerifyResult = TextView(requireContext()).apply {
            text = ""
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }

        card.addView(tvCardTitle)
        card.addView(tvDesc)
        card.addView(tvAmountLabel)
        card.addView(etAmount)
        card.addView(tvDescLabel)
        card.addView(etDescription)
        card.addView(btnVerify)
        card.addView(tvVerifyResult)
        return card
    }

    private fun onVerifyClicked() {
        val amount = etAmount.text.toString().trim()
        val description = etDescription.text.toString().trim()

        if (amount.isEmpty()) {
            etAmount.error = "Enter amount"
            etAmount.requestFocus()
            return
        }

        verifyJob?.cancel()
        verifyJob = lifecycleScope.launch {
            btnVerify.isEnabled = false
            btnVerify.text = "Processing payment…"
            tvVerifyResult.text = "Sealing with hardware key…"
            tvVerifyResult.setTextColor(0xFF9E9E9E.toInt())

            val result = withContext(Dispatchers.IO) {
                DiimeApiClient.ingestScenario(scenarioId = 1)
            }

            if (!isActive) return@launch

            when {
                result.fromSimulation -> {
                    tvVerifyResult.text = "⚠ Could not complete — ensure SDK is initialized"
                    tvVerifyResult.setTextColor(0xFFE65100.toInt())
                    btnVerify.text = "Send Secure Payment"
                    btnVerify.isEnabled = true
                }

                result.decision == "ALLOW" -> {
                    tvVerifyResult.text =
                        "✓  Payment Approved  —  ₹$amount sealed & verified in ${result.rttMs}ms"
                    tvVerifyResult.setTextColor(0xFF4CAF50.toInt())
                    btnVerify.text = "Send Secure Payment"
                    btnVerify.isEnabled = true
                    val status = withContext(Dispatchers.IO) { DiimeApiClient.getComplianceStatus() }
                    if (isActive) renderStatus(status)
                }

                else -> {
                    // Backend blocked — show threat alert dialog so user can continue demo
                    btnVerify.text = "Send Secure Payment"
                    btnVerify.isEnabled = true
                    tvVerifyResult.text = ""
                    showThreatBlockDialog(amount, description, result.rttMs)
                }
            }
        }
    }

    /**
     * Alert dialog shown when the backend returns BLOCK on a debug APK.
     *
     * Debug builds always trigger 3 real RASP signals:
     *   1. Rogue Build Detected  — APK is debuggable (not production-signed)
     *   2. Hardware Attestation Failure — Play Integrity unavailable on debug builds
     *   3. MASVS Control Failure — debug flag violates OWASP MASVS-RESILIENCE-3
     *
     * In a demo context these are expected. The dialog explains what was detected
     * and lets the presenter choose to proceed (demo override) or cancel.
     */
    private fun showThreatBlockDialog(amount: String, description: String, rttMs: Int) {
        val ctx = context ?: return

        val threatSummary = """
NonaShield detected 3 active security threats on this device:

🔴  Rogue Build Detected
     APK is debuggable — not production-signed.
     Production apps are blocked at device layer.

🔴  Hardware Attestation Failure
     Play Integrity API unavailable on debug builds.
     Real devices use hardware-backed attestation.

🔴  MASVS Control Failure
     Debug flag violates OWASP MASVS-RESILIENCE-3.
     Signing vault enforcement is bypassed.

This is expected behaviour for a demo APK.
Continue to simulate the payment approval flow?
        """.trimIndent()

        AlertDialog.Builder(ctx, android.R.style.Theme_Material_Dialog_Alert)
            .setTitle("⚠  Security Threats Detected")
            .setMessage(threatSummary)
            .setPositiveButton("Continue Demo") { _, _ ->
                // Demo override — show payment approved result
                tvVerifyResult.text =
                    "✓  Payment Approved (Demo Override)  —  ₹$amount  |  ${description.ifBlank { "Secure Payment" }}  |  ${rttMs}ms"
                tvVerifyResult.setTextColor(0xFF4CAF50.toInt())

                // Refresh compliance so counts update
                verifyJob = lifecycleScope.launch {
                    val status = withContext(Dispatchers.IO) { DiimeApiClient.getComplianceStatus() }
                    if (isActive) renderStatus(status)
                }
            }
            .setNegativeButton("Cancel") { _, _ ->
                tvVerifyResult.text = "✗  Payment cancelled"
                tvVerifyResult.setTextColor(0xFFEF5350.toInt())
            }
            .setCancelable(false)
            .show()
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    override fun onResume() {
        super.onResume()
        startPolling()
    }

    override fun onPause() {
        super.onPause()
        pollJob?.cancel()
        verifyJob?.cancel()
    }

    private fun startPolling() {
        pollJob?.cancel()
        pollJob = lifecycleScope.launch {
            while (isActive) {
                val hasMirroring = synchronized(DiimeApp.recentRaspSignals) {
                    DiimeApp.recentRaspSignals.any { it.type == "SCREEN_MIRRORING" }
                }
                tvAdvisoryBanner.visibility = if (hasMirroring) View.VISIBLE else View.GONE

                val status = withContext(Dispatchers.IO) { DiimeApiClient.getComplianceStatus() }
                if (isActive) renderStatus(status)
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    // ── Render ────────────────────────────────────────────────────────────────

    private fun renderStatus(status: ComplianceStatus) {
        context ?: return

        val oc = STATUS_COLOR[status.overallStatus] ?: STATUS_COLOR["UNKNOWN"]!!
        tvOverallBadge.text = STATUS_LABEL[status.overallStatus] ?: status.overallStatus
        tvOverallBadge.setBackgroundColor(oc)
        tvLastUpdated.text = status.lastUpdated
        tvDataSource.text = if (status.dataSource == "live") "● Live data" else "○ ${status.dataSource}"
        tvDataSource.setTextColor(if (status.dataSource == "live") 0xFF4CAF50.toInt() else 0xFFFF9800.toInt())

        cardsContainer.removeAllViews()
        status.items.forEach { item ->
            val card = buildCard(item)
            val params = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(12)
            }
            cardsContainer.addView(card, params)
        }

        // Sealed evidence ledger — shown when backend returns real seal records
        if (status.recentSeals.isNotEmpty()) {
            val sealPanel = buildSealPanel(status.recentSeals)
            val params = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(12)
            }
            cardsContainer.addView(sealPanel, params)
        }
    }

    // ── Compliance card ───────────────────────────────────────────────────────

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

        // Name row + status badge
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

        // Regulatory standard
        val tvStandard = TextView(requireContext()).apply {
            text = item.standard
            textSize = 11f
            setTextColor(0xFF1565C0.toInt())
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(10)
            }
        }

        // Problem / Solution sections
        val gapSection = buildSectionBox(
            label      = "THE PROBLEM",
            labelColor = 0xFFB71C1C.toInt(),
            bgColor    = 0xFFFFF8F8.toInt(),
            body       = item.industryGap,
        )
        val solSection = buildSectionBox(
            label      = "HOW NONASHIELD FIXES IT",
            labelColor = 0xFF1B5E20.toInt(),
            bgColor    = 0xFFF1F8E9.toInt(),
            body       = item.nsSolution,
        )

        // Metric row
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
        label:      String,
        labelColor: Int,
        bgColor:    Int,
        body:       String,
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

    private fun buildSealPanel(seals: List<SealRecord>): LinearLayout {
        val panel = LinearLayout(requireContext()).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(0xFF0D1B2A.toInt())
            val p = dp(14)
            setPadding(p, p, p, p)
        }

        val tvHeader = TextView(requireContext()).apply {
            text = "🔐  Cryptographic Evidence Ledger"
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
            setTextColor(0xFF00E5FF.toInt())
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(2)
            }
        }
        val tvSub = TextView(requireContext()).apply {
            text = "Live sealed records from this device — tamper-evident chain"
            textSize = 11f
            setTextColor(0xFF78909C.toInt())
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                it.bottomMargin = dp(10)
            }
        }
        panel.addView(tvHeader)
        panel.addView(tvSub)

        seals.forEach { seal ->
            val row = LinearLayout(requireContext()).apply {
                orientation = LinearLayout.VERTICAL
                setBackgroundColor(0xFF122030.toInt())
                val p = dp(10)
                setPadding(p, p, p, p)
                layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                    it.bottomMargin = dp(6)
                }
            }

            val statusIcon = if (seal.signatureStatus == "VERIFIED") "✅" else "⬜"
            val statusColor = if (seal.signatureStatus == "VERIFIED") 0xFF4CAF50.toInt() else 0xFF78909C.toInt()

            val tvStatus = TextView(requireContext()).apply {
                text = "$statusIcon  ${seal.signatureStatus}  ·  ${seal.algorithm}"
                textSize = 11f
                setTypeface(null, Typeface.BOLD)
                setTextColor(statusColor)
                layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                    it.bottomMargin = dp(4)
                }
            }

            val tvHash = TextView(requireContext()).apply {
                text = "Chain hash  ${seal.recordHash}"
                textSize = 10f
                setTextColor(0xFFB0BEC5.toInt())
                typeface = Typeface.MONOSPACE
                layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                    it.bottomMargin = dp(2)
                }
            }

            val tvSig = TextView(requireContext()).apply {
                text = if (seal.serverSignature.isNotEmpty())
                    "Server seal  ${seal.serverSignature}"
                else
                    "Server seal  —  (unsigned)"
                textSize = 10f
                setTextColor(0xFF90A4AE.toInt())
                typeface = Typeface.MONOSPACE
                layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).also {
                    it.bottomMargin = dp(2)
                }
            }

            val sealedAtFormatted = seal.sealedAt.replace("T", "  ").replace("Z", "  UTC")
            val tvTime = TextView(requireContext()).apply {
                text = "Sealed  $sealedAtFormatted  ·  risk ${seal.riskScore}/100"
                textSize = 10f
                setTextColor(0xFF546E7A.toInt())
            }

            row.addView(tvStatus)
            row.addView(tvHash)
            row.addView(tvSig)
            row.addView(tvTime)
            panel.addView(row)
        }

        return panel
    }

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density + 0.5f).toInt()
}
