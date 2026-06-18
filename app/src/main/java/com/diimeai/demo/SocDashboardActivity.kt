package com.diimeai.demo

import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.diimeai.demo.network.DecisionRecord
import com.diimeai.demo.network.DashboardStats
import com.diimeai.demo.network.DiimeApiClient
import com.diimeai.demo.network.ThreatEvent
import kotlin.random.Random

/**
 * SocDashboardActivity — Security Operations Centre live dashboard.
 *
 * Uses DiimeApiClient (singleton object) with blocking calls on a background
 * thread, posting results back to the main thread via Handler.
 *
 * Auto-refreshes every 5 seconds.
 */
class SocDashboardActivity : AppCompatActivity() {

    private val handler       = Handler(Looper.getMainLooper())
    private val refreshPeriod = 5_000L

    // Simulation counters that grow between refreshes to look live
    private var simTotal   = Random.nextInt(1200, 1600)
    private var simBlocked = Random.nextInt(40, 90)
    private var simStepUp  = Random.nextInt(80, 160)
    private var simDevices = Random.nextInt(220, 340)

    // ── View refs ──────────────────────────────────────────────────────────────
    private lateinit var tvStatTotal:       TextView
    private lateinit var tvStatAllowed:     TextView
    private lateinit var tvStatStepUp:      TextView
    private lateinit var tvStatBlocked:     TextView
    private lateinit var tvStatAvgRisk:     TextView
    private lateinit var tvStatDevices:     TextView
    private lateinit var tvStatBlockRate:   TextView
    private lateinit var llDecisionRows:    LinearLayout
    private lateinit var llThreatRows:      LinearLayout
    private lateinit var progressRaspCat:   ProgressBar
    private lateinit var tvRaspCatPct:      TextView
    private lateinit var progressNetCat:    ProgressBar
    private lateinit var tvNetCatPct:       TextView
    private lateinit var progressBioCat:    ProgressBar
    private lateinit var tvBioCatPct:       TextView
    private lateinit var progressAppCat:    ProgressBar
    private lateinit var tvAppCatPct:       TextView
    private lateinit var tvDecisionRefresh: TextView

    // ──────────────────────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_soc_dashboard)
        bindViews()

        findViewById<View>(R.id.btnSocBack).setOnClickListener { finish() }
        findViewById<View>(R.id.btnOpenGrafanaSoc).setOnClickListener {
            try {
                startActivity(Intent(Intent.ACTION_VIEW,
                    Uri.parse("https://api.diimeai.com/dashboard/")))
            } catch (_: Exception) { /* offline demo — Grafana not available */ }
        }

        refresh()
    }

    override fun onResume() {
        super.onResume()
        scheduleRefresh()
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacksAndMessages(null)
    }

    // ── Refresh ────────────────────────────────────────────────────────────────

    private fun scheduleRefresh() {
        handler.postDelayed({
            refresh()
            scheduleRefresh()
        }, refreshPeriod)
    }

    private fun refresh() {
        Thread {
            // Blocking calls on background thread
            val stats     = runCatching { DiimeApiClient.getDashboardStats()    }.getOrNull()
            val decisions = runCatching { DiimeApiClient.getRecentDecisions(8)  }.getOrNull()
            val threats   = runCatching { DiimeApiClient.getRecentThreats(8)    }.getOrNull()

            handler.post {
                // Use real stats only when backend confirms live DB data.
                // dataSource="fallback" means the backend was unreachable or returned
                // static placeholder values — fall through to the local incrementing
                // simulation so the dashboard looks live during demos.
                if (stats != null && stats.isLiveData) applyRealStats(stats) else applySimulatedStats()
                renderDecisionFeed(decisions)
                renderThreatLog(threats)
            }
        }.start()
    }

    // ── Stats ──────────────────────────────────────────────────────────────────

    private fun applyRealStats(stats: DashboardStats) {
        val blockRate = if (stats.totalDecisions > 0)
            100.0 * stats.blockedCount / stats.totalDecisions else 0.0
        tvStatTotal.text     = stats.totalDecisions.toString()
        tvStatAllowed.text   = stats.allowedCount.toString()
        tvStatStepUp.text    = stats.stepUpCount.toString()
        tvStatBlocked.text   = stats.blockedCount.toString()
        tvStatAvgRisk.text   = "%.1f%%".format(stats.avgRiskScore * 100)
        tvStatDevices.text   = stats.activeDevices.toString()
        tvStatBlockRate.text = "%.1f%%".format(blockRate)
        setBreakdown(stats.raspPct, stats.networkPct, stats.bioPct, stats.appPct)
    }

    private fun applySimulatedStats() {
        simTotal   += Random.nextInt(1, 5)
        simBlocked += if (Random.nextFloat() < 0.25f) 1 else 0
        simStepUp  += if (Random.nextFloat() < 0.35f) 1 else 0
        val allowed   = simTotal - simBlocked - simStepUp
        val blockRate = 100.0 * simBlocked / simTotal

        tvStatTotal.text     = simTotal.toString()
        tvStatAllowed.text   = allowed.toString()
        tvStatStepUp.text    = simStepUp.toString()
        tvStatBlocked.text   = simBlocked.toString()
        tvStatAvgRisk.text   = "%.1f%%".format(Random.nextFloat() * 35 + 15)
        tvStatDevices.text   = (simDevices + Random.nextInt(-3, 3)).toString()
        tvStatBlockRate.text = "%.1f%%".format(blockRate)
        setBreakdown(38, 22, 18, 22)
    }

    private fun setBreakdown(rasp: Int, net: Int, bio: Int, app: Int) {
        progressRaspCat.progress = rasp; tvRaspCatPct.text = "$rasp%"
        progressNetCat.progress  = net;  tvNetCatPct.text  = "$net%"
        progressBioCat.progress  = bio;  tvBioCatPct.text  = "$bio%"
        progressAppCat.progress  = app;  tvAppCatPct.text  = "$app%"
    }

    // ── Decision feed ──────────────────────────────────────────────────────────

    private fun renderDecisionFeed(decisions: List<DecisionRecord>?) {
        llDecisionRows.removeAllViews()
        val rows = decisions ?: simulateDecisions()
        rows.take(8).forEach { d -> llDecisionRows.addView(buildDecisionRow(d)) }
        val ts = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date())
        tvDecisionRefresh.text = "refreshed $ts"
    }

    private fun simulateDecisions(): List<DecisionRecord> {
        val pool = listOf("BLOCK", "ALLOW", "ALLOW", "STEP_UP", "BLOCK", "ALLOW", "ALLOW", "BLOCK")
        return pool.mapIndexed { idx, dec ->
            val risk = when (dec) {
                "BLOCK"   -> Random.nextInt(75, 100)
                "STEP_UP" -> Random.nextInt(40, 74)
                else      -> Random.nextInt(5, 35)
            }
            DecisionRecord(
                deviceId  = "dev_${randomHex(6)}",
                action    = dec,
                riskScore = risk,
                timestamp = "${idx * 2 + Random.nextInt(0, 2)}m ago",
            )
        }
    }

    private fun buildDecisionRow(d: DecisionRecord): View {
        val decColor = when (d.decision) {
            "BLOCK"   -> Color.parseColor("#DD2222")
            "STEP_UP" -> Color.parseColor("#FFAA00")
            else      -> Color.parseColor("#00AA44")
        }
        val riskColor = when {
            d.riskScore >= 75 -> Color.parseColor("#DD2222")
            d.riskScore >= 40 -> Color.parseColor("#FFAA00")
            else              -> Color.parseColor("#00AA44")
        }
        val container = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity     = android.view.Gravity.CENTER_VERTICAL
            setPadding(0, dpToPx(5), 0, dpToPx(5))
        }
        row.addView(tv(d.deviceId.take(14), 0, 10f, Color.parseColor("#CCCCCC"), mono = true, weight = 2f))
        row.addView(tv("${d.riskScore}", 0, 10f, riskColor, mono = true, weight = 1f))
        row.addView(tv(d.decision, 0, 9f, decColor, mono = true, weight = 1f))
        row.addView(tv(d.timestamp, 0, 9f, Color.parseColor("#555555"), weight = 1f))
        container.addView(row)
        container.addView(divider())
        return container
    }

    // ── Threat log ─────────────────────────────────────────────────────────────

    private fun renderThreatLog(threats: List<ThreatEvent>?) {
        llThreatRows.removeAllViews()
        val rows = threats ?: simulateThreats()
        rows.take(8).forEach { t -> llThreatRows.addView(buildThreatRow(t)) }
    }

    private fun simulateThreats(): List<ThreatEvent> {
        data class T(val id: String, val sev: String, val mod: String)
        val pool = listOf(
            T("SCAM_CM_001",   "CRITICAL", "digital_arrest_detector"),
            T("RASP_DEV_001",  "CRITICAL", "botnet_correlation"),
            T("BOT_APP_001",   "CRITICAL", "botnet_correlation"),
            T("SCAM_SS_001",   "CRITICAL", "sim_swap_proxy"),
            T("MAL_APK_001",   "CRITICAL", "botnet_correlation"),
            T("USR_BEH_002",   "HIGH",     "mule_account"),
            T("NFC_FRAUD_001", "HIGH",     "credential_reuse"),
            T("LOAN_APP_002",  "HIGH",     "beneficiary_abuse"),
            T("SCAM_RS_001",   "MEDIUM",   "investment_fraud_detector"),
            T("BOT_APP_011",   "CRITICAL", "organized_crime_cluster"),
        )
        return pool.shuffled().take(8).mapIndexed { idx, t ->
            ThreatEvent(
                threatId  = t.id,
                severity  = t.sev,
                module    = t.mod,
                deviceId  = "dev_${randomHex(6)}",
                timestamp = "${idx * 3 + Random.nextInt(0, 3)}m ago",
            )
        }
    }

    private fun buildThreatRow(t: ThreatEvent): View {
        val sevColor = when (t.severity) {
            "CRITICAL" -> Color.parseColor("#DD2222")
            "HIGH"     -> Color.parseColor("#FF6600")
            else       -> Color.parseColor("#FFAA00")
        }
        val container = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity     = android.view.Gravity.CENTER_VERTICAL
            setPadding(0, dpToPx(5), 0, dpToPx(5))
        }
        val dot = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(dpToPx(8), dpToPx(8))
                .also { lp -> lp.marginEnd = dpToPx(8) }
            setBackgroundColor(sevColor)
        }
        row.addView(dot)
        row.addView(tv(t.threatId, 0, 10f, Color.parseColor("#CCCCCC"), mono = true, weight = 2f))
        row.addView(tv(t.severity, 0, 9f, sevColor, mono = true, weight = 1.5f))
        row.addView(tv(t.module.ifBlank { t.threatType }, 0, 9f, Color.parseColor("#666666"), mono = true, weight = 2f))
        row.addView(tv(t.timestamp, 0, 9f, Color.parseColor("#444444"), weight = 1f))
        container.addView(row)
        container.addView(divider())
        return container
    }

    // ── Helper builders ────────────────────────────────────────────────────────

    private fun tv(
        text:   String,
        pad:    Int   = 0,
        size:   Float = 12f,
        color:  Int   = Color.WHITE,
        mono:   Boolean = false,
        weight: Float = 0f,
    ): TextView = TextView(this).apply {
        this.text     = text
        this.textSize = size
        setTextColor(color)
        if (mono) typeface = android.graphics.Typeface.MONOSPACE
        if (pad  > 0) setPadding(pad, pad, pad, pad)
        layoutParams = if (weight > 0f)
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, weight)
        else
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT)
    }

    private fun divider(): View = View(this).apply {
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 1)
        setBackgroundColor(Color.parseColor("#111122"))
    }

    private fun bindViews() {
        tvStatTotal       = findViewById(R.id.tvStatTotal)
        tvStatAllowed     = findViewById(R.id.tvStatAllowed)
        tvStatStepUp      = findViewById(R.id.tvStatStepUp)
        tvStatBlocked     = findViewById(R.id.tvStatBlocked)
        tvStatAvgRisk     = findViewById(R.id.tvStatAvgRisk)
        tvStatDevices     = findViewById(R.id.tvStatDevices)
        tvStatBlockRate   = findViewById(R.id.tvStatBlockRate)
        llDecisionRows    = findViewById(R.id.llDecisionRows)
        llThreatRows      = findViewById(R.id.llThreatRows)
        progressRaspCat   = findViewById(R.id.progressRaspCat)
        tvRaspCatPct      = findViewById(R.id.tvRaspCatPct)
        progressNetCat    = findViewById(R.id.progressNetCat)
        tvNetCatPct       = findViewById(R.id.tvNetCatPct)
        progressBioCat    = findViewById(R.id.progressBioCat)
        tvBioCatPct       = findViewById(R.id.tvBioCatPct)
        progressAppCat    = findViewById(R.id.progressAppCat)
        tvAppCatPct       = findViewById(R.id.tvAppCatPct)
        tvDecisionRefresh = findViewById(R.id.tvDecisionRefresh)
    }

    private fun randomHex(len: Int): String {
        val chars = "0123456789abcdef"
        return (1..len).map { chars.random() }.joinToString("")
    }

    private fun dpToPx(dp: Int): Int =
        (dp * resources.displayMetrics.density).toInt()
}
