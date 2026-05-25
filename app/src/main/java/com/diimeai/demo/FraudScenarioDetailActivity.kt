package com.diimeai.demo

import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import com.diimeai.demo.network.DiimeApiClient
import kotlin.random.Random

/**
 * FraudScenarioDetailActivity
 *
 * Per-scenario view that:
 *  1. Shows the attack description + SDK signals involved
 *  2. "TRIGGER ATTACK SIMULATION" animates through the 5-phase backend pipeline
 *     (NGINX edge → Crypto Gate → Compliance → ML Engine → Threat Executor)
 *  3. Shows the final decision (BLOCK / STEP_UP / ALLOW) with risk score and latency
 *  4. Renders a monospace pipeline log for high-tech audience
 *
 * Works fully offline — simulation fallback mirrors the real backend response shape.
 */
class FraudScenarioDetailActivity : AppCompatActivity() {

    private val handler  = Handler(Looper.getMainLooper())
    private val logLines = StringBuilder()

    // ── View refs ──────────────────────────────────────────────────────────────
    private lateinit var tvDetailTitle:       TextView
    private lateinit var tvDetailSeverityBadge: TextView
    private lateinit var tvDetailEmoji:       TextView
    private lateinit var tvDetailDescription: TextView
    private lateinit var tvDetailUseCaseNum:  TextView
    private lateinit var tvDetailModule:      TextView
    private lateinit var tvDetailRbiRule:     TextView
    private lateinit var llSignalRows:        LinearLayout
    private lateinit var cardDecisionResult:  CardView
    private lateinit var cardLog:             CardView
    private lateinit var tvDecisionVerdict:   TextView
    private lateinit var tvDecisionReason:    TextView
    private lateinit var tvDecisionScore:     TextView
    private lateinit var tvDecisionModulesHit:TextView
    private lateinit var tvDecisionLatency:   TextView
    private lateinit var tvDecisionEvidenceHash: TextView
    private lateinit var tvPipelineLatency:   TextView
    private lateinit var tvPipelineLog:       TextView
    private lateinit var btnTriggerAttack:    com.google.android.material.button.MaterialButton
    private lateinit var btnResetDemo:        com.google.android.material.button.MaterialButton

    // Phase UI
    private lateinit var dotPhase1: View; private lateinit var tvPhase1Status: TextView
    private lateinit var dotPhase2: View; private lateinit var tvPhase2Status: TextView
    private lateinit var dotPhase3: View; private lateinit var tvPhase3Status: TextView
    private lateinit var dotPhase4: View; private lateinit var tvPhase4Status: TextView
    private lateinit var dotPhase5: View; private lateinit var tvPhase5Status: TextView

    // ── Scenario signals config ────────────────────────────────────────────────
    data class SignalDef(val threatId: String, val name: String, val confidence: Float, val severity: String)

    private val scenarioSignals: Map<Int, List<SignalDef>> = mapOf(
        1  to listOf(SignalDef("APP_SEC_001", "DeviceKeyManager / TEE attestation", 0.99f, "HIGH")),
        2  to listOf(SignalDef("APP_SEC_002", "HybridEvidenceSigner / chain", 0.99f, "HIGH")),
        3  to listOf(
            SignalDef("RASP_DEV_003", "ScreenMirroringSignal / DisplayManager", 0.92f, "HIGH"),
            SignalDef("RASP_DEV_004", "RemoteDesktopSignal / VNC projection", 0.85f, "HIGH")),
        4  to listOf(
            SignalDef("USR_BEH_001", "BehavioralMonitor / hesitation_spike", 0.78f, "MEDIUM"),
            SignalDef("USR_BEH_001", "BehavioralMonitor / pressure_anomaly", 0.71f, "MEDIUM")),
        5  to listOf(
            SignalDef("RASP_DEV_001", "RootCloakingSignal / Magisk", 0.95f, "CRITICAL"),
            SignalDef("APP_RUNTIME_008", "FreeRaspSensorAdapter / hook_detected", 1.00f, "CRITICAL"),
            SignalDef("RASP_DEV_002", "AdbInstallSignal", 0.80f, "HIGH")),
        6  to listOf(
            SignalDef("USR_BEH_002", "AccountDegreeSignal / degree=7", 0.88f, "HIGH"),
            SignalDef("USR_BEH_003", "ApplicationVelocitySignal / 4 in 24h", 0.76f, "HIGH")),
        7  to listOf(
            SignalDef("BOT_APP_001", "EmulatorSignal / build_fingerprint", 0.97f, "CRITICAL"),
            SignalDef("BOT_APP_002", "EmulatorSignal / sensor_absence", 0.91f, "CRITICAL")),
        8  to listOf(
            SignalDef("SCAM_SS_001", "SimSwapSignal / SIM_STATE_ABSENT", 1.00f, "CRITICAL"),
            SignalDef("SCAM_SS_002", "SimSwapSignal / ICCID_changed", 0.96f, "HIGH")),
        9  to listOf(
            SignalDef("SCAM_CM_001", "CallMergeSignal / VoIP+cellular", 0.98f, "CRITICAL"),
            SignalDef("SCAM_CM_002", "ConcurrentVideoCallSignal", 0.85f, "HIGH")),
        10 to listOf(
            SignalDef("LOAN_APP_002", "PredatoryLoanAppSignal / SMS+CONTACTS+CALL_LOG", 0.90f, "HIGH"),
            SignalDef("LOAN_APP_001", "PredatoryLoanAppSignal / SMS+CONTACTS", 0.75f, "HIGH")),
        11 to listOf(
            SignalDef("NFC_FRAUD_001", "NfcPaymentAbuseSignal / rogue_HCE", 0.80f, "HIGH"),
            SignalDef("NFC_FRAUD_002", "NfcPaymentAbuseSignal / no_screen_lock", 0.85f, "HIGH")),
        12 to listOf(
            SignalDef("MAL_APK_001", "MaliciousApkSignal / sig_mismatch", 0.95f, "CRITICAL"),
            SignalDef("MAL_APK_002", "MaliciousApkSignal / perm_cluster", 0.88f, "CRITICAL"),
            SignalDef("MAL_APK_003", "MaliciousApkSignal / overlay_abuse", 0.92f, "CRITICAL")),
        13 to listOf(
            SignalDef("APP_RUNTIME_008", "VirtualCameraSignal / OBS_detected", 0.94f, "CRITICAL"),
            SignalDef("APP_RUNTIME_008", "VirtualCameraSignal / non_physical_cam_id", 0.87f, "CRITICAL")),
        14 to listOf(
            SignalDef("USR_BEH_003", "ApplicationVelocitySignal / 5 in 60s", 0.93f, "HIGH"),
            SignalDef("USR_BEH_002", "AccountDegreeSignal / off_hours", 0.80f, "HIGH")),
        15 to listOf(
            SignalDef("SCAM_RS_001", "RomanceSocialAppSignal / 3 dating_apps", 0.60f, "MEDIUM"),
            SignalDef("SCAM_RS_001", "InvestmentFraudDetector / foreign_tx", 0.72f, "MEDIUM")),
        16 to listOf(
            SignalDef("BOT_APP_011", "OrganizedCrimeCluster / shared_ip_ring", 0.91f, "CRITICAL"),
            SignalDef("BOT_APP_011", "OrganizedCrimeCluster / timing_rhythm", 0.86f, "CRITICAL")),
    )

    // Expected final decisions per scenario
    private val scenarioDecisions: Map<Int, Triple<String, Int, String>> = mapOf(
        1  to Triple("ALLOW",     12, "Hardware binding valid — session trusted"),
        2  to Triple("ALLOW",     8,  "Evidence chain intact — non-repudiation proven"),
        3  to Triple("BLOCK",     87, "Screen mirroring active — session terminated"),
        4  to Triple("STEP_UP",   62, "Behavioral anomaly — biometric re-auth required"),
        5  to Triple("BLOCK",     100,"Critical RASP violation — process terminated"),
        6  to Triple("BLOCK",     82, "Mule node detected — device blocked"),
        7  to Triple("BLOCK",     98, "Emulator / bot detected — session rejected"),
        8  to Triple("BLOCK",     95, "SIM swap confirmed — account frozen"),
        9  to Triple("BLOCK",     100,"Digital arrest pattern — payment blocked immediately"),
        10 to Triple("STEP_UP",   74, "Predatory loan app detected — step-up auth"),
        11 to Triple("BLOCK",     83, "Rogue HCE app — NFC payment blocked"),
        12 to Triple("BLOCK",     100,"Malicious APK — session terminated immediately"),
        13 to Triple("BLOCK",     96, "Deepfake / virtual camera — KYC rejected"),
        14 to Triple("BLOCK",     88, "Insider enrollment burst — device quarantined"),
        15 to Triple("STEP_UP",   55, "Investment scam pattern — step-up and alert"),
        16 to Triple("BLOCK",     94, "Organized crime ring — cluster match in Redis"),
    )

    // ──────────────────────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_fraud_scenario_detail)

        bindViews()

        val scenarioId = intent.getIntExtra("scenario_id", 1)
        populateScenario(scenarioId)

        btnTriggerAttack.setOnClickListener { runSimulation(scenarioId) }
        btnResetDemo.setOnClickListener    { resetDemo() }
        findViewById<View>(R.id.btnDetailBack).setOnClickListener { finish() }
    }

    private fun bindViews() {
        tvDetailTitle          = findViewById(R.id.tvDetailTitle)
        tvDetailSeverityBadge  = findViewById(R.id.tvDetailSeverityBadge)
        tvDetailEmoji          = findViewById(R.id.tvDetailEmoji)
        tvDetailDescription    = findViewById(R.id.tvDetailDescription)
        tvDetailUseCaseNum     = findViewById(R.id.tvDetailUseCaseNum)
        tvDetailModule         = findViewById(R.id.tvDetailModule)
        tvDetailRbiRule        = findViewById(R.id.tvDetailRbiRule)
        llSignalRows           = findViewById(R.id.llSignalRows)
        cardDecisionResult     = findViewById(R.id.cardDecisionResult)
        cardLog                = findViewById(R.id.cardLog)
        tvDecisionVerdict      = findViewById(R.id.tvDecisionVerdict)
        tvDecisionReason       = findViewById(R.id.tvDecisionReason)
        tvDecisionScore        = findViewById(R.id.tvDecisionScore)
        tvDecisionModulesHit   = findViewById(R.id.tvDecisionModulesHit)
        tvDecisionLatency      = findViewById(R.id.tvDecisionLatency)
        tvDecisionEvidenceHash = findViewById(R.id.tvDecisionEvidenceHash)
        tvPipelineLatency      = findViewById(R.id.tvPipelineLatency)
        tvPipelineLog          = findViewById(R.id.tvPipelineLog)
        btnTriggerAttack       = findViewById(R.id.btnTriggerAttack)
        btnResetDemo           = findViewById(R.id.btnResetDemo)
        dotPhase1 = findViewById(R.id.dotPhase1); tvPhase1Status = findViewById(R.id.tvPhase1Status)
        dotPhase2 = findViewById(R.id.dotPhase2); tvPhase2Status = findViewById(R.id.tvPhase2Status)
        dotPhase3 = findViewById(R.id.dotPhase3); tvPhase3Status = findViewById(R.id.tvPhase3Status)
        dotPhase4 = findViewById(R.id.dotPhase4); tvPhase4Status = findViewById(R.id.tvPhase4Status)
        dotPhase5 = findViewById(R.id.dotPhase5); tvPhase5Status = findViewById(R.id.tvPhase5Status)
    }

    private fun populateScenario(id: Int) {
        val title       = intent.getStringExtra("title")       ?: "Scenario"
        val emoji       = intent.getStringExtra("emoji")       ?: "🔐"
        val severity    = intent.getStringExtra("severity")    ?: "HIGH"
        val description = intent.getStringExtra("description") ?: ""
        val module      = intent.getStringExtra("backend_mod") ?: ""
        val rbiRule     = intent.getStringExtra("rbi_rule")    ?: ""

        val severityColor = severityColor(severity)
        tvDetailTitle.text    = "$emoji  $title"
        tvDetailSeverityBadge.text = severity
        tvDetailSeverityBadge.setBackgroundColor(severityColor)
        tvDetailEmoji.text    = emoji
        tvDetailDescription.text = description
        tvDetailUseCaseNum.text  = "%02d".format(id)
        tvDetailModule.text   = module
        tvDetailRbiRule.text  = rbiRule

        // Build signal rows
        val signals = scenarioSignals[id] ?: emptyList()
        llSignalRows.removeAllViews()
        signals.forEach { sig -> llSignalRows.addView(buildSignalRow(sig, false)) }
    }

    private fun buildSignalRow(sig: SignalDef, fired: Boolean): LinearLayout {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity     = android.view.Gravity.CENTER_VERTICAL
            setPadding(0, dpToPx(4), 0, dpToPx(4))
        }
        val dotColor = if (fired) severityColor(sig.severity) else Color.parseColor("#333333")
        val dot = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(dpToPx(8), dpToPx(8))
                .also { lp -> lp.marginEnd = dpToPx(8) }
            setBackgroundColor(dotColor)
        }
        val nameTv = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            text     = sig.name
            textSize = 10f
            setTextColor(if (fired) Color.WHITE else Color.parseColor("#555555"))
            typeface = android.graphics.Typeface.MONOSPACE
        }
        val confTv = TextView(this).apply {
            text     = "%.0f%%".format(sig.confidence * 100)
            textSize = 10f
            setTextColor(if (fired) severityColor(sig.severity) else Color.parseColor("#333333"))
            typeface = android.graphics.Typeface.MONOSPACE
        }
        row.addView(dot)
        row.addView(nameTv)
        row.addView(confTv)
        return row
    }

    // ── Simulation ─────────────────────────────────────────────────────────────

    private fun runSimulation(scenarioId: Int) {
        btnTriggerAttack.isEnabled = false
        btnTriggerAttack.text      = "⏳  Running pipeline…"
        logLines.clear()
        cardLog.visibility = View.VISIBLE

        val startMs = System.currentTimeMillis()

        // Animate signal rows firing
        val signals = scenarioSignals[scenarioId] ?: emptyList()
        llSignalRows.removeAllViews()
        signals.forEach { sig ->
            llSignalRows.addView(buildSignalRow(sig, true))
            appendLog("SDK  EMIT  ${sig.threatId}  conf=${sig.confidence}  sev=${sig.severity}")
        }

        // Phase 1 — NGINX (300ms delay)
        animatePhase(300, dotPhase1, tvPhase1Status, "PASS", Color.parseColor("#00FF88")) {
            appendLog("NGINX  HMAC_VERIFY=OK  rate_limit=OK  edge_risk=${Random.nextInt(10, 40)}")
        }

        // Phase 2 — Crypto Gate (600ms)
        animatePhase(650, dotPhase2, tvPhase2Status, "VERIFIED", Color.parseColor("#00FF88")) {
            appendLog("CRYPTO  hybrid_sig=OK  chain_hash=sha256:${randomHex(16)}…  nonce=OK")
        }

        // Phase 3 — Compliance (900ms)
        animatePhase(1000, dotPhase3, tvPhase3Status, "MATCHED", Color.parseColor("#FFAA00")) {
            val rbiRule = intent.getStringExtra("rbi_rule") ?: "UC-0$scenarioId"
            appendLog("COMPLIANCE  rule=$rbiRule  regulation=RBI_Master_Dir  hash=v2.3.1")
        }

        // Phase 4 — ML Engine (1300ms)
        val (verdict, score, _) = scenarioDecisions[scenarioId] ?: Triple("BLOCK", 90, "")
        val mlScore = if (score > 80) (score * 0.95).toInt() else score
        animatePhase(1400, dotPhase4, tvPhase4Status, "%.2f".format(mlScore / 100.0),
            if (mlScore > 80) Color.parseColor("#DD2222") else Color.parseColor("#FFAA00")) {
            appendLog("ML_ENGINE  score=${mlScore / 100.0}  fallback=false  model=v2.1.0")
        }

        // Phase 5 — Threat Executor + final decision (1800ms)
        animatePhase(1850, dotPhase5, tvPhase5Status, "FLAGGED",
            if (verdict == "BLOCK") Color.parseColor("#DD2222") else Color.parseColor("#FFAA00")) {
            val module = intent.getStringExtra("backend_mod") ?: "threat_executor"
            appendLog("THREAT_EXECUTOR  module=$module  modules_run=7  threats=${if (verdict == "ALLOW") 0 else 1}")
        }

        // Show final decision at 2200ms
        handler.postDelayed({
            showDecision(scenarioId, startMs)
        }, 2200)
    }

    private fun animatePhase(
        delayMs: Long,
        dot: View,
        statusTv: TextView,
        statusText: String,
        statusColor: Int,
        onComplete: () -> Unit,
    ) {
        // Pulse in-progress
        handler.postDelayed({
            dot.setBackgroundColor(Color.parseColor("#FFAA00"))
            statusTv.text      = "RUNNING…"
            statusTv.setTextColor(Color.parseColor("#FFAA00"))
        }, delayMs - 150)

        handler.postDelayed({
            dot.setBackgroundColor(statusColor)
            statusTv.text      = statusText
            statusTv.setTextColor(statusColor)
            onComplete()
            tvPipelineLog.text = logLines.toString()
        }, delayMs)
    }

    private fun showDecision(scenarioId: Int, startMs: Long) {
        val (verdict, score, reason) = scenarioDecisions[scenarioId]
            ?: Triple("BLOCK", 90, "Threat detected")
        val latencyMs = System.currentTimeMillis() - startMs

        val verdictColor = when (verdict) {
            "BLOCK"   -> Color.parseColor("#DD2222")
            "STEP_UP" -> Color.parseColor("#FFAA00")
            else      -> Color.parseColor("#00FF88")
        }
        val signals = scenarioSignals[scenarioId] ?: emptyList()

        cardDecisionResult.visibility  = View.VISIBLE
        tvDecisionVerdict.text         = verdict
        tvDecisionVerdict.setTextColor(verdictColor)
        tvDecisionReason.text          = reason
        tvDecisionScore.text           = "$score"
        tvDecisionScore.setTextColor(verdictColor)
        tvDecisionModulesHit.text      = "${if (verdict == "ALLOW") 0 else minOf(signals.size, 3)}/7"
        tvDecisionLatency.text         = "${latencyMs}ms"
        tvDecisionEvidenceHash.text    = "sha256:${randomHex(32)}"
        tvPipelineLatency.text         = "${latencyMs}ms"

        appendLog("DECISION  verdict=$verdict  score=$score  reason=\"$reason\"")
        appendLog("EVIDENCE  hash=${tvDecisionEvidenceHash.text}")
        tvPipelineLog.text = logLines.toString()

        btnTriggerAttack.visibility = View.GONE
        btnResetDemo.visibility     = View.VISIBLE
    }

    private fun resetDemo() {
        // Reset all phase dots
        listOf(dotPhase1, dotPhase2, dotPhase3, dotPhase4, dotPhase5)
            .forEach { it.setBackgroundColor(Color.parseColor("#333333")) }
        listOf(tvPhase1Status, tvPhase2Status, tvPhase3Status, tvPhase4Status, tvPhase5Status)
            .forEach { it.text = "WAITING"; it.setTextColor(Color.parseColor("#444444")) }

        cardDecisionResult.visibility = View.GONE
        cardLog.visibility            = View.GONE
        logLines.clear()

        // Re-render signals in un-fired state
        val id = intent.getIntExtra("scenario_id", 1)
        val signals = scenarioSignals[id] ?: emptyList()
        llSignalRows.removeAllViews()
        signals.forEach { sig -> llSignalRows.addView(buildSignalRow(sig, false)) }

        btnTriggerAttack.isEnabled = true
        btnTriggerAttack.text      = "▶  TRIGGER ATTACK SIMULATION"
        btnTriggerAttack.visibility = View.VISIBLE
        btnResetDemo.visibility     = View.GONE
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private fun appendLog(line: String) {
        val ts = java.text.SimpleDateFormat("HH:mm:ss.SSS", java.util.Locale.US)
            .format(java.util.Date())
        logLines.append("[$ts] $line\n")
    }

    private fun randomHex(len: Int): String {
        val chars = "0123456789abcdef"
        return (1..len).map { chars.random() }.joinToString("")
    }

    private fun severityColor(severity: String): Int = when (severity) {
        "CRITICAL" -> Color.parseColor("#DD2222")
        "HIGH"     -> Color.parseColor("#FF6600")
        else       -> Color.parseColor("#FFAA00")
    }

    private fun dpToPx(dp: Int): Int =
        (dp * resources.displayMetrics.density).toInt()

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacksAndMessages(null)
    }
}
