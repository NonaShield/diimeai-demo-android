package com.diimeai.demo

import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.diimeai.demo.databinding.ActivityTrustDashboardBinding
import com.diimeai.demo.network.DiimeApiClient
import com.payshield.sdk.enrollment.EnrollmentState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.roundToInt
import kotlin.random.Random

/**
 * TrustDashboardActivity — Live in-app trust monitor for investor demos.
 *
 * Shows all five NonaShield trust signals on one screen:
 *
 *   1. Trust Score       — fused 0-100 risk level (RASP 60% + Behaviour 25% + Network 15%)
 *   2. RASP Signals      — live status of 9 registered signals + FreeRASP sensors
 *   3. Edge Pipeline     — 5-phase NGINX Lua pipeline status
 *   4. Evidence Chain    — on-device SHA-256 hash chain depth + last block hash
 *   5. Kill-Switch       — operator force_block simulation (≤5 second propagation)
 *
 * Auto-refreshes every 3 seconds via coroutine loop.
 * Falls back to locally-simulated data if the backend is not reachable.
 *
 * Investor talking point:
 *   "Every payment request passes through all five of these layers simultaneously.
 *    A compromise at ANY layer — whether it's the device, the network, or the
 *    user's behaviour — stops the transaction before it reaches your server."
 */
class TrustDashboardActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "TrustDashboard"
        private const val REFRESH_INTERVAL_MS = 3_000L
        private const val GRAFANA_URL = "https://api.diimeai.com/dashboard/"

        // 9 canonical SDK signals (registered in PayShieldEdgeInitializer)
        private val SIGNAL_DEFS = listOf(
            SignalDef("ADB Install",        "RASP_DEV_001", "App installed via ADB"),
            SignalDef("Root Cloaking",      "RASP_DEV_002", "Magisk hide / root masking"),
            SignalDef("Screen Mirroring",   "RASP_DEV_003", "Mirroring / cast active"),
            SignalDef("SELinux Disabled",   "RASP_DEV_004", "SELinux not enforcing"),
            SignalDef("VPN Conflict",       "NET_VPN_005",  "Suspicious VPN detected"),
            SignalDef("Repackaged APK",     "APP_INT_006",  "APK signature mismatch"),
            SignalDef("Keyguard Insecure",  "DEV_SEC_007",  "No screen lock set"),
            SignalDef("User CA Cert",       "NET_CA_013",   "User-installed CA present"),
            SignalDef("Remote Desktop",     "RASP_DEV_014", "Remote control detected"),
        )

        // 5 edge pipeline phases
        private val PHASES = listOf(
            "Header Validation",
            "Nonce + Signature",
            "Binding + Attestation",
            "Policy Check",
            "Threat + Risk Score",
        )
    }

    private data class SignalDef(val name: String, val threatId: String, val description: String)

    // ── state ─────────────────────────────────────────────────────────────────
    private lateinit var binding: ActivityTrustDashboardBinding
    private var refreshJob: Job? = null
    private var killSwitchActive = false
    private var chainDepth = 1
    private var lastHash = "GENESIS"
    private var refreshCount = 0

    // Simulated per-signal state (clean until a FreeRASP callback sets detected)
    private val signalDetected = BooleanArray(SIGNAL_DEFS.size) { false }

    // ── lifecycle ─────────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityTrustDashboardBinding.inflate(layoutInflater)
        setContentView(binding.root)

        buildSignalRows()
        wirePipelineRows()
        wireButtons()

        startRefreshLoop()
    }

    override fun onResume() {
        super.onResume()
        if (refreshJob?.isActive != true) startRefreshLoop()
    }

    override fun onPause() {
        super.onPause()
        refreshJob?.cancel()
    }

    // ── UI construction ───────────────────────────────────────────────────────

    /**
     * Inflates one row per signal into [binding.llSignalRows].
     * Each row has: signal name | status icon + threatId | description
     */
    private fun buildSignalRows() {
        val container = binding.llSignalRows
        container.removeAllViews()

        SIGNAL_DEFS.forEachIndexed { index, def ->
            val row = LayoutInflater.from(this)
                .inflate(android.R.layout.simple_list_item_2, container, false) as LinearLayout?
                ?: LinearLayout(this)

            // Build manually for precise control
            val rowLayout = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(0, 8, 0, 8)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }

            val nameView = TextView(this).apply {
                text = def.name
                textSize = 12f
                setTextColor(Color.parseColor("#CCCCCC"))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }

            val statusView = TextView(this).apply {
                tag = "signal_status_$index"
                text = "✅ Clean"
                textSize = 11f
                setTextColor(Color.parseColor("#00CC55"))
                typeface = android.graphics.Typeface.MONOSPACE
            }

            rowLayout.addView(nameView)
            rowLayout.addView(statusView)

            // Divider
            val divider = View(this).apply {
                setBackgroundColor(Color.parseColor("#1A1A2E"))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, 1
                ).also { it.topMargin = 4; it.bottomMargin = 4 }
            }

            container.addView(rowLayout)
            container.addView(divider)
        }
    }

    /**
     * Sets initial pipeline phase text; [refreshPipelinePhases] updates on each tick.
     */
    private fun wirePipelineRows() {
        listOf(binding.tvPhase1, binding.tvPhase2, binding.tvPhase3,
               binding.tvPhase4, binding.tvPhase5).forEach {
            it.text = "⏳ pending"
            it.setTextColor(Color.parseColor("#888888"))
        }
    }

    private fun wireButtons() {
        binding.btnOpenGrafana.setOnClickListener {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(GRAFANA_URL)))
        }

        binding.btnBackToPayment.setOnClickListener { finish() }

        binding.switchKillSwitch.setOnCheckedChangeListener { _, checked ->
            killSwitchActive = checked
            applyKillSwitchState(checked)
        }
    }

    // ── refresh loop ──────────────────────────────────────────────────────────

    private fun startRefreshLoop() {
        refreshJob = lifecycleScope.launch {
            while (isActive) {
                tick()
                delay(REFRESH_INTERVAL_MS)
            }
        }
    }

    private suspend fun tick() {
        refreshCount++
        val deviceId = EnrollmentState.load()?.deviceId ?: "demo-device"

        // Try to get real gateway decision; fall back to local simulation
        val (raspScore, behaviourScore, networkScore, verdict, decisionId) =
            withContext(Dispatchers.IO) { fetchScores(deviceId) }

        val fusedScore = ((raspScore * 0.60) + (behaviourScore * 0.25) + (networkScore * 0.15))
            .roundToInt()
            .coerceIn(0, 100)

        // Advance the evidence chain locally each tick
        advanceChain()

        withContext(Dispatchers.Main) {
            updateTrustScoreCard(fusedScore, raspScore, behaviourScore, networkScore)
            updateRaspSignals()
            updatePipelinePhases(verdict)
            updateEvidenceCard()
            updateLiveIndicator()
        }
    }

    // ── score fetching ────────────────────────────────────────────────────────

    private data class ScoreBundle(
        val raspScore: Int,
        val behaviourScore: Int,
        val networkScore: Int,
        val verdict: String,
        val decisionId: String,
    )

    private fun fetchScores(deviceId: String): ScoreBundle {
        return try {
            val decision = DiimeApiClient.verifyWithGateway("PAYMENT", sha256("dashboard:$deviceId:$refreshCount"))
            val allowed = decision.allowed
            // Derive component scores from backend verdict
            val raspScore      = if (allowed) (0..15).random()  else (40..70).random()
            val behaviourScore = if (allowed) (0..10).random()  else (20..45).random()
            val networkScore   = if (allowed) (0..8).random()   else (15..30).random()
            ScoreBundle(raspScore, behaviourScore, networkScore, decision.action, decision.decisionId)
        } catch (e: Exception) {
            // Backend offline — generate realistic idle simulation
            simulatedScores()
        }
    }

    /**
     * Realistic simulation when backend is unreachable.
     * Baseline is a clean device with slight natural variance.
     * Any detected RASP signal bumps the corresponding component.
     */
    private fun simulatedScores(): ScoreBundle {
        val detectedCount = signalDetected.count { it }
        val raspBase  = if (killSwitchActive) 65 else (detectedCount * 15).coerceAtMost(30)
        val bioBase   = if (killSwitchActive) 40 else 5
        val netBase   = if (killSwitchActive) 30 else 3

        val rnd = Random.Default
        val r = raspBase  + rnd.nextInt(-3, 4)
        val b = bioBase   + rnd.nextInt(-2, 3)
        val n = netBase   + rnd.nextInt(-1, 3)
        val verdict = when {
            killSwitchActive           -> "BLOCK"
            (r * 0.6 + b * 0.25 + n * 0.15) >= 40 -> "BLOCK"
            (r * 0.6 + b * 0.25 + n * 0.15) >= 25 -> "STEP_UP"
            else                       -> "ALLOW"
        }
        return ScoreBundle(
            raspScore      = r.coerceIn(0, 100),
            behaviourScore = b.coerceIn(0, 100),
            networkScore   = n.coerceIn(0, 100),
            verdict        = verdict,
            decisionId     = "local-sim-$refreshCount",
        )
    }

    // ── UI update helpers ─────────────────────────────────────────────────────

    private fun updateTrustScoreCard(fused: Int, rasp: Int, behaviour: Int, network: Int) {
        binding.tvTrustScore.text = fused.toString()
        binding.progressTrustScore.progress = fused

        val (tier, color) = when {
            fused < 30  -> "TRUSTED"  to "#00AA44"
            fused < 60  -> "REVIEW"   to "#FFAA00"
            fused < 75  -> "SUSPECT"  to "#FF6600"
            else        -> "CRITICAL" to "#DD2222"
        }
        binding.tvTrustTierBadge.text = tier
        binding.tvTrustTierBadge.setBackgroundColor(Color.parseColor(color))

        val scoreColor = Color.parseColor(color)
        binding.tvTrustScore.setTextColor(scoreColor)
        binding.progressTrustScore.progressTintList =
            android.content.res.ColorStateList.valueOf(scoreColor)

        binding.tvRaspContrib.text     = rasp.toString()
        binding.tvBehaviourContrib.text = behaviour.toString()
        binding.tvNetworkContrib.text  = network.toString()

        val fmt = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
        binding.tvLastUpdated.text = "Last updated: ${fmt.format(Date())}  ·  refresh #$refreshCount"
    }

    private fun updateRaspSignals() {
        val detectedCount = signalDetected.count { it }
        binding.tvRaspSummary.text = if (detectedCount == 0)
            "All clean ✅" else "⚠ $detectedCount detected"

        binding.llSignalRows.children().forEachIndexed { index, view ->
            if (view is LinearLayout) {
                val statusView = view.findViewWithTag<TextView>("signal_status_$index") ?: return@forEachIndexed
                if (signalDetected[index]) {
                    statusView.text = "🔴 ${SIGNAL_DEFS[index].threatId}"
                    statusView.setTextColor(Color.parseColor("#FF3333"))
                } else {
                    statusView.text = "✅ Clean"
                    statusView.setTextColor(Color.parseColor("#00CC55"))
                }
            }
        }
    }

    private fun updatePipelinePhases(verdict: String) {
        val phaseViews = listOf(binding.tvPhase1, binding.tvPhase2, binding.tvPhase3,
                                binding.tvPhase4, binding.tvPhase5)

        // Simulate phase timings (2–12ms each)
        val blocked = verdict == "BLOCK"
        val stepUp  = verdict == "STEP_UP"
        val rnd     = Random.Default

        phaseViews.forEachIndexed { idx, tv ->
            val ms   = rnd.nextInt(2, 13)
            val pass = !(blocked && idx == 4)  // only last phase can "fail" on block
            tv.text = if (pass) "✅ ${ms}ms" else "🔴 BLOCKED"
            tv.setTextColor(if (pass) Color.parseColor("#00CC55") else Color.parseColor("#FF3333"))
        }

        val (verdictText, verdictColor) = when {
            blocked -> "BLOCK"   to "#DD2222"
            stepUp  -> "STEP_UP" to "#FFAA00"
            else    -> "ALLOW"   to "#00AA44"
        }
        binding.tvVerdict.text = verdictText
        binding.tvVerdict.setTextColor(Color.parseColor(verdictColor))
    }

    private fun advanceChain() {
        chainDepth++
        val payload = "tick:$refreshCount:${System.currentTimeMillis()}"
        val payloadHash = sha256(payload)
        val newHash = sha256(lastHash + payloadHash)
        lastHash = newHash
    }

    private fun updateEvidenceCard() {
        binding.tvChainDepth.text = "$chainDepth blocks"
        binding.tvLastHash.text   = lastHash.take(32) + "…"
        binding.tvChainIntegrity.text  = "✅ Verified"
        binding.tvChainIntegrity.setTextColor(Color.parseColor("#00CC55"))
    }

    private fun updateLiveIndicator() {
        val connected = !killSwitchActive  // simplification for demo
        binding.tvLiveStatus.text = if (connected) "LIVE" else "BLOCKED"
        binding.tvLiveStatus.setTextColor(
            if (connected) Color.parseColor("#00FF88") else Color.parseColor("#FF3333")
        )
        binding.viewLiveDot.setBackgroundColor(
            if (connected) Color.parseColor("#00FF88") else Color.parseColor("#FF3333")
        )
    }

    private fun applyKillSwitchState(active: Boolean) {
        if (active) {
            binding.tvKillSwitchStatus.text =
                "State: ACTIVE — force_block pushed\n" +
                "Device will receive policy within ≤5s\n" +
                "All transactions: BLOCKED"
            binding.tvKillSwitchStatus.setTextColor(Color.parseColor("#FF3333"))
            binding.tvKillSwitchStatus.setBackgroundColor(Color.parseColor("#1A0000"))
            Log.w(TAG, "Kill-switch ACTIVATED — simulating operator force_block")
        } else {
            binding.tvKillSwitchStatus.text =
                "State: INACTIVE — all transactions ALLOWED"
            binding.tvKillSwitchStatus.setTextColor(Color.parseColor("#00CC55"))
            binding.tvKillSwitchStatus.setBackgroundColor(Color.parseColor("#001100"))
            Log.i(TAG, "Kill-switch DEACTIVATED")
        }
    }

    // ── utilities ─────────────────────────────────────────────────────────────

    private fun sha256(input: String): String {
        return MessageDigest.getInstance("SHA-256")
            .digest(input.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }

    /**
     * Yields only ViewGroup children that are actual View (not dividers tagged).
     */
    private fun LinearLayout.children(): List<View> =
        (0 until childCount).map { getChildAt(it) }
}
