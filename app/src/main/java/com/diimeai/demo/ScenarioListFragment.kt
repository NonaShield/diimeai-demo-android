package com.diimeai.demo

import android.graphics.Color
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.diimeai.demo.network.DiimeApiClient
import com.diimeai.demo.network.ScenarioResult
import com.google.android.material.button.MaterialButton
import com.payshield.sdk.PayShieldEdgeInitializer
import com.payshield.sdk.state.SignalStateManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ScenarioListFragment : Fragment() {

    companion object {
        private const val ARG_TAB = "tab_index"

        fun newInstance(tabIndex: Int): ScenarioListFragment =
            ScenarioListFragment().apply {
                arguments = Bundle().apply { putInt(ARG_TAB, tabIndex) }
            }

        // Metadata for all 17 scenarios
        data class ScenarioMeta(
            val id:          Int,
            val emoji:       String,
            val name:        String,
            val signal:      String,
            val description: String,
            val riskScore:   Int,
            val decision:    String,
            val action:      String,
        )

        val ALL_SCENARIOS: Map<Int, ScenarioMeta> = mapOf(
            1  to ScenarioMeta(1,  "🔐", "Hardware Possession",
                "DEVICE_ATTESTATION",
                "Play Integrity hardware attestation — proves the enrolled physical device",
                5, "ALLOW", "SESSION_CREATE"),

            2  to ScenarioMeta(2,  "📜", "Non-Repudiation Receipt",
                "EVIDENCE_CHAIN_VERIFY",
                "Full audit chain — device key signs transaction, evidence stored in S3",
                5, "ALLOW", "SESSION_CREATE"),

            3  to ScenarioMeta(3,  "📺", "Screen Mirroring Attack",
                "SCREEN_MIRROR_DETECTED",
                "Unauthorized screen capture / sharing while app is in foreground",
                87, "BLOCK", "PAYMENT"),

            4  to ScenarioMeta(4,  "🧠", "Behavioral Biometrics",
                "BIOMETRIC_ANOMALY",
                "Typing rhythm, swipe pressure, touch size — anomaly against enrolled baseline",
                55, "STEP_UP", "PAYMENT"),

            5  to ScenarioMeta(5,  "🛡", "Device RASP (38 sensors)",
                "RASP_THREAT_DETECTED",
                "Root/jailbreak, hook frameworks (Frida/Xposed), debugger, emulator, Magisk",
                100, "BLOCK", "PAYMENT"),

            6  to ScenarioMeta(6,  "🕸", "Mule Account Network",
                "MULE_ACCOUNT_SIGNAL",
                "Graph-based detection — recipient account part of known mule network",
                82, "BLOCK", "PAYMENT"),

            7  to ScenarioMeta(7,  "🤖", "Bot Attack / Emulator",
                "BOT_EMULATOR_DETECTED",
                "Google Play Integrity CTS failure, emulator fingerprint, automated touch injection",
                98, "BLOCK", "LOGIN"),

            8  to ScenarioMeta(8,  "📱", "SIM Swap Fraud",
                "SIM_SWAP_SIGNAL",
                "SIM operator/IMSI change detected since last session; triggers step-up auth",
                95, "BLOCK", "OTP"),

            9  to ScenarioMeta(9,  "🚔", "Digital Arrest Scam",
                "DIGITAL_ARREST_SIGNAL",
                "Victim coerced by fake authority — active video call + prolonged session",
                100, "BLOCK", "PAYMENT"),

            10 to ScenarioMeta(10, "💰", "Fake Loan App Extortion",
                "PREDATORY_LOAN_SIGNAL",
                "Accessibility abuse by predatory app — SMS/contacts/call-log permissions cluster",
                68, "STEP_UP", "KYC"),

            11 to ScenarioMeta(11, "📡", "Ghost Tapping / NFC Abuse",
                "NFC_FRAUD_SIGNAL",
                "Relay attack via NFC proxy — transaction origin doesn't match physical location",
                83, "BLOCK", "PAYMENT"),

            12 to ScenarioMeta(12, "☣", "Malicious APK Injection",
                "MALICIOUS_APK_SIGNAL",
                "Repackaged/side-loaded APK, certificate mismatch, overlay abuse",
                100, "BLOCK", "PAYMENT"),

            13 to ScenarioMeta(13, "🎭", "Deepfake KYC Bypass",
                "DEEPFAKE_KYC_SIGNAL",
                "AI-generated face during KYC — virtual camera, OBS package, frame-rate anomaly",
                96, "BLOCK", "KYC"),

            14 to ScenarioMeta(14, "🏦", "NBFC Insider Burst",
                "INSIDER_BURST_SIGNAL",
                "High-velocity approval burst by a single operator — insider threat pattern",
                78, "BLOCK", "PAYMENT"),

            15 to ScenarioMeta(15, "💔", "Investment / Romance Scam",
                "INVESTMENT_SCAM_SIGNAL",
                "Social engineering pattern — victim initiating large transfer to unknown account",
                72, "STEP_UP", "PAYMENT"),

            16 to ScenarioMeta(16, "🦹", "Organized Crime Ring",
                "ORG_CRIME_RING_SIGNAL",
                "Cross-account graph cluster — coordinated fraud ring detected via Neo4j",
                90, "BLOCK", "PAYMENT"),

            17 to ScenarioMeta(17, "⚡", "ATL-2027 Autonomous Trust",
                "ATL_AUTONOMOUS_SIGNAL",
                "Composite Decision Token — all 5 trust layers scored simultaneously",
                0, "ALLOW", "SESSION_CREATE"),

            18 to ScenarioMeta(18, "🔍", "Device Fingerprinting / ATO",
                "DEVICE_FINGERPRINT_RISK",
                "Composite risk: emulator HW, new-device ATO, outdated OS (API 26), VPN — " +
                "Attestation enforced in STAGING/PRODUCTION (Play Integrity + iOS App Attest)",
                88, "BLOCK", "LOGIN"),

            19 to ScenarioMeta(19, "💸", "Real-time Payment Risk Scoring",
                "PAYMENT_RISK_SIGNAL",
                "₹5L UPI to new beneficiary + geo-velocity 609 km/h (Mumbai→Delhi) + " +
                "device trust 42 + 8 payments/7d — SDK calls evaluateAtCheckpoint(PAYMENT) " +
                "automatically; no risk logic in customer app. RBI: 4h hold on first high-value UPI.",
                72, "STEP_UP", "PAYMENT"),
        )

        // Tab → scenario IDs mapping.
        // Tab 0 (Device / Runtime Integrity) is rendered separately as a live 3-column
        // sensor table — see buildLiveSensorTable() — not the simulated cards below.
        val TAB_SCENARIOS: List<List<Int>> = listOf(
            emptyList(),                   // 0: Device / Runtime Integrity (RASP) — live table, see buildLiveSensorTable()
            listOf(8, 13, 15),             // 1: Identity & Account Fraud
            listOf(4, 9, 10),              // 2: Behavioral & Biometric Fraud
            listOf(6, 11, 14, 16, 19),     // 3: Network / Transaction Fraud
            listOf(1, 2, 17),              // 4: Platform Verification
        )
    }

    // Safety-net poll interval — covers silent TTL expiry only (a transient signal aging
    // out without an explicit clear() call). The push listener below handles every actual
    // fire/clear transition instantly; this loop just catches the rare case where a TTL
    // lapses with no corresponding OS callback. 30s is far below user-perceptible staleness
    // for that edge case while eliminating the previous 1s busy-poll entirely.
    private var safetyNetJob: Job? = null
    private val sensorStatusViews = mutableMapOf<Int, TextView>()
    private val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())

    /**
     * Pushed by the SDK the instant any RASP signal fires or clears — see
     * PayShieldEdgeInitializer.addSignalStateListener(). Runs on whatever thread the
     * triggering signal evaluation happened on, so UI work is marshalled to main.
     */
    private val raspStateListener = SignalStateManager.SignalStateListener { _, _ ->
        mainHandler.post { refreshLiveStatuses() }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View = inflater.inflate(R.layout.fragment_scenario_list, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val tabIndex = arguments?.getInt(ARG_TAB) ?: 0
        val container = view.findViewById<LinearLayout>(R.id.scenarioContainer)
        if (tabIndex == 0) {
            buildLiveSensorTable(container)
            PayShieldEdgeInitializer.addSignalStateListener(raspStateListener)
            startSafetyNetLoop()
        } else {
            buildCards(tabIndex, container)
        }
    }

    override fun onResume() {
        super.onResume()
        if ((arguments?.getInt(ARG_TAB) ?: 0) == 0) {
            refreshLiveStatuses()  // catch anything that changed while paused
            if (safetyNetJob?.isActive != true) startSafetyNetLoop()
        }
    }

    override fun onPause() {
        super.onPause()
        safetyNetJob?.cancel()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        safetyNetJob?.cancel()
        PayShieldEdgeInitializer.removeSignalStateListener(raspStateListener)
        sensorStatusViews.clear()
    }

    // ── Tab 0: live 3-column RASP sensor table (real data, no simulation, no cards) ──

    private fun buildLiveSensorTable(container: LinearLayout) {
        sensorStatusViews.clear()
        val ctx = requireContext()

        // Header row
        val header = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(Color.parseColor("#0D1117"))
            setPadding(12, 10, 12, 10)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }
        fun headerCell(text: String, weight: Float) = TextView(ctx).apply {
            this.text = text
            textSize = 10.5f
            setTextColor(Color.parseColor("#666666"))
            typeface = android.graphics.Typeface.DEFAULT_BOLD
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, weight)
        }
        header.addView(headerCell("RASP SENSOR", 2.2f))
        header.addView(headerCell("SEVERITY", 1f))
        header.addView(headerCell("STATUS", 1f))
        container.addView(header)

        RaspSensorRegistry.ALL.forEachIndexed { index, sensor ->
            val row = LinearLayout(ctx).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = android.view.Gravity.CENTER_VERTICAL
                setPadding(12, 12, 12, 12)
                setBackgroundColor(
                    if (index % 2 == 0) Color.parseColor("#0D1117") else Color.parseColor("#0A0A1A")
                )
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }

            val nameCol = LinearLayout(ctx).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 2.2f)
            }
            nameCol.addView(TextView(ctx).apply {
                text = sensor.name
                textSize = 12f
                setTextColor(Color.parseColor("#FFFFFF"))
            })
            nameCol.addView(TextView(ctx).apply {
                text = sensor.threatId
                textSize = 9f
                setTextColor(Color.parseColor("#555555"))
                typeface = android.graphics.Typeface.MONOSPACE
            })

            val severityView = TextView(ctx).apply {
                text = sensor.severity.label
                textSize = 10.5f
                setTextColor(Color.parseColor(sensor.severity.colorHex))
                typeface = android.graphics.Typeface.DEFAULT_BOLD
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }

            val statusView = TextView(ctx).apply {
                textSize = 10.5f
                typeface = android.graphics.Typeface.DEFAULT_BOLD
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }
            sensorStatusViews[index] = statusView

            row.addView(nameCol)
            row.addView(severityView)
            row.addView(statusView)
            container.addView(row)
        }

        refreshLiveStatuses()
    }

    private fun startSafetyNetLoop() {
        safetyNetJob = lifecycleScope.launch {
            while (isActive) {
                delay(30_000L)
                refreshLiveStatuses()
            }
        }
    }

    private fun refreshLiveStatuses() {
        RaspSensorRegistry.ALL.forEachIndexed { index, sensor ->
            val view = sensorStatusViews[index] ?: return@forEachIndexed
            val active = sensor.signalTypes.any { PayShieldEdgeInitializer.isSignalActive(it) }
            if (active) {
                view.text = "● ACTIVE"
                view.setTextColor(Color.parseColor("#FF3333"))
            } else {
                view.text = "● Inactive"
                view.setTextColor(Color.parseColor("#00CC55"))
            }
        }
    }

    // ── Tabs 1-4: simulated attack cards (backend ingest demo) ───────────────────

    private fun buildCards(tabIndex: Int, container: LinearLayout) {
        val inflater = LayoutInflater.from(requireContext())
        val scenarioIds = TAB_SCENARIOS.getOrElse(tabIndex) { emptyList() }

        // Tab 4 (Platform Verification): add Live Payment card at the top
        if (tabIndex == 4) {
            val payCard = inflater.inflate(R.layout.item_scenario_card, container, false)
            payCard.findViewById<TextView>(R.id.tvScenarioEmoji).text = "💳"
            payCard.findViewById<TextView>(R.id.tvScenarioName).text = "Live Payment Test"
            payCard.findViewById<TextView>(R.id.tvSignalType).text = "PAYMENT_INITIATED"
            payCard.findViewById<TextView>(R.id.tvScenarioDesc).text =
                "Real end-to-end payment with 5-phase CDT scoring, behavioral telemetry, and evidence receipt"
            payCard.findViewById<TextView>(R.id.tvRiskScore).text = "—"
            payCard.findViewById<TextView>(R.id.tvActionContext).text = "PAYMENT"
            val decisionView = payCard.findViewById<TextView>(R.id.tvDecisionBadge)
            decisionView.text = "LIVE"
            decisionView.setBackgroundColor(0xFF0088FF.toInt())
            payCard.findViewById<MaterialButton>(R.id.btnSimulate).apply {
                text = "💳  Open Payment Screen"
                setOnClickListener {
                    startActivity(
                        android.content.Intent(requireContext(), PaymentActivity::class.java)
                            .putExtra("USER_ID", "demo_investor")
                    )
                }
            }
            container.addView(payCard)
        }

        for (id in scenarioIds) {
            val meta = ALL_SCENARIOS[id] ?: continue
            val cardView = inflater.inflate(R.layout.item_scenario_card, container, false)

            cardView.findViewById<TextView>(R.id.tvScenarioEmoji).text = meta.emoji
            cardView.findViewById<TextView>(R.id.tvScenarioName).text = meta.name
            cardView.findViewById<TextView>(R.id.tvSignalType).text = meta.signal
            cardView.findViewById<TextView>(R.id.tvScenarioDesc).text = meta.description
            cardView.findViewById<TextView>(R.id.tvRiskScore).apply {
                text = if (meta.riskScore == 0) "—" else meta.riskScore.toString()
                setTextColor(decisionColor(meta.decision))
            }
            cardView.findViewById<TextView>(R.id.tvActionContext).text = meta.action

            val decisionBadge = cardView.findViewById<TextView>(R.id.tvDecisionBadge)
            decisionBadge.text = meta.decision
            decisionBadge.setBackgroundColor(decisionColor(meta.decision))

            val btn = cardView.findViewById<MaterialButton>(R.id.btnSimulate)
            btn.setOnClickListener { runScenario(id, meta, btn) }

            container.addView(cardView)
        }
    }

    private fun runScenario(id: Int, meta: ScenarioMeta, btn: MaterialButton) {
        btn.isEnabled = false
        btn.text = "⏳  Running…"

        lifecycleScope.launch(Dispatchers.IO) {
            val result = runCatching { DiimeApiClient.ingestScenario(id) }.getOrNull()
            withContext(Dispatchers.Main) {
                btn.isEnabled = true
                btn.text = "⚡  Simulate Attack"
                if (result != null) showResultDialog(meta, result)
                else showErrorDialog(meta.name)
            }
        }
    }

    private fun showResultDialog(meta: ScenarioMeta, r: ScenarioResult) {
        val sim = if (r.fromSimulation) " (simulated)" else ""
        val msg = buildString {
            append("━━━━━━━━━━━━━━━━━━━━━━━━\n")
            append("${meta.emoji}  ${meta.name}\n")
            append("━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
            append("Decision:\n  ${r.decision}$sim\n\n")
            append("Trust Level:\n  ${r.trustLevel}\n\n")
            append("Risk Score:\n  ${r.riskScore} / 100\n\n")
            append("Composite Score:\n  ${r.compositeScore}\n\n")
            if (r.eipTotalMs > 0) append("Backend EIP:\n  ${r.eipTotalMs} ms\n\n")
            if (r.nginxMs > 0) append("NGINX Edge:\n  ${r.nginxMs} ms\n\n")
            append("RTT:\n  ${r.rttMs} ms\n\n")
            if (r.modulesHit.isNotEmpty()) {
                append("Modules Hit:\n  ${r.modulesHit.joinToString(", ")}\n\n")
            }
            if (r.evidenceHash.isNotBlank()) {
                append("Evidence Hash:\n  ${r.evidenceHash.take(32)}…\n\n")
            }
            append("Signal:\n  ${meta.signal}\n")
            append("Action Context:\n  ${meta.action}")
        }

        AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle("Scenario Result")
            .setMessage(msg)
            .setPositiveButton("OK", null)
            .show()
    }

    private fun showErrorDialog(name: String) {
        AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle("Error")
            .setMessage("Failed to run scenario: $name\n\nCheck network connection or enrollment status.")
            .setPositiveButton("OK", null)
            .show()
    }

    private fun decisionColor(decision: String): Int = when (decision) {
        "BLOCK"   -> 0xFFFF4444.toInt()
        "STEP_UP" -> 0xFFFF8800.toInt()
        "ALLOW"   -> 0xFF00AA44.toInt()
        else      -> 0xFF888888.toInt()
    }
}
