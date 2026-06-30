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
        // Tab 0 (Device / Runtime Integrity) is rendered separately via RASP_LIVE_GROUPS —
        // it shows real on-device sensor status, not the simulated cards below.
        val TAB_SCENARIOS: List<List<Int>> = listOf(
            emptyList(),                   // 0: Device / Runtime Integrity (RASP) — live cards, see buildLiveRaspCards()
            listOf(8, 13, 15),             // 1: Identity & Account Fraud
            listOf(4, 9, 10),              // 2: Behavioral & Biometric Fraud
            listOf(6, 11, 14, 16, 19),     // 3: Network / Transaction Fraud
            listOf(1, 2, 17),              // 4: Platform Verification
        )

        /**
         * Live (non-simulated) RASP sensor groups shown on Tab 0.
         * Status is read directly from [PayShieldEdgeInitializer.isSignalActive] — same
         * source of truth as [RaspSensorTableActivity]. Each group's `signalTypes` is a
         * subset of [RaspSensorRegistry.ALL] grouped by fraud-scenario concept for the
         * investor/CISO narrative.
         */
        data class RaspLiveGroup(
            val emoji:       String,
            val name:        String,
            val description: String,
            val signalTypes: List<String>,
            val sensorCount: Int,
            val opensTable:  Boolean = false,
        )

        val RASP_LIVE_GROUPS: List<RaspLiveGroup> = listOf(
            RaspLiveGroup(
                "🛡", "Device RASP — All Sensors",
                "Composite status across every registered RASP sensor on this device — root, hooking, tamper, emulator, and more",
                RaspSensorRegistry.ALL.flatMap { it.signalTypes },
                RaspSensorRegistry.ALL.size,
                opensTable = true,
            ),
            RaspLiveGroup(
                "📺", "Screen Mirroring / Recording",
                "Unauthorized screen capture, casting, or companion-app sharing while the app is in foreground",
                listOf("SCREEN_MIRRORING", "SCREEN_RECORDING_ACTIVE", "COMPANION_SCREEN_SHARE_ACTIVE"),
                3,
            ),
            RaspLiveGroup(
                "🤖", "Bot Attack / Emulator",
                "Emulator fingerprint, automated touch injection, scripted enrollment bursts",
                listOf("EMULATOR_FINGERPRINT", "ENROLLMENT_BURST", "AUTO_CLICKER_DETECTED"),
                3,
            ),
            RaspLiveGroup(
                "☣", "Malicious APK Injection",
                "Repackaged or sideloaded APK, certificate mismatch, malicious app cloning",
                listOf("APP_REPACKAGED", "SIDELOAD_DETECTED", "APP_CLONE_MALICIOUS", "APP_CLONE_DETECTED"),
                3,
            ),
            RaspLiveGroup(
                "🔍", "Device Fingerprint / ATO",
                "Device anchor mismatch and hardware attestation failure — new-device account takeover risk",
                listOf("DEVICE_ANCHOR_MISMATCH", "ATTESTATION_NO_CHAIN", "ATTESTATION_UNTRUSTED"),
                2,
            ),
        )
    }

    private var liveRefreshJob: Job? = null
    private val liveStatusBadges = mutableMapOf<Int, TextView>()

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
            buildLiveRaspCards(container)
            startLiveRefreshLoop()
        } else {
            buildCards(tabIndex, container)
        }
    }

    override fun onResume() {
        super.onResume()
        if ((arguments?.getInt(ARG_TAB) ?: 0) == 0 && liveRefreshJob?.isActive != true) {
            startLiveRefreshLoop()
        }
    }

    override fun onPause() {
        super.onPause()
        liveRefreshJob?.cancel()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        liveRefreshJob?.cancel()
        liveStatusBadges.clear()
    }

    // ── Tab 0: live RASP sensor cards (real data, no simulation) ────────────────

    private fun buildLiveRaspCards(container: LinearLayout) {
        val inflater = LayoutInflater.from(requireContext())
        liveStatusBadges.clear()

        RASP_LIVE_GROUPS.forEachIndexed { index, group ->
            val card = inflater.inflate(R.layout.item_rasp_live_card, container, false)

            card.findViewById<TextView>(R.id.tvLiveEmoji).text = group.emoji
            card.findViewById<TextView>(R.id.tvLiveName).text = group.name
            card.findViewById<TextView>(R.id.tvLiveDesc).text = group.description
            card.findViewById<TextView>(R.id.tvLiveSensorCount).text =
                "${group.sensorCount} sensor${if (group.sensorCount == 1) "" else "s"} · live, on-device"
            card.findViewById<TextView>(R.id.tvLiveViewDetail).text =
                if (group.opensTable) "View All Sensors →" else "View in Sensor Table →"

            val badge = card.findViewById<TextView>(R.id.tvLiveStatusBadge)
            liveStatusBadges[index] = badge

            card.setOnClickListener {
                startActivity(android.content.Intent(requireContext(), RaspSensorTableActivity::class.java))
            }

            container.addView(card)
        }

        refreshLiveStatuses()
    }

    private fun startLiveRefreshLoop() {
        liveRefreshJob = lifecycleScope.launch {
            while (isActive) {
                refreshLiveStatuses()
                delay(1_000L)
            }
        }
    }

    private fun refreshLiveStatuses() {
        RASP_LIVE_GROUPS.forEachIndexed { index, group ->
            val badge = liveStatusBadges[index] ?: return@forEachIndexed
            val active = group.signalTypes.any { PayShieldEdgeInitializer.isSignalActive(it) }
            if (active) {
                badge.text = "ACTIVE"
                badge.setBackgroundColor(Color.parseColor("#FF3333"))
            } else {
                badge.text = "CLEAN"
                badge.setBackgroundColor(Color.parseColor("#00CC55"))
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
