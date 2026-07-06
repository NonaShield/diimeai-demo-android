package com.diimeai.demo

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.TextUtils
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.diimeai.demo.network.DiimeApiClient
import com.diimeai.demo.network.ScenarioResult
import com.google.android.material.button.MaterialButton
import com.payshield.sdk.BehaviourCategory
import com.payshield.sdk.BehaviourParam
import com.payshield.sdk.BehaviourStatus
import com.payshield.sdk.PayShieldEdgeInitializer
import com.payshield.sdk.state.SignalStateListener
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
        // Tab 0 — live RASP sensor table (buildLiveSensorTable); no simulated cards.
        // Tab 1 — live Identity threat defense table (buildIdentityThreatTable); no simulated cards.
        val TAB_SCENARIOS: List<List<Int>> = listOf(
            emptyList(),                   // 0: Device / Runtime Integrity — live sensor table
            emptyList(),                   // 1: Identity & Account Fraud — live identity table
            emptyList(),                   // 2: Behavioral & Biometric — live 40-param baseline table
            emptyList(),                   // 3: Network / Transaction Fraud — live NGINX threat table
            listOf(1, 2, 17),              // 4: Platform Verification
        )
    }

    // Safety-net poll interval — covers silent TTL expiry only (a transient signal aging
    // out without an explicit clear() call). The push listener below handles every actual
    // fire/clear transition instantly; this loop just catches the rare case where a TTL
    // lapses with no corresponding OS callback. 30s is far below user-perceptible staleness
    // for that edge case while eliminating the previous 1s busy-poll entirely.
    private var safetyNetJob: Job? = null
    private var identitySafetyNetJob: Job? = null
    private var networkSafetyNetJob: Job? = null
    private val sensorStatusViews = mutableMapOf<Int, TextView>()
    // Triple<statusView, riskScoreView, threat> for each identity threat row
    private data class IdentityRowView(
        val statusView: TextView,
        val riskView: TextView,
        val threat: IdentityThreatRegistry.Threat,
    )
    private val identityRowViews = mutableMapOf<Int, IdentityRowView>()
    private data class NetworkRowView(
        val statusView: TextView,
        val riskView: TextView,
        val threat: NetworkThreatRegistry.NetworkThreat,
    )
    private val networkRowViews = mutableMapOf<Int, NetworkRowView>()
    private val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())

    // ── Tab 2: behavioural biometrics live refresh ────────────────────────────
    private var behaviourRefreshJob: Job? = null
    private data class BehaviourRowView(
        val rowLayout: LinearLayout,
        val nameView: TextView,
        val baselineView: TextView,
        val actualView: TextView,
        val statusView: TextView,
    )
    private val behaviourRowViews = mutableListOf<BehaviourRowView>()
    private var behaviourChipMatch: TextView? = null
    private var behaviourChipDrift: TextView? = null
    private var behaviourChipAnomaly: TextView? = null
    private var behaviourBaselineInfo: TextView? = null

    /**
     * Pushed by the SDK the instant any RASP signal fires or clears — see
     * PayShieldEdgeInitializer.addSignalStateListener(). Runs on whatever thread the
     * triggering signal evaluation happened on, so UI work is marshalled to main.
     */
    private val raspStateListener = SignalStateListener { _, _ ->
        mainHandler.post { refreshLiveStatuses() }
    }

    private val identityStateListener = SignalStateListener { _, _ ->
        mainHandler.post { refreshIdentityStatuses() }
    }

    private val networkStateListener = SignalStateListener { _, _ ->
        mainHandler.post { refreshNetworkStatuses() }
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
        when (tabIndex) {
            0 -> {
                buildLiveSensorTable(container)
                PayShieldEdgeInitializer.addSignalStateListener(raspStateListener)
                startSafetyNetLoop()
            }
            1 -> {
                buildIdentityThreatTable(container)
                PayShieldEdgeInitializer.addSignalStateListener(identityStateListener)
                startIdentitySafetyNetLoop()
            }
            2 -> {
                buildBehaviourBiometricsTable(container)
                startBehaviourRefreshLoop()
            }
            3 -> {
                buildNetworkThreatTable(container)
                PayShieldEdgeInitializer.addSignalStateListener(networkStateListener)
                startNetworkSafetyNetLoop()
            }
            else -> buildCards(tabIndex, container)
        }
    }

    override fun onResume() {
        super.onResume()
        when (arguments?.getInt(ARG_TAB) ?: 0) {
            0 -> {
                refreshLiveStatuses()
                if (safetyNetJob?.isActive != true) startSafetyNetLoop()
            }
            1 -> {
                refreshIdentityStatuses()
                if (identitySafetyNetJob?.isActive != true) startIdentitySafetyNetLoop()
            }
            2 -> {
                refreshBehaviourTable()
                if (behaviourRefreshJob?.isActive != true) startBehaviourRefreshLoop()
            }
            3 -> {
                refreshNetworkStatuses()
                if (networkSafetyNetJob?.isActive != true) startNetworkSafetyNetLoop()
            }
        }
    }

    override fun onPause() {
        super.onPause()
        safetyNetJob?.cancel()
        identitySafetyNetJob?.cancel()
        behaviourRefreshJob?.cancel()
        networkSafetyNetJob?.cancel()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        safetyNetJob?.cancel()
        identitySafetyNetJob?.cancel()
        behaviourRefreshJob?.cancel()
        networkSafetyNetJob?.cancel()
        PayShieldEdgeInitializer.removeSignalStateListener(raspStateListener)
        PayShieldEdgeInitializer.removeSignalStateListener(identityStateListener)
        PayShieldEdgeInitializer.removeSignalStateListener(networkStateListener)
        sensorStatusViews.clear()
        identityRowViews.clear()
        networkRowViews.clear()
        behaviourRowViews.clear()
        behaviourChipMatch = null
        behaviourChipDrift = null
        behaviourChipAnomaly = null
        behaviourBaselineInfo = null
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

    // ── Tab 1: live 5-column Identity threat defense table ──────────────────────

    private fun buildIdentityThreatTable(container: LinearLayout) {
        identityRowViews.clear()
        val ctx = requireContext()

        // Protection pillars header banner
        val banner = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#050F1A"))
            setPadding(16, 14, 16, 14)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }
        banner.addView(TextView(ctx).apply {
            text = "NonaShield Identity Defense Layer"
            textSize = 12.5f
            setTextColor(Color.parseColor("#4FC3F7"))
            typeface = Typeface.DEFAULT_BOLD
        })
        banner.addView(TextView(ctx).apply {
            text = "🔑 Hardware-bound public key (AndroidKeyStore TEE)" +
                   "  ·  📋 Signed headers: X-PS-Nonce, X-PS-Timestamp, X-PS-Request-Hash" +
                   "  ·  🔍 Runtime threat signals → X-Edge-Risk-Level at NGINX"
            textSize = 8f
            setTextColor(Color.parseColor("#4A7A8A"))
            setPadding(0, 5, 0, 0)
            maxLines = 3
        })
        container.addView(banner)

        // Thin accent divider
        container.addView(View(ctx).apply {
            setBackgroundColor(Color.parseColor("#0D3355"))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 2)
        })

        // Column header row
        val header = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(Color.parseColor("#040D14"))
            setPadding(10, 10, 10, 10)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }
        fun hCell(text: String, wt: Float, align: Int = android.view.Gravity.START) =
            TextView(ctx).apply {
                this.text = text
                textSize = 9f
                setTextColor(Color.parseColor("#5577AA"))
                typeface = Typeface.DEFAULT_BOLD
                gravity = align
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, wt)
            }
        header.addView(hCell("IDENTITY THREAT  /  NONASHIELD PROTECTION", 3.0f))
        header.addView(hCell("SEV", 0.65f, android.view.Gravity.CENTER))
        header.addView(hCell("STATUS", 0.95f, android.view.Gravity.CENTER))
        header.addView(hCell("RISK", 0.55f, android.view.Gravity.CENTER))
        header.addView(hCell("ACTION", 0.85f, android.view.Gravity.CENTER))
        container.addView(header)

        // Divider under header
        container.addView(View(ctx).apply {
            setBackgroundColor(Color.parseColor("#0D2233"))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 1)
        })

        // Data rows
        IdentityThreatRegistry.ALL.forEachIndexed { index, threat ->
            val row = LinearLayout(ctx).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = android.view.Gravity.CENTER_VERTICAL
                setPadding(10, 14, 10, 14)
                setBackgroundColor(
                    if (index % 2 == 0) Color.parseColor("#060E16") else Color.parseColor("#040A11")
                )
                layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
            }

            // Column 1: threat name + protection subtitle
            val nameCol = LinearLayout(ctx).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 3.0f)
            }
            nameCol.addView(TextView(ctx).apply {
                text = threat.name
                textSize = 11f
                setTextColor(Color.parseColor("#E8E8FF"))
                typeface = Typeface.DEFAULT_BOLD
                maxLines = 2
                ellipsize = TextUtils.TruncateAt.END
            })
            nameCol.addView(TextView(ctx).apply {
                text = threat.protectionLine
                textSize = 8f
                setTextColor(Color.parseColor("#445566"))
                setPadding(0, 3, 0, 0)
                maxLines = 2
                ellipsize = TextUtils.TruncateAt.END
            })
            nameCol.addView(TextView(ctx).apply {
                text = threat.threatId
                textSize = 7.5f
                setTextColor(Color.parseColor("#2A3A4A"))
                typeface = Typeface.MONOSPACE
                setPadding(0, 2, 0, 0)
            })
            row.addView(nameCol)

            // Column 2: severity
            row.addView(TextView(ctx).apply {
                text = threat.severity.label
                textSize = 8.5f
                setTextColor(Color.parseColor(threat.severity.colorHex))
                typeface = Typeface.DEFAULT_BOLD
                gravity = android.view.Gravity.CENTER
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 0.65f)
            })

            // Column 3: status (live, updated by refreshIdentityStatuses)
            val statusView = TextView(ctx).apply {
                text = "● ..."
                textSize = 8.5f
                typeface = Typeface.DEFAULT_BOLD
                gravity = android.view.Gravity.CENTER
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 0.95f)
            }
            row.addView(statusView)

            // Column 4: risk score (shown when active)
            val riskView = TextView(ctx).apply {
                text = "—"
                textSize = 10f
                typeface = Typeface.DEFAULT_BOLD
                gravity = android.view.Gravity.CENTER
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 0.55f)
            }
            row.addView(riskView)

            // Column 5: decision badge
            row.addView(TextView(ctx).apply {
                text = threat.decision.label
                textSize = 8f
                setTextColor(Color.parseColor(threat.decision.colorHex))
                typeface = Typeface.DEFAULT_BOLD
                gravity = android.view.Gravity.CENTER
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 0.85f)
            })

            identityRowViews[index] = IdentityRowView(statusView, riskView, threat)

            // Tap row → show full detail dialog
            row.isClickable = true
            row.isFocusable = true
            row.setOnClickListener { showIdentityThreatDetail(threat) }

            container.addView(row)

            // Row separator
            container.addView(View(ctx).apply {
                setBackgroundColor(Color.parseColor("#090F16"))
                layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 1)
            })
        }

        refreshIdentityStatuses()
    }

    private fun startIdentitySafetyNetLoop() {
        identitySafetyNetJob = lifecycleScope.launch {
            while (isActive) {
                delay(30_000L)
                refreshIdentityStatuses()
            }
        }
    }

    private fun refreshIdentityStatuses() {
        IdentityThreatRegistry.ALL.forEachIndexed { index, threat ->
            val rv = identityRowViews[index] ?: return@forEachIndexed
            val (statusView, riskView) = rv.statusView to rv.riskView
            val activeSignals = threat.signalTypes.filter { PayShieldEdgeInitializer.isSignalActive(it) }
            when {
                threat.architectureProtected -> {
                    // Protection is structural (KeyStore TEE / NGINX gateway headers) —
                    // always active regardless of device signal state.
                    statusView.text = "🛡 Protected"
                    statusView.setTextColor(Color.parseColor("#00AACC"))
                    statusView.isClickable = false
                    statusView.setOnClickListener(null)
                    riskView.text = "0"
                    riskView.setTextColor(Color.parseColor("#00AACC"))
                }
                activeSignals.isNotEmpty() -> {
                    statusView.text = "● ACTIVE ▶"
                    statusView.setTextColor(Color.parseColor("#FF2222"))
                    // Tap ACTIVE label → Agentic AI Root Cause Advisory
                    statusView.isClickable = true
                    statusView.isFocusable = true
                    statusView.setOnClickListener { showAgenticAdvisory(threat, activeSignals) }
                    riskView.text = threat.riskScore.toString()
                    riskView.setTextColor(Color.parseColor("#FF2222"))
                }
                else -> {
                    statusView.text = "● Safe"
                    statusView.setTextColor(Color.parseColor("#00CC55"))
                    statusView.isClickable = false
                    statusView.setOnClickListener(null)
                    riskView.text = "—"
                    riskView.setTextColor(Color.parseColor("#334455"))
                }
            }
        }
    }

    // ── Tab 2: live 40-parameter Behavioural Biometrics baseline vs. actual table ─

    // ── UI-only presentation helpers for BehaviourStatus / BehaviourCategory ──
    // These map SDK enum values to display colors and symbols.
    // They are pure presentation — no security or detection logic.
    private fun BehaviourStatus.colorHex() = when (this) {
        BehaviourStatus.ANOMALY -> "#FF3333"
        BehaviourStatus.DRIFT   -> "#FFAA00"
        else                    -> "#00CC55"
    }
    private fun BehaviourStatus.symbol() = when (this) {
        BehaviourStatus.ANOMALY -> "✗"
        BehaviourStatus.DRIFT   -> "⚠"
        else                    -> "✓"
    }
    private fun BehaviourStatus.displayLabel() = when (this) {
        BehaviourStatus.ANOMALY -> "Anomaly"
        BehaviourStatus.DRIFT   -> "Drift"
        else                    -> "Match"
    }
    private fun BehaviourCategory.colorHex() = when (this) {
        BehaviourCategory.TOUCH     -> "#4FC3F7"
        BehaviourCategory.KEYSTROKE -> "#CE93D8"
        BehaviourCategory.MOTION    -> "#80CBC4"
        BehaviourCategory.SESSION   -> "#FFCC80"
        BehaviourCategory.CONTEXT   -> "#A5D6A7"
    }

    private fun buildBehaviourBiometricsTable(container: LinearLayout) {
        behaviourRowViews.clear()
        val ctx = requireContext()

        // Pull live data from the SDK — no hardcoded baselines or actual values.
        val params       = PayShieldEdgeInitializer.getBehaviourParams()
        val matchCount   = params.count { it.status == BehaviourStatus.MATCH }
        val driftCount   = params.count { it.status == BehaviourStatus.DRIFT }
        val anomalyCount = params.count { it.status == BehaviourStatus.ANOMALY }

        // ── Summary banner ────────────────────────────────────────────────────────
        val banner = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#050F1A"))
            setPadding(16, 14, 16, 14)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }
        banner.addView(TextView(ctx).apply {
            text = "Behavioural Biometrics Profile"
            textSize = 12.5f
            setTextColor(Color.parseColor("#FFCC80"))
            typeface = Typeface.DEFAULT_BOLD
        })
        val tvBaselineInfo = TextView(ctx).apply {
            text = "Calibrating… — use the app normally; baseline locks after 15 minutes"
            textSize = 8f
            setTextColor(Color.parseColor("#6A5530"))
            setPadding(0, 4, 0, 0)
        }
        behaviourBaselineInfo = tvBaselineInfo
        banner.addView(tvBaselineInfo)
        // Match / Drift / Anomaly summary chips
        val chipRow = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 8, 0, 0)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }
        fun chip(text: String, colorHex: String) = TextView(ctx).apply {
            this.text = text
            textSize = 9f
            setTextColor(Color.parseColor(colorHex))
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 20, 0)
        }
        val cMatch   = chip("✓ $matchCount Match",    "#00CC55")
        val cDrift   = chip("⚠ $driftCount Drift",    "#FFAA00")
        val cAnomaly = chip("✗ $anomalyCount Anomaly", "#FF3333")
        behaviourChipMatch   = cMatch
        behaviourChipDrift   = cDrift
        behaviourChipAnomaly = cAnomaly
        chipRow.addView(cMatch)
        chipRow.addView(cDrift)
        chipRow.addView(cAnomaly)
        val behaviourScore = if (params.isEmpty()) 0
            else (params.map { it.deviationScore }.average() * 100).toInt()
        chipRow.addView(chip("→ Risk: $behaviourScore / 100", "#4FC3F7"))
        banner.addView(chipRow)
        container.addView(banner)

        container.addView(View(ctx).apply {
            setBackgroundColor(Color.parseColor("#3A2800"))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 2)
        })

        // ── Column header ─────────────────────────────────────────────────────────
        val header = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(Color.parseColor("#040D14"))
            setPadding(10, 10, 10, 10)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }
        fun hCell(text: String, wt: Float, align: Int = android.view.Gravity.START) =
            TextView(ctx).apply {
                this.text = text
                textSize = 8.5f
                setTextColor(Color.parseColor("#7A6040"))
                typeface = Typeface.DEFAULT_BOLD
                gravity = align
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, wt)
            }
        header.addView(hCell("#", 0.28f, android.view.Gravity.CENTER))
        header.addView(hCell("PARAMETER", 2.1f))
        header.addView(hCell("BASELINE (15 min enrol)", 1.35f, android.view.Gravity.CENTER))
        header.addView(hCell("ACTUAL", 1.1f, android.view.Gravity.CENTER))
        header.addView(hCell("STATUS", 0.8f, android.view.Gravity.CENTER))
        container.addView(header)

        container.addView(View(ctx).apply {
            setBackgroundColor(Color.parseColor("#1A0E00"))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 1)
        })

        // ── Data rows grouped by category — all data from SDK ─────────────────────
        var lastCategory: BehaviourCategory? = null
        var globalIndex = 0

        params.forEach { param ->
            // Category divider row when category changes
            if (param.category != lastCategory) {
                lastCategory = param.category
                container.addView(LinearLayout(ctx).apply {
                    orientation = LinearLayout.HORIZONTAL
                    setBackgroundColor(Color.parseColor("#0A0A0A"))
                    setPadding(10, 6, 10, 6)
                    layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
                    addView(TextView(ctx).apply {
                        text = "▸  ${param.category.label}"
                        textSize = 8f
                        setTextColor(Color.parseColor(param.category.colorHex()))
                        typeface = Typeface.DEFAULT_BOLD
                        alpha = 0.85f
                    })
                })
            }

            globalIndex++
            val rowBg = when (param.status) {
                BehaviourStatus.ANOMALY -> Color.parseColor("#1A0000")
                BehaviourStatus.DRIFT   -> Color.parseColor("#12100A")
                else -> if (globalIndex % 2 == 0) Color.parseColor("#060E16")
                        else Color.parseColor("#040A11")
            }

            val row = LinearLayout(ctx).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = android.view.Gravity.CENTER_VERTICAL
                setPadding(10, 11, 10, 11)
                setBackgroundColor(rowBg)
                layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
            }

            // #
            row.addView(TextView(ctx).apply {
                text = "$globalIndex"
                textSize = 8f
                setTextColor(Color.parseColor("#334455"))
                gravity = android.view.Gravity.CENTER
                typeface = Typeface.MONOSPACE
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 0.28f)
            })

            // Parameter name
            val nameCol = LinearLayout(ctx).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 2.1f)
            }
            val tvName = TextView(ctx).apply {
                text = param.name
                textSize = 10.5f
                setTextColor(
                    if (param.status == BehaviourStatus.ANOMALY)
                        Color.parseColor("#FF6666")
                    else Color.parseColor("#CCDDEE")
                )
            }
            nameCol.addView(tvName)
            row.addView(nameCol)

            // Baseline
            val tvBaseline = TextView(ctx).apply {
                text = param.baseline
                textSize = 9.5f
                setTextColor(Color.parseColor("#557799"))
                gravity = android.view.Gravity.CENTER
                typeface = Typeface.MONOSPACE
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1.35f)
            }
            row.addView(tvBaseline)

            // Actual
            val tvActual = TextView(ctx).apply {
                text = param.actual
                textSize = 9.5f
                setTextColor(Color.parseColor(param.status.colorHex()))
                gravity = android.view.Gravity.CENTER
                typeface = if (param.status != BehaviourStatus.MATCH)
                    Typeface.DEFAULT_BOLD else Typeface.MONOSPACE
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1.1f)
            }
            row.addView(tvActual)

            // Status
            val tvStatus = TextView(ctx).apply {
                text = "${param.status.symbol()} ${param.status.displayLabel()}"
                textSize = 9f
                setTextColor(Color.parseColor(param.status.colorHex()))
                gravity = android.view.Gravity.CENTER
                typeface = Typeface.DEFAULT_BOLD
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 0.8f)
            }
            row.addView(tvStatus)

            behaviourRowViews.add(BehaviourRowView(row, tvName, tvBaseline, tvActual, tvStatus))
            container.addView(row)

            container.addView(View(ctx).apply {
                setBackgroundColor(Color.parseColor("#080E14"))
                layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 1)
            })
        }

        // ── Footer: behaviour score contribution ──────────────────────────────────
        container.addView(View(ctx).apply {
            setBackgroundColor(Color.parseColor("#3A2800"))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 2)
        })
        container.addView(LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#050F1A"))
            setPadding(16, 12, 16, 12)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
            addView(TextView(ctx).apply {
                text = "Behaviour score: $behaviourScore / 100  ·  Contributes 25% to X-Edge-Risk-Level"
                textSize = 8.5f
                setTextColor(Color.parseColor("#FFCC80"))
                typeface = Typeface.DEFAULT_BOLD
            })
            val anomalyNames = params.filter { it.status == BehaviourStatus.ANOMALY }
                .joinToString(" · ") { it.name }
            if (anomalyNames.isNotEmpty()) {
                addView(TextView(ctx).apply {
                    text = "Anomalies flagged: $anomalyNames"
                    textSize = 7.5f
                    setTextColor(Color.parseColor("#AA4444"))
                    setPadding(0, 5, 0, 0)
                })
            }
            addView(TextView(ctx).apply {
                text = "Risk formula: RASP (60%) + Behaviour (25%) + Network (15%) → X-Edge-Risk-Level"
                textSize = 7f
                setTextColor(Color.parseColor("#445566"))
                setPadding(0, 4, 0, 0)
            })
        })
    }

    private fun startBehaviourRefreshLoop() {
        behaviourRefreshJob = lifecycleScope.launch {
            while (isActive) {
                delay(3_000L)
                refreshBehaviourTable()
            }
        }
    }

    private fun refreshBehaviourTable() {
        if (!isAdded || view == null) return
        val params = PayShieldEdgeInitializer.getBehaviourParams()
        if (params.isEmpty()) return

        val pct = PayShieldEdgeInitializer.getBehaviourBaselineProgressPct()
        val matchCount   = params.count { it.status == BehaviourStatus.MATCH }
        val driftCount   = params.count { it.status == BehaviourStatus.DRIFT }
        val anomalyCount = params.count { it.status == BehaviourStatus.ANOMALY }
        val liveCount    = params.count { it.isLive }

        behaviourChipMatch?.text   = "✓ $matchCount Match"
        behaviourChipDrift?.text   = "⚠ $driftCount Drift"
        behaviourChipAnomaly?.text = "✗ $anomalyCount Anomaly"

        val minElapsed = pct * 15 / 100
        behaviourBaselineInfo?.text = if (pct < 100) {
            "Calibrating $pct% ($minElapsed / 15 min)  —  baseline locks at 15 min"
        } else {
            "✓ Baseline locked  ·  $liveCount live sensors active  ·  refreshing every 3 s"
        }

        params.forEachIndexed { i, param ->
            val rv = behaviourRowViews.getOrNull(i) ?: return@forEachIndexed
            rv.baselineView.text = param.baseline
            rv.actualView.text   = param.actual

            val (statusText, colorHex) = when (param.status) {
                BehaviourStatus.ANOMALY -> ("✗ Anomaly" to "#FF3333")
                BehaviourStatus.DRIFT   -> ("⚠ Drift"   to "#FFAA00")
                else                    -> ("✓ Match"   to "#00CC55")
            }
            val color = Color.parseColor(colorHex)
            rv.statusView.text = statusText
            rv.statusView.setTextColor(color)
            rv.actualView.setTextColor(color)
            rv.actualView.typeface = if (param.status != BehaviourStatus.MATCH)
                Typeface.DEFAULT_BOLD else Typeface.MONOSPACE

            val rowBg = when (param.status) {
                BehaviourStatus.ANOMALY -> Color.parseColor("#1A0000")
                BehaviourStatus.DRIFT   -> Color.parseColor("#12100A")
                else -> if (i % 2 == 0) Color.parseColor("#060E16") else Color.parseColor("#040A11")
            }
            rv.rowLayout.setBackgroundColor(rowBg)
            rv.nameView.setTextColor(
                if (param.status == BehaviourStatus.ANOMALY) Color.parseColor("#FF6666")
                else Color.parseColor("#CCDDEE")
            )
        }
    }

    // ── Tab 3: live 5-column Network threat table (NGINX Lua pipeline) ──────────

    private fun buildNetworkThreatTable(container: LinearLayout) {
        networkRowViews.clear()
        val ctx = requireContext()

        // Banner
        val banner = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#050F1A"))
            setPadding(16, 14, 16, 14)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }
        banner.addView(TextView(ctx).apply {
            text = "NonaShield Network Defense Layer"
            textSize = 12.5f
            setTextColor(Color.parseColor("#4FC3F7"))
            typeface = Typeface.DEFAULT_BOLD
        })
        banner.addView(TextView(ctx).apply {
            text = "5-phase NGINX/OpenResty pipeline  ·  17 Lua enforcement modules" +
                   "  ·  Redis nonce dedup  ·  MaxMind GeoIP2"
            textSize = 8f
            setTextColor(Color.parseColor("#1A4A6A"))
            setPadding(0, 5, 0, 0)
            maxLines = 2
        })
        container.addView(banner)

        container.addView(View(ctx).apply {
            setBackgroundColor(Color.parseColor("#0D3355"))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 2)
        })

        // Column header
        val header = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(Color.parseColor("#040D14"))
            setPadding(10, 10, 10, 10)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }
        fun hCell(text: String, wt: Float, align: Int = android.view.Gravity.START) =
            TextView(ctx).apply {
                this.text = text
                textSize = 9f
                setTextColor(Color.parseColor("#5577AA"))
                typeface = Typeface.DEFAULT_BOLD
                gravity = align
                layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, wt)
            }
        header.addView(hCell("NETWORK THREAT  /  NGINX LUA MODULE", 3.0f))
        header.addView(hCell("SEV", 0.65f, android.view.Gravity.CENTER))
        header.addView(hCell("STATUS", 0.95f, android.view.Gravity.CENTER))
        header.addView(hCell("RISK", 0.55f, android.view.Gravity.CENTER))
        header.addView(hCell("ACTION", 0.85f, android.view.Gravity.CENTER))
        container.addView(header)

        container.addView(View(ctx).apply {
            setBackgroundColor(Color.parseColor("#0D2233"))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 1)
        })

        var rowIndex = 0
        NetworkThreatRegistry.ALL_GROUPS.forEach { group ->
            // Group label row
            container.addView(LinearLayout(ctx).apply {
                orientation = LinearLayout.HORIZONTAL
                setBackgroundColor(Color.parseColor("#060A0F"))
                setPadding(10, 7, 10, 7)
                layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
                addView(TextView(ctx).apply {
                    text = "▸  ${group.label}"
                    textSize = 8f
                    setTextColor(Color.parseColor(group.colorHex))
                    typeface = Typeface.DEFAULT_BOLD
                    alpha = 0.85f
                })
            })

            group.threats.forEach { threat ->
                val idx = rowIndex++
                val row = LinearLayout(ctx).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = android.view.Gravity.CENTER_VERTICAL
                    setPadding(10, 14, 10, 14)
                    setBackgroundColor(
                        if (idx % 2 == 0) Color.parseColor("#060E16") else Color.parseColor("#040A11")
                    )
                    layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
                }

                // Column 1: threat name + Lua module subtitle
                val nameCol = LinearLayout(ctx).apply {
                    orientation = LinearLayout.VERTICAL
                    layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 3.0f)
                }
                nameCol.addView(TextView(ctx).apply {
                    text = threat.name
                    textSize = 11f
                    setTextColor(Color.parseColor("#E8E8FF"))
                    typeface = Typeface.DEFAULT_BOLD
                    maxLines = 2
                    ellipsize = TextUtils.TruncateAt.END
                })
                nameCol.addView(TextView(ctx).apply {
                    text = threat.protectionLine
                    textSize = 8f
                    setTextColor(Color.parseColor("#334466"))
                    setPadding(0, 3, 0, 0)
                    maxLines = 2
                    ellipsize = TextUtils.TruncateAt.END
                })
                nameCol.addView(TextView(ctx).apply {
                    text = "${threat.threatId}  ·  ${threat.nginxPhase.label}"
                    textSize = 7.5f
                    setTextColor(Color.parseColor("#222E3C"))
                    typeface = Typeface.MONOSPACE
                    setPadding(0, 2, 0, 0)
                })
                row.addView(nameCol)

                // Column 2: severity
                row.addView(TextView(ctx).apply {
                    text = threat.severity.label
                    textSize = 8.5f
                    setTextColor(Color.parseColor(threat.severity.colorHex))
                    typeface = Typeface.DEFAULT_BOLD
                    gravity = android.view.Gravity.CENTER
                    layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 0.65f)
                })

                // Column 3: live status
                val statusView = TextView(ctx).apply {
                    text = "● ..."
                    textSize = 8.5f
                    typeface = Typeface.DEFAULT_BOLD
                    gravity = android.view.Gravity.CENTER
                    layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 0.95f)
                }
                row.addView(statusView)

                // Column 4: risk score
                val riskView = TextView(ctx).apply {
                    text = "—"
                    textSize = 10f
                    typeface = Typeface.DEFAULT_BOLD
                    gravity = android.view.Gravity.CENTER
                    layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 0.55f)
                }
                row.addView(riskView)

                // Column 5: decision badge
                row.addView(TextView(ctx).apply {
                    text = threat.decision.label
                    textSize = 8f
                    setTextColor(Color.parseColor(threat.decision.colorHex))
                    typeface = Typeface.DEFAULT_BOLD
                    gravity = android.view.Gravity.CENTER
                    layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 0.85f)
                })

                networkRowViews[idx] = NetworkRowView(statusView, riskView, threat)

                row.isClickable = true
                row.isFocusable = true
                row.setOnClickListener { showNetworkThreatDetail(threat) }

                container.addView(row)
                container.addView(View(ctx).apply {
                    setBackgroundColor(Color.parseColor("#090F16"))
                    layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 1)
                })
            }
        }

        // Footer
        container.addView(View(ctx).apply {
            setBackgroundColor(Color.parseColor("#0D3355"))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 2)
        })
        container.addView(LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#050F1A"))
            setPadding(16, 12, 16, 12)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
            addView(TextView(ctx).apply {
                text = "Network score: 15% of X-Edge-Risk-Level  ·  BLOCK_THRESHOLD = 60  ·  MAX_RISK_ALLOWED = 40"
                textSize = 8.5f
                setTextColor(Color.parseColor("#4FC3F7"))
                typeface = Typeface.DEFAULT_BOLD
            })
            addView(TextView(ctx).apply {
                text = "NGINX blocks malicious requests before they reach the bank backend or core systems."
                textSize = 7.5f
                setTextColor(Color.parseColor("#2A4A6A"))
                setPadding(0, 5, 0, 0)
            })
        })

        refreshNetworkStatuses()
    }

    private fun startNetworkSafetyNetLoop() {
        networkSafetyNetJob = lifecycleScope.launch {
            while (isActive) {
                delay(30_000L)
                refreshNetworkStatuses()
            }
        }
    }

    private fun refreshNetworkStatuses() {
        NetworkThreatRegistry.ALL.forEachIndexed { index, threat ->
            val rv = networkRowViews[index] ?: return@forEachIndexed
            val (statusView, riskView) = rv.statusView to rv.riskView
            val activeSignals = threat.signalTypes.filter { PayShieldEdgeInitializer.isSignalActive(it) }
            when {
                threat.architectureProtected -> {
                    statusView.text = "🛡 Protected"
                    statusView.setTextColor(Color.parseColor("#00AACC"))
                    statusView.isClickable = false
                    statusView.setOnClickListener(null)
                    riskView.text = "0"
                    riskView.setTextColor(Color.parseColor("#00AACC"))
                }
                activeSignals.isNotEmpty() -> {
                    statusView.text = "● ACTIVE"
                    statusView.setTextColor(Color.parseColor("#FF2222"))
                    statusView.isClickable = false
                    statusView.setOnClickListener(null)
                    riskView.text = threat.riskScore.toString()
                    riskView.setTextColor(Color.parseColor("#FF2222"))
                }
                else -> {
                    statusView.text = "● Safe"
                    statusView.setTextColor(Color.parseColor("#00CC55"))
                    statusView.isClickable = false
                    statusView.setOnClickListener(null)
                    riskView.text = "—"
                    riskView.setTextColor(Color.parseColor("#334455"))
                }
            }
        }
    }

    private fun showNetworkThreatDetail(threat: NetworkThreatRegistry.NetworkThreat) {
        val activeSignals = threat.signalTypes.filter { PayShieldEdgeInitializer.isSignalActive(it) }
        val statusLine = when {
            threat.architectureProtected -> "🛡 Protected — enforced by NGINX/OpenResty edge; always active"
            activeSignals.isNotEmpty()   -> "● ACTIVE  —  risk score: ${threat.riskScore} / 100"
            else                         -> "● Safe  —  no active signals"
        }
        val allSignals = threat.signalTypes.joinToString("\n  ") { "· $it" }.ifBlank { "(none — server-side only)" }

        val msg = buildString {
            append("━━━━━━━━━━━━━━━━━━━━━━━━\n")
            append("${threat.name}\n")
            append("ID: ${threat.threatId}   Severity: ${threat.severity.label}\n")
            append("Lua module: ${threat.luaModule}   ${threat.nginxPhase.label}\n")
            append("━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
            append("STATUS\n  $statusLine\n\n")
            append("──── How NonaShield Stops This ────\n")
            append(threat.detailText)
            append("\n\n")
            append("──── SDK Signal Correlation ────\n")
            append("  $allSignals\n\n")
            append("──── Risk Gate ────\n")
            append("  Decision on threat active: ${threat.decision.label}\n")
            append("  Risk score contribution:   ${if (threat.riskScore == 0) "N/A (architecture-protected)" else "${threat.riskScore} / 100"}\n")
            append("  NGINX enforcement: BLOCK_THRESHOLD=60  MAX_RISK_ALLOWED=40\n\n")
            append("──── Formula ────\n")
            append("  Network score (15%) + RASP (60%) + Behaviour (25%) = X-Edge-Risk-Level\n")
        }

        AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle("Network Defense Detail")
            .setMessage(msg)
            .setPositiveButton("OK", null)
            .show()
    }

    private fun showAgenticAdvisory(
        threat: IdentityThreatRegistry.Threat,
        activeSignals: List<String>,
    ) {
        val msg = AgenticAdvisory.buildAdvisory(threat, activeSignals)
        AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle("🤖 Agentic AI Root Cause Advisory")
            .setMessage(msg)
            .setPositiveButton("Dismiss", null)
            .setNeutralButton("Full Detail") { _, _ -> showIdentityThreatDetail(threat) }
            .show()
    }

    private fun showIdentityThreatDetail(threat: IdentityThreatRegistry.Threat) {
        val active = threat.signalTypes.any { PayShieldEdgeInitializer.isSignalActive(it) }
        val statusLine = when {
            threat.architectureProtected -> "🛡 Protected — guaranteed by architecture (KeyStore TEE / NGINX gateway)"
            active                       -> "● ACTIVE  —  risk score: ${threat.riskScore} / 100"
            else                         -> "● Safe  —  no active signals"
        }
        val activeSignals = threat.signalTypes
            .filter { PayShieldEdgeInitializer.isSignalActive(it) }
            .joinToString("\n  ") { "● $it" }
            .ifBlank { "(none)" }
        val allSignals = threat.signalTypes.joinToString("\n  ") { "· $it" }

        val nonce     = java.util.UUID.randomUUID().toString()
        val tsEpoch   = System.currentTimeMillis() / 1000L
        val hashSample = "SHA-256(METHOD|path|body)"

        val msg = buildString {
            append("━━━━━━━━━━━━━━━━━━━━━━━━\n")
            append("${threat.name}\n")
            append("ID: ${threat.threatId}   Severity: ${threat.severity.label}\n")
            append("━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

            append("STATUS\n  $statusLine\n\n")

            append("──── How NonaShield Stops This ────\n")
            append(threat.detailText)
            append("\n\n")

            append("──── Hardware-Bound Identity ────\n")
            append("  Key alias:   payshield_device_key\n")
            append("  Storage:     AndroidKeyStore TEE (hardware-backed)\n")
            append("  Algorithm:   HMAC-SHA256\n")
            append("  Properties:  Non-exportable · device-bound · never in heap\n")
            append("  Guarantee:   Cloned APK = no key = gateway HTTP 401\n\n")

            append("──── NonaShield Request Headers ────\n")
            append("  X-PS-Nonce:         $nonce\n")
            append("                      (per-request UUID — 60 s validity)\n")
            append("  X-PS-Timestamp:     $tsEpoch\n")
            append("                      (epoch sec — rejects requests > ±30 s old)\n")
            append("  X-PS-Request-Hash:  $hashSample\n")
            append("                      (tampered body → hash mismatch → HTTP 400)\n")
            append("  X-Edge-Risk-Level:  [0–100 fused RASP score]\n")
            append("                      ≥ 70  →  NGINX enforces BLOCK\n")
            append("                      40–69 →  NGINX enforces STEP_UP\n")
            append("                      < 40  →  ALLOW\n\n")

            append("──── Risk Score Formula ────\n")
            append("  RASP signals (60%) + Behaviour (25%) + Network (15%)\n")
            append("  This threat's peak score: ${threat.riskScore} / 100\n")
            append("  Enforcement when active:  ${threat.decision.label}\n\n")

            append("──── Signals Monitored ────\n")
            append("  $allSignals\n\n")

            if (active) {
                append("──── Currently Firing ────\n")
                append("  $activeSignals\n")
            }
        }

        AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
            .setTitle("Identity Defense Detail")
            .setMessage(msg)
            .setPositiveButton("OK", null)
            .show()
    }

    // ── Tabs 2-4: simulated attack cards (backend ingest demo) ──────────────────

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
