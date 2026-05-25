package com.diimeai.demo

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView

/**
 * FraudScenarioDemoActivity — Central hub for all 16 fraud use case demos.
 *
 * Presents each use case as a tappable card. Tapping opens
 * FraudScenarioDetailActivity which runs the live signal + pipeline trace.
 *
 * All 16 scenarios work in simulation mode when the backend is offline.
 *
 * Use cases covered:
 *   UC-01  Hardware Possession & Device Binding
 *   UC-02  Non-Repudiation & Receipt Integrity
 *   UC-03  Screen Mirroring / Remote Viewing
 *   UC-04  Behavioral Biometrics & Social Engineering
 *   UC-05  Device-Level Comprehensive RASP
 *   UC-06  Mule Account Network Detection
 *   UC-07  Bot Attack & Emulator Detection
 *   UC-08  SIM Swap Fraud
 *   UC-09  Digital Arrest / Call Merge Scam
 *   UC-10  Fake Loan App Extortion
 *   UC-11  Ghost Tapping / NFC Payment Abuse
 *   UC-12  Malicious APK Injection
 *   UC-13  Deepfake KYC Bypass
 *   UC-14  NBFC Insider Enrollment Burst
 *   UC-15  Investment / Romance Scam
 *   UC-16  Organized Crime Ring (Neo4j cluster scan)
 */
class FraudScenarioDemoActivity : AppCompatActivity() {

    data class ScenarioCard(
        val id:          Int,
        val emoji:       String,
        val title:       String,
        val subtitle:    String,
        val severity:    String,     // CRITICAL | HIGH | MEDIUM
        val sdkSignal:   String,
        val threatId:    String,
        val backendMod:  String,
        val description: String,
        val rbiRule:     String,
    )

    private val scenarios = listOf(
        ScenarioCard(1, "🔐", "Hardware Possession",
            "TEE-bound device identity · AndroidKeyStore",
            "HIGH", "DeviceKeyManager", "APP_SEC_001", "evidence_verifier",
            "Proves this exact physical device enrolled using a hardware-backed ECDSA P-256 key stored in the Trusted Execution Environment. The private key never leaves the secure enclave — even a cloned SIM cannot impersonate this device.",
            "UC-01"),
        ScenarioCard(2, "📜", "Non-Repudiation Receipt",
            "Classical + post-quantum hybrid signature",
            "HIGH", "HybridEvidenceSigner", "APP_SEC_002", "evidence_verifier",
            "Every payment event is signed with both an ECDSA classical signature and a Dilithium post-quantum signature. The tamper-evident receipt is stored in a SHA-256 hash chain. Dispute: the bank queries the chain and proves the customer authorized the transaction.",
            "UC-02"),
        ScenarioCard(3, "📺", "Screen Mirroring Attack",
            "DisplayManager + MediaProjection detection",
            "HIGH", "ScreenMirroringSignal", "RASP_DEV_003", "botnet_correlation",
            "Attackers use screen-mirroring apps (AnyDesk, TeamViewer) to view the victim's OTP and banking session in real time. NonaShield detects active presentation displays, VNC projections, and MediaProjection streams — blocking the session immediately.",
            "UC-03"),
        ScenarioCard(4, "🤚", "Behavioral Biometrics",
            "Pressure · velocity · hesitation · grip (6 channels)",
            "MEDIUM", "BehavioralMonitor", "USR_BEH_001", "mule_account",
            "Six channels of touch biometrics (pressure, finger size, swipe velocity, inter-action hesitation, device posture, grip stability) create a session fingerprint. A scammer verbally coaching the victim causes hesitation spikes and pressure anomalies that trigger step-up auth.",
            "UC-04"),
        ScenarioCard(5, "🛡", "Device-Level RASP",
            "38 sensors: root · hook · emulator · repackage",
            "CRITICAL", "FreeRaspSensorAdapter", "RASP_DEV_001", "botnet_correlation",
            "38 registered RASP sensors continuously monitor for root/jailbreak, code hooks (Frida, Xposed), debugger attachment, app repackaging, kernel exploits (Magisk, KernelSU, APatch), and accessibility overlay abuse. Any critical detection terminates the process immediately.",
            "UC-05"),
        ScenarioCard(6, "🏦", "Mule Account Network",
            "Graph degree · shared IPs · account velocity",
            "HIGH", "AccountDegreeSignal", "USR_BEH_002", "mule_account",
            "Criminals recruit individuals to receive and forward stolen funds. NonaShield tracks account_degree (number of unique accounts linked per device) and enrollment velocity. Devices linked to 5+ accounts or enrolling 3+ in 24h are flagged as probable mule nodes.",
            "UC-06"),
        ScenarioCard(7, "🤖", "Bot Attack / Emulator",
            "Emulator probes · timing patterns · sensor absence",
            "CRITICAL", "EmulatorSignal", "BOT_APP_001", "botnet_correlation",
            "Automated bots use Android emulators for credential stuffing and account takeover at scale. NonaShield probes system properties (ro.product.model, build fingerprint), sensor presence, and timing jitter. Emulators lack gyroscope and barometer — detected within 200ms.",
            "UC-07"),
        ScenarioCard(8, "📱", "SIM Swap Fraud",
            "ICCID/IMSI change · carrier transition · SIM absence",
            "CRITICAL", "SimSwapSignal", "SCAM_SS_001", "sim_swap_proxy",
            "Fraudster convinces carrier to port victim's number to attacker SIM. NonaShield securely stores the ICCID and IMSI on first enrollment (EncryptedSharedPreferences). Any carrier change, SIM absence, or ICCID rotation fires SCAM_SS_001 with CRITICAL severity — the HMAC-signed SIM state is compared against stored baseline.",
            "UC-08"),
        ScenarioCard(9, "📞", "Digital Arrest Scam",
            "VoIP + cellular merge · overnight call + OTP",
            "CRITICAL", "CallMergeSignal", "SCAM_CM_001", "digital_arrest_detector",
            "Scammers impersonate CBI/ED officers on video call, threatening 'digital arrest' to coerce large transfers. NonaShield detects simultaneous VoIP (AudioManager.MODE_IN_COMMUNICATION) + cellular (CALL_STATE_OFFHOOK) — the exact call-merge pattern. Backend fast-path: SCAM_CM_001 + OTP/LOGIN action → score=100, BLOCK immediately.",
            "UC-09"),
        ScenarioCard(10, "💸", "Fake Loan App Extortion",
            "Predatory permissions: READ_SMS + READ_CONTACTS + CALL_LOG",
            "HIGH", "PredatoryLoanAppSignal", "LOAN_APP_001", "beneficiary_abuse",
            "Illegal loan apps harvest contacts and call logs, then threaten victims with public shaming. NonaShield detects apps holding READ_CONTACTS + READ_EXTERNAL_STORAGE + READ_SMS simultaneously (confidence 0.75) or adding READ_CALL_LOG (confidence 0.90). 26 trusted payment apps are whitelisted.",
            "UC-10"),
        ScenarioCard(11, "💳", "Ghost Tapping / NFC Abuse",
            "Rogue HCE app · NFC enabled without screen lock",
            "HIGH", "NfcPaymentAbuseSignal", "NFC_FRAUD_001", "credential_reuse",
            "Rogue Host Card Emulation (HCE) apps impersonate payment cards for contactless fraud. NonaShield checks for non-system, non-whitelisted HCE apps (NFC_FRAUD_001, confidence 0.80) and NFC active without a screen lock (NFC_FRAUD_002, confidence 0.85). Whitelist covers 8 major payment apps.",
            "UC-11"),
        ScenarioCard(12, "☣", "Malicious APK Injection",
            "Signature mismatch · dangerous permissions cluster · overlay",
            "CRITICAL", "MaliciousApkSignal", "MAL_APK_001", "botnet_correlation",
            "Trojanized banking apps are side-loaded with extra permissions and accessibility overlays. Three detection layers: (1) APK signature mismatch vs Play Store, (2) dangerous-permission cluster (SEND_SMS + READ_SMS + RECORD_AUDIO + CAMERA), (3) overlay abuse without accessibility justification. Any layer fires CRITICAL.",
            "UC-12"),
        ScenarioCard(13, "🎭", "Deepfake KYC Bypass",
            "Virtual camera · OBS · DroidCam detection",
            "CRITICAL", "VirtualCameraSignal", "APP_RUNTIME_008", "synthetic_identity",
            "Fraudsters use AI-generated face deepfakes streamed through virtual camera apps (OBS, DroidCam) to pass KYC liveness checks. NonaShield detects virtual camera packages and checks Camera2 API for non-physical camera IDs. Backend synthetic_identity module cross-validates against enrollment face hash.",
            "UC-13"),
        ScenarioCard(14, "🏢", "NBFC Insider Burst",
            "Enrollment velocity · off-hours · device reuse",
            "HIGH", "ApplicationVelocitySignal", "USR_BEH_003", "beneficiary_abuse",
            "Compromised NBFC agent enrolls many mule accounts from a single device during off-hours. NonaShield tracks enrollment velocity (≥3 accounts in 60s on same device = HIGH, ≥5 = CRITICAL) and device reuse count. Backend flags the device in Neo4j for cluster inclusion.",
            "UC-14"),
        ScenarioCard(15, "💌", "Investment / Romance Scam",
            "Dating apps + investment patterns + foreign transfers",
            "MEDIUM", "RomanceSocialAppSignal", "SCAM_RS_001", "investment_fraud_detector",
            "Scammers build trust via dating apps then lure victims into fake investment platforms. NonaShield detects 26 dating/matrimonial apps (Tinder, Bumble, Shaadi.com, BharatMatrimony…) with confidence 0.60. Backend fuses with investment transaction patterns: repeated foreign transfers + first-time high-value tx → STEP_UP.",
            "UC-15"),
        ScenarioCard(16, "🕸", "Organized Crime Ring",
            "Neo4j cluster scan · shared-IP ring · coordinated timing",
            "CRITICAL", "OrganizedCrimeCluster", "BOT_APP_011", "organized_crime_cluster",
            "Coordinated device rings stay below per-device thresholds to evade individual fraud rules. Every 15 minutes, an Airflow DAG runs 3 Cypher queries against the Neo4j behaviour graph: Q1=shared-IP cluster (≥10 devices, ≥2 shared IPs), Q2=enrollment rhythm (≥8 devices enrolling in 180s bands), Q3=high-degree peer cluster. Flagged device IDs are cached in Redis (24h TTL). Per-event path: O(1) Redis GET — no Neo4j on the hot path.",
            "UC-16"),
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_fraud_demo)

        findViewById<View>(R.id.btnBack).setOnClickListener { finish() }
        findViewById<View>(R.id.btnSocDashboard).setOnClickListener {
            startActivity(Intent(this, SocDashboardActivity::class.java))
        }

        val container = findViewById<LinearLayout>(R.id.llScenarioCards)
        scenarios.forEach { scenario ->
            container.addView(buildScenarioCard(scenario))
        }
    }

    private fun buildScenarioCard(s: ScenarioCard): View {
        val severityColor = when (s.severity) {
            "CRITICAL" -> Color.parseColor("#DD2222")
            "HIGH"     -> Color.parseColor("#FF6600")
            else       -> Color.parseColor("#FFAA00")
        }

        // Root card
        val card = CardView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).also { lp -> lp.bottomMargin = dpToPx(10) }
            radius               = dpToPx(12).toFloat()
            cardElevation        = dpToPx(4).toFloat()
            setCardBackgroundColor(Color.parseColor("#0D1117"))
            isClickable          = true
            isFocusable          = true
            setOnClickListener {
                val intent = Intent(this@FraudScenarioDemoActivity,
                    FraudScenarioDetailActivity::class.java)
                intent.putExtra("scenario_id",    s.id)
                intent.putExtra("emoji",          s.emoji)
                intent.putExtra("title",          s.title)
                intent.putExtra("subtitle",       s.subtitle)
                intent.putExtra("severity",       s.severity)
                intent.putExtra("sdk_signal",     s.sdkSignal)
                intent.putExtra("threat_id",      s.threatId)
                intent.putExtra("backend_mod",    s.backendMod)
                intent.putExtra("description",    s.description)
                intent.putExtra("rbi_rule",       s.rbiRule)
                startActivity(intent)
            }
        }

        // Inner layout
        val inner = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dpToPx(14), dpToPx(14), dpToPx(14), dpToPx(14))
        }

        // Left severity strip
        val strip = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(dpToPx(4), LinearLayout.LayoutParams.MATCH_PARENT)
                .also { lp -> lp.marginEnd = dpToPx(12) }
            setBackgroundColor(severityColor)
        }
        inner.addView(strip)

        // UC number badge
        val numBadge = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(dpToPx(36), dpToPx(36))
                .also { lp -> lp.marginEnd = dpToPx(12) }
            text      = "%02d".format(s.id)
            textSize  = 12f
            setTextColor(severityColor)
            typeface  = android.graphics.Typeface.MONOSPACE
            gravity   = android.view.Gravity.CENTER
            setBackgroundColor(Color.argb(30, Color.red(severityColor),
                Color.green(severityColor), Color.blue(severityColor)))
        }
        inner.addView(numBadge)

        // Text block
        val textBlock = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        // Title row
        val titleRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity     = android.view.Gravity.CENTER_VERTICAL
        }
        val titleTv = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            text     = "${s.emoji}  ${s.title}"
            textSize = 14f
            setTextColor(Color.WHITE)
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        }
        val severityBadge = TextView(this).apply {
            text    = s.severity
            textSize = 8f
            setTextColor(Color.BLACK)
            setTypeface(null, android.graphics.Typeface.BOLD)
            setPadding(dpToPx(5), dpToPx(2), dpToPx(5), dpToPx(2))
            setBackgroundColor(severityColor)
        }
        titleRow.addView(titleTv)
        titleRow.addView(severityBadge)

        val subtitleTv = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
                .also { lp -> lp.topMargin = dpToPx(3); lp.bottomMargin = dpToPx(4) }
            text     = s.subtitle
            textSize = 10f
            setTextColor(Color.parseColor("#888888"))
        }
        val signalRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity     = android.view.Gravity.CENTER_VERTICAL
        }
        val signalLabel = TextView(this).apply {
            text     = "Signal: "
            textSize = 9f
            setTextColor(Color.parseColor("#555555"))
        }
        val signalVal = TextView(this).apply {
            text     = "${s.sdkSignal}  |  ${s.threatId}"
            textSize = 9f
            setTextColor(Color.parseColor("#00D4FF"))
            typeface = android.graphics.Typeface.MONOSPACE
        }
        signalRow.addView(signalLabel)
        signalRow.addView(signalVal)

        textBlock.addView(titleRow)
        textBlock.addView(subtitleTv)
        textBlock.addView(signalRow)

        inner.addView(textBlock)

        // Arrow
        val arrow = TextView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT)
                .also { lp -> lp.marginStart = dpToPx(8) }
            text     = "›"
            textSize = 20f
            setTextColor(Color.parseColor("#444444"))
        }
        inner.addView(arrow)

        card.addView(inner)
        return card
    }

    private fun dpToPx(dp: Int): Int =
        (dp * resources.displayMetrics.density).toInt()
}
