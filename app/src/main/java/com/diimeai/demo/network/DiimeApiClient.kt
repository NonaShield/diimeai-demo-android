package com.diimeai.demo.network

import android.content.Context
import android.util.Log
import com.diimeai.demo.BuildConfig
import com.payshield.android.sdk.PinningInterceptor
import com.payshield.android.sdk.SignalSink
import com.payshield.sdk.crypto.DeviceKeyManager
import com.payshield.sdk.integration.PayShieldAuthInterceptor
import com.payshield.sdk.token.SessionHolder
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.logging.HttpLoggingInterceptor
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * DiimeAI network client.
 *
 * Wraps OkHttp with the NonaShield security interceptor stack:
 *
 *   ┌────────────────────────────────────────────────────┐
 *   │  PayShieldAuthInterceptor (outermost)              │
 *   │    — detects JWT alg:none, Basic auth, brute-force │
 *   │  PinningInterceptor (inner)                        │
 *   │    — attaches X-PayShield-Token + Signature        │
 *   │    — attaches 7 flat headers required by nginx     │
 *   │    — checks EdgeRiskEnforcer (fail-closed)         │
 *   │  HttpLoggingInterceptor (debug only)               │
 *   └────────────────────────────────────────────────────┘
 *
 * Session lifecycle:
 *   - Before login: SessionHolder has no session — PinningInterceptor will
 *     throw IllegalStateException if a protected call is attempted.
 *   - After login: call [setSession] to inject user identity.  The interceptors
 *     pick up the new session on the next request without client rebuild.
 */
object DiimeApiClient {

    private const val TAG = "DiimeApiClient"
    private val JSON = "application/json; charset=utf-8".toMediaType()

    // Populated by DiimeApp.registerSignalSink()
    var signalSink: SignalSink? = null

    private lateinit var client: OkHttpClient

    /**
     * Call once from Application.onCreate() BEFORE any network calls.
     */
    fun init(context: Context, keyManager: DeviceKeyManager) {
        val logging = HttpLoggingInterceptor().apply {
            level = if (BuildConfig.IS_DEBUG)
                HttpLoggingInterceptor.Level.BODY
            else
                HttpLoggingInterceptor.Level.NONE
        }

        // PinningInterceptor — reads session from SessionHolder on every call.
        // SessionHolder.setSession() is called after login (see LoginActivity).
        val pinning = PinningInterceptor(
            keyManager = keyManager,
            act        = "REQUEST"   // default; overridden per-call via action-specific clients
        )

        // PayShieldAuthInterceptor — wire-level auth observation.
        // Detects JWT alg:none, Basic auth, auth-over-HTTP, brute-force patterns.
        val authMonitor = PayShieldAuthInterceptor(
            sink = object : com.payshield.sdk.signal.SignalSink {
                override fun emit(signal: com.payshield.sdk.signal.EdgeSignal) {
                    Log.w(TAG, "[AuthMonitor] ${signal.type} confidence=${signal.confidence}")
                }
            }
        )

        client = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .addInterceptor(authMonitor)    // outermost — observe before signing
            .addInterceptor(pinning)        // sign + attach all PayShield headers
            .addInterceptor(logging)        // innermost — log final signed request
            .build()

        Log.i(TAG, "DiimeApiClient initialized. baseUrl=${BuildConfig.NONASHIELD_BASE_URL}")
    }

    /**
     * Inject user session after successful login.
     * PinningInterceptor will pick this up immediately for all subsequent requests.
     */
    fun setSession(userId: String, deviceId: String, sessionId: String, jwt: String? = null) {
        SessionHolder.setSession(
            userId    = userId,
            deviceId  = deviceId,
            sessionId = sessionId,
            jwt       = jwt
        )
        Log.i(TAG, "Session set: userId=$userId deviceId=$deviceId")
    }

    fun clearSession() {
        SessionHolder.clear()
    }

    // -------------------------------------------------------------------------
    // DiimeAI API calls
    // All calls are blocking — call from Dispatchers.IO coroutine.
    // -------------------------------------------------------------------------

    /**
     * Mock login — in production this would call your real auth endpoint.
     * Returns a JWT and session details on success.
     *
     * For the demo: accepts any non-empty username/password and generates
     * a mock session.  Replace with real auth backend in production.
     */
    fun login(username: String, password: String): LoginResult {
        // DEMO ONLY: real auth would call your identity provider here.
        // The NonaShield SDK is not involved in authentication — it protects
        // subsequent API calls AFTER the user is authenticated.
        if (username.isBlank() || password.isBlank()) {
            return LoginResult.Failure("Username and password required")
        }

        // In production: POST to your auth endpoint and get back a JWT.
        // For the demo we simulate success with a fixed mock session.
        val mockUserId    = "usr_${username.lowercase().replace(" ", "_")}"
        val mockSessionId = "sess_${System.currentTimeMillis()}"
        val mockJwt       = "eyJhbGciOiJFUzI1NiJ9.demo_payload.demo_sig"  // NOT a real JWT

        return LoginResult.Success(
            userId    = mockUserId,
            sessionId = mockSessionId,
            jwt       = mockJwt
        )
    }

    /**
     * Initiate a payment — protected by the full NonaShield 5-phase pipeline.
     *
     * The request goes to the Customer API Gateway (api.diimeai.com) which:
     *   1. nginx validates X-PayShield-Token + Signature (5-phase Lua pipeline)
     *   2. Forwards to backend /api/v1/verify/gateway for CDT decision
     *   3. Returns ALLOW / STEP_UP / DENY
     *
     * The HTTP client automatically attaches all required headers via
     * PinningInterceptor (X-PayShield-Token, X-PayShield-Signature, X-Device-Id, etc.)
     */
    fun initiatePayment(
        amount:      Double,
        currency:    String,
        recipientId: String,
        note:        String
    ): PaymentResult {
        val body = JSONObject().apply {
            put("amount",       amount)
            put("currency",     currency)
            put("recipient_id", recipientId)
            put("note",         note)
            put("timestamp",    System.currentTimeMillis() / 1000)
        }.toString()

        val request = Request.Builder()
            .url("${BuildConfig.DIIMEAI_API_URL}/api/v1/payment/initiate")
            .post(body.toRequestBody(JSON))
            // X-PS-Idempotency-Key — idempotent retry support (optional but recommended)
            .header("X-PS-Idempotency-Key", "pay_${System.currentTimeMillis()}")
            .build()

        return try {
            client.newCall(request).execute().use { response ->
                val responseBody = response.body?.string() ?: ""
                when {
                    response.isSuccessful -> {
                        val json = JSONObject(responseBody)
                        PaymentResult.Success(
                            transactionId = json.optString("transaction_id", "TXN_DEMO"),
                            status        = json.optString("status", "PENDING"),
                            receiptUrl    = json.optString("receipt_url", ""),
                            decisionId    = json.optString("decision_id", "")
                        )
                    }
                    response.code == 403 -> {
                        // NonaShield blocked this request
                        val json = runCatching { JSONObject(responseBody) }.getOrDefault(JSONObject())
                        PaymentResult.Blocked(
                            reason     = json.optString("detail", "Request blocked by security policy"),
                            threatType = json.optString("threat_type", "")
                        )
                    }
                    response.code == 402 -> {
                        // Step-up auth required
                        PaymentResult.StepUpRequired(
                            challengeType = runCatching {
                                JSONObject(responseBody).optString("challenge_type", "OTP")
                            }.getOrDefault("OTP")
                        )
                    }
                    else -> PaymentResult.Failure("Payment failed: HTTP ${response.code}")
                }
            }
        } catch (e: SecurityException) {
            // EdgeRiskEnforcer.assertAllowed() threw — device is RASP-blocked
            Log.e(TAG, "Payment blocked by local RASP enforcer: ${e.message}")
            PaymentResult.Blocked(reason = "Device security check failed")
        } catch (e: Exception) {
            Log.e(TAG, "Payment network error: ${e.message}", e)
            PaymentResult.Failure("Network error: ${e.message}")
        }
    }

    /**
     * Fetch hardware binding proof for this device — Demo 1.
     * Returns attestation level, key fingerprint, enrolled date.
     *
     * C4 fix: endpoint is now api_key_required — passes X-Api-Key header.
     * The key is baked into BuildConfig.DEMO_API_KEY at build time via the
     * DEMO_API_KEY environment variable.
     */
    fun getBindingProof(deviceId: String): BindingProof? {
        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/device/$deviceId/binding-proof")
            .get()
            .apply {
                if (BuildConfig.DEMO_API_KEY.isNotBlank()) {
                    header("X-Api-Key", BuildConfig.DEMO_API_KEY)
                }
            }
            .build()

        return try {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return null
                val json = JSONObject(response.body?.string() ?: return null)
                BindingProof(
                    deviceId         = json.optString("device_id"),
                    attestationLevel = json.optString("attestation_level", "BASIC"),
                    pubkeyFingerprint= json.optString("pubkey_fingerprint"),
                    enrolledAtIso    = json.optString("enrolled_at_iso"),
                    hardwareBacked   = json.optBoolean("hardware_backed", false),
                    bindingSummary   = json.optString("binding_summary"),
                    proofId          = json.optString("proof_id")
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "getBindingProof failed: ${e.message}")
            null
        }
    }

    /**
     * Fetch non-repudiation receipt for a gateway decision — Demo 2.
     *
     * C4 fix: endpoint is now api_key_required — passes X-Api-Key header.
     */
    fun getEvidenceReceipt(decisionId: String): EvidenceReceipt? {
        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/evidence/$decisionId/receipt")
            .get()
            .apply {
                if (BuildConfig.DEMO_API_KEY.isNotBlank()) {
                    header("X-Api-Key", BuildConfig.DEMO_API_KEY)
                }
            }
            .build()

        return try {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return null
                val json = JSONObject(response.body?.string() ?: return null)
                val chainArr = json.optJSONArray("chain_of_custody")
                val chain = (0 until (chainArr?.length() ?: 0)).map { chainArr!!.getString(it) }
                EvidenceReceipt(
                    decisionId      = json.optString("decision_id"),
                    deviceId        = json.optString("device_id"),
                    action          = json.optString("action"),
                    payloadHash     = json.optString("payload_hash"),
                    serverSignature = json.optString("server_signature"),
                    signedAtIso     = json.optString("signed_at_iso"),
                    signingAlgorithm= json.optString("signing_algorithm"),
                    chainOfCustody  = chain,
                    receiptUrl      = json.optString("receipt_url")
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "getEvidenceReceipt failed: ${e.message}")
            null
        }
    }

    /**
     * Verify transaction with NonaShield gateway.
     * Used by the Customer API Gateway to get a binary ALLOW/DENY decision.
     * Called automatically as part of each protected API call in production.
     */
    fun verifyWithGateway(action: String, payloadHash: String): GatewayDecision {
        val body = JSONObject().apply {
            put("action",       action)
            put("payload_hash", payloadHash)
        }.toString()

        // MISMATCH 6a fix: backend /api/v1/verify/gateway requires a valid JWT Bearer
        // token to identify the caller's session. Without it the backend returns 401
        // and every gateway verify call is treated as DENY.
        // SessionHolder.session is null before login completes; in that case we send
        // no Authorization header and let the backend reject with 401 (correct behaviour).
        val requestBuilder = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/verify/gateway")
            .post(body.toRequestBody(JSON))
        SessionHolder.session?.jwt?.let { jwt ->
            requestBuilder.header("Authorization", "Bearer $jwt")
        }
        val request = requestBuilder.build()

        return try {
            client.newCall(request).execute().use { response ->
                val json = runCatching { JSONObject(response.body?.string() ?: "{}") }
                    .getOrDefault(JSONObject())

                GatewayDecision(
                    allowed       = json.optBoolean("allowed", false),
                    action        = json.optString("action", "DENY"),
                    decisionId    = json.optString("decision_id", ""),
                    reason        = json.optString("reason", "unknown"),
                    challengeType = json.optString("challenge_type", ""),
                    receiptUrl    = json.optString("receipt_url", "")
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Gateway verify failed: ${e.message}")
            GatewayDecision(allowed = false, action = "DENY", decisionId = "", reason = "Network error")
        }
    }

    // ── Demo Scenario Trigger ─────────────────────────────────────────────────

    /**
     * Trigger a fraud scenario through the REAL backend pipeline.
     *
     * POST /api/v1/demo/scenario/trigger
     * Auth: X-Api-Key header (DEMO_API_KEY from BuildConfig)
     *
     * The backend constructs a synthetic ThreatPayload for the scenario and runs
     * it through Compliance → ML Engine → ThreatModuleExecutor → DecisionEngine.
     * Returns the full pipeline trace with real timing data from each phase.
     *
     * If the backend is unavailable, returns a realistic simulated trace so the
     * demo always works even without a live server.
     *
     * @param scenarioId  1–16 (maps to the 16 NonaShield use cases)
     * @param tenantId    demo tenant identifier
     * @param action      PAYMENT | LOGIN | KYC | OTP
     * @param p1NginxMs   NGINX phase timing measured by the app (0 = let backend estimate)
     * @param p2CryptoMs  Crypto Gate timing measured by the app (0 = let backend estimate)
     */
    fun triggerScenario(
        scenarioId: Int,
        tenantId:   String = "demo_tenant",
        action:     String = "PAYMENT",
        p1NginxMs:  Int    = 0,
        p2CryptoMs: Int    = 0,
    ): ScenarioResult {
        val body = org.json.JSONObject().apply {
            put("scenario_id",     scenarioId)
            put("tenant_id",       tenantId)
            put("action",          action)
            put("phase1_nginx_ms", p1NginxMs)
            put("phase2_crypto_ms",p2CryptoMs)
        }.toString()

        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/demo/scenario/trigger")
            .post(body.toRequestBody(JSON))
            .apply {
                if (BuildConfig.DEMO_API_KEY.isNotBlank())
                    header("X-Api-Key", BuildConfig.DEMO_API_KEY)
            }
            .build()

        return try {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    Log.w(TAG, "triggerScenario HTTP ${response.code} — using simulation")
                    return simulatedScenarioResult(scenarioId)
                }
                val j = JSONObject(response.body?.string() ?: return simulatedScenarioResult(scenarioId))
                val trace = j.optJSONObject("pipeline_trace") ?: org.json.JSONObject()
                val signalsArr = j.optJSONArray("signals_fired")
                val signals = (0 until (signalsArr?.length() ?: 0)).map { i ->
                    val s = signalsArr!!.getJSONObject(i)
                    SignalFired(
                        threatId   = s.optString("threat_id"),
                        confidence = s.optDouble("confidence", 0.9).toFloat(),
                        severity   = s.optString("severity", "HIGH"),
                        module     = s.optString("module", ""),
                    )
                }
                val modulesArr = j.optJSONArray("modules_hit")
                val modules = (0 until (modulesArr?.length() ?: 0)).map { modulesArr!!.getString(it) }

                ScenarioResult(
                    scenarioId    = j.optInt("scenario_id", scenarioId),
                    scenarioName  = j.optString("scenario_name", ""),
                    eventId       = j.optString("event_id", ""),
                    decision      = j.optString("decision", "BLOCK"),
                    riskScore     = j.optInt("risk_score", 0),
                    phase1NginxMs = trace.optInt("phase1_nginx_ms", p1NginxMs),
                    phase2CryptoMs= trace.optInt("phase2_crypto_ms", p2CryptoMs),
                    phase3ComplianceMs = trace.optInt("phase3_compliance_ms", 12),
                    phase4MlMs    = trace.optInt("phase4_ml_ms", 28),
                    phase5ThreatsMs = trace.optInt("phase5_threats_ms", 18),
                    totalMs       = trace.optInt("total_ms", 80),
                    signalsFired  = signals,
                    modulesHit    = modules,
                    reason        = j.optString("reason", ""),
                    evidenceHash  = j.optString("evidence_hash", ""),
                    ruleVersion   = j.optString("rule_version", ""),
                    mlScore       = j.optDouble("ml_score", 0.0).toFloat(),
                    mlFallback    = j.optBoolean("ml_fallback", false),
                    fromSimulation = false,
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "triggerScenario network error — using simulation: ${e.message}")
            simulatedScenarioResult(scenarioId)
        }
    }

    /**
     * Fully realistic simulation of the pipeline trace for offline/demo mode.
     * Matches the real response shape exactly so FraudScenarioDetailActivity
     * renders identically whether online or offline.
     */
    private fun simulatedScenarioResult(scenarioId: Int): ScenarioResult {
        data class Def(val name: String, val dec: String, val score: Int,
                       val tid: String, val sev: String, val mod: String)
        val defs = mapOf(
            1  to Def("Hardware Possession","ALLOW",  12, "APP_SEC_001",      "HIGH",     "evidence_verifier"),
            2  to Def("Non-Repudiation",    "ALLOW",   8, "APP_SEC_002",      "HIGH",     "evidence_verifier"),
            3  to Def("Screen Mirroring",   "BLOCK",  87, "RASP_DEV_003",     "HIGH",     "botnet_correlation"),
            4  to Def("Behavioral Biometrics","STEP_UP",62,"USR_BEH_001",     "MEDIUM",   "mule_account"),
            5  to Def("Device RASP",        "BLOCK", 100, "RASP_DEV_001",     "CRITICAL", "botnet_correlation"),
            6  to Def("Mule Account",       "BLOCK",  82, "USR_BEH_002",      "HIGH",     "mule_account"),
            7  to Def("Bot / Emulator",     "BLOCK",  98, "BOT_APP_001",      "CRITICAL", "botnet_correlation"),
            8  to Def("SIM Swap",           "BLOCK",  95, "SCAM_SS_001",      "CRITICAL", "sim_swap_proxy"),
            9  to Def("Digital Arrest",     "BLOCK", 100, "SCAM_CM_001",      "CRITICAL", "digital_arrest_detector"),
            10 to Def("Fake Loan App",      "STEP_UP",68, "LOAN_APP_002",     "HIGH",     "beneficiary_abuse"),
            11 to Def("Ghost Tap / NFC",    "BLOCK",  83, "NFC_FRAUD_001",    "HIGH",     "credential_reuse"),
            12 to Def("Malicious APK",      "BLOCK", 100, "MAL_APK_001",      "CRITICAL", "botnet_correlation"),
            13 to Def("Deepfake KYC",       "BLOCK",  96, "APP_RUNTIME_008",  "CRITICAL", "synthetic_identity"),
            14 to Def("NBFC Insider",       "BLOCK",  88, "USR_BEH_003",      "HIGH",     "beneficiary_abuse"),
            15 to Def("Investment Scam",    "STEP_UP",55, "SCAM_RS_001",      "MEDIUM",   "investment_fraud_detector"),
            16 to Def("Organized Crime",    "BLOCK",  94, "BOT_APP_011",      "CRITICAL", "organized_crime_cluster"),
        )
        val d   = defs[scenarioId] ?: defs[7]!!
        val p1  = (8..18).random(); val p2 = (6..14).random()
        val p3  = (5..20).random(); val p4 = (15..45).random(); val p5 = (10..35).random()
        val eventId = "sim_${System.currentTimeMillis().toString(16)}"
        val hash    = "sha256:${(1..32).map { "0123456789abcdef".random() }.joinToString("")}"
        return ScenarioResult(
            scenarioId    = scenarioId, scenarioName  = d.name,
            eventId       = eventId,   decision       = d.dec,
            riskScore     = d.score,   phase1NginxMs  = p1,
            phase2CryptoMs= p2,        phase3ComplianceMs = p3,
            phase4MlMs    = p4,        phase5ThreatsMs = p5,
            totalMs       = p1+p2+p3+p4+p5,
            signalsFired  = listOf(SignalFired(d.tid, d.score/100f, d.sev, d.mod)),
            modulesHit    = listOf(d.mod),
            reason        = "${d.name} detected — pipeline decision: ${d.dec}",
            evidenceHash  = hash,      ruleVersion    = "2.3.1",
            mlScore       = d.score / 100f, mlFallback = true,
            fromSimulation = true,
        )
    }

    // ── SOC Dashboard ─────────────────────────────────────────────────────────

    /**
     * Fetch aggregate stats for the SOC dashboard.
     * Endpoint: GET /api/v1/dashboard/stats (api_key_required)
     * Falls back to realistic simulation if backend not reachable.
     */
    fun getDashboardStats(): DashboardStats {
        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/dashboard/stats")
            .get()
            .apply { if (BuildConfig.DEMO_API_KEY.isNotBlank()) header("X-Api-Key", BuildConfig.DEMO_API_KEY) }
            .build()
        return try {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return simulatedDashboardStats()
                val j = JSONObject(response.body?.string() ?: return simulatedDashboardStats())
                DashboardStats(
                    totalDecisions = j.optInt("total_decisions"),
                    blockedCount   = j.optInt("blocked_count"),
                    stepUpCount    = j.optInt("step_up_count"),
                    allowedCount   = j.optInt("allowed_count"),
                    avgRiskScore   = j.optDouble("avg_risk_score").toFloat(),
                    activeDevices  = j.optInt("active_devices"),
                    period         = j.optString("period", "last_24h"),
                    raspPct        = j.optInt("rasp_pct", 38),
                    networkPct     = j.optInt("network_pct", 22),
                    bioPct         = j.optInt("bio_pct", 18),
                    appPct         = j.optInt("app_pct", 22),
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "getDashboardStats: ${e.message}")
            simulatedDashboardStats()
        }
    }

    private fun simulatedDashboardStats(): DashboardStats {
        val total   = (180..620).random()
        val blocked = (total * 0.07).toInt()
        val stepUp  = (total * 0.11).toInt()
        return DashboardStats(
            totalDecisions = total,
            blockedCount   = blocked,
            stepUpCount    = stepUp,
            allowedCount   = total - blocked - stepUp,
            avgRiskScore   = (6f..24f).random(),
            activeDevices  = (8..52).random(),
            period         = "last_24h"
        )
    }

    /**
     * Fetch the most recent gateway decisions for the live feed.
     * Endpoint: GET /api/v1/dashboard/decisions?limit=N (api_key_required)
     */
    fun getRecentDecisions(limit: Int = 20): List<DecisionRecord> {
        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/dashboard/decisions?limit=$limit")
            .get()
            .apply { if (BuildConfig.DEMO_API_KEY.isNotBlank()) header("X-Api-Key", BuildConfig.DEMO_API_KEY) }
            .build()
        return try {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return simulatedDecisions(limit)
                val arr = JSONObject(response.body?.string() ?: "{}").optJSONArray("decisions")
                    ?: return simulatedDecisions(limit)
                (0 until arr.length()).map { i ->
                    val d = arr.getJSONObject(i)
                    val threats = d.optJSONArray("threat_types")
                    DecisionRecord(
                        decisionId  = d.optString("decision_id"),
                        deviceId    = d.optString("device_id"),
                        action      = d.optString("action"),
                        riskScore   = d.optInt("risk_score"),
                        timestamp   = d.optString("timestamp"),
                        tenantId    = d.optString("tenant_id", ""),
                        threatTypes = (0 until (threats?.length() ?: 0)).map { threats!!.getString(it) }
                    )
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "getRecentDecisions: ${e.message}")
            simulatedDecisions(limit)
        }
    }

    private fun simulatedDecisions(limit: Int): List<DecisionRecord> {
        val actions = listOf("ALLOW", "ALLOW", "ALLOW", "ALLOW", "STEP_UP", "BLOCK")
        val threats = listOf(
            listOf(), listOf(), listOf("NET_VPN_005"), listOf(),
            listOf("USR_BEH_012"), listOf("RASP_DEV_002", "APP_INT_006")
        )
        val now = System.currentTimeMillis()
        return (0 until limit).map { i ->
            val idx = actions.indices.random()
            DecisionRecord(
                decisionId  = "dec_${(now - i * 18_000L).toString(16)}",
                deviceId    = "dev_${(1000 + i * 37).toString(16)}",
                action      = actions[idx],
                riskScore   = when (actions[idx]) { "ALLOW" -> (2..28).random(); "STEP_UP" -> (30..55).random(); else -> (56..92).random() },
                timestamp   = formatRelative(now - i * 18_000L),
                threatTypes = threats[idx]
            )
        }
    }

    /**
     * Fetch recent threat events (RASP signals, policy violations).
     * Endpoint: GET /api/v1/dashboard/threats?limit=N (api_key_required)
     */
    fun getRecentThreats(limit: Int = 15): List<ThreatEvent> {
        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/dashboard/threats?limit=$limit")
            .get()
            .apply { if (BuildConfig.DEMO_API_KEY.isNotBlank()) header("X-Api-Key", BuildConfig.DEMO_API_KEY) }
            .build()
        return try {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return simulatedThreats(limit)
                val arr = JSONObject(response.body?.string() ?: "{}").optJSONArray("threats")
                    ?: return simulatedThreats(limit)
                (0 until arr.length()).map { i ->
                    val t = arr.getJSONObject(i)
                    ThreatEvent(
                        threatId   = t.optString("threat_id"),
                        threatType = t.optString("threat_type"),
                        severity   = t.optString("severity"),
                        module     = t.optString("module", ""),
                        deviceId   = t.optString("device_id"),
                        timestamp  = t.optString("timestamp"),
                        details    = t.optString("details"),
                    )
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "getRecentThreats: ${e.message}")
            simulatedThreats(limit)
        }
    }

    private fun simulatedThreats(limit: Int): List<ThreatEvent> {
        data class ThreatDef(val id: String, val type: String, val sev: String, val mod: String)
        val types = listOf(
            ThreatDef("RASP_DEV_002",  "ROOT_CLOAKING",     "HIGH",     "botnet_correlation"),
            ThreatDef("NET_VPN_005",   "VPN_CONFLICT",      "MEDIUM",   "sim_swap_proxy"),
            ThreatDef("APP_INT_006",   "REPACKAGED_APK",    "HIGH",     "botnet_correlation"),
            ThreatDef("SCAM_CM_001",   "DIGITAL_ARREST",    "CRITICAL", "digital_arrest_detector"),
            ThreatDef("USR_BEH_002",   "MULE_ACCOUNT",      "HIGH",     "mule_account"),
            ThreatDef("RASP_DEV_003",  "SCREEN_MIRRORING",  "HIGH",     "botnet_correlation"),
            ThreatDef("DATA_SEC_020",  "MALWARE_DETECTED",  "CRITICAL", "botnet_correlation"),
            ThreatDef("SCAM_SS_001",   "SIM_SWAP",          "CRITICAL", "sim_swap_proxy"),
            ThreatDef("BOT_APP_011",   "ORG_CRIME_CLUSTER", "CRITICAL", "organized_crime_cluster"),
            ThreatDef("NFC_FRAUD_001", "GHOST_TAP",         "HIGH",     "credential_reuse"),
        )
        val now = System.currentTimeMillis()
        return (0 until limit).map { i ->
            val t = types[i % types.size]
            ThreatEvent(
                threatId   = t.id,
                threatType = t.type,
                severity   = t.sev,
                module     = t.mod,
                deviceId   = "dev_${(2000 + i * 41).toString(16)}",
                timestamp  = formatRelative(now - i * 24_000L),
                details    = "Signal confidence: ${(75..98).random()}%"
            )
        }
    }

    // ── OTP / Step-Up Auth ────────────────────────────────────────────────────

    /**
     * Request an OTP for step-up authentication.
     * Endpoint: POST /api/v1/auth/otp/request (jwt required)
     * Demo: always succeeds; returns 60-second TTL.
     */
    fun requestOtp(sessionId: String): OtpRequest {
        val body = JSONObject().apply { put("session_id", sessionId) }.toString()
        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/auth/otp/request")
            .post(body.toRequestBody(JSON))
            .apply { SessionHolder.session?.jwt?.let { header("Authorization", "Bearer $it") } }
            .build()
        return try {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return OtpRequest(sessionId, 60)
                val j = JSONObject(response.body?.string() ?: "{}")
                OtpRequest(j.optString("session_id", sessionId), j.optInt("expires_in_seconds", 60))
            }
        } catch (e: Exception) {
            Log.w(TAG, "requestOtp: ${e.message}")
            OtpRequest(sessionId, 60)
        }
    }

    /**
     * Verify OTP entered by user. Demo accepts "123456" or any 6-digit code.
     * Endpoint: POST /api/v1/auth/otp/verify (jwt required)
     */
    fun verifyOtp(sessionId: String, code: String): OtpVerifyResult {
        val body = JSONObject().apply {
            put("session_id", sessionId)
            put("code", code)
        }.toString()
        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/auth/otp/verify")
            .post(body.toRequestBody(JSON))
            .apply { SessionHolder.session?.jwt?.let { header("Authorization", "Bearer $it") } }
            .build()
        return try {
            client.newCall(request).execute().use { response ->
                val j = runCatching { JSONObject(response.body?.string() ?: "{}") }.getOrDefault(JSONObject())
                OtpVerifyResult(
                    verified = j.optBoolean("verified", code.length == 6),
                    reason   = j.optString("reason", if (code.length == 6) "OTP verified" else "Invalid OTP")
                )
            }
        } catch (e: Exception) {
            // Demo fallback: any 6-digit code passes
            OtpVerifyResult(verified = code.length == 6, reason = "Demo: local verification")
        }
    }

    // ── KYC ───────────────────────────────────────────────────────────────────

    /**
     * Submit a KYC request protected by the full NonaShield pipeline.
     * Endpoint: POST /api/v1/kyc/submit
     * The PinningInterceptor automatically attaches X-PayShield-Token + Signature.
     */
    fun submitKyc(aadhaar: String, pan: String, deviceId: String): KycResult {
        // Hash PII before sending — DPDP Act: no raw identity data over the wire
        val aadhaarHash = sha256hex(aadhaar)
        val panHash     = sha256hex(pan)

        val body = JSONObject().apply {
            put("aadhaar_hash", aadhaarHash)
            put("pan_hash",     panHash)
            put("device_id",    deviceId)
            put("timestamp",    System.currentTimeMillis() / 1000)
        }.toString()

        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/kyc/submit")
            .post(body.toRequestBody(JSON))
            .header("X-PS-Idempotency-Key", "kyc_${System.currentTimeMillis()}")
            .apply { SessionHolder.session?.jwt?.let { header("Authorization", "Bearer $it") } }
            .build()

        return try {
            client.newCall(request).execute().use { response ->
                val j = runCatching { JSONObject(response.body?.string() ?: "{}") }.getOrDefault(JSONObject())
                when {
                    response.isSuccessful -> KycResult(
                        status    = j.optString("status", "APPROVED"),
                        kycId     = j.optString("kyc_id", "kyc_${System.currentTimeMillis()}"),
                        riskScore = j.optInt("risk_score", (5..18).random()),
                        reason    = j.optString("reason", "Verified")
                    )
                    response.code == 403 -> KycResult(
                        status    = "BLOCKED",
                        kycId     = "",
                        riskScore = j.optInt("risk_score", 72),
                        reason    = j.optString("detail", "Blocked by security policy")
                    )
                    else -> KycResult("PENDING", "kyc_${System.currentTimeMillis()}", 12, "Under review")
                }
            }
        } catch (e: Exception) {
            // Demo fallback — simulate approved KYC
            KycResult("APPROVED", "kyc_demo_${System.currentTimeMillis()}", (5..18).random(), "Demo approval")
        }
    }

    // ── Utils ─────────────────────────────────────────────────────────────────

    private fun sha256hex(input: String): String =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(input.toByteArray())
            .joinToString("") { "%02x".format(it) }

    private fun formatRelative(epochMs: Long): String {
        val diff = System.currentTimeMillis() - epochMs
        return when {
            diff < 60_000    -> "${diff / 1000}s ago"
            diff < 3_600_000 -> "${diff / 60_000}m ago"
            else             -> "${diff / 3_600_000}h ago"
        }
    }

    private fun ClosedFloatingPointRange<Float>.random(): Float =
        start + (endInclusive - start) * kotlin.random.Random.nextFloat()
}

// ─────────────────────────────────────────────────────────────────────────────
// Result types
// ─────────────────────────────────────────────────────────────────────────────

sealed class LoginResult {
    data class Success(val userId: String, val sessionId: String, val jwt: String) : LoginResult()
    data class Failure(val reason: String) : LoginResult()
}

sealed class PaymentResult {
    data class Success(
        val transactionId: String,
        val status: String,
        val receiptUrl: String = "",        // Demo 2: non-repudiation receipt URL
        val decisionId: String = ""
    ) : PaymentResult()
    data class Blocked(val reason: String, val threatType: String = "")  : PaymentResult()
    data class StepUpRequired(val challengeType: String)                 : PaymentResult()
    data class Failure(val reason: String)                               : PaymentResult()
}

data class GatewayDecision(
    val allowed:       Boolean,
    val action:        String,
    val decisionId:    String,
    val reason:        String,
    val challengeType: String = "",
    val receiptUrl:    String = ""
)

// ─────────────────────────────────────────────────────────────────────────────
// Demo 1: Hardware binding proof
// ─────────────────────────────────────────────────────────────────────────────
data class BindingProof(
    val deviceId:          String,
    val attestationLevel:  String,   // FULL | BASIC | GATEWAY
    val pubkeyFingerprint: String,
    val enrolledAtIso:     String,
    val hardwareBacked:    Boolean,
    val bindingSummary:    String,
    val proofId:           String
)

// ─────────────────────────────────────────────────────────────────────────────
// Demo 2: Non-repudiation receipt
// ─────────────────────────────────────────────────────────────────────────────
data class EvidenceReceipt(
    val decisionId:       String,
    val deviceId:         String,
    val action:           String,
    val payloadHash:      String,
    val serverSignature:  String,
    val signedAtIso:      String,
    val signingAlgorithm: String,
    val chainOfCustody:   List<String>,
    val receiptUrl:       String
)

// ─────────────────────────────────────────────────────────────────────────────
// SOC Dashboard
// ─────────────────────────────────────────────────────────────────────────────
data class DashboardStats(
    val totalDecisions: Int,
    val blockedCount:   Int,
    val stepUpCount:    Int,
    val allowedCount:   Int,
    val avgRiskScore:   Float,
    val activeDevices:  Int,
    val period:         String,
    // Category breakdown percentages (0–100)
    val raspPct:        Int = 38,
    val networkPct:     Int = 22,
    val bioPct:         Int = 18,
    val appPct:         Int = 22,
) {
    // Convenience aliases used by SocDashboardActivity
    val total:   Int   get() = totalDecisions
    val blocked: Int   get() = blockedCount
    val stepUp:  Int   get() = stepUpCount
    val allowed: Int   get() = allowedCount
    val avgRisk: Float get() = avgRiskScore
}

data class DecisionRecord(
    val decisionId:  String  = "",
    val deviceId:    String,
    val action:      String  = "ALLOW",  // ALLOW | STEP_UP | BLOCK
    val riskScore:   Int,
    val timestamp:   String,
    val tenantId:    String  = "",
    val threatTypes: List<String> = emptyList(),
) {
    // Convenience alias — SocDashboardActivity uses 'decision'
    val decision: String get() = action
}

data class ThreatEvent(
    val threatId:   String,
    val threatType: String  = "",
    val severity:   String,          // INFO | MEDIUM | HIGH | CRITICAL
    val deviceId:   String,
    val timestamp:  String,
    val module:     String  = "",    // backend module that flagged this
    val details:    String  = "",
)

// ─────────────────────────────────────────────────────────────────────────────
// Step-Up / OTP
// ─────────────────────────────────────────────────────────────────────────────
data class OtpRequest(val sessionId: String, val expiresInSeconds: Int)
data class OtpVerifyResult(val verified: Boolean, val reason: String)

// ─────────────────────────────────────────────────────────────────────────────
// KYC
// ─────────────────────────────────────────────────────────────────────────────
data class KycResult(
    val status:    String,   // APPROVED | PENDING | BLOCKED | REJECTED
    val kycId:     String,
    val riskScore: Int,
    val reason:    String
)

// ─────────────────────────────────────────────────────────────────────────────
// Demo scenario trigger — full pipeline trace
// ─────────────────────────────────────────────────────────────────────────────

data class SignalFired(
    val threatId:   String,
    val confidence: Float,
    val severity:   String,
    val module:     String,
)

/**
 * Full pipeline trace returned by POST /api/v1/demo/scenario/trigger.
 *
 * When fromSimulation=false the data comes from the live backend:
 *   - phase3ComplianceMs / phase4MlMs / phase5ThreatsMs are real wall-clock timings
 *   - evidenceHash is a real SHA-256 stored in EvidenceRecord
 *   - signalsFired are real ThreatFlags from ThreatModuleExecutor
 *
 * When fromSimulation=true the backend was unreachable and values are
 * representative estimates that match typical live timings.
 */
data class ScenarioResult(
    val scenarioId:         Int,
    val scenarioName:       String,
    val eventId:            String,
    val decision:           String,   // BLOCK | STEP_UP | ALLOW
    val riskScore:          Int,      // 0–100
    val phase1NginxMs:      Int,
    val phase2CryptoMs:     Int,
    val phase3ComplianceMs: Int,
    val phase4MlMs:         Int,
    val phase5ThreatsMs:    Int,
    val totalMs:            Int,
    val signalsFired:       List<SignalFired>,
    val modulesHit:         List<String>,
    val reason:             String,
    val evidenceHash:       String,
    val ruleVersion:        String,
    val mlScore:            Float,
    val mlFallback:         Boolean,
    val fromSimulation:     Boolean,
)
