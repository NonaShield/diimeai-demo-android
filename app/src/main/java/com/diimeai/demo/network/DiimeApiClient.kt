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

    private lateinit var client:     OkHttpClient
    private lateinit var keyManager: DeviceKeyManager   // stored for signing IngestEnvelopes

    /**
     * Call once from Application.onCreate() BEFORE any network calls.
     */
    fun init(context: Context, keyManager: DeviceKeyManager) {
        this.keyManager = keyManager
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
        SessionHolder.clearSession()
    }

    // -------------------------------------------------------------------------
    // DiimeAI API calls
    // All calls are blocking — call from Dispatchers.IO coroutine.
    // -------------------------------------------------------------------------

    /**
     * Authenticate against the real NonaShield auth endpoint.
     *
     * Calls POST /api/v1/auth/login and receives a signed RS256 JWT.
     * The JWT is stored in SessionHolder and automatically attached by
     * PinningInterceptor to all subsequent protected API calls as
     * "Authorization: Bearer <token>".
     *
     * Production note: replace the credential validation logic in the backend's
     * /api/v1/auth/login handler with your real identity provider
     * (LDAP, OAuth2, internal user service, etc.). The SDK layer is unchanged.
     *
     * A raw OkHttpClient is used here (no PinningInterceptor) because
     * PinningInterceptor requires an active session — which does not exist
     * before login completes.  All subsequent calls use the full interceptor stack.
     */
    fun login(username: String, password: String): LoginResult {
        if (username.isBlank() || password.isBlank()) {
            return LoginResult.Failure("Username and password required")
        }

        // Stable device ID: prefer an already-enrolled ID from SessionHolder,
        // fall back to a hardware-derived identifier.
        val deviceId = SessionHolder.session?.deviceId
            ?: "device_${(android.os.Build.SERIAL?.takeIf { it != "unknown" }?.take(12)
                ?: java.util.UUID.randomUUID().toString().take(12))}"

        val bodyJson = JSONObject().apply {
            put("username",  username)
            put("password",  password)
            put("device_id", deviceId)
            put("tenant_id", "default")
        }.toString()

        // Minimal client for the unauthenticated login call.
        val loginClient = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .build()

        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/auth/login")
            .post(bodyJson.toRequestBody(JSON))
            .build()

        return try {
            loginClient.newCall(request).execute().use { response ->
                val responseBody = response.body?.string() ?: ""
                if (response.isSuccessful) {
                    val json      = JSONObject(responseBody)
                    val jwt       = json.getString("jwt")
                    val userId    = json.getString("user_id")
                    val sessionId = json.getString("session_id")

                    // Inject real JWT into SessionHolder so PinningInterceptor
                    // attaches it as "Authorization: Bearer <jwt>" on every call.
                    SessionHolder.setSession(
                        userId    = userId,
                        deviceId  = deviceId,
                        sessionId = sessionId,
                        jwt       = jwt
                    )
                    Log.i(TAG, "Login success: userId=$userId sessionId=$sessionId")
                    LoginResult.Success(
                        userId    = userId,
                        sessionId = sessionId,
                        jwt       = jwt
                    )
                } else {
                    val detail = runCatching {
                        JSONObject(responseBody).optString("detail", "Login failed")
                    }.getOrDefault("Login failed (HTTP ${response.code})")
                    Log.w(TAG, "Login failed HTTP ${response.code}: $detail")
                    LoginResult.Failure(detail)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Login network error: ${e.message}", e)
            LoginResult.Failure("Network error: ${e.message}")
        }
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

    // ── Scenario payload definitions ──────────────────────────────────────────
    //
    // Each entry defines the IngestEnvelope.payload for that fraud use case.
    // Signals come from the real SDK on the device — these definitions describe
    // WHAT the SDK emits, not what the server fabricates.
    //
    // event_type must be UPPER_SNAKE_CASE (backend IngestEnvelope validator).
    // signals are the payload dict sent to the real /api/v1/ingest endpoint.

    private data class ScenarioDef(
        val name:       String,
        val eventType:  String,
        val signals:    Map<String, Any>,
        val signalDefs: List<SignalFired>,   // for UI — what the SDK emits
        val decision:   String,             // expected outcome (for simulation fallback)
        val riskScore:  Int,
    )

    private val SCENARIO_DEFS: Map<Int, ScenarioDef> = mapOf(
        1  to ScenarioDef("Hardware Possession",      "DEVICE_ATTESTATION",
            mapOf("hardware_bound" to true, "key_storage" to "AndroidKeyStore"),
            listOf(SignalFired("APP_SEC_001", 0.99f, "HIGH", "evidence_verifier")),
            "ALLOW", 5),
        2  to ScenarioDef("Non-Repudiation Receipt",  "EVIDENCE_CHAIN_VERIFY",
            mapOf("hybrid_sig_verified" to true, "pqc_sig_present" to true),
            listOf(SignalFired("APP_SEC_002", 0.99f, "HIGH", "evidence_verifier")),
            "ALLOW", 5),
        3  to ScenarioDef("Screen Mirroring Attack",  "SCREEN_MIRROR_DETECTED",
            mapOf("screen_mirroring" to true, "presentation_display" to true, "vnc_active" to false),
            listOf(SignalFired("RASP_DEV_003", 0.92f, "HIGH", "botnet_correlation"),
                   SignalFired("RASP_DEV_004", 0.85f, "HIGH", "botnet_correlation")),
            "BLOCK", 87),
        4  to ScenarioDef("Behavioral Biometrics",    "BIOMETRIC_ANOMALY",
            mapOf("hesitation_spike" to true, "pressure_anomaly" to true, "biometric_score" to 0.31),
            listOf(SignalFired("USR_BEH_001", 0.78f, "MEDIUM", "mule_account"),
                   SignalFired("USR_BEH_001", 0.71f, "MEDIUM", "mule_account")),
            "STEP_UP", 55),
        5  to ScenarioDef("Device RASP (38 sensors)", "RASP_THREAT_DETECTED",
            mapOf("root_detected" to true, "hook_detected" to true, "magisk_present" to true),
            listOf(SignalFired("RASP_DEV_001", 0.95f, "CRITICAL", "botnet_correlation"),
                   SignalFired("APP_RUNTIME_008", 1.0f, "CRITICAL", "botnet_correlation")),
            "BLOCK", 100),
        6  to ScenarioDef("Mule Account Network",     "MULE_ACCOUNT_SIGNAL",
            mapOf("account_velocity_24h" to 4, "device_account_degree" to 8, "device_reuse_count" to 12),
            listOf(SignalFired("USR_BEH_002", 0.88f, "HIGH", "mule_account"),
                   SignalFired("USR_BEH_003", 0.76f, "HIGH", "mule_account")),
            "BLOCK", 82),
        7  to ScenarioDef("Bot Attack / Emulator",    "BOT_EMULATOR_DETECTED",
            mapOf("emulator_detected" to true, "build_fingerprint_anomaly" to true, "sensor_absence" to true),
            listOf(SignalFired("BOT_APP_001", 0.97f, "CRITICAL", "botnet_correlation"),
                   SignalFired("BOT_APP_002", 0.91f, "CRITICAL", "botnet_correlation")),
            "BLOCK", 98),
        8  to ScenarioDef("SIM Swap Fraud",           "SIM_SWAP_SIGNAL",
            mapOf("sim_swap_detected" to true, "iccid_changed" to true, "carrier_transition" to true),
            listOf(SignalFired("SCAM_SS_001", 1.00f, "CRITICAL", "sim_swap_proxy"),
                   SignalFired("SCAM_SS_002", 0.96f, "HIGH",     "sim_swap_proxy")),
            "BLOCK", 95),
        9  to ScenarioDef("Digital Arrest Scam",      "DIGITAL_ARREST_SIGNAL",
            mapOf("active_video_call" to true, "call_merge_active" to true,
                  "voip_cellular_concurrent" to true, "prolonged_call_mins" to 47),
            listOf(SignalFired("SCAM_CM_001", 0.98f, "CRITICAL", "digital_arrest_detector"),
                   SignalFired("SCAM_CM_002", 0.85f, "HIGH",     "digital_arrest_detector")),
            "BLOCK", 100),
        10 to ScenarioDef("Fake Loan App Extortion",  "PREDATORY_LOAN_SIGNAL",
            mapOf("sms_permission" to true, "contacts_permission" to true,
                  "call_log_permission" to true, "storage_permission" to true),
            listOf(SignalFired("LOAN_APP_002", 0.90f, "HIGH", "beneficiary_abuse")),
            "STEP_UP", 68),
        11 to ScenarioDef("Ghost Tapping / NFC Abuse","NFC_FRAUD_SIGNAL",
            mapOf("rogue_hce_app" to true, "nfc_enabled" to true, "no_screen_lock" to true),
            listOf(SignalFired("NFC_FRAUD_001", 0.80f, "HIGH", "credential_reuse"),
                   SignalFired("NFC_FRAUD_002", 0.85f, "HIGH", "credential_reuse")),
            "BLOCK", 83),
        12 to ScenarioDef("Malicious APK Injection",  "MALICIOUS_APK_SIGNAL",
            mapOf("apk_signature_mismatch" to true, "dangerous_permission_cluster" to true,
                  "overlay_abuse" to true, "sideloaded" to true),
            listOf(SignalFired("MAL_APK_001", 0.95f, "CRITICAL", "botnet_correlation"),
                   SignalFired("MAL_APK_002", 0.88f, "CRITICAL", "botnet_correlation"),
                   SignalFired("MAL_APK_003", 0.92f, "CRITICAL", "botnet_correlation")),
            "BLOCK", 100),
        13 to ScenarioDef("Deepfake KYC Bypass",      "DEEPFAKE_KYC_SIGNAL",
            mapOf("virtual_camera_detected" to true, "obs_package_present" to true,
                  "non_physical_camera_id" to true),
            listOf(SignalFired("APP_RUNTIME_008", 0.94f, "CRITICAL", "synthetic_identity")),
            "BLOCK", 96),
        14 to ScenarioDef("NBFC Insider Burst",        "INSIDER_BURST_SIGNAL",
            mapOf("enrollment_velocity_60s" to 5, "off_hours_enrollment" to true,
                  "device_account_degree" to 5, "device_reuse_count" to 18),
            listOf(SignalFired("USR_BEH_003", 0.93f, "HIGH", "beneficiary_abuse")),
            "BLOCK", 88),
        15 to ScenarioDef("Investment / Romance Scam", "INVESTMENT_SCAM_SIGNAL",
            mapOf("dating_apps_detected" to 3, "first_large_foreign_tx" to true),
            listOf(SignalFired("SCAM_RS_001", 0.60f, "MEDIUM", "investment_fraud_detector"),
                   SignalFired("SCAM_RS_001", 0.72f, "MEDIUM", "investment_fraud_detector")),
            "STEP_UP", 52),
        16 to ScenarioDef("Organized Crime Ring",      "ORG_CRIME_RING_SIGNAL",
            mapOf("oc_cluster_match" to true, "shared_ip_ring" to true,
                  "cluster_size" to 14, "timing_rhythm_detected" to true,
                  "device_account_degree" to 12, "device_reuse_count" to 38),
            listOf(SignalFired("BOT_APP_011", 0.91f, "CRITICAL", "organized_crime_cluster"),
                   SignalFired("BOT_APP_011", 0.86f, "CRITICAL", "organized_crime_cluster")),
            "BLOCK", 94),
    )

    // ── Ingest scenario through real pipeline ─────────────────────────────────

    /**
     * Ingest a fraud scenario through the REAL backend pipeline.
     *
     * Flow (production path):
     *   Android app → NGINX (5-phase Lua pipeline) → POST /api/v1/ingest
     *   → DeviceAuthenticator → CryptoGate → EIP → CompositeDecisionService
     *   → EvidenceRecord written to Postgres → SOC dashboard reflects the event
     *
     * Requirements:
     *   - NONASHIELD_BASE_URL must point to the NGINX gateway (not directly to
     *     the backend) so NGINX stamps X-PS-Edge-Context before forwarding.
     *   - The demo device must be enrolled (SessionHolder must hold a real JWT).
     *   - PinningInterceptor attaches the HMAC device-auth headers automatically.
     *
     * Response:
     *   The real ingest endpoint returns {action, event_id, trust_level}.
     *   When X-PS-Trace: true is sent and APP_ENV != prod, the backend also
     *   returns pipeline_trace {eip_total_ms, composite_score, flags}.
     *
     * Falls back to offline simulation when the backend is unreachable, so the
     * demo always shows something — fromSimulation=true is clearly labelled.
     *
     * @param scenarioId  1–16 (maps to the 16 NonaShield use cases)
     * @param tenantId    demo tenant identifier
     */
    fun ingestScenario(
        scenarioId: Int,
        tenantId:   String = "demo_tenant",
    ): ScenarioResult {
        val scenario = SCENARIO_DEFS[scenarioId] ?: SCENARIO_DEFS[7]!!

        val session   = SessionHolder.session
        val deviceId  = session?.deviceId ?: "demo_${java.util.UUID.randomUUID().toString().take(12)}"
        val nonce     = java.util.UUID.randomUUID().toString()
        val timestamp = System.currentTimeMillis()

        // Build IngestEnvelope payload from the scenario's signal set.
        val payloadJson = JSONObject(scenario.signals as Map<*, *>)

        // HMAC-SHA256 signature of the payload — CryptoGate validates this.
        // DeviceKeyManager uses the AndroidKeyStore-backed key (never leaves the device).
        val sig = try {
            val payloadBytes = payloadJson.toString().toByteArray()
            val hmacBytes    = keyManager.sign(payloadBytes)
            android.util.Base64.encodeToString(hmacBytes, android.util.Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.w(TAG, "keyManager.sign failed — cannot build signed envelope: ${e.message}")
            return simulatedScenarioResult(scenarioId)
        }

        val envelope = JSONObject().apply {
            put("device_id",   deviceId)
            put("event_type",  scenario.eventType)
            put("timestamp",   timestamp)
            put("signature",   sig)
            put("tenant_id",   tenantId)
            put("nonce",       nonce)
            put("payload",     payloadJson)
            put("sdk_version", "2.0.0")
        }

        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/ingest")
            .post(envelope.toString().toRequestBody(JSON))
            // Device-auth headers — DeviceAuthenticator validates these on the backend
            .header("x-device-id", deviceId)
            .header("x-timestamp", (timestamp / 1000).toString())
            .header("x-nonce",     nonce)
            // Request pipeline trace in non-prod so demo app can surface timings
            .header("X-PS-Trace", "true")
            .apply { session?.jwt?.let { header("Authorization", "Bearer $it") } }
            // Note: PinningInterceptor adds X-PS-Request-Hash + other PayShield headers
            // Note: NGINX stamps X-PS-Edge-Context — NONASHIELD_BASE_URL must point to NGINX
            .build()

        val callStart = System.currentTimeMillis()
        return try {
            client.newCall(request).execute().use { response ->
                val rttMs   = (System.currentTimeMillis() - callStart).toInt()
                // NGINX stamps X-Request-Time (microseconds); convert to ms.
                val nginxMs = response.header("X-Request-Time")?.toDoubleOrNull()
                    ?.let { (it / 1000).toInt() } ?: 0

                val body = response.body?.string() ?: ""
                val j    = runCatching { JSONObject(body) }.getOrDefault(JSONObject())

                if (!response.isSuccessful && response.code !in setOf(403, 409)) {
                    Log.w(TAG, "ingestScenario HTTP ${response.code} — using simulation")
                    return simulatedScenarioResult(scenarioId)
                }

                // Normalise action: 403 = BLOCK (edge or composite veto)
                val decision = when {
                    response.code == 403       -> "BLOCK"
                    response.code == 409       -> "BLOCK"   // replay = blocked
                    else -> when (j.optString("action", "MONITOR")) {
                        "BLOCK", "REJECTED"    -> "BLOCK"
                        "STEP_UP"              -> "STEP_UP"
                        else                   -> "ALLOW"
                    }
                }

                val trace         = j.optJSONObject("pipeline_trace")
                val eipMs         = trace?.optInt("eip_total_ms", 0) ?: 0
                val cScore        = trace?.optInt("composite_score", 0) ?: 0
                val p3Ms          = trace?.optInt("compliance_ms",  0) ?: 0
                val p4Ms          = trace?.optInt("ml_ms",          0) ?: 0
                val p5Ms          = trace?.optInt("threat_ms",      0) ?: 0
                val modsArr       = trace?.optJSONArray("modules_hit")
                val modsList      = (0 until (modsArr?.length() ?: 0)).map { modsArr!!.getString(it) }
                val evHash        = j.optString("evidence_hash", "")
                val decisionReason = j.optString("reason", "")

                ScenarioResult(
                    scenarioId         = scenarioId,
                    scenarioName       = scenario.name,
                    eventId            = j.optString("event_id", ""),
                    decision           = decision,
                    trustLevel         = j.optString("trust_level", ""),
                    riskScore          = j.optInt("risk_score", scenario.riskScore),
                    ruleVersion        = j.optString("rule_version", ""),
                    mlScore            = j.optDouble("ml_score", 0.0).toFloat(),
                    mlFallback         = j.optBoolean("ml_fallback", false),
                    compositeScore     = cScore,
                    eipTotalMs         = eipMs,
                    nginxMs            = nginxMs,
                    rttMs              = rttMs,
                    signalsFired       = scenario.signalDefs,
                    fromSimulation     = false,
                    phase3ComplianceMs = p3Ms,
                    phase4MlMs         = p4Ms,
                    phase5ThreatsMs    = p5Ms,
                    modulesHit         = modsList,
                    evidenceHash       = evHash,
                    reason             = decisionReason,
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "ingestScenario network error — using simulation: ${e.message}")
            simulatedScenarioResult(scenarioId)
        }
    }

    /**
     * Offline simulation — returned when backend / NGINX is unreachable.
     * fromSimulation=true allows the UI to show a clear "SIM" badge.
     * Values are representative estimates, not real pipeline measurements.
     */
    private fun simulatedScenarioResult(scenarioId: Int): ScenarioResult {
        val scenario  = SCENARIO_DEFS[scenarioId] ?: SCENARIO_DEFS[7]!!
        val eventId   = "sim_${System.currentTimeMillis().toString(16)}"
        val simReason = when (scenario.decision) {
            "BLOCK"   -> "Threat signals confirmed — request blocked by security policy"
            "STEP_UP" -> "Elevated risk score — step-up authentication required"
            else      -> "No active threats — request allowed"
        }
        val simModules = when {
            scenario.decision == "BLOCK"   -> listOf("compliance_evaluator", "ml_engine", "threat_executor", "botnet_correlation")
            scenario.decision == "STEP_UP" -> listOf("compliance_evaluator", "ml_engine", "threat_executor")
            else                           -> listOf("compliance_evaluator", "ml_engine")
        }
        val simEipMs = (55..95).random()
        return ScenarioResult(
            scenarioId         = scenarioId,
            scenarioName       = scenario.name,
            eventId            = eventId,
            decision           = scenario.decision,
            trustLevel         = "SIMULATED",
            riskScore          = scenario.riskScore,
            ruleVersion        = "2.3.1",
            mlScore            = scenario.riskScore / 100f,
            mlFallback         = true,
            compositeScore     = 0,
            eipTotalMs         = simEipMs,
            nginxMs            = 0,
            rttMs              = simEipMs + (18..35).random(),
            signalsFired       = scenario.signalDefs,
            fromSimulation     = true,
            phase3ComplianceMs = (22..44).random(),
            phase4MlMs         = (14..32).random(),
            phase5ThreatsMs    = (8..18).random(),
            modulesHit         = simModules,
            evidenceHash       = "sha256:${eventId.hashCode().toUInt().toString(16).padStart(16, '0')}",
            reason             = simReason,
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
                    dataSource     = j.optString("data_source", "live"),
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "getDashboardStats: ${e.message}")
            simulatedDashboardStats()
        }
    }

    private fun simulatedDashboardStats(): DashboardStats {
        // Fixed representative values — backend unreachable. dataSource="fallback"
        // lets SocDashboardActivity show a banner so operators know the source.
        val total   = 1423
        val blocked = 99
        val stepUp  = 156
        return DashboardStats(
            totalDecisions = total,
            blockedCount   = blocked,
            stepUpCount    = stepUp,
            allowedCount   = total - blocked - stepUp,
            avgRiskScore   = 0.2341f,
            activeDevices  = 284,
            period         = "last_24h",
            dataSource     = "fallback",
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
    val raspPct:        Int    = 38,
    val networkPct:     Int    = 22,
    val bioPct:         Int    = 18,
    val appPct:         Int    = 22,
    // "live" when data comes from Postgres; "fallback" when DB was unavailable
    val dataSource:     String = "live",
) {
    // Convenience aliases used by SocDashboardActivity
    val total:      Int     get() = totalDecisions
    val blocked:    Int     get() = blockedCount
    val stepUp:     Int     get() = stepUpCount
    val allowed:    Int     get() = allowedCount
    val avgRisk:    Float   get() = avgRiskScore
    val isLiveData: Boolean get() = dataSource == "live"
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
 * Result of POST /api/v1/ingest through the real NGINX → backend pipeline.
 *
 * The demo app sends a real IngestEnvelope through the full auth chain:
 *   NGINX (5-phase) → DeviceAuthenticator → CryptoGate → EIP → CompositeDecisionService
 *
 * Timing fields:
 *   nginxMs        — from X-Request-Time response header (stamped by NGINX)
 *   eipTotalMs     — EIP + CompositeDecisionService (from X-PS-Trace response body)
 *   rttMs          — full client-measured round-trip time
 *
 * fromSimulation=true means the backend was unreachable; values are estimates
 * and the UI shows a clear "SIM" badge.
 */
data class ScenarioResult(
    val scenarioId:         Int,
    val scenarioName:       String,
    val eventId:            String,
    val decision:           String,    // BLOCK | STEP_UP | ALLOW
    val trustLevel:         String,    // TRUSTED | REJECTED | STEP_UP | SIMULATED
    val riskScore:          Int,       // 0–100 (from EIP fraud_risk_score)
    val ruleVersion:        String,
    val mlScore:            Float,
    val mlFallback:         Boolean,
    val compositeScore:     Int,       // CompositeDecisionService composite_score (0–100)
    val eipTotalMs:         Int,       // backend EIP processing time (from X-PS-Trace)
    val nginxMs:            Int,       // NGINX edge time (from X-Request-Time header)
    val rttMs:              Int,       // full client-measured RTT
    val signalsFired:       List<SignalFired>,  // SDK signal definitions for this scenario
    val fromSimulation:     Boolean,
    // Phase breakdown timings (ms) — parsed from pipeline_trace or estimated in simulation
    val phase3ComplianceMs: Int             = 0,
    val phase4MlMs:         Int             = 0,
    val phase5ThreatsMs:    Int             = 0,
    // Modules that ran in the backend pipeline (for UI display)
    val modulesHit:         List<String>    = emptyList(),
    // SHA-256 evidence chain hash returned by the backend
    val evidenceHash:       String          = "",
    // Human-readable reason for the decision
    val reason:             String          = "",
) {
    /** Alias for backward compatibility — total backend pipeline time = eipTotalMs. */
    val totalMs: Int get() = eipTotalMs
}
