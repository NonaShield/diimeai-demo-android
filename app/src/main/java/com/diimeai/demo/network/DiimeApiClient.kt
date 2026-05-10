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
     */
    fun getBindingProof(deviceId: String): BindingProof? {
        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/device/$deviceId/binding-proof")
            .get()
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
     */
    fun getEvidenceReceipt(decisionId: String): EvidenceReceipt? {
        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/evidence/$decisionId/receipt")
            .get()
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

        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/verify/gateway")
            .post(body.toRequestBody(JSON))
            .build()

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
