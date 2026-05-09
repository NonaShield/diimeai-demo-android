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
                            status        = json.optString("status", "PENDING")
                        )
                    }
                    response.code == 403 -> {
                        // NonaShield blocked this request
                        val json = runCatching { JSONObject(responseBody) }.getOrDefault(JSONObject())
                        PaymentResult.Blocked(
                            reason = json.optString("detail", "Request blocked by security policy")
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
                    challengeType = json.optString("challenge_type", "")
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
    data class Success(val transactionId: String, val status: String)   : PaymentResult()
    data class Blocked(val reason: String)                              : PaymentResult()
    data class StepUpRequired(val challengeType: String)                : PaymentResult()
    data class Failure(val reason: String)                              : PaymentResult()
}

data class GatewayDecision(
    val allowed:       Boolean,
    val action:        String,
    val decisionId:    String,
    val reason:        String,
    val challengeType: String = ""
)
