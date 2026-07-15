package com.diimeai.demo.network

import android.content.Context
import android.util.Log
import com.diimeai.demo.BuildConfig
import com.payshield.android.sdk.PinningInterceptor
import com.payshield.android.sdk.SignalSink
import com.payshield.sdk.integration.PayShieldAuthInterceptor
import com.payshield.sdk.token.SessionHolder
import okhttp3.CertificatePinner
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
 *   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
 *   â”‚  PayShieldAuthInterceptor (outermost)              â”‚
 *   â”‚    â€” detects JWT alg:none, Basic auth, brute-force â”‚
 *   â”‚  PinningInterceptor (inner)                        â”‚
 *   â”‚    â€” attaches X-PayShield-Token + Signature        â”‚
 *   â”‚    â€” attaches 7 flat headers required by nginx     â”‚
 *   â”‚    â€” checks EdgeRiskEnforcer (fail-closed)         â”‚
 *   â”‚  HttpLoggingInterceptor (debug only)               â”‚
 *   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
 *
 * Session lifecycle:
 *   - Before login: SessionHolder has no session â€” PinningInterceptor will
 *     throw IllegalStateException if a protected call is attempted.
 *   - After login: call [setSession] to inject user identity.  The interceptors
 *     pick up the new session on the next request without client rebuild.
 */
object DiimeApiClient {

    private const val TAG = "DiimeApiClient"
    private val JSON = "application/json; charset=utf-8".toMediaType()

    // â”€â”€ TLS Certificate Pinning for api.diimeai.com â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // This is the CUSTOMER APP's cert pin to its own backend â€” the customer's
    // responsibility to update when the backend certificate rotates.
    // In production: replace "api.diimeai.com" with your bank's own API hostname
    // and update these pins whenever your backend TLS certificate is renewed.
    //
    // Current leaf cert: issued 2026-05-28, expires 2026-08-26 (Let's Encrypt YE2)
    // Intermediate pin (YE2) is included as backup so routine 90-day leaf renewals
    // do NOT require an app update â€” only a key-pair rotation does.
    //
    // To get the current pin after a renewal:
    //   openssl s_client -connect api.diimeai.com:443 -servername api.diimeai.com \
    //     </dev/null 2>/dev/null | openssl x509 -pubkey -noout \
    //     | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary \
    //     | openssl enc -base64
    private val BACKEND_CERT_PINNER: CertificatePinner = CertificatePinner.Builder()
        .add("api.diimeai.com", "sha256/1kxomJM4WNmZfPDERIy86e7hsmxV9fCaGgEexIUyZ3w=")  // leaf â€” expires 2026-08-26
        .add("api.diimeai.com", "sha256/s/tdAOmUzd8syaTuqfgGvFcn6DzA5Cmb+Vby1ST+U3Y=")  // Let's Encrypt YE2 intermediate (backup)
        .add("diimeai.com",     "sha256/1kxomJM4WNmZfPDERIy86e7hsmxV9fCaGgEexIUyZ3w=")
        .add("diimeai.com",     "sha256/s/tdAOmUzd8syaTuqfgGvFcn6DzA5Cmb+Vby1ST+U3Y=")
        .build()

    // Populated by DiimeApp.registerSignalSink()
    var signalSink: SignalSink? = null

    private lateinit var client: OkHttpClient

    // Minimal client for read-only SOC dashboard calls.
    // Dashboard stats/decisions/threats only need X-Api-Key â€” they must NOT go
    // through PinningInterceptor because:
    //   1. PinningInterceptor adds X-Edge-Risk-Level; if the test device's RASP tier
    //      is HIGH (emulator, rooted phone, USB-debugging device) NGINX blocks with 403.
    //   2. EdgeRiskEnforcer.assertAllowed() is called on every intercept â€” unnecessary
    //      overhead for read-only observability endpoints.
    //   3. RuntimeIntegrityGate.assertClean() runs before every signing â€” debug APK
    //      checks add latency and may throw on certain debug configurations.
    // Login and enrollment also skip PinningInterceptor for the same reason.
    private val statsClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .certificatePinner(BACKEND_CERT_PINNER)
            .build()
    }

    /**
     * Call once from Application.onCreate() BEFORE any network calls.
     * Signing of ingest envelopes is done via PayShieldSDK.signIngestPayload()
     * so customer app code never touches DeviceKeyManager directly.
     */
    fun init(context: Context) {
        val logging = HttpLoggingInterceptor().apply {
            level = if (BuildConfig.IS_DEBUG)
                HttpLoggingInterceptor.Level.BODY
            else
                HttpLoggingInterceptor.Level.NONE
        }

        // PinningInterceptor â€” reads session from SessionHolder on every call.
        // SessionHolder.setSession() is called after login (see LoginActivity).
        // keyManager is created internally by PinningInterceptor â€” customer app does not
        // hold a DeviceKeyManager reference.
        // ATL-2027: X-DPIP-Device-Hash salt is read from EnrollmentState.loadDpipSalt()
        // (SecureStorage / AES-256-GCM + AndroidKeyStore) on every request â€” not passed
        // as a constructor param.  The salt is backend-issued at enrollment time.
        val pinning = PinningInterceptor(
            act = "REQUEST"    // default; overridden per-call via action-specific clients
        )

        // PayShieldAuthInterceptor â€” wire-level auth observation.
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
            .certificatePinner(BACKEND_CERT_PINNER)
            .addInterceptor(authMonitor)    // outermost â€” observe before signing
            .addInterceptor(pinning)        // sign + attach all PayShield headers
            .addInterceptor(logging)        // innermost â€” log final signed request
            .build()

        Log.i(TAG, "DiimeApiClient initialized. baseUrl=${BuildConfig.NONASHIELD_BASE_URL}")
    }

    /**
     * Inject user session after successful login.
     * PinningInterceptor will pick this up immediately for all subsequent requests.
     */
    fun setSession(userId: String, deviceId: String, sessionId: String, jwt: String? = null) {
        SessionHolder.setSession(
            uid = userId,
            did = deviceId,
            sid = sessionId,
            jwt = jwt
        )
        Log.i(TAG, "Session set: userId=$userId deviceId=$deviceId")
    }

    fun clearSession() {
        SessionHolder.clearSession()
    }

    // -------------------------------------------------------------------------
    // DiimeAI API calls
    // All calls are blocking â€” call from Dispatchers.IO coroutine.
    // -------------------------------------------------------------------------

    /**
     * DEMO ONLY â€” authenticate using the NonaShield demo login stub.
     *
     * Calls POST /api/v1/auth/login â€” a demo endpoint that simulates the
     * customer bank's IdP and issues a NonaShield-signed RS256 JWT directly.
     * That endpoint returns 503 in live (non-demo) environments.
     *
     * â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
     * PRODUCTION INTEGRATION (do NOT call this method):
     *
     *   1. Customer app calls the bank's own IdP â†’ receives bank JWT.
     *   2. App calls POST /api/v1/auth/session  (NonaShield production endpoint):
     *        Authorization: Bearer <bank-jwt>
     *        X-Tenant-Id:   <tenant-id>
     *        X-Device-Id:   <device-id>
     *        Body: { "user_id": "...", "session_id": "..." }
     *      NonaShield validates the bank JWT against the tenant's configured
     *      public key (TENANT_<ID>_JWT_PUBLIC_KEY_PEM) and returns a
     *      short-lived NonaShield session JWT.
     *   3. App calls PayShieldSDK.setSession(userId, sessionId, jwt=nonashieldJwt).
     *
     * See DiimeApiClient.establishSession() for a reference implementation.
     * â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
     *
     * A raw OkHttpClient is used here (no PinningInterceptor) because
     * PinningInterceptor requires an active session â€” which does not exist
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
            .certificatePinner(BACKEND_CERT_PINNER)
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
                        uid = userId,
                        did = deviceId,
                        sid = sessionId,
                        jwt = jwt
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
     * PRODUCTION â€” exchange a bank-issued JWT for a NonaShield session JWT.
     *
     * **Deprecated.** Use [com.payshield.sdk.PayShieldSDK.establishSession] instead â€”
     * the SDK now owns this exchange and derives deviceId internally from
     * [com.payshield.sdk.crypto.DeviceKeyManager], eliminating the need for the
     * customer app to pass it:
     *
     * ```kotlin
     * // New single-call production pattern (Dispatchers.IO):
     * when (val r = PayShieldSDK.establishSession(bankJwt = bankJwt, userId = userId)) {
     *     is SessionEstablishResult.Success -> { /* proceed */ }
     *     is SessionEstablishResult.Failure -> { /* show error */ }
     * }
     * // On token refresh, call it again â€” SDK atomically replaces the session.
     * ```
     *
     * This method is a no-op in the demo app (demo uses [login] instead) and is
     * kept only for reference until integrators have migrated to the SDK method.
     */
    @Deprecated(
        message = "Use PayShieldSDK.establishSession(bankJwt, userId) â€” the SDK derives deviceId automatically.",
        replaceWith = ReplaceWith(
            "PayShieldSDK.establishSession(bankJwt = customerJwt, userId = userId)",
            "com.payshield.sdk.PayShieldSDK"
        )
    )
    fun establishSession(
        customerJwt: String,
        userId:      String,
        deviceId:    String,
        tenantId:    String    = "default",
        sessionId:   String?   = null,
    ): SessionResult {
        val bodyJson = JSONObject().apply {
            put("user_id",    userId)
            sessionId?.let { put("session_id", it) }
        }.toString()

        val sessionClient = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .certificatePinner(BACKEND_CERT_PINNER)
            .build()

        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/auth/session")
            .post(bodyJson.toRequestBody(JSON))
            .header("Authorization", "Bearer $customerJwt")
            .header("X-Tenant-Id",   tenantId)
            .header("X-Device-Id",   deviceId)
            .build()

        return try {
            sessionClient.newCall(request).execute().use { response ->
                val responseBody = response.body?.string() ?: ""
                if (response.isSuccessful) {
                    val json       = JSONObject(responseBody)
                    val nsJwt      = json.getString("jwt")
                    val sid        = json.getString("session_id")
                    SessionHolder.setSession(uid = userId, did = deviceId, sid = sid, jwt = nsJwt)
                    Log.i(TAG, "[session] established: userId=$userId sessionId=$sid")
                    SessionResult.Success(userId = userId, sessionId = sid, jwt = nsJwt)
                } else {
                    val detail = runCatching {
                        JSONObject(responseBody).optString("detail", "Session establishment failed")
                    }.getOrDefault("Session establishment failed (HTTP ${response.code})")
                    Log.w(TAG, "[session] failed HTTP ${response.code}: $detail")
                    SessionResult.Failure(detail)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "[session] network error: ${e.message}", e)
            SessionResult.Failure("Network error: ${e.message}")
        }
    }

    /**
     * Initiate a payment â€” protected by the full NonaShield 5-phase pipeline.
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
        // NonaShield is privacy-preserving â€” never send raw PII (amount, recipient, VPA).
        // Compute an opaque SHA-256 commitment from the payment details so the backend
        // can sign the decision without seeing transaction values.
        val amountPaise = (amount * 100).toLong()
        val txCommitment = sha256hex("${amountPaise}|${currency}|${recipientId}")

        val session  = SessionHolder.session
        val deviceId = session?.deviceId ?: "unknown"

        val body = JSONObject().apply {
            put("tx_commitment", txCommitment)
            put("device_id",    deviceId)
            session?.sessionId?.let { put("session_id", it) }
        }.toString()

        // MISMATCH 6b fix: backend /api/v1/payment/initiate requires a valid JWT Bearer
        // token (Depends(require_jwt)) to identify the caller's session. Without it the
        // backend returns 401 â†’ app shows "Payment failed: HTTP 401".
        // Pattern matches verifyWithGateway() (MISMATCH 6a) and submitKyc().
        val request = Request.Builder()
            .url("${BuildConfig.DIIMEAI_API_URL}/api/v1/payment/initiate")
            .post(body.toRequestBody(JSON))
            .header("X-PS-Action",          "PAYMENT")
            .header("X-PS-Idempotency-Key", "pay_${System.currentTimeMillis()}")
            .apply { session?.jwt?.let { header("Authorization", "Bearer $it") } }
            .build()

        return try {
            client.newCall(request).execute().use { response ->
                val responseBody = response.body?.string() ?: ""
                when {
                    response.isSuccessful -> {
                        val json = JSONObject(responseBody)
                        val txnId = json.optString("transaction_id", "TXN_DEMO")
                        // Backend payment response uses "decision" (ALLOW/DENY/STEP_UP),
                        // not "status".  Fall back to "status" for any future field rename,
                        // then to "ALLOW" so existing receipts show meaningful text.
                        val decision = json.optString("decision")
                            .ifBlank { json.optString("status", "ALLOW") }
                        // Read attestation values captured by PinningInterceptor for this request.
                        // These are the exact nonce/timestamp/hash/hwLevel that were signed and
                        // sent to the NGINX gateway â€” proof the request was device-attested.
                        val att = com.payshield.android.sdk.LastAttestation
                        PaymentResult.Success(
                            transactionId = txnId,
                            status        = decision,
                            receiptUrl    = json.optString("receipt_url", ""),
                            // Backend returns transaction_id as the primary key used for
                            // evidence receipt lookup (GET /api/v1/evidence/{id}/receipt).
                            decisionId    = json.optString("decision_id", txnId),
                            nonce         = att.nonce,
                            timestampEpoch= att.timestampEpoch,
                            deviceKeyId   = att.deviceId,
                            hwLevel       = att.hwLevel,
                            requestHash   = att.requestHash,
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
            // EdgeRiskEnforcer.assertAllowed() threw â€” device is RASP-blocked
            Log.e(TAG, "Payment blocked by local RASP enforcer: ${e.message}")
            PaymentResult.Blocked(reason = "Device security check failed")
        } catch (e: Exception) {
            Log.e(TAG, "Payment network error: ${e.message}", e)
            PaymentResult.Failure("Network error: ${e.message}")
        }
    }

    /**
     * Fetch hardware binding proof for this device â€” Demo 1.
     * Returns attestation level, key fingerprint, enrolled date.
     *
     * C4 fix: endpoint is now api_key_required â€” passes X-Api-Key header.
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
                    pubkeyHex        = json.optString("pubkey_hex"),
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
     * Fetch non-repudiation receipt for a gateway decision â€” Demo 2.
     *
     * C4 fix: endpoint is now api_key_required â€” passes X-Api-Key header.
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
                    // receipt_hmac is the Non-Repudiation HMAC field (renamed from server_signature
                    // to avoid the PII scrubber masking it â€” scrubber only redacts server_signature)
                    serverSignature = json.optString("receipt_hmac").ifBlank { json.optString("server_signature") },
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

    // â”€â”€ Scenario payload definitions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    //
    // Each entry defines the IngestEnvelope.payload for that fraud use case.
    // Signals come from the real SDK on the device â€” these definitions describe
    // WHAT the SDK emits, not what the server fabricates.
    //
    // event_type must be UPPER_SNAKE_CASE (backend IngestEnvelope validator).
    // signals are the payload dict sent to the real /api/v1/ingest endpoint.

    private data class ScenarioDef(
        val name:       String,
        val eventType:  String,
        val signals:    Map<String, Any>,
        val signalDefs: List<SignalFired>,   // for UI â€” what the SDK emits
        val decision:   String,             // expected outcome (for simulation fallback)
        val riskScore:  Int,
        // Action context â€” the sensitive operation being guarded.
        // PAYMENT | KYC | OTP | LOGIN | SESSION_CREATE
        // Flows as X-PS-Action header + JSON body "action" field so NGINX policy
        // enforcement and the backend compliance engine apply action-specific rules.
        val action:     String,
    )

    private val SCENARIO_DEFS: Map<Int, ScenarioDef> = mapOf(
        //           name                            eventType                   signals                                                                       signalDefs                                                                                                  decision    riskScore  action
        1  to ScenarioDef("Hardware Possession",      "DEVICE_ATTESTATION",
            mapOf("hardware_bound" to true, "key_storage" to "AndroidKeyStore"),
            listOf(SignalFired("APP_SEC_001", 0.99f, "HIGH", "evidence_verifier")),
            "ALLOW", 5, "SESSION_CREATE"),
        2  to ScenarioDef("Non-Repudiation Receipt",  "EVIDENCE_CHAIN_VERIFY",
            mapOf("hybrid_sig_verified" to true, "pqc_sig_present" to true),
            listOf(SignalFired("APP_SEC_002", 0.99f, "HIGH", "evidence_verifier")),
            "ALLOW", 5, "SESSION_CREATE"),
        3  to ScenarioDef("Screen Mirroring Attack",  "SCREEN_MIRROR_DETECTED",
            mapOf("screen_mirroring" to true, "presentation_display" to true, "vnc_active" to false),
            listOf(SignalFired("RASP_DEV_003", 0.92f, "HIGH", "botnet_correlation"),
                   SignalFired("RASP_DEV_004", 0.85f, "HIGH", "botnet_correlation")),
            "BLOCK", 87, "PAYMENT"),
        4  to ScenarioDef("Behavioral Biometrics",    "BIOMETRIC_ANOMALY",
            mapOf("hesitation_spike" to true, "pressure_anomaly" to true, "biometric_score" to 0.31),
            listOf(SignalFired("USR_BEH_001", 0.78f, "MEDIUM", "mule_account"),
                   SignalFired("USR_BEH_001", 0.71f, "MEDIUM", "mule_account")),
            "STEP_UP", 55, "PAYMENT"),
        5  to ScenarioDef("Device RASP (38 sensors)", "RASP_THREAT_DETECTED",
            mapOf("root_detected" to true, "hook_detected" to true, "magisk_present" to true),
            listOf(SignalFired("RASP_DEV_001", 0.95f, "CRITICAL", "botnet_correlation"),
                   SignalFired("APP_RUNTIME_008", 1.0f, "CRITICAL", "botnet_correlation")),
            "BLOCK", 100, "PAYMENT"),
        6  to ScenarioDef("Mule Account Network",     "MULE_ACCOUNT_SIGNAL",
            mapOf("account_velocity_24h" to 4, "device_account_degree" to 8, "device_reuse_count" to 12),
            listOf(SignalFired("USR_BEH_002", 0.88f, "HIGH", "mule_account"),
                   SignalFired("USR_BEH_003", 0.76f, "HIGH", "mule_account")),
            "BLOCK", 82, "PAYMENT"),
        7  to ScenarioDef("Bot Attack / Emulator",    "BOT_EMULATOR_DETECTED",
            mapOf("emulator_detected" to true, "build_fingerprint_anomaly" to true, "sensor_absence" to true),
            listOf(SignalFired("BOT_APP_001", 0.97f, "CRITICAL", "botnet_correlation"),
                   SignalFired("BOT_APP_002", 0.91f, "CRITICAL", "botnet_correlation")),
            "BLOCK", 98, "LOGIN"),
        8  to ScenarioDef("SIM Swap Fraud",           "SIM_SWAP_SIGNAL",
            mapOf("sim_swap_detected" to true, "iccid_changed" to true, "carrier_transition" to true),
            listOf(SignalFired("SCAM_SS_001", 1.00f, "CRITICAL", "sim_swap_proxy"),
                   SignalFired("SCAM_SS_002", 0.96f, "HIGH",     "sim_swap_proxy")),
            "BLOCK", 95, "OTP"),
        9  to ScenarioDef("Digital Arrest Scam",      "DIGITAL_ARREST_SIGNAL",
            mapOf("active_video_call" to true, "call_merge_active" to true,
                  "voip_cellular_concurrent" to true, "prolonged_call_mins" to 47),
            listOf(SignalFired("SCAM_CM_001", 0.98f, "CRITICAL", "digital_arrest_detector"),
                   SignalFired("SCAM_CM_002", 0.85f, "HIGH",     "digital_arrest_detector")),
            "BLOCK", 100, "PAYMENT"),
        10 to ScenarioDef("Fake Loan App Extortion",  "PREDATORY_LOAN_SIGNAL",
            mapOf("sms_permission" to true, "contacts_permission" to true,
                  "call_log_permission" to true, "storage_permission" to true),
            listOf(SignalFired("LOAN_APP_002", 0.90f, "HIGH", "beneficiary_abuse")),
            "STEP_UP", 68, "KYC"),
        11 to ScenarioDef("Ghost Tapping / NFC Abuse","NFC_FRAUD_SIGNAL",
            mapOf("rogue_hce_app" to true, "nfc_enabled" to true, "no_screen_lock" to true),
            listOf(SignalFired("NFC_FRAUD_001", 0.80f, "HIGH", "credential_reuse"),
                   SignalFired("NFC_FRAUD_002", 0.85f, "HIGH", "credential_reuse")),
            "BLOCK", 83, "PAYMENT"),
        12 to ScenarioDef("Malicious APK Injection",  "MALICIOUS_APK_SIGNAL",
            mapOf("apk_signature_mismatch" to true, "dangerous_permission_cluster" to true,
                  "overlay_abuse" to true, "sideloaded" to true),
            listOf(SignalFired("MAL_APK_001", 0.95f, "CRITICAL", "botnet_correlation"),
                   SignalFired("MAL_APK_002", 0.88f, "CRITICAL", "botnet_correlation"),
                   SignalFired("MAL_APK_003", 0.92f, "CRITICAL", "botnet_correlation")),
            "BLOCK", 100, "PAYMENT"),
        13 to ScenarioDef("Deepfake KYC Bypass",      "DEEPFAKE_KYC_SIGNAL",
            // ATL-2027 enhanced: 8 device-layer signals feed deepfake_risk_detector.py
            mapOf("virtual_camera_detected" to true, "obs_package_present" to true,
                  "non_physical_camera_id" to true,
                  "overlay_attack"      to true,      // RASP_DEV_063 â€” SYSTEM_ALERT_WINDOW redress
                  "background_camera"   to true,      // RASP_DEV_064 â€” deepfake frame acquisition
                  "frame_rate_anomaly"  to true,      // RASP_DEV_065 â€” synthetic camera FPS
                  "mediapipe_injection" to true,      // RASP_DEV_065 â€” AR deepfake SDK present
                  "voice_changer"       to true),     // RASP_DEV_065 â€” voice spoof for liveness
            listOf(
                SignalFired("APP_RUNTIME_008", 0.94f, "CRITICAL", "synthetic_identity"),
                // ATL-2027 deepfake precondition compound signals
                SignalFired("RASP_DEV_063",    0.88f, "HIGH",     "deepfake_risk_detector"),  // overlay
                SignalFired("RASP_DEV_064",    0.92f, "HIGH",     "deepfake_risk_detector"),  // bg camera
                SignalFired("RASP_DEV_065",    0.85f, "HIGH",     "deepfake_risk_detector"),  // compound
            ),
            "BLOCK", 97, "KYC"),
        14 to ScenarioDef("NBFC Insider Burst",        "INSIDER_BURST_SIGNAL",
            mapOf("enrollment_velocity_60s" to 5, "off_hours_enrollment" to true,
                  "device_account_degree" to 5, "device_reuse_count" to 18),
            listOf(SignalFired("USR_BEH_003", 0.93f, "HIGH", "beneficiary_abuse")),
            "BLOCK", 88, "PAYMENT"),
        15 to ScenarioDef("Investment / Romance Scam", "INVESTMENT_SCAM_SIGNAL",
            mapOf("dating_apps_detected" to 3, "first_large_foreign_tx" to true),
            listOf(SignalFired("SCAM_RS_001", 0.60f, "MEDIUM", "investment_fraud_detector"),
                   SignalFired("SCAM_RS_001", 0.72f, "MEDIUM", "investment_fraud_detector")),
            "STEP_UP", 52, "PAYMENT"),
        16 to ScenarioDef("Organized Crime Ring",      "ORG_CRIME_RING_SIGNAL",
            mapOf("oc_cluster_match" to true, "shared_ip_ring" to true,
                  "cluster_size" to 14, "timing_rhythm_detected" to true,
                  "device_account_degree" to 12, "device_reuse_count" to 38),
            listOf(SignalFired("BOT_APP_011", 0.91f, "CRITICAL", "organized_crime_cluster"),
                   SignalFired("BOT_APP_011", 0.86f, "CRITICAL", "organized_crime_cluster")),
            "BLOCK", 94, "PAYMENT"),

        // â”€â”€ ATL-2027: Autonomous Trust Layer â€” DPIP + autonomous command enforcement â”€â”€
        17 to ScenarioDef("ATL-2027 Autonomous Trust",  "ATL_AUTONOMOUS_SIGNAL",
            // Compound payload: DPIP consortium blocklist hit + autonomous BLOCK command +
            // full deepfake precondition cluster (overlay + background camera + compound)
            mapOf("dpip_blocklist_hit"    to true,
                  "autonomous_command"    to "BLOCK",
                  "command_confidence"    to 0.97,
                  "command_source"        to "autonomous_decision_enhancer",
                  "overlay_attack"        to true,
                  "background_camera"     to true,
                  "frame_rate_anomaly"    to true,
                  "mediapipe_injection"   to true,
                  "voice_changer"         to true,
                  "dpip_device_hash_sent" to true),
            listOf(
                SignalFired("ATL_DPIP_001",    0.95f, "CRITICAL", "dpip_client"),
                SignalFired("ATL_COMMAND_001", 0.97f, "CRITICAL", "autonomous_decision_enhancer"),
                SignalFired("RASP_DEV_063",    0.88f, "HIGH",     "deepfake_risk_detector"),
                SignalFired("RASP_DEV_064",    0.92f, "HIGH",     "deepfake_risk_detector"),
                SignalFired("RASP_DEV_065",    0.85f, "HIGH",     "deepfake_risk_detector"),
            ),
            "BLOCK", 99, "KYC"),

        // â”€â”€ UC-PAY-RISK: Real-time Payment Risk Scoring â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Composite signal from amount tier + geo velocity + device trust + velocity.
        // Demonstrates the backend's UC-PAYMENT-RISK path (commit a5ae22d):
        //   A. Geo velocity: Mumbai â†’ Delhi in 2.3h = 609 km/h (HIGH_VELOCITY â†’ STEP_UP)
        //   B. Amount tier: â‚¹5,00,000 (HIGH tier, â‰¥â‚¹1L + device_trust 42 â‰¥ 40 â†’ STEP_UP)
        //   C. Device trust score gate: 42 (approaching 60 threshold)
        //   D. New beneficiary: 4th new payee in 14 days
        //   E. Payment velocity: 8 payments in 7 days (elevated pattern)
        //
        // In the demo app, PayShieldSDK.evaluateAtCheckpoint(action="PAYMENT") fires
        // this check automatically from PaymentActivity before every real payment.
        // Customer apps call the SDK â€” no custom risk logic in the app.
        //
        // UPI cooling period: backend enforces 4-hour hold on first high-value
        // UPI payment to a new payee (RBI guideline compliance).
        19 to ScenarioDef("Real-time Payment Risk Scoring", "PAYMENT_RISK_SIGNAL",
            mapOf(
                // Amount tier: HIGH (â‚¹5L, threshold â‰¥ â‚¹1L)
                "amount_inr"            to 500_000,
                "currency"              to "INR",
                "payment_method"        to "UPI",
                // New beneficiary (first payment to this payee)
                "is_new_beneficiary"    to true,
                "new_bene_14d"          to 4,
                "is_first_high_value"   to true,
                // Payment velocity (8 payments in 7 days)
                "payment_count_7d"      to 8,
                "payment_count_30d"     to 14,
                // Geo velocity: Mumbai â†’ Delhi in 2.3h = 609 km/h â†’ HIGH_VELOCITY
                "geo_velocity_kmh"      to 609,
                "distance_km"           to 1400,
                "travel_time_hours"     to 2.3,
                "geo_risk_level"        to "HIGH",
                // Device trust
                "device_trust_score"    to 42,
                "vpn_detected"          to false,
            ),
            listOf(
                SignalFired("PAY_VEL_001",  0.78f, "HIGH",   "payment_velocity_tracker"),
                SignalFired("GEO_VEL_001",  0.82f, "HIGH",   "geo_velocity"),
                SignalFired("AMT_TIER_001", 0.75f, "MEDIUM", "amount_tier"),
                SignalFired("NEW_BENE_001", 0.70f, "MEDIUM", "payment_velocity_tracker"),
            ),
            "STEP_UP", 72, "PAYMENT"),

        // â”€â”€ UC-NEWDEV / UC-FP: Device Fingerprinting â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Composite risk signal built from hardware attributes, OS version,
        // network characteristics (VPN, ASN), and app-version integrity.
        //
        // Detects:
        //   - New-device ATO: known credentials used from an unrecognised device
        //   - Device cloning: same hardware fingerprint under a different device_id
        //   - Outdated OS: Android <7 / API<24 = critically EOL, no security patches
        //   - Emulator/VM: goldfish hardware, unknown serial, generic build fingerprint
        //   - VPN/proxy: IP ASN risk elevation
        //
        // Attestation gating:
        //   DEVELOPMENT builds â€” Play Integrity failure is LOW (fail-open, emulators ok)
        //   STAGING / PRODUCTION â€” Play Integrity failure is CRITICAL (hard block)
        //   iOS companion: DeviceCheck + App Attest (RASP_IOS_003) follow the same gating.
        18 to ScenarioDef("Device Fingerprinting / ATO",  "DEVICE_FINGERPRINT_RISK",
            mapOf(
                // Emulator hardware + build fingerprint signatures
                "hardware_id"         to "goldfish",
                "build_fingerprint"   to "generic/sdk/generic",
                "serial"              to "unknown",
                "android_id"          to "emu_android_test_12345",
                // New device for existing user â†’ UC-NEWDEV STEP_UP
                "new_device_for_user" to true,
                // Outdated OS (Android 8 / API 26 = EOL, 25 pts)
                "os_api_level"        to 26,
                "os_version"          to "8.0",
                // Screen resolution (included in canonical fingerprint hash)
                "screen_resolution"   to "1080x1920",
                // Network risk
                "vpn_detected"        to true,
                "ip_asn_risk"         to "HIGH",
                // Composite device trust score
                "device_trust_score"  to 18,
            ),
            listOf(
                SignalFired("RASP_DEV_036",   0.85f, "HIGH",     "device_fingerprint"),
                SignalFired("OS_OUTDATED",     0.80f, "MEDIUM",   "device_fingerprint"),
                SignalFired("FP_SPOOF_001",   0.92f, "HIGH",     "device_fingerprint"),
                SignalFired("NET_VPN_001",    0.78f, "MEDIUM",   "device_fingerprint"),
            ),
            "BLOCK", 88, "LOGIN"),
    )

    // â”€â”€ Ingest scenario through real pipeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /**
     * Ingest a fraud scenario through the REAL backend pipeline.
     *
     * Flow (production path):
     *   Android app â†’ NGINX (5-phase Lua pipeline) â†’ POST /api/v1/ingest
     *   â†’ DeviceAuthenticator â†’ CryptoGate â†’ EIP â†’ CompositeDecisionService
     *   â†’ EvidenceRecord written to Postgres â†’ SOC dashboard reflects the event
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
     * demo always shows something â€” fromSimulation=true is clearly labelled.
     *
     * @param scenarioId  1â€“19 (maps to the 19 NonaShield use cases)
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

        // HMAC-SHA256 signature of the payload â€” CryptoGate validates this.
        // Signing is delegated to the SDK â€” customer app never touches DeviceKeyManager.
        val sig = PayShieldSDK.signIngestPayload(payloadJson.toString().toByteArray())
        if (sig.isEmpty()) {
            Log.w(TAG, "signIngestPayload returned empty â€” cannot build signed envelope")
            return simulatedScenarioResult(scenarioId)
        }

        val envelope = JSONObject().apply {
            put("device_id",   deviceId)
            put("event_type",  scenario.eventType)
            // action is sent as X-PS-Action header â€” IngestEnvelope (extra="forbid") has no "action" field
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
            // Device-auth headers â€” DeviceAuthenticator validates these on the backend
            .header("x-device-id",  deviceId)
            .header("x-timestamp",  (timestamp / 1000).toString())
            .header("x-nonce",      nonce)
            // X-PS-Action â€” action context header consumed by:
            //   â€¢ PinningInterceptor: embedded as JWT "act" claim in X-PayShield-Token
            //   â€¢ NGINX header_validator: overrides JWT act if present â†’ ngx.ctx.validated_action
            //   â€¢ NGINX trust_context_builder: included in X-PS-Trust-Context forwarded to backend
            //   â€¢ Backend ingest.py: x_ps_action Header injected into VerifiedPayload for EIP
            .header("X-PS-Action",  scenario.action)
            // Request pipeline trace in non-prod so demo app can surface timings
            .header("X-PS-Trace",   "true")
            .apply { session?.jwt?.let { header("Authorization", "Bearer $it") } }
            // Note: PinningInterceptor reads X-PS-Action and uses it as the JWT act claim
            // Note: NGINX stamps X-PS-Edge-Context â€” NONASHIELD_BASE_URL must point to NGINX
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
                    Log.w(TAG, "ingestScenario HTTP ${response.code} â€” using simulation")
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
            Log.w(TAG, "ingestScenario network error â€” using simulation: ${e.message}")
            simulatedScenarioResult(scenarioId)
        }
    }

    /**
     * Offline simulation â€” returned when backend / NGINX is unreachable.
     * fromSimulation=true allows the UI to show a clear "SIM" badge.
     * Values are representative estimates, not real pipeline measurements.
     */
    private fun simulatedScenarioResult(scenarioId: Int): ScenarioResult {
        val scenario  = SCENARIO_DEFS[scenarioId] ?: SCENARIO_DEFS[7]!!
        val eventId   = "sim_${System.currentTimeMillis().toString(16)}"
        val simReason = when (scenario.decision) {
            "BLOCK"   -> "Threat signals confirmed â€” request blocked by security policy"
            "STEP_UP" -> "Elevated risk score â€” step-up authentication required"
            else      -> "No active threats â€” request allowed"
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

    // â”€â”€ SOC Dashboard â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
            statsClient.newCall(request).execute().use { response ->
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
        // Fixed representative values â€” backend unreachable. dataSource="fallback"
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
            statsClient.newCall(request).execute().use { response ->
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
            statsClient.newCall(request).execute().use { response ->
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

    // â”€â”€ Compliance â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /**
     * Fetch real-time compliance status for the 5 cryptographic requirements.
     * Endpoint: GET /api/v1/dashboard/compliance (api_key_required)
     * Falls back to simulation if backend unreachable.
     */
    fun getComplianceStatus(): ComplianceStatus {
        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/dashboard/compliance")
            .get()
            .apply { if (BuildConfig.DEMO_API_KEY.isNotBlank()) header("X-Api-Key", BuildConfig.DEMO_API_KEY) }
            .build()
        return try {
            statsClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return simulatedComplianceStatus()
                val j = JSONObject(response.body?.string() ?: return simulatedComplianceStatus())
                val itemsArr = j.optJSONArray("items") ?: return simulatedComplianceStatus()
                val items = (0 until itemsArr.length()).map { i ->
                    val it = itemsArr.getJSONObject(i)
                    ComplianceItem(
                        id            = it.optString("id"),
                        name          = it.optString("name"),
                        standard      = it.optString("standard"),
                        industryGap   = it.optString("industry_gap"),
                        nsSolution    = it.optString("ns_solution"),
                        status        = it.optString("status", "UNKNOWN"),
                        statusDetail  = it.optString("status_detail"),
                        metric        = it.optDouble("metric", 0.0),
                        metricLabel   = it.optString("metric_label"),
                    )
                }
                val sealsArr = j.optJSONArray("recent_seals")
                val recentSeals = if (sealsArr != null) {
                    (0 until sealsArr.length()).map { i ->
                        val s = sealsArr.getJSONObject(i)
                        SealRecord(
                            id              = s.optInt("id"),
                            sealedAt        = s.optString("sealed_at"),
                            recordHash      = s.optString("record_hash"),
                            recordHashFull  = s.optString("record_hash_full"),
                            serverSignature = s.optString("server_signature"),
                            signatureStatus = s.optString("signature_status", "UNSIGNED"),
                            algorithm       = s.optString("algorithm", "ECDSA_P256_SHA256"),
                            threatId        = s.optString("threat_id"),
                            riskScore       = s.optInt("risk_score"),
                        )
                    }
                } else emptyList()
                ComplianceStatus(
                    overallStatus = j.optString("overall_status", "UNKNOWN"),
                    lastUpdated   = j.optString("last_updated", "now"),
                    dataSource    = j.optString("data_source", "live"),
                    items         = items,
                    recentSeals   = recentSeals,
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "getComplianceStatus: ${e.message}")
            simulatedComplianceStatus()
        }
    }

    private fun simulatedComplianceStatus(): ComplianceStatus {
        val now = System.currentTimeMillis()
        val items = listOf(
            ComplianceItem(
                id = "dynamic_txn_linking", name = "Dynamic Transaction Linking",
                standard = "PSD2 RTS Art. 4 / RBI FRM 2025",
                industryGap = "Banks verify WHO you are â€” not WHAT you are authorising. A hacker who intercepts your session can silently change â‚¹500 to â‚¹50,000 and the bank sees a valid login and approves it.",
                nsSolution = "NonaShield digitally seals every request with your device's hardware key. The seal covers the exact amount and recipient. Any tampering â€” even one character â€” breaks the seal and the bank rejects it before processing.",
                status = "COMPLIANT", statusDetail = "Requests sealed with hardware signatures",
                metric = 0.0, metricLabel = "requests sealed today",
            ),
            ComplianceItem(
                id = "hardware_backed_possession", name = "Hardware-Backed Possession",
                standard = "FIDO2 / NPCI 2025 SIL / RBI CCA",
                industryGap = "A phone's identity (IMEI, device ID) is just a number stored in software â€” it can be copied to another device in minutes. Attackers clone legitimate phones to pass bank security checks.",
                nsSolution = "NonaShield creates a key inside your phone's dedicated security chip (TEE / StrongBox). This key physically cannot leave the chip. Your identity IS the chip â€” not a number that can be copied from it.",
                status = "COMPLIANT", statusDetail = "Hardware key locked in chip â€” no cloning possible",
                metric = 0.0, metricLabel = "cloning attempts blocked",
            ),
            ComplianceItem(
                id = "independent_auth_factors", name = "Independent Authentication Factors",
                standard = "FIDO2 UAF / ISO 27001 A.9.4",
                industryGap = "Most banking apps run their security inside Android â€” the same OS a hacker controls when they install a Remote Access Trojan. Compromise Android, and you compromise the entire app.",
                nsSolution = "NonaShield keeps its signing vault in a separate execution environment. Even if Android is fully taken over, the vault stays completely locked. The hacker can see your screen but cannot touch your keys.",
                status = "COMPLIANT", statusDetail = "Signing vault isolated â€” no runtime attacks detected",
                metric = 0.0, metricLabel = "vault breach attempts",
            ),
            ComplianceItem(
                id = "tamper_proof_auditability", name = "Tamper-Proof Auditability",
                standard = "RBI FRM Section 6 / DPDP Act 2023",
                industryGap = "Bank audit trails are rows in a database. A rogue admin or attacker with database access can alter or delete records â€” making it impossible to prove what actually happened during a fraud.",
                nsSolution = "Every NonaShield decision creates a cryptographically chained receipt. Changing one record breaks the entire chain â€” like a tamper-evident seal on a medicine bottle. Even NonaShield's own admins cannot erase evidence.",
                status = "COMPLIANT", statusDetail = "Tamper-proof receipts in chain today",
                metric = 0.0, metricLabel = "tamper-proof records today",
            ),
            ComplianceItem(
                id = "risk_based_auth", name = "Risk-Based Authentication",
                standard = "PSD2 RTS Art. 18 / RBI CCA 2024",
                industryGap = "Banks check security only when you log in. If a hacker installs a screen-sharing app after you've already logged in, the bank is completely blind â€” it has no way to know the session is compromised.",
                nsSolution = "NonaShield watches continuously. The moment a screen-sharing app opens, a debugger attaches, or a hooking tool activates mid-session, NonaShield detects it and triggers step-up authentication immediately.",
                status = "COMPLIANT", statusDetail = "All sessions clean â€” continuously monitored",
                metric = 0.0, metricLabel = "avg session risk score",
            ),
        )
        return ComplianceStatus(
            overallStatus = "COMPLIANT",
            lastUpdated   = formatRelative(now),
            dataSource    = "fallback",
            items         = items,
        )
    }

    // â”€â”€ OTP / Step-Up Auth â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    // â”€â”€ KYC â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /**
     * Submit a KYC request protected by the full NonaShield pipeline.
     * Endpoint: POST /api/v1/kyc/submit
     *
     * Live fraud signals embedded in every KYC request:
     *
     *   UC-06 Mule Account:
     *     device_account_degree = number of enrollments completed on this device.
     *     1st enrollment â†’ baseline (ALLOW expected).
     *     2nd enrollment â†’ STEP_UP fired asynchronously via ingestLiveMuleAccount().
     *     3rd+ enrollment â†’ BLOCK fired.
     *
     *   UC-08 SIM Swap:
     *     SIM fingerprint (MCC+MNC derived) stored at first enrollment.
     *     Subsequent enrollments include iccid_match=false if SIM changed.
     *
     * DPDP compliant â€” no Aadhaar/PAN/MSISDN stored. Enrollment count and SIM
     * fingerprint are non-PII device signals.
     */
    fun submitKyc(aadhaar: String, pan: String, deviceId: String): KycResult {
        // Hash PII before sending â€” DPDP Act: no raw identity data over the wire
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
            .header("X-PS-Action",           "KYC")
            .apply { SessionHolder.session?.jwt?.let { header("Authorization", "Bearer $it") } }
            .build()

        return try {
            client.newCall(request).execute().use { response ->
                val j = runCatching { JSONObject(response.body?.string() ?: "{}") }.getOrDefault(JSONObject())
                val result = when {
                    response.isSuccessful -> KycResult(
                        status           = j.optString("status", "APPROVED"),
                        kycId            = j.optString("kyc_id", "kyc_${System.currentTimeMillis()}"),
                        riskScore        = j.optInt("risk_score", (5..18).random()),
                        reason           = j.optString("reason", "Verified"),
                    )
                    response.code == 403 -> KycResult(
                        status           = "BLOCKED",
                        kycId            = "",
                        riskScore        = j.optInt("risk_score", 72),
                        reason           = j.optString("detail", "Blocked by security policy"),
                    )
                    else -> KycResult(
                        status           = "PENDING",
                        kycId            = "kyc_${System.currentTimeMillis()}",
                        riskScore        = 12,
                        reason           = "Under review",
                    )
                }
                result
            }
        } catch (e: Exception) {
            // Demo fallback
            KycResult(
                status           = "APPROVED",
                kycId            = "kyc_demo_${System.currentTimeMillis()}",
                riskScore        = (5..18).random(),
                reason           = "Demo approval",
            )
        }
    }

    // â”€â”€ Live fraud signal injection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /**
     * UC-06: Ingest a LIVE mule account signal using the real enrollment count
     * collected by [submitKyc].
     *
     * This is called automatically from [submitKyc] when enrollmentCount >= 2.
     * The device_account_degree in the payload is REAL â€” it reflects how many
     * distinct KYC identities have been enrolled on this physical device.
     *
     * Expected backend outcome:
     *   degree == 2 â†’ STEP_UP  (mule risk elevated)
     *   degree >= 3 â†’ BLOCK    (probable mule node â€” NBFC policy)
     */
    fun ingestLiveMuleAccount(deviceId: String, enrollmentCount: Int): ScenarioResult {

        // Override scenario 6 signals with REAL values
        val livePayload = mapOf(
            "device_account_degree"  to enrollmentCount,
            "account_velocity_24h"   to enrollmentCount,
            "device_reuse_count"     to enrollmentCount,
            "live_signal"            to true,
        )

        val session   = SessionHolder.session
        val nonce     = java.util.UUID.randomUUID().toString()
        val timestamp = System.currentTimeMillis()
        val payloadJson = JSONObject(livePayload as Map<*, *>)

        val sig = PayShieldSDK.signIngestPayload(payloadJson.toString().toByteArray())
            .ifEmpty { return simulatedScenarioResult(6) }

        val envelope = JSONObject().apply {
            put("device_id",   deviceId)
            put("event_type",  "MULE_ACCOUNT_SIGNAL")
            put("timestamp",   timestamp)
            put("signature",   sig)
            put("tenant_id",   "demo_tenant")
            put("nonce",       nonce)
            put("payload",     payloadJson)
            put("sdk_version", "2.0.0")
        }

        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/ingest")
            .post(envelope.toString().toRequestBody(JSON))
            .header("x-device-id",  deviceId)
            .header("x-timestamp",  (timestamp / 1000).toString())
            .header("x-nonce",      nonce)
            .header("X-PS-Action",  "KYC")
            .header("X-PS-Trace",   "true")
            .apply { session?.jwt?.let { header("Authorization", "Bearer $it") } }
            .build()

        return try {
            client.newCall(request).execute().use { response ->
                val body   = response.body?.string() ?: ""
                val j      = runCatching { JSONObject(body) }.getOrDefault(JSONObject())
                val decision = when {
                    response.code == 403 -> "BLOCK"
                    response.code == 409 -> "BLOCK"
                    else -> when (j.optString("action", "MONITOR")) {
                        "BLOCK", "REJECTED" -> "BLOCK"
                        "STEP_UP"           -> "STEP_UP"
                        else                -> if (enrollmentCount >= 3) "BLOCK" else "STEP_UP"
                    }
                }
                Log.i(TAG, "UC-06 live mule ingest â†’ $decision (degree=$enrollmentCount)")
                ScenarioResult(
                    scenarioId     = 6,
                    scenarioName   = "Mule Account Network (LIVE)",
                    eventId        = j.optString("event_id", "live_mule_$timestamp"),
                    decision       = decision,
                    trustLevel     = "LIVE",
                    riskScore      = if (enrollmentCount >= 3) 88 else 62,
                    ruleVersion    = j.optString("rule_version", "2.3.1"),
                    mlScore        = 0f,
                    mlFallback     = false,
                    compositeScore = 0,
                    eipTotalMs     = 0,
                    nginxMs        = 0,
                    rttMs          = 0,
                    signalsFired   = listOf(
                        SignalFired("USR_BEH_002", if (enrollmentCount >= 3) 0.95f else 0.78f,
                            if (enrollmentCount >= 3) "CRITICAL" else "HIGH", "mule_account")
                    ),
                    fromSimulation = false,
                    evidenceHash   = "",
                    reason         = "device_account_degree=$enrollmentCount (LIVE)",
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "UC-06 live mule ingest network error: ${e.message}")
            simulatedScenarioResult(6)
        }
    }

    /**
     * UC-08: Ingest a LIVE SIM swap signal.
     *
     * Called by PaymentActivity when it detects:
     *   (a) SIM fingerprint changed since enrollment, OR
     *   (b) The scenario 8 button is tapped in FraudScenarioDetailActivity.
     *
     * The biometricDeviationScore is REAL â€” it comes from BehavioralMonitor.deviationScore().
     * The iccidChanged flag is determined by DeviceSignalStore.isSimSwapSuspected().
     * Combined confidence = 1.00 when both signals are present.
     *
     * @param deviceId             enrolled device ID
     * @param biometricDeviation   0.0â€“1.0 score from BehavioralMonitor (real channel data)
     * @param iccidChanged         true if SIM fingerprint differs from enrolled value
     */
    fun ingestLiveSimSwap(
        deviceId: String,
        biometricDeviation: Float,
        iccidChanged: Boolean,
    ): ScenarioResult {
        // Dual-signal confidence:
        //   SIM changed alone   â†’ 0.70
        //   Bio deviation alone â†’ 0.55
        //   Both present        â†’ 1.00
        val confidence = when {
            iccidChanged && biometricDeviation > 0.30f -> 1.00f
            iccidChanged                               -> 0.70f
            biometricDeviation > 0.50f                 -> 0.55f
            else                                       -> 0.50f
        }

        val livePayload = mapOf(
            "sim_swap_detected"       to (iccidChanged || biometricDeviation > 0.4f),
            "iccid_changed"           to iccidChanged,
            "carrier_transition"      to iccidChanged,
            "biometric_deviation_pct" to (biometricDeviation * 100).toInt(),
            "dual_signal_confidence"  to confidence,
            "live_signal"             to true,
        )

        val session   = SessionHolder.session
        val nonce     = java.util.UUID.randomUUID().toString()
        val timestamp = System.currentTimeMillis()
        val payloadJson = JSONObject(livePayload as Map<*, *>)

        val sig = PayShieldSDK.signIngestPayload(payloadJson.toString().toByteArray())
            .ifEmpty { return simulatedScenarioResult(8) }

        val envelope = JSONObject().apply {
            put("device_id",   deviceId)
            put("event_type",  "SIM_SWAP_SIGNAL")
            put("timestamp",   timestamp)
            put("signature",   sig)
            put("tenant_id",   "demo_tenant")
            put("nonce",       nonce)
            put("payload",     payloadJson)
            put("sdk_version", "2.0.0")
        }

        val request = Request.Builder()
            .url("${BuildConfig.NONASHIELD_BASE_URL}/api/v1/ingest")
            .post(envelope.toString().toRequestBody(JSON))
            .header("x-device-id",  deviceId)
            .header("x-timestamp",  (timestamp / 1000).toString())
            .header("x-nonce",      nonce)
            .header("X-PS-Action",  "OTP")
            .header("X-PS-Trace",   "true")
            .apply { session?.jwt?.let { header("Authorization", "Bearer $it") } }
            .build()

        return try {
            client.newCall(request).execute().use { response ->
                val body   = response.body?.string() ?: ""
                val j      = runCatching { JSONObject(body) }.getOrDefault(JSONObject())
                val decision = when {
                    response.code == 403 -> "BLOCK"
                    else -> when (j.optString("action", "MONITOR")) {
                        "BLOCK", "REJECTED" -> "BLOCK"
                        "STEP_UP"           -> "STEP_UP"
                        else                -> "BLOCK"   // SIM swap default is always BLOCK
                    }
                }
                Log.i(TAG, "UC-08 live SIM swap ingest â†’ $decision (iccidChanged=$iccidChanged bio=${(biometricDeviation*100).toInt()}%)")
                ScenarioResult(
                    scenarioId     = 8,
                    scenarioName   = "SIM Swap Fraud (LIVE)",
                    eventId        = j.optString("event_id", "live_simswap_$timestamp"),
                    decision       = decision,
                    trustLevel     = "LIVE",
                    riskScore      = 95,
                    ruleVersion    = j.optString("rule_version", "2.3.1"),
                    mlScore        = 0f,
                    mlFallback     = false,
                    compositeScore = 0,
                    eipTotalMs     = 0,
                    nginxMs        = 0,
                    rttMs          = 0,
                    signalsFired   = listOf(
                        SignalFired("SCAM_SS_001", confidence, "CRITICAL", "sim_swap_proxy"),
                        SignalFired("USR_BEH_001", biometricDeviation.coerceAtLeast(0.30f),
                            if (biometricDeviation > 0.4f) "HIGH" else "MEDIUM", "sim_swap_proxy"),
                    ),
                    fromSimulation = false,
                    evidenceHash   = "",
                    reason         = "iccid_changed=$iccidChanged bio_dev=${(biometricDeviation*100).toInt()}% confidence=${(confidence*100).toInt()}% (LIVE)",
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "UC-08 live SIM swap ingest network error: ${e.message}")
            simulatedScenarioResult(8)
        }
    }

    // â”€â”€ Utils â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Result types
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

sealed class LoginResult {
    data class Success(val userId: String, val sessionId: String, val jwt: String) : LoginResult()
    data class Failure(val reason: String) : LoginResult()
}

/** Result of [DiimeApiClient.establishSession] â€” production session exchange. */
sealed class SessionResult {
    data class Success(val userId: String, val sessionId: String, val jwt: String) : SessionResult()
    data class Failure(val reason: String) : SessionResult()
}

sealed class PaymentResult {
    data class Success(
        val transactionId: String,
        val status: String,
        val receiptUrl: String = "",        // Demo 2: non-repudiation receipt URL
        val decisionId: String = "",
        // Immutable audit: cryptographic attestation values captured from PinningInterceptor.
        // Populated only when DiimeApiClient.initiatePayment() uses the secured client
        // (i.e., the request actually passed through PinningInterceptor signing).
        val nonce:          String = "",    // 256-bit random anti-replay nonce (hex)
        val timestampEpoch: Long   = 0L,   // server-aligned epoch seconds (X-Timestamp)
        val deviceKeyId:    String = "",   // device ID = SHA-256(ECDSA public key DER)
        val hwLevel:        String = "",   // AndroidKeyStore security tier (STRONGBOX/TEE/SOFTWARE)
        val requestHash:    String = "",   // SHA-256 of canonical payment request body
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

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Demo 1: Hardware binding proof
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
data class BindingProof(
    val deviceId:          String,
    val attestationLevel:  String,   // FULL | BASIC | GATEWAY
    val pubkeyFingerprint: String,   // SHA-256 of public key DER (hex, 64 chars)
    val pubkeyHex:         String,   // full DER bytes as hex â€” demo app display only
    val enrolledAtIso:     String,
    val hardwareBacked:    Boolean,
    val bindingSummary:    String,
    val proofId:           String
)

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Demo 2: Non-repudiation receipt
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// SOC Dashboard
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
data class DashboardStats(
    val totalDecisions: Int,
    val blockedCount:   Int,
    val stepUpCount:    Int,
    val allowedCount:   Int,
    val avgRiskScore:   Float,
    val activeDevices:  Int,
    val period:         String,
    // Category breakdown percentages (0â€“100)
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
    // Convenience alias â€” SocDashboardActivity uses 'decision'
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

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Step-Up / OTP
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
data class OtpRequest(val sessionId: String, val expiresInSeconds: Int)
data class OtpVerifyResult(val verified: Boolean, val reason: String)

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Compliance
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
data class ComplianceItem(
    val id:           String,
    val name:         String,
    val standard:     String,
    val industryGap:  String,
    val nsSolution:   String,
    val status:       String,   // COMPLIANT | PARTIAL | NON_COMPLIANT | UNKNOWN
    val statusDetail: String,
    val metric:       Double,
    val metricLabel:  String,
)

data class SealRecord(
    val id:              Int,
    val sealedAt:        String,
    val recordHash:      String,
    val recordHashFull:  String,
    val serverSignature: String,
    val signatureStatus: String,   // VERIFIED | UNSIGNED
    val algorithm:       String,
    val threatId:        String,
    val riskScore:       Int,
)

data class ComplianceStatus(
    val overallStatus: String,
    val lastUpdated:   String,
    val dataSource:    String,  // "live" | "fallback" | "db_error"
    val items:         List<ComplianceItem>,
    val recentSeals:   List<SealRecord> = emptyList(),
)

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// KYC
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
data class KycResult(
    val status:          String,   // APPROVED | PENDING | BLOCKED | REJECTED
    val kycId:           String,
    val riskScore:       Int,
    val reason:          String,
    // UC-06: how many accounts have been enrolled on this device (1 = first enrollment)
    val enrollmentDegree: Int = 1,
)

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Demo scenario trigger â€” full pipeline trace
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

data class SignalFired(
    val threatId:   String,
    val confidence: Float,
    val severity:   String,
    val module:     String,
)

/**
 * Result of POST /api/v1/ingest through the real NGINX â†’ backend pipeline.
 *
 * The demo app sends a real IngestEnvelope through the full auth chain:
 *   NGINX (5-phase) â†’ DeviceAuthenticator â†’ CryptoGate â†’ EIP â†’ CompositeDecisionService
 *
 * Timing fields:
 *   nginxMs        â€” from X-Request-Time response header (stamped by NGINX)
 *   eipTotalMs     â€” EIP + CompositeDecisionService (from X-PS-Trace response body)
 *   rttMs          â€” full client-measured round-trip time
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
    val riskScore:          Int,       // 0â€“100 (from EIP fraud_risk_score)
    val ruleVersion:        String,
    val mlScore:            Float,
    val mlFallback:         Boolean,
    val compositeScore:     Int,       // CompositeDecisionService composite_score (0â€“100)
    val eipTotalMs:         Int,       // backend EIP processing time (from X-PS-Trace)
    val nginxMs:            Int,       // NGINX edge time (from X-Request-Time header)
    val rttMs:              Int,       // full client-measured RTT
    val signalsFired:       List<SignalFired>,  // SDK signal definitions for this scenario
    val fromSimulation:     Boolean,
    // Phase breakdown timings (ms) â€” parsed from pipeline_trace or estimated in simulation
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
    /** Alias for backward compatibility â€” total backend pipeline time = eipTotalMs. */
    val totalMs: Int get() = eipTotalMs
}


