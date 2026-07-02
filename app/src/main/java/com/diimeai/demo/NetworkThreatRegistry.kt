package com.diimeai.demo

/**
 * Network & Edge threat catalog for Tab 3 of the investor/CISO demo.
 *
 * Every threat here maps directly to a real NGINX/OpenResty Lua enforcement module
 * in the NonaShield gateway pipeline (5 phases, 17 Lua modules).
 *
 * Architecture-protected threats are ALWAYS enforced by the NGINX edge — no device
 * signal needed.  Signal-correlated threats show live status from the SDK.
 *
 * NGINX 5-phase pipeline (from nginx.conf + conf.d/payshield.conf):
 *   Phase 1: header_validator · schema_validator · bot_detector · geo_enrichment · trust_context_builder
 *   Phase 2: nonce_validator · payload_hash_validator · nonce_binding_validator · signature_verifier
 *   Phase 3: trusted_time_validator · public_key_resolver · binding_validator · attestation_validator · handoff_controller
 *   Phase 4: policy_validator · decision_engine · secure_forwarder
 *   Phase 5: request_filter · device_block · edge_threat · security_checks · risk_score · edge_risk_handler
 */
object NetworkThreatRegistry {

    enum class Decision(val label: String, val colorHex: String) {
        BLOCK  ("BLOCK",   "#FF3333"),
        STEP_UP("STEP UP", "#FF8800"),
        FLAG   ("FLAG",    "#FFCC00"),
    }

    enum class NginxPhase(val label: String) {
        PHASE_1("Phase 1"),
        PHASE_2("Phase 2"),
        PHASE_3("Phase 3"),
        PHASE_4("Phase 4"),
        PHASE_5("Phase 5"),
    }

    data class NetworkThreat(
        val name: String,
        val protectionLine: String,
        val detailText: String,
        val threatId: String,
        val severity: RaspSensorRegistry.Severity,
        val riskScore: Int,
        val decision: Decision,
        val nginxPhase: NginxPhase,
        val luaModule: String,
        val signalTypes: List<String> = emptyList(),
        val architectureProtected: Boolean = false,
    )

    // ── Group 1: Request Integrity ──────────────────────────────────────────────

    val GROUP_INTEGRITY = "REQUEST INTEGRITY"
    val GROUP_REPLAY    = "REPLAY PREVENTION"
    val GROUP_BOT       = "BOT & AUTOMATION"
    val GROUP_ORIGIN    = "NETWORK ORIGIN"
    val GROUP_RISK      = "RISK GATE & KILL-SWITCH"

    data class ThreatGroup(val label: String, val colorHex: String, val threats: List<NetworkThreat>)

    val ALL_GROUPS: List<ThreatGroup> = listOf(

        ThreatGroup(GROUP_INTEGRITY, "#4FC3F7", listOf(

            NetworkThreat(
                name = "SDK Token Validation",
                protectionLine = "header_validator.lua — X-PayShield-Token: 9-field JWT, ts ±60s, nonce 256-bit",
                detailText = """
NGINX Phase 1 — header_validator.lua

Every request must carry X-PayShield-Token (Base64Url JSON) + X-PayShield-Signature.
NGINX validates all 9 required fields: did, uid, sid, nonce, ts, exp, act, rng, bh.

Enforced checks:
  • Token format: valid Base64Url → valid JSON
  • Timestamp (ts): within ±60 s of server time — NGINX-HDR-VALID-010
  • Expiry (exp): not exceeded — NGINX-HDR-VALID-012
  • Nonce entropy: ≥ 256-bit (64 hex chars or 44 base64url chars) — NGINX-HDR-VALID-013
  • Range (rng): one of LOW / MEDIUM / HIGH — NGINX-HDR-VALID-016
  • Binding hash (bh): SHA-256(uid|did|sid|ts), 64-char hex — NGINX-HDR-VALID-017
  • Signature format: alg= prefix + sig= base64 (crypto-agile: ECDSA_P256 / ML_DSA_65)

Missing or malformed token → HTTP 403 (NGINX-HDR-VALID-001 to -022).
No SDK token = no bank API access. Period.
                """.trimIndent(),
                threatId = "NGINX-HDR-001",
                severity = RaspSensorRegistry.Severity.CRITICAL,
                riskScore = 0,
                decision = Decision.BLOCK,
                nginxPhase = NginxPhase.PHASE_1,
                luaModule = "header_validator.lua",
                architectureProtected = true,
            ),

            NetworkThreat(
                name = "Payload Tampering",
                protectionLine = "payload_hash_validator.lua — SHA-256(raw body) must match X-Payload-Hash",
                detailText = """
NGINX Phase 2 — payload_hash_validator.lua

The SDK computes SHA-256 of the raw request body before sending and attaches the
hex digest as X-Payload-Hash.  NGINX recomputes the same hash after receiving the
body and rejects any mismatch.

How it stops MITM tampering:
  A man-in-the-middle who intercepts and modifies the payment amount from ₹1,000 to
  ₹100,000 changes the body bytes → changes the SHA-256 → mismatch → HTTP 403
  (NGINX-HASH-VALID-004) before the bank's core system ever sees the request.

The computed hash is also forwarded to signature_verifier.lua as part of the
canonical signed input:
    "x-payshield-token:{token}\ncontent-type:{ct}\n\n{body_hash}"
so any body change also invalidates the ECDSA signature in Phase 2.

Missing X-Payload-Hash → NGINX-HASH-VALID-001 (403).
                """.trimIndent(),
                threatId = "NGINX-HASH-001",
                severity = RaspSensorRegistry.Severity.CRITICAL,
                riskScore = 0,
                decision = Decision.BLOCK,
                nginxPhase = NginxPhase.PHASE_2,
                luaModule = "payload_hash_validator.lua",
                architectureProtected = true,
            ),

            NetworkThreat(
                name = "ECDSA Signature Forgery",
                protectionLine = "signature_verifier.lua — ECDSA-P256 over token+content-type+body-hash",
                detailText = """
NGINX Phase 2 — signature_verifier.lua

Every request is signed with the device's ECDSA P-256 private key stored inside
the AndroidKeyStore TEE (alias: payshield_device_key).  NGINX verifies the signature
using the corresponding public key fetched from Redis (pubkey:{device_id}).

Canonical signed input (must match SDK exactly):
    "x-payshield-token:{raw_token}\n"
    "content-type:{content_type}\n"
    "\n"
    "{body_hash_hex}"

Two-level key cache:
  L1: redis_cache shared dict (per-worker, TTL 300 s) — zero network cost
  L2: Redis GET pubkey:{device_id}  — written at device enrollment

Bad signature → cache evicted + HTTP 403 (NGINX-SIG-VERIF-002).
Device key not in Redis → HTTP 403 REVERIFY_DEVICE challenge (NGINX-SIG-VERIF-001).
Unregistered device / cloned APK → no key → all requests rejected at this phase.

Future: ML_DSA_65 (Dilithium3 / post-quantum) routing is wired — the alg= prefix
in X-PayShield-Signature is crypto-agile; the PQC branch is stub-ready (NGINX-SIG-VERIF-008).
                """.trimIndent(),
                threatId = "NGINX-SIG-001",
                severity = RaspSensorRegistry.Severity.CRITICAL,
                riskScore = 0,
                decision = Decision.BLOCK,
                nginxPhase = NginxPhase.PHASE_2,
                luaModule = "signature_verifier.lua",
                architectureProtected = true,
            ),

            NetworkThreat(
                name = "Play Integrity / App Attest",
                protectionLine = "attestation_validator.lua — Google Play Integrity JWS · Apple App Attest CBOR",
                detailText = """
NGINX Phase 3 — attestation_validator.lua

Android: Reads X-Attestation-Token (raw JWS from Play Integrity API) and posts it
to /internal/verify-attestation (backend endpoint, only reachable via NGINX subrequest).
Backend uses Google's public key to cryptographically verify the token and extracts
the device integrity verdict:
  • MEETS_BASIC_INTEGRITY  — APK not tampered
  • MEETS_DEVICE_INTEGRITY — hardware-backed TEE present
  • MEETS_STRONG_INTEGRITY — StrongBox / HSM (Pixel/Samsung flagship)

iOS: Reads X-Attestation-Object (Base64-encoded CBOR from Apple App Attest) and
routes to /internal/verify-ios-attestation.  Backend verifies the certificate chain
against Apple's Hardware Attestation Root CA.

NGINX caches per-device result for 30 s (attestation_cache) to avoid redundant
subrequests on high-frequency sessions.

Failure modes → HTTP 403:
  • Token absent: NGINX-ATTEST-001
  • Token structurally invalid: NGINX-ATTEST-002
  • Backend returns verified=false: NGINX-ATTEST-003
  • Backend unreachable (5xx): NGINX-ATTEST-004 (fail-closed)
  • Device does not meet MEETS_DEVICE_INTEGRITY: NGINX-ATTEST-005

Dev/CI bypass available via ATTESTATION_BYPASS_ALLOWED=true (NEVER in production).
                """.trimIndent(),
                threatId = "NGINX-ATTEST-001",
                severity = RaspSensorRegistry.Severity.CRITICAL,
                riskScore = 0,
                decision = Decision.BLOCK,
                nginxPhase = NginxPhase.PHASE_3,
                luaModule = "attestation_validator.lua",
                architectureProtected = true,
            ),
        )),

        // ── Group 2: Replay Prevention ──────────────────────────────────────────

        ThreatGroup(GROUP_REPLAY, "#CE93D8", listOf(

            NetworkThreat(
                name = "Nonce Replay (Redis, 300 s)",
                protectionLine = "nonce_validator.lua — SET NX EX in Redis; composite key SHA-256(device+nonce)",
                detailText = """
NGINX Phase 2 — nonce_validator.lua

Prevents cross-instance replay attacks by deduplicating nonces in Redis — shared
across all NGINX worker processes and all edge nodes.

Redis key format:
    "nonce:" + SHA-256(device_id + ":" + nonce_value)
This matches the backend's NonceStore.consume() composite key exactly, ensuring
both layers protect the same logical nonce space.

Write strategy: SET NX EX 300 (atomic, race-condition-safe).
  • SET succeeds (nonce not seen) → request continues.
  • SET returns nil (nonce already in Redis) → HTTP 403 NGINX-NONCE-REDIS-001.

Two-level check:
  L1: local shared dict fast-path (30 s TTL) — avoids Redis on obvious replays.
  L2: Redis distributed check — covers cross-worker and cross-instance cases.

Fail-open on Redis outage (ERR log) — in-process cache from request_filter.lua
provides intra-worker protection as fallback.

All canonical window sizes are aligned: SDK token exp = ts + 300s,
NGINX filter window = 300s, Redis TTL = 300s, backend NonceStore = 300s.
                """.trimIndent(),
                threatId = "NGINX-NONCE-001",
                severity = RaspSensorRegistry.Severity.CRITICAL,
                riskScore = 0,
                decision = Decision.BLOCK,
                nginxPhase = NginxPhase.PHASE_2,
                luaModule = "nonce_validator.lua",
                architectureProtected = true,
            ),

            NetworkThreat(
                name = "Timestamp Replay (±60 s)",
                protectionLine = "header_validator.lua — ts field checked against ngx.time(); ±60 s window",
                detailText = """
NGINX Phase 1 — header_validator.lua + trusted_time_validator.lua

The X-PayShield-Token carries a ts (epoch seconds) field. NGINX checks:
    |ngx.time() - ts| ≤ 60 seconds

If outside the window: HTTP 403 with challenge RESYNC_TIME (NGINX-HDR-VALID-010).
The RESYNC_TIME challenge tells the SDK to re-sync its clock via the trusted time
endpoint (/api/v1/time) before retrying.

trusted_time_validator.lua (Phase 3) enforces a stricter ±300 s drift check with
a Redis-backed server clock offset to defend against NTP manipulation attacks.

Why both checks?
  header_validator enforces the SDK-level freshness contract (±60 s is the expected
  maximum drift for a legitimate device in normal use).
  trusted_time_validator is the anti-NTP-spoofing backstop — if an attacker tampers
  the device clock to extend the ±60 s window, the server-side reference catches it.
                """.trimIndent(),
                threatId = "NGINX-TS-001",
                severity = RaspSensorRegistry.Severity.HIGH,
                riskScore = 0,
                decision = Decision.BLOCK,
                nginxPhase = NginxPhase.PHASE_1,
                luaModule = "header_validator.lua + trusted_time_validator.lua",
                architectureProtected = true,
            ),

            NetworkThreat(
                name = "In-process Nonce Replay (30 s)",
                protectionLine = "request_filter.lua — shared dict replay_cache; 300 s TTL per nonce",
                detailText = """
NGINX Phase 5 — request_filter.lua + edge_threat.lua

Intra-worker, in-process first line of defence before the Redis check.
Nonces are stored in the NGINX shared dict replay_cache with TTL = 300 s.

This catches same-nonce replays from the same client IP within the same NGINX
worker process without any network hop — useful for rapid automated replay attacks
that hit the same worker.

edge_threat.lua (Phase 5) maintains a separate SDK-nonce dedup in replay_cache
with NONCE_TTL_SECONDS = 30 s and rejects at threshold IP_REPLAY_LIMIT = 10
requests per IP_REPLAY_WINDOW = 5 s:
    Sets header X-PayShield-Edge-Threat: NGINX-API-REPLAY-001

The 30 s / 5 s windows here are tighter than the 300 s Redis window, providing
immediate rate-based replay detection before the distributed Redis check.
                """.trimIndent(),
                threatId = "NGINX-REPLAY-001",
                severity = RaspSensorRegistry.Severity.HIGH,
                riskScore = 0,
                decision = Decision.BLOCK,
                nginxPhase = NginxPhase.PHASE_5,
                luaModule = "request_filter.lua + edge_threat.lua",
                architectureProtected = true,
            ),
        )),

        // ── Group 3: Bot & Automation ────────────────────────────────────────────

        ThreatGroup(GROUP_BOT, "#A5D6A7", listOf(

            NetworkThreat(
                name = "Bot / Automated Traffic",
                protectionLine = "bot_detector.lua — composite score: rate + UA fingerprint + Accept-Language",
                detailText = """
NGINX Phase 1 — bot_detector.lua  (SIGNAL ONLY — score forwarded to backend)

Three signals combine into a bot likelihood score (0–100):

Signal 1 — Request rate per IP:
  Counts requests in a 10 s rolling window (bot_churn shared dict).
  >30 req/10 s = automated → score contribution up to 60 points.
  Normal SDK users: 1–3 requests per interaction.

Signal 2 — User-Agent fingerprint:
  • Empty UA  → +50 (automation script)
  • curl / python-requests / wget / go-http-client / java → +40
  • UA present but no "PayShield" substring → +20
  • PayShield SDK UA (e.g. "PayShield/2.1.0 (Android 14; SM-G998B)") → 0

Signal 3 — Accept-Language header:
  • Missing → +10 (headless browsers and scripts typically omit it)

Score published as X-PS-Bot-Score header to backend ML pipeline.
Backend combines X-PS-Bot-Score with behavioral biometric anomaly to decide
STEP_UP or BLOCK.  bot_detector.lua does NOT call ngx.exit() — it is signal-only.
                """.trimIndent(),
                threatId = "NGINX-BOT-001",
                severity = RaspSensorRegistry.Severity.HIGH,
                riskScore = 70,
                decision = Decision.STEP_UP,
                nginxPhase = NginxPhase.PHASE_1,
                luaModule = "bot_detector.lua",
                architectureProtected = true,
            ),

            NetworkThreat(
                name = "IP Rate Burst",
                protectionLine = "edge_threat.lua — >10 req / 5 s per IP → NGINX-API-REPLAY-001 flag",
                detailText = """
NGINX Phase 5 — edge_threat.lua

Tracks request count per IP in a 5-second window using the replay_store shared dict.
If count ≥ IP_REPLAY_LIMIT (10), sets header:
    X-PayShield-Edge-Threat: NGINX-API-REPLAY-001

This header is forwarded to the backend as a threat signal. The backend's risk
engine reads it and applies enhanced scrutiny (reduced rate limit on that device,
forced STEP_UP for next PAYMENT action).

Why not block at edge?  Legitimate high-frequency use cases (e.g. a user rapidly
switching between screens) could hit 10 requests in 5 seconds.  The backend has
device-level session context to distinguish legitimate from malicious bursts.
                """.trimIndent(),
                threatId = "NGINX-RATE-001",
                severity = RaspSensorRegistry.Severity.MEDIUM,
                riskScore = 45,
                decision = Decision.FLAG,
                nginxPhase = NginxPhase.PHASE_5,
                luaModule = "edge_threat.lua",
                architectureProtected = true,
            ),
        )),

        // ── Group 4: Network Origin ──────────────────────────────────────────────

        ThreatGroup(GROUP_ORIGIN, "#FFAB91", listOf(

            NetworkThreat(
                name = "Tor Exit Node",
                protectionLine = "asn_reputation_blocker.lua — MaxMind geoip2_data_is_tor_exit_node → BLOCK",
                detailText = """
NGINX Phase 1 — asn_reputation_blocker.lua (NGINX-ASN-TOR-001)

Reads the MaxMind GeoLite2-Anonymous-IP database flag:
    geoip2_data_is_tor_exit_node = "1"

Tor exit nodes are IP addresses from which Tor circuit traffic exits onto the
public internet.  Banking API traffic via Tor indicates:
  (a) Deliberate anonymisation to hide the request origin, OR
  (b) A compromised device routing traffic through Tor unbeknownst to the user.

Both cases are blocked immediately — HTTP 403 NGINX-ASN-TOR-001.
Result is cached in asn_block_cache shared dict for 10 minutes so repeated
connections from the same IP skip the GeoIP2 lookup.

Note: MaxMind GeoLite2-Anonymous-IP database must be mounted at:
  /usr/share/GeoIP/GeoLite2-Anonymous-IP.mmdb
If absent, the variable resolves to "" (treated as "0") — fail-open for availability.
                """.trimIndent(),
                threatId = "NGINX-ASN-TOR-001",
                severity = RaspSensorRegistry.Severity.CRITICAL,
                riskScore = 100,
                decision = Decision.BLOCK,
                nginxPhase = NginxPhase.PHASE_1,
                luaModule = "asn_reputation_blocker.lua",
                architectureProtected = true,
            ),

            NetworkThreat(
                name = "VPN / Anonymous Proxy",
                protectionLine = "asn_reputation_blocker.lua — MaxMind anonymous VPN + public proxy flag → BLOCK",
                detailText = """
NGINX Phase 1 — asn_reputation_blocker.lua (NGINX-ASN-PROXY-001)
Also: geo_enrichment.lua signals X-PS-Proxy-Flags: VPN / TOR / HOSTING / PROXY

MaxMind GeoLite2-Anonymous-IP flags checked:
  geoip2_data_is_anonymous_vpn  = "1"  → anonymous VPN service
  geoip2_data_is_public_proxy   = "1"  → public proxy

If either is "1": HTTP 403 NGINX-ASN-PROXY-001.

geo_enrichment.lua (Phase 1, signal-only) additionally forwards all anonymiser
flags as X-PS-Proxy-Flags (VPN, TOR, HOSTING, PROXY) and X-PS-Anon-Flags to the
backend ML pipeline for fraud scoring context.

On-device correlation: the SDK's VPN_CONFLICT RASP signal fires when a conflicting
VPN app is detected on the device itself — this provides the client-side view of
the same threat that the NGINX GeoIP2 check provides from the network side.
                """.trimIndent(),
                threatId = "NGINX-ASN-PROXY-001",
                severity = RaspSensorRegistry.Severity.HIGH,
                riskScore = 80,
                decision = Decision.BLOCK,
                nginxPhase = NginxPhase.PHASE_1,
                luaModule = "asn_reputation_blocker.lua",
                signalTypes = listOf("VPN_CONFLICT"),
            ),

            NetworkThreat(
                name = "Hostile ASN (Bulletproof Hosting)",
                protectionLine = "asn_reputation_blocker.lua — static ASN denylist: bulletproof hosting + botnet C2",
                detailText = """
NGINX Phase 1 — asn_reputation_blocker.lua (NGINX-ASN-HOSTILE-001)

Static list of known-hostile Autonomous System Numbers (ASNs) sourced from:
  • abuse.ch threat intelligence
  • Spamhaus ASN-DROP list
  • Internal threat intel (bulletproof hosting, botnet C2 ranges)

Examples in the deny list:
  AS209588 — Flyservers (bulletproof hosting)
  AS49581   — Sebastian-Fabian Schulz (botnet infrastructure)
  AS206728  — MonoVM (abuse-heavy VPS)
  AS197414  — Maxko (bulletproof hosting EU)
  AS35913   — DediPath (history of abuse)
  AS9009    — M247 Europe (high VPN usage)
  AS36352   — ColoCrossing (frequent abuse)

If the inbound IP's ASN matches: HTTP 403 NGINX-ASN-HOSTILE-001.
Cached 10 minutes per IP.

Legitimate bank users never originate from bulletproof hosting ASNs.
Automated fraud campaigns and botnet-driven credential stuffing commonly do.

Long-term: Redis-backed dynamic ASN denylist replaces this static list for
real-time threat intel updates without NGINX restarts.
                """.trimIndent(),
                threatId = "NGINX-ASN-HOSTILE-001",
                severity = RaspSensorRegistry.Severity.CRITICAL,
                riskScore = 100,
                decision = Decision.BLOCK,
                nginxPhase = NginxPhase.PHASE_1,
                luaModule = "asn_reputation_blocker.lua",
                architectureProtected = true,
            ),

            NetworkThreat(
                name = "Geo Velocity Anomaly",
                protectionLine = "edge_threat.lua — country-change within 5 min window → NGINX-GEO-ANOMALY-001",
                detailText = """
NGINX Phase 5 — edge_threat.lua

Tracks the last-seen country code per IP in the geo_store shared dict (TTL 300 s).
If the country changes within the 300 s window:
    X-PayShield-Edge-Threat: NGINX-GEO-ANOMALY-001

This detects impossible geo-velocity:
  Request 1 from Mumbai (IN) → stored in geo_store
  Request 2 (< 5 min later) from Dubai (AE) → country change → anomaly flagged

The flag is forwarded to the backend as a threat signal alongside the full geo
context from geo_enrichment.lua:
    X-PS-Country: {country_code}
    X-PS-ASN:     {asn}
    X-PS-ASN-Org: {asn_organisation}

Backend's composite decision engine factors geo-velocity into the fraud score.
High-value transactions (PAYMENT) with active geo anomaly → STEP_UP.

On-device correlation: MOCK_LOCATION RASP signal fires when the device's GPS
location is being spoofed — the client-side counterpart to network-layer geo anomaly.
                """.trimIndent(),
                threatId = "NGINX-GEO-001",
                severity = RaspSensorRegistry.Severity.HIGH,
                riskScore = 65,
                decision = Decision.FLAG,
                nginxPhase = NginxPhase.PHASE_5,
                luaModule = "edge_threat.lua",
                signalTypes = listOf("MOCK_LOCATION"),
            ),

            NetworkThreat(
                name = "Datacenter Origin (Registration)",
                protectionLine = "asn_reputation_blocker.lua — hosting provider on /enroll/register blocked",
                detailText = """
NGINX Phase 1 — asn_reputation_blocker.lua (NGINX-ASN-HOSTING-001)

MaxMind flag: geoip2_data_is_hosting_provider = "1"

Applied ONLY on pre-auth registration routes:
  /api/v1/device/register
  /api/v1/enroll/register
  /api/v1/enroll/nonce

Legitimate mobile SDK clients are always on cellular or residential WiFi — they
do NOT originate from AWS/GCP/Azure/Hetzner data centres.  A hosting-provider IP
on a registration route indicates automated key stuffing (mass enrollment of fake
devices for later fraudulent use).

NOT applied on authenticated telemetry / payment routes — enterprise customers
behind cloud-based NAT gateways must be supported on those routes.

Blocked: HTTP 403 NGINX-ASN-HOSTING-001.
                """.trimIndent(),
                threatId = "NGINX-ASN-HOSTING-001",
                severity = RaspSensorRegistry.Severity.MEDIUM,
                riskScore = 60,
                decision = Decision.BLOCK,
                nginxPhase = NginxPhase.PHASE_1,
                luaModule = "asn_reputation_blocker.lua",
                architectureProtected = true,
            ),
        )),

        // ── Group 5: Risk Gate & Kill-switch ────────────────────────────────────

        ThreatGroup(GROUP_RISK, "#EF9A9A", listOf(

            NetworkThreat(
                name = "SDK Edge Risk ≥ 60 (HIGH)",
                protectionLine = "edge_risk_handler.lua — X-Edge-Risk-Level ≥ 60 → HTTP 403 NGINX-ERR-001",
                detailText = """
NGINX Phase 5 — edge_risk_handler.lua

The PayShield SDK computes a fused risk score (0–100) from:
    RASP signals (60%) + Behaviour (25%) + Network (15%)
and sends it as X-Edge-Risk-Level on every request.

Thresholds:
  ≥ 60 (HIGH rng="HIGH")   → ngx.exit(403) NGINX-ERR-001  — hard BLOCK
  ≥ 30 (rng="MEDIUM")      → ngx.ctx.edge_risk_review = true — REVIEW flag, pass through
  < 30 (rng="LOW")          → ALLOW

Example path to score ≥ 60:
  Root cloaking detected (RASP signal, weight 60%) → score ≈ 60 → BLOCK at edge
  even before the request body is parsed or the backend ML runs.

The backend (gateway_verify.py) applies a secondary threshold of 40 as a backstop
for the case where DeviceCommandStore (Redis) is down and force_block can't be read —
edge risk is the last line of defence in that failure mode.

Note: Previous code compared risk_level == "BLOCK" (string) — the header is always
an integer string ("0", "30", "60"). The bug was fixed; tonumber() is used.
                """.trimIndent(),
                threatId = "NGINX-RISK-HIGH-001",
                severity = RaspSensorRegistry.Severity.CRITICAL,
                riskScore = 60,
                decision = Decision.BLOCK,
                nginxPhase = NginxPhase.PHASE_5,
                luaModule = "edge_risk_handler.lua",
                architectureProtected = true,
            ),

            NetworkThreat(
                name = "Edge Risk Gate ≥ 40 (edge_threat)",
                protectionLine = "edge_threat.lua — MAX_RISK_ALLOWED=40; missing SDK headers → BLOCK",
                detailText = """
NGINX Phase 5 — edge_threat.lua

A complementary (older) risk gate that enforces:
    MAX_RISK_ALLOWED = 40

Also enforces required SDK headers:
  • X-Edge-Risk-Level  — must be present
  • X-Edge-Nonce       — must be present
  • X-Device-Id        — must be present
  → Missing any: HTTP 403 NGINX-EDGE-HEADER-MISSING-001

Risk enforcement:
  risk ≥ 40 → HTTP 403 NGINX-EDGE-RISK-BLOCK-001
  risk < 40 → forward X-Edge-Request-Hash, X-Edge-Nonce, X-Device-Id to backend

After passing, sets X-PS-Forward-Approved: true — the backend MUST reject any
request without this header (proves it cleared the full NGINX pipeline).
Any client-supplied X-PS-Forward-Approved is stripped first to prevent forgery.

Note: edge_risk_handler.lua (threshold 60) runs AFTER this module.  They coexist:
  edge_threat.lua:       MAX_RISK_ALLOWED = 40 (legacy; mismatched thresholds fix needed)
  edge_risk_handler.lua: BLOCK_THRESHOLD  = 60 (primary enforcement)
  gateway_verify.py:     _EDGE_RISK_DENY_THRESHOLD = 40 (backend backstop)
                """.trimIndent(),
                threatId = "NGINX-RISK-GATE-001",
                severity = RaspSensorRegistry.Severity.CRITICAL,
                riskScore = 40,
                decision = Decision.BLOCK,
                nginxPhase = NginxPhase.PHASE_5,
                luaModule = "edge_threat.lua",
                architectureProtected = true,
            ),

            NetworkThreat(
                name = "Threat Matrix Enforcement",
                protectionLine = "security_checks.lua — 7-rule threat_matrix.json; TLS/proxy/replay/bot/repackaged",
                detailText = """
NGINX Phase 5 — security_checks.lua + /config/threat_matrix.json

7 deterministic block rules evaluated against ctx.signals in sequence:

  ID                    SIGNAL          VALUE   ACTION
  ─────────────────────────────────────────────────────────
  TLS_PINNING_FAIL      tls_pinning     false   BLOCK (HTTP 403)
  PROXY_VPN_TOR         proxy           true    BLOCK
  REPLAY_NONCE          replay          true    BLOCK
  APPICRYPT_FAIL        attestation     false   BLOCK
  NETWORK_MGMT_DETECTED network_mgmt    true    BLOCK
  BOT_TRAFFIC           bot             true    BLOCK
  REPACKAGED_APP        tampered        true    BLOCK

Any matching rule: HTTP 403, body: {"decision":"blocked","threat":"{rule.id}"}.
Rules are evaluated in order; first match blocks (no further evaluation).
Config is mounted from payshield-backend/config/threat_matrix.json — shared by
both the NGINX pipeline and the backend compliance evaluator for consistency.
                """.trimIndent(),
                threatId = "NGINX-MATRIX-001",
                severity = RaspSensorRegistry.Severity.CRITICAL,
                riskScore = 100,
                decision = Decision.BLOCK,
                nginxPhase = NginxPhase.PHASE_5,
                luaModule = "security_checks.lua",
                architectureProtected = true,
            ),

            NetworkThreat(
                name = "Device Kill-switch (Admin Force-block)",
                protectionLine = "device_block.lua — Redis block flag; gateway_verify.py DeviceCommandStore",
                detailText = """
NGINX Phase 5 — device_block.lua + backend gateway_verify.py DeviceCommandStore

Operators issue device-level commands via POST /api/v1/admin/device-commands:
  force_block    — immediately block ALL requests from this device
  force_step_up  — require step-up auth for listed action types

NGINX device_block.lua reads the block flag from a Redis-backed device block dict:
  ngx.var.block_device == "1" → HTTP 403, edge_block_reason = EDGE_DEVICE_BLOCK

The same command is also propagated to the mobile SDK via the ThreatBuffer ACK
on /threats/batch — the SDK receives kill-switch commands within 5 seconds and
blocks locally before the next request is even sent.

gateway_verify.py checks DeviceCommandStore on every /verify/gateway call as a
belt-and-suspenders enforcement:
  force_block active → DENY (returned to customer API gateway in < 20 ms)
  force_step_up[ACTION] → STEP_UP + challenge_type = "OTP"

Fail-open on Redis outage for DeviceCommandStore — the edge risk gate (threshold 40)
serves as backstop, since a HIGH-risk device carries X-Edge-Risk-Level ≥ 40 and
would be blocked by edge_threat.lua regardless.
                """.trimIndent(),
                threatId = "NGINX-DEVICE-BLOCK-001",
                severity = RaspSensorRegistry.Severity.CRITICAL,
                riskScore = 100,
                decision = Decision.BLOCK,
                nginxPhase = NginxPhase.PHASE_5,
                luaModule = "device_block.lua",
                architectureProtected = true,
            ),
        )),
    )

    /** Flat list of all threats, in group order, for indexing into row views. */
    val ALL: List<NetworkThreat> = ALL_GROUPS.flatMap { it.threats }
}
