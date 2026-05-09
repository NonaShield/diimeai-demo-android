"""
PayShield — Composite Decision Service  (Gap X.1)

OWASP: A04:2021 — Insecure Design (missing multi-layer decision composition)
Architecture: Cross-cutting — NGINX ↔ Backend decision contract

Problem
───────
  X-PS-Forward-Approved was a 1-bit header: NGINX either approved or blocked.
  The backend ran its own layers (fraud, semantic, AI, compliance) independently
  but there was no composition — NGINX's crypto result and the backend's fraud
  result could never be combined into a single authoritative decision.

  Consequences:
    • "Crypto OK but AI flagged anomaly" had no expression path
    • Forensic evidence did not include which layers contributed to a decision
    • A spoofed X-PS-Forward-Approved: true bypassed all backend checks

Solution
────────
  1. NGINX produces X-PS-Edge-Context: HMAC-signed JSON with all edge layer
     scores (trust, RASP, bot, geo, replay, schema) — replaces the 1-bit header.

  2. Backend verifies the HMAC, extracts edge layer scores, runs its own layers
     (fraud, graph, semantic, ai, compliance), then calls this service to compose
     a weighted FinalCompositeDecision.

  3. FinalCompositeDecision is:
     (a) Returned from the API route (action field drives HTTP status code)
     (b) Persisted as advisory_data["composite_decision"] in the evidence record
     (c) Stamped on the response as X-PS-Final-Decision / X-PS-Composite-Score /
         X-PS-Decision-Id so NGINX can log it in header_filter

Layer weights
─────────────
  edge_trust  10%  — NGINX crypto + attestation (hardware root-of-trust)
  fraud       30%  — ML engine + RiskAggregator (highest weight: core product)
  graph       15%  — Neo4j graph pattern analysis
  semantic    15%  — SemanticAnomalyGate heuristic inspection
  ai          20%  — Agentic AI (Airflow async; 0 if unavailable — conservative)
  compliance  10%  — Compliance rule violation severity

Action thresholds
─────────────────
  BLOCK    composite_score ≥ 75  OR  any layer has a hard BLOCK flag
  STEP_UP  composite_score ≥ 50
  REVIEW   composite_score ≥ 30
  ALLOW    composite_score < 30  AND  no hard flags
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional

from app.models.composite_decision import (
    EdgeBotLayer,
    EdgeContext,
    EdgeGeoLayer,
    EdgeLayers,
    EdgeRASPLayer,
    EdgeTrustLayer,
    FinalCompositeDecision,
    LayerScores,
)

logger = logging.getLogger("payshield.composite_decision_service")

# ── Configuration ─────────────────────────────────────────────────────────────
_HMAC_KEY       = os.environ.get("EDGE_CONTEXT_HMAC_KEY", "")
_TOKEN_MAX_AGE  = int(os.environ.get("EDGE_CONTEXT_MAX_AGE", "120"))  # seconds

# Layer weights — configurable but must sum to 1.0
_WEIGHTS: Dict[str, float] = {
    "edge_trust":  float(os.environ.get("CDT_WEIGHT_EDGE_TRUST",  "0.10")),
    "fraud":       float(os.environ.get("CDT_WEIGHT_FRAUD",        "0.30")),
    "graph":       float(os.environ.get("CDT_WEIGHT_GRAPH",        "0.15")),
    "semantic":    float(os.environ.get("CDT_WEIGHT_SEMANTIC",     "0.15")),
    "ai":          float(os.environ.get("CDT_WEIGHT_AI",           "0.20")),
    "compliance":  float(os.environ.get("CDT_WEIGHT_COMPLIANCE",   "0.10")),
}

# Action thresholds
_BLOCK_THRESHOLD   = int(os.environ.get("CDT_BLOCK_THRESHOLD",   "75"))
_STEP_UP_THRESHOLD = int(os.environ.get("CDT_STEP_UP_THRESHOLD", "50"))
_REVIEW_THRESHOLD  = int(os.environ.get("CDT_REVIEW_THRESHOLD",  "30"))


# ═════════════════════════════════════════════════════════════════════════════
# Edge Context Verifier
# ═════════════════════════════════════════════════════════════════════════════

class EdgeContextError(ValueError):
    """Raised when the X-PS-Edge-Context header is absent, invalid, or expired."""


class EdgeContextVerifier:
    """
    Verifies and parses the X-PS-Edge-Context header set by edge_context_composer.lua.

    Token format:  <base64url_json>.<hmac_sha256_hex>
    """

    @classmethod
    def verify(cls, header_value: Optional[str]) -> EdgeContext:
        """
        Verify HMAC and extract the EdgeContext from the header.

        Parameters
        ----------
        header_value : str | None — value of X-PS-Edge-Context request header

        Returns
        -------
        EdgeContext — verified and parsed; .signed=False if HMAC key not configured

        Raises
        ------
        EdgeContextError — if header is missing, malformed, HMAC fails, or token expired
        """
        if not header_value:
            raise EdgeContextError("X-PS-Edge-Context header is absent")

        parts = header_value.strip().split(".")
        if len(parts) != 2:
            raise EdgeContextError(
                f"X-PS-Edge-Context has {len(parts)} parts; expected 2 (payload.hmac)"
            )

        payload_b64, received_hmac = parts[0], parts[1]

        # ── HMAC verification ────────────────────────────────────────────────
        signed = False
        if _HMAC_KEY:
            expected_hmac = _hmac.new(
                _HMAC_KEY.encode("utf-8"),
                payload_b64.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            if not _hmac.compare_digest(expected_hmac, received_hmac):
                logger.warning(
                    "[edge_context] HMAC verification FAILED — possible header forgery"
                )
                raise EdgeContextError("X-PS-Edge-Context HMAC verification failed")
            signed = True
        else:
            # HMAC key not configured — accept token but mark as unsigned.
            # Backend will apply REVIEW-level minimum trust.
            logger.warning(
                "[edge_context] EDGE_CONTEXT_HMAC_KEY not set — accepting unsigned token "
                "(configure key for production)"
            )

        # ── Decode payload ───────────────────────────────────────────────────
        # Add padding back for base64 decoding
        padded = payload_b64.replace("-", "+").replace("_", "/")
        padded += "=" * (4 - len(padded) % 4)
        try:
            raw_json = base64.b64decode(padded).decode("utf-8")
            data: Dict[str, Any] = json.loads(raw_json)
        except Exception as exc:
            raise EdgeContextError(f"X-PS-Edge-Context payload decode failed: {exc}") from exc

        # ── Schema version guard ─────────────────────────────────────────────
        if data.get("v") != 1:
            raise EdgeContextError(
                f"X-PS-Edge-Context schema version {data.get('v')} not supported"
            )

        # ── Expiry check ─────────────────────────────────────────────────────
        now = int(time.time())
        token_ts  = int(data.get("ts",  0))
        token_exp = int(data.get("exp", 0))

        if token_exp > 0 and now > token_exp:
            raise EdgeContextError(
                f"X-PS-Edge-Context expired (issued={token_ts}, exp={token_exp}, now={now})"
            )

        # Reject tokens older than _TOKEN_MAX_AGE even if exp was not set
        if token_ts > 0 and (now - token_ts) > _TOKEN_MAX_AGE:
            raise EdgeContextError(
                f"X-PS-Edge-Context too old (age={(now - token_ts)}s, max={_TOKEN_MAX_AGE}s)"
            )

        # ── Build EdgeContext ─────────────────────────────────────────────────
        raw_layers = data.get("layers") or {}
        raw_trust  = raw_layers.get("trust")  or {}
        raw_rasp   = raw_layers.get("rasp")   or {}
        raw_bot    = raw_layers.get("bot")    or {}
        raw_geo    = raw_layers.get("geo")    or {}

        layers = EdgeLayers(
            trust = EdgeTrustLayer(
                level    = str(raw_trust.get("level",    "REVIEW")),
                attested = bool(raw_trust.get("attested", False)),
                strong   = bool(raw_trust.get("strong",   False)),
                basic    = bool(raw_trust.get("basic",    False)),
            ),
            rasp = EdgeRASPLayer(
                risk              = str(raw_rasp.get("risk",              "CLEAN")),
                root_detected     = bool(raw_rasp.get("root_detected",     False)),
                hook_detected     = bool(raw_rasp.get("hook_detected",     False)),
                emulator_detected = bool(raw_rasp.get("emulator_detected", False)),
                debug_detected    = bool(raw_rasp.get("debug_detected",    False)),
            ),
            bot = EdgeBotLayer(
                score = int(raw_bot.get("score", 0)),
                clean = bool(raw_bot.get("clean", True)),
            ),
            geo = EdgeGeoLayer(
                cc         = str(raw_geo.get("cc",         "XX")),
                is_tor     = bool(raw_geo.get("is_tor",     False)),
                is_vpn     = bool(raw_geo.get("is_vpn",     False)),
                is_hosting = bool(raw_geo.get("is_hosting", False)),
            ),
            time_drift   = int(raw_layers.get("time_drift", 0)),
            replay_clean = bool((raw_layers.get("replay") or {}).get("clean", True)),
            schema_valid = bool((raw_layers.get("schema") or {}).get("valid", True)),
        )

        return EdgeContext(
            v          = 1,
            req_id     = str(data.get("req_id",     "")),
            device_id  = str(data.get("device_id",  "")),
            tenant_id  = str(data.get("tenant_id",  "")),
            ts         = token_ts,
            exp        = token_exp,
            edge_score = int(data.get("edge_score", 0)),
            layers     = layers,
            signed     = signed,
        )

    @classmethod
    def verify_or_minimum(cls, header_value: Optional[str]) -> EdgeContext:
        """
        Like verify() but never raises — on failure returns a maximum-scrutiny
        EdgeContext (edge_score=100, trust=REVIEW, signed=False).

        Use this on routes where X-PS-Edge-Context may legitimately be absent
        (e.g. during the rollout transition period).
        """
        try:
            return cls.verify(header_value)
        except EdgeContextError as exc:
            logger.warning("[edge_context] verify failed — applying maximum edge scrutiny: %s", exc)
            return EdgeContext(
                edge_score = 100,
                signed     = False,
                layers     = EdgeLayers(
                    trust = EdgeTrustLayer(level="REVIEW"),
                    rasp  = EdgeRASPLayer(risk="HIGH"),
                ),
            )


# ═════════════════════════════════════════════════════════════════════════════
# Composite Decision Service
# ═════════════════════════════════════════════════════════════════════════════

class CompositeDecisionService:
    """
    Composes a FinalCompositeDecision from all 6 decision layers.

    The six layers and their risk scores (0-100 each) are weighted and summed
    to produce a composite_score which drives the final enforcement action.

    Hard-block rules
    ────────────────
    Independent of the composite score, these conditions always produce BLOCK:
      • RASP risk = HIGH (root / hook / tamper detected)
      • Tor exit node
      • Edge context HMAC forgery (edge_score=100 AND signed=False AND key is set)
    """

    @staticmethod
    def compose(
        edge_ctx:      EdgeContext,
        fraud_score:   int,
        graph_score:   int,
        semantic_score: int,
        compliance_score: int,
        ai_score:      int       = 0,
        evidence_id:   str       = "",
        tenant_id:     str       = "",
        device_id:     str       = "",
        rule_version:  str       = "",
        rule_hash:     str       = "",
        extra_flags:   Optional[List[str]] = None,
    ) -> FinalCompositeDecision:
        """
        Compose all layer scores into a single FinalCompositeDecision.

        Parameters
        ----------
        edge_ctx        : EdgeContext — verified NGINX edge context
        fraud_score     : int 0-100  — from MLEngine + RiskAggregator
        graph_score     : int 0-100  — from GraphAnalyzer (0 if Neo4j unavailable)
        semantic_score  : int 0-100  — from SemanticAnomalyGate
        compliance_score: int 0-100  — 0=compliant, 100=critical violation
        ai_score        : int 0-100  — from async AI pipeline (0 if unavailable)
        evidence_id     : str        — UUID of the persisted forensic evidence record
        tenant_id       : str
        device_id       : str
        rule_version    : str
        rule_hash       : str
        extra_flags     : List[str]  — additional flags from callers

        Returns
        -------
        FinalCompositeDecision
        """
        t_start = time.time()
        flags: List[str] = list(extra_flags or [])

        # ── Clamp all scores to 0-100 ────────────────────────────────────────
        edge_trust_score  = max(0, min(100, edge_ctx.edge_score))
        fraud_score       = max(0, min(100, fraud_score))
        graph_score       = max(0, min(100, graph_score))
        semantic_score    = max(0, min(100, semantic_score))
        ai_score          = max(0, min(100, ai_score))
        compliance_score  = max(0, min(100, compliance_score))

        # ── Hard-block conditions (override composite score) ─────────────────
        hard_block = False

        if edge_ctx.layers.rasp.risk == "HIGH":
            flags.append("HARD_BLOCK:RASP_HIGH_RISK")
            hard_block = True

        if edge_ctx.layers.geo.is_tor:
            flags.append("HARD_BLOCK:TOR_EXIT_NODE")
            hard_block = True

        # Unsigned token AND HMAC key is configured → possible forgery
        if not edge_ctx.signed and _HMAC_KEY:
            flags.append("HARD_BLOCK:EDGE_CONTEXT_UNSIGNED")
            hard_block = True

        # Schema validity failure at edge
        if not edge_ctx.layers.schema_valid:
            flags.append("HARD_BLOCK:SCHEMA_INVALID")
            hard_block = True

        # ── Collect advisory flags (non-blocking but informational) ──────────
        if not edge_ctx.layers.trust.attested:
            flags.append("FLAG:NO_ATTESTATION")

        if edge_ctx.layers.rasp.risk == "ELEVATED":
            flags.append("FLAG:RASP_ELEVATED")

        if edge_ctx.layers.rasp.emulator_detected:
            flags.append("FLAG:EMULATOR")

        if edge_ctx.layers.bot.score >= 60:
            flags.append("FLAG:HIGH_BOT_SCORE")

        if edge_ctx.layers.geo.is_vpn or edge_ctx.layers.geo.is_hosting:
            flags.append("FLAG:PROXY")

        if not edge_ctx.layers.replay_clean:
            flags.append("FLAG:REPLAY_ATTEMPT")

        if ai_score == 0:
            flags.append("FLAG:AI_UNAVAILABLE")

        if graph_score == 0:
            flags.append("FLAG:GRAPH_UNAVAILABLE")

        # ── Weighted composite score ─────────────────────────────────────────
        composite_score = int(round(
            edge_trust_score  * _WEIGHTS["edge_trust"]  +
            fraud_score       * _WEIGHTS["fraud"]        +
            graph_score       * _WEIGHTS["graph"]        +
            semantic_score    * _WEIGHTS["semantic"]     +
            ai_score          * _WEIGHTS["ai"]           +
            compliance_score  * _WEIGHTS["compliance"]
        ))
        composite_score = max(0, min(100, composite_score))

        # ── Determine final action ───────────────────────────────────────────
        if hard_block or composite_score >= _BLOCK_THRESHOLD:
            final_action = "BLOCK"
        elif composite_score >= _STEP_UP_THRESHOLD:
            final_action = "STEP_UP"
        elif composite_score >= _REVIEW_THRESHOLD:
            final_action = "REVIEW"
        else:
            final_action = "ALLOW"

        processing_ms = (time.time() - t_start) * 1000

        decision = FinalCompositeDecision(
            decision_id     = str(uuid.uuid4()),
            final_action    = final_action,
            composite_score = composite_score,
            layer_scores    = LayerScores(
                edge_trust  = edge_trust_score,
                fraud       = fraud_score,
                graph       = graph_score,
                semantic    = semantic_score,
                ai          = ai_score,
                compliance  = compliance_score,
            ),
            flags           = flags,
            evidence_id     = evidence_id,
            processing_ms   = processing_ms,
            tenant_id       = tenant_id,
            device_id       = device_id,
            rule_version    = rule_version,
            rule_hash       = rule_hash,
        )

        logger.info(
            "[CDT] decision_id=%s action=%s composite=%d "
            "scores(edge=%d fraud=%d graph=%d semantic=%d ai=%d compliance=%d) "
            "flags=%s tenant=%s device=%s",
            decision.decision_id,
            final_action,
            composite_score,
            edge_trust_score, fraud_score, graph_score,
            semantic_score, ai_score, compliance_score,
            flags,
            tenant_id, device_id,
        )

        return decision

    @staticmethod
    def compliance_score_from_result(compliance_result: Any) -> int:
        """
        Convert a ComplianceResult object to a 0-100 risk score.

        ComplianceResult status values:
          COMPLIANT      → 0
          WARNING        → 30
          NON_COMPLIANT  → 70
          CRITICAL       → 100
        """
        if compliance_result is None:
            return 0

        status = getattr(compliance_result, "status", None)
        if status is None:
            # Try .result attribute (different compliance evaluator return shapes)
            status = getattr(compliance_result, "result", None)

        mapping = {
            "COMPLIANT":     0,
            "PASS":          0,
            "WARNING":      30,
            "WARN":         30,
            "NON_COMPLIANT": 70,
            "FAIL":         70,
            "CRITICAL":    100,
            "BLOCK":       100,
        }
        return mapping.get(str(status).upper(), 0)
