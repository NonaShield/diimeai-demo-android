"""
PayShield — Composite Decision Models  (Gap X.1)

Data models for the multi-layer Composite Decision Token (CDT) that replaces
the single-bit X-PS-Forward-Approved header.

Layers
──────
  edge_trust   NGINX cryptographic + attestation layer score   (weight 10%)
  fraud        ML engine + RiskAggregator fraud risk score     (weight 30%)
  graph        Neo4j graph pattern analysis score              (weight 15%)
  semantic     SemanticAnomalyGate heuristic inspection score  (weight 15%)
  ai           Agentic AI (Airflow async pipeline)             (weight 20%)
  compliance   Compliance rule violation score                 (weight 10%)

Final action
────────────
  ALLOW    — composite_score < 30 AND no hard flags
  REVIEW   — composite_score 30-49  (forward to backend, flag for review)
  STEP_UP  — composite_score 50-74  (re-authentication required)
  BLOCK    — composite_score >= 75 OR any hard BLOCK flag from any layer
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── Edge context (NGINX → Backend) ───────────────────────────────────────────

@dataclass
class EdgeTrustLayer:
    """NGINX trust / attestation layer from the edge context token."""
    level:    str  = "REVIEW"   # FULL | STANDARD | REVIEW
    attested: bool = False
    strong:   bool = False
    basic:    bool = False


@dataclass
class EdgeRASPLayer:
    """RASP runtime integrity signals from the device."""
    risk:              str  = "CLEAN"   # CLEAN | ELEVATED | HIGH
    root_detected:     bool = False
    hook_detected:     bool = False
    emulator_detected: bool = False
    debug_detected:    bool = False


@dataclass
class EdgeBotLayer:
    """Bot detection score from NGINX."""
    score: int  = 0
    clean: bool = True


@dataclass
class EdgeGeoLayer:
    """Geo-context from the edge."""
    cc:         str  = "XX"
    is_tor:     bool = False
    is_vpn:     bool = False
    is_hosting: bool = False


@dataclass
class EdgeLayers:
    """All NGINX-side layer data extracted from the edge context token."""
    trust:      EdgeTrustLayer = field(default_factory=EdgeTrustLayer)
    rasp:       EdgeRASPLayer  = field(default_factory=EdgeRASPLayer)
    bot:        EdgeBotLayer   = field(default_factory=EdgeBotLayer)
    geo:        EdgeGeoLayer   = field(default_factory=EdgeGeoLayer)
    time_drift: int            = 0
    replay_clean: bool         = True
    schema_valid: bool         = True


@dataclass
class EdgeContext:
    """
    Parsed and HMAC-verified edge context token.

    Produced by edge_context_composer.lua, verified by
    EdgeContextVerifier.verify() in composite_decision_service.py.
    """
    v:          int        = 1
    req_id:     str        = ""
    device_id:  str        = ""
    tenant_id:  str        = ""
    ts:         int        = 0
    exp:        int        = 0
    edge_score: int        = 0     # 0-100 risk score from NGINX
    layers:     EdgeLayers = field(default_factory=EdgeLayers)
    signed:     bool       = False  # False if HMAC was absent/invalid


# ── Layer scores (all 6 layers) ───────────────────────────────────────────────

@dataclass
class LayerScores:
    """
    Individual risk scores from each decision layer (0-100 each).

    Convention: 0 = fully clean / trusted, 100 = absolute block signal.
    """
    edge_trust:  int = 0   # from EdgeContext.edge_score
    fraud:       int = 0   # from MLEngine + RiskAggregator
    graph:       int = 0   # from GraphAnalyzer (0 if Neo4j unavailable)
    semantic:    int = 0   # from SemanticAnomalyGate
    ai:          int = 0   # from Agentic AI pipeline (0 if async / unavailable)
    compliance:  int = 0   # 0=compliant, >0 = violation severity


# ── Final Composite Decision ─────────────────────────────────────────────────

@dataclass
class FinalCompositeDecision:
    """
    The authoritative multi-layer decision produced by CompositeDecisionService.

    This is the single source of truth for enforcement and is persisted as
    forensic evidence (advisory_data["composite_decision"]) so auditors can
    trace exactly how every request was decided.
    """
    decision_id:     str         = ""
    final_action:    str         = "ALLOW"   # ALLOW | REVIEW | STEP_UP | BLOCK
    composite_score: int         = 0         # 0-100 weighted sum across all layers
    layer_scores:    LayerScores = field(default_factory=LayerScores)
    flags:           List[str]   = field(default_factory=list)
    evidence_id:     str         = ""
    processing_ms:   float       = 0.0
    tenant_id:       str         = ""
    device_id:       str         = ""
    rule_version:    str         = ""
    rule_hash:       str         = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict for storage in advisory_data."""
        return {
            "decision_id":     self.decision_id,
            "final_action":    self.final_action,
            "composite_score": self.composite_score,
            "layer_scores": {
                "edge_trust":  self.layer_scores.edge_trust,
                "fraud":       self.layer_scores.fraud,
                "graph":       self.layer_scores.graph,
                "semantic":    self.layer_scores.semantic,
                "ai":          self.layer_scores.ai,
                "compliance":  self.layer_scores.compliance,
            },
            "flags":         self.flags,
            "evidence_id":   self.evidence_id,
            "processing_ms": round(self.processing_ms, 2),
            "tenant_id":     self.tenant_id,
            "device_id":     self.device_id,
            "rule_version":  self.rule_version,
            "rule_hash":     self.rule_hash,
        }

    def to_response_headers(self) -> Dict[str, str]:
        """
        Produce response headers for the HTTP reply.

        NGINX reads these in header_filter_by_lua_file to log the final
        decision and optionally feed it back into the edge learning cache.
        """
        return {
            "X-PS-Final-Decision":   self.final_action,
            "X-PS-Composite-Score":  str(self.composite_score),
            "X-PS-Decision-Id":      self.decision_id,
            "X-PS-Evidence-Id":      self.evidence_id,
        }
