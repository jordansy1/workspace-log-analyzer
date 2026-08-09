"""
Tier-1 Detection Adapter

Wrapper around the deterministic detection methods that provides:
- Individual detection method execution (vs running all 16 at once)
- "needs_investigation" verdict assignment for ambiguous cases
- Structured result objects for comparison analysis

This adapter enables testing individual detection methods in isolation
and measuring their effectiveness against ground truth.
"""

import sys
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable

# Add project root to path for imports
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Import detection methods
from tier1_detection.detection_methods import (
    detect_missing_mfa,
    detect_geographic_anomalies,
    detect_failed_logins,
    detect_rapid_access,
    detect_credential_stuffing,
    detect_password_spray,
    detect_impossible_travel,
    detect_mfa_fatigue,
    detect_session_anomalies,
    detect_off_hours_access,
    detect_account_manipulation,
    detect_google_suspicious_events,
    detect_google_session_cookie_hijacking,
    detect_oauth_token_abuse,
    detect_stolen_oauth_token,
    detect_malicious_oauth_app
)


@dataclass
class Tier1Result:
    """
    Result from tier-1 detection.

    Attributes:
        detected: Whether any anomaly was detected
        anomaly_count: Number of anomalies found
        anomalies: List of detected anomaly objects
        severity: Highest severity among detected anomalies (or None)
        verdict: Deterministic verdict ('clear_threat', 'clear_benign', 'needs_investigation')
        verdict_confidence: How confident is the deterministic system in this verdict
        verdict_rationale: Explanation of why this verdict was assigned
        execution_time_ms: Time taken to run detection
    """
    detected: bool
    anomaly_count: int
    anomalies: List[Dict[str, Any]]
    severity: Optional[str]
    verdict: str
    verdict_confidence: str
    verdict_rationale: str
    execution_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'detected': self.detected,
            'anomaly_count': self.anomaly_count,
            'anomalies': self.anomalies,
            'severity': self.severity,
            'verdict': self.verdict,
            'verdict_confidence': self.verdict_confidence,
            'verdict_rationale': self.verdict_rationale,
            'execution_time_ms': self.execution_time_ms
        }


class Tier1Adapter:
    """
    Adapter for running tier-1 detection methods on test scenarios.

    Unlike the full AnomalyDetector which runs all 16 methods,
    this adapter can run specific methods individually and provides
    verdict assignment based on detection results and context.
    """

    # Severity ranking for comparison
    SEVERITY_RANK = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1,
        None: 0
    }

    # Detection types that typically have clear verdicts (not ambiguous)
    CLEAR_THREAT_INDICATORS = {
        'session_cookie_hijacking',  # Google confirmed this - always critical
        'google_suspicious',         # Google flagged it
    }

    # Detection types that often need investigation (context-dependent)
    AMBIGUOUS_TYPES = {
        'missing_mfa',              # Could be policy gap vs compromise
        'geographic_anomalies',     # Could be travel vs attack
        'failed_login',             # Could be user error vs brute force
        'impossible_travel',        # Could be VPN vs attack
        'off_hours_access',         # Could be legitimate remote work
        'session_anomalies',        # Could be multi-device vs hijacking
    }

    def __init__(self):
        """Initialize the adapter with detection method mappings."""
        # Map detection types to their functions
        self.detection_map: Dict[str, Callable] = {
            'missing_mfa': detect_missing_mfa,
            'geographic_anomalies': detect_geographic_anomalies,
            'failed_login': detect_failed_logins,
            'rapid_access': detect_rapid_access,
            'credential_stuffing': detect_credential_stuffing,
            'password_spray': detect_password_spray,
            'impossible_travel': detect_impossible_travel,
            'mfa_fatigue': detect_mfa_fatigue,
            'session_anomalies': detect_session_anomalies,
            'off_hours_access': detect_off_hours_access,
            'account_manipulation': detect_account_manipulation,
            'google_suspicious': detect_google_suspicious_events,
            'session_cookie_hijacking': detect_google_session_cookie_hijacking,
            'oauth_token_abuse': detect_oauth_token_abuse,
            'stolen_oauth_token': detect_stolen_oauth_token,
            'malicious_oauth_app': detect_malicious_oauth_app,
        }

        # Thresholds for verdict assignment
        self.severity_thresholds = {
            'clear_threat': ['critical'],  # Critical severity = clear threat
            'likely_threat': ['high'],     # High severity = likely threat
            'needs_investigation': ['medium', 'low'],  # Medium/low = investigate
        }

    def detect(
        self,
        events: List[Dict[str, Any]],
        metadata: Dict[str, Any],
        detection_type: str,
        enriched_context: Optional[Dict[str, Any]] = None
    ) -> Tier1Result:
        """
        Run a specific detection method on events.

        Args:
            events: List of authentication events
            metadata: Event metadata (timestamps, user info, etc.)
            detection_type: Type of detection to run (e.g., 'failed_login')
            enriched_context: Optional enrichment data for verdict assignment

        Returns:
            Tier1Result with detection outcome and verdict
        """
        detection_func = self.detection_map.get(detection_type)
        if not detection_func:
            raise ValueError(f"Unknown detection type: {detection_type}")

        # Run detection
        start_time = time.time()

        # Handle different function signatures
        if detection_type in ['oauth_token_abuse', 'stolen_oauth_token', 'malicious_oauth_app']:
            # OAuth detections don't take metadata
            anomalies = detection_func(events)
        else:
            anomalies = detection_func(events, metadata)

        elapsed_ms = (time.time() - start_time) * 1000

        # Normalize result to list
        if anomalies is None:
            anomalies = []
        elif isinstance(anomalies, dict):
            anomalies = [anomalies]

        # Determine highest severity
        highest_severity = self._get_highest_severity(anomalies)

        # Assign verdict
        verdict, confidence, rationale = self._assign_verdict(
            detection_type=detection_type,
            anomalies=anomalies,
            severity=highest_severity,
            enriched_context=enriched_context
        )

        return Tier1Result(
            detected=len(anomalies) > 0,
            anomaly_count=len(anomalies),
            anomalies=anomalies,
            severity=highest_severity,
            verdict=verdict,
            verdict_confidence=confidence,
            verdict_rationale=rationale,
            execution_time_ms=elapsed_ms
        )

    def detect_all(
        self,
        events: List[Dict[str, Any]],
        metadata: Dict[str, Any],
        enriched_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Tier1Result]:
        """
        Run all detection methods on events.

        Args:
            events: List of authentication events
            metadata: Event metadata
            enriched_context: Optional enrichment data

        Returns:
            Dictionary mapping detection type to Tier1Result
        """
        results = {}
        for detection_type in self.detection_map.keys():
            try:
                results[detection_type] = self.detect(
                    events=events,
                    metadata=metadata,
                    detection_type=detection_type,
                    enriched_context=enriched_context
                )
            except Exception as e:
                # Log error but continue with other detections
                print(f"[Tier1Adapter] Error in {detection_type}: {e}")
                results[detection_type] = Tier1Result(
                    detected=False,
                    anomaly_count=0,
                    anomalies=[],
                    severity=None,
                    verdict='error',
                    verdict_confidence='none',
                    verdict_rationale=f'Detection error: {str(e)}',
                    execution_time_ms=0
                )
        return results

    def _get_highest_severity(self, anomalies: List[Dict[str, Any]]) -> Optional[str]:
        """Get the highest severity from a list of anomalies."""
        if not anomalies:
            return None

        highest = None
        highest_rank = 0

        for anomaly in anomalies:
            severity = anomaly.get('severity', 'low')
            rank = self.SEVERITY_RANK.get(severity, 0)
            if rank > highest_rank:
                highest_rank = rank
                highest = severity

        return highest

    def _assign_verdict(
        self,
        detection_type: str,
        anomalies: List[Dict[str, Any]],
        severity: Optional[str],
        enriched_context: Optional[Dict[str, Any]] = None
    ) -> tuple:
        """
        Assign a verdict based on detection results and context.

        The key innovation here is the 'needs_investigation' verdict for
        ambiguous cases where deterministic rules cannot confidently decide.

        Returns:
            Tuple of (verdict, confidence, rationale)
        """
        # No detection = clear benign
        if not anomalies:
            return (
                'clear_benign',
                'high',
                'No anomalies detected by deterministic rules'
            )

        # Session cookie hijacking is always critical - Google confirmed it
        if detection_type == 'session_cookie_hijacking':
            return (
                'clear_threat',
                'very_high',
                'Google detected session cookie theft - confirmed compromise'
            )

        # Critical severity from any detection = clear threat
        if severity == 'critical':
            return (
                'clear_threat',
                'high',
                f'Critical severity {detection_type} detected'
            )

        # Check if this is an ambiguous detection type
        if detection_type in self.AMBIGUOUS_TYPES:
            # These detection types need context to make a verdict
            return self._evaluate_ambiguous(
                detection_type=detection_type,
                anomalies=anomalies,
                severity=severity,
                enriched_context=enriched_context
            )

        # High severity attacks (spray, stuffing, etc.) = likely threat
        if severity == 'high' and detection_type in [
            'password_spray', 'credential_stuffing', 'mfa_fatigue',
            'account_manipulation', 'oauth_token_abuse', 'stolen_oauth_token'
        ]:
            return (
                'clear_threat',
                'high',
                f'High severity attack pattern ({detection_type}) detected'
            )

        # Default for other high severity = needs investigation
        if severity == 'high':
            return (
                'needs_investigation',
                'medium',
                f'High severity {detection_type} - context needed for verdict'
            )

        # Medium/low severity = needs investigation
        return (
            'needs_investigation',
            'low',
            f'{severity.title()} severity {detection_type} - cannot determine verdict without context'
        )

    def _evaluate_ambiguous(
        self,
        detection_type: str,
        anomalies: List[Dict[str, Any]],
        severity: Optional[str],
        enriched_context: Optional[Dict[str, Any]] = None
    ) -> tuple:
        """
        Evaluate ambiguous detection types.

        These are detection types where the verdict depends heavily on context:
        - Missing MFA could be policy gap or compromise attempt
        - Geographic anomalies could be travel or attack
        - Failed logins could be user error or brute force

        Returns:
            Tuple of (verdict, confidence, rationale)
        """
        # Without enriched context, we cannot make a confident verdict
        if not enriched_context:
            return (
                'needs_investigation',
                'low',
                f'{detection_type} detected but no context available for verdict'
            )

        # Check for clear benign indicators in context
        ip_rep = enriched_context.get('ip_reputation', {})
        geo = enriched_context.get('geolocation', enriched_context.get('enriched_location', {}))
        user_ctx = enriched_context.get('user_context', {})
        baseline = enriched_context.get('baseline', enriched_context.get('baseline_comparison', {}))

        # Build risk factors and benign factors
        risk_factors = []
        benign_factors = []

        # IP reputation analysis
        risk_score = ip_rep.get('risk_score', ip_rep.get('abuse_confidence_score', 0))
        if risk_score > 70:
            risk_factors.append(f'High risk IP (score: {risk_score})')
        elif risk_score < 20:
            benign_factors.append(f'Clean IP reputation (score: {risk_score})')

        if ip_rep.get('is_malicious'):
            risk_factors.append('IP flagged as malicious')

        # Threat indicators
        if geo.get('is_tor'):
            risk_factors.append('Tor exit node detected')
        if geo.get('is_hosting'):
            risk_factors.append('Hosting/datacenter IP')
        if geo.get('is_vpn') and not geo.get('is_tor'):
            # VPN alone is not necessarily bad
            pass  # Context-dependent

        # User context
        if user_ctx.get('is_admin'):
            risk_factors.append('Admin account targeted')
        if user_ctx.get('is_2fa_enrolled'):
            benign_factors.append('User has 2FA enrolled')

        # Baseline comparison
        if baseline.get('is_new_ip') and baseline.get('is_new_location'):
            risk_factors.append('New IP and new location')
        elif baseline.get('is_known_ip'):
            benign_factors.append('Known IP from baseline')

        # Decision logic
        risk_count = len(risk_factors)
        benign_count = len(benign_factors)

        # Clear threat: multiple risk factors and no benign
        if risk_count >= 2 and benign_count == 0:
            return (
                'clear_threat',
                'high',
                f'{detection_type}: {"; ".join(risk_factors)}'
            )

        # Clear benign: no risk factors and multiple benign
        if risk_count == 0 and benign_count >= 2:
            return (
                'clear_benign',
                'high',
                f'{detection_type} with benign context: {"; ".join(benign_factors)}'
            )

        # Mixed signals = needs investigation
        rationale_parts = []
        if risk_factors:
            rationale_parts.append(f'Risk: {"; ".join(risk_factors)}')
        if benign_factors:
            rationale_parts.append(f'Benign: {"; ".join(benign_factors)}')

        return (
            'needs_investigation',
            'low' if risk_count > benign_count else 'medium',
            f'{detection_type} with mixed signals. {" | ".join(rationale_parts)}'
        )

    def get_supported_detections(self) -> List[str]:
        """Return list of supported detection types."""
        return list(self.detection_map.keys())
