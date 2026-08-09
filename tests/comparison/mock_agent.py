"""
Mock AI Agent for Testing

Rule-based mock that simulates tier-2 AI agent responses for rapid testing
without requiring API keys or incurring API costs.

The mock uses the same contextual signals that real AI agents consider:
- IP reputation scores
- Geographic deviations
- User admin status
- 2FA enrollment
- Known threat indicators (Tor, VPN, hosting)

This enables:
1. Rapid test iteration during development
2. Baseline comparison (mock vs real AI)
3. CI/CD testing without API dependencies
"""

from dataclasses import dataclass
from typing import Dict, List, Any, Optional


@dataclass
class Tier2Result:
    """
    Result from tier-2 AI analysis.

    Attributes:
        is_actual_risk: AI's verdict on whether this is a real threat
        adjusted_severity: AI's assessment of severity (may differ from tier-1)
        confidence: How confident is the AI in this verdict
        threat_classification: Type of threat identified (or 'benign')
        forensic_narrative: AI-generated explanation/reasoning
        recommended_actions: Specific actions to take
        evidence_cited: Key evidence the AI used to reach verdict
        execution_time_ms: Time taken for analysis
        used_mock: Whether this result came from mock or real AI
    """
    is_actual_risk: bool
    adjusted_severity: str
    confidence: str
    threat_classification: str
    forensic_narrative: str
    recommended_actions: List[str]
    evidence_cited: List[str]
    execution_time_ms: float = 0.0
    used_mock: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'is_actual_risk': self.is_actual_risk,
            'adjusted_severity': self.adjusted_severity,
            'confidence': self.confidence,
            'threat_classification': self.threat_classification,
            'forensic_narrative': self.forensic_narrative,
            'recommended_actions': self.recommended_actions,
            'evidence_cited': self.evidence_cited,
            'execution_time_ms': self.execution_time_ms,
            'used_mock': self.used_mock
        }


class MockAgent:
    """
    Rule-based mock AI agent for testing.

    Simulates the decision-making of tier-2 AI agents using deterministic
    rules based on the same signals the real agents use. This provides:

    1. Fast execution (no API latency)
    2. Deterministic results (reproducible tests)
    3. No cost (no API charges)
    4. Baseline for comparing against real AI

    The mock is intentionally simpler than real AI - it's designed to
    provide "reasonable" verdicts, not match AI exactly. The goal is to
    enable test development and measure where real AI adds value.
    """

    def __init__(self):
        """Initialize mock agent with scoring weights."""
        # Weights for different risk signals
        self.risk_weights = {
            'high_ip_risk': 35,          # IP risk score > 70
            'moderate_ip_risk': 15,      # IP risk score 40-70
            'malicious_ip': 40,          # IP flagged as malicious
            'tor_exit': 40,              # Tor exit node
            'hosting_provider': 20,      # Datacenter/hosting IP
            'vpn_detected': 5,           # VPN (not inherently bad)
            'proxy_detected': 15,        # Proxy server
            'admin_account': 15,         # Admin user targeted
            'new_location': 10,          # First time from this location
            'new_ip': 5,                 # First time from this IP
            'impossible_travel': 35,     # Impossible travel detected
            'no_mfa_admin': 30,          # Admin without MFA
            'no_mfa_user': 10,           # Regular user without MFA
            'multiple_failed': 15,       # Multiple failed attempts
        }

        # Weights for benign signals
        self.benign_weights = {
            'clean_ip': -20,             # Low risk IP score
            'known_ip': -25,             # IP in user's baseline
            'known_location': -20,       # Location in user's baseline
            '2fa_enrolled': -15,         # User has 2FA enabled
            '2fa_enforced': -10,         # 2FA is enforced
            'residential_ip': -10,       # Residential ISP
            'corporate_vpn': -20,        # Known corporate VPN
        }

        # Threshold for verdict
        self.risk_threshold = 40         # Score >= this = actual risk
        self.high_confidence_threshold = 60

    def analyze(
        self,
        anomaly: Dict[str, Any],
        enriched_context: Dict[str, Any]
    ) -> Tier2Result:
        """
        Generate mock AI analysis response.

        Args:
            anomaly: Detected anomaly from tier-1
            enriched_context: Enriched context data (IP rep, geo, user, etc.)

        Returns:
            Tier2Result with mock AI verdict and reasoning
        """
        import time
        start_time = time.time()

        # Extract context data
        ip_rep = enriched_context.get('ip_reputation', {})
        geo = enriched_context.get('geolocation', enriched_context.get('enriched_location', {}))
        user = enriched_context.get('user_context', {})
        baseline = enriched_context.get('baseline', enriched_context.get('baseline_comparison', {}))

        # Calculate risk score
        risk_score, risk_factors = self._calculate_risk_score(
            anomaly=anomaly,
            ip_rep=ip_rep,
            geo=geo,
            user=user,
            baseline=baseline
        )

        # Calculate benign score
        benign_score, benign_factors = self._calculate_benign_score(
            ip_rep=ip_rep,
            geo=geo,
            user=user,
            baseline=baseline
        )

        # Net score
        net_score = risk_score + benign_score  # benign_score is negative

        # Determine verdict
        is_risk = net_score >= self.risk_threshold
        confidence = self._determine_confidence(net_score, risk_factors, benign_factors)
        severity = self._determine_severity(net_score, anomaly.get('severity', 'medium'))
        threat_class = self._classify_threat(risk_factors, anomaly.get('type', 'unknown'))

        # Generate narrative
        narrative = self._generate_narrative(
            is_risk=is_risk,
            net_score=net_score,
            risk_factors=risk_factors,
            benign_factors=benign_factors,
            anomaly_type=anomaly.get('type', 'unknown')
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(
            is_risk=is_risk,
            risk_factors=risk_factors,
            user=user,
            anomaly=anomaly
        )

        elapsed_ms = (time.time() - start_time) * 1000

        return Tier2Result(
            is_actual_risk=is_risk,
            adjusted_severity=severity,
            confidence=confidence,
            threat_classification=threat_class,
            forensic_narrative=narrative,
            recommended_actions=recommendations,
            evidence_cited=risk_factors + benign_factors,
            execution_time_ms=elapsed_ms,
            used_mock=True
        )

    def _calculate_risk_score(
        self,
        anomaly: Dict[str, Any],
        ip_rep: Dict[str, Any],
        geo: Dict[str, Any],
        user: Dict[str, Any],
        baseline: Dict[str, Any]
    ) -> tuple:
        """Calculate risk score based on signals."""
        score = 0
        factors = []

        # IP reputation
        risk_score = ip_rep.get('risk_score', ip_rep.get('abuse_confidence_score', 0))
        if risk_score > 70:
            score += self.risk_weights['high_ip_risk']
            factors.append(f'high_ip_risk_score_{risk_score}')
        elif risk_score > 40:
            score += self.risk_weights['moderate_ip_risk']
            factors.append(f'moderate_ip_risk_score_{risk_score}')

        if ip_rep.get('is_malicious'):
            score += self.risk_weights['malicious_ip']
            factors.append('malicious_ip_flagged')

        # Threat indicators
        if geo.get('is_tor'):
            score += self.risk_weights['tor_exit']
            factors.append('tor_exit_node')

        if geo.get('is_hosting'):
            score += self.risk_weights['hosting_provider']
            factors.append('hosting_provider_ip')

        if geo.get('is_vpn'):
            score += self.risk_weights['vpn_detected']
            factors.append('vpn_detected')

        if geo.get('is_proxy'):
            score += self.risk_weights['proxy_detected']
            factors.append('proxy_detected')

        # User context
        if user.get('is_admin'):
            score += self.risk_weights['admin_account']
            factors.append('admin_account_targeted')

            # Admin without MFA is higher risk
            if not user.get('is_2fa_enrolled'):
                score += self.risk_weights['no_mfa_admin']
                factors.append('admin_no_mfa_enrolled')
        elif not user.get('is_2fa_enrolled'):
            score += self.risk_weights['no_mfa_user']
            factors.append('user_no_mfa_enrolled')

        # Baseline deviations
        if baseline.get('is_new_location') or baseline.get('new_location'):
            score += self.risk_weights['new_location']
            factors.append('new_geographic_location')

        if baseline.get('is_new_ip') or baseline.get('new_ip'):
            score += self.risk_weights['new_ip']
            factors.append('new_ip_address')

        # Check for impossible travel in anomaly evidence
        evidence = anomaly.get('evidence', {})
        if evidence.get('speed_kmh', 0) > 800:
            score += self.risk_weights['impossible_travel']
            factors.append('impossible_travel_speed')

        # Multiple failed attempts
        if evidence.get('failure_count', 0) >= 3:
            score += self.risk_weights['multiple_failed']
            factors.append(f'multiple_failures_{evidence.get("failure_count")}')

        return score, factors

    def _calculate_benign_score(
        self,
        ip_rep: Dict[str, Any],
        geo: Dict[str, Any],
        user: Dict[str, Any],
        baseline: Dict[str, Any]
    ) -> tuple:
        """Calculate benign score (reduces risk)."""
        score = 0  # Will be negative values
        factors = []

        # Clean IP
        risk_score = ip_rep.get('risk_score', ip_rep.get('abuse_confidence_score', 50))
        if risk_score < 20:
            score += self.benign_weights['clean_ip']
            factors.append(f'clean_ip_reputation_{risk_score}')

        # Known from baseline
        if baseline.get('is_known_ip') or baseline.get('known_ip'):
            score += self.benign_weights['known_ip']
            factors.append('ip_in_user_baseline')

        if baseline.get('is_known_location') or baseline.get('known_location'):
            score += self.benign_weights['known_location']
            factors.append('location_in_user_baseline')

        # 2FA status
        if user.get('is_2fa_enrolled'):
            score += self.benign_weights['2fa_enrolled']
            factors.append('user_2fa_enrolled')

        if user.get('is_2fa_enforced'):
            score += self.benign_weights['2fa_enforced']
            factors.append('2fa_policy_enforced')

        # ISP type
        isp = geo.get('org', geo.get('isp', '')).lower()
        if any(res in isp for res in ['comcast', 'verizon', 'at&t', 'spectrum', 'residential']):
            score += self.benign_weights['residential_ip']
            factors.append('residential_isp')

        return score, factors

    def _determine_confidence(
        self,
        net_score: int,
        risk_factors: List[str],
        benign_factors: List[str]
    ) -> str:
        """Determine confidence level in verdict."""
        # High confidence if score is very high or very low
        if abs(net_score) >= self.high_confidence_threshold:
            return 'high'

        # If many factors on one side, higher confidence
        if len(risk_factors) >= 3 and len(benign_factors) == 0:
            return 'high'
        if len(benign_factors) >= 3 and len(risk_factors) == 0:
            return 'high'

        # Mixed signals = lower confidence
        if risk_factors and benign_factors:
            return 'medium'

        return 'medium'

    def _determine_severity(self, net_score: int, original_severity: str) -> str:
        """Determine adjusted severity based on analysis."""
        if net_score >= 80:
            return 'critical'
        elif net_score >= 60:
            return 'high'
        elif net_score >= 40:
            return 'medium'
        elif net_score >= 20:
            return 'low'
        else:
            return 'low'

    def _classify_threat(self, risk_factors: List[str], anomaly_type: str) -> str:
        """Classify the type of threat detected."""
        if not risk_factors:
            return 'benign_activity'

        # Check for specific threat types
        if 'tor_exit_node' in risk_factors or 'malicious_ip_flagged' in risk_factors:
            return 'credential_compromise'

        if 'impossible_travel_speed' in risk_factors:
            return 'account_takeover'

        if any('multiple_failures' in f for f in risk_factors):
            return 'brute_force_attempt'

        if 'hosting_provider_ip' in risk_factors:
            return 'automated_attack'

        if 'admin_no_mfa_enrolled' in risk_factors:
            return 'policy_violation'

        # Default based on anomaly type
        type_mapping = {
            'failed_login': 'authentication_attack',
            'password_spray': 'password_spray_attack',
            'credential_stuffing': 'credential_stuffing_attack',
            'session_anomalies': 'session_hijacking',
            'impossible_travel': 'geographic_anomaly',
            'missing_mfa': 'mfa_policy_gap',
            'off_hours_access': 'suspicious_access_pattern',
        }

        return type_mapping.get(anomaly_type, 'unknown_threat')

    def _generate_narrative(
        self,
        is_risk: bool,
        net_score: int,
        risk_factors: List[str],
        benign_factors: List[str],
        anomaly_type: str
    ) -> str:
        """Generate forensic narrative explaining the verdict."""
        if is_risk:
            narrative = f"This {anomaly_type} event presents a genuine security risk. "
            narrative += f"Risk assessment score: {net_score}/100. "

            if risk_factors:
                narrative += f"Key risk indicators: {', '.join(risk_factors[:3])}. "

            if benign_factors:
                narrative += f"Some benign factors noted ({', '.join(benign_factors[:2])}), "
                narrative += "but insufficient to offset the identified risks."
        else:
            narrative = f"This {anomaly_type} event is assessed as low risk or benign. "
            narrative += f"Risk assessment score: {net_score}/100. "

            if benign_factors:
                narrative += f"Benign indicators: {', '.join(benign_factors[:3])}. "

            if risk_factors:
                narrative += f"Minor concerns ({', '.join(risk_factors[:2])}) "
                narrative += "do not rise to the level of actionable threat."

        return narrative

    def _generate_recommendations(
        self,
        is_risk: bool,
        risk_factors: List[str],
        user: Dict[str, Any],
        anomaly: Dict[str, Any]
    ) -> List[str]:
        """Generate specific recommendations based on analysis."""
        recommendations = []

        if not is_risk:
            recommendations.append('No immediate action required')
            recommendations.append('Continue normal monitoring')
            return recommendations

        # Risk-based recommendations
        if 'tor_exit_node' in risk_factors or 'malicious_ip_flagged' in risk_factors:
            recommendations.append('Force immediate password reset')
            recommendations.append('Revoke all active sessions')
            recommendations.append('Review account for unauthorized changes')

        if user.get('is_admin'):
            recommendations.append('Contact user directly to verify activity')
            recommendations.append('Review admin console audit logs')

        if 'admin_no_mfa_enrolled' in risk_factors:
            recommendations.append('Enforce MFA enrollment for this admin account')

        if 'impossible_travel_speed' in risk_factors:
            recommendations.append('Verify user location through secondary channel')

        if any('multiple_failures' in f for f in risk_factors):
            recommendations.append('Temporarily increase monitoring for this account')
            recommendations.append('Consider temporary account lockout if pattern continues')

        # Default recommendations if none specific
        if not recommendations:
            recommendations.append('Investigate further before taking action')
            recommendations.append('Contact user to verify recent activity')

        return recommendations
