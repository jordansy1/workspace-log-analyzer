"""
Tier 1 Anomaly Detector - Modular Architecture

Orchestrates all tier-1 detection methods to identify potential security anomalies
using deterministic pattern matching aligned with MITRE ATT&CK framework.
"""

import json
from typing import Dict, List, Any
from pathlib import Path

# Import all detection methods
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


class AnomalyDetector:
    """
    Primary analyzer that performs initial anomaly detection using modular detection methods.

    Each detection method is a standalone function in tier1_detection/detection_methods/
    that can be independently developed, tested, and maintained.
    """

    def __init__(self, log_file_path: str):
        """
        Initialize detector with log file path.

        Args:
            log_file_path: Path to JSON file containing authentication logs
        """
        self.log_file_path = log_file_path
        self.logs = self._load_logs()
        self.metadata = self.logs.get('metadata', {})
        self.events = self.logs.get('events', [])

        print(f"[Tier1Detector] Loaded {len(self.events)} events from {Path(log_file_path).name}")

    def _load_logs(self) -> Dict:
        """Load logs from JSON file."""
        with open(self.log_file_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """
        Perform initial anomaly detection using all detection methods.

        Each detection method runs independently and returns anomalies
        that require tier-2 sub-agent analysis.

        Returns:
            List of detected anomalies with metadata for sub-agent routing
        """
        anomalies = []

        print(f"[Tier1Detector] Running {16} detection methods...")

        # Detection 1: Check for Google session cookie hijacking (T1539) - CRITICAL
        session_cookie_anomalies = detect_google_session_cookie_hijacking(self.events, self.metadata)
        if session_cookie_anomalies:
            anomalies.extend(session_cookie_anomalies)
            print(f"  [+] Session Cookie Hijacking: {len(session_cookie_anomalies)} anomalies (CRITICAL)")

        # Detection 2: Check for Google-flagged suspicious events (T1078)
        google_suspicious_anomalies = detect_google_suspicious_events(self.events, self.metadata)
        if google_suspicious_anomalies:
            anomalies.extend(google_suspicious_anomalies)
            print(f"  [+] Google Suspicious: {len(google_suspicious_anomalies)} anomalies")

        # Detection 3: Check for missing MFA (T1556.006, T1621, T1111)
        mfa_anomaly = detect_missing_mfa(self.events, self.metadata)
        if mfa_anomaly:
            anomalies.append(mfa_anomaly)
            print(f"  [+] MFA: {mfa_anomaly['id']} ({mfa_anomaly['severity']})")

        # Detection 4: Check for geographic anomalies (T1078)
        geo_anomalies = detect_geographic_anomalies(self.events, self.metadata)
        if geo_anomalies:
            anomalies.extend(geo_anomalies)
            print(f"  [+] Geographic: {len(geo_anomalies)} anomalies")

        # Detection 5: Check for failed login patterns (T1110)
        failed_login_anomalies = detect_failed_logins(self.events, self.metadata)
        if failed_login_anomalies:
            anomalies.extend(failed_login_anomalies)
            print(f"  [+] Failed Logins: {len(failed_login_anomalies)} anomalies")

        # Detection 6: Check for rapid access patterns (T1110)
        rapid_access_anomalies = detect_rapid_access(self.events, self.metadata)
        if rapid_access_anomalies:
            anomalies.extend(rapid_access_anomalies)
            print(f"  [+] Rapid Access: {len(rapid_access_anomalies)} anomalies")

        # Detection 7: Credential stuffing detection (T1110.004)
        credential_stuffing_anomalies = detect_credential_stuffing(self.events, self.metadata)
        if credential_stuffing_anomalies:
            anomalies.extend(credential_stuffing_anomalies)
            print(f"  [+] Credential Stuffing: {len(credential_stuffing_anomalies)} anomalies")

        # Detection 8: Password spray detection (T1110.003)
        password_spray_anomalies = detect_password_spray(self.events, self.metadata)
        if password_spray_anomalies:
            anomalies.extend(password_spray_anomalies)
            print(f"  [+] Password Spray: {len(password_spray_anomalies)} anomalies")

        # Detection 9: Impossible travel detection (enhanced geographic)
        impossible_travel_anomalies = detect_impossible_travel(self.events, self.metadata)
        if impossible_travel_anomalies:
            anomalies.extend(impossible_travel_anomalies)
            print(f"  [+] Impossible Travel: {len(impossible_travel_anomalies)} anomalies")

        # Detection 10: MFA fatigue/bombing detection (T1621)
        mfa_fatigue_anomalies = detect_mfa_fatigue(self.events, self.metadata)
        if mfa_fatigue_anomalies:
            anomalies.extend(mfa_fatigue_anomalies)
            print(f"  [+] MFA Fatigue: {len(mfa_fatigue_anomalies)} anomalies")

        # Detection 11: Session anomaly detection (T1539, T1185)
        session_anomalies = detect_session_anomalies(self.events, self.metadata)
        if session_anomalies:
            anomalies.extend(session_anomalies)
            print(f"  [+] Session Anomalies: {len(session_anomalies)} anomalies")

        # Detection 12: Off-hours access detection (M1036)
        off_hours_anomalies = detect_off_hours_access(self.events, self.metadata)
        if off_hours_anomalies:
            anomalies.extend(off_hours_anomalies)
            print(f"  [+] Off-Hours Access: {len(off_hours_anomalies)} anomalies")

        # Detection 13: Account manipulation detection (T1098)
        account_manipulation_anomalies = detect_account_manipulation(self.events, self.metadata)
        if account_manipulation_anomalies:
            anomalies.extend(account_manipulation_anomalies)
            print(f"  [+] Account Manipulation: {len(account_manipulation_anomalies)} anomalies")

        # Detection 14: OAuth token abuse detection (T1550.001)
        oauth_abuse_anomalies = detect_oauth_token_abuse(self.events)
        if oauth_abuse_anomalies:
            anomalies.extend(oauth_abuse_anomalies)
            print(f"  [+] OAuth Token Abuse: {len(oauth_abuse_anomalies)} anomalies")

        # Detection 15: Stolen OAuth token detection (T1528)
        stolen_token_anomalies = detect_stolen_oauth_token(self.events)
        if stolen_token_anomalies:
            anomalies.extend(stolen_token_anomalies)
            print(f"  [+] Stolen OAuth Token: {len(stolen_token_anomalies)} anomalies")

        # Detection 16: Malicious OAuth app detection (T1098.001)
        malicious_oauth_anomalies = detect_malicious_oauth_app(self.events)
        if malicious_oauth_anomalies:
            anomalies.extend(malicious_oauth_anomalies)
            print(f"  [+] Malicious OAuth App: {len(malicious_oauth_anomalies)} anomalies")

        print(f"[Tier1Detector] Complete: {len(anomalies)} total anomalies detected")
        return anomalies


# Helper function for extracting enriched context (used by tier-2 agents)
def _extract_enriched_context(anomaly: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract enriched contextual data from anomaly evidence.

    Pulls out IP reputation, geolocation, user context, and baseline
    comparison data that was enriched during log fetching.

    Args:
        anomaly: Detected anomaly with evidence

    Returns:
        Dictionary of enriched context for tier-2 analysis
    """
    evidence = anomaly.get('evidence', {})
    context = {}

    # Extract from verification events if present
    verification_events = evidence.get('verification_events', [])
    if verification_events:
        sample_event = verification_events[0]

        # IP reputation data
        if 'ip_reputation' in sample_event:
            context['ip_reputation'] = sample_event['ip_reputation']

        # Enriched location data
        if 'enriched_location' in sample_event:
            context['enriched_location'] = sample_event['enriched_location']

        # User context data
        if 'user_context' in sample_event:
            context['user_context'] = sample_event['user_context']

        # Baseline comparison
        if 'baseline_comparison' in sample_event:
            context['baseline_comparison'] = sample_event['baseline_comparison']

    # Extract from failed events
    failed_events = evidence.get('failed_events', [])
    if failed_events and not context:
        sample_event = failed_events[0]

        if 'ip_reputation' in sample_event:
            context['ip_reputation'] = sample_event['ip_reputation']
        if 'enriched_location' in sample_event:
            context['enriched_location'] = sample_event['enriched_location']
        if 'user_context' in sample_event:
            context['user_context'] = sample_event['user_context']
        if 'baseline_comparison' in sample_event:
            context['baseline_comparison'] = sample_event['baseline_comparison']

    # Extract from locations list (geographic anomalies)
    locations = evidence.get('locations', [])
    if locations and not context:
        context['locations'] = locations

    return context


# Export for backward compatibility
__all__ = ['AnomalyDetector', '_extract_enriched_context']
