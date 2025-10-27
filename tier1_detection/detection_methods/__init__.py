"""
Detection Methods - Individual Tier-1 Detection Implementations

Each detection method is responsible for identifying a specific type of anomaly
using deterministic rules and thresholds.
"""

# MITRE ATT&CK aligned imports
from tier1_detection.detection_methods.T1556_006_mfa_bypass_detection import detect_missing_mfa
from tier1_detection.detection_methods.T1078_geographic_anomalies_detection import detect_geographic_anomalies
from tier1_detection.detection_methods.T1110_failed_login_detection import detect_failed_logins
from tier1_detection.detection_methods.T1110_rapid_access_detection import detect_rapid_access
from tier1_detection.detection_methods.T1110_004_credential_stuffing_detection import detect_credential_stuffing
from tier1_detection.detection_methods.T1110_003_password_spray_detection import detect_password_spray
from tier1_detection.detection_methods.T1078_impossible_travel_detection import detect_impossible_travel
from tier1_detection.detection_methods.T1621_mfa_fatigue_detection import detect_mfa_fatigue
from tier1_detection.detection_methods.T1539_session_anomalies_detection import detect_session_anomalies
from tier1_detection.detection_methods.M1036_off_hours_access_detection import detect_off_hours_access
from tier1_detection.detection_methods.T1098_account_manipulation_detection import detect_account_manipulation
from tier1_detection.detection_methods.T1078_google_suspicious_detection import detect_google_suspicious_events
from tier1_detection.detection_methods.T1539_session_cookie_hijacking_detection import detect_google_session_cookie_hijacking

__all__ = [
    'detect_missing_mfa',
    'detect_geographic_anomalies',
    'detect_failed_logins',
    'detect_rapid_access',
    'detect_credential_stuffing',
    'detect_password_spray',
    'detect_impossible_travel',
    'detect_mfa_fatigue',
    'detect_session_anomalies',
    'detect_off_hours_access',
    'detect_account_manipulation',
    'detect_google_suspicious_events',
    'detect_google_session_cookie_hijacking'
]
