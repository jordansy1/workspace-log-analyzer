"""
Detection Methods - Individual Tier-1 Detection Implementations

Each detection method is responsible for identifying a specific type of anomaly
using deterministic rules and thresholds.
"""

from tier1_detection.detection_methods.mfa_detection import detect_missing_mfa
from tier1_detection.detection_methods.geographic_detection import detect_geographic_anomalies
from tier1_detection.detection_methods.failed_login_detection import detect_failed_logins
from tier1_detection.detection_methods.rapid_access_detection import detect_rapid_access
from tier1_detection.detection_methods.credential_stuffing_detection import detect_credential_stuffing
from tier1_detection.detection_methods.password_spray_detection import detect_password_spray
from tier1_detection.detection_methods.impossible_travel_detection import detect_impossible_travel
from tier1_detection.detection_methods.mfa_fatigue_detection import detect_mfa_fatigue
from tier1_detection.detection_methods.session_detection import detect_session_anomalies
from tier1_detection.detection_methods.off_hours_detection import detect_off_hours_access
from tier1_detection.detection_methods.account_manipulation_detection import detect_account_manipulation

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
    'detect_account_manipulation'
]
