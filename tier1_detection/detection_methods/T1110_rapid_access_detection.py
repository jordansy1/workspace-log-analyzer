"""
Rapid Access Detection - MITRE ATT&CK T1110

Detects rapid retry or access patterns that may indicate automated
credential testing, bot activity, or unusual authentication behavior.
"""

from typing import Dict, Any, List


def detect_rapid_access(events: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect rapid retry or access patterns.

    Identifies authentication attempts with very short time intervals,
    particularly rapid retries after failures which may indicate automation.

    Args:
        events: List of authentication events from logs
        metadata: Log metadata

    Returns:
        List of anomaly dicts for rapid access patterns detected
    """
    anomalies = []

    # Sort events by timestamp
    sorted_events = sorted(
        events,
        key=lambda e: e.get('timestamp', '')
    )

    # Look for rapid retries (< 60 seconds)
    for i in range(len(sorted_events) - 1):
        current = sorted_events[i]
        next_event = sorted_events[i + 1]

        # Check if both are for same user
        if current.get('user_email') != next_event.get('user_email'):
            continue

        # Parse timestamps
        try:
            from dateutil import parser
            t1 = parser.isoparse(current.get('timestamp'))
            t2 = parser.isoparse(next_event.get('timestamp'))
            diff_seconds = (t2 - t1).total_seconds()

            # Rapid retry after failure
            if (current.get('event_name') == 'login_failure' and
                next_event.get('event_name') in ['login_success', 'login_verification'] and
                diff_seconds < 60):

                anomalies.append({
                    'id': f'ANOM-RAPID-{i:03d}',
                    'type': 'rapid_retry',
                    'severity': 'low',
                    'requires_deep_analysis': True,
                    'sub_agent': 'failed_login_analyzer',
                    'description': f'Rapid retry ({diff_seconds:.0f}s) after failed login',
                    'evidence': {
                        'failure_event': current,
                        'success_event': next_event,
                        'time_diff_seconds': diff_seconds
                    },
                    'context_questions': [
                        'Is this consistent with legitimate user correcting mistake?',
                        'Is the retry from same IP and location?',
                        'Are there multiple rapid retries suggesting automation?'
                    ]
                })
        except Exception:
            continue

    return anomalies
