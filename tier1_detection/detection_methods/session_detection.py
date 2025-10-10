"""
Session Anomaly Detection - MITRE ATT&CK T1539, T1185

Detects suspicious session behaviors including session hijacking,
token theft, or unusual session patterns.

Indicators:
- Sudden change in user agent mid-session
- Session from multiple IPs simultaneously
- Geographic jump without re-authentication

Note: This detection is limited if session IDs are not available in logs.
"""

from typing import Dict, Any, List


def detect_session_anomalies(events: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect suspicious session behaviors.

    Analyzes authentication events for patterns suggesting session hijacking
    or token theft, such as simultaneous access from different IPs.

    Args:
        events: List of authentication events from logs
        metadata: Log metadata

    Returns:
        List of anomaly dicts for session anomalies detected
    """
    anomalies = []

    # Since Google Workspace logs may not include explicit session IDs,
    # we'll use a time-based heuristic: group events by user within short timeframes
    from dateutil import parser
    from collections import defaultdict

    user_sessions = defaultdict(list)

    for event in events:
        if event.get('event_name') in ['login_success', 'login_verification']:
            user = event.get('user_email')
            user_sessions[user].append(event)

    # Check for simultaneous access from different IPs
    for user, user_events in user_sessions.items():
        if len(user_events) < 2:
            continue

        sorted_events = sorted(user_events, key=lambda e: e.get('timestamp', ''))

        # Look for near-simultaneous logins from different IPs (within 2 minutes)
        for i in range(len(sorted_events) - 1):
            try:
                current = sorted_events[i]
                next_event = sorted_events[i + 1]

                t1 = parser.isoparse(current.get('timestamp'))
                t2 = parser.isoparse(next_event.get('timestamp'))

                time_diff = (t2 - t1).total_seconds()

                if time_diff < 120:  # Within 2 minutes
                    ip1 = current.get('ip_address')
                    ip2 = next_event.get('ip_address')

                    if ip1 != ip2:
                        anomalies.append({
                            'id': f'ANOM-SESSION-{hash(user) % 1000:03d}',
                            'type': 'session_hijacking',
                            'severity': 'high',
                            'requires_deep_analysis': True,
                            'sub_agent': 'session_analyzer',
                            'description': f'Simultaneous access from different IPs for {user} ({time_diff:.0f}s apart)',
                            'evidence': {
                                'user': user,
                                'ip_addresses': [ip1, ip2],
                                'time_diff_seconds': time_diff,
                                'events': [current, next_event]
                            },
                            'context_questions': [
                                'Could this be legitimate multi-device usage?',
                                'Are the IPs from same geographic region?',
                                'Is one IP a known VPN or proxy?',
                                'Was re-authentication required for the second access?'
                            ]
                        })
            except Exception:
                continue

    return anomalies
