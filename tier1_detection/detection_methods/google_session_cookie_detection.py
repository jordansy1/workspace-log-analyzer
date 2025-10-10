"""
Google Session Cookie Hijacking Detection - MITRE ATT&CK T1539

Detects confirmed session hijacking events where Google Workspace
automatically signed out a user due to suspicious session cookies.

Indicators:
- event_name: user_signed_out_due_to_suspicious_session_cookie
- Google's internal ML detected session cookie theft/replay
- High-confidence indicator requiring immediate response

Note: This is a critical severity event with minimal false positives.
"""

from typing import Dict, Any, List


def detect_google_session_cookie_hijacking(events: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect confirmed session hijacking events flagged by Google.

    Google Workspace automatically detects and terminates sessions when
    suspicious session cookie behavior is identified (e.g., cookie theft,
    replay attacks, session fixation).

    Args:
        events: List of authentication events from logs
        metadata: Log metadata

    Returns:
        List of anomaly dicts for confirmed session hijacking events
    """
    anomalies = []

    # Find all session cookie hijacking events
    for event in events:
        event_name = event.get('event_name')

        # Google explicitly flags this event type for session cookie issues
        if event_name == 'user_signed_out_due_to_suspicious_session_cookie':
            user = event.get('affected_email_address') or event.get('user_email')
            timestamp = event.get('timestamp')
            ip_address = event.get('ip_address')

            anomalies.append({
                'id': f'ANOM-SESSION-HIJACK-{hash(user + timestamp) % 10000:04d}',
                'type': 'session_hijacking_confirmed',
                'severity': 'critical',
                'requires_deep_analysis': False,  # Google already confirmed it
                'sub_agent': 'session_analyzer',
                'description': f'Google detected and terminated suspicious session cookie for {user}',
                'evidence': {
                    'user': user,
                    'detection_source': 'Google Workspace Security',
                    'action_taken': 'User automatically signed out',
                    'timestamp': timestamp,
                    'ip_address': ip_address,
                    'event_details': event
                },
                'triage_guidance': {
                    'priority': 'IMMEDIATE',
                    'severity_rationale': 'Google confirmed session cookie compromise',
                    'recommended_actions': [
                        'Contact user immediately to verify recent activity',
                        'Force password reset for affected account',
                        'Review all user sessions in last 24 hours',
                        'Check for unauthorized data access or exfiltration',
                        'Scan user devices for malware/keyloggers',
                        'Review account for unauthorized changes (delegates, forwarding rules)'
                    ],
                    'investigation_questions': [
                        'Did user report phishing emails or suspicious links?',
                        'Was user device recently compromised?',
                        'Are there signs of lateral movement to other accounts?',
                        'What sensitive data did the session access?'
                    ]
                },
                'context_questions': [
                    'What actions were performed during the suspicious session?',
                    'Were any account settings or permissions modified?',
                    'Did the attacker access sensitive emails or files?',
                    'Are there other accounts at risk?'
                ],
                'mitre_attack': ['T1539']  # Steal Web Session Cookie
            })

    return anomalies
