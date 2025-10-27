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
                        # Check additional risk signals from Google
                        google_flagged_suspicious = next_event.get('is_suspicious', False)
                        challenge_method = next_event.get('login_challenge_method')
                        login_type = next_event.get('login_type', '')

                        # Get location data if available
                        loc1 = current.get('enriched_location', {})
                        loc2 = next_event.get('enriched_location', {})

                        same_city = loc1.get('city') == loc2.get('city') if loc1 and loc2 else False
                        same_country = loc1.get('country') == loc2.get('country') if loc1 and loc2 else False

                        # Adjust severity based on signals
                        if google_flagged_suspicious:
                            severity = 'critical'
                        elif not same_country:
                            severity = 'high'
                        elif same_city:
                            severity = 'medium'  # Could be legitimate multi-device
                        else:
                            severity = 'high'

                        anomalies.append({
                            'id': f'ANOM-SESSION-{hash(user) % 1000:03d}',
                            'type': 'concurrent_sessions',
                            'severity': severity,
                            'requires_deep_analysis': True,
                            'sub_agent': 'session_analyzer',
                            'description': f'Concurrent sessions from different IPs for {user} ({time_diff:.0f}s apart)',
                            'evidence': {
                                'user': user,
                                'ip_addresses': [ip1, ip2],
                                'time_diff_seconds': round(time_diff, 1),
                                'google_flagged_suspicious': google_flagged_suspicious,
                                'challenge_method_used': challenge_method,
                                'login_type': login_type,
                                'location_comparison': {
                                    'same_city': same_city,
                                    'same_country': same_country,
                                    'first_location': {
                                        'city': loc1.get('city'),
                                        'country': loc1.get('country'),
                                        'ip': ip1
                                    },
                                    'second_location': {
                                        'city': loc2.get('city'),
                                        'country': loc2.get('country'),
                                        'ip': ip2
                                    }
                                },
                                'events': [current, next_event]
                            },
                            'triage_guidance': {
                                'priority': 'HIGH' if google_flagged_suspicious else 'MEDIUM',
                                'severity_rationale': f'Concurrent sessions {time_diff:.0f}s apart from different IPs',
                                'risk_factors': {
                                    'google_flagged': google_flagged_suspicious,
                                    'different_countries': not same_country,
                                    'rapid_succession': time_diff < 60,
                                    'challenge_presented': challenge_method is not None
                                },
                                'recommended_actions': [
                                    'Verify if user has multiple registered devices',
                                    'Check if IPs are from same corporate network or VPN',
                                    'Review user device inventory in Workspace admin',
                                    'Examine both sessions for suspicious activity patterns',
                                    'Consider requiring re-authentication if unverified'
                                ],
                                'investigation_questions': [
                                    'Does user regularly work from multiple devices simultaneously?',
                                    'Are both IPs from known/trusted locations?',
                                    'Was additional verification required for second login?',
                                    'Are there signs of automation or bot activity?'
                                ],
                                'likely_false_positive_if': [
                                    'User has both desktop and mobile devices registered',
                                    'IPs are from same geographic city/region',
                                    'User is known multi-device power user',
                                    'Both sessions from same corporate VPN or network'
                                ]
                            },
                            'context_questions': [
                                'Could this be legitimate multi-device usage?',
                                'Are the IPs from same geographic region?',
                                'Is one IP a known VPN or proxy?',
                                'Was re-authentication required for the second access?'
                            ],
                            'mitre_attack': ['T1078', 'T1539']  # Valid Accounts, Steal Web Session Cookie
                        })
            except Exception:
                continue

    return anomalies
