"""
Off-Hours Access Detection - MITRE ATT&CK M1036

Detects logins outside of normal business hours which may indicate
compromised credentials, insider threats, or unusual work patterns.

Indicators:
- Successful logins between 10 PM and 6 AM local time
- Configurable per user/role if needed
"""

from typing import Dict, Any, List


def detect_off_hours_access(events: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect logins outside of normal business hours.

    Analyzes successful login events and flags those occurring during
    off-hours (22:00-06:00 in the user's local timezone).

    Args:
        events: List of authentication events from logs
        metadata: Log metadata

    Returns:
        List of anomaly dicts for off-hours access detected
    """
    anomalies = []

    from dateutil import parser
    import pytz

    for event in events:
        if event.get('event_name') == 'login_success':
            try:
                timestamp = parser.isoparse(event.get('timestamp'))

                # Get user's timezone from enriched location
                enriched_loc = event.get('enriched_location', {})
                timezone_str = enriched_loc.get('timezone', 'UTC')

                try:
                    user_tz = pytz.timezone(timezone_str)
                    local_time = timestamp.astimezone(user_tz)
                    hour = local_time.hour
                except Exception:
                    # Fallback to UTC
                    hour = timestamp.hour

                # Off-hours: 22:00-06:00
                if hour >= 22 or hour < 6:
                    anomalies.append({
                        'id': f'ANOM-HOURS-{hash(event.get("event_id")) % 1000:03d}',
                        'type': 'off_hours_access',
                        'severity': 'low',
                        'requires_deep_analysis': True,
                        'sub_agent': 'behavioral_analyzer',
                        'description': f'Off-hours login at {local_time.strftime("%Y-%m-%d %H:%M %Z") if "local_time" in locals() else timestamp.strftime("%Y-%m-%d %H:%M UTC")}',
                        'evidence': {
                            'event': event,
                            'hour': hour,
                            'user': event.get('user_email'),
                            'ip_address': event.get('ip_address')
                        },
                        'context_questions': [
                            'Is this user known to work irregular hours?',
                            'Is the access from a known/trusted location?',
                            'Are there other suspicious indicators (IP reputation, location)?',
                            'Is this consistent with the user\'s historical access patterns?'
                        ]
                    })
            except Exception:
                continue

    return anomalies
