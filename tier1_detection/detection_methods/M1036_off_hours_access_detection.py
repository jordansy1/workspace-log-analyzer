"""
Off-Hours Access Detection - MITRE ATT&CK M1036

Detects logins outside of normal business hours which may indicate
compromised credentials, insider threats, or unusual work patterns.

Indicators:
- Successful logins outside configured business hours
- Considers primary and additional timezones for distributed teams
- Respects observed holidays and weekend policies

Configuration:
- Business hours defined in config/business_context.yaml
- Supports multiple timezones for distributed organizations
"""

from typing import Dict, Any, List
from datetime import datetime, time
from config import get_business_hours
from config.timezone_mapper import normalize_timezone, get_timezone_object


def detect_off_hours_access(events: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect logins outside of normal business hours.

    Analyzes successful login events and flags those occurring during
    off-hours based on configurable business hours for multiple timezones.

    Args:
        events: List of authentication events from logs
        metadata: Log metadata

    Returns:
        List of anomaly dicts for off-hours access detected
    """
    anomalies = []

    from dateutil import parser
    import pytz

    # Load business hours configuration
    try:
        business_hours_config = get_business_hours()
    except Exception as e:
        # Fallback to hardcoded hours if config unavailable
        print(f"[WARNING] Could not load business hours config: {e}")
        print("[WARNING] Falling back to default hours: 08:00-18:00 UTC")
        business_hours_config = {
            'primary_timezone': 'America/New_York',
            'weekday_start': '08:00',
            'weekday_end': '18:00',
            'weekend_start': None,
            'weekend_end': None,
            'additional_timezones': {},
            'holidays': []
        }

    for event in events:
        if event.get('event_name') == 'login_success':
            try:
                timestamp = parser.isoparse(event.get('timestamp'))

                # Get user's timezone from enriched location and normalize it
                enriched_loc = event.get('enriched_location', {})
                detected_timezone_raw = enriched_loc.get('timezone', business_hours_config['primary_timezone'])

                # Normalize timezone to handle various formats (Windows, abbreviations, etc.)
                detected_timezone = normalize_timezone(
                    detected_timezone_raw,
                    fallback=business_hours_config['primary_timezone']
                )

                try:
                    user_tz = get_timezone_object(detected_timezone)
                    local_time = timestamp.astimezone(user_tz)
                except Exception:
                    # Fallback to primary timezone
                    user_tz = get_timezone_object(business_hours_config['primary_timezone'])
                    local_time = timestamp.astimezone(user_tz)

                # Check if this is a holiday
                date_str = local_time.strftime('%Y-%m-%d')
                is_holiday = date_str in business_hours_config.get('holidays', [])

                # Check if weekend
                is_weekend = local_time.weekday() >= 5  # Saturday=5, Sunday=6

                # Determine which timezone config to use
                timezone_config = None
                if detected_timezone in business_hours_config.get('additional_timezones', {}):
                    timezone_config = business_hours_config['additional_timezones'][detected_timezone]
                else:
                    # Use primary timezone config
                    timezone_config = {
                        'weekday_start': business_hours_config['weekday_start'],
                        'weekday_end': business_hours_config['weekday_end'],
                        'weekend_start': business_hours_config.get('weekend_start'),
                        'weekend_end': business_hours_config.get('weekend_end')
                    }

                # Check if access is outside business hours
                is_off_hours = _is_off_hours(local_time, timezone_config, is_weekend, is_holiday)

                if is_off_hours:
                    # Build context-aware description
                    reason = []
                    if is_holiday:
                        reason.append(f'holiday ({date_str})')
                    if is_weekend and timezone_config.get('weekend_start') is None:
                        reason.append('weekend')
                    if not is_holiday and not is_weekend:
                        reason.append(f'outside business hours ({timezone_config["weekday_start"]}-{timezone_config["weekday_end"]})')

                    description = f'Off-hours login at {local_time.strftime("%Y-%m-%d %H:%M %Z")} ({", ".join(reason)})'

                    anomalies.append({
                        'id': f'ANOM-HOURS-{hash(event.get("event_id")) % 1000:03d}',
                        'type': 'off_hours_access',                        'requires_deep_analysis': True,
                        'sub_agent': 'behavioral_analyzer',
                        'description': description,
                        'evidence': {
                            'event': event,
                            'local_time': local_time.strftime("%Y-%m-%d %H:%M %Z"),
                            'timezone': str(user_tz),
                            'is_weekend': is_weekend,
                            'is_holiday': is_holiday,
                            'configured_hours': f"{timezone_config['weekday_start']}-{timezone_config['weekday_end']}",
                            'user': event.get('user_email'),
                            'ip_address': event.get('ip_address')
                        },
                        'context_questions': [
                            'Is this user known to work irregular hours?',
                            'Is the access from a known/trusted location?',
                            'Are there other suspicious indicators (IP reputation, location)?',
                            'Is this consistent with the user\'s historical access patterns?',
                            'Does the user role typically work outside business hours?'
                        ]
                    })
            except Exception:
                continue

    return anomalies


def _is_off_hours(local_time: datetime, timezone_config: Dict[str, Any], is_weekend: bool, is_holiday: bool) -> bool:
    """
    Determine if a given time is outside business hours.

    Args:
        local_time: Datetime in user's local timezone
        timezone_config: Business hours configuration for timezone
        is_weekend: Whether the day is a weekend
        is_holiday: Whether the day is a holiday

    Returns:
        True if outside business hours, False otherwise
    """
    # Holidays are always off-hours
    if is_holiday:
        return True

    # Weekends depend on configuration
    if is_weekend:
        weekend_start = timezone_config.get('weekend_start')
        if weekend_start is None:
            # Weekends not configured = off-hours
            return True
        else:
            # Weekend has configured hours, check them
            weekend_end = timezone_config.get('weekend_end')
            return not _is_within_hours(local_time, weekend_start, weekend_end)

    # Weekday - check against configured hours
    weekday_start = timezone_config.get('weekday_start', '08:00')
    weekday_end = timezone_config.get('weekday_end', '18:00')
    return not _is_within_hours(local_time, weekday_start, weekday_end)


def _is_within_hours(local_time: datetime, start_time_str: str, end_time_str: str) -> bool:
    """
    Check if a datetime falls within specified hours.

    Args:
        local_time: Datetime to check
        start_time_str: Start time in "HH:MM" format
        end_time_str: End time in "HH:MM" format

    Returns:
        True if within hours, False otherwise
    """
    current_time = local_time.time()

    # Parse start and end times
    start_hour, start_min = map(int, start_time_str.split(':'))
    end_hour, end_min = map(int, end_time_str.split(':'))

    start_time = time(start_hour, start_min)
    end_time = time(end_hour, end_min)

    return start_time <= current_time <= end_time
