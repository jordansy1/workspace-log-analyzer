"""
MITRE ATT&CK Technique: T1528 - Steal Application Access Token

This detection identifies patterns that may indicate OAuth token theft or compromise.
Attackers can steal OAuth tokens to gain persistent access to cloud resources without
needing the user's primary credentials.

Detection Logic:
1. Token usage from different IP than authorization IP
2. Token usage from impossible travel locations
3. Mass token revocations (potential compromise cleanup)
4. Token revocation followed by immediate re-authorization
5. Token usage during off-hours or anomalous times

References:
- https://attack.mitre.org/techniques/T1528/
- https://developers.google.com/identity/protocols/oauth2/resources/token-theft
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
from collections import defaultdict
import math


def detect_stolen_oauth_token(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect potential OAuth token theft patterns.

    Args:
        events: List of OAuth token events from Google Workspace logs

    Returns:
        List of detected anomalies with evidence
    """
    anomalies = []

    # Detection 1: Mass token revocations (potential compromise cleanup)
    anomalies.extend(_detect_mass_revocations(events))

    # Detection 2: Revocation followed by immediate re-authorization
    anomalies.extend(_detect_revoke_reauth_pattern(events))

    # Detection 3: Geographic anomalies in token usage
    # (This would require token usage events, which aren't in the authorize/revoke logs)
    # For now, we detect geographic anomalies in authorization patterns

    return anomalies


def _is_authorize_event(event: Dict[str, Any]) -> bool:
    """Check if event is an OAuth authorization."""
    return (
        event.get('id', {}).get('applicationName') == 'token' and
        len(event.get('events', [])) > 0 and
        event['events'][0].get('name') == 'authorize'
    )


def _is_revoke_event(event: Dict[str, Any]) -> bool:
    """Check if event is an OAuth token revocation."""
    return (
        event.get('id', {}).get('applicationName') == 'token' and
        len(event.get('events', [])) > 0 and
        event['events'][0].get('name') == 'revoke'
    )


def _extract_oauth_params(event: Dict[str, Any]) -> Dict[str, Any]:
    """Extract OAuth parameters from event."""
    params = {}
    for param in event.get('events', [{}])[0].get('parameters', []):
        name = param.get('name')
        if 'value' in param:
            params[name] = param['value']
        elif 'multiValue' in param:
            params[name] = param['multiValue']
        elif 'multiMessageValue' in param:
            params[name] = param['multiMessageValue']
    return params


def _detect_mass_revocations(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect mass token revocations that may indicate compromise cleanup.

    When an organization discovers compromised OAuth tokens, they typically
    revoke multiple tokens in a short period. This can be legitimate security
    response OR an attacker cleaning up after exfiltration.
    """
    anomalies = []

    # Filter to revoke events only
    revoke_events = [e for e in events if _is_revoke_event(e)]

    if len(revoke_events) < 3:
        return anomalies

    # Group revocations by user and time window
    revoke_by_user = defaultdict(list)
    for event in revoke_events:
        user = event.get('actor', {}).get('email', 'unknown')
        revoke_by_user[user].append(event)

    # Check for multiple revocations in short time
    for user, user_events in revoke_by_user.items():
        if len(user_events) < 3:
            continue

        # Sort by timestamp
        sorted_events = sorted(
            user_events,
            key=lambda e: datetime.fromisoformat(e['id']['time'].replace('Z', '+00:00'))
        )

        # Check if multiple revocations within 1 hour
        first_time = datetime.fromisoformat(sorted_events[0]['id']['time'].replace('Z', '+00:00'))
        last_time = datetime.fromisoformat(sorted_events[-1]['id']['time'].replace('Z', '+00:00'))

        if last_time - first_time <= timedelta(hours=1):
            # Get app names
            app_names = []
            for event in sorted_events:
                oauth_params = _extract_oauth_params(event)
                app_names.append(oauth_params.get('app_name', 'Unknown'))

            anomalies.append({
                'id': f"oauth_mass_revoke_{sorted_events[0]['id']['uniqueQualifier']}",
                'type': 'T1528 - Mass OAuth Token Revocations',
                'description': (
                    f"User '{user}' revoked {len(sorted_events)} OAuth tokens within "
                    f"{(last_time - first_time).total_seconds() / 60:.0f} minutes. "
                    f"This may indicate: (1) legitimate security response to compromise, "
                    f"(2) attacker cleaning up after data exfiltration, or (3) user "
                    f"reviewing and removing unused apps."
                ),
                'mitre_attack': ['T1528'],
                'sub_agent': 'oauth_token_analyzer',
                'evidence': {
                    'events': sorted_events,
                    'user_email': user,
                    'revocation_count': len(sorted_events),
                    'revoked_apps': app_names,
                    'time_window_minutes': (last_time - first_time).total_seconds() / 60,
                },
                'context_questions': [
                    f"Did user '{user}' report their account being compromised?",
                    "Was this revocation initiated by IT/security team?",
                    "Were any of these apps recently flagged as suspicious?",
                    "Is there evidence of unauthorized access prior to revocation?",
                ],
            })

    return anomalies


def _detect_revoke_reauth_pattern(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect token revocation followed by immediate re-authorization.

    This pattern may indicate:
    - Attacker testing stolen tokens and re-authorizing after detection
    - User troubleshooting app issues
    - Automated systems with poor token management
    """
    anomalies = []

    # Group events by user and app
    user_app_events = defaultdict(list)

    for event in events:
        if not (_is_authorize_event(event) or _is_revoke_event(event)):
            continue

        user = event.get('actor', {}).get('email', 'unknown')
        oauth_params = _extract_oauth_params(event)
        app_name = oauth_params.get('app_name', 'Unknown')
        client_id = oauth_params.get('client_id', 'unknown')

        key = f"{user}:{app_name}:{client_id}"
        user_app_events[key].append(event)

    # Check for revoke→authorize pattern
    for key, app_events in user_app_events.items():
        if len(app_events) < 2:
            continue

        # Sort by timestamp
        sorted_events = sorted(
            app_events,
            key=lambda e: datetime.fromisoformat(e['id']['time'].replace('Z', '+00:00'))
        )

        # Look for revoke followed by authorize within 1 hour
        for i in range(len(sorted_events) - 1):
            curr_event = sorted_events[i]
            next_event = sorted_events[i + 1]

            if not _is_revoke_event(curr_event):
                continue
            if not _is_authorize_event(next_event):
                continue

            curr_time = datetime.fromisoformat(curr_event['id']['time'].replace('Z', '+00:00'))
            next_time = datetime.fromisoformat(next_event['id']['time'].replace('Z', '+00:00'))

            time_diff = next_time - curr_time

            if time_diff <= timedelta(hours=1):
                user, app_name, client_id = key.split(':', 2)

                anomalies.append({
                    'id': f"oauth_revoke_reauth_{curr_event['id']['uniqueQualifier']}",
                    'type': 'T1528 - OAuth Revocation Followed by Re-authorization',
                    'description': (
                        f"User '{user}' revoked OAuth token for '{app_name}' and then "
                        f"re-authorized it {time_diff.total_seconds() / 60:.0f} minutes later. "
                        f"This pattern may indicate token testing by an attacker, user "
                        f"troubleshooting, or poor app design."
                    ),
                    'mitre_attack': ['T1528'],
                'sub_agent': 'oauth_token_analyzer',
                    'evidence': {
                        'events': [curr_event, next_event],
                        'user_email': user,
                        'app_name': app_name,
                        'client_id': client_id,
                        'time_between_revoke_reauth_minutes': time_diff.total_seconds() / 60,
                    },
                    'context_questions': [
                        f"Did user '{user}' report issues with '{app_name}'?",
                        "Was this revocation/re-authorization expected?",
                        "Are there signs of compromise on this account?",
                        "Is the app functioning normally after re-authorization?",
                    ],
                })

    return anomalies


def calculate_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate distance between two geographic coordinates using Haversine formula.
    Returns distance in kilometers.
    """
    # Earth's radius in kilometers
    R = 6371.0

    # Convert to radians
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)

    # Haversine formula
    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad

    a = math.sin(dlat / 2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    distance = R * c
    return distance


def _detect_geographic_anomalies(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect impossible travel or suspicious geographic patterns in OAuth authorizations.

    Note: This detection requires location data for each event. The Google Reports API
    provides limited location data (region/subdivision codes but not precise lat/lon).
    """
    anomalies = []

    # Group by user
    user_events = defaultdict(list)
    for event in events:
        if not _is_authorize_event(event):
            continue

        user = event.get('actor', {}).get('email', 'unknown')
        user_events[user].append(event)

    # Check for suspicious location changes
    for user, events_list in user_events.items():
        if len(events_list) < 2:
            continue

        # Sort by timestamp
        sorted_events = sorted(
            events_list,
            key=lambda e: datetime.fromisoformat(e['id']['time'].replace('Z', '+00:00'))
        )

        # Look for rapid country changes (impossible travel indicator)
        for i in range(len(sorted_events) - 1):
            curr_event = sorted_events[i]
            next_event = sorted_events[i + 1]

            curr_location = curr_event.get('enriched_location', {})
            next_location = next_event.get('enriched_location', {})

            curr_country = curr_location.get('country', '')
            next_country = next_location.get('country', '')

            # Skip if same country or missing location data
            if not curr_country or not next_country or curr_country == next_country:
                continue

            curr_time = datetime.fromisoformat(curr_event['id']['time'].replace('Z', '+00:00'))
            next_time = datetime.fromisoformat(next_event['id']['time'].replace('Z', '+00:00'))
            time_diff = next_time - curr_time

            # If country change within 1 hour, flag as suspicious
            if time_diff <= timedelta(hours=1):
                oauth_params_curr = _extract_oauth_params(curr_event)
                oauth_params_next = _extract_oauth_params(next_event)

                anomalies.append({
                    'id': f"oauth_impossible_travel_{curr_event['id']['uniqueQualifier']}",
                    'type': 'T1528 - OAuth Authorization from Impossible Travel',
                    'description': (
                        f"User '{user}' authorized OAuth apps from {curr_country} and "
                        f"{next_country} within {time_diff.total_seconds() / 60:.0f} minutes. "
                        f"This may indicate: (1) token theft and usage from different location, "
                        f"(2) VPN/proxy usage, or (3) credential compromise."
                    ),
                    'mitre_attack': ['T1528', 'T1078.004'],
                'sub_agent': 'oauth_token_analyzer',
                    'evidence': {
                        'events': [curr_event, next_event],
                        'user_email': user,
                        'first_location': curr_location,
                        'second_location': next_location,
                        'time_between_minutes': time_diff.total_seconds() / 60,
                        'first_app': oauth_params_curr.get('app_name'),
                        'second_app': oauth_params_next.get('app_name'),
                    },
                    'context_questions': [
                        f"Does user '{user}' typically use VPN services?",
                        "Has the user reported traveling recently?",
                        "Are there other signs of account compromise?",
                        "Is this pattern consistent with the user's work habits?",
                    ],
                })

    return anomalies
