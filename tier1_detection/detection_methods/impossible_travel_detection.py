"""
Impossible Travel Detection - MITRE ATT&CK T1078

Detects impossible travel based on geographic distance and time between
authentication events, indicating potential credential compromise.

Indicators:
- User activity in two locations within a timeframe shorter than physically possible
- Maximum realistic travel speed (800 km/h for commercial flight)
"""

from typing import Dict, Any, List


def detect_impossible_travel(events: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect impossible travel based on geographic distance and time.

    Analyzes sequential authentication events for the same user to identify
    geographic transitions that would require impossibly fast travel.

    Args:
        events: List of authentication events from logs
        metadata: Log metadata

    Returns:
        List of anomaly dicts for impossible travel patterns detected
    """
    anomalies = []

    try:
        from geopy.distance import geodesic
    except ImportError:
        # Fallback: skip this detection if geopy not installed
        return anomalies

    from dateutil import parser

    # Group events by user and sort by time
    user_events = {}
    for event in events:
        if event.get('event_name') in ['login_success', 'login_verification']:
            user = event.get('user_email')
            if user not in user_events:
                user_events[user] = []
            user_events[user].append(event)

    # Check each user for impossible travel
    for user, user_event_list in user_events.items():
        sorted_events = sorted(user_event_list, key=lambda e: e.get('timestamp', ''))

        for i in range(len(sorted_events) - 1):
            current = sorted_events[i]
            next_event = sorted_events[i + 1]

            # Get location data from enriched_location
            curr_loc = current.get('enriched_location', {})
            next_loc = next_event.get('enriched_location', {})

            curr_coords = curr_loc.get('loc', '')
            next_coords = next_loc.get('loc', '')

            if not curr_coords or not next_coords:
                continue

            try:
                # Parse coordinates (format: "lat,lon")
                curr_lat, curr_lon = map(float, curr_coords.split(','))
                next_lat, next_lon = map(float, next_coords.split(','))

                # Calculate distance and time
                distance_km = geodesic(
                    (curr_lat, curr_lon),
                    (next_lat, next_lon)
                ).kilometers

                # Skip if same location (within 50km)
                if distance_km < 50:
                    continue

                t1 = parser.isoparse(current.get('timestamp'))
                t2 = parser.isoparse(next_event.get('timestamp'))
                time_diff_hours = (t2 - t1).total_seconds() / 3600

                # Maximum realistic speed: 800 km/h (commercial flight)
                required_speed = distance_km / time_diff_hours if time_diff_hours > 0 else float('inf')

                if required_speed > 800:
                    # Check additional risk signals from Google
                    google_flagged_suspicious = next_event.get('is_suspicious', False)
                    login_type = next_event.get('login_type', '')
                    required_reauth = 'reauth' in login_type
                    challenge_method = next_event.get('login_challenge_method')

                    # Adjust severity based on additional signals
                    # If Google flagged it OR no reauth required, it's more suspicious
                    if google_flagged_suspicious or not required_reauth:
                        severity = 'critical'
                        requires_analysis = True
                    else:
                        # If user had to reauth, slightly less suspicious (could be legit travel)
                        severity = 'high'
                        requires_analysis = True

                    anomalies.append({
                        'id': f'ANOM-TRAVEL-{hash(user) % 1000:03d}-{i:02d}',
                        'type': 'impossible_travel',
                        'severity': severity,
                        'requires_deep_analysis': requires_analysis,
                        'sub_agent': 'geographic_analyzer',
                        'description': f'Impossible travel detected for {user}: {distance_km:.0f}km in {time_diff_hours:.1f}h ({required_speed:.0f}km/h)',
                        'evidence': {
                            'user': user,
                            'distance_km': round(distance_km, 1),
                            'time_delta_hours': round(time_diff_hours, 2),
                            'speed_kmh': round(required_speed, 0),
                            'google_flagged_suspicious': google_flagged_suspicious,
                            'required_reauth': required_reauth,
                            'challenge_method_used': challenge_method,
                            'first_location': {
                                'city': curr_loc.get('city'),
                                'region': curr_loc.get('region'),
                                'country': curr_loc.get('country'),
                                'ip': current.get('ip_address'),
                                'timestamp': current.get('timestamp')
                            },
                            'second_location': {
                                'city': next_loc.get('city'),
                                'region': next_loc.get('region'),
                                'country': next_loc.get('country'),
                                'ip': next_event.get('ip_address'),
                                'timestamp': next_event.get('timestamp')
                            },
                            'first_event': current,
                            'second_event': next_event
                        },
                        'triage_guidance': {
                            'priority': 'HIGH' if google_flagged_suspicious else 'MEDIUM',
                            'severity_rationale': f'Travel speed of {required_speed:.0f}km/h exceeds maximum realistic speed (800km/h)',
                            'risk_factors': {
                                'impossible_speed': True,
                                'google_flagged': google_flagged_suspicious,
                                'no_reauth_required': not required_reauth,
                                'challenge_presented': challenge_method is not None
                            },
                            'recommended_actions': [
                                'Verify user location and recent travel with user directly',
                                'Check if VPN, proxy, or Tor was involved',
                                'Review IP reputation scores for both locations',
                                'Examine session activity for signs of unauthorized access',
                                'If confirmed compromise: force password reset and review account activity'
                            ],
                            'investigation_questions': [
                                f'Was user actually traveling from {curr_loc.get("city")} to {next_loc.get("city")}?',
                                'Did user report lost device or credential theft?',
                                'Is either IP from a corporate VPN or known travel location?',
                                'Were any sensitive actions performed during these sessions?',
                                'Does user have authorized remote access from these regions?'
                            ],
                            'likely_false_positive_if': [
                                'User confirmed legitimate travel with VPN usage',
                                'Both IPs belong to same corporate network/VPN provider',
                                'User works remotely and uses location-shifting VPN'
                            ]
                        },
                        'context_questions': [
                            'Could VPN or proxy usage explain this geographic jump?',
                            'Is one of these IPs a known VPN/hosting provider?',
                            'Are there any other indicators of credential compromise?',
                            'Did both logins succeed, or was one blocked?'
                        ],
                        'mitre_attack': ['T1078']  # Valid Accounts
                    })
            except Exception:
                continue

    return anomalies
