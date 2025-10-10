"""
Multi-Agent Log Analysis System

This module coordinates multiple specialized analysis agents to provide
nuanced, context-aware security analysis of authentication logs.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any


class AnomalyDetector:
    """
    Primary analyzer that performs initial anomaly detection
    and identifies which sub-agents should analyze specific findings.
    """

    def __init__(self, log_file_path: str):
        """Initialize with log file path."""
        self.log_file_path = log_file_path
        self.logs = self._load_logs()
        self.metadata = self.logs.get('metadata', {})
        self.events = self.logs.get('events', [])

    def _load_logs(self) -> Dict:
        """Load logs from JSON file."""
        with open(self.log_file_path, 'r') as f:
            return json.load(f)

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """
        Perform initial anomaly detection aligned with MITRE ATT&CK framework.
        Returns list of potential anomalies with metadata for sub-agent routing.
        """
        anomalies = []

        # Detection 1: Check for missing MFA (T1556.006, T1621, T1111)
        mfa_anomaly = self._detect_missing_mfa()
        if mfa_anomaly:
            anomalies.append(mfa_anomaly)

        # Detection 2: Check for geographic anomalies (T1078)
        geo_anomalies = self._detect_geographic_anomalies()
        anomalies.extend(geo_anomalies)

        # Detection 3: Check for failed login patterns (T1110)
        failed_login_anomalies = self._detect_failed_logins()
        anomalies.extend(failed_login_anomalies)

        # Detection 4: Check for rapid access patterns (T1110)
        rapid_access_anomalies = self._detect_rapid_access()
        anomalies.extend(rapid_access_anomalies)

        # Detection 5: Credential stuffing detection (T1110.004)
        credential_stuffing_anomalies = self._detect_credential_stuffing()
        anomalies.extend(credential_stuffing_anomalies)

        # Detection 6: Password spray detection (T1110.003)
        password_spray_anomalies = self._detect_password_spray()
        anomalies.extend(password_spray_anomalies)

        # Detection 7: Impossible travel detection (enhanced geographic)
        impossible_travel_anomalies = self._detect_impossible_travel()
        anomalies.extend(impossible_travel_anomalies)

        # Detection 8: MFA fatigue/bombing detection (T1621)
        mfa_fatigue_anomalies = self._detect_mfa_fatigue()
        anomalies.extend(mfa_fatigue_anomalies)

        # Detection 9: Session hijacking detection (T1539, T1185)
        session_anomalies = self._detect_session_anomalies()
        anomalies.extend(session_anomalies)

        # Detection 10: Off-hours access detection (M1036)
        off_hours_anomalies = self._detect_off_hours_access()
        anomalies.extend(off_hours_anomalies)

        # Detection 11: Account manipulation detection (T1098)
        account_manipulation_anomalies = self._detect_account_manipulation()
        anomalies.extend(account_manipulation_anomalies)

        return anomalies

    def _detect_missing_mfa(self) -> Dict[str, Any]:
        """Detect events without multi-factor authentication."""
        login_verification_events = [
            e for e in self.events
            if e.get('event_name') == 'login_verification'
        ]

        # Check if any verification events have is_second_factor = true
        has_2fa = any(
            e.get('is_second_factor') == True
            for e in login_verification_events
        )

        # Count events with explicit false
        no_2fa_count = sum(
            1 for e in login_verification_events
            if e.get('is_second_factor') == False
        )

        if not has_2fa and no_2fa_count > 0:
            return {
                'id': 'ANOM-MFA-001',
                'type': 'missing_mfa',
                'severity': 'high',  # Initial severity, may be adjusted
                'requires_deep_analysis': True,
                'sub_agent': 'mfa_context_analyzer',
                'description': 'No second factor authentication detected in login verification events',
                'evidence': {
                    'total_verification_events': len(login_verification_events),
                    'events_with_2fa': 0,
                    'events_without_2fa': no_2fa_count,
                    'verification_events': login_verification_events
                },
                'context_questions': [
                    'Could this be a trusted device scenario?',
                    'Was there a valid session already established?',
                    'Is this an OAuth/API authentication flow?',
                    'What is the login_type and does it explain the MFA absence?'
                ]
            }

        return None

    def _detect_geographic_anomalies(self) -> List[Dict[str, Any]]:
        """Detect unusual geographic patterns."""
        anomalies = []

        # Extract all unique locations
        locations = []
        for event in self.events:
            network_info = event.get('network_info')
            if network_info:
                locations.append({
                    'timestamp': event.get('timestamp'),
                    'region_code': network_info.get('region_code'),
                    'subdivision': network_info.get('subdivision_code'),
                    'ip': event.get('ip_address'),
                    'user': event.get('user_email')
                })

        # Check for multiple regions
        unique_regions = set(loc['region_code'] for loc in locations if loc['region_code'])

        if len(unique_regions) > 1:
            anomalies.append({
                'id': 'ANOM-GEO-001',
                'type': 'multiple_locations',
                'severity': 'medium',
                'requires_deep_analysis': True,
                'sub_agent': 'geographic_analyzer',
                'description': f'Authentication from {len(unique_regions)} different geographic regions',
                'evidence': {
                    'locations': locations,
                    'unique_regions': list(unique_regions)
                },
                'context_questions': [
                    'Is impossible travel detected based on timestamps?',
                    'Could this be VPN/proxy usage?',
                    'Are the regions geographically adjacent?',
                    'Is the user known to travel frequently?'
                ]
            })

        return anomalies

    def _detect_failed_logins(self) -> List[Dict[str, Any]]:
        """Detect failed login patterns."""
        anomalies = []

        failed_events = [
            e for e in self.events
            if e.get('event_name') == 'login_failure'
        ]

        if failed_events:
            # Group by user
            failed_by_user = {}
            for event in failed_events:
                user = event.get('user_email')
                if user not in failed_by_user:
                    failed_by_user[user] = []
                failed_by_user[user].append(event)

            for user, failures in failed_by_user.items():
                anomalies.append({
                    'id': f'ANOM-FAIL-{hash(user) % 1000:03d}',
                    'type': 'failed_login',
                    'severity': 'medium' if len(failures) < 3 else 'high',
                    'requires_deep_analysis': True,
                    'sub_agent': 'failed_login_analyzer',
                    'description': f'{len(failures)} failed login attempt(s) for {user}',
                    'evidence': {
                        'user': user,
                        'failure_count': len(failures),
                        'failed_events': failures
                    },
                    'context_questions': [
                        'Is there a successful login immediately after?',
                        'Are failures from same IP or different IPs?',
                        'What is the time interval between failures?',
                        'Could this be legitimate user error vs attack?'
                    ]
                })

        return anomalies

    def _detect_rapid_access(self) -> List[Dict[str, Any]]:
        """Detect rapid retry or access patterns."""
        anomalies = []

        # Sort events by timestamp
        sorted_events = sorted(
            self.events,
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

    def _detect_credential_stuffing(self) -> List[Dict[str, Any]]:
        """
        Detect credential stuffing patterns (MITRE ATT&CK T1110.004).

        Indicators:
        - Multiple failed logins from same IP across different users
        - Distributed attack from many IPs targeting few users
        - Success after many failures suggesting credential list testing
        """
        anomalies = []

        # Group failures by IP address
        failures_by_ip = {}
        for event in self.events:
            if event.get('event_name') == 'login_failure':
                ip = event.get('ip_address')
                if ip not in failures_by_ip:
                    failures_by_ip[ip] = []
                failures_by_ip[ip].append(event)

        # Detect IPs attacking multiple different accounts
        for ip, failures in failures_by_ip.items():
            unique_users = set(f.get('user_email') for f in failures)
            if len(unique_users) >= 3:  # Threshold: 3+ different users
                anomalies.append({
                    'id': f'ANOM-STUFF-{hash(ip) % 1000:03d}',
                    'type': 'credential_stuffing',
                    'severity': 'high',
                    'requires_deep_analysis': True,
                    'sub_agent': 'credential_stuffing_analyzer',
                    'description': f'Possible credential stuffing from {ip} targeting {len(unique_users)} accounts',
                    'evidence': {
                        'source_ip': ip,
                        'targeted_users': list(unique_users),
                        'failure_count': len(failures),
                        'failed_events': failures
                    },
                    'context_questions': [
                        'Is this IP known to be malicious (check IP reputation)?',
                        'Are any of these login attempts successful?',
                        'Does the pattern suggest automated credential testing?',
                        'Is this a VPN, proxy, or hosting provider IP?'
                    ]
                })

        return anomalies

    def _detect_password_spray(self) -> List[Dict[str, Any]]:
        """
        Detect password spraying patterns (MITRE ATT&CK T1110.003).

        Indicators:
        - Small number of failures per account across many accounts
        - Spread out timing to avoid lockouts
        - Same source attempting access to many accounts
        """
        anomalies = []

        # Time window for spray detection (30 minutes)
        time_window_seconds = 1800

        # Group login events by time windows and source IP
        from dateutil import parser
        from collections import defaultdict

        time_windows = defaultdict(lambda: defaultdict(lambda: {'users': set(), 'events': []}))

        for event in self.events:
            if event.get('event_name') in ['login_failure', 'login_success']:
                try:
                    timestamp = parser.isoparse(event.get('timestamp'))
                    window = int(timestamp.timestamp() // time_window_seconds)
                    ip = event.get('ip_address')
                    user = event.get('user_email')
                    event_type = event.get('event_name')

                    time_windows[window][(ip, event_type)]['users'].add(user)
                    time_windows[window][(ip, event_type)]['events'].append(event)
                except Exception:
                    continue

        # Detect spray patterns
        for window, data in time_windows.items():
            for (ip, event_type), info in data.items():
                users = info['users']
                events = info['events']
                # Password spray: many users targeted with few attempts each
                if event_type == 'login_failure' and len(users) >= 5:
                    anomalies.append({
                        'id': f'ANOM-SPRAY-{window % 1000:03d}',
                        'type': 'password_spray',
                        'severity': 'critical',
                        'requires_deep_analysis': True,
                        'sub_agent': 'password_spray_analyzer',
                        'description': f'Password spray detected from {ip} targeting {len(users)} accounts',
                        'evidence': {
                            'source_ip': ip,
                            'targeted_users': list(users),
                            'time_window_start': window * time_window_seconds,
                            'failure_count': len(events),
                            'failed_events': events
                        },
                        'context_questions': [
                            'Are login attempts evenly distributed across users?',
                            'Is timing consistent with automated spraying (e.g., 1 attempt per user)?',
                            'Does IP reputation indicate malicious activity?',
                            'Are there any successful logins from this IP?'
                        ]
                    })

        return anomalies

    def _detect_impossible_travel(self) -> List[Dict[str, Any]]:
        """
        Detect impossible travel based on geographic distance and time.

        Indicators:
        - User activity in two locations within a timeframe shorter than physically possible
        - Maximum realistic travel speed (800 km/h for commercial flight)
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
        for event in self.events:
            if event.get('event_name') in ['login_success', 'login_verification']:
                user = event.get('user_email')
                if user not in user_events:
                    user_events[user] = []
                user_events[user].append(event)

        # Check each user for impossible travel
        for user, events in user_events.items():
            sorted_events = sorted(events, key=lambda e: e.get('timestamp', ''))

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
                        anomalies.append({
                            'id': f'ANOM-TRAVEL-{hash(user) % 1000:03d}-{i:02d}',
                            'type': 'impossible_travel',
                            'severity': 'critical',
                            'requires_deep_analysis': True,
                            'sub_agent': 'geographic_analyzer',
                            'description': f'Impossible travel detected for {user}: {distance_km:.0f}km in {time_diff_hours:.1f}h (requires {required_speed:.0f}km/h)',
                            'evidence': {
                                'user': user,
                                'distance_km': distance_km,
                                'time_hours': time_diff_hours,
                                'required_speed_kmh': required_speed,
                                'first_location': {
                                    'city': curr_loc.get('city'),
                                    'region': curr_loc.get('region'),
                                    'country': curr_loc.get('country'),
                                    'ip': current.get('ip_address')
                                },
                                'second_location': {
                                    'city': next_loc.get('city'),
                                    'region': next_loc.get('region'),
                                    'country': next_loc.get('country'),
                                    'ip': next_event.get('ip_address')
                                },
                                'first_event': current,
                                'second_event': next_event
                            },
                            'context_questions': [
                                'Could VPN or proxy usage explain this geographic jump?',
                                'Is one of these IPs a known VPN/hosting provider?',
                                'Are there any other indicators of credential compromise?',
                                'Did both logins succeed, or was one blocked?'
                            ]
                        })
                except Exception:
                    continue

        return anomalies

    def _detect_mfa_fatigue(self) -> List[Dict[str, Any]]:
        """
        Detect MFA fatigue/bombing attacks (MITRE ATT&CK T1621).

        Indicators:
        - Multiple MFA prompts in short time period
        - Repeated denials followed by eventual approval
        - Same user receiving many push notifications
        """
        anomalies = []

        from dateutil import parser
        from collections import defaultdict

        # Group MFA challenges by user
        user_mfa_events = defaultdict(list)

        for event in self.events:
            if event.get('event_name') == 'login_verification':
                user = event.get('user_email')
                user_mfa_events[user].append(event)

        # Detect rapid repeated MFA requests
        for user, events in user_mfa_events.items():
            if len(events) < 3:
                continue

            sorted_events = sorted(events, key=lambda e: e.get('timestamp', ''))

            # Count rapid MFA requests (within 5 minutes)
            for i in range(len(sorted_events) - 2):
                try:
                    t1 = parser.isoparse(sorted_events[i].get('timestamp'))
                    t2 = parser.isoparse(sorted_events[i + 2].get('timestamp'))

                    if (t2 - t1).total_seconds() < 300:  # 3+ requests in 5 min
                        # Count how many events in this burst
                        burst_events = []
                        for event in sorted_events[i:]:
                            event_time = parser.isoparse(event.get('timestamp'))
                            if (event_time - t1).total_seconds() <= 300:
                                burst_events.append(event)
                            else:
                                break

                        anomalies.append({
                            'id': f'ANOM-MFA-BOMB-{hash(user) % 1000:03d}',
                            'type': 'mfa_fatigue',
                            'severity': 'high',
                            'requires_deep_analysis': True,
                            'sub_agent': 'mfa_context_analyzer',
                            'description': f'Possible MFA fatigue attack on {user} ({len(burst_events)} requests in 5 minutes)',
                            'evidence': {
                                'user': user,
                                'rapid_mfa_count': len(burst_events),
                                'events': burst_events
                            },
                            'context_questions': [
                                'Were these MFA requests approved or denied?',
                                'Was there eventual successful authentication?',
                                'What is the source IP for these requests?',
                                'Is there a pattern of denials followed by approval (fatigue)?'
                            ]
                        })
                        break  # Only report once per user
                except Exception:
                    continue

        return anomalies

    def _detect_session_anomalies(self) -> List[Dict[str, Any]]:
        """
        Detect suspicious session behaviors (MITRE ATT&CK T1539, T1185).

        Indicators:
        - Sudden change in user agent mid-session
        - Session from multiple IPs simultaneously
        - Geographic jump without re-authentication

        Note: This detection is limited if session IDs are not available in logs.
        """
        anomalies = []

        # Since Google Workspace logs may not include explicit session IDs,
        # we'll use a time-based heuristic: group events by user within short timeframes
        from dateutil import parser
        from collections import defaultdict

        user_sessions = defaultdict(list)

        for event in self.events:
            if event.get('event_name') in ['login_success', 'login_verification']:
                user = event.get('user_email')
                user_sessions[user].append(event)

        # Check for simultaneous access from different IPs
        for user, events in user_sessions.items():
            if len(events) < 2:
                continue

            sorted_events = sorted(events, key=lambda e: e.get('timestamp', ''))

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

    def _detect_off_hours_access(self) -> List[Dict[str, Any]]:
        """
        Detect logins outside of normal business hours (MITRE ATT&CK M1036).

        Indicators:
        - Successful logins between 10 PM and 6 AM local time
        - Configurable per user/role if needed
        """
        anomalies = []

        from dateutil import parser
        import pytz

        for event in self.events:
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

    def _detect_account_manipulation(self) -> List[Dict[str, Any]]:
        """
        Detect suspicious account changes (MITRE ATT&CK T1098).

        Indicators:
        - Password changes outside business hours
        - Rapid sequential password changes (bypassing password history)
        - Permission/role changes

        Note: This requires password_edit events which may not be in all log sets.
        """
        anomalies = []

        # Look for password change events
        password_changes = [
            e for e in self.events
            if e.get('event_name') == 'password_edit'
        ]

        if not password_changes:
            # No password change events in this dataset
            return anomalies

        # Detect rapid password changes (password history bypass)
        from dateutil import parser

        user_pwd_changes = {}
        for event in password_changes:
            user = event.get('user_email')
            if user not in user_pwd_changes:
                user_pwd_changes[user] = []
            user_pwd_changes[user].append(event)

        for user, changes in user_pwd_changes.items():
            sorted_changes = sorted(changes, key=lambda e: e.get('timestamp', ''))

            # Detect 3+ password changes within 1 hour (policy bypass attempt)
            if len(sorted_changes) >= 3:
                try:
                    t1 = parser.isoparse(sorted_changes[0].get('timestamp'))
                    t_last = parser.isoparse(sorted_changes[2].get('timestamp'))

                    if (t_last - t1).total_seconds() < 3600:
                        anomalies.append({
                            'id': f'ANOM-ACCT-{hash(user) % 1000:03d}',
                            'type': 'account_manipulation',
                            'severity': 'high',
                            'requires_deep_analysis': True,
                            'sub_agent': 'account_analyzer',
                            'description': f'Rapid password changes detected for {user} (possible policy bypass)',
                            'evidence': {
                                'user': user,
                                'change_count': len(sorted_changes),
                                'events': sorted_changes
                            },
                            'context_questions': [
                                'Is this user attempting to bypass password history requirements?',
                                'Are these changes from a legitimate admin account?',
                                'Was the account recently compromised?',
                                'Are there other signs of account takeover?'
                            ]
                        })
                except Exception:
                    continue

        return anomalies


def _extract_enriched_context(anomaly: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract enriched contextual data from anomaly evidence.

    Args:
        anomaly: Anomaly with verification events

    Returns:
        Enriched context summary
    """
    context = {
        'ip_reputation_summary': [],
        'user_context_summary': [],
        'location_summary': [],
        'baseline_summary': []
    }

    # Extract from verification events
    verification_events = anomaly.get('evidence', {}).get('verification_events', [])

    for event in verification_events:
        # IP Reputation
        ip_rep = event.get('ip_reputation', {})
        if ip_rep and not ip_rep.get('enrichment_enabled') == False:
            context['ip_reputation_summary'].append({
                'ip': ip_rep.get('ip_address'),
                'risk_score': ip_rep.get('overall_risk_score', 0),
                'is_malicious': ip_rep.get('is_malicious', False),
                'abuse_confidence': ip_rep.get('abuseipdb', {}).get('abuse_confidence_score', 0),
                'is_tor': ip_rep.get('abuseipdb', {}).get('is_tor', False)
            })

        # User Context
        user_ctx = event.get('user_context', {})
        if user_ctx and not user_ctx.get('error'):
            context['user_context_summary'].append({
                'user': user_ctx.get('user_email'),
                'is_admin': user_ctx.get('is_admin', False),
                'is_2fa_enrolled': user_ctx.get('is_2fa_enrolled', False),
                'is_2fa_enforced': user_ctx.get('is_2fa_enforced', False),
                'org_unit': user_ctx.get('org_unit_path')
            })

        # Location
        location = event.get('enriched_location', {})
        if location:
            context['location_summary'].append({
                'ip': event.get('ip_address'),
                'city': location.get('city'),
                'region': location.get('region'),
                'country': location.get('country'),
                'timezone': location.get('timezone'),
                'is_vpn': location.get('is_vpn'),
                'is_proxy': location.get('is_proxy'),
                'is_tor': location.get('is_tor'),
                'is_hosting': location.get('is_hosting')
            })

        # Baseline
        baseline = event.get('baseline_comparison', {})
        if baseline:
            context['baseline_summary'].append({
                'has_baseline': baseline.get('has_baseline', False),
                'deviations': baseline.get('deviations', []),
                'is_anomalous': baseline.get('is_anomalous', False)
            })

    return context


def generate_sub_agent_prompt(anomaly: Dict[str, Any], all_events: List[Dict]) -> str:
    """
    Generate specialized prompts for sub-agents based on anomaly type.
    Now includes enriched contextual data for smarter analysis.
    """
    # Extract enriched context from verification events
    enriched_context = _extract_enriched_context(anomaly)

    prompts = {
        'mfa_context_analyzer': f"""
You are a senior authentication security analyst specializing in Multi-Factor Authentication (MFA) bypass detection and analysis (MITRE ATT&CK T1556.006, T1621, T1111).

## Your Mission
Conduct a forensic investigation into apparent "missing MFA" to determine if this represents an MFA bypass attack, policy misconfiguration, or legitimate trusted device scenario.

## Evidence Package
{json.dumps(anomaly, indent=2)}

## ENRICHED CONTEXTUAL INTELLIGENCE
{json.dumps(enriched_context, indent=2)}

## MFA Attack & Bypass Techniques

### MITRE ATT&CK Techniques to Evaluate
1. **T1556.006 - Modify Authentication Process: MFA**
   - Adversaries bypass MFA by excluding users from policies
   - Registering vulnerable MFA methods (SMS instead of hardware tokens)
   - Patching MFA verification programs

2. **T1621 - MFA Request Generation (MFA Fatigue/Bombing)**
   - Repeated MFA requests to exhaust user into approving
   - Social engineering to convince user to approve attacker's request

3. **T1111 - MFA Interception**
   - Intercepting MFA codes via phishing, SIM swapping
   - Stealing hardware token seeds or backup codes

### Google Workspace MFA Behavior (Legitimate Scenarios)

**Trusted Device Behavior:**
- After initial 2FA setup, users check "Don't ask again on this device"
- Browser session cookies preserve 2FA state for 30+ days
- Re-authentication (login_type='reauth') doesn't require full 2FA
- is_second_factor=false on password verification is CORRECT (password is first factor)

**Look for EVIDENCE of 2FA elsewhere in session:**
- Check for login_verification events with is_second_factor=true
- Check user_context.is_2fa_enrolled (if TRUE, user HAS 2FA configured)
- OAuth/SAML flows may not show is_second_factor in logs

**Session Re-authentication:**
- login_type='reauth' = user re-authenticating within existing session
- Workspace may skip 2FA challenge if:
  - Recent 2FA success (< 10 minutes ago)
  - Same device, browser, IP address
  - Session cookie still valid

## Investigation Framework - Think Like an MFA Security Analyst

**Phase 1: Enrollment Verification**
Check if MFA is even configured:
```
IF user_context.is_2fa_enrolled == TRUE:
  → User HAS 2FA configured
  → This is likely trusted device scenario
ELSE IF user_context.is_2fa_enrolled == FALSE:
  → User does NOT have 2FA
  → Check if is_2fa_enforced == TRUE (policy violation)
```

**Phase 2: Infrastructure Risk Assessment**
Evaluate the authentication source:
```
IP Reputation Analysis:
├─ Risk Score 0-30: Low risk (likely legitimate)
├─ Risk Score 31-60: Medium risk (investigate further)
├─ Risk Score 61-100: HIGH RISK (likely compromised credential)

Anonymization Check:
├─ is_tor == TRUE: CRITICAL (attacker hiding identity)
├─ is_vpn == TRUE: Moderate (could be legitimate, investigate)
├─ is_proxy == TRUE: Moderate (common for attackers)
├─ is_hosting == TRUE: HIGH (automated attack infrastructure)
```

**Phase 3: Baseline Deviation Analysis**
Compare to user's normal behavior:
```
Baseline Deviations Check:
├─ "new_ip_address" → First time from this IP (investigate)
├─ "new_geographic_region" → Travel or compromise? (investigate)
├─ "tor_exit_node_detected" → CRITICAL RED FLAG
├─ Empty deviations → Matches baseline (likely legitimate)
```

**Phase 4: Geographic Context Correlation**
Cross-reference location with user's known patterns:
```
Location Analysis:
├─ enriched_location.city matches user's home/office? → Likely legitimate
├─ enriched_location.country is hostile nation? → Investigate
├─ Location + high IP risk + new IP = Likely compromise
```

**Phase 5: Attack Pattern Detection**
Look for indicators of MFA bypass attack:
```
Compromise Indicators:
├─ is_2fa_enrolled == TRUE + high IP risk score (> 60) → Stolen session cookie
├─ New geographic region + Tor/VPN + is_2fa_enrolled == FALSE → Policy bypass attempt
├─ Multiple failed MFA prompts followed by success → MFA fatigue attack (T1621)
├─ Sudden MFA de-enrollment → T1556.006 attack
```

## Critical Decision Matrix

### Mark as **CRITICAL SEVERITY - TRUE RISK** if:
- User has MFA enrolled (is_2fa_enrolled == TRUE) AND
- IP reputation score > 70 AND
- (is_tor == TRUE OR is_hosting == TRUE) AND
- Baseline shows new_ip_address OR new_geographic_region
→ **Likely stolen credential + session cookie theft**

### Mark as **HIGH SEVERITY - INVESTIGATE** if:
- User has MFA NOT enrolled (is_2fa_enrolled == FALSE) AND
- Policy enforcement enabled (is_2fa_enforced == TRUE) AND
- User is admin/privileged account
→ **Policy violation requiring immediate remediation**

OR

- IP reputation score 50-70 AND
- New geographic location not explained by travel AND
- Login succeeds without is_second_factor=true visible
→ **Possible MFA bypass, needs investigation**

### Mark as **MEDIUM SEVERITY - MONITOR** if:
- is_2fa_enrolled == TRUE (user has MFA) AND
- IP reputation score 30-50 AND
- Location is new but residential ISP (not Tor/hosting) AND
- login_type == 'reauth' (session re-auth)
→ **Possibly legitimate trusted device, but new location warrants monitoring**

### Mark as **LOW SEVERITY - LIKELY LEGITIMATE** if:
- is_2fa_enrolled == TRUE (user has MFA) AND
- IP reputation score < 30 AND
- No baseline deviations OR minor deviations only AND
- Location matches known user patterns AND
- login_type == 'reauth' or 'exchange'
→ **Trusted device scenario, standard Workspace behavior**

### Mark as **FALSE POSITIVE - NO RISK** if:
- is_2fa_enrolled == TRUE AND
- is_2fa_enforced == TRUE AND
- IP reputation score == 0 AND
- enriched_location.city matches user's known office/home AND
- No baseline deviations
→ **Legitimate trusted device access, MFA configured and enforced**

## Real-World Attack Scenarios to Compare Against

**Session Cookie Theft (Common):**
- Attacker steals browser session cookie via malware/phishing
- Uses cookie to authenticate without needing password or MFA
- Pattern: is_2fa_enrolled==TRUE, but high-risk IP, new location, Tor/VPN usage

**Credential Compromise + MFA Bypass Tool:**
- Attacker has password, uses MFA bypass tool (e.g., Evilginx, Modlishka)
- Proxies authentication through their server to steal session
- Pattern: Rapid success after failures, hosting provider IP, unusual user-agent

**Policy Misconfiguration:**
- Organization failed to enforce MFA on all accounts
- High-value accounts (admin, finance) without MFA
- Pattern: is_2fa_enrolled==FALSE, is_2fa_enforced==FALSE, privileged account

**Legitimate Trusted Device:**
- User authenticated with MFA last week, checking "trust this device"
- Workspace not re-challenging MFA for 30 days
- Pattern: is_2fa_enrolled==TRUE, low IP risk, known location, no deviations

## Required Forensic Analysis Output

Provide detailed security assessment in JSON format:
{{
  "is_actual_risk": true/false,
  "threat_classification": "session_cookie_theft|mfa_bypass_attack|policy_violation|trusted_device|oauth_flow|false_positive",
  "confidence": "low|medium|high",
  "adjusted_severity": "critical|high|medium|low",
  "mfa_enrollment_status": {{
    "is_enrolled": true/false,
    "is_enforced": true/false,
    "enrollment_risk_assessment": "compliant|policy_violation|attack_indicator"
  }},
  "infrastructure_assessment": {{
    "ip_reputation_score": 0-100,
    "ip_risk_level": "low|medium|high|critical",
    "is_anonymized": true/false,
    "anonymization_type": "none|tor|vpn|proxy|hosting",
    "geographic_location": "city, country",
    "location_risk": "trusted|expected|unusual|suspicious|hostile"
  }},
  "baseline_analysis": {{
    "has_baseline": true/false,
    "deviations": ["list"],
    "deviation_severity": "none|minor|moderate|significant|critical",
    "is_anomalous": true/false
  }},
  "authentication_flow_analysis": {{
    "login_type": "value from logs",
    "is_second_factor_visible": true/false,
    "likely_scenario": "trusted_device|reauth_within_session|oauth_saml|mfa_properly_challenged|mfa_bypassed",
    "session_token_theft_indicators": ["list if any"]
  }},
  "attack_pattern_match": {{
    "matches_known_attack": true/false,
    "attack_type_if_matched": "T1556.006|T1621|T1111|none",
    "attack_description": "Brief description if matched"
  }},
  "forensic_narrative": "Multi-paragraph analysis suitable for security team review. Explain the MFA status, whether this is a trusted device scenario or potential bypass, infrastructure risk factors, baseline deviations, and final determination. Reference specific evidence from user_context.is_2fa_enrolled, IP reputation scores, location data, and baseline comparison. Explain your reasoning clearly.",
  "recommended_actions": [
    "Immediate action if high risk",
    "Investigation step if uncertain",
    "Monitoring recommendation if low risk"
  ],
  "user_notification_required": true/false,
  "policy_remediation_needed": true/false,
  "key_evidence_summary": {{
    "mfa_enrolled": true/false,
    "ip_risk_score": 0-100,
    "is_anonymized": true/false,
    "baseline_deviations": ["list"],
    "location_matches_user_pattern": true/false
  }},
  "false_positive_likelihood": "very_low|low|medium|high|very_high",
  "escalation_required": true/false,
  "escalation_reason": "Brief explanation if escalation needed"
}}

## Remember: The presence of is_second_factor=false does NOT mean MFA is missing. Check user_context.is_2fa_enrolled to see if the user actually has MFA configured. If enrolled, this is likely a trusted device scenario, NOT an attack.
""",

        'geographic_analyzer': f"""
You are a senior geolocation intelligence analyst specializing in impossible travel detection and credential compromise investigation (MITRE ATT&CK T1078: Valid Accounts).

## Your Mission
Conduct a geographic forensic analysis to determine if authentication from multiple locations indicates legitimate user travel/VPN usage or credential compromise requiring incident response.

## Geographic Evidence
{json.dumps(anomaly, indent=2)}

## ENRICHED GEOLOCATION INTELLIGENCE
{json.dumps(enriched_context, indent=2)}

## Geographic Anomaly Types & Attack Patterns

### MITRE ATT&CK T1078: Valid Accounts
Adversaries obtain and abuse credentials of existing accounts to:
- Blend in with normal activity using legitimate accounts
- Maintain access without creating new accounts
- Appear as authorized users to evade detection

**Geographic indicators of compromised credentials:**
- Impossible travel (human can't physically travel that fast)
- Access from hostile nations inconsistent with user profile
- Simultaneous access from geographically distant locations
- Access from cloud/hosting providers (attacker infrastructure)

## Investigation Framework - Think Like a Geolocation Analyst

**Phase 1: Impossible Travel Calculation**

Calculate if physical travel is possible:
```
Required Information:
├─ Location A: (lat1, lon1) at time T1
├─ Location B: (lat2, lon2) at time T2
├─ Geographic distance: Great circle distance in km
├─ Time difference: (T2 - T1) in hours
└─ Required speed: distance_km / time_hours

Impossibility Thresholds:
├─ > 1000 km/h: IMPOSSIBLE (faster than commercial aircraft)
├─ 800-1000 km/h: SUSPICIOUS (Concorde-level speed, investigate)
├─ 500-800 km/h: UNLIKELY (commercial flight, but check timing)
├─ < 500 km/h: POSSIBLE (car, train, regional flight)
```

**Phase 2: Infrastructure Type Analysis**

Classify the source infrastructure for each location:
```
IP Infrastructure Risk Matrix:

CRITICAL RISK - Likely Attacker Infrastructure:
├─ Hosting Provider (AWS, GCP, Azure, DigitalOcean): Automated attack tools
├─ Tor Exit Node: Anonymization, hiding identity
├─ Known VPN in hostile nation: Adversary infrastructure
└─ Bulletproof hosting: Abuse-tolerant hosting

HIGH RISK - Anonymization:
├─ Commercial VPN: Could be attacker OR legitimate remote worker
├─ Proxy Service: Often used for malicious activity
├─ Mobile Carrier in unexpected country: SIM swapping or compromise
└─ Cloud provider + multiple rapid location changes

MEDIUM RISK - Investigate Further:
├─ Corporate VPN (but user not employed in that location): Verify employment records
├─ Mobile carrier (but travel unexpected): Check with user
├─ Residential ISP in new city: Moving? Traveling? Compromised?
└─ ISP in same country but different region: Possible legitimate

LOW RISK - Likely Legitimate:
├─ Residential ISP in user's known locations (home, office, family)
├─ Mobile carrier with gradual geographic progression (actual travel)
├─ Corporate VPN matching company office locations
└─ Same /24 subnet (NAT gateway rotation)
```

**Phase 3: Geographic Plausibility Assessment**

Evaluate whether locations make sense for this user:
```
User Profile Correlation:
├─ Does user's role involve international travel? (Sales, exec → possible)
├─ Does org have offices in these locations? (If yes → VPN likely)
├─ Are locations adjacent/reasonable? (Toronto → Montreal ≠ Toronto → Beijing)
├─ Is timing consistent with business hours in each location?
└─ Does user have historical travel patterns to these locations?

Hostile Geography Check:
├─ Country on sanctions list? (Iran, North Korea, Syria, etc.)
├─ Known adversary nation? (Russia, China for targeted industries)
├─ Jurisdiction with lax cybercrime enforcement?
└─ Location inconsistent with business operations?
```

**Phase 4: Timeline & Sequence Analysis**

Examine the temporal pattern of accesses:
```
Temporal Pattern Analysis:

Legitimate Travel Pattern:
├─ Gradual geographic progression (NYC → Philadelphia → DC)
├─ Reasonable time gaps between locations (4+ hours for flight)
├─ Activity during business hours in local timezone
└─ Mobile carrier IPs showing cell tower transitions

Compromised Credential Pattern:
├─ Instantaneous location jumps (US → China in 5 minutes)
├─ Simultaneous access from distant locations (impossible)
├─ Off-hours access in multiple timezones simultaneously
└─ Access from hosting providers interspersed with normal activity

VPN Usage Pattern:
├─ Rapid but discrete location changes (VPN exit node switching)
├─ All IPs from same VPN provider (NordVPN, ExpressVPN, etc.)
├─ Consistent user-agent across all locations
└─ Locations align with VPN provider's server list
```

**Phase 5: Cross-Reference with IP Reputation**

Correlate geographic risk with IP threat intelligence:
```
Combined Risk Assessment:

CRITICAL COMBINATION (Likely Compromise):
├─ Impossible travel (>800 km/h) + High IP reputation score (>60)
├─ Multiple countries + Hosting provider IPs
├─ Hostile nation + Tor/VPN + Never seen before
└─ Cloud provider + Rapid location cycling

HIGH RISK COMBINATION:
├─ Unlikely travel (500-800 km/h) + Medium IP reputation (30-60)
├─ New country + VPN/Proxy usage + No business justification
├─ Weekend travel to unexpected location + Moderate IP risk
└─ Baseline deviation: new_geographic_region + new_ip_address

MEDIUM RISK:
├─ Possible travel (<500 km/h) + Residential ISP + New location
├─ Corporate VPN + Office location but user not at that office
├─ Adjacent regions + Mobile carrier (could be legitimate roaming)
└─ Known VPN provider + Low IP risk + During business hours

LOW RISK:
├─ Same city/region + Different ISPs (mobile + home WiFi normal)
├─ Known office locations + Corporate VPN + Business hours
├─ Gradual geographic progression + Mobile carrier
└─ Historical pattern of VPN usage from these locations
```

## Legitimate Scenarios to Rule Out (False Positive Prevention)

**1. Corporate VPN Usage:**
- User connects to company VPN with global exit nodes
- VPN load balances across US-East, US-West, EU servers
- Pattern: Rapid location changes, all from VPN provider ASN, same user-agent
- **NOT an attack** if locations match company's VPN infrastructure

**2. Mobile Network Roaming:**
- User traveling and phone switches between carriers
- International roaming shows foreign carrier IPs
- Pattern: Gradual geographic movement, mobile user-agent, timeline matches flight
- **NOT an attack** if travel is work-related and plausible

**3. Split VPN / Home + Office:**
- User works from home (residential ISP) and office (corporate IP)
- Appears as two regions if home and office are in different cities
- Pattern: Two predictable locations, consistent schedule, both low IP risk
- **NOT an attack** if both locations are known and expected

**4. Cloud Development/Testing:**
- Developers SSH into cloud instances (AWS, GCP) for work
- Appears as access from Virginia (us-east-1) or other cloud regions
- Pattern: Cloud provider ASN, access to dev resources, during work hours
- **NOT an attack** if role is developer/DevOps and activity matches job function

**5. Legitimate International Travel:**
- Executive/sales traveling for business
- Gradual progression: Home → Airport → Hotel → Client site
- Pattern: Timeline matches flight schedules, expense reports, calendar events
- **NOT an attack** if user role involves travel and progression is plausible

## Real-World Attack Scenarios to Compare

**Credential Compromise + Attacker in Foreign Country:**
- Attacker in Russia/China has stolen credentials
- User in US logs in normally, attacker simultaneously accesses from abroad
- Pattern: Impossible travel, hostile nation, hosting/Tor IP, off-hours

**Cloud-Based Phishing Kit:**
- Attacker uses AWS/GCP instances to host phishing pages
- Steals credentials, immediately tests them from cloud infrastructure
- Pattern: Cloud provider IP, never seen before, rapid attempts, credential stuffing signature

**VPN for Anonymization:**
- Attacker uses commercial VPN to hide true location
- Cycles through VPN exit nodes to avoid IP-based blocking
- Pattern: Commercial VPN provider, high IP reputation score, unusual user behavior

## Required Forensic Analysis Output

Provide detailed geographic intelligence assessment in JSON format:
{{
  "is_actual_risk": true/false,
  "threat_classification": "credential_compromise|vpn_legitimate|travel_legitimate|mobile_roaming|cloud_dev_access|unknown|false_positive",
  "confidence": "low|medium|high",
  "adjusted_severity": "critical|high|medium|low",
  "impossible_travel_analysis": {{
    "is_impossible": true/false,
    "required_speed_kmh": 0,
    "distance_km": 0,
    "time_hours": 0.0,
    "impossibility_level": "impossible|suspicious|unlikely|possible",
    "locations": [
      {{
        "city": "City A",
        "country": "Country A",
        "timestamp": "ISO8601",
        "ip": "x.x.x.x"
      }}
    ]
  }},
  "infrastructure_analysis": {{
    "location_count": 0,
    "infrastructure_types": ["hosting|vpn|residential|corporate|mobile"],
    "risk_by_location": [
      {{
        "location": "city, country",
        "infrastructure_type": "type",
        "risk_level": "critical|high|medium|low",
        "is_known_vpn": true/false,
        "is_hosting_provider": true/false,
        "is_tor": true/false
      }}
    ],
    "infrastructure_mismatch": "User's home is residential but access from hosting = RED FLAG"
  }},
  "geographic_plausibility": {{
    "locations_match_user_profile": true/false,
    "locations_match_org_offices": true/false,
    "contains_hostile_geography": true/false,
    "hostile_locations": ["list if any"],
    "business_justification_plausible": true/false,
    "justification_reasoning": "Explain why locations do/don't make sense"
  }},
  "temporal_pattern_analysis": {{
    "pattern_type": "legitimate_travel|credential_compromise|vpn_usage|mobile_roaming|simultaneous_access",
    "pattern_confidence": "low|medium|high",
    "timeline_plausibility": "Explain whether timing makes sense for physical travel",
    "timezone_analysis": "Access during business hours in local timezones? Or unusual timing?"
  }},
  "combined_risk_assessment": {{
    "geography_risk": "critical|high|medium|low",
    "ip_reputation_risk": "critical|high|medium|low",
    "baseline_deviation_risk": "critical|high|medium|low",
    "composite_risk_level": "critical|high|medium|low",
    "risk_multipliers": ["impossible_travel", "hostile_nation", "tor_usage", "etc"]
  }},
  "false_positive_assessment": {{
    "likely_false_positive": true/false,
    "false_positive_scenario": "corporate_vpn|mobile_roaming|cloud_dev|travel|none",
    "false_positive_confidence": "low|medium|high",
    "reasoning": "Explain why this might be false positive"
  }},
  "forensic_narrative": "Multi-paragraph geographic analysis. Explain the locations involved, whether impossible travel was detected, infrastructure types at each location, whether locations make sense for user's profile and role, timeline plausibility, and final determination of legitimate vs. compromise. Reference specific evidence from IP reputation, infrastructure types, baseline deviations, and geographic calculations.",
  "recommended_actions": [
    "Immediate: Block access from hostile IPs if credential compromise confirmed",
    "Investigation: Contact user to verify travel or VPN usage",
    "Monitoring: Watch for additional access from these locations"
  ],
  "user_verification_required": true/false,
  "escalation_required": true/false,
  "indicators_of_compromise": {{
    "suspicious_ips": ["list"],
    "hostile_nations_accessed": ["list"],
    "impossible_travel_events": ["list"]
  }}
}}

## Remember: Multiple locations can be 100% legitimate (VPN, travel, mobile roaming). Focus on whether the SPEED of travel is physically possible, infrastructure makes sense for user's role, and IP reputation indicates malicious activity.
""",

        'failed_login_analyzer': f"""
You are a senior incident responder specializing in authentication attack detection and failed login analysis (MITRE ATT&CK T1110 - Brute Force family).

## Your Mission
Conduct a forensic investigation into failed login patterns to distinguish between legitimate user errors, persistent account issues, and malicious brute force attacks.

## Evidence Package
{json.dumps(anomaly, indent=2)}

## ENRICHED CONTEXTUAL INTELLIGENCE
{json.dumps(enriched_context, indent=2)}

## Investigation Framework - Think Like an Incident Responder

**Phase 1: Attack Pattern Fingerprinting**

Analyze the failure pattern to classify the attack type:

```
Pattern Recognition Matrix:
├─ BRUTE FORCE (T1110.001): Single IP, same account, 10+ rapid attempts
├─ CREDENTIAL STUFFING (T1110.004): Multiple IPs, multiple accounts, distributed
├─ PASSWORD SPRAY (T1110.003): Multiple accounts, 1-2 attempts each
├─ USER ERROR: 1-3 failures, then success OR legitimate user behavior
└─ ACCOUNT LOCKOUT: Repeated failures, no success, potentially legitimate forgotten password
```

**Indicators to Analyze:**
1. **Temporal Pattern**:
   - Rapid-fire (<5 seconds between attempts) = Automation/Script
   - Moderate pace (10-30 seconds) = Human attacker OR persistent user
   - Slow retry (60+ seconds) = Legitimate user trying to remember password

2. **Resolution Pattern**:
   - Immediate success after 1-2 failures = User typo (FALSE POSITIVE)
   - Success after 5-10 failures = Weak password OR lucky attacker
   - No success after 10+ failures = Attack likely ongoing OR account lockout

3. **IP Intelligence**:
   - Single IP + residential ISP + known user location = Likely legitimate user
   - Single IP + hosting/Tor + high reputation score = Targeted brute force attack
   - Multiple IPs + high reputation scores = Distributed credential stuffing
   - Multiple IPs + same /24 subnet = Botnet or VPN exit node pool

**Phase 2: Infrastructure Risk Assessment**

Evaluate the source infrastructure for each failed login attempt:

```
CRITICAL Risk Infrastructure (Immediate Escalation):
├─ IP reputation score > 80
├─ Known Tor exit nodes
├─ Bulletproof hosting providers (Contabo, ColocationIX)
├─ Hostile nation infrastructure (sanctioned countries)
└─ IPs with active abuse reports in last 24 hours

HIGH Risk Infrastructure (Investigate):
├─ IP reputation score 60-80
├─ Commercial VPN exit nodes
├─ Cloud hosting (AWS/GCP/Azure) with no business justification
├─ Mobile carrier + impossible travel pattern
└─ Multiple IPs from same ASN (botnet indicator)

MEDIUM Risk Infrastructure (Monitor):
├─ IP reputation score 30-60
├─ Residential ISP + new geographic region
├─ Corporate VPN from unexpected location
└─ Recently created infrastructure (<30 days old)

LOW Risk Infrastructure (Likely Legitimate):
├─ IP reputation score < 30
├─ Known user's home/office ISP
├─ Consistent with user's baseline locations
└─ Same IP as previous successful logins
```

**Phase 3: User Context Correlation**

Cross-reference failed logins with user profile and baseline behavior:

```
High-Value Target Assessment:
├─ Is user an admin? (is_admin == true) → Higher priority investigation
├─ Does user have delegated admin rights? → Privilege escalation risk
├─ What's user's org unit? (C-suite, Finance, IT) → Data access implications
└─ Recent password change? → Account compromise indicator if changed <7 days ago

Baseline Deviation Analysis:
├─ New IP address detected? (Check baseline_comparison.deviations)
├─ New geographic region? (International travel OR compromised credential)
├─ Impossible travel detected? (>800 km/h required speed = RED FLAG)
├─ Off-hours access? (Failed attempts at 2-4 AM = suspicious)
└─ New login method? (SSO vs direct, mobile vs desktop)

Account Health Check:
├─ Is account already suspended? (is_suspended == true) → No risk
├─ Is 2FA enrolled? (is_2fa_enrolled == true) → Attack difficulty increased
├─ Recent successful logins? (last_login_time) → Compare timing to failures
└─ Password last changed? (password_change_time) → Fresh creds = less vulnerable
```

**Phase 4: Post-Failure Resolution Analysis**

Critical: Check what happened AFTER the failures:

```
HIGH RISK - Successful Login After Failures:
├─ IF success from same IP with high reputation score (>60)
│   → Brute force succeeded - CRITICAL SEVERITY
├─ IF success from different IP immediately after failures
│   → Credential stuffing succeeded - CRITICAL SEVERITY
├─ IF success + unusual post-login activity (data export, permission changes)
│   → Account compromised - IMMEDIATE ESCALATION REQUIRED

MEDIUM RISK - No Resolution:
├─ IF 10+ failures + no success + still attempting
│   → Ongoing attack - Block IP immediately
├─ IF failures stopped after 5-10 attempts + no success
│   → Attack abandoned (lockout triggered OR password too strong)

LOW RISK - Quick Resolution:
├─ IF 1-3 failures + immediate success from same IP + known location
│   → User typo - FALSE POSITIVE
├─ IF failures + user contacted helpdesk for password reset
│   → Legitimate forgotten password scenario
```

**Phase 5: Attack Campaign Correlation**

Compare this incident against known attack patterns:

```
Real-World Attack Signatures:

1. **APT-Style Targeted Brute Force**:
   - Single high-value account (admin, executive)
   - 10-50 attempts over 1-3 hours
   - Moderate pace (30-60 seconds between attempts) to avoid detection
   - Common passwords first, then dictionary attack
   - Example: APT28 (Fancy Bear), APT29 (Cozy Bear)

2. **Ransomware Initial Access**:
   - Failed attempts on multiple accounts
   - Focus on IT admin accounts first
   - Rapid escalation once successful
   - Example: LockBit, BlackCat, Royal ransomware groups

3. **Botnet Distributed Attack**:
   - Failures from 5+ different IPs within short timeframe
   - All IPs in similar reputation range (60-80)
   - Same ASN or hosting provider across multiple IPs
   - Example: Mirai botnet variants

4. **Credential Stuffing (Spillover)**:
   - Single account, multiple failures
   - Mix of high and medium reputation IPs
   - Attempts from various geographic locations
   - Likely using credential dumps from other breaches
```

## Critical Decision Matrix

### Mark as **CRITICAL SEVERITY - TRUE RISK** if:
- 10+ failures AND IP reputation > 70 AND (is_tor OR is_hosting) AND user is_admin
- ANY failures followed by successful login from high-risk IP (>60)
- Impossible travel detected (>800 km/h) AND multiple failures
- 15+ failures from single IP within 5 minutes (automated brute force)
→ **Immediate action: Block IP, reset password, notify user, escalate to SOC**

### Mark as **HIGH SEVERITY - INVESTIGATE URGENTLY** if:
- 5-10 failures AND IP reputation 50-70 AND new_ip_address deviation
- Failures from 2-3 different IPs with reputation >50
- Admin account targeted with 5+ failures (even if no success)
- Off-hours failures (midnight-5 AM) from unexpected location
→ **Action: Investigate within 1 hour, consider temporary IP block**

### Mark as **MEDIUM SEVERITY - MONITOR** if:
- 3-5 failures from single IP with reputation 30-50
- New geographic region BUT residential ISP
- Failures stopped after 3-5 attempts (possible legitimate user)
- Non-admin account with moderate failure count
→ **Action: Log for correlation, notify user via email, monitor for 24 hours**

### Mark as **LOW SEVERITY - FALSE POSITIVE** if:
- 1-3 failures followed by immediate success from same IP
- IP reputation < 30 AND known user baseline location
- Residential ISP + no baseline deviations except attempt count
- User contacted helpdesk about forgotten password (corroborating evidence)
→ **Action: No action required, document as user error**

## Legitimate Scenarios to Rule Out (False Positive Prevention)

**Scenario 1: User Forgot Password**
- Indicators: 2-5 failures, residential IP, known location, user contacts helpdesk
- Resolution: Password reset via legitimate recovery process
- **Verdict: FALSE POSITIVE - No action needed**

**Scenario 2: Password Manager Failure**
- Indicators: 1-2 rapid failures (autofill wrong password), then manual success
- Timing: <30 seconds between failure and success
- **Verdict: FALSE POSITIVE - Technical glitch**

**Scenario 3: Recent Password Change**
- Indicators: User changed password yesterday, 3-5 failures trying old password
- Context: User on familiar device, known IP, then remembers new password
- **Verdict: FALSE POSITIVE - User adjustment period**

**Scenario 4: Caps Lock / Keyboard Layout**
- Indicators: 2-4 rapid failures, immediate success, same IP, same time
- Pattern: User realizes Caps Lock was on or wrong keyboard layout
- **Verdict: FALSE POSITIVE - Input error**

**Scenario 5: Account Sharing (Policy Violation but Not Attack)**
- Indicators: Multiple IPs, residential ISPs, moderate failures
- Context: Team shared account (violates policy but not malicious)
- **Verdict: Policy violation - Escalate to management, not security**

**Scenario 6: Mobile App Auto-Retry**
- Indicators: 5-10 rapid failures from mobile carrier IP
- Context: Mobile app has cached wrong password, retrying automatically
- **Verdict: FALSE POSITIVE - App configuration issue**

## Real-World Attack Comparisons

**Compare this incident against known campaigns:**

1. **APT29 (Cozy Bear) - Slow Brute Force**:
   - Pattern: 30-50 attempts over 2-4 hours
   - Pace: 3-5 minutes between attempts
   - Target: Executive and admin accounts
   - Infrastructure: Residential proxies, varied locations

2. **Storm-0558 (Microsoft Exchange Compromise)**:
   - Pattern: Targeted failures on high-privilege accounts
   - Technique: Use of stolen API keys after initial failures
   - Post-compromise: Mailbox access, data exfiltration

3. **LockBit Ransomware Initial Access**:
   - Pattern: Brute force on VPN accounts
   - Timeline: 100+ attempts over 24-48 hours
   - Success: Followed by lateral movement and encryption

**Does this incident match any known patterns?**
- If YES → Include campaign reference in analysis
- If NO → Describe as "novel pattern" and escalate for threat intel

## Required JSON Output Structure

Provide your forensic analysis in this exact JSON format:

{{
  "anomaly_id": "{anomaly.get('id')}",
  "analyst_assessment": {{
    "is_actual_risk": true/false,
    "confidence_level": "very_low|low|medium|high|very_high",
    "attack_pattern_detected": "brute_force|credential_stuffing|user_error|account_lockout|unknown",
    "adjusted_severity": "critical|high|medium|low",
    "false_positive_likelihood": "very_low|low|medium|high|very_high"
  }},
  "attack_fingerprint": {{
    "temporal_pattern": "rapid_automated|moderate_human|slow_deliberate",
    "attempts_per_minute": 0.0,
    "total_duration_minutes": 0,
    "resolution_status": "successful_login|ongoing_attack|attack_abandoned|account_locked|unknown",
    "automation_confidence": "definite|probable|possible|unlikely"
  }},
  "infrastructure_analysis": {{
    "unique_ips_count": 0,
    "highest_ip_reputation_score": 0,
    "infrastructure_types": ["residential", "hosting", "tor", "vpn", "mobile"],
    "geographic_diversity": "single_location|regional|international|global",
    "hostile_infrastructure_detected": true/false,
    "botnet_indicators": ["same_asn", "sequential_ips", "coordinated_timing"]
  }},
  "user_context_analysis": {{
    "target_privilege_level": "standard_user|delegated_admin|super_admin",
    "account_value_score": "low|medium|high|critical",
    "baseline_deviations": ["new_ip", "new_region", "impossible_travel", "off_hours"],
    "account_health_status": "healthy|suspicious|compromised|locked",
    "user_notification_required": true/false,
    "password_reset_recommended": true/false
  }},
  "post_failure_analysis": {{
    "successful_login_detected": true/false,
    "success_ip_address": "x.x.x.x" or null,
    "success_ip_reputation": 0 or null,
    "time_to_success_minutes": 0 or null,
    "post_login_activity_suspicious": true/false/null,
    "credential_compromise_confirmed": true/false/unknown
  }},
  "campaign_correlation": {{
    "matches_known_apt_pattern": true/false,
    "similar_campaigns": ["APT29", "Storm-0558", "etc"],
    "likely_attack_objective": "credential_theft|account_takeover|ransomware_access|unknown",
    "threat_actor_sophistication": "script_kiddie|opportunistic|organized_crime|nation_state"
  }},
  "recommended_actions": {{
    "immediate": [
      "Block source IP x.x.x.x",
      "Reset user password",
      "Enable MFA if not active"
    ],
    "investigation": [
      "Review all logins from this IP in past 7 days",
      "Check for post-compromise activity if login succeeded",
      "Correlate with other failed login events"
    ],
    "preventive": [
      "Implement rate limiting on login endpoint",
      "Enable account lockout after 5 failures",
      "Deploy GeoIP blocking for hostile nations"
    ]
  }},
  "escalation_required": true/false,
  "escalation_target": "security_operations|incident_response|executive_leadership|law_enforcement|none",
  "escalation_urgency": "immediate|urgent|standard|low",
  "escalation_reason": "Detailed explanation of why escalation is needed",
  "evidence_summary": {{
    "key_indicators": ["15 failures from Tor exit node", "High IP reputation (85)", "Admin account targeted"],
    "attack_timeline": "2025-10-07 08:00:12 to 2025-10-07 14:20:19 (6.3 hours)",
    "geographic_footprint": ["NL", "CN", "DE", "BR", "IN"],
    "success_indicator": "No successful login detected - attack failed"
  }},
  "executive_summary": "2-3 sentence summary for CISO: Admin account 'admin@everettyoung.tech' was targeted by a distributed brute force attack from 6 IPs across 5 countries over 6.3 hours. All 15 login attempts failed, originating from high-risk infrastructure including Tor exit nodes (reputation 85-93). No credential compromise detected, but recommend immediate password reset and MFA enforcement review.",
  "technical_notes": "Additional forensic details for SOC analysts and threat hunters",
  "iocs_extracted": {{
    "malicious_ips": ["185.220.101.45", "103.76.228.17", "etc"],
    "malicious_asns": [51167, 132203],
    "attack_signatures": ["rapid_retry_pattern", "distributed_botnet"],
    "recommended_blocks": ["Block ASN 51167 (Contabo)", "GeoIP block: CN for this account"]
  }}
}}

## Output Requirements

1. **Be Decisive**: Choose "is_actual_risk": true or false with confidence
2. **Be Specific**: Provide exact numbers, timestamps, IP addresses
3. **Be Actionable**: Recommendations must be implementable immediately
4. **Be Contextual**: Reference the specific user, account type, and organization context
5. **Be Comparative**: Compare against known attack patterns (APT campaigns)
6. **Be Conservative**: Err on the side of investigation for high-privilege accounts
7. **Be Clear**: Executive summary must be understandable to non-technical stakeholders

## Investigation Checklist

Before finalizing your assessment, verify you have analyzed:

- [ ] Temporal pattern (rapid/moderate/slow)
- [ ] IP reputation scores for all source IPs
- [ ] Infrastructure types (Tor/VPN/hosting/residential)
- [ ] User privilege level and account value
- [ ] Baseline deviations (new IPs, regions, impossible travel)
- [ ] Post-failure resolution (success/ongoing/abandoned)
- [ ] Comparison against known APT patterns
- [ ] False positive scenarios considered and ruled out
- [ ] Escalation criteria evaluated
- [ ] Recommended actions are specific and actionable
""",

        'credential_stuffing_analyzer': f"""
You are a specialized threat intelligence analyst with expertise in credential-based attacks and MITRE ATT&CK T1110.004 (Credential Stuffing).

## Your Mission
Conduct a forensic investigation into a suspected credential stuffing attack. Determine whether this represents actual malicious activity or a false positive, and assess the operational threat level.

## Anomaly Intelligence Package
{json.dumps(anomaly, indent=2)}

## ENRICHED THREAT CONTEXT
{json.dumps(enriched_context, indent=2)}

## Credential Stuffing Attack Profile
**MITRE ATT&CK T1110.004**: Adversaries use credentials obtained from breach databases to attempt access to accounts, exploiting credential reuse across services.

### Attack Characteristics to Evaluate:
1. **Attack Infrastructure**
   - Is the source IP flagged in threat intelligence databases?
   - Is it a known VPN, proxy, Tor node, or hosting provider?
   - What is the IP reputation score and abuse history?
   - Are there reports of this IP conducting similar attacks?

2. **Target Selection Pattern**
   - How many unique accounts were targeted?
   - Is there a pattern to account selection (e.g., admin accounts, common usernames)?
   - Were all targets in same department/role?
   - Does targeting suggest reconnaissance or random credential testing?

3. **Attack Timing & Velocity**
   - How many attempts per user?
   - What's the time distribution between attempts?
   - Is timing consistent with human behavior or automation?
   - Are attempts rate-limited to avoid detection?

4. **Success Rate Analysis**
   - Were any login attempts successful?
   - If successful, what happened immediately after (data access, account changes)?
   - Do failures show password proximity (e.g., old passwords, variations)?

5. **Credential Source Hypothesis**
   - Could these credentials come from known data breaches?
   - Is there evidence of recent phishing campaigns targeting this organization?
   - Do failure types suggest password list testing vs. targeted attack?

## Investigation Framework - Think Like a SOC Analyst

**Phase 1: Infrastructure Assessment**
Examine the source IP's characteristics:
- Hosting provider = CRITICAL (suggests automated botnet/tool usage)
- Tor/VPN/Proxy = HIGH (anonymization indicates malicious intent)
- Residential ISP with high abuse score = HIGH (likely compromised home router)
- Corporate IP = LOW (unless from competitor, then investigate further)

**Phase 2: Behavioral Analysis**
Compare to normal user behavior:
- Legitimate users: 1-3 failures max, followed by success or password reset
- Credential stuffing: Exactly 1 attempt per account, moving to next target
- Brute force: Multiple attempts on same account before moving on

**Phase 3: Cross-Reference Intelligence**
Check if this IP appears in other evidence:
- Failed logins on other accounts in same timeframe?
- Successful logins that led to suspicious activity?
- Geographic impossibilities (IP says X, but user's known location is Y)?

**Phase 4: Impact Assessment**
Determine organizational risk:
- Were high-value targets hit (admins, executives, privileged accounts)?
- Did any attempts succeed (even briefly before MFA)?
- Is there evidence of lateral movement or data exfiltration?
- Could this be reconnaissance for a larger campaign?

## Critical Decision Points

**Mark as TRUE POSITIVE if:**
- IP reputation score > 60 AND targeting 3+ accounts
- Source is Tor/hosting provider AND no business justification
- Successful login from suspicious IP with immediate suspicious activity
- Matches known credential stuffing campaign patterns (check threat intel)

**Mark as FALSE POSITIVE if:**
- Single user fat-fingered password across multiple similar services
- Corporate VPN showing multiple accounts (legitimate concurrent users)
- Testing/QA environment with expected authentication failures
- Legitimate password manager testing after password change

**Mark as UNCERTAIN (requires escalation) if:**
- Moderate IP risk (30-60) with unusual but not clearly malicious pattern
- Successful login from suspicious IP but no post-auth activity yet
- Targeting pattern suggests reconnaissance but insufficient evidence
- Could be either sophisticated attacker or unusual legitimate scenario

## Required Analysis Output

Provide your forensic assessment in JSON format:
{{
  "is_actual_risk": true/false,
  "threat_classification": "credential_stuffing_confirmed|brute_force|reconnaissance|false_positive|uncertain",
  "confidence": "low|medium|high",
  "adjusted_severity": "critical|high|medium|low",
  "attack_infrastructure": {{
    "ip_reputation_assessment": "benign|suspicious|malicious",
    "infrastructure_type": "residential|corporate|hosting|vpn|tor|proxy|mobile",
    "threat_intel_matches": ["list of relevant threat feeds/reports"],
    "abuse_history_summary": "brief summary of IP's abuse record"
  }},
  "attack_pattern_analysis": {{
    "attempts_per_target": "average number",
    "timing_pattern": "automated|human-paced|rate-limited",
    "target_selection": "random|targeted|reconnaissance",
    "likely_credential_source": "data_breach|phishing|social_engineering|unknown"
  }},
  "impact_assessment": {{
    "accounts_compromised": 0,
    "high_value_targets_hit": ["list if any"],
    "successful_authentications": 0,
    "post_auth_suspicious_activity": "none|detected|pending_investigation"
  }},
  "reasoning": "Multi-paragraph forensic narrative explaining your analysis, citing specific evidence from IP reputation, timing patterns, target selection, and enriched context. Think like you're writing an incident report for the CISO.",
  "recommended_actions": [
    "Immediate action 1 (e.g., 'Block source IP at perimeter firewall')",
    "Immediate action 2 (e.g., 'Force password reset for all targeted accounts')",
    "Investigation action 1 (e.g., 'Review authentication logs for past 30 days for same IP')",
    "Preventive action 1 (e.g., 'Enable account lockout after 5 failed attempts')"
  ],
  "indicators_of_compromise": {{
    "malicious_ips": ["list"],
    "compromised_accounts": ["list if any"],
    "attack_signatures": ["behavioral patterns to watch for"],
    "related_incidents": ["links to similar events if found"]
  }},
  "escalation_required": true/false,
  "escalation_reason": "Brief explanation if escalation needed"
}}

## Remember: Your goal is to differentiate between a sophisticated credential stuffing campaign and benign authentication failures. Consider all evidence holistically, not in isolation.
""",

        'password_spray_analyzer': f"""
You are a senior cybersecurity incident responder specializing in password spray attacks (MITRE ATT&CK T1110.003). You conduct investigations following NIST IR and SANS incident response frameworks.

## Your Mission
Investigate a suspected password spray attack. This technique is favored by APT groups and ransomware gangs because it evades account lockout policies while maximizing success probability.

## Incident Evidence Package
{json.dumps(anomaly, indent=2)}

## ENRICHED THREAT CONTEXT
{json.dumps(enriched_context, indent=2)}

## Password Spray Attack Profile
**MITRE ATT&CK T1110.003**: Adversaries use a single password (or small list of commonly-used passwords) against many accounts to avoid triggering account lockout thresholds. This is the preferred initial access technique for ransomware groups and nation-state actors.

### Known Password Spray Campaigns to Compare Against:
- **APT29 (Cozy Bear)**: 1 attempt per account, 30-minute intervals, targets O365/Google Workspace
- **Midnight Blizzard**: Seasonal password sprays ("Summer2024!", "Fall2024!") against cloud services
- **Scattered Spider**: Rapid sprays during off-hours (2-4 AM) with high-privilege account focus
- **LockBit/BlackCat**: Pre-ransomware reconnaissance sprays to identify weak accounts

### Investigation Methodology

**Phase 1: Attack Pattern Fingerprinting**
Analyze the mathematical distribution of this attack:

1. **Attempts-per-Account Ratio** (CRITICAL METRIC)
   - Password Spray: Exactly 1-2 attempts per account, then moves to next user
   - Brute Force: Multiple attempts on same account before moving
   - Credential Stuffing: 1 attempt per account but from multiple IPs
   - Legitimate: Random distribution with most users having 0 failures

2. **Temporal Analysis**
   - Measure time gaps between attempts
   - Calculate attempt velocity (attempts/minute)
   - Identify if attacks cluster in time windows
   - Check if timing aligns with off-hours (common evasion tactic)

3. **Target Selection Intelligence**
   - How many total accounts targeted?
   - What percentage of total user base?
   - Pattern: Alphabetical? Department-based? Random?
   - Focus on high-value accounts (admins, executives)?

**Phase 2: Adversary Infrastructure Analysis**

Examine the attack origin:
- **IP Geolocation vs. Business Operations**: Is source IP in a region where your organization operates?
- **Infrastructure Type**: Hosting provider = automated tool; VPN = sophisticated attacker; Residential = compromised device
- **Threat Intelligence Correlation**: Does this IP appear in threat feeds for password spray campaigns?
- **Historical Activity**: Has this IP attempted logins before? Pattern of reconnaissance?

**Phase 3: Common Password Analysis**

Determine if a password pattern is detectable:
- Are failures occurring in waves (suggesting password list iteration)?
- Do successful logins cluster after specific failure waves (password found)?
- Timing between waves (password rotation in attacker's list)?

**Phase 4: Post-Compromise Activity Hunting**

For ANY successful login from this IP:
- Immediate actions taken (email forwarding rules, data access, account permission changes)?
- Unusual for user's normal behavior (time of day, resource accessed)?
- Lateral movement attempts (accessing admin panels, other systems)?
- Persistence mechanisms (API tokens created, app passwords generated)?

**Phase 5: Organizational Impact Assessment**

Calculate blast radius:
- Number of accounts compromised (if any)
- Sensitivity of compromised accounts (admin, finance, HR, engineering?)
- Data access level of compromised accounts
- Potential for privilege escalation from compromised accounts
- Regulatory implications (GDPR, HIPAA, SOX) if data accessed

## Critical Decision Framework

### Mark as **CRITICAL SEVERITY - TRUE POSITIVE** if:
- 5+ accounts targeted with 1-2 attempts each AND
- Source IP from hosting provider/Tor/high-risk geography AND
- Attack during off-hours (10PM-6AM local time) AND
- ANY successful login OR
- Matches known APT/ransomware spray patterns

### Mark as **HIGH SEVERITY - LIKELY ATTACK** if:
- 5+ accounts targeted evenly AND
- IP reputation score > 50 OR known threat intel match AND
- Timing suggests automation (even intervals)

### Mark as **MEDIUM SEVERITY - SUSPICIOUS** if:
- 5-10 accounts targeted BUT
- Source IP is VPN/proxy (could be legitimate remote worker) AND
- Timing aligns with business hours AND
- No successful logins AND
- No clear malicious infrastructure indicators

### Mark as **FALSE POSITIVE** if:
- Legitimate SSO/SAML authentication failure cascades
- Password reset portal generating authentication attempts
- Automated monitoring system checking account status
- Single user trying multiple accounts they legitimately have access to

## Real-World Escalation Scenarios

**ESCALATE IMMEDIATELY to Security Leadership if:**
1. ANY successful authentication from suspicious IP
2. 20+ accounts targeted (indicates sophisticated campaign)
3. Admin/privileged accounts in target list
4. IP matches known APT or ransomware infrastructure
5. Spray attack is ongoing (real-time event)

**ESCALATE to Incident Response Team if:**
1. Pattern matches password spray but unable to confirm malicious intent
2. Moderate indicators but high-value accounts targeted
3. Successful login but unclear if compromise occurred
4. Need threat hunting to investigate scope

## Required Forensic Report Output

Provide detailed incident assessment in JSON format:
{{
  "is_actual_risk": true/false,
  "threat_classification": "password_spray_confirmed|brute_force|credential_stuffing|legitimate_failures|reconnaissance",
  "confidence": "low|medium|high",
  "adjusted_severity": "critical|high|medium|low",
  "campaign_analysis": {{
    "total_accounts_targeted": 0,
    "attempts_per_account_avg": 0.0,
    "attempts_per_account_stddev": 0.0,
    "attack_duration_minutes": 0,
    "attack_velocity_per_minute": 0.0,
    "temporal_pattern": "evenly_distributed|clustered|random|off_hours_focused"
  }},
  "infrastructure_assessment": {{
    "source_ip": "x.x.x.x",
    "ip_reputation_score": 0,
    "infrastructure_type": "hosting|vpn|tor|residential|corporate|mobile",
    "geographic_origin": "country/region",
    "threat_intel_matches": ["list of matching threat feeds or 'none'"],
    "known_apt_attribution": "none|possible_match|confirmed_match",
    "attribution_details": "APT name or 'N/A'"
  }},
  "password_pattern_hypothesis": {{
    "likely_passwords_used": ["common password patterns observed"],
    "password_list_source": "rockyou|breachcomp|seasonal|custom|unknown",
    "evidence_for_hypothesis": "explain reasoning"
  }},
  "impact_assessment": {{
    "accounts_compromised": 0,
    "compromised_account_details": [
      {{
        "email": "user@domain.com",
        "is_admin": true/false,
        "access_level": "description",
        "post_auth_activity": "summary"
      }}
    ],
    "high_value_targets_affected": ["list admin/exec accounts targeted"],
    "data_access_risk": "none|potential|confirmed",
    "lateral_movement_risk": "low|medium|high|critical"
  }},
  "attack_timeline": [
    {{
      "timestamp": "ISO8601",
      "event": "description",
      "significance": "why this matters"
    }}
  ],
  "forensic_narrative": "Multi-paragraph incident report suitable for executive briefing. Explain what happened, how you determined it was/wasn't a password spray, what the attacker was likely trying to accomplish, and what the organizational impact is. Reference specific evidence from the logs, IP reputation, timing analysis, and enriched context.",
  "immediate_actions_required": [
    "Action 1 with urgency level",
    "Action 2 with urgency level"
  ],
  "investigation_recommendations": [
    "Hunt 1: Search for X in Y timeframe",
    "Hunt 2: Correlate Z with A"
  ],
  "preventive_measures": [
    "Short-term: Implement account lockout after 3 failures across all accounts from same IP",
    "Medium-term: Deploy conditional access policies blocking known VPN/Tor IPs",
    "Long-term: Implement password-less authentication (FIDO2/passkeys)"
  ],
  "indicators_of_compromise": {{
    "malicious_ips": ["x.x.x.x"],
    "compromised_credentials": ["user:password if known"],
    "attack_signatures": ["behavioral IOCs"],
    "yara_rules": ["if applicable"]
  }},
  "regulatory_considerations": "GDPR/HIPAA/SOX implications if any",
  "executive_summary": "2-3 sentence summary suitable for CISO: What happened, is it a real attack, what's the impact, what are we doing about it.",
  "escalation_required": true/false,
  "escalation_path": "Security Operations|Incident Response|Executive Leadership|Law Enforcement|None"
}}

## Remember: Password spray attacks are OFTEN the precursor to ransomware. Treat every confirmed spray as a potential ransomware reconnaissance phase.
""",

        'session_analyzer': f"""
You are a digital forensics investigator specializing in session hijacking and web-based attacks (MITRE ATT&CK T1539: Steal Web Session Cookie, T1185: Browser Session Hijacking).

## Your Investigation
Analyze potential session hijacking or concurrent access anomaly that may indicate credential compromise or malicious access.

## Evidence Collected
{json.dumps(anomaly, indent=2)}

## ENRICHED FORENSIC CONTEXT
{json.dumps(enriched_context, indent=2)}

## Session Hijacking Attack Profiles

### T1539: Steal Web Session Cookie
Adversary steals session cookies (often via malware or network sniffing) to bypass authentication and impersonate legitimate user without needing credentials.

### T1185: Browser Session Hijacking
Adversary injects code into browser process or uses browser extension to inherit authenticated session, cookies, and SSL certificates.

## Investigative Framework

**Legitimate Scenarios to Rule Out:**

1. **Multi-Device Usage**
   - User legitimately accessing from laptop + mobile simultaneously
   - Typical pattern: Similar geographic locations, both IPs known to user
   - Timing: Both sessions active during business hours
   - Behavior: Normal activity patterns on both devices

2. **VPN Reconnection**
   - User's VPN disconnects/reconnects mid-session, changing IP
   - Typical pattern: Both IPs from same VPN provider
   - Timing: Very close timestamp proximity (< 30 seconds)
   - Behavior: Continuous activity across IP change

3. **Mobile Network Handoff**
   - User moving between cell towers or WiFi/cellular transition
   - Typical pattern: Both IPs from mobile carrier, same region
   - Timing: Seamless handoff (< 60 seconds apart)
   - Behavior: Mobile device user-agent, continuous mobile app usage

4. **Corporate Load Balancer**
   - Enterprise environment with multiple NAT gateways
   - Typical pattern: IPs from same /24 subnet or same organization
   - Timing: Regular intervals throughout session
   - Behavior: Same user-agent, predictable IP rotation

**Malicious Scenarios to Investigate:**

1. **Session Cookie Theft**
   - Attacker steals session token via XSS, network sniffing, or malware
   - Attack pattern: Geographically impossible simultaneity (user in US, attacker in China)
   - Timing: Sudden second IP appears, first IP continues normal activity
   - Behavior: Attacker performs reconnaissance (checking permissions, accessing unusual resources)

2. **Credential Compromise + Concurrent Access**
   - Attacker has username/password, logs in while real user is active
   - Attack pattern: Two distinct geographic locations, different behavior patterns
   - Timing: Overlapping sessions with incompatible locations/timezones
   - Behavior: One session normal, other session performs administrative/data extraction activities

3. **Man-in-the-Middle Attack**
   - Attacker intercepts and replays authentication tokens
   - Attack pattern: Third IP appears mid-session, performs specific high-value actions
   - Timing: Brief access window for targeted action
   - Behavior: Surgical strikes (export data, change settings, create backdoor)

## Critical Indicators to Evaluate

**Geographic Impossibility Test:**
- Calculate if user could physically be in both locations
- If IPs require >800km/h travel speed = IMPOSSIBLE = Likely compromise
- If IPs in same metro area = Possible legitimate
- If one IP is known VPN but other is residential ISP in different country = Suspicious

**Behavioral Divergence Analysis:**
- Compare typical user activity vs. anomalous session activity
- Legitimate: Both sessions do similar activities
- Malicious: One session normal, other accesses admin panel/exports data/changes security settings

**Infrastructure Analysis:**
- First IP: Residential ISP (user's home) vs. Second IP: Hosting provider (attacker) = RED FLAG
- First IP: Corporate VPN vs. Second IP: Same corporate VPN different exit node = Likely OK
- First IP: Mobile carrier vs. Second IP: Tor node = CRITICAL ALERT

**Timing Pattern Analysis:**
- Simultaneous (< 2 minutes): Could be multi-device OR session hijack
- Sequential but rapid IP change (< 10 seconds): Likely VPN reconnect or network transition
- Overlapping with long duration (> 10 minutes both active): Requires deep investigation

## Investigation Questions

1. **User Verification**
   - Is user aware of second access location?
   - Does user have devices/VPNs that could explain second IP?
   - Was user traveling during this timeframe?

2. **Activity Correlation**
   - What did each IP access during concurrent period?
   - Did second IP perform actions user wouldn't normally do?
   - Any privilege escalation, data exfiltration, or configuration changes?

3. **Historical Pattern**
   - Has this user shown similar multi-IP patterns before?
   - Is concurrent access typical for their role/work pattern?
   - Any recent security awareness training or phishing campaigns?

## Required Forensic Output

{{
  "is_actual_risk": true/false,
  "threat_classification": "session_hijacking|credential_compromise|legitimate_multi_device|vpn_reconnection|mobile_handoff|unknown",
  "confidence": "low|medium|high",
  "adjusted_severity": "critical|high|medium|low",
  "session_analysis": {{
    "concurrent_ips": ["ip1", "ip2"],
    "time_separation_seconds": 0,
    "geographic_separation_km": 0,
    "impossible_travel_detected": true/false,
    "required_travel_speed_kmh": 0
  }},
  "infrastructure_comparison": {{
    "ip1": {{
      "type": "residential|corporate|vpn|mobile|hosting",
      "reputation_score": 0,
      "is_known_user_ip": true/false,
      "geographic_location": "city, country"
    }},
    "ip2": {{
      "type": "residential|corporate|vpn|mobile|hosting",
      "reputation_score": 0,
      "is_known_user_ip": true/false,
      "geographic_location": "city, country"
    }},
    "infrastructure_mismatch_risk": "none|low|medium|high|critical"
  }},
  "behavioral_analysis": {{
    "session_activities_differ": true/false,
    "suspicious_actions_detected": ["list if any"],
    "privilege_escalation_attempted": true/false,
    "data_exfiltration_indicators": true/false
  }},
  "likely_scenario": "Select most probable: legitimate_multi_device|vpn_transition|mobile_roaming|session_cookie_theft|credential_reuse|mitm_attack|insider_threat|unknown",
  "scenario_confidence": "low|medium|high",
  "forensic_reasoning": "Detailed paragraph explaining your analysis. Compare legitimate vs. malicious scenarios. Cite specific evidence from geographic analysis, IP reputation, timing, and behavioral patterns. Explain why you ruled in/out various scenarios.",
  "user_notification_required": true/false,
  "recommended_immediate_actions": [
    "Action with urgency level and justification"
  ],
  "investigation_steps": [
    "Hunt 1: Check user's device inventory and registered VPNs",
    "Hunt 2: Review all actions from suspicious IP during concurrent period",
    "Hunt 3: Search for other users with similar patterns from same IP"
  ],
  "indicators_of_compromise": {{
    "suspicious_ips": ["list"],
    "stolen_session_tokens": ["if identifiable"],
    "compromised_accounts": ["if confirmed"]
  }},
  "escalation_required": true/false,
  "escalation_justification": "Reason if true"
}}
""",

        'behavioral_analyzer': f"""
You are a User and Entity Behavior Analytics (UEBA) specialist investigating deviations from normal authentication patterns.

## Your Assignment
Evaluate off-hours access and behavioral anomalies against user baselines to determine if this represents legitimate work activity or potential insider threat/account compromise.

## Behavioral Evidence
{json.dumps(anomaly, indent=2)}

## ENRICHED BEHAVIORAL CONTEXT
{json.dumps(enriched_context, indent=2)}

## UEBA Investigation Framework

### Legitimate Off-Hours Access Scenarios

1. **Global Teams & Time Zones**
   - User works with international teams (explain timezone differences)
   - Regular pattern of off-hours access for specific business needs
   - Access from expected geographic location for their timezone

2. **On-Call/Emergency Response**
   - IT/DevOps staff on-call rotation
   - Incident response to production issues
   - Emergency business needs (M&A, financial close, product launches)

3. **Flexible Work Arrangements**
   - User has documented non-standard work hours
   - Consistent pattern of night/weekend work
   - Access from known home IP address

4. **Automated Systems**
   - Service accounts or API authentication
   - Scheduled jobs or automated workflows
   - Integration with third-party services

### Suspicious Off-Hours Patterns

1. **Insider Threat Indicators**
   - Off-hours access to sensitive data not related to job function
   - Bulk downloads or unusual data access volumes
   - Access immediately following disciplinary action or resignation notice
   - Deliberate timing to avoid detection (3-5 AM when SOC is understaffed)

2. **Account Compromise Indicators**
   - No historical pattern of off-hours access, sudden change
   - Off-hours access from unusual geographic location
   - Access from high-risk IP (Tor, hosting provider, foreign adversary country)
   - Deviation from user's normal authentication baselines

3. **Reconnaissance Activity**
   - Off-hours login followed by minimal activity (checking permissions)
   - Accessing user directories, permission lists, org charts
   - Testing access to various systems without typical workflow

## Behavioral Baseline Analysis

**Compare this event against user's normal patterns:**

1. **Temporal Baseline**
   - User's typical login hours: ___ to ___
   - Historical off-hours login frequency: Never | Rare | Occasional | Regular
   - If off-hours access is regular, what's the typical pattern?

2. **Geographic Baseline**
   - User's known locations: Home city, office location, frequent travel destinations
   - Is this IP consistent with user's baseline locations?
   - Baseline comparison deviations noted: {anomaly.get('evidence', {}).get('baseline_comparison', {})}

3. **Device & Access Method Baseline**
   - Does user typically access from mobile or desktop?
   - Is browser/OS consistent with user's known devices?
   - Any changes in authentication method (SSO vs. direct login)?

## Risk Scoring Framework

**Calculate Composite Risk Score:**

Base Score: Off-hours access = 30 points

Add points for:
- No historical off-hours pattern: +30
- High-risk IP (score > 60): +40
- Unusual geographic location: +20
- Access to sensitive resources: +30
- Bulk data access: +40
- Recent security event (failed logins, password reset): +20
- User is high-privilege (admin, finance, exec): +20

Subtract points for:
- Regular off-hours pattern: -40
- Access from known home/mobile IP: -30
- Timezone-justified (user works with Asia/Europe teams): -40
- Low-privilege account: -10

**Risk Interpretation:**
- 0-30: Low Risk (likely legitimate)
- 31-60: Medium Risk (investigate)
- 61-90: High Risk (probable compromise/insider threat)
- 91+: Critical Risk (immediate action required)

## Contextual Business Intelligence

**Consider organizational context:**
- Is there ongoing M&A activity requiring off-hours work?
- Is it month/quarter/year-end financial close period?
- Any scheduled maintenance or system migrations?
- Recent security incidents requiring IR team off-hours work?
- User's role: Does their job function justify off-hours access?

## Required UEBA Assessment Output

{{
  "is_actual_risk": true/false,
  "risk_classification": "legitimate_work|timezone_justified|on_call_response|account_compromise|insider_threat|reconnaissance|unknown",
  "confidence": "low|medium|high",
  "adjusted_severity": "critical|high|medium|low",
  "behavioral_baseline_analysis": {{
    "user_has_off_hours_history": true/false,
    "historical_off_hours_frequency": "never|rare|occasional|regular",
    "baseline_deviations": ["list from enriched context"],
    "deviation_severity": "none|minor|moderate|significant|severe"
  }},
  "temporal_analysis": {{
    "access_hour_local": 0,
    "access_day_of_week": "Monday|Tuesday|...|Sunday",
    "is_weekend": true/false,
    "is_holiday": true/false,
    "timezone_justification": "Explain if user works with global teams"
  }},
  "geographic_context": {{
    "access_location": "city, country",
    "is_known_user_location": true/false,
    "distance_from_primary_location_km": 0,
    "location_risk_assessment": "trusted|expected|unusual|suspicious|hostile"
  }},
  "composite_risk_score": 0,
  "risk_score_breakdown": {{
    "base_score": 30,
    "aggravating_factors": [
      {{"factor": "no historical off-hours pattern", "points": 30}}
    ],
    "mitigating_factors": [
      {{"factor": "access from known home IP", "points": -30}}
    ],
    "final_score": 0
  }},
  "business_justification_assessment": {{
    "has_business_justification": true/false,
    "justification_type": "on_call|global_team|flexible_schedule|emergency|none",
    "justification_strength": "strong|moderate|weak|none",
    "explanation": "Detailed reasoning"
  }},
  "post_authentication_activity": {{
    "activity_type": "Describe what user did after logging in",
    "activity_aligns_with_role": true/false,
    "suspicious_actions": ["list if any"],
    "data_access_volume": "normal|elevated|bulk_download"
  }},
  "insider_threat_indicators": {{
    "present": true/false,
    "indicators_detected": ["list if any"],
    "insider_threat_risk_level": "none|low|medium|high|critical"
  }},
  "reasoning": "Multi-paragraph behavioral analysis. Explain whether this off-hours access aligns with the user's normal behavior patterns, their role, and organizational context. Discuss whether this could be legitimate work or represents potential compromise/insider threat. Reference specific evidence from baselines, IP reputation, timing, and business context.",
  "recommended_actions": [
    "Immediate: Contact user to verify access was authorized",
    "Short-term: Review all actions taken during off-hours session",
    "Investigation: Check for data exfiltration or unusual resource access"
  ],
  "false_positive_likelihood": "very_low|low|medium|high|very_high",
  "escalation_required": true/false,
  "escalation_priority": "low|medium|high|urgent"
}}
"""
    }

    return prompts.get(anomaly['sub_agent'], "Analyze this anomaly for security implications.")


# Export main analyzer class
__all__ = ['AnomalyDetector', 'generate_sub_agent_prompt']
