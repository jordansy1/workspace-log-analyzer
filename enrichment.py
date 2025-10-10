"""
Data Enrichment Module

Enriches authentication log data with contextual information from multiple sources:
- IP reputation (AbuseIPDB, VirusTotal)
- Enhanced geolocation (IPInfo.io)
- User context (Google Directory API)
- Historical baseline (your own data)
"""

import os
import json
import time
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class IPReputationEnricher:
    """Enriches IP addresses with reputation data from threat intelligence sources."""

    def __init__(self):
        """Initialize with API keys from environment."""
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.enabled = os.getenv('ENABLE_IP_REPUTATION', 'true').lower() == 'true'

        if not self.abuseipdb_key and not self.virustotal_key:
            print("[WARNING] No IP reputation API keys configured. Enrichment disabled.")
            self.enabled = False

    def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Enrich IP address with reputation data.

        Args:
            ip_address: IP address to check

        Returns:
            Dictionary with reputation data
        """
        if not self.enabled:
            return {'enrichment_enabled': False}

        result = {
            'ip_address': ip_address,
            'enrichment_timestamp': datetime.now().isoformat(),
            'abuseipdb': None,
            'virustotal': None,
            'overall_risk_score': 0,
            'is_malicious': False
        }

        # Check AbuseIPDB
        if self.abuseipdb_key:
            result['abuseipdb'] = self._check_abuseipdb(ip_address)

        # Check VirusTotal
        if self.virustotal_key:
            result['virustotal'] = self._check_virustotal(ip_address)

        # Calculate overall risk
        result['overall_risk_score'] = self._calculate_risk_score(result)
        result['is_malicious'] = result['overall_risk_score'] > 50

        return result

    def _check_abuseipdb(self, ip_address: str) -> Optional[Dict]:
        """Check IP reputation on AbuseIPDB."""
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_key
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': True
            }

            response = requests.get(url, headers=headers, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'country_code': data.get('countryCode'),
                    'isp': data.get('isp'),
                    'domain': data.get('domain'),
                    'total_reports': data.get('totalReports', 0),
                    'num_distinct_users': data.get('numDistinctUsers', 0),
                    'last_reported_at': data.get('lastReportedAt'),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'is_tor': data.get('isTor', False)
                }
            elif response.status_code == 429:
                print(f"  [WARNING] AbuseIPDB rate limit exceeded for {ip_address}")
                return {'error': 'rate_limit_exceeded'}
            else:
                print(f"  [WARNING] AbuseIPDB check failed for {ip_address}: {response.status_code}")
                return {'error': f'api_error_{response.status_code}'}

        except Exception as e:
            print(f"  [ERROR] AbuseIPDB check failed for {ip_address}: {e}")
            return {'error': str(e)}

    def _check_virustotal(self, ip_address: str) -> Optional[Dict]:
        """Check IP reputation on VirusTotal."""
        try:
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
            headers = {
                'accept': 'application/json',
                'x-apikey': self.virustotal_key
            }

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json().get('data', {})
                attributes = data.get('attributes', {})
                last_analysis_stats = attributes.get('last_analysis_stats', {})

                return {
                    'malicious': last_analysis_stats.get('malicious', 0),
                    'suspicious': last_analysis_stats.get('suspicious', 0),
                    'harmless': last_analysis_stats.get('harmless', 0),
                    'undetected': last_analysis_stats.get('undetected', 0),
                    'total_votes_malicious': attributes.get('total_votes', {}).get('malicious', 0),
                    'total_votes_harmless': attributes.get('total_votes', {}).get('harmless', 0),
                    'reputation': attributes.get('reputation', 0),
                    'asn': attributes.get('asn'),
                    'country': attributes.get('country')
                }
            elif response.status_code == 429:
                print(f"  [WARNING] VirusTotal rate limit exceeded for {ip_address}")
                return {'error': 'rate_limit_exceeded'}
            else:
                print(f"  [WARNING] VirusTotal check failed for {ip_address}: {response.status_code}")
                return {'error': f'api_error_{response.status_code}'}

        except Exception as e:
            print(f"  [ERROR] VirusTotal check failed for {ip_address}: {e}")
            return {'error': str(e)}

    def _calculate_risk_score(self, enrichment_data: Dict) -> int:
        """
        Calculate overall risk score (0-100) based on multiple sources.

        Args:
            enrichment_data: Combined enrichment data

        Returns:
            Risk score from 0 (safe) to 100 (highly malicious)
        """
        risk_score = 0

        # AbuseIPDB contribution (0-60 points)
        abuseipdb = enrichment_data.get('abuseipdb')
        if abuseipdb and not abuseipdb.get('error'):
            confidence = abuseipdb.get('abuse_confidence_score', 0)
            risk_score += int(confidence * 0.6)  # Max 60 points

            if abuseipdb.get('is_tor'):
                risk_score += 10  # Tor exit node

        # VirusTotal contribution (0-40 points)
        virustotal = enrichment_data.get('virustotal')
        if virustotal and not virustotal.get('error'):
            malicious = virustotal.get('malicious', 0)
            suspicious = virustotal.get('suspicious', 0)
            total_checks = (malicious + suspicious +
                          virustotal.get('harmless', 0) +
                          virustotal.get('undetected', 0))

            if total_checks > 0:
                malicious_ratio = (malicious + (suspicious * 0.5)) / total_checks
                risk_score += int(malicious_ratio * 40)  # Max 40 points

        return min(risk_score, 100)


class GeolocationEnricher:
    """Enriches IP addresses with detailed geolocation data."""

    def __init__(self):
        """Initialize with IPInfo.io token."""
        self.ipinfo_token = os.getenv('IPINFO_TOKEN')
        self.enabled = os.getenv('ENABLE_GEOLOCATION_ENRICHMENT', 'true').lower() == 'true'

        if not self.ipinfo_token:
            print("[WARNING] IPInfo.io token not configured. Using basic geolocation only.")

    def enrich_location(self, ip_address: str, existing_network_info: Dict = None) -> Dict[str, Any]:
        """
        Enrich with detailed geolocation data.

        Args:
            ip_address: IP address to geolocate
            existing_network_info: Network info from Google Workspace logs

        Returns:
            Enhanced geolocation data
        """
        if not self.enabled or not self.ipinfo_token:
            return existing_network_info or {}

        try:
            url = f'https://ipinfo.io/{ip_address}/json'
            headers = {
                'Authorization': f'Bearer {self.ipinfo_token}'
            }

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()

                # Merge with existing network info
                result = existing_network_info.copy() if existing_network_info else {}

                result.update({
                    'city': data.get('city'),
                    'region': data.get('region'),
                    'country': data.get('country'),
                    'loc': data.get('loc'),  # latitude,longitude
                    'postal': data.get('postal'),
                    'timezone': data.get('timezone'),
                    'org': data.get('org'),  # ASN + Org name
                    'hostname': data.get('hostname'),
                    'is_vpn': data.get('privacy', {}).get('vpn', False) if 'privacy' in data else None,
                    'is_proxy': data.get('privacy', {}).get('proxy', False) if 'privacy' in data else None,
                    'is_tor': data.get('privacy', {}).get('tor', False) if 'privacy' in data else None,
                    'is_hosting': data.get('privacy', {}).get('hosting', False) if 'privacy' in data else None
                })

                return result
            else:
                print(f"  [WARNING] IPInfo.io enrichment failed for {ip_address}: {response.status_code}")
                return existing_network_info or {}

        except Exception as e:
            print(f"  [ERROR] Geolocation enrichment failed for {ip_address}: {e}")
            return existing_network_info or {}


class UserContextEnricher:
    """Enriches with user-specific context from Google Directory API."""

    def __init__(self, credentials_file='credentials.json', token_file='token.json'):
        """Initialize with Google credentials."""
        self.credentials_file = credentials_file
        self.token_file = token_file
        self.enabled = os.getenv('ENABLE_USER_CONTEXT_ENRICHMENT', 'true').lower() == 'true'
        self.service = None

        if self.enabled:
            self._initialize_service()

    def _initialize_service(self):
        """Initialize Google Directory API service."""
        try:
            from google.oauth2.credentials import Credentials
            from google_auth_oauthlib.flow import InstalledAppFlow
            from google.auth.transport.requests import Request
            from googleapiclient.discovery import build

            # Extended scopes for Directory API
            SCOPES = [
                'https://www.googleapis.com/auth/admin.reports.audit.readonly',
                'https://www.googleapis.com/auth/admin.directory.user.readonly',
                'https://www.googleapis.com/auth/admin.directory.device.mobile.readonly'
            ]

            creds = None

            # Load existing token
            if os.path.exists(self.token_file):
                creds = Credentials.from_authorized_user_file(self.token_file, SCOPES)

            # If credentials are invalid, refresh or re-authenticate
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    print("[INFO] Directory API requires re-authentication with expanded scopes")
                    flow = InstalledAppFlow.from_client_secrets_file(
                        self.credentials_file, SCOPES
                    )
                    creds = flow.run_local_server(port=0)

                # Save credentials
                with open(self.token_file, 'w') as token:
                    token.write(creds.to_json())

            self.service = build('admin', 'directory_v1', credentials=creds)
            print("[OK] Directory API initialized")

        except Exception as e:
            print(f"[WARNING] Failed to initialize Directory API: {e}")
            self.enabled = False

    def enrich_user(self, user_email: str) -> Dict[str, Any]:
        """
        Enrich with user context from Directory API.

        Args:
            user_email: User email address

        Returns:
            User context data
        """
        if not self.enabled or not self.service:
            return {'enrichment_enabled': False}

        try:
            # Get user details
            user = self.service.users().get(userKey=user_email).execute()

            return {
                'user_email': user_email,
                'full_name': user.get('name', {}).get('fullName'),
                'is_admin': user.get('isAdmin', False),
                'is_delegated_admin': user.get('isDelegatedAdmin', False),
                'is_suspended': user.get('suspended', False),
                'org_unit_path': user.get('orgUnitPath'),
                'creation_time': user.get('creationTime'),
                'last_login_time': user.get('lastLoginTime'),
                'is_2fa_enrolled': user.get('isEnrolledIn2Sv', False),
                'is_2fa_enforced': user.get('isEnforcedIn2Sv', False),
                'password_change_time': user.get('changePasswordAtNextLogin'),
                'external_ids': user.get('externalIds', []),
                'organizations': user.get('organizations', [])
            }

        except Exception as e:
            print(f"  [WARNING] Failed to enrich user {user_email}: {e}")
            return {'error': str(e), 'user_email': user_email}


class HistoricalBaselineTracker:
    """Tracks and compares against historical baseline patterns."""

    def __init__(self, baseline_db_path='analysis/baseline.json'):
        """Initialize baseline tracker."""
        self.baseline_db_path = baseline_db_path
        self.enabled = os.getenv('ENABLE_HISTORICAL_BASELINE', 'true').lower() == 'true'
        self.lookback_days = int(os.getenv('BASELINE_LOOKBACK_DAYS', 30))
        self.baseline = self._load_baseline()

    def _load_baseline(self) -> Dict:
        """Load existing baseline data."""
        if not self.enabled:
            return {}

        if os.path.exists(self.baseline_db_path):
            try:
                with open(self.baseline_db_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[WARNING] Failed to load baseline: {e}")
                return {}
        return {}

    def update_baseline(self, events: List[Dict]):
        """Update baseline with new events."""
        if not self.enabled:
            return

        for event in events:
            user = event.get('user_email')
            if not user:
                continue

            if user not in self.baseline:
                self.baseline[user] = {
                    'first_seen': event.get('timestamp'),
                    'ips': set(),
                    'regions': set(),
                    'asns': set(),
                    'login_hours': [],
                    'total_logins': 0,
                    'failed_logins': 0
                }

            # Update patterns (convert sets to lists for JSON serialization later)
            baseline = self.baseline[user]
            baseline['total_logins'] += 1

            if event.get('ip_address'):
                if isinstance(baseline['ips'], set):
                    baseline['ips'].add(event['ip_address'])
                else:
                    baseline['ips'] = set(baseline['ips'])
                    baseline['ips'].add(event['ip_address'])

            network_info = event.get('network_info', {})
            if network_info and network_info.get('region_code'):
                if isinstance(baseline['regions'], set):
                    baseline['regions'].add(network_info['region_code'])
                else:
                    baseline['regions'] = set(baseline['regions'])
                    baseline['regions'].add(network_info['region_code'])

            if event.get('event_name') == 'login_failure':
                baseline['failed_logins'] += 1

        self._save_baseline()

    def _save_baseline(self):
        """Save baseline to disk."""
        if not self.enabled:
            return

        os.makedirs(os.path.dirname(self.baseline_db_path), exist_ok=True)

        # Convert sets to lists for JSON serialization
        serializable_baseline = {}
        for user, data in self.baseline.items():
            serializable_baseline[user] = data.copy()
            if isinstance(data.get('ips'), set):
                serializable_baseline[user]['ips'] = list(data['ips'])
            if isinstance(data.get('regions'), set):
                serializable_baseline[user]['regions'] = list(data['regions'])
            if isinstance(data.get('asns'), set):
                serializable_baseline[user]['asns'] = list(data['asns'])

        with open(self.baseline_db_path, 'w') as f:
            json.dump(serializable_baseline, f, indent=2)

    def check_against_baseline(self, event: Dict) -> Dict[str, Any]:
        """
        Check if event deviates from historical baseline.

        Returns:
            Deviation analysis
        """
        if not self.enabled:
            return {'baseline_enabled': False}

        user = event.get('user_email')
        if not user or user not in self.baseline:
            return {
                'is_new_user': True,
                'has_baseline': False
            }

        baseline = self.baseline[user]
        deviations = []

        # Check IP
        ip = event.get('ip_address')
        if ip and ip not in baseline.get('ips', []):
            deviations.append('new_ip_address')

        # Check region
        network_info = event.get('network_info', {})
        region = network_info.get('region_code')
        if region and region not in baseline.get('regions', []):
            deviations.append('new_geographic_region')

        return {
            'has_baseline': True,
            'baseline_login_count': baseline.get('total_logins', 0),
            'baseline_known_ips': len(baseline.get('ips', [])),
            'baseline_known_regions': len(baseline.get('regions', [])),
            'deviations': deviations,
            'is_anomalous': len(deviations) > 0
        }


# Export all enrichers
__all__ = [
    'IPReputationEnricher',
    'GeolocationEnricher',
    'UserContextEnricher',
    'HistoricalBaselineTracker'
]
