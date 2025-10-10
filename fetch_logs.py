"""
Google Workspace Authentication Log Fetcher

This module handles authentication with Google Workspace Admin SDK
and retrieves login activity logs for analysis.
"""

import os
import json
from datetime import datetime, timedelta
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Scopes required for accessing Admin SDK (Reports + Directory APIs)
SCOPES = [
    'https://www.googleapis.com/auth/admin.reports.audit.readonly',
    'https://www.googleapis.com/auth/admin.directory.user.readonly',
    'https://www.googleapis.com/auth/admin.directory.device.mobile.readonly'
]


class WorkspaceLogFetcher:
    """Handles fetching authentication logs from Google Workspace."""

    def __init__(self, credentials_file='credentials.json', token_file='token.json', enable_enrichment=True):
        """
        Initialize the log fetcher.

        Args:
            credentials_file: Path to OAuth 2.0 client credentials JSON
            token_file: Path to store/load access tokens
            enable_enrichment: Whether to enrich logs with contextual data
        """
        self.credentials_file = credentials_file
        self.token_file = token_file
        self.creds = None
        self.service = None
        self.enable_enrichment = enable_enrichment

        # Initialize enrichers if enabled
        if self.enable_enrichment:
            from enrichment import (
                IPReputationEnricher,
                GeolocationEnricher,
                UserContextEnricher,
                HistoricalBaselineTracker
            )
            self.ip_enricher = IPReputationEnricher()
            self.geo_enricher = GeolocationEnricher()
            self.user_enricher = UserContextEnricher(credentials_file, token_file)
            self.baseline_tracker = HistoricalBaselineTracker()
        else:
            self.ip_enricher = None
            self.geo_enricher = None
            self.user_enricher = None
            self.baseline_tracker = None

    def authenticate(self):
        """
        Authenticate with Google Workspace using OAuth 2.0.

        This will:
        1. Load existing token if available
        2. Refresh token if expired
        3. Initiate OAuth flow if no valid token exists
        """
        # Load existing token
        if os.path.exists(self.token_file):
            self.creds = Credentials.from_authorized_user_file(self.token_file, SCOPES)

        # If no valid credentials, get new ones
        if not self.creds or not self.creds.valid:
            if self.creds and self.creds.expired and self.creds.refresh_token:
                # Refresh expired token
                self.creds.refresh(Request())
            else:
                # Run OAuth flow
                if not os.path.exists(self.credentials_file):
                    raise FileNotFoundError(
                        f"Credentials file not found: {self.credentials_file}\n"
                        "Please download OAuth 2.0 credentials from Google Cloud Console."
                    )

                flow = InstalledAppFlow.from_client_secrets_file(
                    self.credentials_file, SCOPES
                )
                self.creds = flow.run_local_server(port=0)

            # Save credentials for next run
            with open(self.token_file, 'w') as token:
                token.write(self.creds.to_json())

        # Build the Admin SDK service
        self.service = build('admin', 'reports_v1', credentials=self.creds)
        print("[OK] Successfully authenticated with Google Workspace")

    def fetch_login_logs(self, hours_back=24, user_key='all', max_results=1000):
        """
        Fetch login activity logs from Google Workspace.

        Args:
            hours_back: Number of hours to look back for logs
            user_key: User identifier ('all' for all users, or specific email)
            max_results: Maximum number of results to return

        Returns:
            List of login activity events
        """
        if not self.service:
            raise RuntimeError("Not authenticated. Call authenticate() first.")

        # Calculate start time
        start_time = datetime.utcnow() - timedelta(hours=hours_back)
        start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%S.000Z')

        print(f"Fetching login logs from the last {hours_back} hours...")
        print(f"Start time: {start_time_str}")

        try:
            all_activities = []
            page_token = None

            while True:
                # Call the Admin SDK Reports API
                results = self.service.activities().list(
                    userKey=user_key,
                    applicationName='login',
                    startTime=start_time_str,
                    maxResults=max_results,
                    pageToken=page_token
                ).execute()

                activities = results.get('items', [])
                all_activities.extend(activities)

                # Check if there are more pages
                page_token = results.get('nextPageToken')
                if not page_token:
                    break

                print(f"  Retrieved {len(all_activities)} events so far...")

            print(f"[OK] Successfully fetched {len(all_activities)} login events")
            return all_activities

        except HttpError as error:
            print(f"[ERROR] Error fetching logs: {error}")
            raise

    def process_logs(self, raw_logs):
        """
        Process raw logs into a structured format for analysis.
        Captures all available fields from Google Workspace Admin SDK.

        Args:
            raw_logs: Raw log data from Google Workspace API

        Returns:
            Processed logs with all available fields extracted
        """
        processed = []

        for event in raw_logs:
            # Extract actor information
            actor = event.get('actor', {})

            # Extract network/location information
            network_info = event.get('networkInfo', {})

            # Build comprehensive event structure
            processed_event = {
                # Timestamp and identification
                'timestamp': event.get('id', {}).get('time'),
                'event_id': event.get('id', {}).get('applicationName'),
                'etag': event.get('etag'),
                'kind': event.get('kind'),

                # Actor (user) information
                'user_email': actor.get('email'),
                'user_profile_id': actor.get('profileId'),
                'caller_type': actor.get('callerType'),

                # Network and location data
                'ip_address': event.get('ipAddress'),
                'network_info': {
                    'ip_asn': network_info.get('ipAsn'),
                    'region_code': network_info.get('regionCode'),
                    'subdivision_code': network_info.get('subdivisionCode')
                } if network_info else None,

                # Domain and resource information
                'owner_domain': event.get('ownerDomain'),
                'resource_details': event.get('resourceDetails'),

                # Event details (to be populated from events array)
                'event_type': None,
                'event_name': None,
                'login_type': None,
                'is_suspicious': False,
                'login_challenge_method': None,
                'login_challenge_status': None,
                'is_second_factor': None,
                'affected_email_address': None,
                'login_failure_type': None,
                'sensitive_action_name': None,
                'login_timestamp': None,

                # All parameters (raw)
                'parameters': {}
            }

            # Extract event details from parameters
            for evt in event.get('events', []):
                processed_event['event_type'] = evt.get('type')
                processed_event['event_name'] = evt.get('name')

                # Parse all parameters
                for param in evt.get('parameters', []):
                    param_name = param.get('name')
                    param_value = param.get('value')

                    # Map known parameters to top-level fields for easier access
                    if param_name == 'login_type':
                        processed_event['login_type'] = param_value
                    elif param_name == 'is_suspicious':
                        processed_event['is_suspicious'] = param_value == 'true'
                    elif param_name == 'login_challenge_method':
                        processed_event['login_challenge_method'] = param_value
                    elif param_name == 'login_challenge_status':
                        processed_event['login_challenge_status'] = param_value
                    elif param_name == 'is_second_factor':
                        processed_event['is_second_factor'] = param_value == 'true'
                    elif param_name == 'affected_email_address':
                        processed_event['affected_email_address'] = param_value
                    elif param_name == 'login_failure_type':
                        processed_event['login_failure_type'] = param_value
                    elif param_name == 'sensitive_action_name':
                        processed_event['sensitive_action_name'] = param_value
                    elif param_name == 'login_timestamp':
                        processed_event['login_timestamp'] = param_value

                    # Store all parameters for comprehensive analysis
                    processed_event['parameters'][param_name] = param_value

            processed.append(processed_event)

        # Enrich logs if enabled
        if self.enable_enrichment:
            processed = self._enrich_logs(processed)

        return processed

    def _enrich_logs(self, logs):
        """
        Enrich logs with contextual data from multiple sources.

        Args:
            logs: Processed log events

        Returns:
            Enriched logs
        """
        print("\n[Enrichment] Adding contextual data...")

        # Track unique IPs and users for batch processing
        unique_ips = set()
        unique_users = set()

        for log in logs:
            if log.get('ip_address'):
                unique_ips.add(log['ip_address'])
            if log.get('user_email'):
                unique_users.add(log['user_email'])

        print(f"  Enriching {len(unique_ips)} unique IPs and {len(unique_users)} unique users...")

        # Batch enrich IPs
        ip_cache = {}
        for i, ip in enumerate(unique_ips, 1):
            print(f"  [{i}/{len(unique_ips)}] Enriching IP: {ip}")

            # IP Reputation
            if self.ip_enricher and self.ip_enricher.enabled:
                ip_cache[f"{ip}_reputation"] = self.ip_enricher.enrich_ip(ip)

            # Geolocation
            if self.geo_enricher and self.geo_enricher.enabled:
                ip_cache[f"{ip}_geo"] = self.geo_enricher.enrich_location(ip)

        # Batch enrich users
        user_cache = {}
        for i, user in enumerate(unique_users, 1):
            print(f"  [{i}/{len(unique_users)}] Enriching user: {user}")

            if self.user_enricher and self.user_enricher.enabled:
                user_cache[user] = self.user_enricher.enrich_user(user)

        # Apply enrichments to each log
        enriched_logs = []
        for log in logs:
            enriched_log = log.copy()

            # Add IP enrichment
            ip = log.get('ip_address')
            if ip:
                enriched_log['ip_reputation'] = ip_cache.get(f"{ip}_reputation")
                enriched_log['enriched_location'] = ip_cache.get(f"{ip}_geo")

            # Add user enrichment
            user = log.get('user_email')
            if user:
                enriched_log['user_context'] = user_cache.get(user)

            # Add baseline comparison
            if self.baseline_tracker and self.baseline_tracker.enabled:
                enriched_log['baseline_comparison'] = self.baseline_tracker.check_against_baseline(log)

            enriched_logs.append(enriched_log)

        # Update baseline with new events
        if self.baseline_tracker and self.baseline_tracker.enabled:
            self.baseline_tracker.update_baseline(logs)

        print("[OK] Enrichment complete")
        return enriched_logs

    def save_logs(self, logs, output_dir='logs', hours_back=None):
        """
        Save logs to JSON file with timestamp.

        Args:
            logs: Processed log data
            output_dir: Directory to save logs
            hours_back: Number of hours that were requested in the fetch

        Returns:
            Path to saved file
        """
        os.makedirs(output_dir, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"auth_logs_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)

        # Gather summary statistics
        unique_users = set()
        unique_ips = set()
        unique_regions = set()
        event_types = {}
        timestamps = []

        for log in logs:
            if log.get('user_email'):
                unique_users.add(log['user_email'])
            if log.get('ip_address'):
                unique_ips.add(log['ip_address'])
            if log.get('network_info') and log['network_info'].get('region_code'):
                unique_regions.add(log['network_info']['region_code'])
            if log.get('timestamp'):
                timestamps.append(log['timestamp'])

            event_name = log.get('event_name', 'unknown')
            event_types[event_name] = event_types.get(event_name, 0) + 1

        # Calculate actual time range from event timestamps
        actual_time_range_info = {}
        if timestamps:
            from dateutil import parser
            parsed_times = [parser.isoparse(ts) for ts in timestamps]
            earliest = min(parsed_times)
            latest = max(parsed_times)
            time_span = (latest - earliest).total_seconds() / 3600  # hours

            actual_time_range_info = {
                'earliest_event': earliest.isoformat(),
                'latest_event': latest.isoformat(),
                'actual_span_hours': round(time_span, 2)
            }

        with open(filepath, 'w') as f:
            json.dump({
                'metadata': {
                    'fetch_time': datetime.now().isoformat(),
                    'total_events': len(logs),
                    'requested_time_range_hours': hours_back,
                    'actual_time_range': actual_time_range_info,
                    'api_version': 'reports_v1',
                    'data_schema_version': '2.1',  # Updated with enhanced time tracking
                    'summary': {
                        'unique_users': len(unique_users),
                        'unique_ips': len(unique_ips),
                        'unique_regions': len(unique_regions),
                        'event_type_breakdown': event_types
                    },
                    'captured_fields': [
                        'timestamp', 'event_id', 'etag', 'kind',
                        'user_email', 'user_profile_id', 'caller_type',
                        'ip_address', 'network_info (ip_asn, region_code, subdivision_code)',
                        'owner_domain', 'resource_details',
                        'event_type', 'event_name', 'login_type', 'is_suspicious',
                        'login_challenge_method', 'login_challenge_status',
                        'is_second_factor', 'affected_email_address',
                        'login_failure_type', 'sensitive_action_name',
                        'login_timestamp', 'parameters (all)'
                    ]
                },
                'events': logs
            }, f, indent=2)

        print(f"[OK] Logs saved to: {filepath}")
        return filepath
