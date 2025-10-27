"""
Configuration Loader for Business Context

Provides centralized access to business context configuration for both
tier-1 detections and tier-2 AI agents.

All configuration fields are OPTIONAL. The loader provides sensible defaults
for any missing values, so the system works even with minimal configuration.

Usage (Tier 1 - Detection Parameters):
    from config.config_loader import get_tier1_config

    config = get_tier1_config()
    # Always returns a value, using defaults if not configured
    max_failed = config['failed_logins']['max_failed_attempts']
    business_hours = config['business_hours']

Usage (Tier 2 - AI Context):
    from config.config_loader import get_tier2_context

    context = get_tier2_context()
    # Returns configured values or empty dicts for optional sections
    org_profile = context['organization']
    workforce_info = context.get('workforce', {})
"""

import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path
from copy import deepcopy


class BusinessContextConfig:
    """Singleton configuration loader for business context with optional fields and defaults."""

    _instance = None
    _config = None

    # Default values for tier-1 parameters
    TIER1_DEFAULTS = {
        'business_hours': {
            'primary_timezone': 'UTC',
            'weekday_start': '08:00',
            'weekday_end': '18:00',
            'weekend_start': None,
            'weekend_end': None,
            'additional_timezones': {},
            'holidays': []
        },
        'geographic': {
            'expected_countries': [],
            'expected_cities': [],
            'office_ip_ranges': [],
            'vpn_ip_ranges': []
        },
        'failed_logins': {
            'max_failed_attempts': 5,
            'time_window_minutes': 30,
            'min_safe_ip_reputation': 50
        },
        'password_spray': {
            'min_unique_users': 5,
            'time_window_minutes': 60,
            'min_attempts_per_user': 1
        },
        'credential_stuffing': {
            'min_failures_from_ip': 3,
            'min_unique_users': 2,
            'time_window_minutes': 30
        },
        'rapid_access': {
            'max_attempts': 10,
            'time_window_minutes': 5
        },
        'mfa_fatigue': {
            'min_challenges': 5,
            'time_window_minutes': 30,
            'flag_eventual_success': True
        },
        'session_anomalies': {
            'flag_concurrent_ips': True,
            'flag_rapid_location_change': True,
            'min_session_duration': 300
        }
    }

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(BusinessContextConfig, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self):
        """Load configuration from YAML file, using defaults for missing values."""
        # Determine config file path
        config_dir = Path(__file__).parent
        config_file = config_dir / 'business_context.yaml'

        if not config_file.exists():
            raise FileNotFoundError(
                f"Business context configuration not found: {config_file}\n"
                f"Please create {config_file} based on the template."
            )

        with open(config_file, 'r', encoding='utf-8') as f:
            user_config = yaml.safe_load(f) or {}

        # Initialize with empty structure
        self._config = {
            'tier1_parameters': {},
            'tier2_context': {}
        }

        # Merge user config with defaults for tier1_parameters
        user_tier1 = user_config.get('tier1_parameters', {})
        for key, default_value in self.TIER1_DEFAULTS.items():
            if key in user_tier1 and user_tier1[key] is not None:
                # Merge user config with defaults (for nested dicts)
                if isinstance(default_value, dict):
                    self._config['tier1_parameters'][key] = {**default_value, **user_tier1[key]}
                else:
                    self._config['tier1_parameters'][key] = user_tier1[key]
            else:
                # Use default
                self._config['tier1_parameters'][key] = deepcopy(default_value)

        # For tier2_context, just pass through what's configured (all optional)
        self._config['tier2_context'] = user_config.get('tier2_context', {})

    def get_tier1_parameters(self) -> Dict[str, Any]:
        """
        Get tier-1 detection parameters.

        Returns:
            Dictionary containing all tier-1 detection thresholds and patterns
        """
        return self._config['tier1_parameters']

    def get_tier2_context(self) -> Dict[str, Any]:
        """
        Get tier-2 AI agent context.

        Returns:
            Dictionary containing rich business context for AI analysis
        """
        return self._config['tier2_context']

    def get_business_hours(self) -> Dict[str, Any]:
        """Get business hours configuration (always returns a value with defaults)."""
        return self._config['tier1_parameters']['business_hours']

    def get_geographic_config(self) -> Dict[str, Any]:
        """Get geographic access configuration (always returns a value with defaults)."""
        return self._config['tier1_parameters']['geographic']

    def get_detection_threshold(self, detection_type: str) -> Dict[str, Any]:
        """
        Get thresholds for a specific detection type.

        Args:
            detection_type: Name of detection (e.g., 'failed_logins', 'password_spray')

        Returns:
            Dictionary of thresholds (uses defaults if not configured)
        """
        return self._config['tier1_parameters'].get(detection_type, {})

    def get_organization_profile(self) -> Dict[str, Any]:
        """Get organization profile for tier-2 context (returns empty dict if not configured)."""
        return self._config['tier2_context'].get('organization', {})

    def get_workforce_context(self) -> Dict[str, Any]:
        """Get workforce characteristics for tier-2 context (returns empty dict if not configured)."""
        return self._config['tier2_context'].get('workforce', {})

    def get_user_role_context(self, role: Optional[str] = None) -> Dict[str, Any]:
        """
        Get user role context.

        Args:
            role: Specific role to retrieve (e.g., 'executives', 'engineers').
                  If None, returns all roles.

        Returns:
            Role-specific context or all roles (empty dict if not configured)
        """
        roles = self._config['tier2_context'].get('user_roles', {})
        if role:
            return roles.get(role, {})
        return roles

    def format_tier2_context_for_agent(self) -> str:
        """
        Format tier-2 context as a string for inclusion in AI agent prompts.

        Only includes sections that have been configured. Returns minimal
        context if nothing is configured.

        Returns:
            Formatted markdown string with business context
        """
        context = self.get_tier2_context()

        if not context:
            return "# BUSINESS CONTEXT\n\nNo additional business context configured."

        output = []
        output.append("# BUSINESS CONTEXT\n")

        # Organization (optional)
        org = context.get('organization', {})
        if org:
            output.append(f"## Organization: {org.get('name', 'Not Specified')}")
            if 'industry' in org or 'size' in org:
                parts = []
                if 'industry' in org:
                    parts.append(f"Industry: {org['industry']}")
                if 'size' in org:
                    parts.append(f"Size: {org['size']}")
                output.append(' | '.join(parts))
            if 'description' in org:
                output.append(f"{org['description']}\n")

        # Workforce (optional)
        workforce = context.get('workforce', {})
        if workforce:
            output.append(f"## Workforce Profile")
            if 'remote_work_policy' in workforce:
                output.append(f"Remote Work Policy: {workforce['remote_work_policy']}")

            if 'workforce_distribution' in workforce:
                output.append(f"\n**Distribution:**")
                for category, percentage in workforce['workforce_distribution'].items():
                    output.append(f"- {category.replace('_', ' ').title()}: {percentage}%")

            if 'common_patterns' in workforce:
                output.append(f"\n**Common Access Patterns:**")
                for pattern in workforce['common_patterns']:
                    output.append(f"- {pattern}")

            if 'legitimate_edge_cases' in workforce:
                output.append(f"\n**Legitimate Edge Cases:**")
                for case in workforce['legitimate_edge_cases']:
                    output.append(f"- {case}")

        # Technology (optional)
        tech = context.get('technology', {})
        if tech and 'security_posture' in tech:
            output.append(f"\n## Security Posture")
            posture = tech['security_posture']
            if 'mfa_required' in posture:
                output.append(f"MFA Required: {posture['mfa_required']}")
            if 'mfa_enforcement' in posture:
                output.append(f"MFA Enforcement: {posture['mfa_enforcement']}")
            if 'session_timeout_minutes' in posture:
                output.append(f"Session Timeout: {posture['session_timeout_minutes']} minutes")

        # User Roles (optional)
        user_roles = context.get('user_roles', {})
        if user_roles:
            output.append(f"\n## User Role Expectations")
            for role, details in user_roles.items():
                output.append(f"\n**{role.title()}:**")
                if 'travel_frequency' in details:
                    output.append(f"- Travel: {details['travel_frequency']}")
                if 'international_access' in details:
                    output.append(f"- International Access: {details['international_access']}")
                if 'off_hours_access' in details:
                    output.append(f"- Off-Hours: {details['off_hours_access']}")
                if 'notes' in details:
                    output.append(f"- Notes: {details['notes']}")

        # Threat Context (optional)
        threat = context.get('threat_context', {})
        if threat and 'known_threats' in threat:
            output.append(f"\n## Known Threats")
            for threat_item in threat['known_threats']:
                output.append(f"- {threat_item}")

        # Risk Profile (optional)
        risk = context.get('risk_profile', {})
        if risk:
            if 'risk_tolerance' in risk:
                output.append(f"\n## Risk Tolerance: {risk['risk_tolerance']}")
            if 'false_positive_tolerance' in risk:
                output.append(f"False Positive Tolerance: {risk['false_positive_tolerance']}")

        return '\n'.join(output) if output else "# BUSINESS CONTEXT\n\nNo additional business context configured."


# Convenience functions for quick access
_config_instance = None

def get_config() -> BusinessContextConfig:
    """Get the singleton configuration instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = BusinessContextConfig()
    return _config_instance


def get_tier1_config() -> Dict[str, Any]:
    """Get tier-1 detection parameters."""
    return get_config().get_tier1_parameters()


def get_tier2_context() -> Dict[str, Any]:
    """Get tier-2 AI agent context."""
    return get_config().get_tier2_context()


def get_business_hours() -> Dict[str, Any]:
    """Get business hours configuration."""
    return get_config().get_business_hours()


def get_geographic_config() -> Dict[str, Any]:
    """Get geographic access patterns."""
    return get_config().get_geographic_config()


def get_detection_threshold(detection_type: str) -> Optional[Dict[str, Any]]:
    """Get thresholds for specific detection type."""
    return get_config().get_detection_threshold(detection_type)


def format_context_for_agent() -> str:
    """Format tier-2 context for AI agent prompts."""
    return get_config().format_tier2_context_for_agent()


# Export all public functions
__all__ = [
    'BusinessContextConfig',
    'get_config',
    'get_tier1_config',
    'get_tier2_context',
    'get_business_hours',
    'get_geographic_config',
    'get_detection_threshold',
    'format_context_for_agent'
]
