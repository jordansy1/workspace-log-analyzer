"""
Configuration Module

Provides access to business context configuration for threat detection and analysis.
"""

from config.config_loader import (
    get_config,
    get_tier1_config,
    get_tier2_context,
    get_business_hours,
    get_geographic_config,
    get_detection_threshold,
    format_context_for_agent
)

from config.timezone_mapper import (
    normalize_timezone,
    get_timezone_object,
    validate_timezone_config
)

__all__ = [
    'get_config',
    'get_tier1_config',
    'get_tier2_context',
    'get_business_hours',
    'get_geographic_config',
    'get_detection_threshold',
    'format_context_for_agent',
    'normalize_timezone',
    'get_timezone_object',
    'validate_timezone_config'
]
