"""
Timezone Normalization Utility

Handles various timezone naming conventions and normalizes them to IANA/Olson format
that pytz can understand. This prevents issues when log data uses different timezone
formats than the configuration file.

Supported Input Formats:
- IANA/Olson: "America/New_York", "Europe/London", "Asia/Tokyo"
- Windows: "Eastern Standard Time", "Pacific Standard Time"
- Abbreviations: "EST", "PST", "GMT" (with ambiguity warnings)
- UTC Offsets: "UTC-5", "-05:00", "+00:00"
- Legacy: "US/Eastern", "US/Pacific"
"""

import pytz
from typing import Optional
from datetime import datetime


# Mapping of Windows timezone names to IANA names
WINDOWS_TO_IANA = {
    # US Timezones
    "Eastern Standard Time": "America/New_York",
    "Central Standard Time": "America/Chicago",
    "Mountain Standard Time": "America/Denver",
    "Pacific Standard Time": "America/Los_Angeles",
    "Alaskan Standard Time": "America/Anchorage",
    "Hawaiian Standard Time": "Pacific/Honolulu",
    "US Mountain Standard Time": "America/Phoenix",  # Arizona (no DST)

    # European Timezones
    "GMT Standard Time": "Europe/London",
    "W. Europe Standard Time": "Europe/Berlin",
    "Central Europe Standard Time": "Europe/Warsaw",
    "Romance Standard Time": "Europe/Paris",
    "Central European Standard Time": "Europe/Belgrade",
    "E. Europe Standard Time": "Europe/Bucharest",
    "FLE Standard Time": "Europe/Helsinki",

    # Asian Timezones
    "India Standard Time": "Asia/Kolkata",
    "China Standard Time": "Asia/Shanghai",
    "Tokyo Standard Time": "Asia/Tokyo",
    "Korea Standard Time": "Asia/Seoul",
    "Singapore Standard Time": "Asia/Singapore",
    "SE Asia Standard Time": "Asia/Bangkok",

    # Australian Timezones
    "AUS Eastern Standard Time": "Australia/Sydney",
    "AUS Central Standard Time": "Australia/Darwin",
    "W. Australia Standard Time": "Australia/Perth",

    # Other Common Timezones
    "UTC": "UTC",
    "Greenwich Standard Time": "UTC",
}


# Mapping of common abbreviations to IANA names
# WARNING: Many abbreviations are ambiguous (e.g., CST = Central/China/Cuba)
ABBREV_TO_IANA = {
    # US (Note: EST/EDT, PST/PDT handled separately based on DST)
    "EST": "America/New_York",
    "EDT": "America/New_York",
    "CST": "America/Chicago",  # Ambiguous: also China, Cuba
    "CDT": "America/Chicago",
    "MST": "America/Denver",
    "MDT": "America/Denver",
    "PST": "America/Los_Angeles",
    "PDT": "America/Los_Angeles",
    "AKST": "America/Anchorage",
    "AKDT": "America/Anchorage",
    "HST": "Pacific/Honolulu",

    # European
    "GMT": "Europe/London",
    "BST": "Europe/London",
    "CET": "Europe/Paris",
    "CEST": "Europe/Paris",
    "EET": "Europe/Athens",
    "EEST": "Europe/Athens",
    "WET": "Europe/Lisbon",
    "WEST": "Europe/Lisbon",

    # Asian
    "IST": "Asia/Kolkata",  # Ambiguous: also Israel, Irish
    "JST": "Asia/Tokyo",
    "KST": "Asia/Seoul",
    "SGT": "Asia/Singapore",

    # Universal
    "UTC": "UTC",
    "GMT+0": "UTC",
    "Z": "UTC",
}


# Legacy IANA names that should be mapped to current names
LEGACY_TO_CURRENT = {
    "US/Eastern": "America/New_York",
    "US/Central": "America/Chicago",
    "US/Mountain": "America/Denver",
    "US/Pacific": "America/Los_Angeles",
    "US/Alaska": "America/Anchorage",
    "US/Hawaii": "Pacific/Honolulu",
}


def normalize_timezone(timezone_str: Optional[str], fallback: str = "UTC") -> str:
    """
    Normalize various timezone formats to IANA/Olson format.

    Args:
        timezone_str: Timezone string in any supported format
        fallback: Fallback timezone if normalization fails (default: "UTC")

    Returns:
        IANA timezone name that pytz can parse

    Examples:
        >>> normalize_timezone("Eastern Standard Time")
        "America/New_York"

        >>> normalize_timezone("EST")
        "America/New_York"

        >>> normalize_timezone("UTC-5")
        "America/New_York"  # Best guess based on offset
    """
    if not timezone_str:
        return fallback

    # Clean up input
    tz = timezone_str.strip()

    # 1. Check Windows timezone names (before IANA check, as they're more specific)
    if tz in WINDOWS_TO_IANA:
        return WINDOWS_TO_IANA[tz]

    # 2. Check legacy names (before IANA, as we want to redirect these)
    if tz in LEGACY_TO_CURRENT:
        return LEGACY_TO_CURRENT[tz]

    # 3. Check abbreviations (before IANA, as abbreviations like EST are valid but deprecated)
    tz_upper = tz.upper()
    if tz_upper in ABBREV_TO_IANA:
        # Log warning about ambiguous abbreviations
        if tz_upper in ["CST", "IST"]:
            # These are highly ambiguous
            pass  # Could add logging here
        return ABBREV_TO_IANA[tz_upper]

    # 4. Check if it's already a valid IANA timezone (prefer region-based like America/New_York)
    if _is_valid_iana_timezone(tz):
        return tz

    # 5. Try to parse UTC offset format (UTC-5, +05:00, etc.)
    iana_tz = _parse_utc_offset(tz)
    if iana_tz:
        return iana_tz

    # 6. Try case-insensitive IANA match
    iana_tz = _case_insensitive_iana_match(tz)
    if iana_tz:
        return iana_tz

    # 7. Give up, return fallback
    return fallback


def _is_valid_iana_timezone(tz_str: str) -> bool:
    """Check if string is a valid IANA timezone name."""
    try:
        pytz.timezone(tz_str)
        return True
    except pytz.UnknownTimeZoneError:
        return False


def _parse_utc_offset(offset_str: str) -> Optional[str]:
    """
    Parse UTC offset string and return best-guess IANA timezone.

    WARNING: Offsets don't account for DST and are ambiguous.
    Multiple cities share the same offset.

    Examples:
        "UTC-5" -> "America/New_York" (could also be Bogota, Lima, etc.)
        "+09:00" -> "Asia/Tokyo" (could also be Seoul)
    """
    import re

    # Match patterns: UTC-5, UTC+0, -05:00, +09:00
    pattern = r'UTC?([+-])(\d{1,2})(?::(\d{2}))?'
    match = re.match(pattern, offset_str, re.IGNORECASE)

    if not match:
        # Try without UTC prefix: -05:00, +09:00
        pattern = r'([+-])(\d{1,2})(?::(\d{2}))?'
        match = re.match(pattern, offset_str)

    if not match:
        return None

    sign = match.group(1)
    hours = int(match.group(2))
    minutes = int(match.group(3)) if match.group(3) else 0

    # Calculate total offset in hours
    offset = hours + (minutes / 60.0)
    if sign == '-':
        offset = -offset

    # Map common offsets to IANA timezones (best guess)
    # NOTE: This is inherently ambiguous!
    offset_map = {
        -10.0: "Pacific/Honolulu",
        -9.0: "America/Anchorage",
        -8.0: "America/Los_Angeles",
        -7.0: "America/Denver",
        -6.0: "America/Chicago",
        -5.0: "America/New_York",
        -4.0: "America/Halifax",
        -3.0: "America/Sao_Paulo",
        0.0: "UTC",
        1.0: "Europe/London",
        2.0: "Europe/Paris",
        3.0: "Europe/Athens",
        5.5: "Asia/Kolkata",
        8.0: "Asia/Shanghai",
        9.0: "Asia/Tokyo",
        10.0: "Australia/Sydney",
        12.0: "Pacific/Auckland",
    }

    return offset_map.get(offset)


def _case_insensitive_iana_match(tz_str: str) -> Optional[str]:
    """Try to match timezone case-insensitively against all IANA zones."""
    tz_lower = tz_str.lower()

    for iana_tz in pytz.all_timezones:
        if iana_tz.lower() == tz_lower:
            return iana_tz

    return None


def get_timezone_object(timezone_str: Optional[str], fallback: str = "UTC") -> pytz.tzinfo.BaseTzInfo:
    """
    Get a pytz timezone object, handling various input formats.

    Args:
        timezone_str: Timezone in any supported format
        fallback: Fallback timezone if parsing fails

    Returns:
        pytz timezone object
    """
    iana_name = normalize_timezone(timezone_str, fallback)
    return pytz.timezone(iana_name)


# Helper for config validation
def validate_timezone_config(config_timezones: list[str]) -> dict[str, str]:
    """
    Validate timezone configuration and return any issues.

    Args:
        config_timezones: List of timezone strings from config

    Returns:
        Dictionary mapping timezone to issue description (empty if all valid)
    """
    issues = {}

    for tz in config_timezones:
        if not _is_valid_iana_timezone(tz):
            issues[tz] = f"Not a valid IANA timezone. Did you mean: {normalize_timezone(tz)}?"

    return issues


# Export
__all__ = [
    'normalize_timezone',
    'get_timezone_object',
    'validate_timezone_config',
    'WINDOWS_TO_IANA',
    'ABBREV_TO_IANA',
]
