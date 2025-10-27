# Timezone Compatibility Guide

## The Problem

Different systems use different timezone naming conventions, which can cause mismatches between:
- **Your configuration** (typically uses IANA names like `America/New_York`)
- **Log data** (may use Windows names, abbreviations, or offsets)

This can lead to:
- ❌ Failed timezone parsing → falls back to UTC
- ❌ Incorrect off-hours detection
- ❌ Mismatched timezone comparisons

## Supported Timezone Formats

The `timezone_mapper` module automatically normalizes all these formats to IANA standard:

### 1. IANA/Olson Names (Preferred) ✓

```
America/New_York
Europe/London
Asia/Tokyo
America/Los_Angeles
```

**Why preferred:** Unambiguous, handles DST automatically, widely supported

### 2. Windows Timezone Names

```
Eastern Standard Time      → America/New_York
Pacific Standard Time      → America/Los_Angeles
GMT Standard Time          → Europe/London
India Standard Time        → Asia/Kolkata
China Standard Time        → Asia/Shanghai
```

**Common in:** Windows systems, Microsoft services, some enterprise software

### 3. Abbreviations

```
EST / EDT                  → America/New_York
PST / PDT                  → America/Los_Angeles
GMT / BST                  → Europe/London
JST                        → Asia/Tokyo
```

**⚠️ Warning:** Some abbreviations are ambiguous:
- `CST` could be Central (US), China, or Cuba
- `IST` could be India, Israel, or Irish

### 4. UTC Offsets

```
UTC-5                      → America/New_York (best guess)
+09:00                     → Asia/Tokyo (best guess)
-08:00                     → America/Los_Angeles (best guess)
```

**⚠️ Warning:**
- Offsets don't account for DST
- Multiple cities share the same offset
- Mapping is a "best guess"

### 5. Legacy IANA Names

```
US/Eastern                 → America/New_York
US/Pacific                 → America/Los_Angeles
US/Central                 → America/Chicago
```

**Status:** Deprecated by IANA, but still supported

### 6. Case Variations

```
america/new_york           → America/New_York (matched case-insensitively)
EUROPE/LONDON             → Europe/London
```

## Usage Examples

### In Configuration

Use **IANA names** in your config file for clarity:

```yaml
# config/business_context.yaml
tier1_parameters:
  business_hours:
    primary_timezone: "America/New_York"  # ✓ IANA format

    additional_timezones:
      "America/Los_Angeles":              # ✓ IANA format
        weekday_start: "08:00"
        weekday_end: "18:00"
```

### In Detection Scripts

Normalize log data before using:

```python
from config.timezone_mapper import normalize_timezone, get_timezone_object

# Log data might have any format
log_timezone = event.get('enriched_location', {}).get('timezone')
# Could be: "Eastern Standard Time", "EST", "UTC-5", etc.

# Normalize to IANA
iana_timezone = normalize_timezone(log_timezone, fallback="UTC")
# Result: "America/New_York"

# Get pytz object (handles normalization automatically)
tz_object = get_timezone_object(log_timezone, fallback="UTC")
local_time = timestamp.astimezone(tz_object)
```

## Common Scenarios

### Scenario 1: Google Workspace Returns Windows Names

**Problem:**
```python
# Config uses:
primary_timezone: "America/New_York"

# Google API returns:
enriched_location.timezone: "Eastern Standard Time"

# Direct comparison fails
if detected_tz == config['primary_timezone']:  # ❌ False!
```

**Solution:**
```python
# Both get normalized to same IANA name
detected_iana = normalize_timezone("Eastern Standard Time")  # "America/New_York"
config_iana = normalize_timezone(config['primary_timezone']) # "America/New_York"

if detected_iana == config_iana:  # ✓ True!
```

### Scenario 2: Logs Use Abbreviations

**Problem:**
```python
# Trying to create pytz timezone from abbreviation
import pytz
tz = pytz.timezone("EST")  # ⚠️ Deprecated, may not work as expected
```

**Solution:**
```python
from config.timezone_mapper import get_timezone_object

# Handles abbreviation → IANA conversion
tz = get_timezone_object("EST")  # Returns America/New_York timezone
```

### Scenario 3: Mixed Format Data

**Problem:**
```python
# Different events have different formats
events = [
    {"timezone": "America/New_York"},
    {"timezone": "Eastern Standard Time"},
    {"timezone": "EST"},
    {"timezone": "UTC-5"},
]

# Need consistent handling
```

**Solution:**
```python
from config.timezone_mapper import normalize_timezone

# All normalize to the same IANA name
for event in events:
    iana_tz = normalize_timezone(event['timezone'])
    # All return: "America/New_York"
```

## Validation

### Validate Your Config

Check if your configured timezones are valid IANA names:

```python
from config import get_business_hours
from config.timezone_mapper import validate_timezone_config

hours_config = get_business_hours()

# Collect all timezones from config
timezones = [hours_config['primary_timezone']]
timezones.extend(hours_config.get('additional_timezones', {}).keys())

# Validate
issues = validate_timezone_config(timezones)

if issues:
    for tz, issue in issues.items():
        print(f"⚠️ {tz}: {issue}")
else:
    print("✓ All configured timezones are valid")
```

### Example Output

```
⚠️ Eastern Standard Time: Not a valid IANA timezone. Did you mean: America/New_York?
⚠️ EST: Not a valid IANA timezone. Did you mean: America/New_York?
```

## Best Practices

### ✅ DO:

1. **Use IANA names in configuration**
   ```yaml
   primary_timezone: "America/New_York"  # ✓
   ```

2. **Normalize all log data**
   ```python
   iana_tz = normalize_timezone(log_data_tz)
   ```

3. **Use `get_timezone_object()` instead of `pytz.timezone()` directly**
   ```python
   tz = get_timezone_object(timezone_str)  # ✓ Handles normalization
   ```

4. **Provide fallback timezones**
   ```python
   tz = normalize_timezone(uncertain_value, fallback="UTC")
   ```

### ❌ DON'T:

1. **Don't use abbreviations in config**
   ```yaml
   primary_timezone: "EST"  # ❌ Ambiguous, use "America/New_York"
   ```

2. **Don't assume log data format**
   ```python
   tz = pytz.timezone(log_tz)  # ❌ May fail if log uses Windows names
   ```

3. **Don't use offsets in config**
   ```yaml
   primary_timezone: "UTC-5"  # ❌ Doesn't handle DST
   ```

4. **Don't ignore normalization errors silently**
   ```python
   # ❌ Bad
   tz = normalize_timezone(value) or "UTC"

   # ✓ Good - fallback is explicit
   tz = normalize_timezone(value, fallback="UTC")
   ```

## Mapping Reference

### US Timezones

| Windows Name | Abbreviation | Offset | IANA Name |
|--------------|--------------|--------|-----------|
| Eastern Standard Time | EST/EDT | UTC-5/-4 | America/New_York |
| Central Standard Time | CST/CDT | UTC-6/-5 | America/Chicago |
| Mountain Standard Time | MST/MDT | UTC-7/-6 | America/Denver |
| Pacific Standard Time | PST/PDT | UTC-8/-7 | America/Los_Angeles |
| Alaskan Standard Time | AKST/AKDT | UTC-9/-8 | America/Anchorage |
| Hawaiian Standard Time | HST | UTC-10 | Pacific/Honolulu |

### European Timezones

| Windows Name | Abbreviation | Offset | IANA Name |
|--------------|--------------|--------|-----------|
| GMT Standard Time | GMT/BST | UTC+0/+1 | Europe/London |
| W. Europe Standard Time | CET/CEST | UTC+1/+2 | Europe/Berlin |
| Romance Standard Time | CET/CEST | UTC+1/+2 | Europe/Paris |

### Asian Timezones

| Windows Name | Abbreviation | Offset | IANA Name |
|--------------|--------------|--------|-----------|
| India Standard Time | IST | UTC+5:30 | Asia/Kolkata |
| China Standard Time | CST | UTC+8 | Asia/Shanghai |
| Tokyo Standard Time | JST | UTC+9 | Asia/Tokyo |
| Singapore Standard Time | SGT | UTC+8 | Asia/Singapore |

## Testing Your Setup

Run this test to verify timezone handling:

```python
from config.timezone_mapper import normalize_timezone

test_cases = {
    "America/New_York": "America/New_York",
    "Eastern Standard Time": "America/New_York",
    "EST": "America/New_York",
    "UTC-5": "America/New_York",
    "US/Eastern": "America/New_York",
}

print("Timezone Normalization Test:")
for input_tz, expected in test_cases.items():
    result = normalize_timezone(input_tz)
    status = "✓" if result == expected else "✗"
    print(f"{status} {input_tz:30s} -> {result}")
```

## Troubleshooting

### Issue: "UnknownTimeZoneError"

**Cause:** Trying to use non-IANA timezone directly with pytz

**Fix:** Use `normalize_timezone()` first
```python
# Before (fails):
tz = pytz.timezone("Eastern Standard Time")  # ✗

# After (works):
from config.timezone_mapper import get_timezone_object
tz = get_timezone_object("Eastern Standard Time")  # ✓
```

### Issue: "Timezone doesn't match config"

**Cause:** Log data uses different format than config

**Fix:** Normalize both before comparing
```python
from config.timezone_mapper import normalize_timezone

config_tz = normalize_timezone(config['primary_timezone'])
log_tz = normalize_timezone(event['timezone'])

if config_tz == log_tz:  # Now compares IANA to IANA
    # Match!
```

### Issue: "Wrong timezone selected for abbreviation"

**Cause:** Abbreviation is ambiguous (e.g., CST = Central/China/Cuba)

**Fix:** Update your configuration to be more specific, or add mapping:
```python
# If you know your logs use "CST" for China, not Central:
# Modify ABBREV_TO_IANA mapping in timezone_mapper.py
```

---

**See Also:**
- [Configuration README](README.md) - Main configuration documentation
- [business_context.yaml](business_context.yaml) - Configuration file
- [timezone_mapper.py](timezone_mapper.py) - Source code
