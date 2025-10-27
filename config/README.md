# Business Context Configuration

This directory contains configuration files that define "normal" business behavior patterns for your organization. These configurations help both **tier-1 detections** (deterministic pattern matching) and **tier-2 AI agents** (forensic analysis) distinguish between legitimate activity and potential threats.

**All configuration fields are OPTIONAL.** The system works out-of-the-box with sensible defaults. Add only the parameters relevant to your environment.

## Quick Start

1. **System works immediately** with minimal configuration (just basic business hours)
2. **Add parameters as needed** - only configure what's relevant to your environment
3. **Tune over time** - as you learn about your organization, add more context
4. **See [business_context.yaml.example](business_context.yaml.example)** for all available options

### Philosophy: Progressive Configuration

```
Minimal Config → Basic Detection → Add Context as Needed → Better Accuracy
```

You don't need to fill out everything. Start small, and expand when you encounter false positives or want more accurate analysis.

## Configuration Files

### [business_context.yaml](business_context.yaml)

The main configuration file with two major sections.

**All fields are OPTIONAL** - the system provides sensible defaults:

| Category | Default Behavior |
|----------|------------------|
| **Business Hours** | 08:00-18:00 UTC, weekdays only |
| **Detection Thresholds** | Conservative values (e.g., 5 failed logins in 30 min) |
| **Geographic** | No restrictions (all countries allowed) |
| **Tier-2 Context** | Empty (agents work without it, but less accurately) |

#### 1. `tier1_parameters` - Detection Thresholds (Optional)

Used by deterministic detection scripts to decide when to flag anomalies.
**If not specified, reasonable defaults are used:**

- **`business_hours`**: Define normal operating hours across multiple timezones
  - Primary timezone and hours
  - Additional timezones for distributed teams
  - Holiday schedules
  - Weekend policies

- **`geographic`**: Expected locations and IP ranges
  - Expected countries and cities
  - Office IP ranges (CIDR notation)
  - VPN/proxy IP ranges

- **`failed_logins`**: Thresholds for failed login detection
- **`password_spray`**: Minimum users/attempts to flag as spray attack
- **`credential_stuffing`**: Thresholds for credential stuffing detection
- **`rapid_access`**: Maximum attempts in time window
- **`mfa_fatigue`**: MFA bombing/fatigue attack thresholds
- **`session_anomalies`**: Session hijacking indicators

#### 2. `tier2_context` - Business Intelligence for AI Agents

Rich contextual information that helps AI agents assess risk:

- **`organization`**: Industry, size, description
- **`workforce`**: Remote work policy, distribution, common patterns
- **`technology`**: MFA enforcement, security posture, integrations
- **`user_roles`**: Expected behavior by role (executives, engineers, sales, etc.)
- **`threat_context`**: Known threats, past incidents, active campaigns
- **`risk_profile`**: Risk tolerance, severity guidance, compliance requirements
- **`seasonal_patterns`**: Expected changes throughout the year

## Usage Examples

### Tier 1: Detection Scripts

Detection scripts automatically load and use configuration:

```python
from config import get_business_hours, get_detection_threshold

# Load business hours
hours_config = get_business_hours()
primary_tz = hours_config['primary_timezone']
weekday_start = hours_config['weekday_start']
weekday_end = hours_config['weekday_end']

# Load specific detection thresholds
failed_login_config = get_detection_threshold('failed_logins')
max_attempts = failed_login_config['max_failed_attempts']
```

**Example detections using config:**
- [M1036_off_hours_access_detection.py](../tier1_detection/detection_methods/M1036_off_hours_access_detection.py) - Uses business hours and timezones

### Tier 2: AI Agents

The `AgentRouter` automatically includes business context when calling agents:

```python
# In tier2_analysis/agent_router.py
from config import format_context_for_agent

# Business context is loaded once
self.business_context = format_context_for_agent()

# And included with every agent call
enriched_context['business_context'] = self.business_context
result = agent.analyze(anomaly, enriched_context)
```

Agents receive business context as formatted markdown that can be included in their prompts.

## Tuning Your Configuration

### Initial Setup

1. **Start conservative**: Use stricter thresholds initially
2. **Document your environment**: Fill in organization profile, workforce characteristics
3. **Define expected patterns**: List known legitimate edge cases

### Iterative Improvement

As you review detections and reduce false positives:

1. **Adjust thresholds**: If too many false positives, increase thresholds
2. **Add context**: Document new legitimate patterns you discover
3. **Log changes**: Use the `tuning_log` section to track what you changed and why

**Example tuning log entry:**
```yaml
tuning_log:
  - date: "2025-02-15"
    change: "Increased failed_logins.max_failed_attempts from 3 to 5"
    notes: "Too many false positives from mobile users with typos. Monitored for 2 weeks, no impact on detection rate."

  - date: "2025-02-20"
    change: "Added 'Philippines' to expected_countries"
    notes: "New customer support team location. Expected access 24/7 for support shifts."
```

### Best Practices

✅ **DO:**
- Start with conservative (stricter) thresholds
- Document all changes in the `tuning_log`
- Review detections weekly and adjust based on patterns
- Add specific context about user roles and their expected behaviors
- Update seasonal patterns as you observe them

❌ **DON'T:**
- Set thresholds too high and miss real threats
- Make changes without documenting the reason
- Ignore repeated false positives (they indicate tuning needed)
- Forget to update config when business changes (new offices, roles, etc.)

## Configuration Impact

### On Tier-1 Detections

Changing tier-1 parameters **immediately affects** what gets flagged:

| Parameter Changed | Impact |
|-------------------|--------|
| `business_hours.weekday_start/end` | Changes what times are considered "off-hours" |
| `failed_logins.max_failed_attempts` | More/fewer failed login anomalies |
| `geographic.expected_countries` | Geographic anomalies from new locations |

### On Tier-2 AI Agents

Business context helps agents make **better risk assessments**:

| Context Added | Agent Benefit |
|---------------|---------------|
| User role expectations | "Sales team travels frequently" → reduces severity of geographic anomalies |
| Common patterns | "Engineers work late nights" → reduces severity of off-hours access |
| Past incidents | "Previous phishing campaign" → increases suspicion of similar patterns |
| Technology posture | "MFA required for all users" → missing MFA is critical vs. informational |

## Helper Functions

The `config_loader.py` module provides several helper functions:

```python
from config import (
    get_tier1_config,           # Get all tier-1 parameters
    get_tier2_context,          # Get all tier-2 context
    get_business_hours,         # Get just business hours
    get_geographic_config,      # Get just geographic config
    get_detection_threshold,    # Get specific detection thresholds
    format_context_for_agent    # Format tier-2 context as markdown
)
```

## File Structure

```
config/
├── README.md                    # This file - documentation
├── business_context.yaml        # Main configuration file
├── config_loader.py            # Python utility to load config
└── __init__.py                 # Makes config a Python module
```

## Troubleshooting

**Problem:** Detection scripts not using config

**Solution:** Check that imports are correct:
```python
from config import get_business_hours  # ✓ Correct
from config.config_loader import get_business_hours  # ✓ Also works
```

---

**Problem:** YAML syntax error when loading config

**Solution:**
- Validate YAML syntax (use an online YAML validator)
- Check indentation (YAML is whitespace-sensitive)
- Ensure quotes around strings with special characters

---

**Problem:** Want to temporarily disable config and use hardcoded values

**Solution:** Detection scripts include fallback behavior:
```python
try:
    config = get_business_hours()
except Exception as e:
    print(f"[WARNING] Could not load config: {e}")
    config = {
        'primary_timezone': 'UTC',
        'weekday_start': '08:00',
        'weekday_end': '18:00',
        # ... fallback values
    }
```

## Next Steps

1. ✏️ **Customize** [business_context.yaml](business_context.yaml) with your organization's details
2. 🧪 **Test** detection scripts to verify configuration is loaded
3. 📊 **Run analysis** and review results
4. 🔧 **Tune** thresholds based on false positive rates
5. 📝 **Document** changes in the `tuning_log`

---

**Questions or issues?** Check the main project [README](../README.md) or review example usage in the detection scripts.
