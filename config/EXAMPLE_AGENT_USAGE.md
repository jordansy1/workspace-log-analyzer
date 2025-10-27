# Example: How Tier-2 Agents Use Business Context

This document shows how tier-2 AI agents can leverage business context to make better risk assessments.

## How Business Context Reaches Agents

```
1. Config File (business_context.yaml)
        ↓
2. Config Loader (config_loader.py)
        ↓ format_context_for_agent()
3. Agent Router (agent_router.py)
        ↓ enriched_context['business_context']
4. Individual Agent (e.g., behavioral_analyzer)
        ↓ Uses in prompt/analysis
5. Better Risk Assessment
```

## Example: Off-Hours Access Analysis

### Scenario

**Anomaly Detected (Tier-1):**
- User: `john.smith@company.com`
- Time: `2025-10-19 02:30 AM EST`
- Event: Successful login
- Flagged as: Off-hours access

### Without Business Context

**Generic AI Analysis:**
```
Risk Level: MEDIUM
Reasoning: Login occurred at 2:30 AM, which is outside typical business hours.
This could indicate compromised credentials or unauthorized access.
Recommendation: Investigate immediately.
```

### With Business Context

**Context-Aware AI Analysis:**

The agent receives this business context:
```markdown
## User Role Expectations

**Engineers:**
- Travel: Low
- International Access: false
- Off-Hours: Common
- Notes: Frequently work late nights and weekends during releases

## Seasonal Patterns
- Period: Q4 (Oct-Dec)
- Description: End of fiscal year - sales push, financial close
- Expected Changes: Extended hours for finance and sales teams
```

**Improved Analysis:**
```
Risk Level: LOW
Reasoning:
1. User john.smith@company.com has role "Engineer"
2. Off-hours access is marked as "Common" for engineering role
3. Business context notes: "Engineers frequently work late nights and weekends during releases"
4. Current period: Q4, which may involve extended hours for various teams
5. No other suspicious indicators (same IP as daytime logins, familiar location)

Recommendation: Normal behavior for this role. Monitor for pattern changes but no immediate action needed.
```

## Example: Geographic Anomaly

### Scenario

**Anomaly Detected (Tier-1):**
- User: `sarah.jones@company.com`
- Location: `Manila, Philippines`
- Event: Successful login
- Flagged as: Geographic anomaly (not in expected_countries)

### Without Business Context

```
Risk Level: HIGH
Reasoning: Login from Philippines, which is not in the list of expected countries.
Could indicate account compromise or unauthorized access from a foreign location.
Recommendation: Lock account and investigate.
```

### With Business Context

```markdown
## Workforce Profile
Common Patterns:
- Customer support team operates 24/7 with shift workers

Legitimate Edge Cases:
- International contractors access from expected foreign locations

## User Role Expectations

**Support:**
- Travel: Low
- International Access: false
- Off-Hours: Very Common
- Expected Locations: ["US", "Philippines", "India"]
- Notes: 24/7 shifts, including nights and weekends
```

**Improved Analysis:**
```
Risk Level: LOW
Reasoning:
1. User sarah.jones@company.com has role "Support"
2. Philippines is listed as an expected location for support role
3. Business context indicates "Customer support team operates 24/7 with shift workers"
4. No other suspicious indicators (successful MFA challenge, consistent login pattern)

Recommendation: Normal access pattern for international support team member. No action needed.
```

## Example: Multiple MFA Challenges

### Scenario

**Anomaly Detected (Tier-1):**
- User: `admin@company.com`
- Event: 8 MFA challenges in 10 minutes, eventually successful
- Flagged as: MFA fatigue/bombing attack

### Without Business Context

```
Risk Level: CRITICAL
Reasoning: Multiple rapid MFA challenges suggest attacker has password and is attempting
to fatigue user into approving MFA. Eventually successful challenge is highly suspicious.
Recommendation: Immediately lock account and investigate.
```

### With Business Context

```markdown
## Technology Environment

Security Posture:
- MFA Required: true
- MFA Enforcement: All users
- Device Management: Partial MDM

Known Legitimate Scenarios:
- IT administrators access from home networks during on-call rotations

## Past Incidents

- Date: 2024-06-20
  Type: Phishing
  Description: Employee credentials compromised via phishing email
  Outcome: MFA prevented account takeover

## Risk Profile
- Risk Tolerance: Low
- False Positive Tolerance: Low (Prefer to investigate more vs. miss threats)
```

**Improved Analysis:**
```
Risk Level: CRITICAL (Unchanged)
Reasoning:
1. Multiple rapid MFA challenges (8 in 10 minutes) is abnormal even for admins
2. Business context shows low risk tolerance: "Prefer to investigate more vs. miss threats"
3. Past incident log shows phishing-based credential compromise (June 2024)
4. No legitimate scenario in business context explains this pattern
5. Even though "IT admins access from home during on-call", multiple rapid MFA denials
   followed by approval is classic MFA fatigue attack pattern

Additional Context from Config:
- Organization has experienced phishing attacks that compromised credentials
- MFA successfully prevented takeover in the past
- Risk posture is "Low tolerance" - prefer false positives over missed threats

Recommendation:
- IMMEDIATE ACTION REQUIRED
- Lock account temporarily
- Contact user through alternate channel (phone) to verify legitimacy
- Review session for any suspicious activity post-approval
- This matches known attack pattern from threat intelligence
```

## How to Update Agent Prompts

### Example: Behavioral Analyzer

When the agent receives `enriched_context`, it now includes:

```python
enriched_context = {
    'event': {...},
    'ip_reputation': {...},
    'enriched_location': {...},
    'business_context': """
    # BUSINESS CONTEXT
    ## Organization: Your Organization Name
    Industry: Technology | Size: Medium
    ...
    (Full formatted business context)
    """
}
```

The agent can include this in its analysis prompt:

```python
# In tier2_analysis/agents/behavioral_analyzer/agent.py
def build_prompt(self, anomaly, enriched_context):
    prompt = f"""
    You are a security analyst investigating an off-hours access anomaly.

    {enriched_context.get('business_context', '')}

    ## Anomaly Details
    {anomaly['description']}

    ## Evidence
    {anomaly['evidence']}

    Given the business context above, assess whether this off-hours access
    represents legitimate business behavior or potential threat.

    Consider:
    - User role expectations
    - Common access patterns
    - Legitimate edge cases
    - Current seasonal patterns
    - Organization's risk tolerance

    Provide risk assessment (LOW/MEDIUM/HIGH/CRITICAL) with reasoning.
    """
    return prompt
```

## Benefits of Business Context

### 1. **Fewer False Positives**
- Agents understand legitimate edge cases
- Role-based expectations reduce noise
- Seasonal patterns are accounted for

### 2. **Better Risk Prioritization**
- High-risk anomalies stay high-risk
- Low-risk patterns (expected for role) are downgraded
- Risk tolerance guides severity assignment

### 3. **Context-Aware Recommendations**
- Actions aligned with security posture
- Compliance requirements considered
- Past incidents inform current analysis

### 4. **Continuous Improvement**
- Add new patterns as you discover them
- Document false positives to prevent recurrence
- Tuning log tracks what works

## Next Steps

1. **Review** [business_context.yaml](business_context.yaml) and customize for your organization
2. **Test** by running analysis on sample logs
3. **Observe** how context affects risk assessments
4. **Tune** by adding patterns that reduce false positives
5. **Document** improvements in the tuning log

---

**See Also:**
- [Configuration README](README.md) - Full configuration documentation
- [business_context.yaml](business_context.yaml) - The configuration file
