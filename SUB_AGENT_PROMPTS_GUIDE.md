# Sub-Agent Prompt Engineering Guide

## Overview
This document explains the forensically-sound sub-agent prompts designed for tier-2 AI analysis in the workspace_log_analyzer system. Each prompt is engineered to guide the LLM to think like an expert security analyst or digital forensic investigator.

---

## Prompt Design Philosophy

### Core Principles

1. **Role-Based Persona**: Each sub-agent is given a specific expert role (threat intelligence analyst, incident responder, forensic investigator, UEBA specialist)

2. **Investigative Framework**: Prompts follow real-world investigation methodologies (NIST IR, SANS incident response, SOC analyst playbooks)

3. **Decision Trees**: Explicit decision points guide the AI through "if-this-then-that" logic chains

4. **Evidence-Based Reasoning**: Requires citing specific evidence from logs, IP reputation, timing analysis, and enriched context

5. **Structured JSON Output**: Forces consistent, machine-parseable responses with required fields

6. **False Positive Awareness**: Prompts explicitly list legitimate scenarios to rule out before declaring threats

---

## Sub-Agent Prompt Catalog

### 1. Credential Stuffing Analyzer
**MITRE ATT&CK**: T1110.004
**Expertise**: Threat Intelligence Analyst
**Framework**: SOC Analyst Investigation Playbook

#### Investigation Phases
```
Phase 1: Infrastructure Assessment
├─ Examine IP characteristics (hosting, Tor, VPN, residential)
├─ Check threat intelligence databases
└─ Analyze abuse history

Phase 2: Behavioral Analysis
├─ Compare to legitimate user patterns
├─ Identify automation signatures
└─ Assess targeting patterns

Phase 3: Cross-Reference Intelligence
├─ Search for related incidents
├─ Check for geographic impossibilities
└─ Look for post-compromise activity

Phase 4: Impact Assessment
├─ Identify high-value targets
├─ Assess lateral movement risk
└─ Evaluate data access implications
```

#### Critical Decision Points
- **TRUE POSITIVE**: IP reputation >60 + targeting 3+ accounts + Tor/hosting source
- **FALSE POSITIVE**: Corporate VPN, testing environment, password manager testing
- **UNCERTAIN**: Moderate risk (30-60) requiring escalation

#### Key Output Fields
- `attack_infrastructure`: IP assessment, abuse history
- `attack_pattern_analysis`: Attempts per target, timing, credential source
- `impact_assessment`: Compromised accounts, high-value targets
- `recommended_actions`: Immediate, investigation, preventive
- `indicators_of_compromise`: Malicious IPs, attack signatures

---

### 2. Password Spray Analyzer
**MITRE ATT&CK**: T1110.003
**Expertise**: Senior Incident Responder
**Framework**: NIST IR + SANS Incident Response

#### Attack Pattern Fingerprinting
```
Critical Metric: Attempts-per-Account Ratio
├─ Password Spray: 1-2 attempts/account → next user
├─ Brute Force: Multiple attempts/account before moving
├─ Credential Stuffing: 1 attempt/account from multiple IPs
└─ Legitimate: Random distribution
```

#### Known Campaign Comparison
Prompts compare against real-world APT patterns:
- **APT29 (Cozy Bear)**: 1 attempt/account, 30-min intervals
- **Midnight Blizzard**: Seasonal passwords ("Summer2024!")
- **Scattered Spider**: Off-hours (2-4 AM), high-privilege focus
- **LockBit/BlackCat**: Pre-ransomware reconnaissance

#### Severity Classification
- **CRITICAL**: 5+ accounts + hosting/Tor IP + off-hours + successful login
- **HIGH**: 5+ accounts + IP reputation >50 + automation timing
- **MEDIUM**: 5-10 accounts + VPN/proxy + business hours + no success
- **FALSE POSITIVE**: SSO cascade, password reset portal, monitoring system

#### Escalation Triggers
**IMMEDIATE**: Successful auth, 20+ accounts, admin targets, ongoing attack
**IR TEAM**: Pattern matches spray but intent unclear, need threat hunting

#### Key Output Fields
- `campaign_analysis`: Account counts, velocity, temporal patterns
- `infrastructure_assessment`: IP reputation, threat intel matches, APT attribution
- `password_pattern_hypothesis`: Likely passwords, source (rockyou, breachcomp, seasonal)
- `attack_timeline`: Event sequence with significance
- `executive_summary`: 2-3 sentence CISO briefing
- `escalation_path`: Security Ops | IR | Executive | Law Enforcement

---

### 3. Session Analyzer
**MITRE ATT&CK**: T1539 (Session Cookie Theft), T1185 (Browser Session Hijacking)
**Expertise**: Digital Forensics Investigator
**Framework**: Forensic Investigation Methodology

#### Legitimate vs. Malicious Scenario Matrix

**Legitimate:**
```
Multi-Device Usage
├─ Similar geographic locations
├─ Both IPs known to user
├─ Business hours timing
└─ Normal activity on both devices

VPN Reconnection
├─ Both IPs from same VPN provider
├─ <30 seconds timestamp proximity
└─ Continuous activity across IP change

Mobile Network Handoff
├─ IPs from mobile carrier, same region
├─ <60 seconds handoff time
└─ Mobile user-agent, continuous usage

Corporate Load Balancer
├─ IPs from same /24 subnet
├─ Regular interval IP rotation
└─ Same user-agent, predictable pattern
```

**Malicious:**
```
Session Cookie Theft
├─ Geographic impossibility (US user + China attacker)
├─ Sudden second IP, first continues normally
└─ Reconnaissance behavior (checking permissions)

Credential Compromise + Concurrent
├─ Two distinct locations, different behaviors
├─ Overlapping incompatible locations
└─ One normal, one admin/data extraction

Man-in-the-Middle
├─ Third IP appears mid-session
├─ Brief targeted action window
└─ Surgical strikes (export, settings, backdoor)
```

#### Geographic Impossibility Test
- Required travel speed >800 km/h = IMPOSSIBLE = Likely compromise
- Same metro area = Possible legitimate
- VPN + residential ISP different countries = Suspicious

#### Infrastructure Mismatch Analysis
- Residential ISP vs. Hosting provider = RED FLAG
- Corporate VPN vs. Same VPN different exit = Likely OK
- Mobile carrier vs. Tor node = CRITICAL ALERT

#### Key Output Fields
- `session_analysis`: Concurrent IPs, time separation, impossible travel detection
- `infrastructure_comparison`: IP1 vs IP2 type, reputation, known status
- `behavioral_analysis`: Activity differences, suspicious actions
- `likely_scenario`: Most probable explanation with confidence
- `user_notification_required`: Should user be contacted?

---

### 4. Behavioral Analyzer (Off-Hours Access)
**MITRE ATT&CK**: M1036 (Account Use Policies)
**Expertise**: User and Entity Behavior Analytics (UEBA) Specialist
**Framework**: UEBA Investigation + Insider Threat Detection

#### Behavioral Baseline Comparison
```
Temporal Baseline
├─ User's typical hours: ___ to ___
├─ Historical off-hours frequency
└─ Established patterns

Geographic Baseline
├─ Known locations (home, office, travel)
├─ IP consistency with baseline
└─ Deviation analysis

Device & Access Method
├─ Mobile vs desktop typical usage
├─ Browser/OS consistency
└─ Authentication method changes
```

#### Risk Scoring Framework
```
Base Score: Off-hours access = 30 points

Aggravating Factors:
├─ No historical pattern: +30
├─ High-risk IP (>60): +40
├─ Unusual location: +20
├─ Sensitive resource access: +30
├─ Bulk data access: +40
├─ Recent security event: +20
└─ High-privilege user: +20

Mitigating Factors:
├─ Regular off-hours pattern: -40
├─ Known home/mobile IP: -30
├─ Timezone justified: -40
└─ Low-privilege account: -10

Risk Interpretation:
├─ 0-30: Low (likely legitimate)
├─ 31-60: Medium (investigate)
├─ 61-90: High (probable compromise/insider)
└─ 91+: Critical (immediate action)
```

#### Insider Threat Indicators
- Off-hours access to data outside job function
- Bulk downloads or unusual volumes
- Access post-disciplinary action/resignation
- Deliberate timing (3-5 AM when SOC understaffed)

#### Legitimate Justifications
- **Global Teams**: Works with Asia/Europe, timezone differences
- **On-Call**: IT/DevOps rotation, incident response
- **Flexible Schedule**: Documented non-standard hours
- **Automated Systems**: Service accounts, scheduled jobs

#### Key Output Fields
- `behavioral_baseline_analysis`: Historical patterns, deviation severity
- `temporal_analysis`: Hour, day of week, weekend, holiday
- `composite_risk_score`: Calculated score with breakdown
- `business_justification_assessment`: Has justification?, type, strength
- `insider_threat_indicators`: Present?, detected indicators, risk level
- `false_positive_likelihood`: Very low to very high

---

## Prompt Engineering Techniques Used

### 1. **Chain-of-Thought Reasoning**
Prompts explicitly walk through investigation phases:
```
Phase 1: Infrastructure Assessment → Phase 2: Behavioral Analysis →
Phase 3: Cross-Reference → Phase 4: Impact Assessment
```

### 2. **Real-World Examples**
References actual APT campaigns, ransomware groups, and attack patterns:
- APT29, Midnight Blizzard, Scattered Spider, LockBit
- Provides concrete comparison points for pattern matching

### 3. **Decision Matrix**
Clear if-then logic for classification:
```
IF (IP reputation >60 AND targeting 3+ accounts AND Tor source)
THEN mark as TRUE POSITIVE
```

### 4. **False Positive Prevention**
Explicit sections listing legitimate scenarios to rule out before declaring threats:
- Corporate VPN usage
- Password manager testing
- Multi-device access
- Mobile network transitions

### 5. **Structured Output Schema**
Enforces JSON output with required fields ensuring:
- Consistency across analyses
- Machine-parseable results
- Audit trail of reasoning
- Actionable recommendations

### 6. **Escalation Criteria**
Clear triggers for escalation to different teams:
```
IMMEDIATE → Security Leadership
IR TEAM → Incident Response
PENDING → Further Investigation
```

### 7. **Multi-Audience Communication**
Outputs include:
- **Technical**: IOCs, YARA rules, attack signatures
- **Executive**: CISO-ready summaries
- **Operational**: Immediate actions, investigation steps

### 8. **Regulatory Awareness**
Prompts consider compliance implications:
- GDPR, HIPAA, SOX considerations
- Data access risk assessment
- Reporting requirements

---

## How Prompts Leverage Enriched Context

Each prompt receives enriched data and explicitly instructs the AI how to use it:

### IP Reputation Data
```json
"ip_reputation": {
  "overall_risk_score": 0-100,
  "is_malicious": true/false,
  "abuse_confidence_score": 0-100,
  "is_tor": true/false
}
```

**Usage Guidance in Prompts:**
- Score 0-30 = low risk
- Score 31-60 = medium risk
- Score 61-100 = high risk
- is_tor=true → anonymization → likely malicious
- High abuse_confidence → known bad actor

### Enriched Location Data
```json
"enriched_location": {
  "city": "Amsterdam",
  "is_vpn": true,
  "is_proxy": true,
  "is_tor": true,
  "is_hosting": true
}
```

**Usage Guidance:**
- is_hosting=true → automated tool usage (critical)
- is_tor=true → anonymization (high risk)
- Geographic impossibility calculation

### User Context Data
```json
"user_context": {
  "is_admin": true,
  "is_2fa_enrolled": true,
  "is_2fa_enforced": true,
  "org_unit_path": "/Administrators"
}
```

**Usage Guidance:**
- is_2fa_enrolled=true → don't flag "missing MFA" as risk
- is_admin=true → high-value target, increase severity
- org_unit_path → understand role and expected behavior

### Baseline Comparison Data
```json
"baseline_comparison": {
  "deviations": ["new_ip_address", "new_geographic_region"],
  "is_anomalous": true
}
```

**Usage Guidance:**
- new_ip_address → investigate if legitimate
- new_geographic_region + impossible travel → likely compromise
- Empty deviations → aligns with baseline, lower risk

---

## Testing Sub-Agent Prompts

### Manual Testing Process

1. **Extract Test Anomaly**: Get anomaly from tier-1 detection
2. **Generate Prompt**: Call `generate_sub_agent_prompt(anomaly, all_events)`
3. **Execute with LLM**: Send to Claude/GPT with prompt
4. **Validate Output**: Check JSON structure, reasoning quality
5. **Iterate**: Refine prompt based on output quality

### Automated Testing (Future)

```python
def test_sub_agent_prompt(anomaly_type, test_cases):
    """
    Test sub-agent prompts against known attack scenarios

    Args:
        anomaly_type: e.g., 'credential_stuffing'
        test_cases: List of {input, expected_classification}

    Returns:
        Test results with accuracy metrics
    """
    pass
```

### Quality Criteria

**Good Sub-Agent Output:**
- ✅ Cites specific evidence from logs
- ✅ Reasoning follows investigation framework
- ✅ Considers multiple scenarios before concluding
- ✅ Provides actionable recommendations
- ✅ Explains confidence level
- ✅ Valid JSON structure

**Poor Sub-Agent Output:**
- ❌ Generic reasoning without evidence
- ❌ Jumps to conclusions
- ❌ Doesn't consider false positives
- ❌ Vague recommendations
- ❌ Doesn't explain uncertainty
- ❌ Malformed JSON

---

## Prompt Maintenance

### When to Update Prompts

1. **New Attack Techniques**: MITRE ATT&CK updates, emerging threats
2. **False Positive Patterns**: Discover new legitimate scenarios being flagged
3. **Output Quality Issues**: AI misinterprets evidence or misses key indicators
4. **Regulatory Changes**: New compliance requirements (e.g., GDPR updates)
5. **Feedback Loop**: Security team reports prompt-driven misclassifications

### Version Control

Track prompt changes with:
```
Version: 1.0 - Initial implementation (2025-10-09)
Version: 1.1 - Added APT campaign comparison
Version: 1.2 - Enhanced false positive detection
```

### A/B Testing

Test prompt variations:
```python
# Prompt A: Strict thresholds
# Prompt B: Contextual thresholds

Compare:
- True positive rate
- False positive rate
- Time to detection
- Analyst feedback
```

---

## Integration with Orchestrator

Sub-agent prompts integrate with the automated orchestrator workflow:

```
1. Tier-1 Detection → Anomaly flagged with sub_agent field
2. Orchestrator → Calls generate_sub_agent_prompt(anomaly, events)
3. LLM Execution → Sends prompt to AI model
4. Response Parsing → Extracts JSON from AI response
5. Integration → Merges refined analysis into final report
6. Escalation → Routes to appropriate team based on severity
```

### Prompt Injection Protection

Prompts sanitize user-controlled data:
```python
json.dumps(anomaly, indent=2)  # Escapes special characters
```

Prevents malicious log entries from manipulating AI analysis.

---

## Best Practices

### For Prompt Authors

1. **Think Like the Expert**: Research how real analysts investigate each attack type
2. **Provide Examples**: Include specific attack campaigns, APT groups, tools
3. **Decision Trees**: Explicit "if-then" logic, not vague guidance
4. **False Positive Lists**: Always include legitimate scenarios to rule out
5. **Structured Output**: Enforce JSON schema for consistency
6. **Escalation Paths**: Clear criteria for when to escalate

### For System Operators

1. **Monitor Output Quality**: Review AI responses periodically
2. **Collect Feedback**: Security team validates AI conclusions
3. **Update Threat Intel**: Keep APT campaign references current
4. **Tune Thresholds**: Adjust risk scores based on organizational tolerance
5. **Document Changes**: Track why prompts were modified

---

## Future Enhancements

### Planned Improvements

1. **Dynamic Threat Intel Integration**
   - Fetch latest APT campaign data from MITRE ATT&CK
   - Real-time threat feed correlation

2. **Organizational Context Awareness**
   - User role-specific baselines
   - Department-specific off-hours patterns
   - VIP account special handling

3. **Multi-Modal Analysis**
   - Combine authentication logs with endpoint detection
   - Correlate with email security events
   - Cross-reference with DLP alerts

4. **Explainable AI Reporting**
   - Confidence scores for each conclusion
   - Alternative scenario probabilities
   - Evidence strength weighting

5. **Prompt Optimization via ML**
   - Learn from analyst feedback
   - Auto-tune thresholds based on true/false positive rates
   - Generate custom prompts per organization

---

## References

### MITRE ATT&CK Techniques
- [T1110.004 - Credential Stuffing](https://attack.mitre.org/techniques/T1110/004/)
- [T1110.003 - Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [T1539 - Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [T1185 - Browser Session Hijacking](https://attack.mitre.org/techniques/T1185/)
- [M1036 - Account Use Policies](https://attack.mitre.org/mitigations/M1036/)

### Investigation Frameworks
- NIST IR Framework (SP 800-61)
- SANS Incident Handler's Handbook
- MITRE D3FEND Knowledge Graph
- OWASP Authentication Cheat Sheet

### Threat Intelligence
- APT Group Activity Tracking
- Ransomware Campaign Analysis
- Password Spray Trend Reports

---

## Conclusion

These sub-agent prompts transform the tier-2 AI from a generic chatbot into a specialized security analyst with domain expertise. By following real-world investigation methodologies, considering both malicious and legitimate scenarios, and providing structured, evidence-based output, the prompts enable accurate threat detection while minimizing false positives.

The key to effective prompt engineering is **thinking like the expert you're simulating**—in this case, seasoned security analysts, incident responders, and forensic investigators who have investigated thousands of attacks and can quickly differentiate true threats from benign anomalies.
