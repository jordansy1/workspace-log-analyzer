# SAML & OAuth Security Analysis Implementation Plan

## Executive Summary

This document outlines the complete implementation plan for extending the workspace log analyzer to detect and analyze SAML (Single Sign-On) and OAuth (token authorization) security events.

**Timeline:** 2-3 development sessions
**Complexity:** Medium (following established patterns)
**Security Value:** High (detects lateral movement, token theft, malicious apps)

---

## Phase 1: Data Collection & Analysis (Current Session)

### Objective
Understand the actual structure of SAML and OAuth events from Google Workspace to inform detection rule design.

### Tasks

#### 1.1 ✅ Add Fetch Methods
**Status:** Complete
**Files Modified:**
- `fetch_logs.py` (added `fetch_saml_logs()` and `fetch_token_logs()`)

**Code Added:**
- Lines 153-204: `fetch_saml_logs()` - Fetches SAML SSO events
- Lines 206-257: `fetch_token_logs()` - Fetches OAuth/API token events

#### 1.2 ⏳ Collect Sample Data (Next: Run This Now)
**Status:** Ready to execute
**Script:** `collect_saml_oauth_samples.py`

**Run Command:**
```bash
cd workspace_log_analyzer
venv/Scripts/python.exe collect_saml_oauth_samples.py
```

**Expected Output:**
```
samples/
├── saml_events_sample.json
└── token_events_sample.json
```

**What This Reveals:**
- Available event types (e.g., `saml_login`, `oauth_grant`, `token_revoke`)
- Event structure and field names
- Parameters we can use for detection rules
- Context data for tier-2 enrichment

#### 1.3 📊 Analyze Event Structure
**Status:** Pending (after 1.2)

**Analysis Questions:**
1. **SAML Events:**
   - What field indicates the target application?
   - How do we identify the IdP vs. SP?
   - What parameters indicate success/failure?
   - Are there assertion attributes we can check?

2. **OAuth Events:**
   - What field shows the app requesting authorization?
   - How do we identify scope/permissions requested?
   - What distinguishes user consent vs. admin-granted?
   - Can we see the client ID of the OAuth app?

**Deliverable:** Annotated sample files with key detection fields highlighted

---

## Phase 2: MITRE ATT&CK Mapping & Threat Modeling

### Objective
Map SAML/OAuth attack patterns to MITRE techniques and identify detection opportunities.

### SAML Attack Patterns (MITRE Mapping)

#### T1550.001 - Use Alternate Authentication Material: Application Access Token
**Attack:** Attacker uses stolen SAML assertion to impersonate user

**Detection Indicators:**
- SAML login from unusual IP/location
- SAML assertion with unexpected attributes
- Multiple SAML logins to different apps in short timeframe
- SAML login outside user's normal hours

**Tier-1 Detection:** `T1550_001_saml_assertion_abuse.py`
**Tier-2 Agent:** `saml_sso_analyzer`

#### T1556.007 - Modify Authentication Process: Hybrid Identity
**Attack:** Attacker modifies SAML configuration to bypass authentication

**Detection Indicators:**
- New SAML service provider added
- SAML configuration changes (admin logs)
- SAML authentication bypassing expected workflow

**Tier-1 Detection:** `T1556_007_saml_config_abuse.py`
**Tier-2 Agent:** `saml_sso_analyzer`

#### T1199 - Trusted Relationship
**Attack:** Attacker compromises third-party SSO application to access target

**Detection Indicators:**
- Authentication to newly integrated SAML app
- SAML login to low-reputation service provider
- Unusual SAML attribute requests from SP

**Tier-1 Detection:** `T1199_suspicious_saml_sp.py`
**Tier-2 Agent:** `saml_sso_analyzer`

### OAuth/Token Attack Patterns (MITRE Mapping)

#### T1550.001 - Use Alternate Authentication Material: Application Access Token
**Attack:** Attacker uses stolen OAuth token to access user data

**Detection Indicators:**
- OAuth token used from unusual IP/location
- Token usage outside normal hours
- High volume API calls using token
- Token accessing sensitive scopes (Drive, Gmail)

**Tier-1 Detection:** `T1550_001_oauth_token_abuse.py`
**Tier-2 Agent:** `oauth_token_analyzer`

#### T1528 - Steal Application Access Token
**Attack:** Malicious OAuth application tricks user into granting excessive permissions

**Detection Indicators:**
- OAuth grant with broad scopes (e.g., `https://www.googleapis.com/auth/drive`)
- OAuth app with suspicious client ID
- Multiple OAuth grants to same app across users (phishing campaign)
- OAuth grant shortly after suspicious login

**Tier-1 Detection:** `T1528_malicious_oauth_app.py`
**Tier-2 Agent:** `oauth_token_analyzer`

#### T1098.001 - Account Manipulation: Additional Cloud Credentials
**Attack:** Attacker creates API tokens for persistence

**Detection Indicators:**
- Service account token creation by non-admin
- Multiple token grants in short timeframe
- Token creation from unusual IP
- Token with elevated permissions

**Tier-1 Detection:** `T1098_001_suspicious_token_creation.py`
**Tier-2 Agent:** `oauth_token_analyzer`

---

## Phase 3: Tier-1 Detection Implementation

### Objective
Create deterministic detection rules for SAML/OAuth anomalies following existing patterns.

### 3.1 SAML Detection Methods

#### T1550_001_saml_assertion_abuse.py
**Detects:** Unusual SAML authentication patterns

**Logic:**
```python
def detect_saml_assertion_abuse(events, metadata):
    """
    Detect suspicious SAML assertion usage.

    Triggers on:
    - SAML login from new geographic location
    - Multiple SAML apps accessed in < 5 minutes
    - SAML login outside user's normal hours
    - SAML login from high-risk IP
    """
    saml_events = [e for e in events if e.get('event_name') == 'saml_login']

    # Check for rapid app switching
    # Check for geographic anomalies
    # Check for temporal anomalies

    return anomaly_dict if suspicious else None
```

**Evidence Structure:**
```json
{
  "id": "ANOM-SAML-001",
  "type": "saml_assertion_abuse",
  "requires_deep_analysis": true,
  "sub_agent": "saml_sso_analyzer",
  "description": "Suspicious SAML authentication pattern detected",
  "evidence": {
    "saml_events": [...],
    "target_applications": ["app1", "app2"],
    "ip_addresses": ["..."],
    "time_span_seconds": 120
  },
  "mitre_attack": ["T1550.001"]
}
```

#### T1199_suspicious_saml_sp.py
**Detects:** Authentication to untrusted or new SAML service providers

**Logic:**
```python
def detect_suspicious_saml_sp(events, metadata):
    """
    Detect authentication to suspicious SAML service providers.

    Triggers on:
    - First-time authentication to new SP
    - SP with suspicious domain pattern
    - SP requesting unusual attributes
    """
    # Compare against baseline of known SPs
    # Check SP domain reputation
    # Analyze attribute requests

    return anomaly_dict if suspicious else None
```

### 3.2 OAuth/Token Detection Methods

#### T1550_001_oauth_token_abuse.py
**Detects:** Stolen or compromised OAuth tokens in use

**Logic:**
```python
def detect_oauth_token_abuse(events, metadata):
    """
    Detect suspicious OAuth token usage patterns.

    Triggers on:
    - Token used from different IP than grant location
    - Token usage outside normal hours
    - High-volume API calls
    - Token accessing sensitive resources
    """
    token_events = [e for e in events if e.get('event_name') in ['token_grant', 'api_access']]

    # Compare grant IP vs. usage IP
    # Check for excessive API calls
    # Analyze scope usage patterns

    return anomaly_dict if suspicious else None
```

#### T1528_malicious_oauth_app.py
**Detects:** Malicious OAuth applications requesting authorization

**Logic:**
```python
def detect_malicious_oauth_app(events, metadata):
    """
    Detect potentially malicious OAuth application grants.

    Triggers on:
    - OAuth app requesting broad scopes
    - OAuth app with suspicious client ID pattern
    - Multiple users granting to same app (potential phishing)
    - OAuth grant after suspicious login
    """
    oauth_grants = [e for e in events if e.get('event_name') == 'authorize']

    # Analyze requested scopes
    # Check client ID reputation (if available)
    # Detect grant campaigns
    # Correlate with login events

    return anomaly_dict if suspicious else None
```

---

## Phase 4: Tier-2 Agent Implementation

### Objective
Create specialized AI agents that provide contextual analysis of SAML/OAuth anomalies.

### 4.1 SAML SSO Analyzer Agent

#### Agent Structure
```
tier2_analysis/agents/saml_sso_analyzer/
├── __init__.py
├── agent.py
├── prompt.md
├── config.yaml
└── examples/
    ├── legitimate_sso.json
    ├── compromised_assertion.json
    └── new_saml_app.json
```

#### Agent Responsibilities
1. **Assess SAML authentication legitimacy**
   - Is the service provider trustworthy?
   - Does the authentication pattern match user's normal behavior?
   - Are the SAML attributes appropriate?

2. **Analyze SAML assertions**
   - Check assertion timing and validity period
   - Verify IP/location consistency
   - Evaluate scope of access requested

3. **Provide actionable recommendations**
   - Should the SAML integration be reviewed?
   - Should user be contacted for verification?
   - Should access be revoked?

#### Prompt Structure (prompt.md)
```markdown
# SAML SSO Context Analyzer

You are a specialized security analyst focusing on SAML (Single Sign-On)
authentication security. Your role is to analyze suspicious SAML authentication
events and determine if they represent actual security risks.

## Your Expertise
- SAML protocol and assertion structure
- Service provider trust evaluation
- SSO abuse patterns
- Third-party application risk assessment

## Analysis Context
You have access to:
- SAML event details (service provider, attributes, timing)
- IP reputation and geolocation data
- User behavioral baseline
- Historical SAML usage patterns

## Output Format
{
  "is_actual_risk": bool,
  "confidence": "high|medium|low",
  "adjusted_severity": "critical|high|medium|low",
  "forensic_narrative": "Detailed analysis...",
  "recommended_actions": [
    "Navigate to Admin Console > Security > Settings > API controls...",
    ...
  ]
}

## Remember
- First-time SSO to legitimate apps (Slack, Salesforce) is often benign
- Geographic anomalies may be VPN or travel
- Consider if user has history with this service provider
- Broad SAML scopes aren't always malicious if it's a known app
```

### 4.2 OAuth Token Analyzer Agent

#### Agent Structure
```
tier2_analysis/agents/oauth_token_analyzer/
├── __init__.py
├── agent.py
├── prompt.md
├── config.yaml
└── examples/
    ├── legitimate_oauth.json
    ├── malicious_app.json
    └── stolen_token.json
```

#### Agent Responsibilities
1. **Assess OAuth application trustworthiness**
   - Is the app legitimate or potentially malicious?
   - Are the requested scopes appropriate?
   - Is there evidence of user consent vs. phishing?

2. **Analyze token usage patterns**
   - Does token usage match grant circumstances?
   - Is there evidence of token theft?
   - Are API calls within normal bounds?

3. **Provide remediation guidance**
   - Should the OAuth grant be revoked?
   - Should the app be blocked organization-wide?
   - Should user be educated on OAuth risks?

#### Prompt Structure (prompt.md)
```markdown
# OAuth Token Security Analyzer

You are a specialized security analyst focusing on OAuth authorization
and API token security. Your role is to analyze suspicious OAuth grant
and token usage events.

## Your Expertise
- OAuth 2.0 protocol and flow types
- Scope risk assessment
- Malicious application identification patterns
- Token theft and replay attack indicators

## Analysis Context
You have access to:
- OAuth grant details (app, scopes, client ID)
- Token usage patterns (API calls, resources accessed)
- IP reputation and geolocation
- User behavioral baseline
- Cross-user grant patterns (phishing campaigns)

## Output Format
{
  "is_actual_risk": bool,
  "confidence": "high|medium|low",
  "adjusted_severity": "critical|high|medium|low",
  "forensic_narrative": "Detailed analysis...",
  "recommended_actions": [
    "Navigate to Admin Console > Security > API controls > App access control...",
    ...
  ]
}

## Remember
- Popular apps (Google Drive API, Gmail API) have legitimate broad scopes
- Multiple users granting to same app could be organic or phishing
- Token IP != grant IP might be VPN or legitimate user travel
- Consider app reputation and user's intent
```

---

## Phase 5: Integration & Testing

### Objective
Integrate SAML/OAuth analysis into existing pipeline and validate accuracy.

### 5.1 Update Detector to Include New Methods

**File:** `tier1_detection/detector.py`

**Changes:**
```python
from tier1_detection.detection_methods import (
    # Existing imports...
    detect_saml_assertion_abuse,
    detect_suspicious_saml_sp,
    detect_oauth_token_abuse,
    detect_malicious_oauth_app,
    detect_suspicious_token_creation,
)

class AnomalyDetector:
    def detect_anomalies(self):
        anomalies = []

        # ... existing detections ...

        # Detection 14: SAML assertion abuse (T1550.001)
        saml_abuse = detect_saml_assertion_abuse(self.events, self.metadata)
        if saml_abuse:
            anomalies.append(saml_abuse)

        # Detection 15: Suspicious SAML service providers (T1199)
        saml_sp = detect_suspicious_saml_sp(self.events, self.metadata)
        if saml_sp:
            anomalies.extend(saml_sp) if isinstance(saml_sp, list) else anomalies.append(saml_sp)

        # Detection 16: OAuth token abuse (T1550.001)
        oauth_abuse = detect_oauth_token_abuse(self.events, self.metadata)
        if oauth_abuse:
            anomalies.append(oauth_abuse)

        # Detection 17: Malicious OAuth apps (T1528)
        oauth_malicious = detect_malicious_oauth_app(self.events, self.metadata)
        if oauth_malicious:
            anomalies.extend(oauth_malicious) if isinstance(oauth_malicious, list) else anomalies.append(oauth_malicious)

        return anomalies
```

### 5.2 Update Agent Router

**File:** `tier2_analysis/agent_router.py`

**Changes:**
```python
from tier2_analysis.agents import (
    # Existing imports...
    SAMLSSOAnalyzer,
    OAuthTokenAnalyzer,
)

class AgentRouter:
    def __init__(self):
        self.agents = {
            # Existing agents...
            'saml_sso_analyzer': SAMLSSOAnalyzer(),
            'oauth_token_analyzer': OAuthTokenAnalyzer(),
        }
```

### 5.3 Update Web UI Backend

**File:** `web-ui/backend/main.py`

**Modify:** `fetch_logs` endpoint to fetch all log types

```python
@app.post("/api/logs/fetch", response_model=LogsResponse)
async def fetch_logs(request: FetchLogsRequest, token: str = Query(...)):
    # ... existing code ...

    # Fetch all log types
    login_logs = fetcher.fetch_login_logs(hours_back=request.hours_back)
    saml_logs = fetcher.fetch_saml_logs(hours_back=request.hours_back)
    token_logs = fetcher.fetch_token_logs(hours_back=request.hours_back)

    # Combine into unified event stream
    all_events = {
        'login': login_logs,
        'saml': saml_logs,
        'token': token_logs
    }

    # Process and save...
```

### 5.4 Testing Strategy

#### Unit Tests
```python
# tests/test_saml_detections.py
def test_detect_saml_assertion_abuse():
    # Test rapid app switching
    # Test geographic anomaly
    # Test temporal anomaly
    pass

# tests/test_oauth_detections.py
def test_detect_oauth_token_abuse():
    # Test token IP != grant IP
    # Test excessive API calls
    # Test sensitive scope access
    pass
```

#### Integration Tests
```python
# tests/test_saml_oauth_pipeline.py
def test_end_to_end_saml_analysis():
    # Fetch SAML logs
    # Run tier-1 detection
    # Verify anomaly structure
    # Run tier-2 analysis
    # Verify output format
    pass
```

#### Manual Testing Checklist
- [ ] Collect sample SAML/OAuth logs (30 days lookback)
- [ ] Run tier-1 detection on samples
- [ ] Verify anomalies are generated for suspicious patterns
- [ ] Run tier-2 analysis on detected anomalies
- [ ] Verify forensic narratives are detailed and accurate
- [ ] Test web UI displays SAML/OAuth events correctly
- [ ] Verify drawer shows tier-2 analysis for SAML/OAuth anomalies

---

## Phase 6: Documentation & Rollout

### 6.1 User Documentation

**Create:** `documentation/SAML_OAUTH_DETECTION_GUIDE.md`

**Contents:**
- What SAML/OAuth events are monitored
- Which attack patterns are detected
- How to interpret SAML/OAuth anomalies
- Example scenarios (legitimate vs. malicious)
- How to respond to alerts

### 6.2 Developer Documentation

**Create:** `documentation/SAML_OAUTH_DEVELOPER_NOTES.md`

**Contents:**
- Event field reference for SAML/token logs
- Detection rule design patterns
- Agent prompt engineering tips
- How to add new SAML/OAuth detection rules

### 6.3 Rollout Plan

**Week 1: Silent Monitoring**
- Deploy SAML/OAuth log collection
- Run detections but don't display in UI yet
- Analyze false positive rate
- Tune detection thresholds

**Week 2: Tier-1 Rollout**
- Enable SAML/OAuth anomaly display in UI
- Monitor user feedback
- Adjust detection sensitivity

**Week 3: Tier-2 Rollout**
- Enable AI agents for SAML/OAuth anomalies
- Review agent narratives for accuracy
- Refine agent prompts based on real data

---

## Success Metrics

### Coverage Metrics
- [ ] SAML events are being collected (>0 events if SSO is used)
- [ ] OAuth/token events are being collected
- [ ] 5+ tier-1 detection rules for SAML/OAuth implemented
- [ ] 2 specialized tier-2 agents operational

### Accuracy Metrics
- [ ] False positive rate < 10% for SAML detections
- [ ] False positive rate < 10% for OAuth detections
- [ ] Tier-2 agents correctly classify 90%+ of anomalies

### Operational Metrics
- [ ] SAML/OAuth analysis adds < 5 seconds to total analysis time
- [ ] No API rate limit errors from additional log types
- [ ] Web UI displays SAML/OAuth events without performance degradation

---

## Risk Mitigation

### Risk 1: No SAML/OAuth Events in Workspace
**Likelihood:** Medium
**Mitigation:** Document that these features require SSO or OAuth app usage; provide guidance on generating test events

### Risk 2: API Rate Limits from Multiple Log Types
**Likelihood:** Low
**Mitigation:** Implement rate limiting and exponential backoff; batch requests

### Risk 3: High False Positive Rate
**Likelihood:** Medium
**Mitigation:** Start with conservative thresholds; use 30-day baseline before flagging anomalies

### Risk 4: Agent Hallucination on Unfamiliar Event Types
**Likelihood:** Low
**Mitigation:** Provide extensive examples in agent prompts; validate agent outputs during testing phase

---

## Next Steps (Immediate Actions)

### Action 1: Collect Sample Data ⏳
```bash
cd workspace_log_analyzer
venv/Scripts/python.exe collect_saml_oauth_samples.py
```

**Expected Time:** 2-5 minutes
**Output:** Sample JSON files in `samples/` directory

### Action 2: Analyze Sample Structure 📊
- Open `samples/saml_events_sample.json`
- Open `samples/token_events_sample.json`
- Identify key fields for detection
- Document suspicious patterns

**Expected Time:** 15-30 minutes

### Action 3: Begin Tier-1 Implementation 🔨
- Create first detection method: `T1550_001_saml_assertion_abuse.py`
- Test on sample data
- Iterate based on results

**Expected Time:** 30-60 minutes

---

## Dependencies

### Google Workspace Requirements
- Admin SDK API enabled (already configured)
- Reports API scopes (already granted)
- At least one SAML-integrated app (for testing)
- OAuth app usage (for testing)

### Code Dependencies
- `fetch_logs.py` - Updated ✅
- `tier1_detection/detector.py` - Needs update
- `tier2_analysis/agent_router.py` - Needs update
- `web-ui/backend/main.py` - Needs update

### External APIs
- Anthropic Claude API (already configured)
- AbuseIPDB (already configured)
- VirusTotal (already configured)
- IPInfo (already configured)

---

## Appendix A: SAML Event Types (Expected)

Based on Google's documentation:

- `saml_login` - User authenticated via SAML SSO
- `saml_logout` - User logged out of SAML session
- `saml_assertion` - SAML assertion created/validated
- `change_saml_service_provider_certificate` - SP certificate changed

## Appendix B: OAuth/Token Event Types (Expected)

Based on Google's documentation:

- `authorize` - OAuth consent granted
- `change_application_setting` - OAuth app settings modified
- `revoke` - OAuth token revoked
- `api_access` - API accessed using token
- `create_api_client` - New API client created

## Appendix C: Reference Links

- [Google Reports API - SAML Events](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/saml)
- [Google Reports API - Token Events](https://developers.google.com/admin-sdk/reports/v1/appendix/activity/token)
- [MITRE ATT&CK - T1550.001](https://attack.mitre.org/techniques/T1550/001/)
- [MITRE ATT&CK - T1528](https://attack.mitre.org/techniques/T1528/)
- [MITRE ATT&CK - T1556.007](https://attack.mitre.org/techniques/T1556/007/)
- [MITRE ATT&CK - T1199](https://attack.mitre.org/techniques/T1199/)
