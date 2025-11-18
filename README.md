# Google Workspace Authentication Log Analyzer

A small leadrning project I've been working on to explore the uses and limits of LLM-based security event investigation using primarily Google Auth logs from Workspace. Developed using Claude Code (mostly Sonnet 4.5) in Cursor.

The tool is a multi-agent AI security analysis system that fetches Google Workspace authentication logs, enriches them with threat intelligence from multiple sources, and uses specialized AI agents to detect and analyze security anomalies with contextual awareness.

## Features

- **Automated Log Fetching**: Pulls authentication logs from Google Workspace Admin SDK
- **Multi-Source Enrichment**: Integrates threat intelligence from:
  - **AbuseIPDB**: IP reputation and abuse confidence scoring
  - **VirusTotal**: Multi-engine malware/threat detection
  - **IPInfo.io**: Enhanced geolocation with VPN/proxy/Tor detection
  - **Google Directory API**: User context (admin status, 2FA enrollment)
  - **Historical Baseline**: Pattern learning and deviation detection
- **Multi-Agent Analysis**: Specialized AI sub-agents for different anomaly types
- **False Positive Filtering**: Context-aware analysis to distinguish real threats from expected behavior
- **Executive Reporting**: Comprehensive markdown reports with risk assessment and recommendations

## Architecture

```
┌─────────────────┐
│  fetch_logs.py  │  Fetches logs from Google Workspace
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ enrichment.py   │  Enriches with 4 data sources
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ analyze_logs.py │  Primary anomaly detection
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│ orchestrator_automated  │  Routes to specialized sub-agents
└────────┬────────────────┘
         │
         ▼
┌─────────────────────┐
│ report_aggregator   │  Generates executive report
└─────────────────────┘
```

## Setup

### 1. Install Dependencies

Create and activate a virtual environment:

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

Install required packages:

```bash
pip install -r requirements.txt
```

### 2. Configure Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create or select your project
3. Enable the **Admin SDK API**:
   - Navigate to "APIs & Services" > "Library"
   - Search for "Admin SDK API"
   - Click "Enable"

### 3. Create OAuth 2.0 Credentials

1. In Google Cloud Console, go to "APIs & Services" > "Credentials"
2. Click "Create Credentials" > "OAuth client ID"
3. Choose "Desktop app" as application type
4. Download the credentials JSON file
5. Rename it to `credentials.json` and place it in this directory

### 4. Configure API Keys (Optional but Recommended)

For enhanced threat intelligence, create accounts and get API keys:

1. **AbuseIPDB** (free tier available): https://www.abuseipdb.com/
2. **VirusTotal** (free tier available): https://www.virustotal.com/
3. **IPInfo.io** (free tier available): https://ipinfo.io/

### 5. Configure Environment

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your settings:
   ```env
   # Google Workspace Configuration
   WORKSPACE_DOMAIN=yourdomain.com
   ADMIN_USER_EMAIL=admin@yourdomain.com
   LOG_HOURS_BACK=24

   # API Keys (optional but recommended)
   ABUSEIPDB_API_KEY=your_key_here
   VIRUSTOTAL_API_KEY=your_key_here
   IPINFO_API_KEY=your_key_here

   # Feature Flags
   ENABLE_IP_REPUTATION=true
   ENABLE_GEOLOCATION=true
   ENABLE_USER_CONTEXT=true
   ENABLE_BASELINE_TRACKING=true
   ```

## Usage

You can use this tool in two ways:
1. **Web Interface** (Recommended): Modern browser-based UI with Google OAuth
2. **Command Line**: Python scripts for automation and CI/CD

### Web Interface

The web interface provides an intuitive, browser-based way to analyze your Google Workspace authentication logs with real-time analysis and interactive results.

#### Starting the Web Interface

**1. Install Frontend Dependencies**

```bash
cd web-ui/frontend
npm install
cd ../..
```

**2. Start the Backend Server**

```bash
# From the project root directory
cd web-ui/backend
../../venv/Scripts/python.exe main.py

# You should see:
# INFO:     Uvicorn running on http://0.0.0.0:8000
```

**3. Start the Frontend Development Server**

Open a new terminal:

```bash
cd web-ui/frontend
npm run dev

# You should see:
# VITE v5.x.x  ready in xxx ms
# ➜  Local:   http://localhost:5173/
```

**4. Access the Web UI**

Open your browser to: **http://localhost:5173**

#### Using the Web Interface

**Step 1: Sign In with Google**

1. Click "Sign in with Google" button
2. Select your Google Workspace admin account
3. Grant the requested permissions:
   - View audit reports for your domain
   - View user information on your domain
   - View your email address
4. You'll be redirected back to the dashboard

**Step 2: Fetch Authentication Logs**

1. Select a **lookback period** from the dropdown:
   - Last 1 hour
   - Last 6 hours
   - Last 12 hours
   - Last 24 hours (default)
   - Last 48 hours
   - Last 72 hours
   - Last 7 days

2. Click **"Fetch Logs"** button

3. Wait for the fetch to complete (you'll see a green success message):
   ```
   ✓ Successfully fetched N events
   Period: X hours requested • Y hours of actual events
   ```

**Step 3: Automatic Tier-2 AI Analysis**

The system automatically runs tier-2 AI analysis on suspicious events:

1. **Blue spinning indicator** appears:
   ```
   Running tier-2 AI analysis on suspicious events...
   Deep analysis in progress - this may take a moment
   ```

2. **Analysis completion message** shows results:
   - **Green message** if all events are benign:
     ```
     ✓ Tier-2 analysis complete: All suspicious events analyzed as benign
     ```
   - **Red message** if actual threats detected:
     ```
     ⚠️ Tier-2 analysis complete: N actual threat(s) detected
     ```

**Step 4: Review Events in the Table**

The events table displays all authentication events with the following indicators:

| Icon | Color | Meaning |
|------|-------|---------|
| 🛡️ (Blue Shield) | Blue row background | Event analyzed by tier-2 AI and confirmed **benign** |
| ⚠️ (Red Triangle) | Red row background | Event analyzed by tier-2 AI and flagged as **actual threat** |
| (No icon) | White row background | Event not flagged as suspicious by initial detection |

**Table Features:**
- **Search**: Type in the search box to filter events by any field
- **Sort**: Click column headers to sort by that field
- **Risk Score**: Color-coded risk scores (green = low, yellow = medium, red = high)
- **Pagination**: Navigate through pages at the bottom of the table

**Step 5: View Detailed Analysis**

Click on any **analyzed event** (with blue shield or red triangle icon) to open the analysis drawer:

**Analysis Drawer Contents:**

1. **Event Details**
   - Timestamp, user email, IP address
   - Event type (login_success, login_failure, login_verification)
   - Geographic location and ISP information
   - Risk score and reputation data

2. **AI Analysis Results** (for analyzed events)
   - **Threat Assessment**: Actual risk status (Yes/No)
   - **Confidence Level**: High/Medium/Low
   - **Likely Scenario**: Description of what the AI determined (e.g., "trusted_device", "legitimate_travel", "brute_force_attack")
   - **Detailed Reasoning**: Full explanation of why the AI made this determination
   - **Recommendations**: Specific actions to take (or confirmation that no action is needed)

3. **Enrichment Context**
   - IP reputation scores from AbuseIPDB and VirusTotal
   - User context (admin status, 2FA enrollment)
   - Geographic and network information
   - Baseline comparison (deviations from typical behavior)

**Step 6: Understanding the Dashboard Stats**

The dashboard displays four key metrics:

- **Total Events**: All authentication events in the selected period
- **Unique Users**: Number of distinct users who authenticated
- **Unique IPs**: Number of distinct IP addresses used
- **Suspicious Events**: Number of events that received tier-2 AI analysis

#### Web Interface Architecture

The web UI consists of two components that work together:

**Backend (FastAPI)**
- **Port**: 8000
- **Purpose**: REST API that wraps the Python analysis modules
- **Functions**:
  - Handles Google OAuth authentication flow
  - Executes `fetch_logs.py` to retrieve authentication logs
  - Runs `orchestrator_automated.py` for tier-2 AI analysis
  - Serves log and analysis data to the frontend

**Frontend (React + Vite)**
- **Port**: 5173
- **Purpose**: Modern, interactive user interface
- **Technologies**:
  - React 18 with TypeScript
  - TanStack Table for data display
  - TanStack Query for API state management
  - Tailwind CSS for styling

**Key Features:**
- ✅ Automatic analysis after log fetch
- ✅ Real-time progress indicators
- ✅ Color-coded risk visualization
- ✅ Interactive event details drawer
- ✅ Sortable and searchable event table
- ✅ Pagination for large datasets

#### Web UI Troubleshooting

**Backend Not Starting:**
```bash
# Make sure you're in the right directory and using the venv
cd web-ui/backend
../../venv/Scripts/python.exe main.py

# Check for missing dependencies:
../../venv/Scripts/python.exe -m pip install fastapi uvicorn[standard]
```

**Frontend Not Starting:**
```bash
# Make sure dependencies are installed
cd web-ui/frontend
npm install

# Try clearing cache and rebuilding
rm -rf node_modules
npm install
npm run dev
```

**OAuth Issues:**
- The OAuth client may show the name from a previous project (this is cosmetic and doesn't affect functionality)
- To update the OAuth consent screen name:
  1. Go to Google Cloud Console > APIs & Services > OAuth consent screen
  2. Edit the application name

**Session Cleared After Backend Restart:**
- Backend uses in-memory sessions for development
- You'll need to sign out and sign in again after restarting the backend
- This is expected behavior for local development

**Analysis Not Running:**
- Check browser console (F12) for error messages
- Verify both backend and frontend are running
- Check backend terminal for analysis execution logs

#### Tier-2 AI Analysis: How It Works

The system uses a two-tier detection approach to minimize false positives while catching real threats.

**Tier-1: Initial Detection Criteria**

Events are flagged for tier-2 AI analysis if they match ANY of these rule-based patterns:

1. **Missing MFA Detection**
   - **Criteria**: Login verification events where `is_second_factor` is `false` or `null`
   - **Why flagged**: Could indicate bypassed 2FA or account compromise
   - **Example**: User logs in without completing second factor authentication
   - **Code location**: `analyze_logs.py:68-85`

2. **Multiple Geographic Locations**
   - **Criteria**: User authenticates from 2+ different countries/regions in the same session
   - **Why flagged**: Could indicate impossible travel or account sharing
   - **Example**: Login from New York at 10:00 AM, then from London at 10:15 AM
   - **Code location**: `analyze_logs.py:122-138`

3. **Failed Login Patterns**
   - **Criteria**: One or more `login_failure` events for a user
   - **Why flagged**: Could indicate brute force attack or credential stuffing
   - **Example**: 3 failed login attempts followed by a success
   - **Code location**: `analyze_logs.py:142-174`

4. **Rapid Retry After Failure**
   - **Criteria**: Successful login within 10 seconds of a failed login from same IP
   - **Why flagged**: Extremely fast retry suggests automated attack tools
   - **Example**: Failed login at 10:00:00, success at 10:00:03
   - **Code location**: `analyze_logs.py:212-227`

**Important**: These are intentionally sensitive patterns that will generate false positives. This is by design - tier-2 AI analysis filters them out.

**Tier-2: AI Analysis Steps**

When an event is flagged by tier-1 detection, it's routed to a specialized sub-agent for deep contextual analysis:

**Step 1: Sub-Agent Selection** (`orchestrator_automated.py:102-137`)

Each anomaly type is routed to a specialized sub-agent:

| Anomaly Type | Sub-Agent | Specialization |
|--------------|-----------|----------------|
| `missing_mfa` | `mfa_context_analyzer` | MFA behavior and trusted device scenarios |
| `multiple_locations` | `geographic_analyzer` | Travel patterns and VPN detection |
| `failed_login` | `failed_login_analyzer` | Brute force vs. user error distinction |
| `rapid_retry` | `failed_login_analyzer` | Automated vs. human retry timing |

**Step 2: Context Enrichment**

The sub-agent receives a comprehensive data package including:

1. **Anomaly Details**
   - Type, severity, description
   - Specific events that triggered the detection
   - Initial severity assessment

2. **Enriched Event Data**
   - **IP Reputation** (AbuseIPDB + VirusTotal):
     - Overall risk score (0-100)
     - Abuse confidence level
     - Known malicious activity
     - Tor/VPN/proxy detection

   - **User Context** (Google Directory API):
     - Admin privileges status
     - 2FA enrollment and enforcement
     - Organizational unit
     - Account creation date
     - Last login timestamp

   - **Geographic Intelligence** (IPInfo.io):
     - City, region, country
     - ISP and ASN information
     - Timezone
     - Hosting/cloud provider detection

   - **Historical Baseline**:
     - User's typical IP addresses
     - User's typical geographic regions
     - Deviation indicators

3. **Context Questions**
   - Sub-agent-specific questions to guide analysis
   - Example for MFA: "Could this be a trusted device scenario?"
   - Example for geographic: "Is this consistent with legitimate travel?"

**Step 3: AI Reasoning** (`orchestrator_automated.py:144-202`)

The specialized sub-agent (powered by Claude AI) performs structured analysis:

1. **Evidence Review**
   - Analyzes all provided enrichment data
   - Considers temporal patterns (timing of events)
   - Evaluates geographic and network context
   - Reviews user's historical behavior baseline

2. **Scenario Identification**
   - Determines the most likely explanation for the anomaly
   - Examples:
     - `trusted_device`: User on previously verified device with valid session
     - `legitimate_travel`: Real user traveling for business/vacation
     - `user_error`: Legitimate user made typo in password
     - `brute_force_attack`: Automated attack pattern detected
     - `credential_stuffing`: Stolen credentials being tested

3. **Risk Assessment**
   - **is_actual_risk**: Boolean determination (true/false)
   - **confidence**: High/Medium/Low confidence in assessment
   - **adjusted_severity**: Final severity rating (low/medium/high)

4. **Reasoning Documentation**
   - Multi-paragraph explanation of the decision
   - Specific evidence citations
   - Explanation of why alternative scenarios were ruled out

5. **Recommendations**
   - Specific actions to take (for actual threats)
   - Confirmation that no action is needed (for false positives)
   - Optional preventive measures

**Step 4: Response Integration** (`orchestrator_automated.py:203-230`)

The orchestrator integrates sub-agent responses back into the anomaly records:

1. Matches sub-agent responses to original anomalies by ID
2. Updates severity based on AI assessment
3. Adds `is_actual_risk` flag for filtering
4. Preserves original detection for audit trail
5. Generates summary statistics:
   - Total initial detections
   - Number refined as actual risks
   - Number identified as false positives

**Example: MFA Context Analysis**

Let's walk through how a missing MFA event is analyzed:

**Initial Detection (Tier-1):**
```json
{
  "id": "ANOM-MFA-001",
  "type": "missing_mfa",
  "severity": "high",
  "description": "No second factor detected in login verification events"
}
```

**Context Provided to Sub-Agent:**
- User: jordan@company.com
- IP: 99.209.227.194 (Rogers Communications, Toronto)
- Time: 10:07 AM EST
- User has 2FA enabled in admin console
- Same IP used for last 10 logins
- Same geographic region (Toronto) for 30 days
- No suspicious flags from Google

**AI Analysis Process:**

1. **Reviews Evidence**:
   - Checks if `is_second_factor=false` means missing 2FA or is first factor verification
   - Notes that login_type='reauth' (re-authentication within existing session)
   - Observes consistent IP and location (no travel anomaly)

2. **Identifies Scenario**:
   - This is `trusted_device` behavior
   - Google Workspace allows re-authentication without full 2FA on trusted devices
   - Initial 2FA was completed in a previous session

3. **Makes Determination**:
   - `is_actual_risk: false`
   - `confidence: high`
   - `adjusted_severity: low`

4. **Provides Reasoning**:
   > "This is NOT a security risk. The is_second_factor=false flag indicates password verification (first factor), not missing 2FA. The reauth login_type shows this is re-authentication within an existing session on a trusted device. Google Workspace does not require full 2FA for re-auth on devices that previously completed 2FA verification..."

5. **Recommends**:
   > "No action required. This is normal behavior for Google Workspace with 2FA enforcement enabled and trusted devices allowed..."

**Result in Web UI:**
- Event shows **blue shield icon** (benign)
- Row has **blue background**
- Clicking event shows full AI reasoning
- Dashboard shows "0 actual threats detected"

This two-tier approach ensures:
- ✅ No real threats slip through (sensitive tier-1 rules)
- ✅ Minimal alert fatigue (AI filters false positives)
- ✅ Full transparency (complete reasoning provided)
- ✅ Audit trail (both tiers preserved in logs)

### Command Line Interface

The full analysis workflow consists of three steps:

#### Step 1: Fetch and Enrich Logs

```bash
python main.py
```

**What happens:**
- Authenticates with Google Workspace (opens browser on first run)
- Fetches authentication logs for the specified time period
- Enriches each event with threat intelligence from 4 data sources
- Saves enriched logs to `logs/auth_logs_YYYYMMDD_HHMMSS.json`

**Output:**
```
Google Workspace Log Analyzer
------------------------------------------------------------
Domain: yourdomain.com
Looking back: 24 hours
------------------------------------------------------------

[OK] Successfully authenticated with Google Workspace
Fetching login logs from the last 24 hours...
[OK] Successfully fetched 5 login events

[Enrichment] Adding contextual data...
  Enriching 1 unique IPs and 1 unique users...
[OK] Enrichment complete
[OK] Logs saved to: logs\auth_logs_20251002_142537.json
```

#### Step 2: Run Automated Multi-Agent Analysis

```bash
python orchestrator_automated.py logs/auth_logs_20251002_142537.json
```

**What happens:**
- Primary detector identifies potential anomalies using rule-based patterns
- Routes each anomaly to specialized sub-agents:
  - **mfa_context_analyzer**: Analyzes MFA behavior and trusted device scenarios
  - **geographic_analyzer**: Detects impossible travel and location anomalies
  - **failed_login_analyzer**: Distinguishes attacks from user errors
- Sub-agents use enriched context to assess actual risk
- Aggregates refined assessments with false positive filtering
- Saves analysis to `analysis/automated_analysis_YYYYMMDD_HHMMSS.json`

**Output:**
```
AUTOMATED MULTI-AGENT LOG ANALYSIS
============================================================

[Step 1/4] Running primary anomaly detection...
  Detected 3 potential anomalies

[Step 2/4] Executing specialized sub-agents (automated)...
  Found 2 sub-agent types to execute
  Executing mfa_context_analyzer for 1 anomalies...
  Executing failed_login_analyzer for 2 anomalies...

[Step 3/4] Aggregating sub-agent analyses...
  Found 1 sub-agent responses

[Step 4/4] Generating comprehensive analysis report...

SUMMARY:
  Initial detections: 3
  After sub-agent refinement: 1
  Actual risks: 0
  False positives filtered: 1
```

#### Step 3: Generate Executive Report

```bash
python report_aggregator.py analysis/automated_analysis_20251002_142537.json
```

**What happens:**
- Aggregates multi-agent analysis into executive summary
- Calculates overall risk level
- Generates prioritized recommendations
- Creates comprehensive markdown report
- Saves to `analysis/automated_analysis_YYYYMMDD_HHMMSS_report.md`

**Output:**
```
[OK] Executive report saved: analysis/automated_analysis_20251002_142537_report.md

Executive Report Generated!
```

### Understanding the Analysis

The system performs several layers of analysis:

#### Layer 1: Primary Detection (Rule-Based)

Fast pattern matching identifies potential anomalies:
- Missing MFA events
- Multiple geographic regions
- Failed login patterns
- Rapid retry attempts

#### Layer 2: Data Enrichment

Each event is enriched with contextual data:

**IP Reputation:**
- Risk score (0-100) from AbuseIPDB and VirusTotal
- Malicious activity indicators
- Tor/VPN/proxy detection

**User Context:**
- Admin privileges
- 2FA enrollment and enforcement status
- Organizational unit

**Geographic Data:**
- City, region, country, timezone
- ISP and ASN information
- Hosting/cloud provider detection

**Historical Baseline:**
- User's typical IPs and locations
- Deviation detection from established patterns

#### Layer 3: Sub-Agent Analysis

Specialized AI agents analyze each anomaly type:

**MFA Context Analyzer:**
- Understands trusted device scenarios
- Distinguishes between missing 2FA vs. trusted device behavior
- Checks Directory API for actual 2FA enrollment
- Evaluates session re-authentication patterns

**Geographic Analyzer:**
- Calculates impossible travel based on timestamps
- Identifies VPN/proxy usage patterns
- Distinguishes legitimate travel from account compromise

**Failed Login Analyzer:**
- Distinguishes brute force from user typos
- Detects credential stuffing patterns
- Evaluates retry timing (automated vs. human)

#### Layer 4: Report Aggregation

Synthesizes all analyses into actionable intelligence:
- Executive summary with key findings
- Overall risk level assessment
- Detailed findings by severity
- Prioritized recommendations
- Technical appendix with methodology

## Analysis Output Examples

### Executive Report Structure

```markdown
# Google Workspace Authentication Security Analysis
**Generated:** 2025-10-02 14:26:27

## Executive Summary
**Requested Analysis Period:** Last 24 hours
**Actual Event Window:** 2025-10-02 15:02:35 UTC to 2025-10-02 15:07:52 UTC (0.09 hours)
**Total Authentication Events:** 5

### Key Findings
[OK] **No significant security risks detected**
- 3 potential anomalies investigated
- All findings assessed as low-risk or expected behavior
- 1 false positives successfully filtered by AI analysis

## Risk Assessment
### Overall Risk Level: [LOW] **LOW**

## Detailed Findings
### [LOW] Low Severity Findings
#### Finding 1: Missing Mfa
**Description:** No second factor authentication detected...
**AI Analysis:**
- Actual Risk: No
- Scenario: trusted_device
- Confidence: HIGH
*Reasoning:* [Detailed contextual analysis...]

## Recommendations
[OK] **No immediate actions required**
**Ongoing Best Practices:**
- Continue monitoring authentication logs regularly
- Maintain 2FA enforcement for all users

## Appendix
### Analysis Methodology
[Technical details about multi-agent system...]
```

## Project Structure

```
workspace_log_analyzer/
├── .env                          # Configuration (not tracked)
├── .env.example                  # Configuration template
├── .gitignore                    # Git ignore rules
├── requirements.txt              # Python dependencies
├── README.md                     # This file
│
├── credentials.json              # OAuth client credentials (not tracked)
├── token.json                    # OAuth access tokens (not tracked)
│
├── main.py                       # Entry point: fetch and enrich logs (CLI)
├── fetch_logs.py                 # Google Workspace API client
├── enrichment.py                 # Multi-source data enrichment
├── analyze_logs.py               # Primary anomaly detection + sub-agent prompts
├── orchestrator_automated.py     # Automated multi-agent orchestration
├── report_aggregator.py          # Executive report generation
│
├── web-ui/                       # Web interface components
│   ├── backend/                  # FastAPI REST API server
│   │   ├── main.py               # API endpoints and OAuth flow
│   │   └── requirements.txt      # Backend Python dependencies
│   │
│   └── frontend/                 # React + TypeScript UI
│       ├── src/
│       │   ├── pages/            # Dashboard and login pages
│       │   ├── components/       # Reusable UI components
│       │   ├── lib/              # API client and utilities
│       │   ├── App.tsx           # Root component
│       │   └── main.tsx          # Entry point
│       ├── package.json          # Frontend Node.js dependencies
│       ├── vite.config.ts        # Vite build configuration
│       └── tailwind.config.js    # Tailwind CSS configuration
│
├── logs/                         # Fetched logs (not tracked)
│   └── auth_logs_*.json          # Enriched authentication logs
│
└── analysis/                     # Analysis results (not tracked)
    ├── automated_analysis_*.json     # Multi-agent analysis results
    ├── automated_analysis_*_report.md # Executive reports
    └── sub_agent_responses/          # Individual sub-agent assessments
```

## Anomaly Types Detected

| Type | Description | Sub-Agent |
|------|-------------|-----------|
| **missing_mfa** | No second factor detected in verification events | mfa_context_analyzer |
| **multiple_locations** | Authentication from multiple geographic regions | geographic_analyzer |
| **failed_login** | Failed login attempts requiring investigation | failed_login_analyzer |
| **rapid_retry** | Quick retry after failure (potential automation) | failed_login_analyzer |

## Security & Privacy

### Data Handling
- **Read-Only Access**: Uses read-only OAuth scopes for Google Workspace
- **Local Storage**: All logs and analysis stored locally
- **No External Transmission**: Enrichment APIs receive only IP addresses (not user data)
- **Sensitive Data**: Logs contain authentication details - handle appropriately

### OAuth Scopes Used
```
https://www.googleapis.com/auth/admin.reports.audit.readonly
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.device.mobile.readonly
```

### Enrichment API Privacy
- **AbuseIPDB**: Receives only IP addresses
- **VirusTotal**: Receives only IP addresses
- **IPInfo.io**: Receives only IP addresses
- **Directory API**: Google-to-Google communication only

## Troubleshooting

### Authentication Errors

If you encounter OAuth authentication issues:
```bash
# Delete the token and re-authenticate
rm token.json
python main.py
```

Verify:
1. Admin SDK API is enabled in Google Cloud Console
2. Your user has admin privileges in Google Workspace
3. OAuth credentials are for "Desktop app" type

### Missing Enrichment Data

If enrichment is failing:
1. Check API keys in `.env` file
2. Verify feature flags are set to `true`
3. Check API rate limits (free tiers have daily limits)
4. The system will gracefully degrade - logs will still be fetched

### No Logs Returned

If no authentication events are found:
- Verify the time range in `.env` (LOG_HOURS_BACK)
- Check that users actually logged in during the specified timeframe
- Ensure your account has permission to view audit logs
- Try expanding the time window (e.g., 48 or 72 hours)

### Sub-Agent Analysis Not Running

If sub-agent responses aren't being integrated:
1. Check that `analysis/sub_agent_responses/` directory exists
2. Manually create sub-agent response files following the format in automated_tasks/
3. For manual sub-agent execution, use prompts from `orchestrator_automated.py`

## Advanced Usage

### Custom Time Ranges

Edit `.env` to change the lookback period:
```env
LOG_HOURS_BACK=48  # Fetch last 48 hours
```

### Disable Enrichment

To fetch logs without enrichment (faster, no API keys needed):
```env
ENABLE_IP_REPUTATION=false
ENABLE_GEOLOCATION=false
ENABLE_USER_CONTEXT=false
ENABLE_BASELINE_TRACKING=false
```

### Historical Baseline Training

The system automatically builds user baselines. For best results:
1. Run log fetching regularly (daily recommended)
2. Baseline tracker learns from `analysis/baseline_data.json`
3. After 7-10 days, deviation detection becomes more accurate

## Contributing

This is a personal security analysis tool. Contributions welcome via pull requests.

## License

MIT License - See LICENSE file for details

## Acknowledgments

- **Google Workspace Admin SDK**: Authentication log data
- **AbuseIPDB**: IP reputation database
- **VirusTotal**: Multi-engine threat intelligence
- **IPInfo.io**: Geolocation and network intelligence
- **Anthropic Claude**: AI-powered contextual analysis
