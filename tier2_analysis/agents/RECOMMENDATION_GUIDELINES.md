# Agent Recommendation Guidelines

## Purpose

This document provides standardized guidelines for all tier-2 AI agents to ensure they produce **specific, actionable recommendations** rather than vague guidance.

## Core Principle

**SPECIFIC > VAGUE**

❌ **Bad:** "Monitor user activity"
✅ **Good:** "Set up real-time alerting in Google Workspace Admin Console (Security > Alert Center) for this user's account for the next 7 days to detect any suspicious password changes or privilege escalations"

❌ **Bad:** "Review security settings"
✅ **Good:** "Navigate to Google Workspace Admin Console > Security > Authentication > 2-Step Verification and enforce MFA for all users in the 'Administrators' organizational unit within 24 hours"

---

## Recommendation Framework

Every recommendation should answer:

1. **WHAT** - The specific action to take
2. **WHERE** - The exact console/tool/location to perform it
3. **HOW** - Step-by-step instructions if complex
4. **WHY** - Brief rationale tied to the threat assessment
5. **WHEN** - Timeline or urgency level

---

## Standard Recommendation Patterns

### Pattern 1: Google Workspace Admin Console Actions

**Template:**
```
Navigate to Google Workspace Admin Console > [Menu Path] and [Specific Action] for [Specific Scope] because [Reason based on analysis].
```

**Examples:**

**MFA Enforcement:**
```
Navigate to Google Workspace Admin Console > Security > Authentication > 2-Step Verification
and enable enforcement for the '/Administrators' organizational unit. This prevents future
authentication bypasses like the one detected in this event.
```

**Session Management:**
```
Navigate to Google Workspace Admin Console > Security > Session Control and set 'Re-authentication
frequency' to 4 hours for users in high-privilege groups. This limits the window for session
hijacking attacks.
```

**Device Trust:**
```
Navigate to Google Workspace Admin Console > Devices > Mobile Devices, locate the device with
IP 203.0.113.45, and verify it appears in the trusted device list. If not found, require
re-enrollment via 'Actions > Require re-enrollment'.
```

---

### Pattern 2: Alert Configuration

**Template:**
```
Configure real-time alerting in [Tool] for [Specific Event Type] affecting [Specific Users/Resources]
to detect [Specific Attack Pattern].
```

**Examples:**

**Credential Abuse Monitoring:**
```
Configure real-time alerting in Google Workspace Admin Console (Security > Alert Center >
Manage Rules > Create Rule) for:
- Event Type: 'Suspicious login'
- Scope: user@domain.com
- Notification: Email to security@domain.com
- Duration: 30 days

This monitors for credential stuffing attempts targeting this account.
```

**Geographic Anomaly Detection:**
```
In Google Workspace Admin Console > Reports > Audit > Admin, create a saved filter for
login events from countries outside [US, UK] for VIP users. Schedule daily review at
9 AM EST to catch impossible travel patterns.
```

---

### Pattern 3: User Account Actions

**Template:**
```
For user [email], perform [Specific Action] in [Location] because [Threat-Specific Reason],
then [Follow-up Action].
```

**Examples:**

**Password Reset:**
```
For user jordan@domain.com, navigate to Google Workspace Admin Console > Directory > Users >
[Select User] > Security > 'Reset Password' and enable 'User must change password at next sign-in'.
This invalidates any potentially compromised credentials. After reset, verify MFA devices
via 'Security > 2-Step Verification' and remove any unrecognized authenticators.
```

**Privilege Review:**
```
For user jordan@domain.com, navigate to Google Workspace Admin Console > Directory > Users >
[Select User] > Admin roles and verify the 'Super Admin' role is justified. If this user
doesn't require Super Admin for daily tasks, reduce to 'User Management Admin' or a custom
role with principle of least privilege.
```

**Session Revocation:**
```
For user jordan@domain.com, navigate to Google Workspace Admin Console > Directory > Users >
[Select User] > Security > 'Sign out of all web sessions' to immediately terminate any
active sessions. This prevents session hijacking if credentials were exposed.
```

---

### Pattern 4: Investigation Actions

**Template:**
```
Review [Specific Log Source] for [Date/Time Range] focusing on [Specific Indicators] to
[Investigation Goal]. Expected findings: [What to look for].
```

**Examples:**

**Login Audit:**
```
Review Google Workspace Admin Console > Reports > Audit > Admin for Oct 27, 2025
14:00-16:00 UTC, filtering for user=jordan@domain.com. Look for:
- Multiple failed login attempts before successful authentication (credential stuffing)
- Different User-Agent strings in rapid succession (automation)
- Access to sensitive Google Drive files immediately after login (data exfiltration)

If found, escalate to incident response team immediately.
```

**Device Correlation:**
```
Cross-reference this login (IP: 203.0.113.45) with Google Workspace Admin Console >
Devices > Mobile Devices to identify the device used. Check:
- Device compliance status (should be 'Compliant')
- Last sync time (should be within 24 hours)
- Installed apps (verify no suspicious MDM/remote access apps)
```

---

### Pattern 5: External Tool Integration

**Template:**
```
In [External Tool], perform [Action] to [Goal] because [Reason]. Expected result: [What success looks like].
```

**Examples:**

**SIEM Correlation:**
```
In your SIEM (Splunk/Sentinel/Chronicle), run this query:
index=workspace_logs user="jordan@domain.com" earliest=-24h
| stats count by src_ip, event_type
| where count > 50

This identifies if the rapid re-authentication pattern seen in Google Workspace logs
correlates with high-volume API access, indicating automated credential testing.
```

**Threat Intelligence Lookup:**
```
Submit IP address 203.0.113.45 to VirusTotal (virustotal.com) and AbuseIPDB (abuseipdb.com).
If threat score > 50 or listed in 3+ blacklists, block the IP at your firewall/proxy level
immediately to prevent further access attempts.
```

---

## Specificity Checklist

Before finalizing a recommendation, verify:

- [ ] **Console path is complete** - Don't say "security settings", say "Admin Console > Security > Authentication"
- [ ] **Action is unambiguous** - "Enable MFA" vs "Navigate to 2-Step Verification and click 'Enforce 2SV'"
- [ ] **Scope is defined** - "For all users" vs "For jordan@domain.com" vs "For /Administrators OU"
- [ ] **Timeline is included** - "Within 24 hours" vs "Immediately" vs "At next monthly review"
- [ ] **Success criteria is clear** - "Verify that the setting shows 'Enforced' status"
- [ ] **Rationale ties to analysis** - Connect recommendation to specific findings in the forensic narrative

---

## Examples by Agent Type

### MFA Context Analyzer

**Scenario:** User logged in without MFA on a new device

❌ **Vague:**
```
1. Enable MFA for this user
2. Review device settings
3. Monitor future logins
```

✅ **Specific:**
```
1. Navigate to Google Workspace Admin Console > Directory > Users > jordan@everettyoung.tech >
   Security > 2-Step Verification. Verify 'Status: Enforced' is set. If not, click 'Edit' and
   select 'Enforcement: On' then 'Save'. This ensures all future logins require MFA.

2. In the same screen, review 'Backup codes' section. If codes show 'Last used: Never', the
   user may have registered a device as 'trusted' which bypassed MFA. Click 'Manage trusted
   devices' and revoke any devices with 'Last used' timestamps matching this login (Oct 27, 10:38 UTC).

3. Configure real-time alerting: Admin Console > Security > Alert Center > Manage Rules >
   'Suspicious login blocked' and add jordan@everettyoung.tech to the monitored users list.
   Set notification to send to security@everettyoung.tech immediately. This detects future
   authentication bypass attempts within 5 minutes.

4. Schedule a security awareness reminder: Email the user explaining that trusted devices
   should only be used for personal laptops, not public/shared computers. Reference your
   organization's acceptable use policy section 4.2 on device trust.
```

---

### Geographic Analyzer

**Scenario:** User accessed from unexpected country

❌ **Vague:**
```
1. Verify VPN usage
2. Check if travel was planned
3. Review access patterns
```

✅ **Specific:**
```
1. Contact user via verified channel (desk phone or Slack DM) and ask: "Did you access
   Google Workspace from Dallas, Texas on Oct 22 at 6:47 PM local time?" Document their
   response in your ticketing system (reference ticket #SEC-2025-1027).

2. If user confirms travel: No action needed. Add Dallas, TX to their expected locations
   in your UEBA baseline for next 30 days.

3. If user denies access: Navigate to Admin Console > Directory > Users > jordan@everettyoung.tech >
   Security > 'Sign out of all web sessions' immediately. Then reset password via 'Reset password'
   button with 'User must change password at next sign-in' enabled.

4. Check IP reputation: Visit abuseipdb.com/check/[IP] and virustotal.com/gui/ip-address/[IP].
   If threat score > 50, add IP to your firewall block list (refer to your infrastructure team's
   IP blocking procedures in Confluence: Network/Firewall Rules).

5. If this is a VPN exit node (check IP owner = Cloudflare WARP, NordVPN, etc.), verify in
   Admin Console > Devices > Mobile Devices that the user has an approved VPN client installed.
   If no VPN client is registered, this may indicate credential theft with VPN obfuscation.
```

---

### Session Analyzer

**Scenario:** Multiple rapid logins from different IPs

❌ **Vague:**
```
1. Check for session hijacking
2. Review user devices
3. Investigate suspicious activity
```

✅ **Specific:**
```
1. Access Admin Console > Reports > Audit > Admin and filter:
   - User: jordan@everettyoung.tech
   - Date: Oct 22, 2025 6:46 PM - 6:49 PM
   - Event type: login_success
   Export this report as CSV for forensic documentation.

2. Open the CSV and examine the 'ip_address' and 'user_agent' columns. The three logins show:
   - 6:46:58 PM: IP ending in :141, User-Agent: Chrome/Mac
   - 6:47:20 PM: IP ending in :2cf, User-Agent: Chrome/Mac
   - 6:48:13 PM: IP ending in :f3, User-Agent: Chrome/Mac

   All three IPs are in Dallas, TX (same /16 subnet) with identical User-Agent strings.
   This pattern is consistent with Cloudflare WARP client connection switching, which
   rotates IPs frequently while maintaining the same session.

3. Verify this interpretation: Check if user has Cloudflare WARP installed by reviewing
   Admin Console > Devices > Mobile Devices > [User's devices] > Installed apps. Look for
   'Cloudflare WARP' or '1.1.1.1' in the app list.

4. If WARP is confirmed: Mark this as benign. Document in your security log: "Rapid IP
   changes due to legitimate VPN client behavior - no action required."

5. If WARP is NOT found: Escalate as potential session hijacking. Perform steps in
   'credential_compromise_runbook.md' section 3.2 (Password reset + session revocation +
   7-day enhanced monitoring).
```

---

## Anti-Patterns to Avoid

### ❌ **Passive Voice**
Don't: "The user should be contacted"
Do: "Contact the user via their registered mobile phone at +1-555-0123"

### ❌ **Ambiguous Conditionals**
Don't: "If necessary, reset the password"
Do: "If threat score > 75 OR user denies access, reset the password immediately using [specific steps]"

### ❌ **Vague Metrics**
Don't: "Monitor for unusual activity"
Do: "Set up alerting for login attempts > 10 per hour from this user using Admin Console alert rules"

### ❌ **Missing Context**
Don't: "Check the logs"
Do: "Check Admin Console > Reports > Audit > Admin for Oct 27 14:00-16:00 UTC, filtering for event_type='login_failure'"

### ❌ **No Success Criteria**
Don't: "Configure MFA"
Do: "Configure MFA enforcement. Verify by logging into a test account and confirming you're prompted for 2FA. Expected: 'Enter verification code' screen appears."

---

## Template for New Recommendations

Use this template when creating recommendations:

```markdown
**Recommendation [N]: [Action Title]**

**What to do:**
[Specific action in imperative voice]

**Where:**
[Exact console path or tool location]

**Steps:**
1. [First specific step]
2. [Second specific step]
3. [Continue as needed]

**Why:**
[1-2 sentence explanation tied to your forensic analysis]

**Expected result:**
[What success looks like - specific status/message/state]

**Timeline:**
[Immediate / Within 24h / Weekly / As needed]

**Responsible party:**
[Security team / Admin / Manager / User]
```

---

## Testing Your Recommendations

Before returning recommendations to the user, ask:

1. **Could a junior analyst execute this?** - They shouldn't need to guess or google
2. **Is the console path copy-pasteable?** - Exact menu hierarchy provided
3. **Is there a clear stopping point?** - They know when the task is complete
4. **Is the rationale clear?** - They understand why they're doing it
5. **Are edge cases handled?** - Guidance for "if X, then Y" scenarios

If you answer "no" to any of these, make the recommendation more specific.

---

## Agent-Specific Guidance

### MFA Context Analyzer
Focus on:
- Trusted device management
- Backup code usage
- MFA enforcement policies
- Device registration flows

### Geographic Analyzer
Focus on:
- VPN detection and verification
- Travel pattern validation
- IP reputation checking
- Impossible travel scenarios

### Failed Login Analyzer
Focus on:
- Brute force mitigation (rate limiting, account lockout)
- Credential stuffing detection (password reuse checks)
- Login failure pattern analysis (distributed vs. single-IP)

### Credential Stuffing Analyzer
Focus on:
- Password reset procedures
- Breach database checks (Have I Been Pwned)
- Account takeover indicators
- Credential leak investigation

### Password Spray Analyzer
Focus on:
- Account lockout policies
- Login throttling configuration
- Organizational-wide password requirements
- Attack pattern documentation for SOC

### Session Analyzer
Focus on:
- Session timeout configuration
- Active session management
- Device trust verification
- Anomalous session patterns

### Behavioral Analyzer
Focus on:
- User behavior baselines
- Off-hours access justification
- Privileged access reviews
- Anomaly threshold tuning

---

## Future Enhancements

As agents gain access to tools and external APIs, recommendations will become even more specific:

**With Tool Access:**
```
I've already revoked the user's active sessions using the Admin SDK API.
Status: 3 sessions terminated at 2025-10-27 15:42:03 UTC.

Next steps:
1. [Specific manual follow-up]
2. [Verification step]
```

**With SOAR Integration:**
```
I've created incident ticket INC-2025-1027-003 in your SOAR platform with:
- Severity: High
- Assigned to: Tier-2 SOC analyst
- SLA: 4 hours
- Runbook: credential_compromise_v2.md

The ticket includes all enrichment data and my forensic analysis. Monitor ticket
status at https://soar.yourorg.com/incidents/INC-2025-1027-003
```

---

## Recommendation Language Guidelines

### Tone
- **Authoritative but not alarmist** - State facts clearly without creating panic
- **Actionable** - Every sentence should lead to action
- **Educational** - Briefly explain the "why" so users learn

### Structure
- **Numbered lists** for sequential steps
- **Bullet points** for non-sequential items
- **Bold** for console paths and key terms
- **Inline code** for commands, filters, queries

### Length
- **Individual recommendation**: 2-4 sentences + steps
- **Total recommendations**: 3-5 items (not overwhelming)
- **Forensic narrative**: Can be longer for complex analysis

---

## Version History

- **v1.0** (Oct 27, 2025) - Initial guidelines created
- Future versions will include agent-specific best practices as the system evolves

---

## Questions?

If you're an agent and unsure whether your recommendation is specific enough, check:
- Does it include a complete console path?
- Could someone execute it without asking clarifying questions?
- Is the success state clearly defined?

If yes to all three, you're on the right track.
