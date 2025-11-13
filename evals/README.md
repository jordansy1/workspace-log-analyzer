# Tier-2 Agent Evaluation Framework

## User Guide for Security Analysts & Product Managers

This framework allows you to **systematically test and improve** the AI-powered tier-2 security agents that analyze authentication anomalies. No coding experience required for most tasks.

---

## Table of Contents

1. [What This Does](#what-this-does)
2. [Quick Start](#quick-start)
3. [Creating Test Cases](#creating-test-cases)
4. [Running Evaluations](#running-evaluations)
5. [Understanding Results](#understanding-results)
6. [Improving Prompts](#improving-prompts)
7. [Workflows for Different Roles](#workflows-for-different-roles)

---

## What This Does

The tier-2 agents are AI systems that analyze security alerts to determine if they're real threats or false positives. This eval framework helps you:

- **Test agent accuracy**: Does the agent correctly identify real attacks vs. benign behavior?
- **Measure improvements**: Did your prompt changes make the agent better or worse?
- **Catch regressions**: Ensure updates don't break existing functionality
- **Build confidence**: Validate the agent works before deploying to production

### Key Concepts

- **Test Case**: A sample security event with a known correct answer
- **Ground Truth**: The correct answer you expect the agent to give
- **Evaluation (Eval)**: Running the agent on many test cases and scoring accuracy
- **Metrics**: Numbers showing how well the agent performed (accuracy, precision, recall)

---

## Quick Start

### Run Your First Evaluation (3 minutes)

```bash
# 1. Navigate to project directory
cd workspace-log-analyzer

# 2. Run evaluation on the MFA agent
python evals/scripts/run_evals.py --agent mfa_context_analyzer

# 3. View results
cat evals/results/mfa_context_analyzer_*/report.md
```

You'll see output like:
```
EVALUATION SUMMARY
======================================================================
Agent: mfa_context_analyzer
Total Cases: 10
Passed: 9 | Failed: 1

--- Core Metrics ---
  Accuracy:  90.0%
  Precision: 85.7%
  Recall:    100.0%
  F1 Score:  92.3%
```

**Interpretation:**
- **Accuracy 90%**: Agent got 9 out of 10 cases correct
- **Precision 85.7%**: When agent says "threat", it's right 85.7% of the time
- **Recall 100%**: Agent catches all real threats (no false negatives)
- **F1 Score 92.3%**: Overall balance of precision and recall

---

## Creating Test Cases

Test cases tell the framework: "Here's a security event, and here's what the agent *should* say about it."

### Understanding Test Case Structure

Each test case has three main parts:

#### 1. The Anomaly (What the agent sees)
```json
"anomaly": {
  "id": "MFA_001",
  "type": "missing_mfa",
  "affected_users": ["alice@company.com"],
  "evidence": {
    "login_verification_events": [...],
    "baseline_comparison": {...}
  }
}
```

#### 2. Enrichment Context (Supporting data)
```json
"enriched_context": {
  "user_context": {
    "is_2fa_enrolled": true,
    "is_admin": false
  },
  "ip_reputation": {
    "risk_score": 15,
    "is_malicious": false
  },
  "geolocation": {...}
}
```

#### 3. Ground Truth (Correct answer)
```json
"ground_truth": {
  "is_actual_risk": false,
  "expected_severity": "low",
  "expected_scenario": "trusted_device",
  "rationale": "User has 2FA enrolled, clean IP, known location"
}
```

### Step-by-Step: Creating a New Test Case

**Scenario**: You want to test if the agent correctly identifies session cookie theft.

1. **Copy the template**
   ```bash
   cp evals/dataset/test_case_template.json evals/dataset/mfa_context_analyzer/my_test.json
   ```

2. **Fill in the anomaly details**

   Use data from a real security incident or create a synthetic case:

   ```json
   {
     "case_id": "MFA_011_cookie_theft_tor",
     "description": "Attack from Tor network should be flagged as session theft",
     "anomaly": {
       "id": "TEST-COOKIE-THEFT-001",
       "type": "missing_mfa",
       "affected_users": ["victim@company.com"],
       "evidence": {
         "baseline_comparison": {
           "deviations": ["new_ip_address", "tor_exit_node_detected"]
         }
       }
     }
   }
   ```

3. **Add enrichment context**

   This is the intelligence data the agent uses:

   ```json
   "enriched_context": {
     "user_context": {
       "is_2fa_enrolled": true,        // User HAS 2FA configured
       "is_2fa_enforced": true
     },
     "ip_reputation": {
       "ip": "185.220.101.45",
       "risk_score": 95,                // Very high risk
       "is_malicious": true
     },
     "geolocation": {
       "country": "NL",
       "is_tor": true,                  // Red flag!
       "is_hosting": false
     }
   }
   ```

4. **Define ground truth**

   What should the agent conclude?

   ```json
   "ground_truth": {
     "is_actual_risk": true,           // This IS a threat
     "expected_severity": "critical",  // Very serious
     "expected_scenario": "session_cookie_theft",
     "rationale": "User has 2FA but accessing from Tor with risk score 95. Clear session theft."
   }
   ```

5. **Add metadata**

   Helps organize and filter test cases:

   ```json
   "metadata": {
     "difficulty": "easy",             // How obvious is this case?
     "source": "synthetic",            // Where did this case come from?
     "tags": ["mfa", "tor", "session_theft", "critical"]
   }
   ```

### Test Case Guidelines

**Creating Effective Test Cases:**

✅ **DO:**
- Include both threats and benign cases (50/50 mix is good)
- Cover edge cases (ambiguous scenarios)
- Use realistic IP addresses and locations
- Write clear rationales explaining the correct answer
- Test difficult cases the agent struggles with

❌ **DON'T:**
- Only test obvious cases (too easy for the agent)
- Use fake data that doesn't match real patterns
- Skip the rationale (you'll forget why later)
- Create unbalanced datasets (all attacks or all safe)

**Recommended Test Case Distribution:**
- 30% True Negatives (benign, should NOT be flagged)
- 20% True Positives (real attacks, SHOULD be flagged)
- 30% Edge Cases (ambiguous, tests reasoning)
- 20% Common False Positives (agent often gets wrong)

### Getting Test Case Ideas

**From Real Data:**
1. Look at recent alerts in `analysis/investigations/`
2. Find cases where you manually reviewed and determined the verdict
3. Convert those into test cases with your verdict as ground truth

**Synthetic Creation:**
1. Read the agent's prompt: `tier2_analysis/agents/mfa_context_analyzer/prompt.md`
2. Look at the "Attack Scenarios" section
3. Create test cases for each scenario (legitimate vs. attack)

**Common Scenarios to Test:**

| Scenario | is_actual_risk | Key Indicators |
|----------|---------------|----------------|
| Trusted device, home IP | False | 2FA enrolled, low risk score, known location |
| VPN during travel | False | 2FA enrolled, VPN flagged, reasonable location change |
| Tor exit node | True | Tor=true, high risk score, new location |
| Cloud hosting provider | True | is_hosting=true, moderate risk, unusual timing |
| Admin without 2FA | True | is_admin=true, is_2fa_enrolled=false |
| OAuth flow | False | login_type=exchange, clean IP, 2FA enforced |

---

## Running Evaluations

### Basic Commands

**Run single agent:**
```bash
python evals/scripts/run_evals.py --agent mfa_context_analyzer
```

**Run with custom test cases:**
```bash
python evals/scripts/run_evals.py \
  --agent mfa_context_analyzer \
  --test-cases evals/dataset/mfa_context_analyzer/my_test.json
```

**Run all agents:**
```bash
python evals/scripts/run_evals.py --all
```

**Save with custom name:**
```bash
python evals/scripts/run_evals.py \
  --agent mfa_context_analyzer \
  --run-name "after_prompt_fix"
```

### Comparing to Baseline

When you improve a prompt, compare performance before/after:

```bash
# 1. Run eval and save as baseline
python evals/scripts/run_evals.py --agent mfa_context_analyzer --run-name baseline

# 2. Edit the prompt
vim tier2_analysis/agents/mfa_context_analyzer/prompt.md

# 3. Run eval again and compare
python evals/scripts/run_evals.py \
  --agent mfa_context_analyzer \
  --compare-baseline evals/results/mfa_context_analyzer_baseline/results.json
```

Output shows improvements/regressions:
```
COMPARISON TO BASELINE
======================================================================
--- Metrics ---
  accuracy    : ↑ +0.050 (+5.6%)
  precision   : ↑ +0.100 (+12.5%)
  recall      : → +0.000 (+0.0%)
  f1_score    : ↑ +0.055 (+6.3%)

✅ No regressions detected
```

### When to Run Evaluations

**Run evals when you:**
- Change an agent's prompt
- Update the decision matrix in a prompt
- Add new attack scenarios to documentation
- Modify enrichment data fields
- Suspect the agent is making more mistakes

**Frequency:**
- After every significant prompt change (required)
- Weekly as part of quality checks (recommended)
- Before deploying updated agents to production (critical)

---

## Understanding Results

### Output Files

After running an eval, you get several files:

```
evals/results/mfa_context_analyzer_20250113_143022/
├── results.json        # Full detailed results
├── summary.json        # Just the metrics
├── failures.json       # Only failed cases (for debugging)
└── report.md          # Human-readable report
```

### Reading the Summary

**Core Metrics:**

- **Accuracy**: Overall correctness (passed cases / total cases)
  - Target: ≥85% minimum, ≥90% good, ≥95% excellent

- **Precision**: When agent says "threat", how often is it correct?
  - Target: ≥80% (too low = too many false alarms)

- **Recall**: Does agent catch all real threats?
  - Target: ≥90% (too low = missing attacks)

- **F1 Score**: Balance of precision and recall
  - Target: ≥85%

**Confusion Matrix:**

```
                Predicted
                Risk  | Not Risk
Actual  Risk      8   |    2       ← 2 False Negatives (missed attacks)
        Not       1   |   19       ← 1 False Positive (false alarm)
```

**Interpreting:**
- **False Negatives (missed attacks)**: CRITICAL - agent failed to detect real threats
- **False Positives (false alarms)**: Bad but less critical - agent flagged benign activity

### What Good Results Look Like

**Excellent Agent (Deploy with confidence):**
```
Accuracy:  95%+
Precision: 90%+
Recall:    95%+
False Negatives: 0-1
```

**Good Agent (Deploy, monitor closely):**
```
Accuracy:  85-95%
Precision: 80-90%
Recall:    85-95%
False Negatives: 1-2
```

**Needs Improvement (Don't deploy yet):**
```
Accuracy:  <85%
Precision: <80%
Recall:    <85%
False Negatives: 3+
```

### Analyzing Failures

When the eval fails cases, dig into why:

1. **Read failures.json**
   ```bash
   cat evals/results/mfa_context_analyzer_*/failures.json | jq
   ```

2. **Identify patterns**
   - Are all failures the same type? (e.g., all VPN cases)
   - Are they all "hard" difficulty cases?
   - Is the agent overconfident on wrong answers?

3. **Example failure analysis:**

   ```json
   {
     "case_id": "MFA_004_vpn_travel",
     "ground_truth": {
       "is_actual_risk": false,
       "expected_severity": "low"
     },
     "prediction": {
       "is_actual_risk": true,
       "adjusted_severity": "high"
     },
     "scores": {
       "confidence": "high",
       "overconfidence_penalty": 1.0
     }
   }
   ```

   **Problem**: Agent flagged legitimate VPN travel as an attack with high confidence.

   **Fix**: Update prompt to better distinguish legitimate VPN usage from malicious proxies.

---

## Improving Prompts

### Iterative Improvement Workflow

This is the systematic process to improve an agent:

#### Step 1: Run Baseline Eval

```bash
python evals/scripts/run_evals.py --agent mfa_context_analyzer --run-name baseline
```

Captures current performance (e.g., 82% accuracy).

#### Step 2: Identify Problems

Look at failures:
```bash
cat evals/results/mfa_context_analyzer_baseline/failures.json | jq '.[] | .case_id'
```

Example output:
```
MFA_004_vpn_travel
MFA_007_ambiguous_moderate_risk
```

Agent struggles with VPN cases and ambiguous scenarios.

#### Step 3: Understand Why

Read the prompt: `tier2_analysis/agents/mfa_context_analyzer/prompt.md`

Find the relevant section:
```markdown
### Infrastructure Risk Assessment
Anonymization Check:
├─ is_vpn == TRUE: Moderate (could be legitimate, investigate)
```

**Problem**: "Investigate" is vague. Agent treats VPN as suspicious.

#### Step 4: Update Prompt

Make it more specific:
```markdown
### Infrastructure Risk Assessment
Anonymization Check:
├─ is_vpn == TRUE:
   ├─ If commercial VPN (NordVPN, ExpressVPN) + residential behavior → Likely legitimate
   ├─ If datacenter VPN + off-hours + high risk IP → Investigate
```

#### Step 5: Test Changes

```bash
python evals/scripts/run_evals.py \
  --agent mfa_context_analyzer \
  --compare-baseline evals/results/mfa_context_analyzer_baseline/results.json
```

Results:
```
COMPARISON TO BASELINE
--- Metrics ---
  accuracy    : ↑ +0.080 (+9.8%)  ← Improved!
  precision   : ↑ +0.120 (+15.0%)
  recall      : → +0.000 (+0.0%)   ← No regression
```

#### Step 6: Repeat Until Satisfied

Keep iterating until:
- Accuracy ≥85%
- No false negatives (recall 100%)
- Failed cases are genuinely ambiguous

### Prompt Improvement Techniques

**Technique 1: Add Specific Examples**

❌ Bad:
```markdown
Check if IP is suspicious.
```

✅ Good:
```markdown
### IP Risk Evaluation
- Risk Score 0-30: Low (residential ISP, clean history)
  Example: 99.209.227.194 (Comcast, Seattle)
- Risk Score 31-60: Medium (some abuse history, investigate)
  Example: 45.123.78.90 (Cox, spam reports)
- Risk Score 61-100: High (known malicious)
  Example: 185.220.101.45 (Tor exit node)
```

**Technique 2: Clarify Edge Cases**

If agent fails on VPN cases, add:
```markdown
### Common False Positives to Avoid

**Legitimate VPN Usage:**
- Corporate VPN during travel (NordVPN, ExpressVPN)
- User in typical time zone (e.g., 9 AM login, not 3 AM)
- Low IP risk score (<30)
→ Mark as: is_actual_risk=false, severity=low

**Malicious VPN Usage:**
- Free/anonymous VPN (TorGuard, Mullvad) + new location
- High IP risk score (>60)
- Off-hours access
→ Mark as: is_actual_risk=true, severity=high
```

**Technique 3: Strengthen Decision Logic**

Add explicit decision trees:
```markdown
### Critical Decision: Session Cookie Theft Detection

IF (is_2fa_enrolled == TRUE) AND (risk_score > 70) AND (is_tor == TRUE OR is_hosting == TRUE):
  → Verdict: is_actual_risk=TRUE
  → Severity: CRITICAL
  → Scenario: session_cookie_theft
  → Rationale: User has MFA but bypassed via stolen session cookie

ELSE IF (is_2fa_enrolled == TRUE) AND (risk_score < 30) AND (no baseline deviations):
  → Verdict: is_actual_risk=FALSE
  → Severity: LOW
  → Scenario: trusted_device
```

**Technique 4: Add Real-World Context**

```markdown
### Google Workspace Trusted Device Behavior

**What agents often misunderstand:**
After a user completes 2FA once and checks "Trust this device",
Google Workspace allows re-authentication WITHOUT requiring 2FA again
for up to 30 days. This is NORMAL and NOT a security issue.

**How to identify:**
- login_type == "reauth"
- is_second_factor == false (this is expected!)
- Same IP/location as recent 2FA success
- user_context.is_2fa_enrolled == TRUE
```

### Testing Prompt Changes

Always test incrementally:

1. **Change one thing at a time**
   - Don't rewrite the entire prompt
   - Modify one section, test, iterate

2. **Run evals after each change**
   ```bash
   # Edit prompt
   vim tier2_analysis/agents/mfa_context_analyzer/prompt.md

   # Test immediately
   python evals/scripts/run_evals.py --agent mfa_context_analyzer
   ```

3. **Track what you changed**
   ```bash
   # Save with descriptive name
   python evals/scripts/run_evals.py \
     --agent mfa_context_analyzer \
     --run-name "v2_added_vpn_examples"
   ```

4. **Compare to baseline**
   ```bash
   python evals/scripts/run_evals.py \
     --agent mfa_context_analyzer \
     --compare-baseline evals/results/mfa_context_analyzer_baseline/results.json
   ```

---

## Workflows for Different Roles

### For Security Analysts

**You are the domain expert.** Your security knowledge makes test cases accurate.

**Your workflow:**

1. **Create test cases from real incidents**
   - Review recent alerts in `analysis/investigations/`
   - Find cases where you manually determined verdict
   - Convert to test case with your verdict as ground truth

   ```bash
   cp evals/dataset/test_case_template.json \
      evals/dataset/mfa_context_analyzer/incident_20250113.json
   # Edit file with incident details
   ```

2. **Run evals to catch agent mistakes**
   ```bash
   python evals/scripts/run_evals.py --agent mfa_context_analyzer
   ```

3. **Review failures**
   - Did agent miss an attack? → Critical, fix immediately
   - Did agent false alarm? → Less critical, but review prompt

4. **Collaborate on prompt fixes**
   - You provide the security logic
   - Work with engineers to update prompts
   - Re-run evals to confirm fix

**Example: Catching a Missed Attack**

You investigated an alert and found it WAS a real attack (session theft). But the agent marked it benign. Here's how to ensure this doesn't happen again:

1. Create test case from the real incident:
   ```json
   {
     "case_id": "REAL_INCIDENT_20250113_session_theft",
     "ground_truth": {
       "is_actual_risk": true,
       "expected_severity": "critical",
       "rationale": "I manually investigated. User reported unauthorized access. Session cookie theft confirmed."
     }
   }
   ```

2. Run eval - it should fail this case
3. Update prompt with lessons learned
4. Re-run eval until it passes

### For Product Managers

**You ensure quality and track improvements over time.**

**Your workflow:**

1. **Weekly quality checks**
   ```bash
   # Run all agents every Monday
   python evals/scripts/run_evals.py --all
   ```

2. **Track metrics over time**
   - Maintain a spreadsheet: [Date, Agent, Accuracy, Precision, Recall]
   - Goal: Accuracy trending upward over weeks

3. **Set quality gates for releases**
   - Don't deploy if accuracy <85%
   - Require re-eval after every prompt change

4. **Prioritize improvements**
   - Agent with lowest accuracy gets attention first
   - Focus on false negatives (missed attacks) over false positives

**Example: Release Decision**

Before deploying updated agents:

```bash
# Run comprehensive eval
python evals/scripts/run_evals.py --all > release_eval.txt

# Check results
cat release_eval.txt
```

Decision criteria:
- ✅ All agents ≥85% accuracy → Approve release
- ⚠️ One agent 80-85% accuracy → Approve with monitoring plan
- ❌ Any agent <80% accuracy → Block release, require fixes

### For Prompt Engineers

**You directly improve the prompts to boost accuracy.**

**Your workflow:**

1. **Establish baseline**
   ```bash
   python evals/scripts/run_evals.py --agent mfa_context_analyzer --run-name baseline
   ```

2. **Analyze failures systematically**
   ```bash
   cat evals/results/mfa_context_analyzer_baseline/failures.json | \
     jq '[.[] | {case: .case_id, difficulty: .metadata.difficulty}] | group_by(.difficulty)'
   ```

   Identify: Are failures concentrated in "hard" cases? Specific tags?

3. **Make targeted prompt changes**

   Example: Many failures involve VPN false positives

   ```bash
   # Edit prompt - add VPN decision logic
   vim tier2_analysis/agents/mfa_context_analyzer/prompt.md

   # Test change
   python evals/scripts/run_evals.py \
     --agent mfa_context_analyzer \
     --compare-baseline evals/results/mfa_context_analyzer_baseline/results.json
   ```

4. **Iterate until metrics improve**

   Keep cycling: Edit → Test → Review Failures → Edit

5. **Document what worked**

   ```bash
   # Save successful version
   python evals/scripts/run_evals.py \
     --agent mfa_context_analyzer \
     --run-name "v3_vpn_logic_improved_accuracy_90pct"
   ```

**Example: Fixing Overconfidence**

The agent makes wrong calls with high confidence:

```
Failed Case: MFA_007
Expected: is_actual_risk=false
Got: is_actual_risk=true, confidence=high
```

**Fix strategy:**
1. Add calibration guidance to prompt:
   ```markdown
   ### Confidence Levels

   Use HIGH confidence only when:
   - Multiple strong indicators align
   - No ambiguity in evidence

   Use MEDIUM confidence when:
   - Some indicators conflict
   - Edge case scenario

   Use LOW confidence when:
   - Limited evidence available
   - Ambiguous situation requiring manual review
   ```

2. Test if this reduces overconfidence penalty in metrics

---

## Advanced Topics

### Creating Test Cases from Production Logs

**Extract real events:**

```bash
# 1. Find a log file with interesting events
ls logs/

# 2. Extract a specific event
cat logs/auth_logs_20250113.json | jq '.events[5]' > extracted_event.json

# 3. Convert to test case format
# (Manual process - copy relevant fields into test_case_template.json)
```

### Batch Testing Multiple Prompt Versions

Test A/B prompt variants:

```bash
# 1. Save current prompt
cp tier2_analysis/agents/mfa_context_analyzer/prompt.md prompt_v1.md

# 2. Test version 1
python evals/scripts/run_evals.py --agent mfa_context_analyzer --run-name v1

# 3. Try alternative approach
vim tier2_analysis/agents/mfa_context_analyzer/prompt.md

# 4. Test version 2
python evals/scripts/run_evals.py --agent mfa_context_analyzer --run-name v2

# 5. Compare results
cat evals/results/mfa_context_analyzer_v1/summary.json
cat evals/results/mfa_context_analyzer_v2/summary.json

# 6. Keep best performing version
```

### Difficulty Stratification

Understand which cases are hard:

```bash
# Run eval and view by difficulty
python evals/scripts/run_evals.py --agent mfa_context_analyzer

# Extract difficulty breakdown from results
cat evals/results/mfa_context_analyzer_*/summary.json | \
  jq '.metrics.difficulty_breakdown'
```

Output:
```json
{
  "easy": 0.95,    // 95% accuracy on easy cases
  "medium": 0.83,  // 83% accuracy on medium
  "hard": 0.60     // 60% accuracy on hard cases ← Focus here
}
```

**Improvement strategy:**
- Easy cases: Should be 95%+ accuracy (if not, prompt has major issues)
- Medium cases: Target 80%+ accuracy
- Hard cases: 70%+ is acceptable (genuinely ambiguous)

---

## Troubleshooting

### "Test cases not found"

**Problem:**
```
Error: Test cases not found: evals/dataset/geographic_analyzer/test_cases.json
```

**Solution:**
Create test cases for that agent:
```bash
cp evals/dataset/test_case_template.json \
   evals/dataset/geographic_analyzer/test_cases.json
# Edit file with appropriate test cases
```

### "Module not found" errors

**Problem:**
```
ModuleNotFoundError: No module named 'evals.framework'
```

**Solution:**
Run from project root:
```bash
cd /home/user/workspace-log-analyzer
python evals/scripts/run_evals.py --agent mfa_context_analyzer
```

### Agent fails all test cases

**Problem:**
Accuracy is 0% or very low (<50%)

**Possible causes:**
1. **Prompt has major errors** - Review prompt syntax
2. **Test cases have wrong format** - Validate against template
3. **API key missing** - Check ANTHROPIC_API_KEY in .env

**Debug steps:**
```bash
# Check if agent loads
python -c "from tier2_analysis.agents.mfa_context_analyzer.agent import MFAContextAgent; print('OK')"

# Run with just 1 test case
python evals/scripts/run_evals.py --agent mfa_context_analyzer
```

### Results don't save

**Problem:**
No files in `evals/results/`

**Solution:**
Check you didn't use `--no-save` flag:
```bash
# This saves results
python evals/scripts/run_evals.py --agent mfa_context_analyzer

# This doesn't save (by design)
python evals/scripts/run_evals.py --agent mfa_context_analyzer --no-save
```

---

## FAQ

**Q: How many test cases do I need?**

A: Minimum 10 per agent. Good: 30-50. Excellent: 100+.

Start small (10 cases covering main scenarios), then expand as you find edge cases.

**Q: Can I use the same test case for multiple agents?**

A: No. Each agent specializes in different anomaly types:
- `mfa_context_analyzer`: MFA-related anomalies
- `geographic_analyzer`: Location-based anomalies
- `failed_login_analyzer`: Brute force, credential stuffing

Create specific test cases for each agent's domain.

**Q: What if my agent gets 100% accuracy?**

A: Two possibilities:
1. **Great agent!** (Rare) - Test on more diverse, harder cases
2. **Test cases too easy** - Add edge cases and ambiguous scenarios

**Q: Should I version control test cases?**

A: **Yes!** Test cases are code. Commit them to git:
```bash
git add evals/dataset/
git commit -m "Add 10 new MFA test cases covering VPN scenarios"
```

**Q: How do I know if my prompt change is "good enough"?**

A: Deploy if:
- ✅ Accuracy ≥85%
- ✅ Recall ≥90% (catching real threats is critical)
- ✅ No regressions vs. baseline

**Q: What's the difference between precision and recall?**

A:
- **Precision**: Of the alerts the agent raises, how many are real threats?
  - High precision = few false alarms
- **Recall**: Of all the real threats, how many does the agent catch?
  - High recall = doesn't miss attacks

Both matter, but recall is more critical for security (don't miss attacks).

---

## Getting Help

**Issues with the eval framework:**
1. Check error message carefully
2. Review this README
3. Ask in team chat with eval output and error message

**Security questions about test cases:**
1. Review agent prompt: `tier2_analysis/agents/<agent_name>/prompt.md`
2. Look at existing test cases for examples
3. Consult security team lead

**Prompt engineering tips:**
1. Review successful agents' prompts
2. Study the "Improving Prompts" section above
3. Iterate with small changes, test frequently

---

## Next Steps

Now that you understand the eval framework:

1. **Run your first eval** (if you haven't):
   ```bash
   python evals/scripts/run_evals.py --agent mfa_context_analyzer
   ```

2. **Create one new test case** from a recent security incident

3. **Try improving a prompt** using the iterative workflow

4. **Set up weekly evals** in your calendar (every Monday)

5. **Share results** with your team to build confidence in the agents

---

## Reference

### File Locations

```
evals/
├── README.md                          # This file
├── dataset/                           # Test cases
│   ├── test_case_template.json        # Template for new cases
│   └── mfa_context_analyzer/
│       └── test_cases.json            # MFA agent test cases (10 examples)
├── framework/                         # Evaluation engine (don't edit)
│   ├── evaluator.py
│   └── metrics.py
├── results/                           # Saved eval results
│   └── mfa_context_analyzer_TIMESTAMP/
│       ├── results.json               # Full results
│       ├── summary.json               # Metrics only
│       ├── failures.json              # Failed cases
│       └── report.md                  # Human-readable
└── scripts/
    └── run_evals.py                   # CLI tool

tier2_analysis/agents/                 # Agent prompts (edit to improve)
├── mfa_context_analyzer/
│   └── prompt.md                      # MFA agent prompt
├── geographic_analyzer/
│   └── prompt.md
└── ...
```

### Metrics Glossary

| Metric | Formula | Target | Interpretation |
|--------|---------|--------|----------------|
| **Accuracy** | (TP + TN) / Total | ≥85% | Overall correctness |
| **Precision** | TP / (TP + FP) | ≥80% | How many alerts are real |
| **Recall** | TP / (TP + FN) | ≥90% | How many real threats are caught |
| **F1 Score** | 2 × (Precision × Recall) / (Precision + Recall) | ≥85% | Balance of precision and recall |

Where:
- **TP** (True Positive): Correctly identified threat
- **TN** (True Negative): Correctly identified benign
- **FP** (False Positive): Incorrectly flagged benign as threat
- **FN** (False Negative): Missed a real threat (most critical error)

### Command Reference

```bash
# Basic eval
python evals/scripts/run_evals.py --agent <agent_name>

# Custom test cases
python evals/scripts/run_evals.py --agent <agent_name> --test-cases <path>

# Compare to baseline
python evals/scripts/run_evals.py --agent <agent_name> --compare-baseline <path>

# Run all agents
python evals/scripts/run_evals.py --all

# Save with custom name
python evals/scripts/run_evals.py --agent <agent_name> --run-name <name>

# Don't save results
python evals/scripts/run_evals.py --agent <agent_name> --no-save
```

---

**Version:** 1.0.0
**Last Updated:** 2025-01-13
**Maintained By:** Security Engineering Team
