# Tier-2 Agent Evals - Quick Start Guide

## 5-Minute Getting Started

### 1. Run Your First Evaluation

```bash
cd /home/user/workspace-log-analyzer
python evals/scripts/run_evals.py --agent mfa_context_analyzer
```

You'll see:
```
RUNNING EVAL: mfa_context_analyzer
======================================================================

[1/10] Running case: MFA_001_trusted_device_home
  ✓ PASS | Risk: False (expected: False) | Severity: low

[2/10] Running case: MFA_002_session_cookie_theft
  ✓ PASS | Risk: True (expected: True) | Severity: critical

...

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

### 2. View Detailed Results

```bash
# Human-readable report
cat evals/results/mfa_context_analyzer_*/report.md

# Full JSON results
cat evals/results/mfa_context_analyzer_*/results.json | jq

# Just the failures
cat evals/results/mfa_context_analyzer_*/failures.json | jq
```

### 3. Make a Prompt Change

```bash
# Edit the agent's prompt
vim tier2_analysis/agents/mfa_context_analyzer/prompt.md

# Re-run eval to see impact
python evals/scripts/run_evals.py --agent mfa_context_analyzer --run-name "after_my_changes"
```

### 4. Compare to Baseline

```bash
# Save first run as baseline
python evals/scripts/run_evals.py --agent mfa_context_analyzer --run-name baseline

# Make changes to prompt
vim tier2_analysis/agents/mfa_context_analyzer/prompt.md

# Compare
python evals/scripts/run_evals.py \
  --agent mfa_context_analyzer \
  --compare-baseline evals/results/mfa_context_analyzer_baseline/results.json
```

Results show deltas:
```
COMPARISON TO BASELINE
--- Metrics ---
  accuracy    : ↑ +0.050 (+5.6%)
  precision   : ↑ +0.100 (+12.5%)
  recall      : → +0.000 (+0.0%)
  f1_score    : ↑ +0.055 (+6.3%)

✅ No regressions detected
```

## What's Included

✅ **10 test cases for MFA agent** covering:
- Trusted device scenarios (should NOT be flagged)
- Session cookie theft (SHOULD be flagged)
- VPN travel (legitimate)
- Tor exit nodes (malicious)
- Policy violations
- Edge cases

✅ **Complete evaluation framework**:
- Accuracy, precision, recall, F1 metrics
- Confusion matrix
- Failure analysis
- Baseline comparison

✅ **CLI tool** for running evals

✅ **Comprehensive documentation** for security analysts and product managers

## Next Steps

1. Read the full guide: `evals/README.md`
2. Create test cases for other agents (geographic, failed_login, etc.)
3. Set up weekly eval runs
4. Integrate into CI/CD pipeline

## Common Commands

```bash
# Run single agent
python evals/scripts/run_evals.py --agent mfa_context_analyzer

# Run all agents
python evals/scripts/run_evals.py --all

# Use custom test cases
python evals/scripts/run_evals.py --agent mfa_context_analyzer --test-cases my_cases.json

# Compare to baseline
python evals/scripts/run_evals.py --agent mfa_context_analyzer --compare-baseline baseline/results.json
```

## Understanding Metrics

| Metric | What It Means | Target |
|--------|---------------|--------|
| **Accuracy** | % of correct answers | ≥85% |
| **Precision** | When agent says "threat", how often is it right? | ≥80% |
| **Recall** | Does agent catch all real threats? | ≥90% |
| **F1 Score** | Balance of precision and recall | ≥85% |

## Troubleshooting

**"Test cases not found"**
→ Create test cases file: `cp evals/dataset/test_case_template.json evals/dataset/<agent>/test_cases.json`

**"Module not found"**
→ Run from project root: `cd /home/user/workspace-log-analyzer`

**Low accuracy (<50%)**
→ Check ANTHROPIC_API_KEY is set in .env file

## Help

Full documentation: `evals/README.md`

Template for new test cases: `evals/dataset/test_case_template.json`

Example test cases: `evals/dataset/mfa_context_analyzer/test_cases.json`
