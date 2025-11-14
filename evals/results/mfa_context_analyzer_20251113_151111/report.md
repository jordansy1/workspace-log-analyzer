# Evaluation Report: mfa_context_analyzer

**Generated:** 2025-11-13T15:11:11.089624

**Test Cases:** evals/dataset/mfa_context_analyzer/test_cases.json

## Summary

- Total Cases: 10
- Passed: 6 (60.0%)
- Failed: 4 (40.0%)

## Core Metrics

| Metric | Score |
|--------|-------|
| Accuracy | 60.0% |
| Precision | 0.0% |
| Recall | 0.0% |
| F1 Score | 0.0% |

## Confusion Matrix

```
                Predicted
                Risk  | Not Risk
Actual  Risk       0  |    4
        Not        0  |    6
```

## Failed Cases (4)

### MFA_002_session_cookie_theft

- **Expected:** is_actual_risk=True, severity=critical
- **Got:** is_actual_risk=False, severity=low
- **Difficulty:** easy

### MFA_005_credential_stuffing_hosting

- **Expected:** is_actual_risk=True, severity=high
- **Got:** is_actual_risk=False, severity=low
- **Difficulty:** medium

### MFA_006_admin_no_mfa_enforced

- **Expected:** is_actual_risk=True, severity=high
- **Got:** is_actual_risk=False, severity=low
- **Difficulty:** hard

### MFA_009_impossible_travel

- **Expected:** is_actual_risk=True, severity=critical
- **Got:** is_actual_risk=False, severity=low
- **Difficulty:** easy

