# Analysis Drawer Enhancements

## Overview

Enhanced the event analysis drawer to provide detailed transparency into the two-tier detection and analysis pipeline, giving users comprehensive visibility into how threats are detected and analyzed.

## New Features

### 1. Tier-1 Detection Details Section

**Visual Design:**
- Indigo-themed card with "Deterministic Analysis" badge
- Magnifying glass icon (🔍) for detection focus

**Information Displayed:**
- **Detection Method**: Human-readable name of the detection rule that flagged the anomaly
- **Anomaly ID**: Unique identifier for tracking (e.g., `ANOM-MFA-001`, `ANOM-SESSION-438`)
- **MITRE ATT&CK Techniques**: Visual badges showing mapped attack techniques (e.g., `T1078`, `T1110.001`)
- **Sub-Agent Assignment**: Which tier-2 AI agent was assigned to analyze this anomaly
- **Investigation Context**: Questions the detection system identified for deeper analysis

**Purpose:**
Provides users with complete transparency into:
- What detection rule fired and why
- How the anomaly maps to industry-standard attack frameworks
- What contextual questions guided the AI analysis

**Example Display:**
```
┌─────────────────────────────────────────────────────┐
│ 🔍 Tier-1 Detection Details [Deterministic Analysis]│
├─────────────────────────────────────────────────────┤
│ Detection Method: Missing MFA                       │
│ Anomaly ID: ANOM-MFA-001                           │
│                                                      │
│ MITRE ATT&CK Techniques:                           │
│ [T1556.006] [T1621] [T1111]                        │
│                                                      │
│ Routed to Sub-Agent: mfa_context_analyzer          │
│                                                      │
│ Investigation Context:                              │
│ • Could this be a trusted device scenario?         │
│ • Was there a valid session already established?   │
│ • Is this an OAuth/API authentication flow?        │
└─────────────────────────────────────────────────────┘
```

---

### 2. Tier-2 AI Agent Analysis Section

**Visual Design:**
- Blue gradient card (from-blue-50 to-cyan-50) with thick border
- Brain icon (🧠) emphasizing AI analysis
- "AI-Powered" badge with lightning bolt (⚡)

**Agent Details Subsection:**
Displays comprehensive information about the AI agent that performed the analysis:
- **Agent Name**: The specific specialized agent (e.g., `mfa_context_analyzer`, `session_analyzer`)
- **Confidence Level**: Agent's confidence in its assessment (HIGH/MEDIUM/LOW)
- **Risk Assessment**: Clear verdict (⚠️ ACTUAL THREAT or ✓ BENIGN)
- **Adjusted Severity**: Severity level after AI analysis (may differ from tier-1)

**Analysis Methodology Subsection:**
Documents the analytical process the agent followed:

```
Analysis Methodology
────────────────────────────────────────────────────
This specialized AI agent analyzed the anomaly using
contextual enrichment data including:

✓ IP Reputation Analysis: Checked against AbuseIPDB
  and VirusTotal threat intelligence feeds

✓ Geolocation Context: Evaluated access patterns and
  travel feasibility

✓ User Behavior Baseline: Compared against historical
  login patterns for this user

✓ Organizational Context: Considered user role,
  permissions, and device trust status

✓ Temporal Analysis: Examined timing patterns and
  sequence of events
```

**Forensic Analysis & Conclusion:**
The agent's detailed narrative explaining:
- What data it examined
- What patterns it identified (or didn't identify)
- Why it reached its conclusion
- The reasoning behind the threat assessment

**Agent Recommendations:**
Actionable recommendations from the AI agent:
- Specific steps to take based on the analysis
- Context-aware guidance (different from tier-1 triage guidance)

**Example Display:**
```
┌──────────────────────────────────────────────────────┐
│ 🧠 Tier-2 AI Agent Analysis              [⚡AI-Powered]│
├──────────────────────────────────────────────────────┤
│ ╔════════════════════════════════════════╗          │
│ ║ Agent Details                          ║          │
│ ╠════════════════════════════════════════╣          │
│ ║ Agent Name: mfa_context_analyzer       ║          │
│ ║ Confidence Level: MEDIUM               ║          │
│ ║ Risk Assessment: ✓ BENIGN              ║          │
│ ║ Adjusted Severity: LOW                 ║          │
│ ╚════════════════════════════════════════╝          │
│                                                      │
│ Analysis Methodology                                 │
│ ────────────────────────────────────────            │
│ [5 analytical steps listed with checkmarks]         │
│                                                      │
│ Forensic Analysis & Conclusion                      │
│ ────────────────────────────────────────            │
│ This is NOT a security risk. The event represents   │
│ a legitimate trusted device re-authentication...    │
│                                                      │
│ Agent Recommendations                                │
│ ────────────────────────────────────────            │
│ 1. Review manually                                  │
│ 2. Enable API for full analysis                     │
└──────────────────────────────────────────────────────┘
```

---

## Technical Implementation

### Frontend Changes

**Files Modified:**
- `web-ui/frontend/src/components/AnalysisDrawer.tsx` - Enhanced drawer UI
- `web-ui/frontend/src/lib/api.ts` - Added TypeScript interfaces

**New TypeScript Interfaces:**
```typescript
export interface Tier2Analysis {
  agent_name: string;
  is_actual_risk: boolean;
  confidence: 'high' | 'medium' | 'low';
  adjusted_severity: string;
  forensic_narrative: string;
  recommended_actions: string[];
}
```

**Enhanced Anomaly Interface:**
```typescript
export interface Anomaly {
  // ... existing fields
  sub_agent?: string;              // NEW
  context_questions?: string[];    // NEW
  tier2_analysis?: Tier2Analysis;  // NEW
  mitre_attack?: string[];         // Existing but now displayed
}
```

### Backend Data Transformation

The backend [main.py:364-413](../../web-ui/backend/main.py#L364-413) automatically transforms the modular orchestrator's output format:

```python
# Backend produces separate arrays:
{
  "tier1_anomalies": [...],
  "tier2_analyses": [...]
}

# Transformed to frontend format:
{
  "refined_anomalies": [
    {
      ...tier1_fields,
      "tier2_analysis": {
        "agent_name": "...",
        "is_actual_risk": false,
        "confidence": "medium",
        "forensic_narrative": "...",
        ...
      }
    }
  ]
}
```

---

## User Experience

### Information Hierarchy

The drawer now presents information in logical layers:

1. **Alert Summary** (top) - Quick overview of the anomaly
2. **Triage Guidance** - Tier-1 recommendations for human analysts
3. **Tier-1 Detection Details** ⭐ NEW - Technical detection information
4. **Tier-2 AI Agent Analysis** ⭐ NEW - Detailed AI reasoning and methodology
5. **Event Information** - Basic event metadata
6. **User Context** - User profile and permissions
7. **Network & Location** - IP and geolocation data
8. **Raw Data** - Complete JSON for technical review

### Visual Design Principles

**Color Coding:**
- **Indigo** = Tier-1 (deterministic, rule-based)
- **Blue/Cyan Gradient** = Tier-2 (AI-powered, intelligent)
- **Purple** = Triage guidance (analyst recommendations)
- **Red/Green** = Risk assessment (threat vs. benign)

**Progressive Disclosure:**
The drawer provides increasingly detailed information as you scroll:
- Top: "What happened?" (anomaly description)
- Middle: "How was it detected?" (tier-1) and "What does AI think?" (tier-2)
- Bottom: "What are the technical details?" (raw event data)

---

## Future Enhancements

### Planned Improvements

1. **Agent-Specific Methodology Display**
   - Each agent type could display its unique analytical approach
   - Dynamic methodology steps based on agent configuration

2. **Evidence Trail Visualization**
   - Show which specific data points the agent examined
   - Highlight key factors that influenced the decision

3. **Confidence Score Breakdown**
   - Display sub-scores for different analysis dimensions
   - Show which factors increased/decreased confidence

4. **Interactive Agent Tools Display**
   - When agents are equipped with tools (future), show which tools were used
   - Display tool outputs and intermediate results

5. **Analysis Timeline**
   - Show the sequence of analytical steps
   - Timestamp when tier-1 detected → tier-2 analyzed → conclusion reached

6. **Multi-Agent Collaboration**
   - When multiple agents analyze the same anomaly (future), show their individual assessments
   - Display consensus or disagreement between agents

### Extensibility Points

The current architecture is designed to accommodate future agent enhancements:

```typescript
// Easy to add new fields as agents evolve:
export interface Tier2Analysis {
  agent_name: string;
  is_actual_risk: boolean;
  confidence: 'high' | 'medium' | 'low';
  adjusted_severity: string;
  forensic_narrative: string;
  recommended_actions: string[];

  // Future additions:
  tools_used?: string[];           // Tools the agent invoked
  evidence_trail?: Evidence[];     // Data points examined
  alternative_scenarios?: Scenario[]; // Other possibilities considered
  confidence_breakdown?: {         // Sub-scores
    temporal: number;
    behavioral: number;
    contextual: number;
  };
}
```

---

## Testing Instructions

### Manual Testing

1. **Start the application**
   ```bash
   # Terminal 1 - Backend
   cd workspace_log_analyzer/web-ui/backend
   ../../venv/Scripts/python.exe main.py

   # Terminal 2 - Frontend
   cd workspace_log_analyzer/web-ui/frontend
   npm run dev
   ```

2. **Fetch logs and trigger analysis**
   - Open http://localhost:5173
   - Sign in with Google Workspace account
   - Click "Fetch Logs"
   - Wait for analysis to complete

3. **Verify Tier-1 Section**
   - Click on an event with a blue shield icon
   - Scroll to "Tier-1 Detection Details" section
   - Verify it shows:
     - Detection method name
     - Anomaly ID
     - MITRE ATT&CK badges (if applicable)
     - Sub-agent assignment
     - Context questions

4. **Verify Tier-2 Section**
   - Check for "Tier-2 AI Agent Analysis" section
   - Verify "Agent Details" subsection displays:
     - Agent name (e.g., `mfa_context_analyzer`)
     - Confidence level
     - Risk assessment (BENIGN or THREAT)
     - Adjusted severity
   - Verify "Analysis Methodology" shows 5 checkmarks
   - Verify "Forensic Analysis & Conclusion" displays narrative
   - Check for "Agent Recommendations" if available

5. **Test with Different Anomaly Types**
   - Test with MFA anomalies → should route to `mfa_context_analyzer`
   - Test with session anomalies → should route to `session_analyzer`
   - Verify each agent's output displays correctly

### Edge Cases

- **No Tier-2 Analysis**: Should still show Tier-1 section
- **Mock Analysis**: When Anthropic API unavailable, should display mock response gracefully
- **Missing Fields**: Should handle optional fields (MITRE badges, context questions) elegantly

---

## Benefits

### For Security Analysts

1. **Complete Audit Trail**: See exactly how each threat was detected and analyzed
2. **Learning Tool**: Understand what patterns trigger detections
3. **Validation**: Verify AI reasoning aligns with security best practices
4. **Efficiency**: Quickly assess whether to investigate further

### For Product Development

1. **Transparency**: Users can see the AI is making informed decisions
2. **Trust**: Detailed methodology builds confidence in automated analysis
3. **Debugging**: Makes it easy to identify if agents need refinement
4. **Documentation**: The UI itself documents the analysis process

### For Future Agent Development

1. **Standardized Output**: Clear contract for what agents must provide
2. **Extensibility**: Easy to add new fields as agents become more sophisticated
3. **Modularity**: Each agent can have unique methodology while sharing common UI patterns

---

## Screenshots

(Add screenshots when testing in browser)

1. Tier-1 Detection Details with MITRE badges
2. Tier-2 Agent Analysis with methodology checklist
3. Complete drawer view showing both sections
4. Different agent types (MFA vs. Session analyzer)

---

## Related Documentation

- [Agent Router Implementation](../../tier2_analysis/agent_router.py)
- [Base Agent Architecture](../../tier2_analysis/base_agent.py)
- [Backend API Transformation](../../web-ui/backend/main.py#L364-413)
- [Frontend Type Definitions](../../web-ui/frontend/src/lib/api.ts)
