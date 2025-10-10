# Archive - Deprecated Code

This directory contains previous implementations that have been replaced by the current modular architecture. These files are preserved for:

- **Historical reference** - Understanding the evolution of the project
- **Learning purposes** - Comparing monolithic vs. modular design patterns
- **Documentation** - Demonstrating why architectural decisions were made

**⚠️ DO NOT USE THESE FILES IN PRODUCTION** - They are outdated and have been superseded by better implementations.

---

## Directory Structure

### 📁 [old_monolithic/](old_monolithic/)
**Contains:** Original monolithic architecture (3,000+ line single file)
**Deprecated:** October 9, 2025
**Reason:** Difficult to maintain, test, and extend

**Key Issues:**
- Combined tier-1 detection and tier-2 AI analysis in one massive file
- Agent prompts embedded as 400-600 line f-strings
- No separation of concerns
- Hard to locate and modify specific detection logic
- Testing required running entire codebase

**Files:**
- `analyze_logs.py` - Original all-in-one analyzer
- `test_enhanced_detections.py` - Development testing script

See [old_monolithic/README.md](old_monolithic/README.md) for details.

---

### 📁 [old_orchestrators/](old_orchestrators/)
**Contains:** Previous orchestration implementations
**Deprecated:** October 9, 2025
**Reason:** Tightly coupled to monolithic architecture

**Files:**
- `orchestrator.py` - Basic orchestrator (first version)
- `orchestrator_automated.py` - Automated tier-1/tier-2 orchestrator

**Problems Solved:**
- Orchestrators depended on monolithic `analyze_logs.py`
- Couldn't independently test detection methods
- Agent routing was hardcoded rather than configurable

See [old_orchestrators/README.md](old_orchestrators/README.md) for details.

---

## What Replaced This Code?

The current architecture is fully modular with clear separation of concerns:

### Current Tier-1 Detection: `tier1_detection/`
**11 independent detection modules:**
- `mfa_detection.py` - Multi-factor authentication anomalies
- `geographic_detection.py` - Geographic anomalies
- `failed_login_detection.py` - Failed login patterns
- `credential_stuffing_detection.py` - Credential stuffing attacks
- `password_spray_detection.py` - Password spray attacks
- `impossible_travel_detection.py` - Impossible travel detection
- `mfa_fatigue_detection.py` - MFA fatigue attacks
- `session_detection.py` - Session hijacking
- `off_hours_detection.py` - Off-hours access
- `rapid_access_detection.py` - Rapid successive access
- `account_manipulation_detection.py` - Account permission changes

**Benefits:**
- Each detection method is independently testable
- Easy to add new detection types
- Clear MITRE ATT&CK mapping per module

### Current Tier-2 Analysis: `tier2_analysis/agents/`
**7 specialized AI agents with markdown prompts:**

Each agent has its own directory with:
- `agent.py` - Agent implementation
- `prompt.md` - Markdown-formatted prompt (easy to edit!)
- `config.yaml` - Agent configuration
- `__init__.py` - Module exports

**Agent types:**
- `behavioral_analyzer/` - User behavior analysis
- `credential_stuffing_analyzer/` - Credential attack analysis
- `failed_login_analyzer/` - Login failure analysis
- `geographic_analyzer/` - Geographic pattern analysis
- `mfa_context_analyzer/` - MFA event analysis
- `password_spray_analyzer/` - Password spray analysis
- `session_analyzer/` - Session anomaly analysis

**Benefits:**
- Prompts are human-readable markdown files
- Version control shows prompt changes clearly
- Each agent can be tested independently
- Easy to add new specialized agents

### Current Orchestration: `orchestrator_modular.py`
**Modern orchestrator with:**
- Dynamic agent routing based on anomaly type
- Configurable detection methods
- Clean separation between detection and analysis
- Proper error handling and logging

---

## Architectural Lessons Learned

`✶ Why We Refactored:`

1. **Maintainability** - Finding specific logic in 3,000 lines was time-consuming
2. **Testability** - Couldn't unit test individual detection methods
3. **Extensibility** - Adding new detections required modifying the monolith
4. **Collaboration** - Large files create merge conflicts
5. **Clarity** - Prompts as Python f-strings were hard to read and edit
6. **Debugging** - Stack traces pointed to massive files with no clear boundaries

**Result:** The modular architecture is ~30% more code lines but 10x easier to work with.

---

## When to Reference These Files

**Good reasons:**
- Understanding the initial approach to the problem
- Comparing design patterns (monolithic vs. modular)
- Learning what not to do in future projects
- Seeing how prompts evolved from Python strings to markdown

**Bad reasons:**
- Copying code into production (use current implementations instead)
- Running the old analyzer (it's unmaintained and may have bugs)

---

## Related Documentation

- [`MODULAR_ARCHITECTURE.md`](../MODULAR_ARCHITECTURE.md) - Complete architecture documentation
- [`MITRE_ATTACK_ENHANCEMENTS.md`](../MITRE_ATTACK_ENHANCEMENTS.md) - MITRE ATT&CK mapping
- [`SUB_AGENT_PROMPTS_GUIDE.md`](../SUB_AGENT_PROMPTS_GUIDE.md) - Agent prompt engineering guide

---

## Timeline

| Date | Event |
|------|-------|
| Early 2025 | Initial monolithic implementation created |
| October 9, 2025 | Modular architecture completed |
| October 9, 2025 | Original files moved to archive |

---

**Questions?** See the main [README.md](../README.md) for current project documentation.
