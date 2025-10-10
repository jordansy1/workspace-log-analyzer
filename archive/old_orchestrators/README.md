# Deprecated Orchestrators

These orchestrators were used before the modular architecture was implemented.

## Files

### orchestrator.py
- **Original orchestrator** (basic version)
- **Replaced by**: orchestrator_modular.py
- **Date deprecated**: October 9, 2025

### orchestrator_automated.py
- **First automated orchestrator** with tier-1 and tier-2 analysis
- **Replaced by**: orchestrator_modular.py
- **Date deprecated**: October 9, 2025
- **Why replaced**: Monolithic architecture, embedded prompts in analyze_logs.py

## New Architecture

Use **orchestrator_modular.py** which leverages:
- `tier1_detection/` - Modular detection methods
- `tier2_analysis/` - Specialized agent system

See `MODULAR_ARCHITECTURE.md` for details.
