# Deprecated Monolithic Files

These files contained the original monolithic architecture before modularization.

## Files

### analyze_logs.py (3,000+ lines)
- **Purpose**: Combined tier-1 detection and tier-2 prompts in single file
- **Replaced by**:
  - `tier1_detection/` - 11 independent detection modules
  - `tier2_analysis/` - 7 specialized agent modules with markdown prompts
- **Date deprecated**: October 9, 2025
- **Why replaced**:
  - Prompts were embedded as 400-600 line f-strings
  - Hard to find and edit specific agent behavior
  - No separation between detection logic and AI analysis
  - Difficult to test individual components

### test_enhanced_detections.py
- **Purpose**: Testing script for development
- **Status**: Testing complete, no longer needed
- **Date deprecated**: October 9, 2025

## New Architecture

All detection methods are now in `tier1_detection/detection_methods/`:
- mfa_detection.py
- geographic_detection.py
- failed_login_detection.py
- credential_stuffing_detection.py
- password_spray_detection.py
- impossible_travel_detection.py
- mfa_fatigue_detection.py
- session_detection.py
- off_hours_detection.py
- rapid_access_detection.py
- account_manipulation_detection.py

All agent prompts are now in `tier2_analysis/agents/{agent_name}/prompt.md`:
- Easy to find and edit
- Markdown format with syntax highlighting
- Version control friendly
- Independent testing

See `MODULAR_ARCHITECTURE.md` for complete details.
