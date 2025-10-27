# Project Cleanup Plan

## Summary

This cleanup will:
1. Archive deprecated files (move to `archive/` folder)
2. Remove old test artifacts from Oct 2
3. Keep recent analysis outputs from Oct 9 (modular architecture testing)
4. Organize project structure for production use

## Files to Archive (Move to archive/)

### Deprecated Python Files
- `analyze_logs.py` - 3,000 line monolithic file (replaced by tier1_detection + tier2_analysis)
- `orchestrator.py` - Original orchestrator
- `orchestrator_automated.py` - First automated orchestrator (replaced by orchestrator_modular.py)
- `test_enhanced_detections.py` - Development testing script

**Reason**: These files are no longer used in the modular architecture but may be useful for reference.

## Files to Delete

### Old Analysis Artifacts (Oct 2)
```
analysis/analysis_20251002_*.json (2 files)
analysis/automated_analysis_20251002_*.json (7 files)
analysis/automated_analysis_20251002_*.md (2 files)
analysis/automated_tasks/ANOM-*_20251002_*.json (20+ files)
analysis/sub_agent_prompts/*.txt (3 files - old prompt outputs)
```

**Reason**: These are test outputs from development on Oct 2, before modular architecture was implemented.

### Recent Test Outputs to Keep (Oct 9)
```
analysis/anomalies/tier1_anomalies_20251009_*.json ✓ KEEP
analysis/investigations/* ✓ KEEP (if exists)
analysis/reports/final_report_20251009_*.json ✓ KEEP
```

**Reason**: These demonstrate the working modular architecture.

## Directory Structure After Cleanup

```
workspace_log_analyzer/
├── archive/                          # NEW: Deprecated files
│   ├── old_orchestrators/
│   │   ├── orchestrator.py
│   │   ├── orchestrator_automated.py
│   │   └── README.md
│   └── old_monolithic/
│       ├── analyze_logs.py
│       ├── test_enhanced_detections.py
│       └── README.md
│
├── tier1_detection/                  # Active detection modules
├── tier2_analysis/                   # Active agent modules
├── analysis/                         # Clean analysis output
│   ├── anomalies/                   # Tier-1 results (recent only)
│   ├── investigations/              # Tier-2 analyses (recent only)
│   └── reports/                     # Final reports (recent only)
│
├── config/                          # Configuration (keep empty dir)
├── data_sources/                    # Data sources (keep)
├── logs/                            # Log files (keep)
├── venv/                            # Virtual environment (keep)
├── web-ui/                          # Web interface (keep)
│
├── enrichment.py                    # Active files
├── fetch_logs.py
├── main.py
├── orchestrator_modular.py          # PRIMARY ORCHESTRATOR
├── report_aggregator.py
├── requirements.txt
│
├── README.md                        # Documentation
├── MODULAR_ARCHITECTURE.md
├── MITRE_ATTACK_ENHANCEMENTS.md
├── SUB_AGENT_PROMPTS_GUIDE.md
└── IMPLEMENTATION_COMPLETE.md
```

## Cleanup Commands

```bash
# 1. Create archive structure
mkdir -p archive/old_orchestrators
mkdir -p archive/old_monolithic

# 2. Move deprecated Python files
mv analyze_logs.py archive/old_monolithic/
mv test_enhanced_detections.py archive/old_monolithic/
mv orchestrator.py archive/old_orchestrators/
mv orchestrator_automated.py archive/old_orchestrators/

# 3. Delete old test artifacts (Oct 2)
rm analysis/analysis_20251002_*.json
rm analysis/automated_analysis_20251002_*.json
rm analysis/automated_analysis_20251002_*.md
rm -rf analysis/automated_tasks/
rm -rf analysis/sub_agent_prompts/

# 4. Create archive README files
echo "# Deprecated Orchestrators" > archive/old_orchestrators/README.md
echo "These orchestrators were replaced by orchestrator_modular.py" >> archive/old_orchestrators/README.md

echo "# Deprecated Monolithic Files" > archive/old_monolithic/README.md
echo "These files were replaced by the modular tier1_detection/ and tier2_analysis/ structure" >> archive/old_monolithic/README.md
```

## Benefits

✅ **Cleaner project structure** - Only active files in root
✅ **Clear primary entry point** - orchestrator_modular.py is the main orchestrator
✅ **Preserved history** - Deprecated files in archive/ for reference
✅ **Reduced confusion** - No multiple versions of orchestrators
✅ **Fresh analysis directory** - Only recent modular architecture outputs

## What NOT to Delete

❌ Don't delete recent analysis files (Oct 9) - they demonstrate working system
❌ Don't delete documentation files - all are current
❌ Don't delete tier1_detection/ or tier2_analysis/ - these are the new architecture
❌ Don't delete web-ui/ - it's the frontend
❌ Don't delete logs/ - contains test data
❌ Don't delete credentials.json or token.json - required for Google Workspace API

## Estimated Space Saved

- Old Python files: ~150KB (moved to archive, not deleted)
- Old analysis artifacts: ~2-3MB (deleted)

## Next Steps After Cleanup

1. Update README.md to point to orchestrator_modular.py as primary entry point
2. Update web-ui backend to import orchestrator_modular instead of orchestrator_automated
3. Run a fresh analysis to populate clean analysis/ directory
4. Consider adding .gitignore entries for analysis/* (keep only templates)
