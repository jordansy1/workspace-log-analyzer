"""
Report Aggregator

Generates comprehensive, executive-ready security analysis reports by aggregating
initial detection, enriched context, and sub-agent refined assessments.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any


class ReportAggregator:
    """Aggregates multi-agent analysis into comprehensive security reports."""

    def __init__(self, analysis_file_path: str):
        """
        Initialize report aggregator.

        Args:
            analysis_file_path: Path to automated_analysis_*.json file
        """
        self.analysis_file_path = analysis_file_path
        with open(analysis_file_path, 'r') as f:
            self.analysis_data = json.load(f)

    def generate_executive_report(self, output_path: str = None) -> str:
        """
        Generate executive summary report in markdown format.

        Args:
            output_path: Optional path to save report

        Returns:
            Markdown formatted report
        """
        report_lines = []

        # Header
        report_lines.append("# Google Workspace Authentication Security Analysis")
        report_lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")

        # Executive Summary
        report_lines.extend(self._generate_executive_summary())

        # Risk Assessment
        report_lines.extend(self._generate_risk_assessment())

        # Detailed Findings
        report_lines.extend(self._generate_detailed_findings())

        # Recommendations
        report_lines.extend(self._generate_recommendations())

        # Appendix
        report_lines.extend(self._generate_appendix())

        # Combine and save
        report = "\n".join(report_lines)

        if output_path:
            with open(output_path, 'w') as f:
                f.write(report)
            print(f"[OK] Executive report saved: {output_path}")

        return report

    def _generate_executive_summary(self) -> List[str]:
        """Generate executive summary section."""
        lines = []
        metadata = self.analysis_data.get('metadata', {})
        summary = metadata.get('anomaly_summary', {})
        log_meta = metadata.get('log_metadata', {})

        lines.append("## Executive Summary")
        lines.append("")

        # Overview - Enhanced time range reporting
        requested_hours = log_meta.get('requested_time_range_hours')
        actual_range = log_meta.get('actual_time_range', {})

        if requested_hours:
            lines.append(f"**Requested Analysis Period:** Last {requested_hours} hours")

        if actual_range:
            earliest = actual_range.get('earliest_event', 'N/A')
            latest = actual_range.get('latest_event', 'N/A')
            span = actual_range.get('actual_span_hours', 0)

            # Format timestamps for readability
            if earliest != 'N/A':
                from dateutil import parser
                earliest_dt = parser.isoparse(earliest)
                latest_dt = parser.isoparse(latest)
                earliest_str = earliest_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                latest_str = latest_dt.strftime('%Y-%m-%d %H:%M:%S UTC')

                lines.append(f"**Actual Event Window:** {earliest_str} to {latest_str} ({span} hours)")

        lines.append(f"**Total Authentication Events:** {metadata.get('total_events_analyzed', 0)}")
        lines.append(f"**Unique Users:** {log_meta.get('summary', {}).get('unique_users', 0)}")
        lines.append(f"**Unique IP Addresses:** {log_meta.get('summary', {}).get('unique_ips', 0)}")
        lines.append(f"**Geographic Regions:** {log_meta.get('summary', {}).get('unique_regions', 0)}")
        lines.append("")

        # Key Findings
        actual_risks = summary.get('actual_risks', 0)
        false_positives = summary.get('false_positives_filtered', 0)

        lines.append("### Key Findings")
        lines.append("")

        if actual_risks == 0:
            lines.append("[OK] **No significant security risks detected**")
            lines.append("")
            lines.append(f"- {summary.get('total_initial_detections', 0)} potential anomalies investigated")
            lines.append(f"- All findings assessed as low-risk or expected behavior")
            lines.append(f"- {false_positives} false positives successfully filtered by AI analysis")
        else:
            lines.append(f"[WARNING] **{actual_risks} security risk(s) requiring attention**")
            lines.append("")
            lines.append(f"- High Severity: {summary.get('high_severity', 0)}")
            lines.append(f"- Medium Severity: {summary.get('medium_severity', 0)}")
            lines.append(f"- Low Severity: {summary.get('low_severity', 0)}")

        lines.append("")
        return lines

    def _generate_risk_assessment(self) -> List[str]:
        """Generate risk assessment section."""
        lines = []
        refined = self.analysis_data.get('refined_anomalies', [])

        lines.append("## Risk Assessment")
        lines.append("")

        # Overall risk level
        high_count = sum(1 for a in refined if a.get('severity') == 'high')
        medium_count = sum(1 for a in refined if a.get('severity') == 'medium')

        if high_count > 0:
            overall_risk = "HIGH"
            risk_indicator = "[HIGH]"
        elif medium_count > 0:
            overall_risk = "MEDIUM"
            risk_indicator = "[MEDIUM]"
        else:
            overall_risk = "LOW"
            risk_indicator = "[LOW]"

        lines.append(f"### Overall Risk Level: {risk_indicator} **{overall_risk}**")
        lines.append("")

        # Risk factors
        if high_count > 0 or medium_count > 0:
            lines.append("**Contributing Factors:**")
            for anomaly in refined:
                if anomaly.get('severity') in ['high', 'medium']:
                    lines.append(f"- {anomaly.get('description', 'Unknown anomaly')}")
            lines.append("")

        return lines

    def _generate_detailed_findings(self) -> List[str]:
        """Generate detailed findings section."""
        lines = []
        refined = self.analysis_data.get('refined_anomalies', [])

        lines.append("## Detailed Findings")
        lines.append("")

        if not refined:
            lines.append("No anomalies detected.")
            lines.append("")
            return lines

        # Group by severity
        high_findings = [a for a in refined if a.get('severity') == 'high']
        medium_findings = [a for a in refined if a.get('severity') == 'medium']
        low_findings = [a for a in refined if a.get('severity') == 'low']

        # High severity findings
        if high_findings:
            lines.append("### [HIGH] High Severity Findings")
            lines.append("")
            for idx, finding in enumerate(high_findings, 1):
                lines.extend(self._format_finding(finding, idx))

        # Medium severity findings
        if medium_findings:
            lines.append("### [MEDIUM] Medium Severity Findings")
            lines.append("")
            for idx, finding in enumerate(medium_findings, 1):
                lines.extend(self._format_finding(finding, idx))

        # Low severity findings
        if low_findings:
            lines.append("### [LOW] Low Severity Findings")
            lines.append("")
            for idx, finding in enumerate(low_findings, 1):
                lines.extend(self._format_finding(finding, idx))

        return lines

    def _format_finding(self, finding: Dict, number: int) -> List[str]:
        """Format individual finding."""
        lines = []

        lines.append(f"#### Finding {number}: {finding.get('type', 'Unknown').replace('_', ' ').title()}")
        lines.append("")
        lines.append(f"**Description:** {finding.get('description', 'No description')}")
        lines.append("")

        # Refined assessment (if available)
        refined = finding.get('refined_assessment', {})
        if refined:
            lines.append("**AI Analysis:**")
            lines.append(f"- Actual Risk: {'Yes' if refined.get('is_actual_risk', True) else 'No'}")
            lines.append(f"- Scenario: {refined.get('likely_scenario', 'Unknown')}")
            lines.append(f"- Confidence: {refined.get('confidence', 'Unknown').upper()}")
            lines.append("")
            lines.append(f"*Reasoning:* {refined.get('reasoning', 'No reasoning provided')}")
            lines.append("")

            # Key enriched factors
            key_factors = refined.get('key_enriched_factors', {})
            if key_factors:
                lines.append("**Contextual Factors:**")
                if '2fa_enrolled' in key_factors:
                    lines.append(f"- 2FA Enrolled: {key_factors['2fa_enrolled']}")
                if 'ip_risk_score' in key_factors:
                    lines.append(f"- IP Risk Score: {key_factors['ip_risk_score']}/100")
                if 'is_anonymized' in key_factors:
                    lines.append(f"- Anonymized Access: {key_factors['is_anonymized']}")
                if 'baseline_deviations' in key_factors and key_factors['baseline_deviations']:
                    lines.append(f"- Baseline Deviations: {', '.join(key_factors['baseline_deviations'])}")
                lines.append("")

            # Recommendation
            if refined.get('recommendation'):
                lines.append(f"**Recommendation:** {refined['recommendation']}")
                lines.append("")

        lines.append("---")
        lines.append("")
        return lines

    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations section."""
        lines = []
        refined = self.analysis_data.get('refined_anomalies', [])

        lines.append("## Recommendations")
        lines.append("")

        # Collect all recommendations
        recommendations = []
        for anomaly in refined:
            refined_assessment = anomaly.get('refined_assessment', {})
            rec = refined_assessment.get('recommendation')
            if rec and rec != 'no action required':
                recommendations.append({
                    'severity': anomaly.get('severity', 'low'),
                    'recommendation': rec,
                    'type': anomaly.get('type')
                })

        if not recommendations:
            lines.append("[OK] **No immediate actions required**")
            lines.append("")
            lines.append("All detected anomalies have been assessed as expected behavior or low risk.")
            lines.append("")
            lines.append("**Ongoing Best Practices:**")
            lines.append("- Continue monitoring authentication logs regularly")
            lines.append("- Maintain 2FA enforcement for all users")
            lines.append("- Review access patterns quarterly")
            lines.append("")
        else:
            # Prioritized recommendations
            lines.append("### Immediate Actions")
            lines.append("")

            high_recs = [r for r in recommendations if r['severity'] == 'high']
            if high_recs:
                lines.append("**High Priority:**")
                for rec in high_recs:
                    lines.append(f"- {rec['recommendation']}")
                lines.append("")

            medium_recs = [r for r in recommendations if r['severity'] == 'medium']
            if medium_recs:
                lines.append("**Medium Priority:**")
                for rec in medium_recs:
                    lines.append(f"- {rec['recommendation']}")
                lines.append("")

            low_recs = [r for r in recommendations if r['severity'] == 'low']
            if low_recs:
                lines.append("**Low Priority:**")
                for rec in low_recs:
                    lines.append(f"- {rec['recommendation']}")
                lines.append("")

        return lines

    def _generate_appendix(self) -> List[str]:
        """Generate appendix with technical details."""
        lines = []
        metadata = self.analysis_data.get('metadata', {})

        lines.append("## Appendix")
        lines.append("")

        lines.append("### Analysis Methodology")
        lines.append("")
        lines.append("This report was generated using a multi-agent AI security analysis system:")
        lines.append("")
        lines.append("1. **Primary Detection:** Rule-based pattern matching for anomaly identification")
        lines.append("2. **Data Enrichment:** Integration of threat intelligence (AbuseIPDB, VirusTotal), geolocation (IPInfo.io), and user context (Google Directory API)")
        lines.append("3. **AI Analysis:** Specialized sub-agents analyze each anomaly with full contextual awareness")
        lines.append("4. **Aggregation:** Results synthesized into actionable intelligence")
        lines.append("")

        lines.append(f"**Analysis Version:** {metadata.get('analysis_version', 'Unknown')}")
        lines.append(f"**Sub-Agent Executions:** {metadata.get('sub_agent_executions', 0)}")
        lines.append("")

        lines.append("### Data Sources")
        lines.append("")
        lines.append("- Google Workspace Admin SDK (Authentication Logs, Directory API)")
        lines.append("- AbuseIPDB (IP Reputation)")
        lines.append("- VirusTotal (Multi-Engine Threat Intelligence)")
        lines.append("- IPInfo.io (Geolocation & VPN Detection)")
        lines.append("- Historical Baseline (Custom Pattern Learning)")
        lines.append("")

        return lines


def main():
    """Generate executive report from analysis file."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python report_aggregator.py <analysis_file>")
        print("\nExample:")
        print("  python report_aggregator.py analysis/automated_analysis_20251002_141156.json")
        sys.exit(1)

    analysis_file = sys.argv[1]

    if not os.path.exists(analysis_file):
        print(f"Error: Analysis file not found: {analysis_file}")
        sys.exit(1)

    # Generate report
    aggregator = ReportAggregator(analysis_file)

    output_path = analysis_file.replace('.json', '_report.md')
    report = aggregator.generate_executive_report(output_path)

    print("\nExecutive Report Generated!")
    print(f"View at: {output_path}")


if __name__ == "__main__":
    main()
