import { X, AlertTriangle, Shield, MapPin, Clock, User, ClipboardList, HelpCircle, CheckCircle, Search, Brain, Zap, FileSearch } from 'lucide-react';
import { format } from 'date-fns';
import Button from './Button';
import type { LogEvent, Anomaly } from '../lib/api';

interface AnalysisDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  event: LogEvent | null;
  anomaly?: Anomaly;
}

export default function AnalysisDrawer({ isOpen, onClose, event, anomaly }: AnalysisDrawerProps) {
  if (!isOpen || !event) return null;

  const severityColors = {
    high: 'bg-red-100 text-red-800 border-red-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-blue-100 text-blue-800 border-blue-200',
  };

  const confidenceColors = {
    high: 'text-green-600',
    medium: 'text-yellow-600',
    low: 'text-red-600',
  };

  return (
    <>
      {/* Overlay */}
      <div
        className="fixed inset-0 bg-black/50 z-40 transition-opacity"
        onClick={onClose}
      />

      {/* Drawer */}
      <div className="fixed right-0 top-0 h-full w-full max-w-2xl bg-white shadow-xl z-50 overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900">Event Details</h2>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Anomaly Alert */}
          {anomaly && (
            <div className="p-4 rounded-lg border-2 bg-yellow-50 text-yellow-900 border-yellow-300">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 mt-0.5" />
                <div className="flex-1">
                  <h3 className="font-semibold mb-1">Tier-1 Suspicious Event Detected</h3>
                  <p className="text-sm mb-2">{anomaly.description}</p>
                  <p className="text-xs text-yellow-800">
                    This event was flagged by tier-1 deterministic detection. See tier-2 AI analysis below for threat assessment and severity determination.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Triage Guidance (Tier-1 Analyst Recommendations) */}
          {anomaly?.triage_guidance && (
            <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3">
                <ClipboardList className="w-5 h-5 text-purple-600" />
                <h3 className="font-semibold text-purple-900">Triage Guidance</h3>
                <span
                  className={`ml-auto px-2 py-0.5 rounded text-xs font-medium ${
                    anomaly.triage_guidance.priority === 'IMMEDIATE'
                      ? 'bg-red-600 text-white'
                      : anomaly.triage_guidance.priority === 'HIGH'
                      ? 'bg-orange-500 text-white'
                      : anomaly.triage_guidance.priority === 'MEDIUM'
                      ? 'bg-yellow-500 text-white'
                      : 'bg-blue-500 text-white'
                  }`}
                >
                  {anomaly.triage_guidance.priority} PRIORITY
                </span>
              </div>

              <div className="space-y-3 text-sm">
                {/* Severity Rationale */}
                <div>
                  <span className="font-medium text-purple-900">Why This Matters:</span>
                  <p className="mt-1 text-purple-800">
                    {anomaly.triage_guidance.severity_rationale}
                  </p>
                </div>

                {/* Risk Factors */}
                {anomaly.triage_guidance.risk_factors && Object.keys(anomaly.triage_guidance.risk_factors).length > 0 && (
                  <div>
                    <span className="font-medium text-purple-900 block mb-2">Risk Factors:</span>
                    <div className="space-y-1">
                      {Object.entries(anomaly.triage_guidance.risk_factors).map(([key, value]) => (
                        <div key={key} className="flex items-center gap-2 text-xs">
                          <CheckCircle className={`w-4 h-4 ${value ? 'text-red-600' : 'text-gray-400'}`} />
                          <span className={value ? 'text-purple-900 font-medium' : 'text-purple-600'}>
                            {key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recommended Actions */}
                {anomaly.triage_guidance.recommended_actions.length > 0 && (
                  <div className="pt-3 border-t border-purple-200">
                    <span className="font-medium text-purple-900 block mb-2">Recommended Actions:</span>
                    <ol className="space-y-1.5 list-decimal list-inside text-purple-800">
                      {anomaly.triage_guidance.recommended_actions.map((action, idx) => (
                        <li key={idx} className="text-xs leading-relaxed">{action}</li>
                      ))}
                    </ol>
                  </div>
                )}

                {/* Investigation Questions */}
                {anomaly.triage_guidance.investigation_questions.length > 0 && (
                  <div className="pt-3 border-purple-200">
                    <span className="font-medium text-purple-900 flex items-center gap-1 mb-2">
                      <HelpCircle className="w-4 h-4" />
                      Investigation Questions:
                    </span>
                    <ul className="space-y-1 list-disc list-inside text-purple-800">
                      {anomaly.triage_guidance.investigation_questions.map((question, idx) => (
                        <li key={idx} className="text-xs leading-relaxed">{question}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* False Positive Indicators */}
                {anomaly.triage_guidance.likely_false_positive_if && anomaly.triage_guidance.likely_false_positive_if.length > 0 && (
                  <div className="pt-3 border-t border-purple-200">
                    <span className="font-medium text-purple-900 block mb-2">
                      Likely False Positive If:
                    </span>
                    <ul className="space-y-1 text-xs text-purple-700">
                      {anomaly.triage_guidance.likely_false_positive_if.map((indicator, idx) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className="text-purple-400 mt-0.5">→</span>
                          <span>{indicator}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Tier-1 Detection Details */}
          {anomaly && (
            <div className="bg-indigo-50 border border-indigo-200 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3">
                <Search className="w-5 h-5 text-indigo-600" />
                <h3 className="font-semibold text-indigo-900">Tier-1 Detection Details</h3>
                <span className="ml-auto px-2 py-0.5 bg-indigo-100 text-indigo-700 rounded-sm text-xs font-medium">
                  Deterministic Analysis
                </span>
              </div>

              <div className="space-y-3 text-sm">
                {/* Detection Method */}
                <div>
                  <span className="font-medium text-indigo-900">Detection Method:</span>{' '}
                  <span className="text-indigo-800">
                    {anomaly.type?.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                  </span>
                </div>

                {/* Anomaly ID */}
                <div>
                  <span className="font-medium text-indigo-900">Anomaly ID:</span>{' '}
                  <code className="text-xs bg-indigo-100 px-2 py-1 rounded-sm text-indigo-800">
                    {anomaly.id}
                  </code>
                </div>

                {/* MITRE ATT&CK Mapping */}
                {anomaly.mitre_attack && anomaly.mitre_attack.length > 0 && (
                  <div>
                    <span className="font-medium text-indigo-900 block mb-2">
                      MITRE ATT&CK Techniques:
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {anomaly.mitre_attack.map((technique) => (
                        <span
                          key={technique}
                          className="px-2 py-1 bg-indigo-600 text-white rounded-sm text-xs font-mono"
                        >
                          {technique}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Sub-Agent Assignment */}
                {anomaly.sub_agent && (
                  <div className="pt-3 border-t border-indigo-200">
                    <span className="font-medium text-indigo-900">Routed to Sub-Agent:</span>{' '}
                    <span className="text-indigo-800 font-mono text-xs">
                      {anomaly.sub_agent}
                    </span>
                  </div>
                )}

                {/* Context Questions */}
                {anomaly.context_questions && anomaly.context_questions.length > 0 && (
                  <div className="pt-3 border-t border-indigo-200">
                    <span className="font-medium text-indigo-900 flex items-center gap-1 mb-2">
                      <HelpCircle className="w-4 h-4" />
                      Investigation Context:
                    </span>
                    <ul className="space-y-1 text-xs text-indigo-700">
                      {anomaly.context_questions.map((question, idx) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className="text-indigo-400 mt-0.5">•</span>
                          <span>{question}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Tier-2 AI Agent Analysis */}
          {anomaly?.tier2_analysis && (
            <div className="bg-linear-to-br from-blue-50 to-cyan-50 border-2 border-blue-300 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3">
                <Brain className="w-5 h-5 text-blue-600" />
                <h3 className="font-semibold text-blue-900">Tier-2 AI Agent Analysis</h3>
                <span className="ml-auto px-2 py-0.5 bg-blue-600 text-white rounded-sm text-xs font-medium flex items-center gap-1">
                  <Zap className="w-3 h-3" />
                  AI-Powered
                </span>
              </div>

              <div className="space-y-4 text-sm">
                {/* Agent Information */}
                <div className="bg-white/60 rounded-lg p-3 border border-blue-200">
                  <div className="flex items-center gap-2 mb-2">
                    <FileSearch className="w-4 h-4 text-blue-700" />
                    <span className="font-semibold text-blue-900">Agent Details</span>
                  </div>
                  <div className="space-y-2 text-xs">
                    <div>
                      <span className="font-medium text-blue-800">Agent Name:</span>{' '}
                      <code className="bg-blue-100 px-2 py-0.5 rounded-sm text-blue-900">
                        {anomaly.tier2_analysis.agent_name}
                      </code>
                    </div>
                    <div>
                      <span className="font-medium text-blue-800">Confidence Level:</span>{' '}
                      <span
                        className={`font-semibold ${
                          confidenceColors[
                            anomaly.tier2_analysis.confidence as keyof typeof confidenceColors
                          ] || 'text-gray-600'
                        }`}
                      >
                        {anomaly.tier2_analysis.confidence.toUpperCase()}
                      </span>
                    </div>
                    <div>
                      <span className="font-medium text-blue-800">Risk Assessment:</span>{' '}
                      <span
                        className={`font-semibold ${
                          anomaly.tier2_analysis.is_actual_risk
                            ? 'text-red-600'
                            : 'text-green-600'
                        }`}
                      >
                        {anomaly.tier2_analysis.is_actual_risk ? '⚠️ ACTUAL THREAT' : '✓ BENIGN'}
                      </span>
                    </div>
                    <div>
                      <span className="font-medium text-blue-800">Adjusted Severity:</span>{' '}
                      <span className="uppercase text-blue-900 font-medium">
                        {anomaly.tier2_analysis.adjusted_severity}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Analysis Methodology & Steps */}
                <div>
                  <span className="font-semibold text-blue-900 flex items-center gap-2 mb-2">
                    <ClipboardList className="w-4 h-4" />
                    Analysis Methodology
                  </span>
                  <div className="bg-white/60 rounded-lg p-3 border border-blue-200">
                    <p className="text-xs text-blue-700 mb-3">
                      This specialized AI agent analyzed the anomaly using contextual enrichment data including:
                    </p>
                    <ul className="space-y-1.5 text-xs text-blue-800">
                      <li className="flex items-start gap-2">
                        <CheckCircle className="w-3.5 h-3.5 text-blue-600 mt-0.5 shrink-0" />
                        <span><strong>IP Reputation Analysis:</strong> Checked against AbuseIPDB and VirusTotal threat intelligence feeds</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <CheckCircle className="w-3.5 h-3.5 text-blue-600 mt-0.5 shrink-0" />
                        <span><strong>Geolocation Context:</strong> Evaluated access patterns and travel feasibility</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <CheckCircle className="w-3.5 h-3.5 text-blue-600 mt-0.5 shrink-0" />
                        <span><strong>User Behavior Baseline:</strong> Compared against historical login patterns for this user</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <CheckCircle className="w-3.5 h-3.5 text-blue-600 mt-0.5 shrink-0" />
                        <span><strong>Organizational Context:</strong> Considered user role, permissions, and device trust status</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <CheckCircle className="w-3.5 h-3.5 text-blue-600 mt-0.5 shrink-0" />
                        <span><strong>Temporal Analysis:</strong> Examined timing patterns and sequence of events</span>
                      </li>
                    </ul>
                  </div>
                </div>

                {/* Forensic Narrative */}
                {anomaly.tier2_analysis.forensic_narrative && (
                  <div>
                    <span className="font-semibold text-blue-900 block mb-2">
                      Forensic Analysis & Conclusion
                    </span>
                    <div className="bg-white/80 rounded-lg p-3 border border-blue-200">
                      <p className="text-sm text-blue-900 whitespace-pre-wrap leading-relaxed">
                        {anomaly.tier2_analysis.forensic_narrative}
                      </p>
                    </div>
                  </div>
                )}

                {/* Recommended Actions */}
                {anomaly.tier2_analysis.recommended_actions &&
                 anomaly.tier2_analysis.recommended_actions.length > 0 && (
                  <div className="pt-3 border-t border-blue-200">
                    <span className="font-semibold text-blue-900 block mb-2">
                      Agent Recommendations
                    </span>
                    <ol className="space-y-1.5 list-decimal list-inside text-blue-800">
                      {anomaly.tier2_analysis.recommended_actions.map((action, idx) => (
                        <li key={idx} className="text-xs leading-relaxed">{action}</li>
                      ))}
                    </ol>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Legacy AI Analysis (fallback for old format) */}
          {anomaly?.refined_assessment && !anomaly?.tier2_analysis && (
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3">
                <Shield className="w-5 h-5 text-blue-600" />
                <h3 className="font-semibold text-blue-900">AI Analysis</h3>
              </div>

              <div className="space-y-3 text-sm">
                <div>
                  <span className="font-medium text-blue-900">Scenario:</span>{' '}
                  <span className="text-blue-800">
                    {anomaly.refined_assessment.likely_scenario.replace(/_/g, ' ')}
                  </span>
                </div>

                <div>
                  <span className="font-medium text-blue-900">Confidence:</span>{' '}
                  <span
                    className={`font-medium ${
                      confidenceColors[
                        anomaly.refined_assessment.confidence as keyof typeof confidenceColors
                      ] || 'text-gray-600'
                    }`}
                  >
                    {anomaly.refined_assessment.confidence.toUpperCase()}
                  </span>
                </div>

                <div>
                  <span className="font-medium text-blue-900">Reasoning:</span>
                  <p className="mt-1 text-blue-800 whitespace-pre-wrap">
                    {anomaly.refined_assessment.reasoning}
                  </p>
                </div>

                {anomaly.refined_assessment.recommendation && (
                  <div className="mt-3 pt-3 border-t border-blue-200">
                    <span className="font-medium text-blue-900">Recommendation:</span>
                    <p className="mt-1 text-blue-800">
                      {anomaly.refined_assessment.recommendation}
                    </p>
                  </div>
                )}

                {/* Key Factors */}
                {anomaly.refined_assessment.key_enriched_factors && (
                  <div className="mt-3 pt-3 border-t border-blue-200">
                    <span className="font-medium text-blue-900 block mb-2">
                      Key Contextual Factors:
                    </span>
                    <div className="grid grid-cols-2 gap-2">
                      {Object.entries(anomaly.refined_assessment.key_enriched_factors).map(
                        ([key, value]) => (
                          <div key={key} className="text-xs">
                            <span className="text-blue-700">
                              {key.replace(/_/g, ' ')}:
                            </span>{' '}
                            <span className="text-blue-900 font-medium">
                              {typeof value === 'boolean'
                                ? value
                                  ? 'Yes'
                                  : 'No'
                                : JSON.stringify(value)}
                            </span>
                          </div>
                        )
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Basic Event Info */}
          <div>
            <h3 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
              <Clock className="w-5 h-5" />
              Event Information
            </h3>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
              <div>
                <dt className="text-gray-600">Timestamp</dt>
                <dd className="font-medium text-gray-900">
                  {format(new Date(event.timestamp), 'PPpp')}
                </dd>
              </div>
              <div>
                <dt className="text-gray-600">Event Type</dt>
                <dd className="font-medium text-gray-900">{event.event_name}</dd>
              </div>
              <div>
                <dt className="text-gray-600">Login Type</dt>
                <dd className="font-medium text-gray-900">{event.login_type || 'N/A'}</dd>
              </div>
              <div>
                <dt className="text-gray-600">Second Factor</dt>
                <dd className="font-medium text-gray-900">
                  {event.is_second_factor === undefined
                    ? 'N/A'
                    : event.is_second_factor
                    ? 'Yes'
                    : 'No'}
                </dd>
              </div>
            </dl>
          </div>

          {/* User Info */}
          <div>
            <h3 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
              <User className="w-5 h-5" />
              User Context
            </h3>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
              <div>
                <dt className="text-gray-600">Email</dt>
                <dd className="font-medium text-gray-900">{event.user_email}</dd>
              </div>
              {event.user_context && (
                <>
                  <div>
                    <dt className="text-gray-600">Admin Status</dt>
                    <dd className="font-medium text-gray-900">
                      {event.user_context.is_admin ? 'Yes' : 'No'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-gray-600">2FA Enrolled</dt>
                    <dd className="font-medium text-gray-900">
                      {event.user_context.is_2fa_enrolled ? 'Yes' : 'No'}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-gray-600">2FA Enforced</dt>
                    <dd className="font-medium text-gray-900">
                      {event.user_context.is_2fa_enforced ? 'Yes' : 'No'}
                    </dd>
                  </div>
                </>
              )}
            </dl>
          </div>

          {/* Network & Location */}
          <div>
            <h3 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
              <MapPin className="w-5 h-5" />
              Network & Location
            </h3>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
              <div>
                <dt className="text-gray-600">IP Address</dt>
                <dd className="font-medium text-gray-900">{event.ip_address}</dd>
              </div>
              {event.enriched_location && (
                <>
                  <div>
                    <dt className="text-gray-600">Location</dt>
                    <dd className="font-medium text-gray-900">
                      {event.enriched_location.city}, {event.enriched_location.region},{' '}
                      {event.enriched_location.country}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-gray-600">VPN/Proxy</dt>
                    <dd className="font-medium text-gray-900">
                      {event.enriched_location.is_vpn ||
                      event.enriched_location.is_proxy ||
                      event.enriched_location.is_tor
                        ? 'Yes'
                        : 'No'}
                    </dd>
                  </div>
                </>
              )}
              {event.ip_reputation && (
                <div>
                  <dt className="text-gray-600">IP Risk Score</dt>
                  <dd className="font-medium text-gray-900">
                    {event.ip_reputation.overall_risk_score}/100
                  </dd>
                </div>
              )}
            </dl>
          </div>

          {/* Raw Data */}
          <div>
            <h3 className="font-semibold text-gray-900 mb-3">Raw Event Data</h3>
            <div className="bg-gray-50 rounded-lg p-4 overflow-x-auto">
              <pre className="text-xs text-gray-800">
                {JSON.stringify(event, null, 2)}
              </pre>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="sticky bottom-0 bg-white border-t border-gray-200 px-6 py-4">
          <Button onClick={onClose} variant="secondary" className="w-full">
            Close
          </Button>
        </div>
      </div>
    </>
  );
}
