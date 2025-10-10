import { X, AlertTriangle, Shield, MapPin, Clock, User } from 'lucide-react';
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
        className="fixed inset-0 bg-black bg-opacity-50 z-40 transition-opacity"
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
            <div
              className={`p-4 rounded-lg border-2 ${
                severityColors[anomaly.severity as keyof typeof severityColors] ||
                'bg-gray-100 text-gray-800 border-gray-200'
              }`}
            >
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 mt-0.5" />
                <div className="flex-1">
                  <h3 className="font-semibold mb-1">Security Anomaly Detected</h3>
                  <p className="text-sm mb-2">{anomaly.description}</p>
                  <div className="flex items-center gap-4 text-xs">
                    <span className="font-medium">
                      Severity: {anomaly.severity?.toUpperCase()}
                    </span>
                    {anomaly.refined_assessment && (
                      <span className="font-medium">
                        Actual Risk:{' '}
                        {anomaly.refined_assessment.is_actual_risk ? 'YES' : 'NO'}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* AI Analysis */}
          {anomaly?.refined_assessment && (
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
