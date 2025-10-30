import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation } from '@tanstack/react-query';
import { authAPI, logsAPI, analysisAPI, type LogEvent, type Anomaly } from '../lib/api';
import Button from '../components/Button';
import EventsTable from '../components/EventsTable';
import AnalysisDrawer from '../components/AnalysisDrawer';
import { Shield, LogOut, Download, CheckCircle, Clock, Loader2 } from 'lucide-react';

export default function DashboardPage() {
  const navigate = useNavigate();
  const [token, setToken] = useState<string | null>(null);
  const [hoursBack, setHoursBack] = useState(24);
  const [logFilePath, setLogFilePath] = useState<string | null>(null);
  const [logFilename, setLogFilename] = useState<string | null>(null);
  const [analysisFilename, setAnalysisFilename] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<LogEvent | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  useEffect(() => {
    const storedToken = localStorage.getItem('auth_token');
    if (!storedToken) {
      navigate('/');
    } else {
      setToken(storedToken);
    }
  }, [navigate]);

  // Fetch user info
  const { data: userInfo } = useQuery({
    queryKey: ['user', token],
    queryFn: () => authAPI.getCurrentUser(token!),
    enabled: !!token,
  });

  // Fetch logs mutation
  const fetchLogsMutation = useMutation({
    mutationFn: () => logsAPI.fetchLogs(token!, hoursBack),
    onSuccess: (data) => {
      setLogFilePath(data.log_file_path);
      const filename = data.log_file_path.split(/[/\\]/).pop() || '';
      setLogFilename(filename);
      // Automatically run analysis after logs are fetched
      // Pass the log file path directly to avoid race condition with state update
      runAnalysisMutation.mutate(data.log_file_path);
    },
  });

  // Get log details
  const { data: logData } = useQuery({
    queryKey: ['logs', logFilename],
    queryFn: () => logsAPI.getLogDetails(token!, logFilename!),
    enabled: !!logFilename && !!token,
  });

  // Run analysis mutation
  const runAnalysisMutation = useMutation({
    mutationFn: (logPath: string) => analysisAPI.runAnalysis(token!, logPath),
    onSuccess: (data) => {
      const filename = data.analysis_file_path.split(/[/\\]/).pop() || '';
      setAnalysisFilename(filename);
    },
  });

  // Get analysis details
  const { data: analysisData } = useQuery({
    queryKey: ['analysis', analysisFilename],
    queryFn: () => analysisAPI.getAnalysisDetails(token!, analysisFilename!),
    enabled: !!analysisFilename && !!token,
  });

  const handleLogout = () => {
    localStorage.removeItem('auth_token');
    navigate('/');
  };

  const handleFetchLogs = () => {
    fetchLogsMutation.mutate();
  };

  const handleEventClick = (event: LogEvent) => {
    setSelectedEvent(event);
    setIsDrawerOpen(true);
  };

  // Get anomalies mapped to events
  const eventAnomalies = new Map<string, Anomaly>();
  if (analysisData?.refined_anomalies) {
    analysisData.refined_anomalies.forEach((anomaly) => {
      // Try to match anomaly to event by user email and timestamp
      const evidence = anomaly.evidence as any;

      // Helper function to add event to map
      const addEventToMap = (evt: any) => {
        if (evt?.user_email && evt?.timestamp) {
          const key = `${evt.user_email}-${evt.timestamp}`;
          eventAnomalies.set(key, anomaly);
        }
      };

      // Handle different evidence structures
      if (evidence?.verification_events) {
        // MFA anomalies have verification_events
        evidence.verification_events.forEach(addEventToMap);
      }

      if (evidence?.failed_events) {
        // Failed login anomalies have failed_events
        evidence.failed_events.forEach(addEventToMap);
      }

      if (evidence?.events) {
        // Session anomalies (concurrent sessions, impossible travel) have events array
        evidence.events.forEach(addEventToMap);
      }

      if (evidence?.failure_event) {
        // Rapid retry anomalies have failure_event and success_event
        addEventToMap(evidence.failure_event);
      }

      if (evidence?.success_event) {
        addEventToMap(evidence.success_event);
      }
    });
  }

  // Mark events as suspicious if they have anomalies
  const eventsWithAnomalies = logData?.events.map((event) => {
    const key = `${event.user_email}-${event.timestamp}`;
    const anomaly = eventAnomalies.get(key);
    return {
      ...event,
      hasAnomaly: !!anomaly,
      anomaly: anomaly,
    };
  }) || [];

  const suspiciousCount = eventsWithAnomalies.filter((e) => e.hasAnomaly).length;

  // Debug logging
  if (analysisData && logData) {
    console.log('=== Analysis Debug ===');
    console.log('Total refined anomalies:', analysisData.refined_anomalies?.length);
    console.log('Event anomalies map size:', eventAnomalies.size);
    console.log('Events with anomalies:', suspiciousCount);
    console.log('Sample event key:', logData.events[0] ? `${logData.events[0].user_email}-${logData.events[0].timestamp}` : 'no events');
    if (analysisData.refined_anomalies?.[0]) {
      const anomaly = analysisData.refined_anomalies[0];
      console.log('Sample anomaly evidence keys:', Object.keys(anomaly.evidence));
      const evidence = anomaly.evidence as any;
      if (evidence.verification_events?.[0]) {
        console.log('Sample verification event key:', `${evidence.verification_events[0].user_email}-${evidence.verification_events[0].timestamp}`);
      }
    }
    console.log('====================');
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">
                  Workspace Log Analyzer
                </h1>
                {userInfo && (
                  <p className="text-sm text-gray-600">
                    {userInfo.user_email} • {userInfo.workspace_domain}
                  </p>
                )}
              </div>
            </div>
            <Button variant="ghost" onClick={handleLogout}>
              <LogOut className="w-4 h-4 mr-2" />
              Sign Out
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Controls */}
        <div className="bg-white rounded-lg shadow p-6 mb-6">
          <div className="flex items-end gap-4 flex-wrap">
            <div className="flex-1 min-w-[200px]">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                <Clock className="w-4 h-4 inline mr-1" />
                Lookback Period
              </label>
              <select
                value={hoursBack}
                onChange={(e) => setHoursBack(Number(e.target.value))}
                className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                disabled={fetchLogsMutation.isPending}
              >
                <option value={1}>Last 1 hour</option>
                <option value={6}>Last 6 hours</option>
                <option value={12}>Last 12 hours</option>
                <option value={24}>Last 24 hours</option>
                <option value={48}>Last 48 hours</option>
                <option value={72}>Last 72 hours</option>
                <option value={168}>Last 7 days</option>
              </select>
            </div>

            <Button
              onClick={handleFetchLogs}
              disabled={fetchLogsMutation.isPending}
              size="lg"
            >
              <Download className="w-4 h-4 mr-2" />
              {fetchLogsMutation.isPending ? 'Fetching...' : 'Fetch Logs'}
            </Button>
          </div>

          {/* Status Messages */}
          {fetchLogsMutation.isSuccess && logData && (
            <div className="mt-4 p-4 bg-green-50 border border-green-200 rounded-md">
              <div className="flex items-start">
                <CheckCircle className="w-5 h-5 text-green-600 mt-0.5 mr-2" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-green-800">
                    Successfully fetched {logData.metadata.total_events} events
                  </p>
                  <p className="text-xs text-green-700 mt-1">
                    Period: {logData.metadata.requested_time_range_hours} hours requested •{' '}
                    {logData.metadata.actual_time_range?.actual_span_hours.toFixed(2)} hours of
                    actual events
                  </p>
                </div>
              </div>
            </div>
          )}

          {runAnalysisMutation.isPending && (
            <div className="mt-4 p-4 bg-blue-50 border border-blue-200 rounded-md">
              <div className="flex items-start">
                <Loader2 className="w-5 h-5 text-blue-600 mt-0.5 mr-2 animate-spin" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-blue-800">
                    Running tier-2 AI analysis on suspicious events...
                  </p>
                  <p className="text-xs text-blue-700 mt-1">
                    Deep analysis in progress - this may take a moment
                  </p>
                </div>
              </div>
            </div>
          )}

          {runAnalysisMutation.isSuccess && analysisData && (
            <div className={`mt-4 p-4 border rounded-md ${
              analysisData.metadata.anomaly_summary.actual_risks > 0
                ? 'bg-red-50 border-red-200'
                : 'bg-green-50 border-green-200'
            }`}>
              <div className="flex items-start">
                {analysisData.metadata.anomaly_summary.actual_risks > 0 ? (
                  <Shield className={`w-5 h-5 mt-0.5 mr-2 ${
                    analysisData.metadata.anomaly_summary.actual_risks > 0
                      ? 'text-red-600'
                      : 'text-green-600'
                  }`} />
                ) : (
                  <CheckCircle className="w-5 h-5 text-green-600 mt-0.5 mr-2" />
                )}
                <div className="flex-1">
                  <p className={`text-sm font-medium ${
                    analysisData.metadata.anomaly_summary.actual_risks > 0
                      ? 'text-red-800'
                      : 'text-green-800'
                  }`}>
                    {analysisData.metadata.anomaly_summary.actual_risks > 0 ? (
                      <>⚠️ Tier-2 analysis complete: {analysisData.metadata.anomaly_summary.actual_risks}{' '}
                      actual threat(s) detected</>
                    ) : (
                      <>✓ Tier-2 analysis complete: All suspicious events analyzed as benign</>
                    )}
                  </p>
                  <p className={`text-xs mt-1 ${
                    analysisData.metadata.anomaly_summary.actual_risks > 0
                      ? 'text-red-700'
                      : 'text-green-700'
                  }`}>
                    {analysisData.metadata.anomaly_summary.total_initial_detections} initial
                    detections • {analysisData.metadata.anomaly_summary.total_refined_anomalies}{' '}
                    analyzed • {analysisData.metadata.anomaly_summary.false_positives_filtered}{' '}
                    false positives filtered
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Stats */}
        {logData && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-white rounded-lg shadow p-4">
              <p className="text-sm text-gray-600">Total Events</p>
              <p className="text-2xl font-bold text-gray-900">
                {logData.metadata.total_events}
              </p>
            </div>
            <div className="bg-white rounded-lg shadow p-4">
              <p className="text-sm text-gray-600">Unique Users</p>
              <p className="text-2xl font-bold text-gray-900">
                {logData.metadata.summary.unique_users}
              </p>
            </div>
            <div className="bg-white rounded-lg shadow p-4">
              <p className="text-sm text-gray-600">Unique IPs</p>
              <p className="text-2xl font-bold text-gray-900">
                {logData.metadata.summary.unique_ips}
              </p>
            </div>
            <div className="bg-white rounded-lg shadow p-4">
              <p className="text-sm text-gray-600">Suspicious Events</p>
              <p className="text-2xl font-bold text-red-600">{suspiciousCount}</p>
            </div>
          </div>
        )}

        {/* Events Table */}
        {logData && (
          <div className="bg-white rounded-lg shadow">
            <EventsTable
              events={eventsWithAnomalies}
              onEventClick={handleEventClick}
            />
          </div>
        )}

        {/* Empty State */}
        {!logData && !fetchLogsMutation.isPending && (
          <div className="bg-white rounded-lg shadow p-12 text-center">
            <Shield className="w-16 h-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No logs loaded</h3>
            <p className="text-gray-600 mb-6">
              Select a lookback period and click "Fetch Logs" to get started
            </p>
          </div>
        )}
      </main>

      {/* Analysis Drawer */}
      <AnalysisDrawer
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
        event={selectedEvent}
        anomaly={(selectedEvent as any)?.anomaly}
      />
    </div>
  );
}
