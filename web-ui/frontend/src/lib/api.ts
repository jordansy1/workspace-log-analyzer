import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
});

export interface AuthResponse {
  authorization_url: string;
  state: string;
}

export interface UserInfo {
  user_email: string;
  workspace_domain: string;
}

export interface LogMetadata {
  fetch_time: string;
  total_events: number;
  requested_time_range_hours: number;
  actual_time_range: {
    earliest_event: string;
    latest_event: string;
    actual_span_hours: number;
  };
  summary: {
    unique_users: number;
    unique_ips: number;
    unique_regions: number;
    event_type_breakdown: Record<string, number>;
  };
}

export interface LogEvent {
  timestamp: string;
  event_id: string;
  user_email: string;
  ip_address: string;
  event_name: string;
  event_type: string;
  login_type?: string;
  is_suspicious: boolean;
  is_second_factor?: boolean;
  login_challenge_method?: string;  // NEW: MFA/challenge type used
  network_info?: {
    ip_asn: string;
    region_code: string;
    subdivision_code: string;
  };
  ip_reputation?: {
    overall_risk_score: number;
    is_malicious: boolean;
  };
  enriched_location?: {
    city: string;
    region: string;
    country: string;
    is_vpn: boolean;
    is_proxy: boolean;
    is_tor: boolean;
  };
  user_context?: {
    is_admin: boolean;
    is_2fa_enrolled: boolean;
    is_2fa_enforced: boolean;
  };
  [key: string]: any;
}

export interface LogData {
  metadata: LogMetadata;
  events: LogEvent[];
}

export interface TriageGuidance {
  priority: 'IMMEDIATE' | 'HIGH' | 'MEDIUM' | 'LOW';
  severity_rationale: string;
  risk_factors?: Record<string, boolean>;
  recommended_actions: string[];
  investigation_questions: string[];
  likely_false_positive_if?: string[];
}

export interface Tier2Analysis {
  agent_name: string;
  is_actual_risk: boolean;
  confidence: 'high' | 'medium' | 'low';
  adjusted_severity: string;
  forensic_narrative: string;
  recommended_actions: string[];
}

export interface Anomaly {
  id: string;
  type: string;
  severity: string;
  description: string;
  is_actual_risk?: boolean;
  sub_agent?: string;  // Tier-2 agent that analyzed this anomaly
  context_questions?: string[];  // Investigation context from tier-1
  triage_guidance?: TriageGuidance;  // Tier-1 analyst guidance
  tier2_analysis?: Tier2Analysis;  // NEW: Tier-2 AI agent analysis
  refined_assessment?: {
    is_actual_risk: boolean;
    likely_scenario: string;
    adjusted_severity: string;
    confidence: string;
    reasoning: string;
    recommendation: string;
    key_enriched_factors?: Record<string, any>;
  };
  evidence?: any;
  mitre_attack?: string[];  // MITRE ATT&CK technique IDs
}

export interface AnalysisData {
  metadata: {
    analysis_timestamp: string;
    log_metadata: LogMetadata;
    anomaly_summary: {
      total_initial_detections: number;
      total_refined_anomalies: number;
      high_severity: number;
      medium_severity: number;
      low_severity: number;
      actual_risks: number;
      false_positives_filtered: number;
    };
  };
  refined_anomalies: Anomaly[];
}

export const authAPI = {
  initiateLogin: async () => {
    const response = await api.get<AuthResponse>('/auth/login');
    return response.data;
  },

  getCurrentUser: async (token: string) => {
    const response = await api.get<UserInfo>('/auth/me', {
      params: { token },
    });
    return response.data;
  },
};

export const logsAPI = {
  fetchLogs: async (token: string, hoursBack: number = 24) => {
    const response = await api.post<{
      log_file_path: string;
      total_events: number;
      metadata: LogMetadata;
    }>(
      '/api/logs/fetch',
      { hours_back: hoursBack },
      { params: { token } }
    );
    return response.data;
  },

  getLogDetails: async (token: string, logFilename: string) => {
    const response = await api.get<LogData>(`/api/logs/${logFilename}`, {
      params: { token },
    });
    return response.data;
  },
};

export const analysisAPI = {
  runAnalysis: async (token: string, logFilePath: string) => {
    const response = await api.post<{
      analysis_file_path: string;
      total_anomalies: number;
      actual_risks: number;
      summary: any;
    }>(
      '/api/analysis/run',
      { log_file_path: logFilePath },
      { params: { token } }
    );
    return response.data;
  },

  getAnalysisDetails: async (token: string, analysisFilename: string) => {
    const response = await api.get<AnalysisData>(
      `/api/analysis/${analysisFilename}`,
      { params: { token } }
    );
    return response.data;
  },
};

export default api;
