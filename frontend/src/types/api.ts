export interface FindingItem {
  finding_code: string;
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;
  confidence: number;
  source_engine: string;
}

export interface SecurityCheckItem {
  name: string;
  status: 'passed' | 'flagged' | 'skipped' | 'warning' | string;
  engine: string;
  details?: string;
  latency_ms?: number;
}

export interface AnalyzeReportResponse {
  analysis_id: string;
  scan_id: string;
  status: 'COMPLETED' | 'PARTIAL' | 'FAILED' | 'INCONCLUSIVE' | string;
  input_type: 'url' | 'message' | 'screenshot' | 'qr' | 'pdf' | 'document' | string;
  target_summary?: string;
  verdict_category:
    | 'LIKELY_SAFE'
    | 'SUSPICIOUS'
    | 'PHISHING_OR_SCAM'
    | 'MALWARE_INDICATORS_DETECTED'
    | 'INCONCLUSIVE'
    | 'UNSUPPORTED_INPUT'
    | string;
  verdict_label: string;
  risk_score: number;
  trust_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;
  confidence: number;
  coverage_ratio: number;
  recommended_action: 'ALLOW' | 'WARN' | 'BLOCK' | 'INCONCLUSIVE' | string;
  summary: string;
  why_this_result: string;
  what_we_checked: Array<Record<string, unknown> | string>;
  what_we_could_not_check: Array<Record<string, unknown> | string>;
  findings: FindingItem[];
  next_steps: string[];
  created_at: string;
}

export interface ScanResponse {
  scan_id: string;
  user_id: string;
  status: string;
  input_type: string;
  raw_target: string;
  normalized_target?: string | null;
  created_at: string;
  completed_at?: string | null;
  risk_level?: string;
  trust_score?: number;
}

export interface EngineVersions {
  policy?: string;
  static_url_analyzer?: string;
  url_normalizer?: string;
  qr_decoder?: string;
  deepfake_detector?: string;
}

export interface ProvidersConfigured {
  gemini?: boolean | string;
  ollama_gemma?: string | boolean;
  virustotal?: boolean;
  safebrowsing?: boolean;
}

export interface SystemHealth {
  status: string;
  service: string;
  version: string;
  environment?: string;
  database?: string;
  policy_version?: string;
  engine_versions?: EngineVersions;
  sandbox_enabled?: boolean;
  rate_limiting_enabled?: boolean;
  rate_limit_store?: string;
  ocr_available?: boolean;
  qr_available?: boolean;
  deepfake_status?: string;
  pilot_mode_enabled?: boolean;
  providers_configured?: ProvidersConfigured;
}

export interface DeepfakeAnalysisResponse {
  status: 'COMPLETED' | 'PROTOTYPE_UNAVAILABLE' | 'FAILED' | string;
  is_deepfake?: boolean | null;
  confidence_score?: number | null;
  probabilistic_notice: string;
  model_version: string;
  indicators_detected: string[];
  limitations: string[];
  processing_notes: string;
}

export interface PostureMetrics {
  totalScans: number;
  cleanRate: number;
  threatsBlocked: number;
  averageTrustScore: number;
  riskDistribution: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  inputTypesDistribution: Record<string, number>;
  activeEnginesCount: number;
}
