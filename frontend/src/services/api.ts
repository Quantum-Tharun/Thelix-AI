import type { AnalyzeReportResponse, ScanResponse, SystemHealth } from '../types/api';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

export async function checkHealth(): Promise<SystemHealth> {
  const res = await fetch(`${API_BASE}/health/ready`, {
    headers: { Accept: 'application/json' },
  }).catch(() => null);

  if (res && res.ok) {
    return res.json();
  }

  // Fallback liveness check
  const liveness = await fetch(`${API_BASE}/health`, {
    headers: { Accept: 'application/json' },
  }).catch(() => null);

  if (liveness && liveness.ok) {
    return liveness.json();
  }

  throw new Error('Backend service unreachable');
}

export interface AnalyzeParams {
  content?: string;
  file?: File;
  context?: string;
}

export async function analyzeTarget(params: AnalyzeParams): Promise<AnalyzeReportResponse> {
  const formData = new FormData();

  if (params.content && params.content.trim()) {
    formData.append('content', params.content.trim());
  } else if (params.file) {
    formData.append('file', params.file);
  } else {
    throw new Error('Please provide either URL/text content or upload a file.');
  }

  if (params.context && params.context.trim()) {
    formData.append('context', params.context.trim());
  }

  // Synchronous default analysis
  formData.append('prefer_async', 'false');

  const response = await fetch(`${API_BASE}/v1/analyze`, {
    method: 'POST',
    body: formData,
    headers: {
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    let errorDetail = 'Analysis request failed';
    try {
      const errJson = await response.json();
      if (errJson && errJson.detail) {
        errorDetail = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {
      errorDetail = `Server responded with status ${response.status}`;
    }
    throw new Error(errorDetail);
  }

  return response.json();
}

export async function fetchRecentScans(): Promise<ScanResponse[]> {
  const response = await fetch(`${API_BASE}/v1/scans`, {
    headers: { Accept: 'application/json' },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch recent scan history');
  }

  return response.json();
}

export async function fetchScanReport(scanId: string): Promise<AnalyzeReportResponse> {
  const response = await fetch(`${API_BASE}/v1/scans/${encodeURIComponent(scanId)}/report`, {
    headers: { Accept: 'application/json' },
  });

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error(`Report not found for scan ${scanId.slice(0, 8)}. The scan may still be processing.`);
    }
    throw new Error(`Failed to fetch report for scan ${scanId.slice(0, 8)} (HTTP ${response.status})`);
  }

  // The /v1/scans/{id}/report endpoint returns a DIFFERENT schema than /v1/analyze.
  // Key differences:
  //   - Scores live under a nested `assessment` object
  //   - Uses `target_url` / `normalized_url` instead of `target_summary`
  //   - Has `evidence_count` instead of inline evidence
  //   - `what_we_checked` contains strings, not objects
  // We normalize into the flat AnalyzeReportResponse shape here.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const raw: any = await response.json();
  const assessment = raw.assessment || {};

  const normalized: AnalyzeReportResponse = {
    analysis_id: raw.scan_id,
    scan_id: raw.scan_id,
    status: raw.status || 'COMPLETED',
    input_type: raw.input_type || 'url',
    target_summary: raw.normalized_url || raw.target_url || raw.scan_id,
    verdict_category: raw.verdict_category || 'INCONCLUSIVE',
    verdict_label: raw.verdict_label || raw.verdict_category || 'Result unavailable',
    risk_score: assessment.risk_score ?? 0,
    trust_score: assessment.trust_score ?? 0,
    risk_level: assessment.risk_level || 'unknown',
    confidence: assessment.confidence ?? 0,
    coverage_ratio: assessment.coverage_ratio ?? 0,
    recommended_action: assessment.recommended_action || 'unknown',
    summary: assessment.summary || raw.verdict_label || '',
    // NOTE: why_this_result may be LLM-generated and can contradict deterministic scores
    why_this_result: raw.why_this_result || assessment.explanation || assessment.summary || '',
    what_we_checked: raw.what_we_checked || [],
    what_we_could_not_check: raw.what_we_could_not_check || [],
    findings: raw.findings || [],
    next_steps: raw.next_steps || [],
    created_at: raw.created_at || new Date().toISOString(),
  };

  return normalized;
}

export async function analyzeDeepfake(file: File): Promise<import('../types/api').DeepfakeAnalysisResponse> {
  const base64 = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });

  const response = await fetch(`${API_BASE}/v1/ai/analyze-deepfake`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({
      media_base64: base64,
      media_type: file.type.startsWith('video') ? 'video_frame' : 'image',
      filename: file.name,
    }),
  });

  if (!response.ok) {
    let errorDetail = `Deepfake analysis failed with status ${response.status}`;
    try {
      const errJson = await response.json();
      if (errJson && errJson.detail) {
        errorDetail = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {
      // ignore
    }
    throw new Error(errorDetail);
  }

  return response.json();
}

