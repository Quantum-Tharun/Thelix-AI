import React, { useState } from 'react';
import type { AnalyzeReportResponse } from '../types/api';

interface TrustScoreCardProps {
  report: AnalyzeReportResponse;
  onClear?: () => void;
}

export const TrustScoreCard: React.FC<TrustScoreCardProps> = ({ report, onClear }) => {
  const [activeTab, setActiveTab] = useState<'evidence' | 'checks' | 'findings' | 'safeguards'>('evidence');

  const isHighRisk = report.risk_score >= 60 || report.risk_level === 'HIGH' || report.risk_level === 'CRITICAL';
  const isMediumRisk = report.risk_score >= 30 && report.risk_score < 60;
  
  const riskClass = isHighRisk ? 'critical' : isMediumRisk ? 'warning' : 'safe';

  const hasFindings = report.findings && report.findings.length > 0;
  const hasHighSeverityFindings = hasFindings && report.findings.some(
    (f) => f.severity === 'HIGH' || f.severity === 'CRITICAL'
  );

  // Detect text-level contradiction: LLM explanation language contradicts the deterministic verdict.
  // This catches the specific case where trust_score=100/verdict=LIKELY_SAFE but the
  // why_this_result text contains phishing/danger language (Gemini hallucination).
  const isSafeVerdict = (
    report.verdict_category === 'LIKELY_SAFE' ||
    report.recommended_action?.toLowerCase() === 'allow'
  );
  const isDangerousVerdict = (
    report.verdict_category === 'PHISHING_OR_SCAM' ||
    report.verdict_category === 'MALWARE_INDICATORS_DETECTED' ||
    report.recommended_action?.toLowerCase() === 'block'
  );
  const explanationText = (report.why_this_result || '').toLowerCase();
  const THREAT_KEYWORDS = ['phishing', 'malware', 'scam', 'dangerous', 'malicious', 'credential', 'do not', 'do not open', 'do not enter', 'suspicious indicator', 'fraudulent'];
  const SAFE_KEYWORDS = ['no threat', 'safe to proceed', 'no significant threat', 'no malware', 'passed', 'all checks passed'];
  const explanationContainsThreats = THREAT_KEYWORDS.some((kw) => explanationText.includes(kw));
  const explanationContainsSafe = SAFE_KEYWORDS.some((kw) => explanationText.includes(kw));

  const textualContradiction =
    (isSafeVerdict && explanationContainsThreats) ||
    (isDangerousVerdict && explanationContainsSafe && !hasFindings);

  const signalMismatch =
    textualContradiction ||
    (report.trust_score >= 70 && hasHighSeverityFindings) ||
    (report.trust_score <= 30 && !hasFindings && report.risk_score <= 20);

  // Human-readable labels for backend check codes
  const CHECK_LABELS: Record<string, string> = {
    input_validation: 'Input Validation',
    static_analysis: 'Static URL Analysis',
    url_normalization: 'URL Canonical Normalization',
    qr_decode: 'QR Code Payload Extraction',
    ocr_extraction: 'OCR Text Extraction',
    scam_nlp: 'NLP Scam Language Detection',
    deepfake_vision: 'Deepfake Vision Analysis',
    sandbox_execution: 'Isolated Sandbox Execution',
    external_threat_intelligence: 'External Threat Intelligence',
    isolated_sandbox: 'Isolated Execution Sandbox',
    capability_limitation: 'Capability Limitation Notice',
  };

  // Format `what_we_checked` items
  const formatCheckItem = (item: Record<string, unknown> | string, index: number) => {
    if (typeof item === 'string') {
      return { id: `check-${index}`, title: item, status: 'passed', detail: '' };
    }
    const code = (item.check || item.check_name || item.name || item.title || item.indicator || '') as string;
    const title = CHECK_LABELS[code] || code.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) || `Check #${index + 1}`;
    const rawStatus = (item.status || item.result || (item.flagged ? 'flagged' : 'passed')) as string;
    // Normalise backend's 'completed' to 'passed' for display
    const status = rawStatus === 'completed' ? 'passed' : rawStatus;
    const detail = (item.reason || item.detail || item.description || '') as string;
    return { id: `check-${index}`, title, status, detail };
  };

  // Format `what_we_could_not_check` items
  const formatSkippedItem = (item: Record<string, unknown> | string, index: number) => {
    if (typeof item === 'string') return { id: `skip-${index}`, title: item, reason: '', status: 'skipped' };
    const code = (item.check || item.name || item.title || '') as string;
    const title = CHECK_LABELS[code] || code.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) || `Item #${index + 1}`;
    const reason = (item.reason || item.detail || item.description || '') as string;
    const status = (item.status || 'skipped') as string;
    return { id: `skip-${index}`, title, reason, status };
  };

  return (
    <div className="report-container">
      <div className="report-header-banner">
        <div className="report-meta-left">
          <span className={`verdict-pill ${riskClass}`}>{report.verdict_label}</span>
          <span className="input-type-badge">{report.input_type.toUpperCase()}</span>
          {report.target_summary && (
            <span className="target-summary-text" title={report.target_summary}>
              Target: <code>{report.target_summary}</code>
            </span>
          )}
        </div>

        <div className="report-meta-right">
          <span className="scan-timestamp">
            {new Date(report.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
          </span>
          {onClear && (
            <button type="button" className="clear-report-btn" onClick={onClear}>
              Close Report
            </button>
          )}
        </div>
      </div>

      {signalMismatch && (
        <div className="signal-mismatch-notice">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <span>
            <strong>Signal discrepancy detected:</strong> The overall score and specific findings may appear contradictory — review the Rationale and Threat Indicators tabs for full context.
          </span>
        </div>
      )}

      <div className="score-summary-grid">
        <div className="score-card trust-score-box">
          <div className="score-card-top">
            <span className="metric-title">Trust Score</span>
            <span className="metric-range">0 to 100</span>
          </div>
          <div className="metric-value-row">
            <span className={`metric-big-number ${riskClass}`}>{report.trust_score}</span>
            <span className="metric-denominator">/ 100</span>
          </div>
          <div className="score-progress-bar">
            <div
              className={`score-progress-fill ${riskClass}`}
              style={{ width: `${Math.max(5, Math.min(100, report.trust_score))}%` }}
            />
          </div>
          <div className="metric-subtext">
            Confidence: {(report.confidence * 100).toFixed(0)}% | Engine Coverage: {(report.coverage_ratio * 100).toFixed(0)}%
          </div>
        </div>

        <div className="score-card risk-level-box">
          <div className="score-card-top">
            <span className="metric-title">Risk Assessment</span>
            <span className={`severity-tag ${riskClass}`}>{report.risk_level}</span>
          </div>
          <div className="metric-value-row">
            <span className={`metric-big-number ${riskClass}`}>{report.risk_score}</span>
            <span className="metric-unit">Risk Index</span>
          </div>
          <div className="action-pill-row">
            <span className="action-label">Policy Action:</span>
            <span className={`action-tag action-${report.recommended_action.toLowerCase()}`}>
              {report.recommended_action}
            </span>
          </div>
        </div>
      </div>

      {/* Internal Tabs for Report Details */}
      <div className="report-subnav">
        <button
          type="button"
          className={`report-subnav-btn ${activeTab === 'evidence' ? 'active' : ''}`}
          onClick={() => setActiveTab('evidence')}
        >
          Rationale & Evidence
        </button>
        <button
          type="button"
          className={`report-subnav-btn ${activeTab === 'checks' ? 'active' : ''}`}
          onClick={() => setActiveTab('checks')}
        >
          Security Checks ({report.what_we_checked?.length || 0})
        </button>
        <button
          type="button"
          className={`report-subnav-btn ${activeTab === 'findings' ? 'active' : ''}`}
          onClick={() => setActiveTab('findings')}
        >
          Threat Indicators ({report.findings?.length || 0})
        </button>
        <button
          type="button"
          className={`report-subnav-btn ${activeTab === 'safeguards' ? 'active' : ''}`}
          onClick={() => setActiveTab('safeguards')}
        >
          Recommended Safeguards ({report.next_steps?.length || 0})
        </button>
      </div>

      {activeTab === 'evidence' && (
        <div className="report-rationale-section">
          <h3 className="section-title">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="16" x2="12" y2="12"/>
              <line x1="12" y1="8" x2="12.01" y2="8"/>
            </svg>
            Analytical Rationale
          </h3>

          {/* Deterministic summary — always shown, always consistent with numeric verdict */}
          <p className="summary-paragraph">{report.summary}</p>

          {report.why_this_result && report.why_this_result !== report.summary && (
            <div className={`why-box ${textualContradiction ? 'why-box-contradicted' : ''}`}>
              <div className="why-box-header">
                <strong>Narrative Explanation</strong>
                <span className="llm-source-tag">LLM&#8209;generated</span>
              </div>
              {textualContradiction && (
                <div className="why-contradiction-notice">
                  ⚠ This explanation was generated by the AI language model and may not align with the deterministic verdict above. The numeric scores (Trust Score, Risk Index) and verdict label are authoritative.
                </div>
              )}
              <p className="why-text">{report.why_this_result}</p>
            </div>
          )}
        </div>
      )}

      {activeTab === 'checks' && (
        <div className="checks-tab-section">
          <div className="checks-group-card">
            <h4 className="checks-subheading">Executed Security Checks</h4>
            {report.what_we_checked && report.what_we_checked.length > 0 ? (
              <div className="checks-grid">
                {report.what_we_checked.map((item, idx) => {
                  const check = formatCheckItem(item, idx);
                  const isFlagged = check.status.toLowerCase().includes('flag') || check.status.toLowerCase().includes('fail');
                  return (
                    <div key={check.id} className={`check-item-card ${isFlagged ? 'flagged' : 'passed'}`}>
                      <div className="check-status-icon">
                        {isFlagged ? (
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                            <line x1="18" y1="6" x2="6" y2="18"/>
                            <line x1="6" y1="6" x2="18" y2="18"/>
                          </svg>
                        ) : (
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                            <polyline points="20 6 9 17 4 12"/>
                          </svg>
                        )}
                      </div>
                      <div className="check-text">
                        <span className="check-title">{check.title}</span>
                        {check.detail && <span className="check-desc">{check.detail}</span>}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="checks-empty">No detailed check data returned by the engine for this scan.</div>
            )}
          </div>

          {report.what_we_could_not_check && report.what_we_could_not_check.length > 0 && (
            <div className="checks-group-card skipped-group">
              <h4 className="checks-subheading skipped">Omitted or Unavailable Inspections</h4>
              <div className="skipped-checks-list">
                {report.what_we_could_not_check
                  .map((item, idx) => formatSkippedItem(item as Record<string, unknown> | string, idx))
                  // Deduplicate: hide 'capability_limitation' if the actual skipped check already shown
                  .filter((sk, _, arr) => {
                    if (sk.title === 'Capability Limitation Notice') {
                      // Only show if there's no other entry with the same reason root
                      const rootCheck = sk.reason.match(/Check '([^']+)'/)?.[1];
                      return !rootCheck || !arr.some((other) => other.id !== sk.id && other.title !== 'Capability Limitation Notice' && sk.reason.includes(rootCheck));
                    }
                    return true;
                  })
                  .map((sk) => (
                    <div key={sk.id} className="skipped-check-item">
                      <span className={`skipped-status-dot ${sk.status}`}></span>
                      <div className="skipped-check-text">
                        <span className="skipped-check-name">{sk.title}</span>
                        {sk.reason && <span className="skipped-check-reason">{sk.reason}</span>}
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'findings' && (
        <div className="findings-section">
          {report.findings && report.findings.length > 0 ? (
            <div className="findings-list">
              {report.findings.map((finding, idx) => (
                <div key={idx} className={`finding-card severity-${finding.severity.toLowerCase()}`}>
                  <div className="finding-header">
                    <span className="finding-code">{finding.finding_code}</span>
                    <span className={`finding-severity-pill ${finding.severity.toLowerCase()}`}>
                      {finding.severity}
                    </span>
                    <span className="finding-source">Engine: {finding.source_engine}</span>
                  </div>
                  <div className="finding-title">{finding.title}</div>
                  <div className="finding-desc">{finding.description}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="clean-findings-notice">
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <polyline points="9 12 11 14 15 10"/>
              </svg>
              <span>No critical threat indicators or malicious patterns identified in submitted target.</span>
            </div>
          )}
        </div>
      )}

      {activeTab === 'safeguards' && (
        <div className="next-steps-section">
          {report.next_steps && report.next_steps.length > 0 ? (
            <ul className="next-steps-list">
              {report.next_steps.map((step, idx) => (
                <li key={idx} className="next-step-item">
                  <span className="step-num">{idx + 1}</span>
                  <span className="step-text">{step}</span>
                </li>
              ))}
            </ul>
          ) : (
            <div className="clean-findings-notice">
              <span>Standard operating precautions apply. No emergency actions required.</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
