import React from 'react';
import type { SystemHealth, ScanResponse } from '../types/api';

interface SecurityPostureProps {
  health: SystemHealth | null;
  scans: ScanResponse[];
  onTriggerScanClick: () => void;
}

export const SecurityPosture: React.FC<SecurityPostureProps> = ({
  health,
  scans,
  onTriggerScanClick,
}) => {
  // Compute metrics from actual session scans
  const totalScans = scans.length;
  const completedScans = scans.filter((s) => s.status.toUpperCase() === 'COMPLETED').length;

  // Breakdown by input type
  const typeCounts: Record<string, number> = {};
  scans.forEach((s) => {
    const t = s.input_type || 'url';
    typeCounts[t] = (typeCounts[t] || 0) + 1;
  });

  const providers = health?.providers_configured || {};
  const activeEngines = [
    {
      name: 'Deterministic Risk Policy',
      version: health?.policy_version || '1.0.0',
      status: 'active',
      desc: 'Canonical heuristic weights & conflict resolution algorithm',
    },
    {
      name: 'Static URL Intelligence',
      version: health?.engine_versions?.static_url_analyzer || '1.0.0',
      status: 'active',
      desc: 'Entropy analysis, homoglyph check, and IP-literal inspection',
    },
    {
      name: 'URL Canonical Normalizer',
      version: health?.engine_versions?.url_normalizer || '1.0.0',
      status: 'active',
      desc: 'RFC-compliant URI sanitization and schema verification',
    },
    {
      name: 'OpenCV QR Code Decoder',
      version: health?.engine_versions?.qr_decoder || (health?.qr_available ? '1.0.0' : 'standby'),
      status: health?.qr_available ? 'active' : 'standby',
      desc: 'In-memory QR payload extraction and embedded URL inspection',
    },
    {
      name: 'Deepfake Vision Detector',
      version: health?.engine_versions?.deepfake_detector || health?.deepfake_status || '1.0.0-prototype',
      status: health?.deepfake_status === 'prototype_weights_unloaded' ? 'standby' : 'active',
      desc: 'Facial frequency artifact and manipulation pattern analysis',
    },
    {
      name: 'Google Gemini LLM Engine',
      version: providers.gemini === true ? 'API Active' : (providers.gemini === 'mock' ? 'Mock Deterministic' : 'Standby / Fallback'),
      status: providers.gemini === true ? 'active' : 'standby',
      desc: 'Online natural language threat explanation and risk factor synthesis',
    },
    {
      name: 'Ollama Gemma Local Model',
      version: providers.ollama_gemma === 'available' ? 'Local Engine' : 'Offline / Standby',
      status: providers.ollama_gemma === 'available' ? 'active' : 'standby',
      desc: 'On-device private inference engine with zero cloud exfiltration',
    },
    {
      name: 'Tesseract OCR Pipeline',
      version: health?.ocr_available ? 'active' : 'optional',
      status: health?.ocr_available ? 'active' : 'standby',
      desc: 'Visual text extraction from uploaded images & screenshots',
    },
    {
      name: 'Google Safe Browsing & Intel',
      version: providers.safebrowsing ? 'API Active' : 'Offline / Standby',
      status: providers.safebrowsing ? 'active' : 'standby',
      desc: 'Real-time domain reputation and malicious host matching',
    },
    {
      name: 'VirusTotal Threat Intel',
      version: providers.virustotal ? 'API Active' : 'Offline / Standby',
      status: providers.virustotal ? 'active' : 'standby',
      desc: 'Multi-vendor reputation telemetry aggregator',
    },
  ];

  return (
    <div className="posture-container">
      {/* Overview Cards */}
      <div className="posture-hero-card">
        <div className="posture-hero-left">
          <div className="posture-badge-row">
            <span className="section-pill">SECURITY POSTURE & TELEMETRY</span>
            <span className="engine-subtext">Active Shield Status</span>
          </div>
          <h2 className="posture-hero-title">Continuous Trust & Risk Posture</h2>
          <p className="posture-hero-desc">
            Deterministic evaluation engine telemetry, engine version integrity, and verified digital defense indicators.
          </p>
        </div>
        <div className="posture-hero-right">
          <button
            type="button"
            className="primary-scan-button"
            onClick={onTriggerScanClick}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
            </svg>
            Initiate Threat Scan
          </button>
        </div>
      </div>

      {/* KPI Metrics Grid */}
      <div className="posture-kpi-grid">
        <div className="kpi-card">
          <div className="kpi-title">Recorded Target Audits</div>
          <div className="kpi-value-row">
            <span className="kpi-number safe">{totalScans}</span>
            <span className="kpi-subtext">Session scans</span>
          </div>
          <div className="kpi-meta">
            <span>Completed: {completedScans}</span>
            <span className="kpi-dot"></span>
            <span>Success Rate: {totalScans > 0 ? `${Math.round((completedScans / totalScans) * 100)}%` : 'N/A'}</span>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-title">Active Policy Spec</div>
          <div className="kpi-value-row">
            <span className="kpi-number safe">{health?.policy_version || '1.0.0'}</span>
            <span className="kpi-subtext">Canonical</span>
          </div>
          <div className="kpi-meta">
            <span>Deterministic Fusion v1</span>
            <span className="kpi-dot"></span>
            <span>Zero-drift scoring</span>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-title">Rate Limiting Guard</div>
          <div className="kpi-value-row">
            <span className={`kpi-number ${health?.rate_limiting_enabled ? 'safe' : 'warning'}`}>
              {health?.rate_limiting_enabled ? 'Active' : 'Disabled'}
            </span>
            <span className="kpi-subtext">{health?.rate_limit_store || 'memory'}</span>
          </div>
          <div className="kpi-meta">
            <span>Sliding window limiter</span>
            <span className="kpi-dot"></span>
            <span>DDoS mitigation</span>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-title">Isolated Execution Sandbox</div>
          <div className="kpi-value-row">
            <span className={`kpi-number ${health?.sandbox_enabled ? 'safe' : 'subtle'}`}>
              {health?.sandbox_enabled ? 'Engaged' : 'Standby'}
            </span>
            <span className="kpi-subtext">In-memory</span>
          </div>
          <div className="kpi-meta">
            <span>Prohibited MIME sniffer</span>
            <span className="kpi-dot"></span>
            <span>Zero file residue</span>
          </div>
        </div>
      </div>

      {/* Risk Engine Architecture & Health */}
      <div className="posture-split-grid">
        {/* Subsystems List */}
        <div className="posture-card">
          <div className="card-header-row">
            <div>
              <h3 className="card-header-title">Subsystem Engines & Models</h3>
              <p className="card-header-sub">Inspection services integrated into the evaluation pipeline.</p>
            </div>
          </div>

          <div className="engines-list">
            {activeEngines.map((engine, idx) => (
              <div key={idx} className="engine-item">
                <div className="engine-item-left">
                  <div className={`engine-status-dot ${engine.status}`}></div>
                  <div className="engine-text">
                    <span className="engine-name">{engine.name}</span>
                    <span className="engine-desc">{engine.desc}</span>
                  </div>
                </div>
                <div className="engine-item-right">
                  <span className={`engine-version-pill ${engine.status}`}>
                    {engine.version}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Vector Distribution and Threat Archetypes */}
        <div className="posture-card">
          <div className="card-header-row">
            <div>
              <h3 className="card-header-title">Vector Coverage & Target Breakdown</h3>
              <p className="card-header-sub">Distribution of assessed vectors during current session.</p>
            </div>
          </div>

          {totalScans > 0 ? (
            <div className="vector-breakdown-container">
              {Object.entries(typeCounts).map(([type, count]) => {
                const pct = Math.round((count / totalScans) * 100);
                return (
                  <div key={type} className="vector-row">
                    <div className="vector-info">
                      <span className="vector-label">{type.toUpperCase()} VECTOR</span>
                      <span className="vector-counts">{count} scan{count > 1 ? 's' : ''} ({pct}%)</span>
                    </div>
                    <div className="vector-bar-track">
                      <div
                        className="vector-bar-fill"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="vector-empty-state">
              <div className="vector-empty-icon">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <circle cx="12" cy="12" r="10"/>
                  <polyline points="12 6 12 12 14 14"/>
                </svg>
              </div>
              <p className="vector-empty-text">No scans conducted in this session yet.</p>
              <span className="vector-empty-sub">
                Execute analysis in the Threat Scanner to generate live telemetry breakdown.
              </span>
            </div>
          )}

          <div className="protection-summary-box">
            <div className="protection-title">Compliance & Zero Exfiltration Guarantee</div>
            <p className="protection-text">
              All OCR-extracted text and screenshot payloads are parsed exclusively in-memory during the request lifecycle. No customer secrets or plaintext credentials are saved to durable storage.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
