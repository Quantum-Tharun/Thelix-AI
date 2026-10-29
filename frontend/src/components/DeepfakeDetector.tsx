import React, { useState, useRef } from 'react';
import type { DeepfakeAnalysisResponse, SystemHealth } from '../types/api';
import { analyzeDeepfake } from '../services/api';

interface DeepfakeDetectorProps {
  health?: SystemHealth | null;
}

export const DeepfakeDetector: React.FC<DeepfakeDetectorProps> = ({ health }) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<DeepfakeAnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (file: File) => {
    // Max 10MB limit
    if (file.size > 10 * 1024 * 1024) {
      setError('File exceeds 10MB limit.');
      return;
    }
    setError(null);
    setResult(null);
    setSelectedFile(file);

    if (file.type.startsWith('image/')) {
      const url = URL.createObjectURL(file);
      setPreviewUrl(url);
    } else {
      setPreviewUrl(null);
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileChange(e.dataTransfer.files[0]);
    }
  };

  const handleAnalyze = async () => {
    if (!selectedFile || isAnalyzing) return;
    setIsAnalyzing(true);
    setError(null);
    try {
      const res = await analyzeDeepfake(selectedFile);
      setResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleReset = () => {
    setSelectedFile(null);
    setPreviewUrl(null);
    setResult(null);
    setError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const isModelReady = health?.deepfake_status === 'ready';
  const isModelInvalid = health?.deepfake_status === 'invalid_weights';

  return (
    <div className="deepfake-detector-container">
      <div className="deepfake-header">
        <div className="section-title-wrap">
          <span className="section-badge">Vision AI Capability</span>
          <h2 className="section-heading">Synthetic Media & Deepfake Analysis</h2>
          <p className="section-subheading">
            Detect facial frequency artifacts, boundary inconsistencies, and synthetic generation markers.
          </p>
        </div>

        <div className="model-state-badge">
          <span className={`status-dot ${isModelReady ? 'online' : isModelInvalid ? 'error' : 'warning'}`}></span>
          <span>
            {isModelReady
              ? 'Model Active (Weights Loaded)'
              : isModelInvalid
              ? 'Model Error (Invalid Weights)'
              : 'Prototype (Weights Unloaded)'}
          </span>
        </div>
      </div>

      <div className="deepfake-grid">
        <div className="deepfake-upload-card">
          <div
            className={`file-drop-zone ${dragActive ? 'drag-active' : ''} ${selectedFile ? 'has-file' : ''}`}
            onDragEnter={handleDrag}
            onDragOver={handleDrag}
            onDragLeave={handleDrag}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept="image/png,image/jpeg,image/webp,video/mp4"
              style={{ display: 'none' }}
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  handleFileChange(e.target.files[0]);
                }
              }}
            />

            {previewUrl ? (
              <div className="media-preview-box">
                <img src={previewUrl} alt="Upload preview" className="preview-image" />
                <span className="file-name-tag">{selectedFile?.name}</span>
              </div>
            ) : selectedFile ? (
              <div className="file-info-box">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                  <polyline points="14 2 14 8 20 8"></polyline>
                </svg>
                <span className="file-name">{selectedFile.name}</span>
                <span className="file-size">({(selectedFile.size / 1024).toFixed(1)} KB)</span>
              </div>
            ) : (
              <div className="drop-prompt">
                <div className="drop-icon">
                  <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                    <circle cx="8.5" cy="8.5" r="1.5"/>
                    <polyline points="21 15 16 10 5 21"/>
                  </svg>
                </div>
                <p className="primary-text">Click or drag media to inspect</p>
                <p className="secondary-text">Supported: PNG, JPEG, WEBP, MP4 frame (max 10MB)</p>
              </div>
            )}
          </div>

          {error && (
            <div className="inline-validation-error" style={{ marginTop: '12px' }}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
              {error}
            </div>
          )}

          <div className="action-row" style={{ marginTop: '16px', display: 'flex', gap: '10px' }}>
            <button
              type="button"
              className="primary-scan-button"
              disabled={!selectedFile || isAnalyzing}
              onClick={handleAnalyze}
            >
              {isAnalyzing ? (
                <>
                  <span className="spinner" style={{ width: '14px', height: '14px', border: '2px solid rgba(245,240,229,0.3)', borderTopColor: '#F5F0E5', borderRadius: '50%', display: 'inline-block', animation: 'spin 0.8s linear infinite' }}></span>
                  Analyzing Frames...
                </>
              ) : (
                <>
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
                  </svg>
                  Evaluate Manipulation
                </>
              )}
            </button>

            {selectedFile && (
              <button type="button" className="secondary-button" onClick={handleReset} disabled={isAnalyzing}>
                Clear
              </button>
            )}
          </div>
        </div>

        <div className="deepfake-result-card">
          {result ? (
            <div className="deepfake-report">
              <div className="result-status-header">
                <span className="badge-title">Analysis Status:</span>
                <span className={`status-badge-val ${result.status === 'COMPLETED' ? 'success' : 'warn'}`}>
                  {result.status}
                </span>
              </div>

              {result.status === 'COMPLETED' && result.confidence_score !== null && result.confidence_score !== undefined && (
                <div className="score-meter-box">
                  <div className="meter-label">
                    <span>Manipulation Probability</span>
                    <span className="meter-val">{Math.round(result.confidence_score * 100)}%</span>
                  </div>
                  <div className="meter-bar-track">
                    <div
                      className="meter-bar-fill"
                      style={{
                        width: `${Math.round(result.confidence_score * 100)}%`,
                        backgroundColor: (result.confidence_score ?? 0) > 0.6 ? '#E05252' : '#78845A',
                      }}
                    />
                  </div>
                </div>
              )}

              <div className="probabilistic-alert">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10"></circle>
                  <line x1="12" y1="8" x2="12" y2="12"></line>
                  <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>
                <p>{result.probabilistic_notice}</p>
              </div>

              {result.indicators_detected && result.indicators_detected.length > 0 && (
                <div className="result-indicators">
                  <h4>Indicators Evaluated</h4>
                  <ul>
                    {result.indicators_detected.map((ind, idx) => (
                      <li key={idx}>
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <polyline points="20 6 9 17 4 12"></polyline>
                        </svg>
                        <span>{ind}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="notes-box">
                <span className="label">System Notes:</span>
                <p>{result.processing_notes}</p>
                <span className="model-ref">Model: {result.model_version}</span>
              </div>
            </div>
          ) : (
            <div className="empty-result-placeholder">
              <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
              </svg>
              <h3>No Media Evaluated</h3>
              <p>Upload a suspicious profile picture, face capture, or video frame to run automated frequency analysis.</p>
              <div className="probabilistic-disclaimer">
                <span>Honest Disclosure: All AI vision detectors are probabilistic and never constitute legal evidence.</span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
