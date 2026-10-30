import React, { useState, useRef, useEffect } from 'react';
import type { AnalyzeParams } from '../services/api';
import type { SystemHealth } from '../types/api';

interface ScannerPanelProps {
  onAnalyze: (params: AnalyzeParams) => void;
  isLoading: boolean;
  prefillContent?: string;
  health?: SystemHealth | null;
}

export const ScannerPanel: React.FC<ScannerPanelProps> = ({
  onAnalyze,
  isLoading,
  prefillContent,
  health,
}) => {
  const [activeMode, setActiveMode] = useState<'url_text' | 'file'>('url_text');
  const [contentInput, setContentInput] = useState('');
  const [contextInput, setContextInput] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (prefillContent) {
      // Schedule state synchronization to prevent cascading re-render warnings
      queueMicrotask(() => {
        setContentInput(prefillContent);
        setActiveMode('url_text');
      });
    }
  }, [prefillContent]);

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
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
      setActiveMode('file');
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleRemoveFile = (e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleClearContent = () => {
    setContentInput('');
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (isLoading) return;
    setValidationError(null);

    if (activeMode === 'url_text') {
      if (!contentInput.trim()) {
        setValidationError('Please enter a URL or message text to analyze.');
        return;
      }
      onAnalyze({
        content: contentInput.trim(),
        context: contextInput.trim() || undefined,
      });
    } else {
      if (!selectedFile) {
        setValidationError('Please select or drop a file to analyze.');
        return;
      }
      onAnalyze({
        file: selectedFile,
        context: contextInput.trim() || undefined,
      });
    }
  };

  const getFileExtension = (name: string) => {
    const ext = name.split('.').pop();
    return ext ? ext.toUpperCase() : 'FILE';
  };

  return (
    <div className="scanner-card">
      <div className="scanner-header">
        <div className="scanner-title-group">
          <div className="scanner-badge-row">
            <span className="section-pill">INPUT VECTORS</span>
            <span className="engine-subtext">Deterministic Analysis</span>
          </div>
          <h2 className="scanner-title">Intelligent Threat Inspector</h2>
          <p className="scanner-subtitle">
            Inspect suspicious URLs, phishing messages, QR codes, or documents through our multi-vector Risk Engine.
          </p>
        </div>

        <div className="mode-toggle-group">
          <button
            type="button"
            className={`mode-toggle-btn ${activeMode === 'url_text' ? 'active' : ''}`}
            onClick={() => setActiveMode('url_text')}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
            </svg>
            URL or Text
          </button>
          <button
            type="button"
            className={`mode-toggle-btn ${activeMode === 'file' ? 'active' : ''}`}
            onClick={() => setActiveMode('file')}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="17 8 12 3 7 8"/>
              <line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
            File or Screenshot
          </button>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="scanner-form">
        {activeMode === 'url_text' ? (
          <div className="input-group">
            <div className="input-label-row">
              <label htmlFor="target-content" className="input-label">
                Target URL or Message Content
              </label>
              {contentInput && (
                <button
                  type="button"
                  className="clear-input-inline-btn"
                  onClick={handleClearContent}
                  disabled={isLoading}
                >
                  Clear input
                </button>
              )}
            </div>
            <div className="text-input-wrapper">
              <textarea
                id="target-content"
                rows={4}
                className="thelix-textarea"
                placeholder="Paste suspect URL (e.g., https://secure-login-update.com/verify) or raw message text to analyze..."
                value={contentInput}
                onChange={(e) => setContentInput(e.target.value)}
                disabled={isLoading}
              />
            </div>
          </div>
        ) : (
          <div className="input-group">
            <div className="input-label-row">
              <label className="input-label">Document, Image, or QR Screenshot</label>
              {selectedFile && (
                <button
                  type="button"
                  className="clear-input-inline-btn"
                  onClick={handleRemoveFile}
                  disabled={isLoading}
                >
                  Remove file
                </button>
              )}
            </div>
            <div
              className={`file-dropzone ${dragActive ? 'drag-active' : ''} ${selectedFile ? 'has-file' : ''}`}
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                className="hidden-file-input"
                accept="image/png,image/jpeg,image/webp,image/bmp,application/pdf"
                onChange={handleFileChange}
                disabled={isLoading}
              />
              <div className="dropzone-content">
                {selectedFile ? (
                  <div className="selected-file-card">
                    <div className="file-type-badge">
                      {getFileExtension(selectedFile.name)}
                    </div>
                    <div className="selected-file-details">
                      <span className="file-name">{selectedFile.name}</span>
                      <span className="file-meta">
                        {(selectedFile.size / 1024).toFixed(1)} KB • Ready for isolated sandbox parsing
                      </span>
                    </div>
                    <button
                      type="button"
                      className="file-remove-chip"
                      onClick={handleRemoveFile}
                      title="Remove file"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <line x1="18" y1="6" x2="6" y2="18"/>
                        <line x1="6" y1="6" x2="18" y2="18"/>
                      </svg>
                    </button>
                  </div>
                ) : (
                  <>
                    <div className="dropzone-icon-pulse">
                      <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                        <circle cx="8.5" cy="8.5" r="1.5"/>
                        <polyline points="21 15 16 10 5 21"/>
                      </svg>
                    </div>
                    <div className="dropzone-prompt">
                      <span className="dropzone-title">Click to upload or drag & drop</span>
                      <span className="dropzone-subtitle">Screenshots, QR Codes, Images (PNG, JPEG, WEBP) & PDFs (Max 10MB)</span>
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        )}

        <div className="input-group">
          <label htmlFor="context-notes" className="input-label optional">
            Contextual Threat Details <span className="label-tag">Optional</span>
          </label>
          <input
            id="context-notes"
            type="text"
            className="thelix-input"
            placeholder="e.g. Received via WhatsApp claiming urgent bank KYC suspension"
            value={contextInput}
            onChange={(e) => setContextInput(e.target.value)}
            disabled={isLoading}
          />
        </div>

        <div className="scanner-actions">
          {validationError && (
            <div className="inline-validation-error">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
              {validationError}
            </div>
          )}
          <div className="safety-notice">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="16" x2="12" y2="12"/>
              <line x1="12" y1="8" x2="12.01" y2="8"/>
            </svg>
            <span>
              {health?.sandbox_enabled
                ? 'Isolated sandbox active. Payloads parsed in-memory with zero file residue.'
                : 'Static analysis mode. Input is evaluated by deterministic heuristics only — no live sandbox.'}
            </span>
          </div>

          <button
            type="submit"
            className="primary-scan-button"
            disabled={isLoading || (activeMode === 'url_text' ? !contentInput.trim() : !selectedFile)}
          >
            {isLoading ? (
              <>
                <span className="spinner"></span>
                <span>Executing Risk Engine...</span>
              </>
            ) : (
              <>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
                </svg>
                <span>Run Trust Assessment</span>
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
