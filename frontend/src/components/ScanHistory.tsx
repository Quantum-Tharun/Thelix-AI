import React, { useState, useMemo } from 'react';
import type { ScanResponse } from '../types/api';

interface ScanHistoryProps {
  scans: ScanResponse[];
  loading: boolean;
  onRefresh: () => void;
  onSelectScan: (scanId: string) => void;
  onUseSample?: (url: string) => void;
}

export const ScanHistory: React.FC<ScanHistoryProps> = ({
  scans,
  loading,
  onRefresh,
  onSelectScan,
  onUseSample,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');

  const sampleUrls = [
    { label: 'Safe Domain Test', url: 'https://en.wikipedia.org/wiki/Computer_security' },
    { label: 'Suspicious IP/Subdomain', url: 'http://192.168.1.100/secure-update-account/login' },
  ];

  // Distinct types from scans
  const availableTypes = useMemo(() => {
    const types = new Set<string>();
    scans.forEach((s) => types.add(s.input_type));
    return Array.from(types);
  }, [scans]);

  // Filtered scans
  const filteredScans = useMemo(() => {
    return scans.filter((scan) => {
      const target = (scan.normalized_target || scan.raw_target || '').toLowerCase();
      const id = scan.scan_id.toLowerCase();
      const matchesSearch = !searchQuery.trim() || target.includes(searchQuery.toLowerCase().trim()) || id.includes(searchQuery.toLowerCase().trim());
      const matchesType = selectedType === 'all' || scan.input_type.toLowerCase() === selectedType.toLowerCase();
      const matchesStatus = selectedStatus === 'all' || scan.status.toLowerCase() === selectedStatus.toLowerCase();
      return matchesSearch && matchesType && matchesStatus;
    });
  }, [scans, searchQuery, selectedType, selectedStatus]);

  return (
    <div className="history-card">
      <div className="history-header">
        <div className="history-title-group">
          <div className="history-badge-row">
            <span className="section-pill">LEDGER TRANSPARENCY</span>
            <span className="scan-count-badge">
              {filteredScans.length} of {scans.length} Audits
            </span>
          </div>
          <h2 className="history-title">Recent Threat Inspections</h2>
          <p className="history-subtitle">
            Search, filter, and inspect verified historical risk audits evaluated across the deterministic engine.
          </p>
        </div>

        <button
          type="button"
          className="refresh-history-btn"
          onClick={onRefresh}
          disabled={loading}
          title="Refresh scan records"
        >
          <svg
            className={loading ? 'spinning' : ''}
            width="15"
            height="15"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <polyline points="23 4 23 10 17 10"/>
            <polyline points="1 20 1 14 7 14"/>
            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
          </svg>
          {loading ? 'Querying...' : 'Refresh'}
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="history-controls-bar">
        <div className="history-search-wrapper">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input
            type="text"
            className="history-search-input"
            placeholder="Search by URL, keyword, or Scan ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
          {searchQuery && (
            <button
              type="button"
              className="clear-search-btn"
              onClick={() => setSearchQuery('')}
            >
              ×
            </button>
          )}
        </div>

        <div className="history-filter-group">
          <select
            className="history-select"
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
          >
            <option value="all">All Input Types</option>
            {availableTypes.map((t) => (
              <option key={t} value={t}>
                {t.toUpperCase()}
              </option>
            ))}
          </select>

          <select
            className="history-select"
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
          >
            <option value="all">All Statuses</option>
            <option value="completed">Completed</option>
            <option value="running">Running</option>
            <option value="queued">Queued</option>
            <option value="failed">Failed</option>
          </select>
        </div>
      </div>

      {loading && scans.length === 0 ? (
        <div className="history-loading-skeleton">
          <div className="skeleton-row"></div>
          <div className="skeleton-row"></div>
          <div className="skeleton-row"></div>
        </div>
      ) : scans.length === 0 ? (
        <div className="history-empty-state">
          <div className="empty-state-shield">
            <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="M12 8v4"/>
              <path d="M12 16h.01"/>
            </svg>
          </div>
          <p className="empty-title">No Scan Records in Current Session</p>
          <span className="empty-desc">
            Submit a target URL, message snippet, or upload a screenshot in the Threat Scanner to initiate your first risk audit.
          </span>

          {onUseSample && (
            <div className="empty-samples-row">
              <span className="sample-hint">Quick test sample:</span>
              {sampleUrls.map((sample) => (
                <button
                  key={sample.label}
                  type="button"
                  className="sample-pill-btn"
                  onClick={() => onUseSample(sample.url)}
                >
                  {sample.label}
                </button>
              ))}
            </div>
          )}
        </div>
      ) : filteredScans.length === 0 ? (
        <div className="history-empty-state">
          <p className="empty-title">No matching scans found</p>
          <span className="empty-desc">
            Try resetting your search query or selecting "All Input Types" above.
          </span>
          <button
            type="button"
            className="sample-pill-btn reset-filters-btn"
            onClick={() => {
              setSearchQuery('');
              setSelectedType('all');
              setSelectedStatus('all');
            }}
          >
            Reset Filters
          </button>
        </div>
      ) : (
        <div className="history-table-container">
          <table className="history-table">
            <thead>
              <tr>
                <th>Target & Reference</th>
                <th>Type</th>
                <th>Status</th>
                <th>Initiated</th>
                <th style={{ textAlign: 'right' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredScans.map((scan) => {
                const dateStr = new Date(scan.created_at).toLocaleString([], {
                  month: 'short',
                  day: 'numeric',
                  hour: '2-digit',
                  minute: '2-digit',
                });

                return (
                  <tr key={scan.scan_id} className="history-row">
                    <td className="target-cell">
                      <div className="target-text" title={scan.normalized_target || scan.raw_target}>
                        {scan.normalized_target || scan.raw_target}
                      </div>
                      <span className="scan-id-tag">REF: {scan.scan_id.slice(0, 10)}...</span>
                    </td>
                    <td>
                      <span className="input-type-tag">{scan.input_type}</span>
                    </td>
                    <td>
                      <span className={`status-badge status-${scan.status.toLowerCase()}`}>
                        {scan.status}
                      </span>
                    </td>
                    <td className="date-cell">{dateStr}</td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        type="button"
                        className="inspect-report-btn"
                        onClick={() => onSelectScan(scan.scan_id)}
                      >
                        Inspect Report
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
