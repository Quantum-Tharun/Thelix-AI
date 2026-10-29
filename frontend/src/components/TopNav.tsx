import React from 'react';
import type { SystemHealth } from '../types/api';

interface TopNavProps {
  health: SystemHealth | null;
  loadingHealth: boolean;
  onRefreshHealth: () => void;
  onToggleMobileMenu?: () => void;
  currentTabName?: string;
}

export const TopNav: React.FC<TopNavProps> = ({
  health,
  loadingHealth,
  onRefreshHealth,
  onToggleMobileMenu,
  currentTabName = 'Trust & Threat Assessment',
}) => {
  const isHealthy = health && (health.status === 'ready' || health.status === 'ok');

  return (
    <header className="thelix-top-nav">
      <div className="nav-left">
        {onToggleMobileMenu && (
          <button
            type="button"
            className="mobile-hamburger-btn"
            onClick={onToggleMobileMenu}
            aria-label="Open navigation menu"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="3" y1="12" x2="21" y2="12"/>
              <line x1="3" y1="6" x2="21" y2="6"/>
              <line x1="3" y1="18" x2="21" y2="18"/>
            </svg>
          </button>
        )}

        <div className="environment-badge">
          <span className="env-dot"></span>
          <span className="env-name">{health?.environment ? health.environment.toUpperCase() : 'CORE'}</span>
        </div>

        <div className="header-breadcrumbs">
          <span className="breadcrumb-root">Shield</span>
          <span className="separator">/</span>
          <span className="current-location">{currentTabName}</span>
        </div>
      </div>

      <div className="nav-right">
        <button
          type="button"
          className="health-badge-button"
          onClick={onRefreshHealth}
          title="Click to re-verify engine readiness"
        >
          <span
            className={`status-indicator ${
              isHealthy ? 'healthy' : loadingHealth ? 'checking' : 'degraded'
            }`}
          />
          <span className="health-label">
            {loadingHealth ? 'Verifying...' : isHealthy ? 'Risk Engine Active' : 'Engine Offline'}
          </span>
          {health?.policy_version && (
            <span className="policy-tag">P-{health.policy_version}</span>
          )}
        </button>

        <div className="user-profile-badge">
          <div className="avatar-circle">
            <span>TX</span>
          </div>
          <div className="user-details">
            <span className="user-name">Security Analyst</span>
            <span className="user-role">Zero-Trust Guard</span>
          </div>
        </div>
      </div>
    </header>
  );
};
