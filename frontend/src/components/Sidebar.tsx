import React from 'react';

interface SidebarProps {
  currentTab: string;
  onTabChange: (tab: string) => void;
  scansCount?: number;
  isOpenMobile?: boolean;
  onCloseMobile?: () => void;
  policyVersion?: string;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onTabChange,
  scansCount = 0,
  isOpenMobile = false,
  onCloseMobile,
  policyVersion = '1.0.0',
}) => {
  const navItems = [
    {
      id: 'scanner',
      label: 'Threat Scanner',
      icon: (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      ),
    },
    {
      id: 'history',
      label: 'Scan History',
      badge: scansCount > 0 ? scansCount : undefined,
      icon: (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10"/>
          <polyline points="12 6 12 12 16 14"/>
        </svg>
      ),
    },
    {
      id: 'deepfake',
      label: 'Deepfake Detector',
      badge: 'AI Vision',
      icon: (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10"/>
          <path d="M8 14s1.5 2 4 2 4-2 4-2"/>
          <line x1="9" y1="9" x2="9.01" y2="9"/>
          <line x1="15" y1="9" x2="15.01" y2="9"/>
        </svg>
      ),
    },
    {
      id: 'analytics',
      label: 'Security Posture',
      icon: (
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <line x1="18" y1="20" x2="18" y2="10"/>
          <line x1="12" y1="20" x2="12" y2="4"/>
          <line x1="6" y1="20" x2="6" y2="14"/>
        </svg>
      ),
    },
  ];

  const handleTabClick = (id: string) => {
    onTabChange(id);
    if (onCloseMobile) {
      onCloseMobile();
    }
  };

  return (
    <>
      {isOpenMobile && (
        <div
          className="sidebar-backdrop"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}

      <aside className={`thelix-sidebar ${isOpenMobile ? 'open-mobile' : ''}`}>
        <div className="sidebar-brand">
          <div className="brand-logo-mark">
            <span className="logo-symbol">⬡</span>
          </div>
          <div className="brand-text">
            <span className="brand-title">THELIX AI</span>
            <span className="brand-subtitle">Digital Trust Engine</span>
          </div>
          {onCloseMobile && (
            <button
              type="button"
              className="sidebar-close-mobile-btn"
              onClick={onCloseMobile}
              aria-label="Close navigation"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="18" y1="6" x2="6" y2="18"/>
                <line x1="6" y1="6" x2="18" y2="18"/>
              </svg>
            </button>
          )}
        </div>

        <div className="sidebar-status-pill">
          <span className="pulse-indicator"></span>
          <span className="status-label">Continuous Defense Active</span>
        </div>

        <nav className="sidebar-nav">
          {navItems.map((item) => {
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                className={`nav-button ${isActive ? 'active' : ''}`}
                onClick={() => handleTabClick(item.id)}
              >
                <span className="nav-icon">{item.icon}</span>
                <span className="nav-label">{item.label}</span>
                {item.badge !== undefined && (
                  <span className={`nav-badge ${isActive ? 'badge-active' : ''}`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <div className="system-pill">
            <div className="system-pill-header">
              <span className="system-pill-title">Zero Trust Protocol</span>
              <span className="system-pill-version">v{policyVersion}</span>
            </div>
            <div className="system-pill-desc">Deterministic Risk Engine</div>
          </div>
        </div>
      </aside>
    </>
  );
};
