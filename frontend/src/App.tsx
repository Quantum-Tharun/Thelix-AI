import { useState, useEffect, useCallback } from 'react';
import './App.css';
import { Sidebar } from './components/Sidebar';
import { TopNav } from './components/TopNav';
import { ScannerPanel } from './components/ScannerPanel';
import { TrustScoreCard } from './components/TrustScoreCard';
import { ScanHistory } from './components/ScanHistory';
import { SecurityPosture } from './components/SecurityPosture';
import { DeepfakeDetector } from './components/DeepfakeDetector';
import {
  checkHealth,
  analyzeTarget,
  fetchRecentScans,
  fetchScanReport,
} from './services/api';
import type { AnalyzeParams } from './services/api';
import type { AnalyzeReportResponse, ScanResponse, SystemHealth } from './types/api';

function App() {
  const [currentTab, setCurrentTab] = useState<'scanner' | 'history' | 'deepfake' | 'analytics'>('scanner');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [loadingHealth, setLoadingHealth] = useState(false);
  const [recentScans, setRecentScans] = useState<ScanResponse[]>([]);
  const [loadingScans, setLoadingScans] = useState(false);
  const [currentReport, setCurrentReport] = useState<AnalyzeReportResponse | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [prefilledUrl, setPrefilledUrl] = useState<string>('');

  const loadHealth = useCallback(async () => {
    setLoadingHealth(true);
    try {
      const res = await checkHealth();
      setHealth(res);
    } catch {
      setHealth(null);
    } finally {
      setLoadingHealth(false);
    }
  }, []);

  const loadScans = useCallback(async () => {
    setLoadingScans(true);
    try {
      const scans = await fetchRecentScans();
      setRecentScans(scans);
    } catch {
      // Backend may be offline or starting up
    } finally {
      setLoadingScans(false);
    }
  }, []);

  useEffect(() => {
    let ignore = false;

    async function initializeDashboard() {
      setLoadingHealth(true);
      setLoadingScans(true);
      try {
        const [healthRes, scansRes] = await Promise.allSettled([
          checkHealth(),
          fetchRecentScans(),
        ]);
        if (!ignore) {
          if (healthRes.status === 'fulfilled') {
            setHealth(healthRes.value);
          } else {
            setHealth(null);
          }
          if (scansRes.status === 'fulfilled') {
            setRecentScans(scansRes.value);
          }
        }
      } finally {
        if (!ignore) {
          setLoadingHealth(false);
          setLoadingScans(false);
        }
      }
    }

    initializeDashboard();

    return () => {
      ignore = true;
    };
  }, []);

  const handleRunAnalysis = async (params: AnalyzeParams) => {
    setAnalyzing(true);
    setErrorMessage(null);
    try {
      const report = await analyzeTarget(params);
      setCurrentReport(report);
      // Smoothly scroll to report view
      window.scrollTo({ top: 0, behavior: 'smooth' });
      // Refresh scan list in background
      loadScans();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Analysis failed. Please check inputs and try again.';
      setErrorMessage(msg);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleSelectHistoricalScan = async (scanId: string) => {
    setAnalyzing(true);
    setErrorMessage(null);
    try {
      const report = await fetchScanReport(scanId);
      setCurrentReport(report);
      setCurrentTab('scanner');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : `Failed to load report for scan ${scanId}`;
      setErrorMessage(msg);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleUseSample = (url: string) => {
    setPrefilledUrl(url);
    setCurrentTab('scanner');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const getTabTitle = () => {
    switch (currentTab) {
      case 'scanner':
        return 'Trust & Threat Assessment';
      case 'history':
        return 'Audit Ledger & History';
      case 'deepfake':
        return 'Synthetic Media & Deepfake Analysis';
      case 'analytics':
        return 'Security Posture & Telemetry';
      default:
        return 'Security Assessment';
    }
  };

  return (
    <div className="dashboard-root">
      <Sidebar
        currentTab={currentTab}
        onTabChange={(tab) => setCurrentTab(tab as 'scanner' | 'history' | 'deepfake' | 'analytics')}
        scansCount={recentScans.length}
        isOpenMobile={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
        policyVersion={health?.policy_version || '1.0.0'}
      />

      <div className="dashboard-main">
        <TopNav
          health={health}
          loadingHealth={loadingHealth}
          onRefreshHealth={loadHealth}
          onToggleMobileMenu={() => setMobileMenuOpen((prev) => !prev)}
          currentTabName={getTabTitle()}
        />

        <main className="dashboard-content">
          {errorMessage && (
            <div className="error-alert-banner">
              <div className="error-content">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>
                  <line x1="12" y1="8" x2="12" y2="12"/>
                  <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                <div className="error-text-group">
                  <span className="error-title">Evaluation Notice</span>
                  <span className="error-desc">{errorMessage}</span>
                </div>
              </div>
              <button
                type="button"
                className="dismiss-error-btn"
                onClick={() => setErrorMessage(null)}
              >
                Dismiss
              </button>
            </div>
          )}

          {currentTab === 'scanner' && (
            <>
              {currentReport && (
                <TrustScoreCard
                  report={currentReport}
                  onClear={() => setCurrentReport(null)}
                />
              )}

              <ScannerPanel
                onAnalyze={handleRunAnalysis}
                isLoading={analyzing}
                prefillContent={prefilledUrl}
                health={health}
              />

              <ScanHistory
                scans={recentScans}
                loading={loadingScans}
                onRefresh={loadScans}
                onSelectScan={handleSelectHistoricalScan}
                onUseSample={handleUseSample}
              />
            </>
          )}

          {currentTab === 'history' && (
            <>
              {currentReport && (
                <TrustScoreCard
                  report={currentReport}
                  onClear={() => setCurrentReport(null)}
                />
              )}
              <ScanHistory
                scans={recentScans}
                loading={loadingScans}
                onRefresh={loadScans}
                onSelectScan={handleSelectHistoricalScan}
                onUseSample={handleUseSample}
              />
            </>
          )}

          {currentTab === 'deepfake' && (
            <DeepfakeDetector health={health} />
          )}

          {currentTab === 'analytics' && (
            <SecurityPosture
              health={health}
              scans={recentScans}
              onTriggerScanClick={() => setCurrentTab('scanner')}
            />
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
