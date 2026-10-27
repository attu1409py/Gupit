import React, { useEffect, useState, useCallback } from 'react';
import { Header } from './components/Header';
import { Footer } from './components/Footer';
import { DashboardShell } from './pages/DashboardShell';
import { fetchHealth } from './services/api';
import { HealthStatus } from './types';

export const App: React.FC = () => {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [apiStatus, setApiStatus] = useState<'checking' | 'online' | 'offline'>('checking');

  const checkHealth = useCallback(async () => {
    setLoading(true);
    setApiStatus('checking');
    try {
      const data = await fetchHealth();
      setHealth(data);
      setApiStatus(data.status === 'ok' ? 'online' : 'offline');
    } catch (err) {
      console.warn('API health check error:', err);
      setHealth(null);
      setApiStatus('offline');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    checkHealth();
  }, [checkHealth]);

  return (
    <div className="app-container">
      <Header apiStatus={apiStatus} apiVersion={health?.version} />
      <DashboardShell
        health={health}
        loading={loading}
        onRefreshHealth={checkHealth}
      />
      <Footer />
    </div>
  );
};

export default App;
