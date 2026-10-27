import React, { useState } from 'react';
import {
  ShieldCheck,
  Server,
  Lock,
  Users,
  AlertTriangle,
  UploadCloud,
  DownloadCloud,
  Key,
  RefreshCw,
  CheckCircle2,
} from 'lucide-react';
import { HealthStatus } from '../types';
import { StatusCard } from '../components/StatusCard';

interface DashboardShellProps {
  health: HealthStatus | null;
  loading: boolean;
  onRefreshHealth: () => void;
}

const WORKFLOW_STEPS = [
  { step: 1, title: 'Auth & Login', desc: 'Sender registers/logs in via Argon2 & session cookies' },
  { step: 2, title: 'Recipient Select', desc: 'Sender picks registered recipient user' },
  { step: 3, title: 'AES-256-GCM', desc: 'File encrypted with fresh 256-bit key & 96-bit nonce' },
  { step: 4, title: 'RSA-OAEP Wrap', desc: 'AES key wrapped with recipient RSA public key' },
  { step: 5, title: 'RSA-PSS Sign', desc: 'Package signed with sender RSA private key' },
  { step: 6, title: 'Restricted Link', desc: 'High-entropy link generated; SHA-256 token stored' },
  { step: 7, title: 'Recipient Login', desc: 'Recipient logs in and accesses share URL' },
  { step: 8, title: 'Access & Expiry Check', desc: 'Backend verifies recipient identity & token hash' },
  { step: 9, title: 'Verify & Decrypt', desc: 'RSA-PSS signature verified; AES-GCM tag authenticated' },
  { step: 10, title: 'Safe Download', desc: 'Plaintext delivered only after full verification' },
];

export const DashboardShell: React.FC<DashboardShellProps> = ({
  health,
  loading,
  onRefreshHealth,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'workflow' | 'team'>('overview');

  return (
    <main className="container" style={{ padding: '2.5rem 1.5rem', flexGrow: 1 }}>
      {/* Hero Header */}
      <section style={{ marginBottom: '2.5rem', textAlign: 'center' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <span className="badge badge-brand">Educational Prototype</span>
          <span className="badge badge-info">Phase 1: Architecture Setup</span>
        </div>
        <h1 style={{
          fontSize: '2.5rem',
          fontWeight: 800,
          letterSpacing: '-0.03em',
          marginBottom: '0.75rem',
          background: 'linear-gradient(135deg, #ffffff 40%, #818cf8 100%)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
        }}>
          Gupit: Secure File Sharing Using Hybrid Cryptography
        </h1>
        <p style={{
          fontSize: '1.05rem',
          color: 'var(--text-secondary)',
          maxWidth: '780px',
          margin: '0 auto 1.5rem auto',
          lineHeight: 1.6
        }}>
          A modular foundation pairing <strong>AES-256-GCM</strong> authenticated encryption with 
          <strong> RSA-OAEP</strong> key wrapping and <strong>RSA-PSS</strong> digital signatures. 
          Engineered for a collaborative 3-person development team.
        </p>

        {/* Quick Action Tabs */}
        <div style={{
          display: 'inline-flex',
          background: 'var(--bg-input)',
          padding: '0.25rem',
          borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--border-subtle)',
          gap: '0.25rem'
        }}>
          <button
            id="tab-btn-overview"
            className={`btn ${activeTab === 'overview' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ padding: '0.5rem 1rem', fontSize: '0.8125rem' }}
            onClick={() => setActiveTab('overview')}
          >
            <Server size={15} />
            <span>Architecture & Health</span>
          </button>
          <button
            id="tab-btn-workflow"
            className={`btn ${activeTab === 'workflow' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ padding: '0.5rem 1rem', fontSize: '0.8125rem' }}
            onClick={() => setActiveTab('workflow')}
          >
            <Lock size={15} />
            <span>10-Step Cryptographic Flow</span>
          </button>
          <button
            id="tab-btn-team"
            className={`btn ${activeTab === 'team' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ padding: '0.5rem 1rem', fontSize: '0.8125rem' }}
            onClick={() => setActiveTab('team')}
          >
            <Users size={15} />
            <span>Team Ownership</span>
          </button>
        </div>
      </section>

      {/* Tab 1: Architecture & System Health */}
      {activeTab === 'overview' && (
        <section style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
          {/* 4 Foundation Status Cards */}
          <div className="grid-4">
            {/* Backend Health Card */}
            <StatusCard
              id="card-backend-health"
              title="FastAPI Backend"
              badgeText={health ? 'Operational' : loading ? 'Probing...' : 'Offline'}
              badgeType={health ? 'success' : 'warning'}
              icon={<Server size={20} />}
              description="Uvicorn ASGI application serving REST endpoints under /api with CORS and typed error envelopes."
              details={[
                { label: 'Status', value: health?.status ?? 'unavailable' },
                { label: 'Version', value: health?.version ?? '0.1.0' },
                { label: 'Storage', value: health?.storage_backend ?? 'local' },
              ]}
            />

            {/* Cryptographic Engine Card */}
            <StatusCard
              id="card-crypto-status"
              title="Crypto Engine"
              badgeText="Frozen Interface"
              badgeType="brand"
              icon={<ShieldCheck size={20} />}
              description="Standardized signatures for AES-256-GCM, RSA-OAEP, and RSA-PSS. Stubs raise NotImplementedError."
              details={[
                { label: 'Symmetric', value: 'AES-256-GCM' },
                { label: 'Key Wrapping', value: 'RSA-OAEP (SHA-256)' },
                { label: 'Signature', value: 'RSA-PSS (SHA-256)' },
              ]}
            />

            {/* Storage Abstraction Card */}
            <StatusCard
              id="card-storage-status"
              title="Storage Driver"
              badgeText="Filesystem Ready"
              badgeType="info"
              icon={<UploadCloud size={20} />}
              description="BaseStorageService abstraction with local disk driver; prepared for future object storage migration."
              details={[
                { label: 'Driver', value: 'LocalFileSystemStorage' },
                { label: 'Max File Size', value: '50 MB' },
                { label: 'Package Type', value: '.pkg binary wire format' },
              ]}
            />

            {/* Security Model Card */}
            <StatusCard
              id="card-security-model"
              title="Security Boundary"
              badgeText="Server-Assisted"
              badgeType="warning"
              icon={<AlertTriangle size={20} />}
              description="Educational prototype using server-side key management. Documented as not end-to-end encrypted (E2EE)."
              details={[
                { label: 'Master Key', value: 'SERVER_MASTER_KEY (env)' },
                { label: 'Password Hash', value: 'Argon2id' },
                { label: 'Tokens', value: 'SHA-256 Hashed at Rest' },
              ]}
            />
          </div>

          {/* Backend Health Check Bar */}
          <div className="card" style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '1rem',
            background: 'rgba(15, 23, 42, 0.6)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <div style={{
                background: health ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)',
                color: health ? 'var(--accent-emerald)' : 'var(--accent-rose)',
                padding: '0.5rem',
                borderRadius: 'var(--radius-md)'
              }}>
                <CheckCircle2 size={20} />
              </div>
              <div>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600 }}>
                  Backend Health Verification
                </h4>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Pings <code>/api/health</code> to verify connectivity between Vite and FastAPI.
                </p>
              </div>
            </div>

            <button
              id="btn-recheck-health"
              className="btn btn-secondary"
              onClick={onRefreshHealth}
              disabled={loading}
            >
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
              <span>{loading ? 'Pinging API...' : 'Re-check Endpoint'}</span>
            </button>
          </div>

          {/* Planned Features Shell Preview */}
          <div style={{ marginTop: '0.5rem' }}>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '1rem', color: '#ffffff' }}>
              Planned Dashboard Workspaces (Phase 2 Roadmap)
            </h2>
            <div className="grid-3">
              <div className="card" style={{ opacity: 0.85, borderStyle: 'dashed' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <UploadCloud size={18} color="var(--accent-indigo)" />
                    <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Send & Encrypt File</h3>
                  </div>
                  <span className="badge badge-warning" style={{ fontSize: '0.65rem' }}>Phase 2 Task</span>
                </div>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                  File dropzone with recipient user search. Automatically runs AES-256-GCM encryption, RSA-OAEP wrapping, and RSA-PSS signing.
                </p>
              </div>

              <div className="card" style={{ opacity: 0.85, borderStyle: 'dashed' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <DownloadCloud size={18} color="var(--accent-cyan)" />
                    <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Received Shares</h3>
                  </div>
                  <span className="badge badge-warning" style={{ fontSize: '0.65rem' }}>Phase 2 Task</span>
                </div>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                  Inbox of incoming files. Enforces recipient identity verification, signature checking, and authenticated decryption prior to file streaming.
                </p>
              </div>

              <div className="card" style={{ opacity: 0.85, borderStyle: 'dashed' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Key size={18} color="var(--accent-violet)" />
                    <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Identity Keypairs</h3>
                  </div>
                  <span className="badge badge-warning" style={{ fontSize: '0.65rem' }}>Phase 2 Task</span>
                </div>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                  Cryptographic identity manager showing SHA-256 fingerprints, SPKI public key downloads, and key rotation status.
                </p>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Tab 2: 10-Step Workflow Stepper */}
      {activeTab === 'workflow' && (
        <section className="card" style={{ padding: '2rem' }}>
          <div style={{ marginBottom: '1.5rem' }}>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.25rem' }}>
              Intended 10-Step Cryptographic Workflow
            </h2>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Execution pipeline specified in project requirements. Every step is cryptographically bound and verified.
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {WORKFLOW_STEPS.map((item) => (
              <div
                key={item.step}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '1rem',
                  padding: '1rem',
                  borderRadius: 'var(--radius-md)',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  width: '32px',
                  height: '32px',
                  borderRadius: 'var(--radius-full)',
                  background: 'linear-gradient(135deg, var(--accent-indigo), var(--accent-cyan))',
                  color: '#ffffff',
                  fontWeight: 700,
                  fontSize: '0.8125rem',
                  flexShrink: 0
                }}>
                  {item.step}
                </div>
                <div>
                  <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#ffffff' }}>
                    {item.title}
                  </h4>
                  <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                    {item.desc}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Tab 3: Team Ownership & Architecture */}
      {activeTab === 'team' && (
        <section style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="grid-3">
            <div className="card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                <span className="badge badge-brand">Developer 1</span>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>Cryptographic Engine</h3>
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                Owns the Python cryptography engine, packaging binary format, RSA key generation, and crypto security tests.
              </p>
              <ul style={{ fontSize: '0.75rem', color: 'var(--text-muted)', listStylePosition: 'inside' }}>
                <li><code>backend/app/services/crypto_engine.py</code></li>
                <li><code>backend/tests/test_crypto_*.py</code></li>
                <li><code>docs/CRYPTO_INTERFACE.md</code></li>
              </ul>
            </div>

            <div className="card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                <span className="badge badge-info">Developer 2</span>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>Frontend & Client</h3>
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                Owns the React 19 / TypeScript single-page app, CSS styling, components, and HTTP API client.
              </p>
              <ul style={{ fontSize: '0.75rem', color: 'var(--text-muted)', listStylePosition: 'inside' }}>
                <li><code>frontend/src/components/</code></li>
                <li><code>frontend/src/pages/</code></li>
                <li><code>frontend/src/services/api.ts</code></li>
              </ul>
            </div>

            <div className="card">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                <span className="badge badge-success">Developer 3</span>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>FastAPI & Storage</h3>
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                Owns FastAPI route handlers, Argon2 authentication, SQLite models, sharing logic, and HTTPX tests.
              </p>
              <ul style={{ fontSize: '0.75rem', color: 'var(--text-muted)', listStylePosition: 'inside' }}>
                <li><code>backend/app/api/</code></li>
                <li><code>backend/app/services/auth_service.py</code></li>
                <li><code>backend/tests/test_api_*.py</code></li>
              </ul>
            </div>
          </div>
        </section>
      )}
    </main>
  );
};
