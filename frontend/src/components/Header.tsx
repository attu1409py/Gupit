import React from 'react';
import { Shield, KeyRound, Lock, FileCode } from 'lucide-react';

interface HeaderProps {
  apiStatus: 'checking' | 'online' | 'offline';
  apiVersion?: string | undefined;
}

export const Header: React.FC<HeaderProps> = ({ apiStatus, apiVersion }) => {
  return (
    <header className="header" style={{
      borderBottom: '1px solid var(--border-subtle)',
      background: 'rgba(9, 13, 22, 0.8)',
      backdropFilter: 'blur(12px)',
      position: 'sticky',
      top: 0,
      zIndex: 50,
      padding: '0.875rem 0'
    }}>
      <div className="container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        {/* Logo and Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{
            background: 'linear-gradient(135deg, #6366f1, #06b6d4)',
            padding: '0.5rem',
            borderRadius: 'var(--radius-md)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: 'var(--glow-indigo)'
          }}>
            <Shield size={24} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontSize: '1.25rem', fontWeight: 800, letterSpacing: '-0.025em', color: '#ffffff' }}>
                GUPIT
              </span>
              <span className="badge badge-brand" style={{ fontSize: '0.65rem' }}>
                v{apiVersion || '0.1.0'} Foundation
              </span>
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Hybrid Cryptography File Sharing
            </p>
          </div>
        </div>

        {/* Navigation & Status Indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          {/* Algorithm Pill */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.375rem 0.75rem',
            background: 'var(--bg-input)',
            borderRadius: 'var(--radius-full)',
            border: '1px solid var(--border-subtle)',
            fontSize: '0.75rem',
            color: 'var(--text-secondary)'
          }}>
            <Lock size={13} color="var(--accent-cyan)" />
            <span>AES-256-GCM</span>
            <span style={{ color: 'var(--border-subtle)' }}>•</span>
            <KeyRound size={13} color="var(--accent-indigo)" />
            <span>RSA-OAEP / PSS</span>
          </div>

          {/* Backend Status Live Badge */}
          <div
            id="backend-status-indicator"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.375rem 0.75rem',
              borderRadius: 'var(--radius-full)',
              background: apiStatus === 'online'
                ? 'rgba(16, 185, 129, 0.1)'
                : apiStatus === 'offline'
                ? 'rgba(244, 63, 94, 0.1)'
                : 'rgba(245, 158, 11, 0.1)',
              border: `1px solid ${
                apiStatus === 'online'
                  ? 'rgba(16, 185, 129, 0.3)'
                  : apiStatus === 'offline'
                  ? 'rgba(244, 63, 94, 0.3)'
                  : 'rgba(245, 158, 11, 0.3)'
              }`,
              fontSize: '0.75rem',
              fontWeight: 600,
              color: apiStatus === 'online'
                ? 'var(--accent-emerald)'
                : apiStatus === 'offline'
                ? 'var(--accent-rose)'
                : 'var(--accent-amber)'
            }}
          >
            <span
              className={`status-dot ${apiStatus === 'online' ? 'active' : ''}`}
              style={{
                backgroundColor: apiStatus === 'online'
                  ? 'var(--accent-emerald)'
                  : apiStatus === 'offline'
                  ? 'var(--accent-rose)'
                  : 'var(--accent-amber)'
              }}
            />
            <span>
              {apiStatus === 'online'
                ? 'API Online'
                : apiStatus === 'offline'
                ? 'API Disconnected'
                : 'Checking API...'}
            </span>
          </div>

          {/* API Contract link */}
          <a
            id="docs-link"
            href="/docs"
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-secondary"
            style={{ fontSize: '0.75rem', padding: '0.375rem 0.75rem' }}
          >
            <FileCode size={14} />
            <span>API Docs</span>
          </a>
        </div>
      </div>
    </header>
  );
};
