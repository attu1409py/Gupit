import React from 'react';
import { ShieldAlert, BookOpen, GitBranch } from 'lucide-react';

export const Footer: React.FC = () => {
  return (
    <footer style={{
      borderTop: '1px solid var(--border-subtle)',
      background: 'rgba(9, 13, 22, 0.95)',
      padding: '2rem 0',
      marginTop: 'auto'
    }}>
      <div className="container" style={{
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '1rem',
        fontSize: '0.8125rem',
        color: 'var(--text-muted)'
      }}>
        {/* Left: Security Disclaimer */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
          <ShieldAlert size={18} color="var(--accent-amber)" />
          <span>
            <strong>Educational Prototype:</strong> Uses server-assisted cryptographic processing.
            Not End-to-End Encrypted (E2EE).
          </span>
        </div>

        {/* Right: Team and Project Info */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
            <GitBranch size={15} color="var(--text-brand)" />
            <span>3-Person Collaborative Project</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
            <BookOpen size={15} color="var(--accent-cyan)" />
            <span>FastAPI • React 19 • Python Cryptography</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
