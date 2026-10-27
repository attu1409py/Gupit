import React from 'react';

interface StatusCardProps {
  title: string;
  badgeText: string;
  badgeType: 'success' | 'info' | 'warning' | 'brand';
  icon: React.ReactNode;
  description: string;
  details?: { label: string; value: string }[];
  id?: string;
}

export const StatusCard: React.FC<StatusCardProps> = ({
  title,
  badgeText,
  badgeType,
  icon,
  description,
  details,
  id,
}) => {
  const badgeClass =
    badgeType === 'success'
      ? 'badge-success'
      : badgeType === 'info'
      ? 'badge-info'
      : badgeType === 'warning'
      ? 'badge-warning'
      : 'badge-brand';

  return (
    <div className="card" id={id} style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Card Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: '38px',
          height: '38px',
          borderRadius: 'var(--radius-md)',
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--accent-indigo)'
        }}>
          {icon}
        </div>
        <span className={`badge ${badgeClass}`}>{badgeText}</span>
      </div>

      {/* Card Content */}
      <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '0.5rem', color: '#ffffff' }}>
        {title}
      </h3>
      <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.25rem', flexGrow: 1 }}>
        {description}
      </p>

      {/* Detail Rows */}
      {details && details.length > 0 && (
        <div style={{
          borderTop: '1px solid var(--border-subtle)',
          paddingTop: '0.875rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.5rem',
          fontSize: '0.75rem'
        }}>
          {details.map((item, index) => (
            <div key={index} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: 'var(--text-muted)' }}>{item.label}</span>
              <code style={{ color: 'var(--accent-cyan)', background: 'rgba(6, 182, 212, 0.08)', padding: '0.125rem 0.375rem', borderRadius: '4px' }}>
                {item.value}
              </code>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
