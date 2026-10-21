import React from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, ArrowLeft } from 'lucide-react';

export const NotFoundPage: React.FC = () => {
  return (
    <div className="container" style={{ textAlign: 'center', padding: '5rem 0' }}>
      <div className="panel" style={{ maxWidth: '440px', margin: '0 auto', padding: '2.5rem' }}>
        <ShieldAlert size={36} color="var(--text-muted)" style={{ margin: '0 auto 1rem' }} />
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, marginBottom: '0.5rem' }}>404 - Resource Not Found</h1>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
          The requested page or confidential document does not exist, or you lack active permission to view it.
        </p>
        <Link to="/" className="btn btn-primary btn-sm">
          <ArrowLeft size={14} />
          <span>Return Home</span>
        </Link>
      </div>
    </div>
  );
};
