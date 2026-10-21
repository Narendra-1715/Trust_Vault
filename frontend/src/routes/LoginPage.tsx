import React, { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../features/auth/AuthContext';
import { Shield, Lock, AlertCircle, UserCheck } from 'lucide-react';

export const LoginPage: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const isExpired = searchParams.get('expired') === 'true';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      await login(email, password);
      navigate('/documents');
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSelectDemoUser = (demoEmail: string, demoPass: string) => {
    setEmail(demoEmail);
    setPassword(demoPass);
    setError(null);
  };

  return (
    <div style={{
      maxWidth: '440px',
      margin: '2rem auto',
      padding: '0 1rem'
    }}>
      <div className="panel" style={{ padding: '2rem' }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: '1.75rem' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: '#0f172a',
            color: '#38bdf8',
            width: '40px',
            height: '40px',
            borderRadius: 'var(--radius-sm)',
            marginBottom: '0.75rem'
          }}>
            <Shield size={22} strokeWidth={2.2} />
          </div>
          <h1 style={{ fontSize: '1.375rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-main)' }}>
            Sign in to TrustVault
          </h1>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Enter your credentials to access confidential workspace
          </p>
        </div>

        {isExpired && (
          <div style={{
            backgroundColor: 'var(--warning-bg)',
            color: 'var(--warning)',
            border: '1px solid var(--warning-border)',
            padding: '0.75rem',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.8125rem',
            marginBottom: '1.25rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}>
            <AlertCircle size={16} />
            <span>Your session has expired. Please sign in again.</span>
          </div>
        )}

        {error && (
          <div style={{
            backgroundColor: 'var(--danger-bg)',
            color: 'var(--danger)',
            border: '1px solid var(--danger-border)',
            padding: '0.75rem',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.8125rem',
            marginBottom: '1.25rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}>
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label" htmlFor="email">Email address</label>
            <input
              id="email"
              type="email"
              className="input-field"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="user@trustvault.com"
              required
              autoFocus
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              className="input-field"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              required
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: '100%', marginTop: '0.5rem', padding: '0.625rem' }}
            disabled={isSubmitting}
          >
            {isSubmitting ? (
              <span>Authenticating...</span>
            ) : (
              <>
                <Lock size={15} />
                <span>Sign in to Workspace</span>
              </>
            )}
          </button>
        </form>

        {/* Demo Accounts Quick-Select */}
        <div style={{ marginTop: '2rem', paddingTop: '1.5rem', borderTop: '1px solid var(--border-main)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', marginBottom: '0.75rem', color: 'var(--text-secondary)', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            <UserCheck size={14} />
            <span>Development Demo Accounts</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              style={{ justifyContent: 'space-between', width: '100%' }}
              onClick={() => handleSelectDemoUser('owner_a@trustvault.com', 'OwnerAPass123!')}
            >
              <div style={{ textAlign: 'left' }}>
                <span style={{ fontWeight: 600 }}>Alice (Document Owner A)</span>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>owner_a@trustvault.com</div>
              </div>
              <span className="badge badge-green">Owner</span>
            </button>

            <button
              type="button"
              className="btn btn-secondary btn-sm"
              style={{ justifyContent: 'space-between', width: '100%' }}
              onClick={() => handleSelectDemoUser('owner_b@trustvault.com', 'OwnerBPass123!')}
            >
              <div style={{ textAlign: 'left' }}>
                <span style={{ fontWeight: 600 }}>Bob (Document Owner B)</span>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>owner_b@trustvault.com</div>
              </div>
              <span className="badge badge-green">Owner</span>
            </button>

            <button
              type="button"
              className="btn btn-secondary btn-sm"
              style={{ justifyContent: 'space-between', width: '100%' }}
              onClick={() => handleSelectDemoUser('viewer_a@trustvault.com', 'ViewerAPass123!')}
            >
              <div style={{ textAlign: 'left' }}>
                <span style={{ fontWeight: 600 }}>Carol (Restricted Viewer)</span>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>viewer_a@trustvault.com</div>
              </div>
              <span className="badge badge-gray">Viewer</span>
            </button>

            <button
              type="button"
              className="btn btn-secondary btn-sm"
              style={{ justifyContent: 'space-between', width: '100%' }}
              onClick={() => handleSelectDemoUser('admin@trustvault.com', 'AdminPass123!')}
            >
              <div style={{ textAlign: 'left' }}>
                <span style={{ fontWeight: 600 }}>Security Admin</span>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>admin@trustvault.com</div>
              </div>
              <span className="badge badge-blue">Admin</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
