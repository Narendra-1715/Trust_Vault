import React, { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../features/auth/AuthContext';
import { useToast } from '../context/ToastContext';
import { Shield, Lock, AlertCircle, UserCheck, UserPlus, LogIn } from 'lucide-react';

export const LoginPage: React.FC = () => {
  const [mode, setMode] = useState<'signin' | 'register'>('signin');

  // Sign In state
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  // Register state
  const [regName, setRegName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regRole, setRegRole] = useState<'owner' | 'viewer'>('owner');

  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const { login, register } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const isExpired = searchParams.get('expired') === 'true';

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      await login(email, password);
      toast.success('Signed in successfully.');
      navigate('/documents');
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please verify credentials.');
      toast.error(err.message || 'Authentication failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (regPassword.length < 8) {
      setError('Password must be at least 8 characters long.');
      return;
    }

    setIsSubmitting(true);
    try {
      await register(regEmail, regPassword, regName, regRole);
      toast.success(`Account created for ${regName}! Signed into workspace.`);
      navigate('/documents');
    } catch (err: any) {
      setError(err.message || 'Registration failed. User may already exist.');
      toast.error(err.message || 'Registration failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSelectDemoUser = (demoEmail: string, demoPass: string) => {
    setMode('signin');
    setEmail(demoEmail);
    setPassword(demoPass);
    setError(null);
  };

  return (
    <div style={{
      maxWidth: '460px',
      margin: '2rem auto',
      padding: '0 1rem'
    }}>
      <div className="panel" style={{ padding: '2rem' }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: '#0f172a',
            color: '#38bdf8',
            width: '42px',
            height: '42px',
            borderRadius: 'var(--radius-sm)',
            marginBottom: '0.75rem',
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'
          }}>
            <Shield size={24} strokeWidth={2.2} />
          </div>
          <h1 style={{ fontSize: '1.375rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-main)' }}>
            {mode === 'signin' ? 'Sign in to TrustVault' : 'Create TrustVault Account'}
          </h1>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            {mode === 'signin' 
              ? 'Enter credentials to access confidential workspace' 
              : 'Register a secure confidential document identity'}
          </p>
        </div>

        {/* Mode Toggle Switcher */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '4px',
          backgroundColor: 'var(--bg-surface-secondary)',
          padding: '4px',
          borderRadius: 'var(--radius-sm)',
          marginBottom: '1.5rem',
          border: '1px solid var(--border-main)'
        }}>
          <button
            type="button"
            onClick={() => { setMode('signin'); setError(null); }}
            style={{
              padding: '0.5rem',
              fontSize: '0.8125rem',
              fontWeight: mode === 'signin' ? 600 : 500,
              color: mode === 'signin' ? 'var(--text-main)' : 'var(--text-muted)',
              backgroundColor: mode === 'signin' ? 'var(--bg-surface)' : 'transparent',
              border: mode === 'signin' ? '1px solid var(--border-main)' : 'none',
              borderRadius: 'var(--radius-xs)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.375rem',
              transition: 'all 0.15s ease'
            }}
          >
            <LogIn size={14} />
            <span>Sign In</span>
          </button>

          <button
            type="button"
            onClick={() => { setMode('register'); setError(null); }}
            style={{
              padding: '0.5rem',
              fontSize: '0.8125rem',
              fontWeight: mode === 'register' ? 600 : 500,
              color: mode === 'register' ? 'var(--text-main)' : 'var(--text-muted)',
              backgroundColor: mode === 'register' ? 'var(--bg-surface)' : 'transparent',
              border: mode === 'register' ? '1px solid var(--border-main)' : 'none',
              borderRadius: 'var(--radius-xs)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.375rem',
              transition: 'all 0.15s ease'
            }}
          >
            <UserPlus size={14} />
            <span>Create Account</span>
          </button>
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

        {mode === 'signin' ? (
          /* Sign In Form */
          <form onSubmit={handleLoginSubmit}>
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
        ) : (
          /* Registration Form */
          <form onSubmit={handleRegisterSubmit}>
            <div className="form-group">
              <label className="form-label" htmlFor="regName">Full Name</label>
              <input
                id="regName"
                type="text"
                className="input-field"
                value={regName}
                onChange={(e) => setRegName(e.target.value)}
                placeholder="John Security"
                required
                autoFocus
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="regEmail">Email address</label>
              <input
                id="regEmail"
                type="email"
                className="input-field"
                value={regEmail}
                onChange={(e) => setRegEmail(e.target.value)}
                placeholder="john@organization.com"
                required
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="regPassword">Password (Argon2id Encrypted)</label>
              <input
                id="regPassword"
                type="password"
                className="input-field"
                value={regPassword}
                onChange={(e) => setRegPassword(e.target.value)}
                placeholder="At least 8 characters"
                required
                minLength={8}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Initial Role</label>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginTop: '0.25rem' }}>
                <label style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '8px',
                  border: `1px solid ${regRole === 'owner' ? 'var(--accent)' : 'var(--border-main)'}`,
                  backgroundColor: regRole === 'owner' ? 'var(--accent-light)' : 'transparent',
                  borderRadius: 'var(--radius-sm)',
                  cursor: 'pointer',
                  fontSize: '0.8125rem'
                }}>
                  <input
                    type="radio"
                    name="role"
                    value="owner"
                    checked={regRole === 'owner'}
                    onChange={() => setRegRole('owner')}
                  />
                  <span>Document Owner</span>
                </label>

                <label style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '8px',
                  border: `1px solid ${regRole === 'viewer' ? 'var(--accent)' : 'var(--border-main)'}`,
                  backgroundColor: regRole === 'viewer' ? 'var(--accent-light)' : 'transparent',
                  borderRadius: 'var(--radius-sm)',
                  cursor: 'pointer',
                  fontSize: '0.8125rem'
                }}>
                  <input
                    type="radio"
                    name="role"
                    value="viewer"
                    checked={regRole === 'viewer'}
                    onChange={() => setRegRole('viewer')}
                  />
                  <span>Viewer</span>
                </label>
              </div>
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              style={{ width: '100%', marginTop: '0.5rem', padding: '0.625rem' }}
              disabled={isSubmitting}
            >
              {isSubmitting ? (
                <span>Registering Account...</span>
              ) : (
                <>
                  <UserPlus size={15} />
                  <span>Register &amp; Enter Workspace</span>
                </>
              )}
            </button>
          </form>
        )}

        {/* Demo Accounts Quick-Select */}
        <div style={{ marginTop: '2rem', paddingTop: '1.5rem', borderTop: '1px solid var(--border-main)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', marginBottom: '0.75rem', color: 'var(--text-secondary)', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            <UserCheck size={14} />
            <span>Evaluator Demo Roles (One-Click Test)</span>
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
