import React, { useState } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { useAuth } from '../features/auth/AuthContext';
import { useToast } from '../context/ToastContext';
import { 
  Shield, 
  Lock, 
  AlertCircle, 
  UserCheck, 
  UserPlus, 
  LogIn, 
  Eye, 
  EyeOff, 
  KeyRound, 
  History, 
  ChevronDown, 
  ChevronUp,
  FileCheck2,
  ShieldAlert
} from 'lucide-react';

export const LoginPage: React.FC = () => {
  const [mode, setMode] = useState<'signin' | 'register'>('signin');

  // Sign In state
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  // Register state
  const [regName, setRegName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [showRegPassword, setShowRegPassword] = useState(false);
  const [regRole, setRegRole] = useState<'owner' | 'viewer'>('owner');

  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isDemoOpen, setIsDemoOpen] = useState(true);

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
      display: 'flex',
      minHeight: '100vh',
      width: '100%',
      backgroundColor: 'var(--bg-warm)',
    }}>
      {/* ================= LEFT COLUMN: GRAPHITE BRAND & VALUE PROP ================= */}
      <div style={{
        flex: '1.2',
        minWidth: '320px',
        backgroundColor: 'var(--graphite)',
        color: '#F6F3F0',
        padding: '3.5rem 4rem',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        position: 'relative',
        overflow: 'hidden',
        borderRight: '1px solid var(--border-dark)',
      }} className="login-left-column">
        {/* Subtle Geometric Linework Background */}
        <svg 
          style={{
            position: 'absolute',
            right: '-40px',
            bottom: '10%',
            width: '420px',
            height: '420px',
            opacity: 0.08,
            pointerEvents: 'none',
          }}
          viewBox="0 0 200 200" 
          fill="none" 
          xmlns="http://www.w3.org/2000/svg"
        >
          <circle cx="100" cy="100" r="90" stroke="#D99A67" strokeWidth="1.5" strokeDasharray="4 4" />
          <circle cx="100" cy="100" r="60" stroke="#FFFFFF" strokeWidth="1.2" />
          <polygon points="100,20 180,100 100,180 20,100" stroke="#D99A67" strokeWidth="1.2" />
          <line x1="20" y1="100" x2="180" y2="100" stroke="#FFFFFF" strokeWidth="1" />
          <line x1="100" y1="20" x2="100" y2="180" stroke="#FFFFFF" strokeWidth="1" />
        </svg>

        {/* Top Header & Brand Identity */}
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.875rem', marginBottom: '2.5rem' }}>
            <div style={{
              width: '42px',
              height: '42px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--graphite-elevated)',
              border: '1px solid var(--border-dark)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--copper)',
              boxShadow: 'var(--shadow-sm)',
            }}>
              <Shield size={22} strokeWidth={2.2} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ fontSize: '1.25rem', fontWeight: 700, letterSpacing: '-0.02em', color: '#FFFFFF' }}>
                  TrustVault
                </span>
                <span style={{
                  fontSize: '0.625rem',
                  fontWeight: 700,
                  color: 'var(--copper)',
                  border: '1px solid var(--copper-border)',
                  backgroundColor: 'var(--copper-light)',
                  padding: '0.125rem 0.375rem',
                  borderRadius: 'var(--radius-xs)',
                  letterSpacing: '0.06em',
                }}>
                  CONFIDENTIAL CORE
                </span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '1px' }}>
                Zero-Trust Document Security Platform
              </div>
            </div>
          </div>

          {/* Main Headline & Supporting Copy */}
          <div style={{ maxWidth: '520px', marginTop: '1.5rem' }}>
            <h1 style={{
              fontSize: '2.375rem',
              fontWeight: 700,
              lineHeight: 1.2,
              letterSpacing: '-0.03em',
              color: '#FFFFFF',
              marginBottom: '1rem',
            }}>
              Confidentiality is not optional.
            </h1>
            <p style={{
              fontSize: '0.9375rem',
              lineHeight: 1.6,
              color: '#D1CEC7',
              marginBottom: '2.5rem',
            }}>
              Engineered for organizations sharing sensitive agreements, financial audits, and intellectual property. 
              Access is evaluated server-side on every request, revokes in real-time, and is permanently accounted for.
            </p>
          </div>

          {/* 3 Core Architectural Highlights */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', maxWidth: '480px' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
              <div style={{
                width: '34px',
                height: '34px',
                borderRadius: 'var(--radius-xs)',
                backgroundColor: 'var(--graphite-elevated)',
                border: '1px solid var(--border-dark)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--copper)',
                flexShrink: 0,
                marginTop: '2px',
              }}>
                <Lock size={17} strokeWidth={2} />
              </div>
              <div>
                <div style={{ fontSize: '0.875rem', fontWeight: 600, color: '#FFFFFF' }}>
                  Server-Side Zero-Trust Enforcement
                </div>
                <div style={{ fontSize: '0.8125rem', color: '#9E9C96', lineHeight: 1.45, marginTop: '2px' }}>
                  No static or pre-signed links. Permissions are evaluated in the active database transaction; unauthorized requests return uniform 404 to mask file existence.
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
              <div style={{
                width: '34px',
                height: '34px',
                borderRadius: 'var(--radius-xs)',
                backgroundColor: 'var(--graphite-elevated)',
                border: '1px solid var(--border-dark)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--copper)',
                flexShrink: 0,
                marginTop: '2px',
              }}>
                <KeyRound size={17} strokeWidth={2} />
              </div>
              <div>
                <div style={{ fontSize: '0.875rem', fontWeight: 600, color: '#FFFFFF' }}>
                  Instant Access Revocation
                </div>
                <div style={{ fontSize: '0.8125rem', color: '#9E9C96', lineHeight: 1.45, marginTop: '2px' }}>
                  Taking access away takes effect immediately. Download and preview streams are verified live, cutting off subsequent requests without delay.
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
              <div style={{
                width: '34px',
                height: '34px',
                borderRadius: 'var(--radius-xs)',
                backgroundColor: 'var(--graphite-elevated)',
                border: '1px solid var(--border-dark)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--copper)',
                flexShrink: 0,
                marginTop: '2px',
              }}>
                <History size={17} strokeWidth={2} />
              </div>
              <div>
                <div style={{ fontSize: '0.875rem', fontWeight: 600, color: '#FFFFFF' }}>
                  Tamper-Evident SHA-256 Audit Ledger
                </div>
                <div style={{ fontSize: '0.8125rem', color: '#9E9C96', lineHeight: 1.45, marginTop: '2px' }}>
                  Every upload, download, grant, and refused attempt is cryptographically linked with canonical JSON hashing to detect alteration or deletion.
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Left Column Restrained Footer */}
        <div style={{
          marginTop: '3rem',
          paddingTop: '1.5rem',
          borderTop: '1px solid var(--border-dark)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          fontSize: '0.75rem',
          color: 'var(--text-muted)',
          letterSpacing: '0.03em',
        }}>
          <span>TRUSTVAULT ENTERPRISE DOCUMENT PLATFORM</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
            <span className="pulse-dot" style={{ backgroundColor: 'var(--copper)', width: '6px', height: '6px' }}></span>
            <span>SYSTEM ACTIVE</span>
          </span>
        </div>
      </div>

      {/* ================= RIGHT COLUMN: AUTHENTICATION WORKSPACE ================= */}
      <div style={{
        flex: '1',
        minWidth: '320px',
        backgroundColor: 'var(--bg-warm)',
        padding: '3rem 2.5rem',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
      }}>
        <div style={{
          width: '100%',
          maxWidth: '430px',
        }}>
          {/* Form Header */}
          <div style={{ marginBottom: '1.75rem' }}>
            <div style={{
              fontSize: '0.75rem',
              fontWeight: 600,
              textTransform: 'uppercase',
              color: 'var(--copper-dark)',
              letterSpacing: '0.06em',
              marginBottom: '0.25rem',
            }}>
              Confidential Access Gateway
            </div>
            <h2 style={{
              fontSize: '1.625rem',
              fontWeight: 700,
              color: 'var(--text-primary)',
              letterSpacing: '-0.02em',
              margin: '0 0 0.375rem',
            }}>
              {mode === 'signin' ? 'Sign in to TrustVault' : 'Create your account'}
            </h2>
            <p style={{
              fontSize: '0.875rem',
              color: 'var(--text-secondary)',
              margin: 0,
            }}>
              {mode === 'signin' 
                ? "Access your organization's confidential workspace." 
                : 'Register a secure confidential document identity.'}
            </p>
          </div>

          {/* Mode Switcher Segmented Control */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '4px',
            backgroundColor: '#EBE6E0',
            padding: '4px',
            borderRadius: 'var(--radius-sm)',
            marginBottom: '1.5rem',
            border: '1px solid var(--border)',
          }}>
            <button
              type="button"
              onClick={() => { setMode('signin'); setError(null); }}
              style={{
                padding: '0.5rem',
                fontSize: '0.8125rem',
                fontWeight: mode === 'signin' ? 600 : 500,
                color: mode === 'signin' ? 'var(--text-primary)' : 'var(--text-secondary)',
                backgroundColor: mode === 'signin' ? 'var(--bg-surface)' : 'transparent',
                border: mode === 'signin' ? '1px solid var(--border)' : 'none',
                borderRadius: 'var(--radius-xs)',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.375rem',
                boxShadow: mode === 'signin' ? 'var(--shadow-sm)' : 'none',
                transition: 'all 0.15s ease',
              }}
            >
              <LogIn size={14} color={mode === 'signin' ? 'var(--copper-dark)' : 'currentColor'} />
              <span>Sign In</span>
            </button>

            <button
              type="button"
              onClick={() => { setMode('register'); setError(null); }}
              style={{
                padding: '0.5rem',
                fontSize: '0.8125rem',
                fontWeight: mode === 'register' ? 600 : 500,
                color: mode === 'register' ? 'var(--text-primary)' : 'var(--text-secondary)',
                backgroundColor: mode === 'register' ? 'var(--bg-surface)' : 'transparent',
                border: mode === 'register' ? '1px solid var(--border)' : 'none',
                borderRadius: 'var(--radius-xs)',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.375rem',
                boxShadow: mode === 'register' ? 'var(--shadow-sm)' : 'none',
                transition: 'all 0.15s ease',
              }}
            >
              <UserPlus size={14} color={mode === 'register' ? 'var(--copper-dark)' : 'currentColor'} />
              <span>Create Account</span>
            </button>
          </div>

          {/* Session Expiration Notice */}
          {isExpired && (
            <div style={{
              backgroundColor: 'var(--warning-bg)',
              color: 'var(--warning)',
              border: '1px solid var(--warning-border)',
              padding: '0.75rem 1rem',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.8125rem',
              marginBottom: '1.25rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
            }}>
              <AlertCircle size={16} />
              <span>Your session has expired. Please sign in again.</span>
            </div>
          )}

          {/* Error Banner */}
          {error && (
            <div style={{
              backgroundColor: 'var(--danger-bg)',
              color: 'var(--danger)',
              border: '1px solid var(--danger-border)',
              padding: '0.75rem 1rem',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.8125rem',
              marginBottom: '1.25rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
            }}>
              <ShieldAlert size={16} />
              <span>{error}</span>
            </div>
          )}

          {/* Main Card */}
          <div style={{
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-lg)',
            padding: '1.75rem',
            boxShadow: 'var(--shadow-sm)',
          }}>
            {mode === 'signin' ? (
              /* ================= SIGN IN FORM ================= */
              <form onSubmit={handleLoginSubmit}>
                <div className="form-group">
                  <label className="form-label" htmlFor="email">Work Email</label>
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

                <div className="form-group" style={{ marginBottom: '1.5rem' }}>
                  <label className="form-label" htmlFor="password">Password</label>
                  <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                    <input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      className="input-field"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••••••"
                      required
                      style={{ paddingRight: '2.5rem' }}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      style={{
                        position: 'absolute',
                        right: '0.75rem',
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-muted)',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        padding: '0.25rem',
                      }}
                      title={showPassword ? 'Hide password' : 'Show password'}
                      aria-label="Toggle password visibility"
                    >
                      {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  </div>
                </div>

                <button
                  type="submit"
                  className="btn btn-primary"
                  style={{
                    width: '100%',
                    padding: '0.6875rem',
                    fontSize: '0.875rem',
                    fontWeight: 600,
                  }}
                  disabled={isSubmitting}
                >
                  {isSubmitting ? (
                    <span>Authenticating session...</span>
                  ) : (
                    <>
                      <Lock size={15} />
                      <span>Sign in to TrustVault</span>
                    </>
                  )}
                </button>
              </form>
            ) : (
              /* ================= REGISTER FORM ================= */
              <form onSubmit={handleRegisterSubmit}>
                <div className="form-group">
                  <label className="form-label" htmlFor="regName">Full Name</label>
                  <input
                    id="regName"
                    type="text"
                    className="input-field"
                    value={regName}
                    onChange={(e) => setRegName(e.target.value)}
                    placeholder="Sarah Connor"
                    required
                    autoFocus
                  />
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="regEmail">Work Email</label>
                  <input
                    id="regEmail"
                    type="email"
                    className="input-field"
                    value={regEmail}
                    onChange={(e) => setRegEmail(e.target.value)}
                    placeholder="sarah@organization.com"
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="regPassword">Password</label>
                  <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                    <input
                      id="regPassword"
                      type={showRegPassword ? 'text' : 'password'}
                      className="input-field"
                      value={regPassword}
                      onChange={(e) => setRegPassword(e.target.value)}
                      placeholder="At least 8 characters"
                      required
                      minLength={8}
                      style={{ paddingRight: '2.5rem' }}
                    />
                    <button
                      type="button"
                      onClick={() => setShowRegPassword(!showRegPassword)}
                      style={{
                        position: 'absolute',
                        right: '0.75rem',
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-muted)',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        padding: '0.25rem',
                      }}
                      title={showRegPassword ? 'Hide password' : 'Show password'}
                      aria-label="Toggle password visibility"
                    >
                      {showRegPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  </div>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem', display: 'block' }}>
                    Hashed with Argon2id memory-hard algorithm.
                  </span>
                </div>

                <div className="form-group" style={{ marginBottom: '1.5rem' }}>
                  <label className="form-label">Initial Workspace Scope</label>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginTop: '0.25rem' }}>
                    <label style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      padding: '0.5rem 0.75rem',
                      border: `1px solid ${regRole === 'owner' ? 'var(--copper)' : 'var(--border)'}`,
                      backgroundColor: regRole === 'owner' ? 'var(--copper-light)' : 'var(--bg-surface)',
                      borderRadius: 'var(--radius-sm)',
                      cursor: 'pointer',
                      fontSize: '0.8125rem',
                      fontWeight: regRole === 'owner' ? 600 : 500,
                      color: regRole === 'owner' ? 'var(--copper-dark)' : 'var(--text-primary)',
                      transition: 'all 0.15s ease',
                    }}>
                      <input
                        type="radio"
                        name="role"
                        value="owner"
                        checked={regRole === 'owner'}
                        onChange={() => setRegRole('owner')}
                        style={{ accentColor: 'var(--copper-dark)' }}
                      />
                      <span>Document Owner</span>
                    </label>

                    <label style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      padding: '0.5rem 0.75rem',
                      border: `1px solid ${regRole === 'viewer' ? 'var(--copper)' : 'var(--border)'}`,
                      backgroundColor: regRole === 'viewer' ? 'var(--copper-light)' : 'var(--bg-surface)',
                      borderRadius: 'var(--radius-sm)',
                      cursor: 'pointer',
                      fontSize: '0.8125rem',
                      fontWeight: regRole === 'viewer' ? 600 : 500,
                      color: regRole === 'viewer' ? 'var(--copper-dark)' : 'var(--text-primary)',
                      transition: 'all 0.15s ease',
                    }}>
                      <input
                        type="radio"
                        name="role"
                        value="viewer"
                        checked={regRole === 'viewer'}
                        onChange={() => setRegRole('viewer')}
                        style={{ accentColor: 'var(--copper-dark)' }}
                      />
                      <span>Restricted Viewer</span>
                    </label>
                  </div>
                </div>

                <button
                  type="submit"
                  className="btn btn-primary"
                  style={{
                    width: '100%',
                    padding: '0.6875rem',
                    fontSize: '0.875rem',
                    fontWeight: 600,
                  }}
                  disabled={isSubmitting}
                >
                  {isSubmitting ? (
                    <span>Registering identity...</span>
                  ) : (
                    <>
                      <UserPlus size={15} />
                      <span>Register &amp; Enter Workspace</span>
                    </>
                  )}
                </button>
              </form>
            )}

            {/* Subtle Security Assurance Statement */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              marginTop: '1.25rem',
              paddingTop: '1rem',
              borderTop: '1px solid var(--border-subtle)',
              fontSize: '0.75rem',
              color: 'var(--text-muted)',
              lineHeight: 1.4,
            }}>
              <FileCheck2 size={15} color="var(--copper-dark)" style={{ flexShrink: 0 }} />
              <span>
                Protected by server-side zero-trust authorization. Role parameters and permissions are verified in the database transaction.
              </span>
            </div>
          </div>

          {/* ================= EVALUATOR DEMO ACCESS (COLLAPSIBLE) ================= */}
          <div style={{
            marginTop: '1.25rem',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-md)',
            backgroundColor: 'var(--bg-surface)',
            overflow: 'hidden',
            boxShadow: 'var(--shadow-sm)',
          }}>
            <button
              type="button"
              onClick={() => setIsDemoOpen(!isDemoOpen)}
              style={{
                width: '100%',
                padding: '0.75rem 1rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                backgroundColor: 'var(--bg-surface-secondary)',
                borderBottom: isDemoOpen ? '1px solid var(--border)' : 'none',
                cursor: 'pointer',
                textAlign: 'left',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <UserCheck size={16} color="var(--copper-dark)" />
                <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Evaluator demo access
                </span>
                <span style={{
                  fontSize: '0.65rem',
                  fontWeight: 600,
                  backgroundColor: 'var(--bg-surface-tertiary)',
                  color: 'var(--text-secondary)',
                  padding: '0.1rem 0.4rem',
                  borderRadius: 'var(--radius-xs)',
                  textTransform: 'uppercase',
                }}>
                  Pre-seeded
                </span>
              </div>
              <div style={{ color: 'var(--text-muted)' }}>
                {isDemoOpen ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
              </div>
            </button>

            {isDemoOpen && (
              <div style={{ padding: '0.875rem' }}>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
                  Select an evaluation persona to populate credentials and test role boundaries:
                </p>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {/* Persona 1: Alice Owner A */}
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    style={{
                      justifyContent: 'space-between',
                      width: '100%',
                      padding: '0.5rem 0.75rem',
                      textAlign: 'left',
                    }}
                    onClick={() => handleSelectDemoUser('owner_a@trustvault.com', 'OwnerAPass123!')}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.8125rem' }}>Alice (Document Owner A)</div>
                      <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>owner_a@trustvault.com</div>
                    </div>
                    <span className="badge badge-green">Owner</span>
                  </button>

                  {/* Persona 2: Bob Owner B */}
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    style={{
                      justifyContent: 'space-between',
                      width: '100%',
                      padding: '0.5rem 0.75rem',
                      textAlign: 'left',
                    }}
                    onClick={() => handleSelectDemoUser('owner_b@trustvault.com', 'OwnerBPass123!')}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.8125rem' }}>Bob (Document Owner B)</div>
                      <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>owner_b@trustvault.com</div>
                    </div>
                    <span className="badge badge-green">Owner</span>
                  </button>

                  {/* Persona 3: Carol Viewer */}
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    style={{
                      justifyContent: 'space-between',
                      width: '100%',
                      padding: '0.5rem 0.75rem',
                      textAlign: 'left',
                    }}
                    onClick={() => handleSelectDemoUser('viewer_a@trustvault.com', 'ViewerAPass123!')}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.8125rem' }}>Carol (Restricted Viewer)</div>
                      <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>viewer_a@trustvault.com</div>
                    </div>
                    <span className="badge badge-gray">Viewer</span>
                  </button>

                  {/* Persona 4: Admin */}
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    style={{
                      justifyContent: 'space-between',
                      width: '100%',
                      padding: '0.5rem 0.75rem',
                      textAlign: 'left',
                    }}
                    onClick={() => handleSelectDemoUser('admin@trustvault.com', 'AdminPass123!')}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.8125rem' }}>Security Administrator</div>
                      <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>admin@trustvault.com</div>
                    </div>
                    <span className="badge badge-copper">Admin</span>
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Right Column Footer Links */}
          <div style={{
            marginTop: '1.5rem',
            textAlign: 'center',
            fontSize: '0.75rem',
            color: 'var(--text-muted)',
            display: 'flex',
            justifyContent: 'center',
            gap: '1.25rem',
          }}>
            <Link to="/privacy" style={{ color: 'var(--text-secondary)', textDecoration: 'none' }} className="hover:underline">
              Privacy Policy
            </Link>
            <span>&bull;</span>
            <Link to="/terms" style={{ color: 'var(--text-secondary)', textDecoration: 'none' }} className="hover:underline">
              Terms of Service
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};
