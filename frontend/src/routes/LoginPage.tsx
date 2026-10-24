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
  const [isDemoOpen, setIsDemoOpen] = useState(false);

  const { login, register } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const isExpired = searchParams.get('expired') === 'true';

  const redirectUrl = searchParams.get('redirect') || '/documents';

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      await login(email, password);
      toast.success('Signed in successfully.');
      navigate(redirectUrl);
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
      navigate(redirectUrl);
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
    <div className="login-container">
      {/* ================= LEFT COLUMN: GRAPHITE BRAND & VALUE PROP (~55%) ================= */}
      <div className="login-left-pane">
        {/* Subtle, Custom Security-Inspired Geometric Pattern */}
        <svg 
          style={{
            position: 'absolute',
            inset: 0,
            width: '100%',
            height: '100%',
            opacity: 0.08,
            pointerEvents: 'none',
            overflow: 'hidden',
          }}
          viewBox="0 0 800 800"
          preserveAspectRatio="xMidYMid slice"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <pattern id="securityGrid" width="48" height="48" patternUnits="userSpaceOnUse">
              <path d="M 48 0 L 0 0 0 48" fill="none" stroke="#FFFFFF" strokeWidth="0.6" strokeOpacity="0.4" />
              <circle cx="48" cy="48" r="1.5" fill="#D99A67" fillOpacity="0.6" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#securityGrid)" />
          {/* Concentric Security Perimeter Radii */}
          <circle cx="560" cy="400" r="180" stroke="#D99A67" strokeWidth="1.2" strokeDasharray="6 6" fill="none" />
          <circle cx="560" cy="400" r="280" stroke="#FFFFFF" strokeWidth="1" strokeOpacity="0.3" fill="none" />
          <circle cx="560" cy="400" r="400" stroke="#D99A67" strokeWidth="1.2" strokeDasharray="12 8" fill="none" />
          {/* Cryptographic Node Lattice Lines */}
          <line x1="80" y1="160" x2="560" y2="400" stroke="#FFFFFF" strokeWidth="0.8" strokeOpacity="0.25" />
          <line x1="160" y1="640" x2="560" y2="400" stroke="#FFFFFF" strokeWidth="0.8" strokeOpacity="0.25" />
          <line x1="560" y1="400" x2="760" y2="120" stroke="#D99A67" strokeWidth="1" strokeOpacity="0.35" />
          <polygon points="560,340 620,400 560,460 500,400" stroke="#D99A67" strokeWidth="1" fill="none" strokeOpacity="0.4" />
        </svg>

          {/* Top Header & Brand Identity */}
        <div style={{ position: 'relative', zIndex: 1 }}>
          <div className="login-brand-header" style={{ display: 'flex', alignItems: 'center', gap: '0.875rem', marginBottom: '2.5rem' }}>
            <div style={{
              width: '42px',
              height: '42px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--graphite-elevated)',
              border: '1px solid rgba(217, 154, 103, 0.35)',
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
                  padding: '0.125rem 0.4rem',
                  borderRadius: 'var(--radius-xs)',
                  letterSpacing: '0.08em',
                  textTransform: 'uppercase',
                }}>
                  CONFIDENTIAL CORE
                </span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '1px' }}>
                Enterprise Document Security &amp; Access Control
              </div>
            </div>
          </div>

          {/* Main Headline & Supporting Copy */}
          <div style={{ maxWidth: '520px', marginTop: '1rem' }}>
            <h1 className="login-left-headline">
              Confidentiality is not optional.
            </h1>
            <p className="login-left-subtext" style={{
              fontSize: '0.9375rem',
              lineHeight: 1.6,
              color: '#D1CEC7',
              marginBottom: '2.5rem',
            }}>
              Purpose-built for organizations sharing sensitive agreements, financial disclosures, and intellectual property. 
              Access is evaluated server-side on every request, revokes in real-time, and is permanently accounted for.
            </p>
          </div>

          {/* Two Compact Feature Highlights: Document Access Control and Audit Visibility */}
          <div className="login-features-list" style={{ display: 'flex', flexDirection: 'column', gap: '1.375rem', maxWidth: '480px' }}>
            {/* Feature 1: Document Access Control */}
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
              <div style={{
                width: '36px',
                height: '36px',
                borderRadius: 'var(--radius-xs)',
                backgroundColor: 'var(--graphite-elevated)',
                border: '1px solid var(--border-dark)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--copper)',
                flexShrink: 0,
                marginTop: '1px',
              }}>
                <Lock size={17} strokeWidth={2} />
              </div>
              <div>
                <div style={{ fontSize: '0.875rem', fontWeight: 600, color: '#FFFFFF', marginBottom: '2px' }}>
                  Document Access Control
                </div>
                <div style={{ fontSize: '0.8125rem', color: '#9E9C96', lineHeight: 1.5 }}>
                  Granular read and edit permissions granted strictly to verified identities. Immediate revocation stops subsequent downloads and streams without delay.
                </div>
              </div>
            </div>

            {/* Feature 2: Audit Visibility */}
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
              <div style={{
                width: '36px',
                height: '36px',
                borderRadius: 'var(--radius-xs)',
                backgroundColor: 'var(--graphite-elevated)',
                border: '1px solid var(--border-dark)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--copper)',
                flexShrink: 0,
                marginTop: '1px',
              }}>
                <History size={17} strokeWidth={2} />
              </div>
              <div>
                <div style={{ fontSize: '0.875rem', fontWeight: 600, color: '#FFFFFF', marginBottom: '2px' }}>
                  Audit Visibility
                </div>
                <div style={{ fontSize: '0.8125rem', color: '#9E9C96', lineHeight: 1.5 }}>
                  A tamper-evident SHA-256 cryptographic hash chain records every download, edit, and denied attempt, providing incontrovertible proof of who accessed what.
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Left Column Restrained Footer */}
        <div className="login-left-footer" style={{
          position: 'relative',
          zIndex: 1,
          marginTop: '3.5rem',
          paddingTop: '1.5rem',
          borderTop: '1px solid var(--border-dark)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.75rem',
          fontSize: '0.75rem',
          color: 'var(--text-muted)',
          letterSpacing: '0.04em',
        }}>
          <span>TRUSTVAULT DOCUMENT SECURITY PLATFORM</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <span className="pulse-dot" style={{ backgroundColor: 'var(--copper)', width: '6px', height: '6px' }}></span>
            <span style={{ color: '#D1CEC7' }}>SYSTEM ACTIVE</span>
          </span>
        </div>
      </div>

      {/* ================= RIGHT COLUMN: AUTHENTICATION WORKSPACE (~45%) ================= */}
      <div className="login-right-pane">
        <div className="login-form-wrapper">
          {/* Header Typography */}
          <div style={{ marginBottom: '1.75rem' }}>
            <div style={{
              fontSize: '0.7rem',
              fontWeight: 700,
              textTransform: 'uppercase',
              color: 'var(--copper-dark)',
              letterSpacing: '0.08em',
              marginBottom: '0.375rem',
            }}>
              Confidential Access Gateway
            </div>
            <h2 style={{
              fontSize: '1.625rem',
              fontWeight: 700,
              color: 'var(--text-primary)',
              letterSpacing: '-0.025em',
              margin: '0 0 0.375rem',
            }}>
              {mode === 'signin' ? 'Sign in to TrustVault' : 'Create an account'}
            </h2>
            <p style={{
              fontSize: '0.875rem',
              color: 'var(--text-secondary)',
              margin: 0,
              lineHeight: 1.45,
            }}>
              {mode === 'signin' 
                ? "Access your organization's confidential workspace." 
                : 'Register your identity for protected document management.'}
            </p>
          </div>

          {/* Mode Switcher Segmented Control */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)',
            gap: '3px',
            backgroundColor: '#EBE6E0',
            padding: '3px',
            borderRadius: 'var(--radius-sm)',
            marginBottom: '1.5rem',
            border: '1px solid var(--border)',
          }}>
            <button
              type="button"
              className="login-mode-btn"
              onClick={() => { setMode('signin'); setError(null); }}
              style={{
                fontWeight: mode === 'signin' ? 600 : 500,
                color: mode === 'signin' ? 'var(--text-primary)' : 'var(--text-secondary)',
                backgroundColor: mode === 'signin' ? 'var(--bg-surface)' : 'transparent',
                border: mode === 'signin' ? '1px solid var(--border)' : '1px solid transparent',
                boxShadow: mode === 'signin' ? 'var(--shadow-sm)' : 'none',
              }}
            >
              <LogIn size={13} color={mode === 'signin' ? 'var(--copper-dark)' : 'currentColor'} />
              <span>Sign In</span>
            </button>

            <button
              type="button"
              className="login-mode-btn"
              onClick={() => { setMode('register'); setError(null); }}
              style={{
                fontWeight: mode === 'register' ? 600 : 500,
                color: mode === 'register' ? 'var(--text-primary)' : 'var(--text-secondary)',
                backgroundColor: mode === 'register' ? 'var(--bg-surface)' : 'transparent',
                border: mode === 'register' ? '1px solid var(--border)' : '1px solid transparent',
                boxShadow: mode === 'register' ? 'var(--shadow-sm)' : 'none',
              }}
            >
              <UserPlus size={13} color={mode === 'register' ? 'var(--copper-dark)' : 'currentColor'} />
              <span>Create Account</span>
            </button>
          </div>

          {/* Session Expiration Notice */}
          {isExpired && (
            <div style={{
              backgroundColor: 'var(--warning-bg)',
              color: 'var(--warning)',
              border: '1px solid var(--warning-border)',
              padding: '0.75rem 0.875rem',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.8125rem',
              marginBottom: '1.25rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
            }}>
              <AlertCircle size={16} style={{ flexShrink: 0 }} />
              <span>Your session has expired. Please sign in again.</span>
            </div>
          )}

          {/* Error Banner */}
          {error && (
            <div style={{
              backgroundColor: 'var(--danger-bg)',
              color: 'var(--danger)',
              border: '1px solid var(--danger-border)',
              padding: '0.75rem 0.875rem',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.8125rem',
              marginBottom: '1.25rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
            }}>
              <ShieldAlert size={16} style={{ flexShrink: 0 }} />
              <span>{error}</span>
            </div>
          )}

          {/* Direct, Uncluttered Form (No oversized card boundary) */}
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {mode === 'signin' ? (
              /* ================= SIGN IN FORM ================= */
              <form onSubmit={handleLoginSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.125rem' }}>
                <div className="form-group" style={{ margin: 0 }}>
                  <label 
                    htmlFor="email" 
                    style={{ 
                      display: 'block', 
                      fontSize: '0.8125rem', 
                      fontWeight: 600, 
                      color: 'var(--text-primary)', 
                      marginBottom: '0.375rem' 
                    }}
                  >
                    Work Email
                  </label>
                  <input
                    id="email"
                    type="email"
                    className="input-field"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="name@organization.com"
                    required
                    style={{
                      height: '40px',
                      backgroundColor: '#FFFFFF',
                      borderColor: 'var(--border)',
                    }}
                  />
                </div>

                <div className="form-group" style={{ margin: 0 }}>
                  <label 
                    htmlFor="password" 
                    style={{ 
                      display: 'block', 
                      fontSize: '0.8125rem', 
                      fontWeight: 600, 
                      color: 'var(--text-primary)', 
                      marginBottom: '0.375rem' 
                    }}
                  >
                    Password
                  </label>
                  <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                    <input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      className="input-field"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••••••"
                      required
                      style={{
                        height: '40px',
                        paddingRight: '2.5rem',
                        backgroundColor: '#FFFFFF',
                        borderColor: 'var(--border)',
                      }}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      style={{
                        position: 'absolute',
                        right: '0.625rem',
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
                  className="btn-login-submit"
                  disabled={isSubmitting}
                  style={{ marginTop: '0.5rem' }}
                >
                  {isSubmitting ? (
                    <span>Authenticating credentials...</span>
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
              <form onSubmit={handleRegisterSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.125rem' }}>
                <div className="form-group" style={{ margin: 0 }}>
                  <label 
                    htmlFor="regName" 
                    style={{ 
                      display: 'block', 
                      fontSize: '0.8125rem', 
                      fontWeight: 600, 
                      color: 'var(--text-primary)', 
                      marginBottom: '0.375rem' 
                    }}
                  >
                    Full Name
                  </label>
                  <input
                    id="regName"
                    type="text"
                    className="input-field"
                    value={regName}
                    onChange={(e) => setRegName(e.target.value)}
                    placeholder="Sarah Connor"
                    required
                    style={{
                      height: '40px',
                      backgroundColor: '#FFFFFF',
                      borderColor: 'var(--border)',
                    }}
                  />
                </div>

                <div className="form-group" style={{ margin: 0 }}>
                  <label 
                    htmlFor="regEmail" 
                    style={{ 
                      display: 'block', 
                      fontSize: '0.8125rem', 
                      fontWeight: 600, 
                      color: 'var(--text-primary)', 
                      marginBottom: '0.375rem' 
                    }}
                  >
                    Work Email
                  </label>
                  <input
                    id="regEmail"
                    type="email"
                    className="input-field"
                    value={regEmail}
                    onChange={(e) => setRegEmail(e.target.value)}
                    placeholder="sarah@organization.com"
                    required
                    style={{
                      height: '40px',
                      backgroundColor: '#FFFFFF',
                      borderColor: 'var(--border)',
                    }}
                  />
                </div>

                <div className="form-group" style={{ margin: 0 }}>
                  <label 
                    htmlFor="regPassword" 
                    style={{ 
                      display: 'block', 
                      fontSize: '0.8125rem', 
                      fontWeight: 600, 
                      color: 'var(--text-primary)', 
                      marginBottom: '0.375rem' 
                    }}
                  >
                    Password
                  </label>
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
                      style={{
                        height: '40px',
                        paddingRight: '2.5rem',
                        backgroundColor: '#FFFFFF',
                        borderColor: 'var(--border)',
                      }}
                    />
                    <button
                      type="button"
                      onClick={() => setShowRegPassword(!showRegPassword)}
                      style={{
                        position: 'absolute',
                        right: '0.625rem',
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
                </div>

                <div className="form-group" style={{ margin: 0 }}>
                  <label 
                    style={{ 
                      display: 'block', 
                      fontSize: '0.8125rem', 
                      fontWeight: 600, 
                      color: 'var(--text-primary)', 
                      marginBottom: '0.375rem' 
                    }}
                  >
                    Initial Workspace Role
                  </label>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                    <label style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      padding: '0.5rem 0.75rem',
                      border: `1px solid ${regRole === 'owner' ? 'var(--copper)' : 'var(--border)'}`,
                      backgroundColor: regRole === 'owner' ? 'var(--copper-light)' : '#FFFFFF',
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
                      backgroundColor: regRole === 'viewer' ? 'var(--copper-light)' : '#FFFFFF',
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
                  className="btn-login-submit"
                  disabled={isSubmitting}
                  style={{ marginTop: '0.5rem' }}
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

            {/* Subtle Security Assurance Statement (Without unsupported claims) */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              marginTop: '1.25rem',
              fontSize: '0.75rem',
              color: 'var(--text-secondary)',
              lineHeight: 1.4,
            }}>
              <FileCheck2 size={15} color="var(--copper-dark)" style={{ flexShrink: 0 }} />
              <span>
                Protected by server-side zero-trust authorization. Role parameters and permissions are evaluated live in the active database transaction.
              </span>
            </div>
          </div>

          {/* ================= EVALUATOR DEMO ACCESS (COMPACT COLLAPSIBLE) ================= */}
          <div style={{
            marginTop: '1.5rem',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: '#FFFFFF',
            overflow: 'hidden',
            boxShadow: 'var(--shadow-sm)',
          }}>
            <button
              type="button"
              onClick={() => setIsDemoOpen(!isDemoOpen)}
              style={{
                width: '100%',
                padding: '0.625rem 0.875rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                backgroundColor: 'var(--bg-surface-secondary)',
                borderBottom: isDemoOpen ? '1px solid var(--border)' : 'none',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'background-color 0.15s ease',
              }}
              aria-expanded={isDemoOpen}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <UserCheck size={15} color="var(--copper-dark)" />
                <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Evaluator demo access
                </span>
                <span style={{
                  fontSize: '0.625rem',
                  fontWeight: 600,
                  backgroundColor: 'var(--bg-surface-tertiary)',
                  color: 'var(--text-secondary)',
                  padding: '0.1rem 0.35rem',
                  borderRadius: 'var(--radius-xs)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.04em',
                }}>
                  Pre-seeded
                </span>
              </div>
              <div style={{ color: 'var(--text-muted)' }}>
                {isDemoOpen ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
              </div>
            </button>

            {isDemoOpen && (
              <div style={{ padding: '0.75rem 0.875rem' }}>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '0.625rem', lineHeight: 1.4 }}>
                  Select an evaluation persona to populate credentials and test role boundaries:
                </p>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                  {/* Persona 1: Alice Owner A */}
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    style={{
                      justifyContent: 'space-between',
                      width: '100%',
                      padding: '0.45rem 0.625rem',
                      textAlign: 'left',
                      borderColor: 'var(--border)',
                    }}
                    onClick={() => handleSelectDemoUser('owner_a@trustvault.com', 'OwnerAPass123!')}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.8125rem' }}>Alice (Document Owner A)</div>
                      <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>owner_a@trustvault.com</div>
                    </div>
                    <span className="badge badge-green" style={{ fontSize: '0.7rem' }}>Owner</span>
                  </button>

                  {/* Persona 2: Bob Owner B */}
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    style={{
                      justifyContent: 'space-between',
                      width: '100%',
                      padding: '0.45rem 0.625rem',
                      textAlign: 'left',
                      borderColor: 'var(--border)',
                    }}
                    onClick={() => handleSelectDemoUser('owner_b@trustvault.com', 'OwnerBPass123!')}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.8125rem' }}>Bob (Document Owner B)</div>
                      <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>owner_b@trustvault.com</div>
                    </div>
                    <span className="badge badge-green" style={{ fontSize: '0.7rem' }}>Owner</span>
                  </button>

                  {/* Persona 3: Carol Viewer */}
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    style={{
                      justifyContent: 'space-between',
                      width: '100%',
                      padding: '0.45rem 0.625rem',
                      textAlign: 'left',
                      borderColor: 'var(--border)',
                    }}
                    onClick={() => handleSelectDemoUser('viewer_a@trustvault.com', 'ViewerAPass123!')}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.8125rem' }}>Carol (Restricted Viewer)</div>
                      <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>viewer_a@trustvault.com</div>
                    </div>
                    <span className="badge badge-gray" style={{ fontSize: '0.7rem' }}>Viewer</span>
                  </button>

                  {/* Persona 4: Admin */}
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    style={{
                      justifyContent: 'space-between',
                      width: '100%',
                      padding: '0.45rem 0.625rem',
                      textAlign: 'left',
                      borderColor: 'var(--border)',
                    }}
                    onClick={() => handleSelectDemoUser('admin@trustvault.com', 'AdminPass123!')}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.8125rem' }}>Security Administrator</div>
                      <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>admin@trustvault.com</div>
                    </div>
                    <span className="badge badge-copper" style={{ fontSize: '0.7rem' }}>Admin</span>
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Right Column Footer Links */}
          <div style={{
            marginTop: '1.75rem',
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
