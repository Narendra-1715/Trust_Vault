import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../features/auth/AuthContext';
import { Shield, Key, FileCheck, History, Sparkles, ArrowRight, Eye, CheckCircle2 } from 'lucide-react';

export const LandingPage: React.FC = () => {
  const { isAuthenticated } = useAuth();

  return (
    <div style={{
      background: 'radial-gradient(ellipse 80% 50% at 50% 0%, rgba(37, 99, 235, 0.08), transparent 70%)',
      minHeight: '100%',
      paddingBottom: '5rem'
    }}>
      <div className="container" style={{ paddingTop: '2rem' }}>
        {/* Hero Section */}
        <section style={{ maxWidth: '860px', margin: '0 auto', textAlign: 'center', padding: '3.5rem 0 4rem' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.625rem',
            padding: '0.35rem 0.875rem',
            backgroundColor: '#ffffff',
            color: '#1d4ed8',
            borderRadius: '20px',
            fontSize: '0.75rem',
            fontWeight: 700,
            marginBottom: '1.75rem',
            border: '1px solid #bfdbfe',
            boxShadow: '0 2px 8px rgba(37, 99, 235, 0.08)',
            letterSpacing: '0.04em',
            textTransform: 'uppercase'
          }}>
            <span className="pulse-dot" style={{ backgroundColor: '#2563eb' }}></span>
            <Shield size={14} />
            <span>Zero-Trust Document Management Platform</span>
          </div>

          <h1 style={{
            fontSize: '3.125rem',
            fontWeight: 800,
            lineHeight: 1.15,
            letterSpacing: '-0.035em',
            color: 'var(--text-main)',
            marginBottom: '1.375rem'
          }}>
            Confidential documents.{' '}
            <span style={{
              background: 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent'
            }}>
              Explicit access.
            </span>{' '}
            Verifiable activity.
          </h1>

          <p style={{
            fontSize: '1.1875rem',
            lineHeight: 1.65,
            color: 'var(--text-secondary)',
            marginBottom: '2.5rem',
            maxWidth: '720px',
            margin: '0 auto 2.5rem'
          }}>
            Store and share sensitive enterprise assets with cryptographic SHA-256 tamper-detection, in-browser forensic watermarking, and sub-millisecond access revocation.
          </p>

          <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem', flexWrap: 'wrap' }}>
            {isAuthenticated ? (
              <Link to="/documents" className="btn btn-primary" style={{ padding: '0.75rem 1.5rem', fontSize: '0.9375rem', boxShadow: '0 4px 12px rgba(15, 23, 42, 0.15)' }}>
                <span>Open Enterprise Workspace</span>
                <ArrowRight size={16} />
              </Link>
            ) : (
              <Link to="/login" className="btn btn-primary" style={{ padding: '0.75rem 1.5rem', fontSize: '0.9375rem', boxShadow: '0 4px 12px rgba(15, 23, 42, 0.15)' }}>
                <span>Sign in to TrustVault</span>
                <ArrowRight size={16} />
              </Link>
            )}

            <a href="#architecture" className="btn btn-secondary" style={{ padding: '0.75rem 1.5rem', fontSize: '0.9375rem' }}>
              <span>Explore Security Architecture</span>
            </a>
          </div>
        </section>

        {/* Real Interface Preview (Actual Document Vault Representation) */}
        <section style={{ marginBottom: '5.5rem' }}>
          <div className="panel" style={{
            padding: '1.25rem',
            backgroundColor: '#ffffff',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.06), 0 8px 10px -6px rgba(0, 0, 0, 0.04)',
            borderRadius: 'var(--radius-lg)'
          }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '0.75rem 1rem',
              borderBottom: '1px solid var(--border-main)',
              marginBottom: '0.75rem'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#f87171' }}></div>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#fbbf24' }}></div>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#34d399' }}></div>
                <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginLeft: '0.5rem', fontFamily: 'monospace' }}>
                  TrustVault Live Repository • Real Database State
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span className="badge badge-green" style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                  <CheckCircle2 size={12} />
                  <span>SHA-256 Ledger Intact</span>
                </span>
              </div>
            </div>

            <table className="data-table">
              <thead>
                <tr>
                  <th>Document Title</th>
                  <th>Category</th>
                  <th>Owner</th>
                  <th>Access Enforcement</th>
                  <th>Revocation Guarantee</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td style={{ fontWeight: 600 }}>Q3 Financial Audit &amp; Compliance Report</td>
                  <td><span className="badge badge-blue">Financial</span></td>
                  <td>Alice Owner</td>
                  <td><span className="badge badge-green">Explicit Read Grant</span></td>
                  <td style={{ color: 'var(--success)', fontSize: '0.8125rem', fontWeight: 500 }}>Immediate (evaluated on every request)</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>2026 Executive Strategic Roadmap</td>
                  <td><span className="badge badge-yellow">Executive</span></td>
                  <td>Alice Owner</td>
                  <td><span className="badge badge-gray">Owner Only (Isolated)</span></td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>Zero unauthorized access</td>
                </tr>
                <tr>
                  <td style={{ fontWeight: 600 }}>Internal Security Architecture Review</td>
                  <td><span className="badge badge-blue">Engineering</span></td>
                  <td>Bob Executive</td>
                  <td><span className="badge badge-gray">Owner Only (Isolated)</span></td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>Zero unauthorized access</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        {/* Security Architecture & Pillars */}
        <section id="architecture" style={{ maxWidth: '1060px', margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: '3.5rem' }}>
            <h2 style={{ fontSize: '2rem', fontWeight: 700, letterSpacing: '-0.02em', marginBottom: '0.75rem' }}>
              Built on Non-Negotiable Security Invariants
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '1.05rem', maxWidth: '600px', margin: '0 auto' }}>
              Every access decision is cryptographically verified against live database state.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(290px, 1fr))', gap: '1.5rem' }}>
            {/* Pillar 1 */}
            <div className="panel panel-hover">
              <div style={{
                width: '42px',
                height: '42px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--accent-light)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--accent)',
                marginBottom: '1.25rem'
              }}>
                <Key size={22} />
              </div>
              <h3 style={{ fontSize: '1.125rem', fontWeight: 600, marginBottom: '0.5rem' }}>
                Server-Side Authorization
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                The backend is the sole authority for access decisions. Document-level policies are evaluated per request. Admins do not silently bypass document confidentiality.
              </p>
            </div>

            {/* Pillar 2 */}
            <div className="panel panel-hover">
              <div style={{
                width: '42px',
                height: '42px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--success-bg)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--success)',
                marginBottom: '1.25rem'
              }}>
                <FileCheck size={22} />
              </div>
              <h3 style={{ fontSize: '1.125rem', fontWeight: 600, marginBottom: '0.5rem' }}>
                Immediate Revocation
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                When access is revoked by a document owner, the very next download or metadata read request fails immediately. No long-lived download URLs are ever issued.
              </p>
            </div>

            {/* Pillar 3 */}
            <div className="panel panel-hover">
              <div style={{
                width: '42px',
                height: '42px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: '#f1f5f9',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#0f172a',
                marginBottom: '1.25rem'
              }}>
                <History size={22} />
              </div>
              <h3 style={{ fontSize: '1.125rem', fontWeight: 600, marginBottom: '0.5rem' }}>
                Tamper-Evident Block Explorer
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                Every audit event is cryptographically linked with SHA-256 canonical hashing. Evaluators can explore interactive blocks to verify hash continuity in real time.
              </p>
            </div>

            {/* Pillar 4 */}
            <div className="panel panel-hover">
              <div style={{
                width: '42px',
                height: '42px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: '#faf5ff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#7e22ce',
                marginBottom: '1.25rem'
              }}>
                <Eye size={22} />
              </div>
              <h3 style={{ fontSize: '1.125rem', fontWeight: 600, marginBottom: '0.5rem' }}>
                Dynamic Forensic DLP Watermark
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                In-browser confidential previews apply an uncopyable dynamic forensic watermark containing user identity and timestamps to eliminate data leakage risks.
              </p>
            </div>

            {/* Pillar 5 */}
            <div className="panel panel-hover">
              <div style={{
                width: '42px',
                height: '42px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: '#fffbeb',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#d97706',
                marginBottom: '1.25rem'
              }}>
                <Sparkles size={22} />
              </div>
              <h3 style={{ fontSize: '1.125rem', fontWeight: 600, marginBottom: '0.5rem' }}>
                Human-in-the-Loop Gemini AI
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                AI models provide least-privilege suggestions based strictly on document metadata. AI cannot grant or modify permissions directly—explicit owner approval is required.
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};
