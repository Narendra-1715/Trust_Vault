import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../features/auth/AuthContext';
import { Shield, Key, FileCheck, History, Sparkles, ArrowRight, Eye, CheckCircle2 } from 'lucide-react';

export const LandingPage: React.FC = () => {
  const { isAuthenticated } = useAuth();

  return (
    <div style={{
      backgroundColor: 'var(--bg-warm)',
      minHeight: '100%',
      paddingBottom: '5rem',
    }}>
      <div className="container" style={{ paddingTop: '1.5rem' }}>
        {/* ================= HERO SECTION ================= */}
        <section style={{ maxWidth: '860px', margin: '0 auto', textAlign: 'center', padding: '3.5rem 0 3.5rem' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.35rem 0.875rem',
            backgroundColor: 'var(--bg-surface)',
            color: 'var(--copper-dark)',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.75rem',
            fontWeight: 700,
            marginBottom: '1.5rem',
            border: '1px solid var(--copper-border)',
            boxShadow: 'var(--shadow-sm)',
            letterSpacing: '0.06em',
            textTransform: 'uppercase',
          }}>
            <Shield size={14} color="var(--copper-dark)" />
            <span>Zero-Trust Enterprise Document Platform</span>
          </div>

          <h1 style={{
            fontSize: '3rem',
            fontWeight: 800,
            lineHeight: 1.15,
            letterSpacing: '-0.035em',
            color: 'var(--graphite)',
            marginBottom: '1.25rem',
          }}>
            Confidential documents.{' '}
            <span style={{ color: 'var(--copper-dark)' }}>
              Explicit access.
            </span>{' '}
            Verifiable activity.
          </h1>

          <p style={{
            fontSize: '1.125rem',
            lineHeight: 1.65,
            color: 'var(--text-secondary)',
            marginBottom: '2.25rem',
            maxWidth: '720px',
            margin: '0 auto 2.25rem',
          }}>
            Protect sensitive executive agreements, financial audits, and intellectual property. 
            Row-level authorization evaluated server-side, real-time revocation, and cryptographic SHA-256 tamper auditing.
          </p>

          <div style={{ display: 'flex', justifyContent: 'center', gap: '0.875rem', flexWrap: 'wrap' }}>
            {isAuthenticated ? (
              <Link to="/documents" className="btn btn-primary btn-lg" style={{ boxShadow: 'var(--shadow-md)' }}>
                <span>Open Enterprise Workspace</span>
                <ArrowRight size={16} color="var(--copper)" />
              </Link>
            ) : (
              <Link to="/login" className="btn btn-primary btn-lg" style={{ boxShadow: 'var(--shadow-md)' }}>
                <span>Sign in to TrustVault</span>
                <ArrowRight size={16} color="var(--copper)" />
              </Link>
            )}

            <a href="#architecture" className="btn btn-secondary btn-lg">
              <span>Security Architecture</span>
            </a>
          </div>
        </section>

        {/* ================= REPOSITORY INTERFACE PREVIEW ================= */}
        <section style={{ marginBottom: '5rem' }}>
          <div className="panel" style={{
            padding: '1.25rem',
            backgroundColor: '#FFFFFF',
            borderRadius: 'var(--radius-xl)',
            boxShadow: 'var(--shadow-lg)',
          }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '0.75rem 1rem',
              borderBottom: '1px solid var(--border)',
              marginBottom: '0.75rem',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <div style={{ width: '9px', height: '9px', borderRadius: '50%', backgroundColor: '#C53030' }}></div>
                <div style={{ width: '9px', height: '9px', borderRadius: '50%', backgroundColor: '#D99A67' }}></div>
                <div style={{ width: '9px', height: '9px', borderRadius: '50%', backgroundColor: '#1E7E34' }}></div>
                <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginLeft: '0.5rem', fontFamily: 'var(--font-mono)' }}>
                  TrustVault Live Secure Repository &bull; Real Database State
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span className="badge badge-green" style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                  <CheckCircle2 size={12} />
                  <span>SHA-256 Ledger Verified</span>
                </span>
              </div>
            </div>

            <div className="table-container" style={{ border: 'none', boxShadow: 'none' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Document Title</th>
                    <th>Classification</th>
                    <th>Owner</th>
                    <th>Access Policy</th>
                    <th>Revocation Guarantee</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td style={{ fontWeight: 600, color: 'var(--graphite)' }}>Q3 Financial Audit &amp; Compliance Report</td>
                    <td><span className="badge badge-copper">Financial</span></td>
                    <td>Alice Owner</td>
                    <td><span className="badge badge-green">Explicit Read Grant</span></td>
                    <td style={{ color: 'var(--success)', fontSize: '0.8125rem', fontWeight: 500 }}>Immediate (synchronous stream check)</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600, color: 'var(--graphite)' }}>2026 Executive Strategic Roadmap</td>
                    <td><span className="badge badge-gray">Executive</span></td>
                    <td>Alice Owner</td>
                    <td><span className="badge badge-gray">Owner Only (Isolated)</span></td>
                    <td style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>Zero unauthorized access (404 mask)</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600, color: 'var(--graphite)' }}>Internal Security Architecture Review</td>
                    <td><span className="badge badge-copper">Engineering</span></td>
                    <td>Bob Executive</td>
                    <td><span className="badge badge-gray">Owner Only (Isolated)</span></td>
                    <td style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>Zero unauthorized access (404 mask)</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* ================= ARCHITECTURE PILLARS ================= */}
        <section id="architecture" style={{ maxWidth: '1060px', margin: '0 auto' }}>
          <div style={{ textAlign: 'center', marginBottom: '3rem' }}>
            <h2 style={{ fontSize: '2rem', fontWeight: 700, letterSpacing: '-0.025em', color: 'var(--graphite)', marginBottom: '0.5rem' }}>
              Engineered on Non-Negotiable Invariants
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '1rem', maxWidth: '600px', margin: '0 auto' }}>
              Every access decision is cryptographically evaluated against live database state.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
            {/* Pillar 1 */}
            <div className="panel panel-hover">
              <div style={{
                width: '38px',
                height: '38px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--graphite)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--copper)',
                marginBottom: '1rem',
              }}>
                <Key size={19} />
              </div>
              <h3 style={{ fontSize: '1.0625rem', fontWeight: 700, color: 'var(--graphite)', marginBottom: '0.375rem' }}>
                Server-Side Sole Authority
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                The backend is the sole authority for access decisions. Document-level policies are evaluated per request. Admins do not silently bypass document confidentiality.
              </p>
            </div>

            {/* Pillar 2 */}
            <div className="panel panel-hover">
              <div style={{
                width: '38px',
                height: '38px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--graphite)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--copper)',
                marginBottom: '1rem',
              }}>
                <FileCheck size={19} />
              </div>
              <h3 style={{ fontSize: '1.0625rem', fontWeight: 700, color: 'var(--graphite)', marginBottom: '0.375rem' }}>
                Immediate Access Revocation
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                When access is revoked by a document owner, the very next download or metadata read request fails immediately. No long-lived download URLs are ever issued.
              </p>
            </div>

            {/* Pillar 3 */}
            <div className="panel panel-hover">
              <div style={{
                width: '38px',
                height: '38px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--graphite)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--copper)',
                marginBottom: '1rem',
              }}>
                <History size={19} />
              </div>
              <h3 style={{ fontSize: '1.0625rem', fontWeight: 700, color: 'var(--graphite)', marginBottom: '0.375rem' }}>
                Tamper-Evident SHA-256 Ledger
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                Every audit event is cryptographically chained with canonical JSON hashing. Evaluators can explore interactive blocks to verify hash continuity in real time.
              </p>
            </div>

            {/* Pillar 4 */}
            <div className="panel panel-hover">
              <div style={{
                width: '38px',
                height: '38px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--graphite)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--copper)',
                marginBottom: '1rem',
              }}>
                <Eye size={19} />
              </div>
              <h3 style={{ fontSize: '1.0625rem', fontWeight: 700, color: 'var(--graphite)', marginBottom: '0.375rem' }}>
                Dynamic Forensic DLP Watermark
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                In-browser confidential previews apply an uncopyable dynamic forensic watermark containing user identity and timestamps to eliminate data leakage risks.
              </p>
            </div>

            {/* Pillar 5 */}
            <div className="panel panel-hover">
              <div style={{
                width: '38px',
                height: '38px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--graphite)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--copper)',
                marginBottom: '1rem',
              }}>
                <Sparkles size={19} />
              </div>
              <h3 style={{ fontSize: '1.0625rem', fontWeight: 700, color: 'var(--graphite)', marginBottom: '0.375rem' }}>
                Human-in-the-Loop AI Advisor
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
                AI models provide least-privilege suggestions based strictly on document metadata. AI cannot grant or modify permissions directly—explicit owner approval is required.
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};
