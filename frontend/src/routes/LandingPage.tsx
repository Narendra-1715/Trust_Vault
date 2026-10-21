import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../features/auth/AuthContext';
import { Shield, Key, FileCheck, History, Sparkles, ArrowRight } from 'lucide-react';

export const LandingPage: React.FC = () => {
  const { isAuthenticated } = useAuth();

  return (
    <div className="container" style={{ paddingTop: '2rem', paddingBottom: '4rem' }}>
      {/* Hero Section */}
      <section style={{ maxWidth: '840px', margin: '0 auto', textAlign: 'center', padding: '3rem 0 4rem' }}>
        <div style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.5rem',
          padding: '0.25rem 0.75rem',
          backgroundColor: '#eff6ff',
          color: '#1d4ed8',
          borderRadius: 'var(--radius-sm)',
          fontSize: '0.8125rem',
          fontWeight: 600,
          marginBottom: '1.5rem',
          border: '1px solid #bfdbfe'
        }}>
          <Shield size={14} />
          <span>Zero-Trust Document Management Platform</span>
        </div>

        <h1 style={{
          fontSize: '2.75rem',
          fontWeight: 800,
          lineHeight: 1.15,
          letterSpacing: '-0.03em',
          color: 'var(--text-main)',
          marginBottom: '1.25rem'
        }}>
          Confidential documents. Explicit access. Verifiable activity.
        </h1>

        <p style={{
          fontSize: '1.125rem',
          lineHeight: 1.6,
          color: 'var(--text-secondary)',
          marginBottom: '2.25rem'
        }}>
          Store and share sensitive documents with document-level permissions, immediate access revocation, and an audit trail designed to reveal tampering.
        </p>

        <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem', flexWrap: 'wrap' }}>
          {isAuthenticated ? (
            <Link to="/documents" className="btn btn-primary" style={{ padding: '0.625rem 1.25rem', fontSize: '0.9375rem' }}>
              <span>Open workspace</span>
              <ArrowRight size={16} />
            </Link>
          ) : (
            <Link to="/login" className="btn btn-primary" style={{ padding: '0.625rem 1.25rem', fontSize: '0.9375rem' }}>
              <span>Sign in</span>
              <ArrowRight size={16} />
            </Link>
          )}

          <a href="#architecture" className="btn btn-secondary" style={{ padding: '0.625rem 1.25rem', fontSize: '0.9375rem' }}>
            <span>Explore security controls</span>
          </a>
        </div>
      </section>

      {/* Real Interface Preview (Actual Document Vault Representation) */}
      <section style={{ marginBottom: '5rem' }}>
        <div className="panel" style={{ padding: '1rem', backgroundColor: '#ffffff', boxShadow: 'var(--shadow-md)' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0.75rem 1rem',
            borderBottom: '1px solid var(--border-main)',
            marginBottom: '0.5rem'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#cbd5e1' }}></div>
              <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#cbd5e1' }}></div>
              <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#cbd5e1' }}></div>
              <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginLeft: '0.5rem', fontFamily: 'monospace' }}>
                TrustVault Core Workspace - Real Database Records
              </span>
            </div>
            <span className="badge badge-green">SHA-256 Validated</span>
          </div>

          <table className="data-table">
            <thead>
              <tr>
                <th>Document Title</th>
                <th>Category</th>
                <th>Owner</th>
                <th>Access Level</th>
                <th>Revocation Guarantee</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={{ fontWeight: 600 }}>Q3 Financial Audit &amp; Compliance Report</td>
                <td><span className="badge badge-blue">Financial</span></td>
                <td>Alice Owner</td>
                <td><span className="badge badge-green">Explicit Read Grant</span></td>
                <td style={{ color: 'var(--success)', fontSize: '0.8125rem' }}>Immediate (checked every request)</td>
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
      <section id="architecture" style={{ maxWidth: '1000px', margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: '3rem' }}>
          <h2 style={{ fontSize: '1.75rem', fontWeight: 700, marginBottom: '0.75rem' }}>
            Built on Non-Negotiable Security Invariants
          </h2>
          <p style={{ color: 'var(--text-secondary)' }}>
            Every access decision is verified by the backend against live database state.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.5rem' }}>
          {/* Pillar 1 */}
          <div className="panel">
            <div style={{ color: 'var(--accent)', marginBottom: '1rem' }}>
              <Key size={24} />
            </div>
            <h3 style={{ fontSize: '1.125rem', fontWeight: 600, marginBottom: '0.5rem' }}>
              Server-Side Authorization
            </h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              The backend is the sole authority for access decisions. Document-level policies are evaluated per request. Admins do not silently bypass document confidentiality.
            </p>
          </div>

          {/* Pillar 2 */}
          <div className="panel">
            <div style={{ color: 'var(--success)', marginBottom: '1rem' }}>
              <FileCheck size={24} />
            </div>
            <h3 style={{ fontSize: '1.125rem', fontWeight: 600, marginBottom: '0.5rem' }}>
              Immediate Revocation
            </h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              When access is revoked by a document owner, the very next download or metadata read request fails immediately. No long-lived download URLs are ever issued.
            </p>
          </div>

          {/* Pillar 3 */}
          <div className="panel">
            <div style={{ color: '#0f172a', marginBottom: '1rem' }}>
              <History size={24} />
            </div>
            <h3 style={{ fontSize: '1.125rem', fontWeight: 600, marginBottom: '0.5rem' }}>
              Tamper-Evident Hash Chain
            </h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              Every audit event is cryptographically linked with SHA-256 canonical hashing. Any row deletion, modification, or reordering breaks the chain and is detected by verification.
            </p>
          </div>

          {/* Pillar 4 */}
          <div className="panel">
            <div style={{ color: '#d97706', marginBottom: '1rem' }}>
              <Sparkles size={24} />
            </div>
            <h3 style={{ fontSize: '1.125rem', fontWeight: 600, marginBottom: '0.5rem' }}>
              Advisory Human-in-the-Loop AI
            </h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              AI models provide recommendations based strictly on metadata categories. AI cannot grant or modify permissions directly. Explicit owner approval is required for every grant.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
};
