import React from 'react';
import { Shield } from 'lucide-react';

export const PrivacyPage: React.FC = () => {
  return (
    <div className="container" style={{ maxWidth: '800px', margin: '0 auto', paddingBottom: '4rem' }}>
      <div className="panel" style={{ padding: '2.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
          <Shield size={28} color="var(--accent)" />
          <div>
            <h1 style={{ fontSize: '1.75rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
              Privacy Policy
            </h1>
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
              Effective Date: October 2026 | Document Draft Version 1.0 (Subject to Legal Review)
            </div>
          </div>
        </div>

        <div style={{
          backgroundColor: '#f1f5f9',
          borderLeft: '4px solid var(--accent)',
          padding: '0.875rem 1rem',
          fontSize: '0.8125rem',
          color: 'var(--text-secondary)',
          marginBottom: '2rem',
          borderRadius: '0 var(--radius-sm) var(--radius-sm) 0'
        }}>
          <strong>Legal Notice:</strong> This privacy policy accurately describes the actual data architecture, storage policies, and AI integration mechanisms of the TrustVault platform. It is provided as a product technical draft and requires final regulatory review before commercial launch.
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem', fontSize: '0.9375rem', lineHeight: 1.7, color: 'var(--text-secondary)' }}>
          <section>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem' }}>
              1. Information We Collect
            </h2>
            <p>
              TrustVault collects only the information necessary to provide confidential document management, enforce server-side access control, and maintain an immutable security audit trail:
            </p>
            <ul style={{ paddingLeft: '1.25rem', marginTop: '0.5rem' }}>
              <li><strong>Account Identifiers:</strong> Email address, display name, account role (Admin, Owner, Viewer), and Argon2id cryptographically hashed passwords. Raw passwords are never stored or logged.</li>
              <li><strong>Document Metadata &amp; Files:</strong> Document titles, descriptions, categories, file size, detected MIME type, SHA-256 cryptographic checksums, and the uploaded binary files.</li>
              <li><strong>Access Control Grants:</strong> Active and revoked permission records linking documents to specific registered user IDs.</li>
              <li><strong>Security Audit Events:</strong> Append-only log of logins, uploads, downloads, permission grants, access revocations, and policy enforcement decisions.</li>
            </ul>
          </section>

          <section>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem' }}>
              2. Private File Storage &amp; Isolation
            </h2>
            <p>
              Uploaded documents are never stored in public web-accessible directories. Files are saved in an isolated, private filesystem storage container using randomized UUID keys. Access is strictly mediated through the backend API, which validates the requesting user's active permissions against the database on every single download or preview attempt.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem' }}>
              3. Artificial Intelligence &amp; Third-Party Processing
            </h2>
            <p>
              When a document owner explicitly requests access recommendations, TrustVault transmits <strong>only document metadata</strong> (title, category, description) and candidate user profiles (names and organizational roles) to the configured AI provider (Google Gemini API).
            </p>
            <p style={{ marginTop: '0.5rem' }}>
              <strong>Zero Document Content Transmission:</strong> Confidential file contents are not transmitted to external AI providers. AI output is treated strictly as untrusted advisory data and has zero autonomous authority to grant access. Only explicit human owner approval can create database permission grants.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem' }}>
              4. Data Retention &amp; Deletion Policy
            </h2>
            <p>
              When a document owner executes a document deletion:
            </p>
            <ul style={{ paddingLeft: '1.25rem', marginTop: '0.5rem' }}>
              <li>The underlying physical file is immediately purged from private storage.</li>
              <li>The document database record is marked as deleted (retained for audit cross-referencing per organizational retention rules).</li>
              <li>Audit ledger entries related to the document remain intact in the append-only cryptographic hash chain to maintain ledger continuity.</li>
            </ul>
          </section>

          <section>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem' }}>
              5. Cryptographic Audit Integrity &amp; Accepted Limitations
            </h2>
            <p>
              Audit events are chained using SHA-256 cryptographic hashes. This ensures that unauthorized deletion, modification, or reordering of prior events is mathematically detectable. However, users should understand that a database superuser with root access could theoretically recompute an entire database chain if external, signed immutable checkpoints are not enabled.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem' }}>
              6. Contact Information &amp; Data Rights
            </h2>
            <p>
              To exercise your data access or account deletion rights, please contact the designated platform administrator at:
            </p>
            <div style={{ marginTop: '0.5rem', fontFamily: 'monospace', fontSize: '0.875rem' }}>
              TrustVault Security Office: [security@trustvault.local / Placeholder - Configure in Production]
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};
