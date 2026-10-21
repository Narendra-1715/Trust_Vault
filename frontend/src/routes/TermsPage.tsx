import React from 'react';
import { Shield } from 'lucide-react';

export const TermsPage: React.FC = () => {
  return (
    <div className="container" style={{ maxWidth: '800px', margin: '0 auto', paddingBottom: '4rem' }}>
      <div className="panel" style={{ padding: '2.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
          <Shield size={28} color="var(--accent)" />
          <div>
            <h1 style={{ fontSize: '1.75rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
              Terms and Conditions
            </h1>
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
              Effective Date: October 2026 | Technical Draft (Subject to Legal Review)
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
          <strong>Legal Disclaimer:</strong> These Terms and Conditions constitute a functional architectural specification of user rights, platform guarantees, and operational boundaries for TrustVault. This text is a draft requiring formal legal review prior to commercial deployment.
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem', fontSize: '0.9375rem', lineHeight: 1.7, color: 'var(--text-secondary)' }}>
          <section>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem' }}>
              1. Acceptance &amp; Scope of Service
            </h2>
            <p>
              By signing into or interacting with TrustVault, you agree to comply with these Terms and Conditions. TrustVault is a security-first confidential document repository designed to enforce granular document-level authorization and provide tamper-evident cryptographic auditing.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem' }}>
              2. Account Responsibilities &amp; Credentials
            </h2>
            <p>
              Users are responsible for safeguarding their authentication credentials. Accounts are protected via Argon2id password hashing and short-lived access credentials. You agree to notify administrators immediately of any suspected unauthorized account activity or compromised access tokens.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem' }}>
              3. Ownership and Document Rights
            </h2>
            <p>
              Document owners retain all intellectual property rights and confidentiality claims over files uploaded to TrustVault. By uploading a document, you warrant that you are authorized to store and share the content within your organization.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem' }}>
              4. Document Sharing &amp; Immediate Revocation
            </h2>
            <p>
              Document owners exercise exclusive authority over who may view, download, or edit documents. When an owner revokes permission for a previously authorized user, that revocation is effective immediately across all API endpoints. No persistent direct URLs exist that could bypass revocation.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem' }}>
              5. AI Advisory Features Disclaimer
            </h2>
            <p>
              AI-generated access recommendations provided by the platform are purely advisory and based on metadata classification. AI recommendations do not constitute formal security or compliance determinations. The platform does not allow AI to independently grant or revoke access. The acting human document owner assumes full responsibility for approving or rejecting proposed access profiles.
            </p>
          </section>

          <section>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem' }}>
              6. Prohibited Activities
            </h2>
            <p>
              Users shall not attempt to:
            </p>
            <ul style={{ paddingLeft: '1.25rem', marginTop: '0.5rem' }}>
              <li>Circumvent server-side authorization checks through ID manipulation, path traversal, or direct API tampering.</li>
              <li>Upload malicious payloads, executables, or disguised binary files.</li>
              <li>Conduct unauthorized penetration tests or denial-of-service attacks against production endpoints.</li>
              <li>Inject prompt manipulation payloads intended to subvert AI policy advisors.</li>
            </ul>
          </section>

          <section>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.5rem' }}>
              7. Governing Law &amp; Platform Operator
            </h2>
            <div style={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
              Operating Entity: [TrustVault Operator Legal Name / Placeholder]<br />
              Jurisdiction: [Designate Applicable Legal Jurisdiction / Placeholder]
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};
