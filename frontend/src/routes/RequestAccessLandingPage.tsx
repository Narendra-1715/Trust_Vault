import React, { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { 
  Shield, 
  Lock, 
  Clock, 
  User, 
  CheckCircle, 
  AlertCircle, 
  ArrowLeft, 
  Send,
  ExternalLink,
  Tag
} from 'lucide-react';
import { api } from '../lib/api';
import { useToast } from '../context/ToastContext';
import type { RequestLinkResolved } from '../types';

export const RequestAccessLandingPage: React.FC = () => {
  const { token } = useParams<{ token: string }>();
  const { toast } = useToast();

  const [reason, setReason] = useState('');
  const [requestedPermission, setRequestedPermission] = useState<'read' | 'edit'>('read');
  const [durationPreset, setDurationPreset] = useState<'1h' | '24h' | '7d' | '30d' | 'never' | 'custom'>('7d');
  const [customExpiry, setCustomExpiry] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submittedSuccess, setSubmittedSuccess] = useState(false);

  // Resolve link safely - minimal metadata only
  const { 
    data: resolved, 
    isLoading, 
    error
  } = useQuery<RequestLinkResolved>({
    queryKey: ['request-link-resolve', token],
    queryFn: () => api.resolveRequestLink(token!),
    enabled: !!token,
    retry: false,
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !reason.trim()) {
      toast.error('Please provide a reason for requesting access');
      return;
    }

    if (reason.trim().length < 5) {
      toast.error('Reason must be at least 5 characters long');
      return;
    }

    setIsSubmitting(true);
    try {
      let finalExpiry: string | undefined = undefined;
      const now = new Date();

      if (durationPreset === '1h') {
        finalExpiry = new Date(now.getTime() + 60 * 60 * 1000).toISOString();
      } else if (durationPreset === '24h') {
        finalExpiry = new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString();
      } else if (durationPreset === '7d') {
        finalExpiry = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();
      } else if (durationPreset === '30d') {
        finalExpiry = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
      } else if (durationPreset === 'custom' && customExpiry) {
        finalExpiry = new Date(customExpiry).toISOString();
      }

      await api.submitAccessRequestViaLink(token, {
        reason: reason.trim(),
        requested_permission: requestedPermission,
        requested_expiry: finalExpiry,
      });

      setSubmittedSuccess(true);
      toast.success('Access request submitted successfully.');
    } catch (err: any) {
      toast.error(err.message || 'Failed to submit access request');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading) {
    return (
      <div className="container" style={{ maxWidth: '640px', padding: '4rem 1rem', textAlign: 'center' }}>
        <div style={{
          width: '48px',
          height: '48px',
          border: '3px solid var(--border)',
          borderTopColor: 'var(--copper)',
          borderRadius: '50%',
          animation: 'spin 1s linear infinite',
          margin: '0 auto 1.5rem',
        }} />
        <h2 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--graphite)', marginBottom: '0.5rem' }}>
          Resolving Access Reference...
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>
          Validating cryptographic token integrity and document binding.
        </p>
      </div>
    );
  }

  // Handle Invalid / Expired / Revoked Token
  if (error || !resolved) {
    const errorMsg = (error as any)?.message || 'The link may have expired or been revoked.';
    return (
      <div className="container" style={{ maxWidth: '580px', padding: '3.5rem 1rem' }}>
        <div className="card card-elevated" style={{ textAlign: 'center', padding: '2.5rem 2rem' }}>
          <div style={{
            width: '56px',
            height: '56px',
            borderRadius: '50%',
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 1.25rem',
            color: '#DC2626',
          }}>
            <AlertCircle size={28} />
          </div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--graphite)', marginBottom: '0.5rem' }}>
            Invalid or Inactive Request Reference
          </h2>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1.5rem', lineHeight: 1.5 }}>
            {errorMsg}
          </p>
          <div style={{
            backgroundColor: 'var(--bg-warm)',
            border: '1px solid var(--border)',
            borderRadius: '0.5rem',
            padding: '1rem',
            fontSize: '0.8125rem',
            color: 'var(--text-secondary)',
            textAlign: 'left',
            marginBottom: '1.5rem'
          }}>
            <strong>Why this happens:</strong>
            <ul style={{ margin: '0.5rem 0 0 1.25rem', padding: 0 }}>
              <li>The document owner may have revoked this link.</li>
              <li>The reference link reached its maximum usage limit.</li>
              <li>The time-based expiration policy for this link passed.</li>
            </ul>
          </div>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '0.75rem' }}>
            <Link to="/documents" className="btn btn-secondary btn-sm">
              <ArrowLeft size={14} style={{ marginRight: '0.375rem' }} />
              Return to Documents
            </Link>
          </div>
        </div>
      </div>
    );
  }

  // Handle Successful Submission
  if (submittedSuccess) {
    return (
      <div className="container" style={{ maxWidth: '600px', padding: '3.5rem 1rem' }}>
        <div className="card card-elevated" style={{ textAlign: 'center', padding: '2.5rem 2rem' }}>
          <div style={{
            width: '60px',
            height: '60px',
            borderRadius: '50%',
            backgroundColor: 'rgba(16, 185, 129, 0.1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 1.25rem',
            color: '#10B981',
          }}>
            <CheckCircle size={32} />
          </div>
          <h2 style={{ fontSize: '1.375rem', fontWeight: 700, color: 'var(--graphite)', marginBottom: '0.5rem' }}>
            Access Request Submitted
          </h2>
          <p style={{ fontSize: '0.9375rem', color: 'var(--text-secondary)', marginBottom: '1.5rem', lineHeight: 1.6 }}>
            Your request for <strong>"{resolved.document_title}"</strong> has been securely routed to <strong>{resolved.owner_name}</strong> for review.
          </p>
          <div style={{
            backgroundColor: 'var(--bg-warm)',
            border: '1px solid var(--border)',
            borderRadius: '0.5rem',
            padding: '1.25rem',
            fontSize: '0.8125rem',
            color: 'var(--text-secondary)',
            textAlign: 'left',
            marginBottom: '1.75rem'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
              <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Document:</span>
              <span>{resolved.document_title}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
              <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Owner:</span>
              <span>{resolved.owner_email}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
              <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Requested Level:</span>
              <span style={{ textTransform: 'capitalize' }}>{requestedPermission}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Status:</span>
              <span style={{ 
                color: '#D97706', 
                fontWeight: 600, 
                backgroundColor: 'rgba(217, 119, 6, 0.1)', 
                padding: '0.125rem 0.5rem', 
                borderRadius: '9999px' 
              }}>
                Pending Owner Decision
              </span>
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '0.75rem' }}>
            <Link to="/requests" className="btn btn-primary btn-sm">
              View My Requests
            </Link>
            <Link to="/documents" className="btn btn-secondary btn-sm">
              Return to Vault
            </Link>
          </div>
        </div>
      </div>
    );
  }

  // Handle User Already Has Access
  if (resolved.already_has_access) {
    return (
      <div className="container" style={{ maxWidth: '580px', padding: '3.5rem 1rem' }}>
        <div className="card card-elevated" style={{ textAlign: 'center', padding: '2.5rem 2rem' }}>
          <div style={{
            width: '56px',
            height: '56px',
            borderRadius: '50%',
            backgroundColor: 'rgba(16, 185, 129, 0.1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 1.25rem',
            color: '#10B981',
          }}>
            <Shield size={28} />
          </div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--graphite)', marginBottom: '0.5rem' }}>
            You Already Have Access
          </h2>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1.5rem', lineHeight: 1.5 }}>
            You already possess authorized access to <strong>"{resolved.document_title}"</strong>. There is no need to submit another access request.
          </p>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '0.75rem' }}>
            <Link to={`/documents/${resolved.document_id}`} className="btn btn-primary btn-sm">
              <ExternalLink size={14} style={{ marginRight: '0.375rem' }} />
              Open Document
            </Link>
            <Link to="/documents" className="btn btn-secondary btn-sm">
              Return to Documents
            </Link>
          </div>
        </div>
      </div>
    );
  }

  // Handle User Has Pending Request
  if (resolved.has_pending_request) {
    return (
      <div className="container" style={{ maxWidth: '580px', padding: '3.5rem 1rem' }}>
        <div className="card card-elevated" style={{ textAlign: 'center', padding: '2.5rem 2rem' }}>
          <div style={{
            width: '56px',
            height: '56px',
            borderRadius: '50%',
            backgroundColor: 'rgba(217, 119, 6, 0.1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 1.25rem',
            color: '#D97706',
          }}>
            <Clock size={28} />
          </div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--graphite)', marginBottom: '0.5rem' }}>
            Access Request Pending Review
          </h2>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1.5rem', lineHeight: 1.5 }}>
            You already have an active request pending review for <strong>"{resolved.document_title}"</strong>. The owner (<strong>{resolved.owner_name}</strong>) has been notified.
          </p>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '0.75rem' }}>
            <Link to="/requests" className="btn btn-primary btn-sm">
              Check Request Status
            </Link>
            <Link to="/documents" className="btn btn-secondary btn-sm">
              Return to Documents
            </Link>
          </div>
        </div>
      </div>
    );
  }

  // Active Reference Form - Minimal safe discovery metadata with request form
  return (
    <div className="container" style={{ maxWidth: '640px', padding: '2.5rem 1rem' }}>
      <Link 
        to="/documents" 
        style={{ 
          display: 'inline-flex', 
          alignItems: 'center', 
          gap: '0.375rem', 
          fontSize: '0.8125rem', 
          color: 'var(--text-secondary)', 
          textDecoration: 'none', 
          marginBottom: '1.25rem' 
        }}
      >
        <ArrowLeft size={14} />
        Back to Documents
      </Link>

      <div className="card card-elevated" style={{ padding: '2rem' }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem', marginBottom: '1.5rem' }}>
          <div style={{
            width: '48px',
            height: '48px',
            borderRadius: '0.5rem',
            backgroundColor: 'var(--copper-light)',
            color: 'var(--copper-dark)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
          }}>
            <Lock size={24} />
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.25rem' }}>
              <span style={{
                fontSize: '0.6875rem',
                fontWeight: 600,
                color: 'var(--copper-dark)',
                backgroundColor: 'rgba(217, 154, 103, 0.15)',
                padding: '0.125rem 0.5rem',
                borderRadius: '0.25rem',
                letterSpacing: '0.025em',
                textTransform: 'uppercase'
              }}>
                Secure Access Reference
              </span>
              {resolved.category && (
                <span style={{
                  fontSize: '0.6875rem',
                  fontWeight: 500,
                  color: 'var(--text-secondary)',
                  backgroundColor: 'var(--bg-warm)',
                  border: '1px solid var(--border)',
                  padding: '0.125rem 0.5rem',
                  borderRadius: '0.25rem',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.25rem'
                }}>
                  <Tag size={10} />
                  {resolved.category}
                </span>
              )}
            </div>
            <h1 style={{ fontSize: '1.375rem', fontWeight: 700, color: 'var(--graphite)', margin: 0, lineHeight: 1.3 }}>
              {resolved.document_title}
            </h1>
          </div>
        </div>

        {/* Discovery Metadata Card */}
        <div style={{
          backgroundColor: 'var(--bg-warm)',
          border: '1px solid var(--border)',
          borderRadius: '0.5rem',
          padding: '1rem',
          marginBottom: '1.5rem',
          fontSize: '0.8125rem',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '0.75rem'
        }}>
          <div>
            <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '0.75rem', marginBottom: '0.125rem' }}>
              Document Owner
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', color: 'var(--text-primary)', fontWeight: 600 }}>
              <User size={13} color="var(--copper-dark)" />
              {resolved.owner_name}
            </div>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-secondary)' }}>
              {resolved.owner_email}
            </span>
          </div>

          <div>
            <span style={{ color: 'var(--text-secondary)', display: 'block', fontSize: '0.75rem', marginBottom: '0.125rem' }}>
              Reference ID
            </span>
            <span style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'var(--text-primary)', fontWeight: 600 }}>
              ref_{resolved.token_prefix}
            </span>
          </div>
        </div>

        {/* Zero-Trust Notice */}
        <div style={{
          display: 'flex',
          gap: '0.75rem',
          padding: '0.875rem',
          borderRadius: '0.5rem',
          backgroundColor: 'rgba(44, 62, 80, 0.04)',
          border: '1px solid rgba(44, 62, 80, 0.1)',
          marginBottom: '1.5rem',
          fontSize: '0.8125rem',
          lineHeight: 1.45,
          color: 'var(--text-secondary)'
        }}>
          <Shield size={18} color="var(--graphite)" style={{ flexShrink: 0, marginTop: '0.125rem' }} />
          <div>
            <strong style={{ color: 'var(--graphite)' }}>Zero-Trust Protection:</strong> Document contents, forensic watermarks, and download streams are locked. Submitting this request sends an access petition to the document owner.
          </div>
        </div>

        {/* Request Form */}
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.375rem' }}>
              Business Justification <span style={{ color: '#EF4444' }}>*</span>
            </label>
            <textarea
              className="form-input"
              rows={3}
              placeholder="Explain why you require access to this document (minimum 5 characters)..."
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              required
              minLength={5}
              maxLength={1000}
              style={{ fontSize: '0.8125rem', resize: 'vertical' }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.375rem' }}>
              Requested Access Level
            </label>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
              <button
                type="button"
                onClick={() => setRequestedPermission('read')}
                className="btn btn-sm"
                style={{
                  padding: '0.5rem',
                  backgroundColor: requestedPermission === 'read' ? 'var(--copper-light)' : '#FFFFFF',
                  borderColor: requestedPermission === 'read' ? 'var(--copper)' : 'var(--border)',
                  color: requestedPermission === 'read' ? 'var(--copper-dark)' : 'var(--text-secondary)',
                  fontWeight: requestedPermission === 'read' ? 600 : 500,
                }}
              >
                Read Only (Standard)
              </button>
              <button
                type="button"
                onClick={() => setRequestedPermission('edit')}
                className="btn btn-sm"
                style={{
                  padding: '0.5rem',
                  backgroundColor: requestedPermission === 'edit' ? 'var(--copper-light)' : '#FFFFFF',
                  borderColor: requestedPermission === 'edit' ? 'var(--copper)' : 'var(--border)',
                  color: requestedPermission === 'edit' ? 'var(--copper-dark)' : 'var(--text-secondary)',
                  fontWeight: requestedPermission === 'edit' ? 600 : 500,
                }}
              >
                Edit Access
              </button>
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.375rem' }}>
              Requested Access Duration
            </label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.375rem', marginBottom: '0.5rem' }}>
              {(['1h', '24h', '7d', '30d', 'never', 'custom'] as const).map(preset => (
                <button
                  key={preset}
                  type="button"
                  onClick={() => setDurationPreset(preset)}
                  className="btn btn-sm"
                  style={{
                    padding: '0.25rem 0.5rem',
                    fontSize: '0.75rem',
                    backgroundColor: durationPreset === preset ? 'var(--graphite)' : 'var(--bg-warm)',
                    color: durationPreset === preset ? '#FFFFFF' : 'var(--text-secondary)',
                    borderColor: durationPreset === preset ? 'var(--graphite)' : 'var(--border)',
                  }}
                >
                  {preset === '1h' ? '1 Hour' : preset === '24h' ? '24 Hours' : preset === '7d' ? '7 Days' : preset === '30d' ? '30 Days' : preset === 'never' ? 'Permanent' : 'Custom'}
                </button>
              ))}
            </div>

            {durationPreset === 'custom' && (
              <input
                type="datetime-local"
                className="form-input"
                value={customExpiry}
                onChange={(e) => setCustomExpiry(e.target.value)}
                style={{ fontSize: '0.8125rem' }}
              />
            )}
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
            <Link to="/documents" className="btn btn-secondary btn-sm">
              Cancel
            </Link>
            <button
              type="submit"
              className="btn btn-primary btn-sm"
              disabled={isSubmitting || !reason.trim()}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '0.375rem' }}
            >
              <Send size={13} />
              {isSubmitting ? 'Submitting...' : 'Submit Access Request'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
