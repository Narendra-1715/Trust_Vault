import React, { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { CheckCircle, AlertTriangle, RefreshCw, Filter } from 'lucide-react';
import { api } from '../lib/api';
import { formatToIST } from '../lib/date';
import { useToast } from '../context/ToastContext';
import type { AuditVerificationReport } from '../types';

export const AuditPage: React.FC = () => {
  const { toast } = useToast();
  const [actionFilter, setActionFilter] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState('');
  const [verificationReport, setVerificationReport] = useState<AuditVerificationReport | null>(null);

  // Queries
  const { data: auditData, isLoading, refetch } = useQuery({
    queryKey: ['auditEvents', actionFilter, outcomeFilter],
    queryFn: () => api.listAuditEvents({
      action: actionFilter || undefined,
      outcome: outcomeFilter || undefined,
    }),
  });

  // Verify Mutation
  const verifyMutation = useMutation({
    mutationFn: () => api.verifyAuditIntegrity(),
    onSuccess: (data) => {
      setVerificationReport(data);
      refetch();
      if (data.is_valid) {
        toast.success(`Audit hash chain cryptographically verified: all ${data.total_events} events valid.`);
      } else {
        toast.error(`Audit chain compromised! Tampering detected at event index ${data.event_index}.`);
      }
    },
    onError: (err: any) => {
      toast.error(err.message || 'Verification failed');
    }
  });

  return (
    <div className="container">
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-main)' }}>
            Immutable Audit Ledger
          </h1>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
            Cryptographically linked event stream with deterministic SHA-256 hash chaining.
          </p>
        </div>

        <button
          className="btn btn-primary"
          onClick={() => verifyMutation.mutate()}
          disabled={verifyMutation.isPending}
        >
          <RefreshCw size={15} className={verifyMutation.isPending ? 'spin' : ''} />
          <span>{verifyMutation.isPending ? 'Verifying Hash Chain...' : 'Verify Ledger Integrity'}</span>
        </button>
      </div>

      {/* Cryptographic Verification Status Banner */}
      {verificationReport && (
        <div style={{
          backgroundColor: verificationReport.is_valid ? 'var(--success-bg)' : 'var(--danger-bg)',
          border: `1px solid ${verificationReport.is_valid ? 'var(--success-border)' : 'var(--danger-border)'}`,
          borderRadius: 'var(--radius-md)',
          padding: '1.25rem',
          marginBottom: '1.5rem',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '1rem'
        }}>
          {verificationReport.is_valid ? (
            <CheckCircle size={24} style={{ color: 'var(--success)', marginTop: '0.125rem' }} />
          ) : (
            <AlertTriangle size={24} style={{ color: 'var(--danger)', marginTop: '0.125rem' }} />
          )}

          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 700, fontSize: '1rem', color: verificationReport.is_valid ? 'var(--success)' : 'var(--danger)' }}>
              {verificationReport.is_valid
                ? 'Audit Ledger Cryptographically Verified'
                : 'INTEGRITY ALERT: Tampering Detected in Audit Ledger'}
            </div>

            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
              {verificationReport.is_valid ? (
                `Verified all ${verificationReport.total_events} consecutive audit records. Every previous hash matches and recomputed SHA-256 payload digests are intact.`
              ) : (
                `Chain failure detected at event ${verificationReport.tampered_event_id}. Reason: ${verificationReport.error_reason}`
              )}
            </p>
          </div>
        </div>
      )}

      {/* Filters Bar */}
      <div className="panel" style={{ padding: '0.875rem 1rem', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Filter size={15} color="var(--text-muted)" />
            <select
              className="input-field"
              value={outcomeFilter}
              onChange={(e) => setOutcomeFilter(e.target.value)}
              style={{ width: 'auto', padding: '0.375rem 0.75rem' }}
            >
              <option value="">All Outcomes</option>
              <option value="success">Success</option>
              <option value="denied">Denied / Forbidden</option>
              <option value="failure">Failure</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, minWidth: '200px' }}>
            <input
              type="text"
              className="input-field"
              placeholder="Filter by action (e.g. document.download, permission.revoke)..."
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              style={{ padding: '0.375rem 0.75rem' }}
            />
          </div>
        </div>
      </div>

      {/* Events Table */}
      {isLoading ? (
        <div className="panel" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
          Loading audit events...
        </div>
      ) : auditData?.events && auditData.events.length > 0 ? (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp (IST)</th>
                <th>Action</th>
                <th>Actor</th>
                <th>Resource</th>
                <th>Outcome</th>
                <th>Event Hash (SHA-256)</th>
              </tr>
            </thead>
            <tbody>
              {auditData.events.map((e) => (
                <tr key={e.id}>
                  <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                    {formatToIST(e.timestamp)}
                  </td>
                  <td>
                    <span style={{ fontWeight: 600, fontFamily: 'monospace', fontSize: '0.8125rem' }}>
                      {e.action}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.8125rem' }}>
                    {e.actor_email ? (
                      <span>{e.actor_email}</span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)' }}>Anonymous</span>
                    )}
                  </td>
                  <td>
                    <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                      {e.resource_type} {e.resource_id ? `(${e.resource_id.substring(0, 8)}...)` : ''}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${
                      e.outcome === 'success' 
                        ? 'badge-green' 
                        : e.outcome === 'denied' 
                        ? 'badge-red' 
                        : 'badge-yellow'
                    }`}>
                      {e.outcome}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                    <span title={`Previous: ${e.previous_event_hash}\nCurrent: ${e.event_hash}`}>
                      {e.event_hash.substring(0, 16)}...
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="panel" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
          No audit events matched your filter.
        </div>
      )}
    </div>
  );
};
