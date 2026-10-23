import React, { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { 
  CheckCircle, 
  AlertTriangle, 
  RefreshCw, 
  Filter, 
  Layers, 
  Table as TableIcon, 
  Link as LinkIcon, 
  ChevronDown, 
  ChevronRight, 
  ShieldCheck, 
  Clock 
} from 'lucide-react';
import { api } from '../lib/api';
import { formatToIST } from '../lib/date';
import { useToast } from '../context/ToastContext';
import type { AuditVerificationReport } from '../types';

export const AuditPage: React.FC = () => {
  const { toast } = useToast();
  const [viewMode, setViewMode] = useState<'table' | 'chain'>('table');
  const [actionFilter, setActionFilter] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState('');
  const [verificationReport, setVerificationReport] = useState<AuditVerificationReport | null>(null);
  const [expandedPayloadId, setExpandedPayloadId] = useState<string | null>(null);

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

      {/* Filters & View Switcher Bar */}
      <div className="panel" style={{ padding: '0.875rem 1rem', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap', flex: 1 }}>
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

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, minWidth: '180px' }}>
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

          {/* View Mode Toggle */}
          <div style={{
            display: 'inline-flex',
            backgroundColor: 'var(--bg-surface-secondary)',
            padding: '3px',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-main)'
          }}>
            <button
              type="button"
              onClick={() => setViewMode('table')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.375rem',
                padding: '0.375rem 0.75rem',
                fontSize: '0.75rem',
                fontWeight: viewMode === 'table' ? 600 : 500,
                color: viewMode === 'table' ? 'var(--text-main)' : 'var(--text-muted)',
                backgroundColor: viewMode === 'table' ? 'var(--bg-surface)' : 'transparent',
                border: viewMode === 'table' ? '1px solid var(--border-main)' : 'none',
                borderRadius: 'var(--radius-xs)',
                cursor: 'pointer',
              }}
            >
              <TableIcon size={14} />
              <span>Table View</span>
            </button>

            <button
              type="button"
              onClick={() => setViewMode('chain')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.375rem',
                padding: '0.375rem 0.75rem',
                fontSize: '0.75rem',
                fontWeight: viewMode === 'chain' ? 600 : 500,
                color: viewMode === 'chain' ? 'var(--text-main)' : 'var(--text-muted)',
                backgroundColor: viewMode === 'chain' ? 'var(--bg-surface)' : 'transparent',
                border: viewMode === 'chain' ? '1px solid var(--border-main)' : 'none',
                borderRadius: 'var(--radius-xs)',
                cursor: 'pointer',
              }}
            >
              <Layers size={14} />
              <span>Cryptographic Block Explorer</span>
            </button>
          </div>
        </div>
      </div>

      {/* Events Presentation */}
      {isLoading ? (
        <div className="panel" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
          Loading audit events...
        </div>
      ) : auditData?.events && auditData.events.length > 0 ? (
        viewMode === 'table' ? (
          /* TABLE VIEW */
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
          /* CRYPTOGRAPHIC BLOCK CHAIN VIEW */
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{ 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'space-between',
              padding: '0.75rem 1rem', 
              backgroundColor: '#0f172a', 
              color: '#f8fafc',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.8125rem'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <ShieldCheck size={16} color="#22c55e" />
                <span><strong>SHA-256 Hash Chain Integrity:</strong> Each block is cryptographically bound to the hash of the preceding block.</span>
              </div>
              <span className="badge badge-green" style={{ textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Immutable Ledger
              </span>
            </div>

            {auditData.events.map((e, idx) => {
              const isExpanded = expandedPayloadId === e.id;
              return (
                <div key={e.id} style={{ display: 'flex', flexDirection: 'column', alignItems: 'stretch' }}>
                  {/* Block Card */}
                  <div className="panel" style={{
                    padding: '1.25rem',
                    border: '1px solid var(--border-main)',
                    borderRadius: 'var(--radius-md)',
                    backgroundColor: 'var(--bg-surface)',
                    boxShadow: 'var(--shadow-sm)'
                  }}>
                    {/* Top Row: Block index, action, timestamp */}
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.875rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                        <span style={{
                          backgroundColor: '#0f172a',
                          color: '#38bdf8',
                          padding: '0.2rem 0.5rem',
                          borderRadius: 'var(--radius-xs)',
                          fontFamily: 'monospace',
                          fontSize: '0.75rem',
                          fontWeight: 700
                        }}>
                          BLOCK #{auditData.events.length - idx}
                        </span>

                        <span style={{ fontWeight: 700, fontSize: '0.9375rem', color: 'var(--text-main)', fontFamily: 'monospace' }}>
                          {e.action}
                        </span>

                        <span className={`badge ${
                          e.outcome === 'success' 
                            ? 'badge-green' 
                            : e.outcome === 'denied' 
                            ? 'badge-red' 
                            : 'badge-yellow'
                        }`}>
                          {e.outcome.toUpperCase()}
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                        <Clock size={13} />
                        <span>{formatToIST(e.timestamp)}</span>
                      </div>
                    </div>

                    {/* Actor & Resource details */}
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem', marginBottom: '1rem', fontSize: '0.8125rem' }}>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Actor: </span>
                        <strong>{e.actor_email || 'System / Anonymous'}</strong>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Target Resource: </span>
                        <strong>{e.resource_type}</strong> {e.resource_id && <code style={{ fontSize: '0.75rem' }}>({e.resource_id.substring(0, 12)}...)</code>}
                      </div>
                      {e.request_id && (
                        <div>
                          <span style={{ color: 'var(--text-muted)' }}>Request ID: </span>
                          <code style={{ fontSize: '0.75rem' }}>{e.request_id.substring(0, 16)}</code>
                        </div>
                      )}
                    </div>

                    {/* Cryptographic Hash Pair */}
                    <div style={{
                      backgroundColor: 'var(--bg-surface-secondary)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '0.75rem 1rem',
                      fontSize: '0.75rem',
                      fontFamily: 'monospace',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.375rem'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-secondary)' }}>
                        <span style={{ color: 'var(--text-muted)', width: '120px' }}>Previous Hash:</span>
                        <code style={{ wordBreak: 'break-all', color: e.previous_event_hash === '0'.repeat(64) ? '#10b981' : 'inherit' }}>
                          {e.previous_event_hash === '0'.repeat(64) ? '0x0000000000000000 (GENESIS BLOCK)' : e.previous_event_hash}
                        </code>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--accent)' }}>
                        <span style={{ color: 'var(--text-muted)', width: '120px' }}>Current Hash:</span>
                        <code style={{ wordBreak: 'break-all', fontWeight: 600 }}>{e.event_hash}</code>
                      </div>
                    </div>

                    {/* Metadata Collapsible */}
                    <div style={{ marginTop: '0.75rem' }}>
                      <button
                        type="button"
                        onClick={() => setExpandedPayloadId(isExpanded ? null : e.id)}
                        style={{
                          background: 'none',
                          border: 'none',
                          color: 'var(--accent)',
                          fontSize: '0.75rem',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.25rem',
                          padding: '0'
                        }}
                      >
                        {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                        <span>{isExpanded ? 'Hide Canonical Payload' : 'Inspect Canonical Hashed Payload'}</span>
                      </button>

                      {isExpanded && (
                        <pre style={{
                          marginTop: '0.5rem',
                          backgroundColor: '#0f172a',
                          color: '#38bdf8',
                          padding: '0.75rem',
                          borderRadius: 'var(--radius-sm)',
                          fontSize: '0.75rem',
                          overflowX: 'auto',
                          maxHeight: '200px'
                        }}>
                          {JSON.stringify(e.structured_metadata, null, 2)}
                        </pre>
                      )}
                    </div>
                  </div>

                  {/* Chain Link Indicator connecting to next block */}
                  {idx < auditData.events.length - 1 && (
                    <div style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      padding: '0.375rem 0'
                    }}>
                      <div style={{
                        width: '2px',
                        height: '14px',
                        backgroundColor: '#22c55e',
                      }} />
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.25rem',
                        fontSize: '0.6875rem',
                        color: '#15803d',
                        backgroundColor: '#f0fdf4',
                        padding: '2px 8px',
                        borderRadius: 'var(--radius-xs)',
                        border: '1px solid #bbf7d0',
                        fontWeight: 600
                      }}>
                        <LinkIcon size={10} />
                        <span>SHA-256 HASH LINK</span>
                      </div>
                      <div style={{
                        width: '2px',
                        height: '14px',
                        backgroundColor: '#22c55e',
                      }} />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )
      ) : (
        <div className="panel" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
          No audit events matched your filter.
        </div>
      )}
    </div>
  );
};
