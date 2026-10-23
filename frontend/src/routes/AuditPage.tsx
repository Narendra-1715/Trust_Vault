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
      {/* ================= TOP PAGE HEADER ================= */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '1.5rem',
        flexWrap: 'wrap',
        gap: '1rem',
      }}>
        <div>
          <div style={{
            fontSize: '0.75rem',
            fontWeight: 700,
            textTransform: 'uppercase',
            color: 'var(--copper-dark)',
            letterSpacing: '0.06em',
            marginBottom: '0.25rem',
          }}>
            Compliance &amp; Non-Repudiation
          </div>
          <h1 style={{
            fontSize: '1.625rem',
            fontWeight: 700,
            letterSpacing: '-0.025em',
            color: 'var(--graphite)',
            margin: 0,
          }}>
            Immutable Audit Ledger
          </h1>
          <p style={{
            fontSize: '0.875rem',
            color: 'var(--text-secondary)',
            marginTop: '0.25rem',
            margin: '0.25rem 0 0',
          }}>
            Tamper-evident chronological event stream secured by deterministic SHA-256 canonical hash chaining.
          </p>
        </div>

        <button
          className="btn btn-primary"
          onClick={() => verifyMutation.mutate()}
          disabled={verifyMutation.isPending}
          style={{ padding: '0.5625rem 1rem' }}
        >
          <RefreshCw size={15} color="var(--copper)" className={verifyMutation.isPending ? 'spin' : ''} />
          <span>{verifyMutation.isPending ? 'Verifying Hash Chain...' : 'Verify Ledger Integrity'}</span>
        </button>
      </div>

      {/* ================= CRYPTOGRAPHIC VERIFICATION BANNER ================= */}
      {verificationReport && (
        <div style={{
          backgroundColor: verificationReport.is_valid ? 'var(--success-bg)' : 'var(--danger-bg)',
          border: `1px solid ${verificationReport.is_valid ? 'var(--success-border)' : 'var(--danger-border)'}`,
          borderRadius: 'var(--radius-lg)',
          padding: '1.25rem 1.5rem',
          marginBottom: '1.5rem',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '1rem',
          boxShadow: 'var(--shadow-sm)',
        }}>
          {verificationReport.is_valid ? (
            <CheckCircle size={22} style={{ color: 'var(--success)', marginTop: '0.125rem', flexShrink: 0 }} />
          ) : (
            <AlertTriangle size={22} style={{ color: 'var(--danger)', marginTop: '0.125rem', flexShrink: 0 }} />
          )}

          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 700, fontSize: '0.9375rem', color: verificationReport.is_valid ? 'var(--success)' : 'var(--danger)' }}>
              {verificationReport.is_valid
                ? 'Cryptographic Ledger Integrity Confirmed'
                : 'INTEGRITY ALERT: Tampering Detected in Audit Ledger'}
            </div>

            <p style={{ fontSize: '0.8125rem', color: 'var(--text-primary)', marginTop: '0.25rem', margin: '0.25rem 0 0', lineHeight: 1.5 }}>
              {verificationReport.is_valid ? (
                `Verified all ${verificationReport.total_events} consecutive audit records from genesis block forward. Every link matches and canonical SHA-256 payload digests are mathematically intact.`
              ) : (
                `Chain break detected at event record ${verificationReport.tampered_event_id}. Detail: ${verificationReport.error_reason}`
              )}
            </p>
          </div>
        </div>
      )}

      {/* ================= FILTERS & VIEW MODE CONTROLS ================= */}
      <div className="panel" style={{ padding: '0.75rem 1rem', marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap', flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Filter size={14} color="var(--text-muted)" />
              <select
                className="input-field"
                value={outcomeFilter}
                onChange={(e) => setOutcomeFilter(e.target.value)}
                style={{ width: 'auto', padding: '0.35rem 0.75rem', fontSize: '0.8125rem' }}
              >
                <option value="">All Outcomes</option>
                <option value="success">Success</option>
                <option value="denied">Denied / Forbidden</option>
                <option value="failure">Failure / Error</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, minWidth: '200px' }}>
              <input
                type="text"
                className="input-field"
                placeholder="Filter by action (e.g. document.download, permission.revoke)..."
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
                style={{ padding: '0.35rem 0.75rem', fontSize: '0.8125rem' }}
              />
            </div>
          </div>

          {/* Segmented View Mode Toggle */}
          <div style={{
            display: 'inline-flex',
            backgroundColor: 'var(--bg-surface-secondary)',
            padding: '3px',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border)',
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
                color: viewMode === 'table' ? 'var(--graphite)' : 'var(--text-secondary)',
                backgroundColor: viewMode === 'table' ? 'var(--bg-surface)' : 'transparent',
                border: viewMode === 'table' ? '1px solid var(--border)' : 'none',
                borderRadius: 'var(--radius-xs)',
                cursor: 'pointer',
                boxShadow: viewMode === 'table' ? 'var(--shadow-sm)' : 'none',
                transition: 'all 0.15s ease',
              }}
            >
              <TableIcon size={13} color={viewMode === 'table' ? 'var(--copper-dark)' : 'currentColor'} />
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
                color: viewMode === 'chain' ? 'var(--graphite)' : 'var(--text-secondary)',
                backgroundColor: viewMode === 'chain' ? 'var(--bg-surface)' : 'transparent',
                border: viewMode === 'chain' ? '1px solid var(--border)' : 'none',
                borderRadius: 'var(--radius-xs)',
                cursor: 'pointer',
                boxShadow: viewMode === 'chain' ? 'var(--shadow-sm)' : 'none',
                transition: 'all 0.15s ease',
              }}
            >
              <Layers size={13} color={viewMode === 'chain' ? 'var(--copper-dark)' : 'currentColor'} />
              <span>Block Explorer</span>
            </button>
          </div>
        </div>
      </div>

      {/* ================= EVENTS PRESENTATION ================= */}
      {isLoading ? (
        <div className="panel" style={{ textAlign: 'center', padding: '3.5rem', color: 'var(--text-muted)' }}>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
            <span className="pulse-dot" style={{ backgroundColor: 'var(--copper)', width: '10px', height: '10px' }}></span>
            <span style={{ fontSize: '0.875rem' }}>Loading audit events...</span>
          </div>
        </div>
      ) : auditData?.events && auditData.events.length > 0 ? (
        viewMode === 'table' ? (
          /* ================= COMPLIANCE TABLE VIEW ================= */
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp (IST)</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>Target Resource</th>
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
                      <span style={{ 
                        fontWeight: 600, 
                        fontFamily: 'var(--font-mono)', 
                        fontSize: '0.8125rem',
                        color: 'var(--graphite)',
                      }}>
                        {e.action}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.8125rem' }}>
                      {e.actor_email ? (
                        <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{e.actor_email}</span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>System / Anonymous</span>
                      )}
                    </td>
                    <td>
                      <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
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
                    <td style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                      <span title={`Previous Hash: ${e.previous_event_hash}\nCurrent Hash: ${e.event_hash}`}>
                        {e.event_hash.substring(0, 16)}...
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          /* ================= CRYPTOGRAPHIC BLOCK EXPLORER ================= */
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'space-between',
              padding: '0.75rem 1rem', 
              backgroundColor: 'var(--graphite)', 
              color: '#F6F3F0',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-dark)',
              fontSize: '0.8125rem',
              boxShadow: 'var(--shadow-sm)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <ShieldCheck size={16} color="var(--copper)" />
                <span><strong>SHA-256 Canonical Chaining:</strong> Every block hashes its canonical JSON payload concatenated with the previous block's digest.</span>
              </div>
              <span className="badge badge-copper" style={{ textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Immutable Ledger
              </span>
            </div>

            {auditData.events.map((e, idx) => {
              const isExpanded = expandedPayloadId === e.id;
              return (
                <div key={e.id} style={{ display: 'flex', flexDirection: 'column', alignItems: 'stretch' }}>
                  {/* Block Panel */}
                  <div className="panel" style={{
                    padding: '1.25rem',
                    backgroundColor: 'var(--bg-surface)',
                  }}>
                    {/* Top Row: Block Number, Action, Timestamp */}
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.875rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
                        <span style={{
                          backgroundColor: 'var(--graphite)',
                          color: 'var(--copper)',
                          padding: '0.2rem 0.5rem',
                          borderRadius: 'var(--radius-xs)',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.75rem',
                          fontWeight: 700,
                          letterSpacing: '0.04em',
                        }}>
                          BLOCK #{auditData.events.length - idx}
                        </span>

                        <span style={{ fontWeight: 700, fontSize: '0.9375rem', color: 'var(--graphite)', fontFamily: 'var(--font-mono)' }}>
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

                    {/* Actor, Resource, and Request Details */}
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem', marginBottom: '1rem', fontSize: '0.8125rem' }}>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Actor: </span>
                        <strong>{e.actor_email || 'System / Anonymous'}</strong>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Target Resource: </span>
                        <strong>{e.resource_type}</strong> {e.resource_id && <code style={{ fontSize: '0.75rem' }}>({e.resource_id.substring(0, 10)}...)</code>}
                      </div>
                      {e.request_id && (
                        <div>
                          <span style={{ color: 'var(--text-muted)' }}>Request ID: </span>
                          <code style={{ fontSize: '0.75rem' }}>{e.request_id.substring(0, 16)}</code>
                        </div>
                      )}
                    </div>

                    {/* Cryptographic Hash Pair Box */}
                    <div style={{
                      backgroundColor: 'var(--bg-surface-secondary)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '0.75rem 1rem',
                      fontSize: '0.75rem',
                      fontFamily: 'var(--font-mono)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.375rem',
                      border: '1px solid var(--border-subtle)',
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-secondary)' }}>
                        <span style={{ color: 'var(--text-muted)', width: '120px', flexShrink: 0 }}>Previous Hash:</span>
                        <code style={{ wordBreak: 'break-all', color: e.previous_event_hash === '0'.repeat(64) ? 'var(--success)' : 'inherit' }}>
                          {e.previous_event_hash === '0'.repeat(64) ? '0x0000000000000000 (GENESIS BLOCK)' : e.previous_event_hash}
                        </code>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--copper-dark)' }}>
                        <span style={{ color: 'var(--text-muted)', width: '120px', flexShrink: 0 }}>Current Hash:</span>
                        <code style={{ wordBreak: 'break-all', fontWeight: 600 }}>{e.event_hash}</code>
                      </div>
                    </div>

                    {/* Canonical Payload Inspector Collapsible */}
                    <div style={{ marginTop: '0.75rem' }}>
                      <button
                        type="button"
                        onClick={() => setExpandedPayloadId(isExpanded ? null : e.id)}
                        style={{
                          background: 'none',
                          border: 'none',
                          color: 'var(--copper-dark)',
                          fontSize: '0.75rem',
                          fontWeight: 600,
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.25rem',
                          padding: '0',
                        }}
                      >
                        {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                        <span>{isExpanded ? 'Hide Canonical Payload' : 'Inspect Canonical Hashed Payload'}</span>
                      </button>

                      {isExpanded && (
                        <pre style={{
                          marginTop: '0.5rem',
                          backgroundColor: 'var(--graphite)',
                          color: 'var(--copper)',
                          padding: '0.875rem',
                          borderRadius: 'var(--radius-sm)',
                          fontSize: '0.75rem',
                          fontFamily: 'var(--font-mono)',
                          overflowX: 'auto',
                          maxHeight: '220px',
                          border: '1px solid var(--border-dark)',
                        }}>
                          {JSON.stringify(e.structured_metadata, null, 2)}
                        </pre>
                      )}
                    </div>
                  </div>

                  {/* Cryptographic Link Visual between blocks */}
                  {idx < auditData.events.length - 1 && (
                    <div style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      padding: '0.25rem 0',
                    }}>
                      <div style={{
                        width: '2px',
                        height: '12px',
                        backgroundColor: 'var(--copper)',
                      }} />
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.25rem',
                        fontSize: '0.625rem',
                        color: 'var(--copper-dark)',
                        backgroundColor: 'var(--copper-light)',
                        padding: '1px 8px',
                        borderRadius: 'var(--radius-xs)',
                        border: '1px solid var(--copper-border)',
                        fontWeight: 700,
                        letterSpacing: '0.04em',
                      }}>
                        <LinkIcon size={10} />
                        <span>SHA-256 HASH LINK</span>
                      </div>
                      <div style={{
                        width: '2px',
                        height: '12px',
                        backgroundColor: 'var(--copper)',
                      }} />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )
      ) : (
        <div className="panel" style={{ textAlign: 'center', padding: '3.5rem 1rem', color: 'var(--text-muted)' }}>
          No audit events matched your filter.
        </div>
      )}
    </div>
  );
};
