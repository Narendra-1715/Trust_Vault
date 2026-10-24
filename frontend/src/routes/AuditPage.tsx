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
  Clock,
  Download,
  Calendar,
  ChevronLeft,
  FileText,
  KeyRound,
  ShieldAlert,
  Lock,
  RotateCcw
} from 'lucide-react';
import { api } from '../lib/api';
import { formatToIST } from '../lib/date';
import { useToast } from '../context/ToastContext';
import type { AuditVerificationReport } from '../types';

const getActionBadgeStyle = (action: string) => {
  if (action.includes('delete') || action.includes('revok') || action.includes('denied') || action.includes('failed')) {
    return {
      backgroundColor: '#fef2f2',
      color: '#991b1b',
      border: '1px solid #fecaca',
    };
  }
  if (action.includes('upload') || action.includes('grant') || action.includes('approve') || action.includes('restore')) {
    return {
      backgroundColor: '#ecfdf5',
      color: '#065f46',
      border: '1px solid #a7f3d0',
    };
  }
  if (action.includes('download') || action.includes('preview') || action.includes('version')) {
    return {
      backgroundColor: '#eff6ff',
      color: '#1e40af',
      border: '1px solid #bfdbfe',
    };
  }
  if (action.includes('alert') || action.includes('emergency')) {
    return {
      backgroundColor: '#fffbeb',
      color: '#92400e',
      border: '1px solid #fde68a',
    };
  }
  return {
    backgroundColor: 'var(--bg-surface-secondary)',
    color: 'var(--graphite)',
    border: '1px solid var(--border)',
  };
};

export const AuditPage: React.FC = () => {
  const { toast } = useToast();
  const [viewMode, setViewMode] = useState<'table' | 'chain'>('table');
  const [categoryTab, setCategoryTab] = useState<'all' | 'documents' | 'permissions' | 'security' | 'auth'>('all');
  const [actionFilter, setActionFilter] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [isExporting, setIsExporting] = useState(false);
  const [verificationReport, setVerificationReport] = useState<AuditVerificationReport | null>(null);
  const [expandedPayloadId, setExpandedPayloadId] = useState<string | null>(null);

  // Compute query action based on tab and custom filter
  const effectiveAction = actionFilter || (
    categoryTab === 'documents' ? 'document' :
    categoryTab === 'permissions' ? 'permission' :
    categoryTab === 'security' ? 'alert' :
    categoryTab === 'auth' ? 'auth' : undefined
  );

  const hasActiveFilters = categoryTab !== 'all' || Boolean(actionFilter) || Boolean(outcomeFilter) || Boolean(dateFrom) || Boolean(dateTo);

  const handleResetFilters = () => {
    setCategoryTab('all');
    setActionFilter('');
    setOutcomeFilter('');
    setDateFrom('');
    setDateTo('');
    setPage(1);
  };

  const handleTabChange = (tab: typeof categoryTab) => {
    setCategoryTab(tab);
    setActionFilter('');
    setPage(1);
  };

  // Queries
  const { data: auditData, isLoading, refetch } = useQuery({
    queryKey: ['auditEvents', categoryTab, actionFilter, outcomeFilter, dateFrom, dateTo, page, pageSize],
    queryFn: () => api.listAuditEvents({
      action: effectiveAction,
      outcome: outcomeFilter || undefined,
      date_from: dateFrom ? new Date(dateFrom).toISOString() : undefined,
      date_to: dateTo ? new Date(dateTo + 'T23:59:59').toISOString() : undefined,
      page,
      page_size: pageSize,
    }),
  });

  const totalEvents = auditData?.total || 0;
  const totalPages = Math.max(1, Math.ceil(totalEvents / pageSize));

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

  const handleExport = async (format: 'csv' | 'json') => {
    setIsExporting(true);
    try {
      await api.exportAuditLog({
        format,
        action: actionFilter || undefined,
        outcome: outcomeFilter || undefined,
        date_from: dateFrom ? new Date(dateFrom).toISOString() : undefined,
        date_to: dateTo ? new Date(dateTo + 'T23:59:59').toISOString() : undefined,
      });
      toast.success(`Audit log exported as ${format.toUpperCase()}.`);
    } catch (err: any) {
      toast.error(err.message || 'Export failed');
    } finally {
      setIsExporting(false);
    }
  };

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

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'inline-flex', borderRadius: 'var(--radius-sm)', overflow: 'hidden', border: '1px solid var(--border)' }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => handleExport('csv')}
              disabled={isExporting}
              style={{ gap: '0.375rem', borderRadius: 0, border: 'none', borderRight: '1px solid var(--border)' }}
              title="Export sanitized CSV log (DDE formula injection protected)"
            >
              <Download size={13} color="var(--copper-dark)" />
              <span>{isExporting ? 'Exporting...' : 'Export CSV'}</span>
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => handleExport('json')}
              disabled={isExporting}
              style={{ gap: '0.375rem', borderRadius: 0, border: 'none' }}
              title="Export raw JSON log"
            >
              <Download size={13} color="var(--copper-dark)" />
              <span>JSON</span>
            </button>
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

      {/* ================= CATEGORY TABS ================= */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
        <button
          type="button"
          onClick={() => handleTabChange('all')}
          className={`btn ${categoryTab === 'all' ? 'btn-primary' : 'btn-secondary'}`}
          style={{ fontSize: '0.8125rem', padding: '0.4rem 0.875rem' }}
        >
          <span>All Events</span>
          {categoryTab === 'all' && totalEvents > 0 && (
            <span className="badge" style={{ backgroundColor: 'rgba(0,0,0,0.2)', color: '#fff', fontSize: '0.6875rem', padding: '0.1rem 0.35rem', marginLeft: '0.25rem' }}>
              {totalEvents}
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => handleTabChange('documents')}
          className={`btn ${categoryTab === 'documents' ? 'btn-primary' : 'btn-secondary'}`}
          style={{
            fontSize: '0.8125rem',
            padding: '0.4rem 0.875rem',
            backgroundColor: categoryTab === 'documents' ? 'var(--copper)' : undefined,
            color: categoryTab === 'documents' ? '#fff' : undefined,
            borderColor: categoryTab === 'documents' ? 'var(--copper)' : undefined,
            gap: '0.35rem'
          }}
        >
          <FileText size={14} />
          <span>Document Operations (Uploads & Deletions)</span>
          {categoryTab === 'documents' && totalEvents > 0 && (
            <span className="badge" style={{ backgroundColor: 'rgba(0,0,0,0.2)', color: '#fff', fontSize: '0.6875rem', padding: '0.1rem 0.35rem', marginLeft: '0.25rem' }}>
              {totalEvents}
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => handleTabChange('permissions')}
          className={`btn ${categoryTab === 'permissions' ? 'btn-primary' : 'btn-secondary'}`}
          style={{
            fontSize: '0.8125rem',
            padding: '0.4rem 0.875rem',
            backgroundColor: categoryTab === 'permissions' ? 'var(--copper)' : undefined,
            color: categoryTab === 'permissions' ? '#fff' : undefined,
            borderColor: categoryTab === 'permissions' ? 'var(--copper)' : undefined,
            gap: '0.35rem'
          }}
        >
          <KeyRound size={14} />
          <span>Access & Permissions</span>
          {categoryTab === 'permissions' && totalEvents > 0 && (
            <span className="badge" style={{ backgroundColor: 'rgba(0,0,0,0.2)', color: '#fff', fontSize: '0.6875rem', padding: '0.1rem 0.35rem', marginLeft: '0.25rem' }}>
              {totalEvents}
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => handleTabChange('security')}
          className={`btn ${categoryTab === 'security' ? 'btn-primary' : 'btn-secondary'}`}
          style={{
            fontSize: '0.8125rem',
            padding: '0.4rem 0.875rem',
            backgroundColor: categoryTab === 'security' ? 'var(--copper)' : undefined,
            color: categoryTab === 'security' ? '#fff' : undefined,
            borderColor: categoryTab === 'security' ? 'var(--copper)' : undefined,
            gap: '0.35rem'
          }}
        >
          <ShieldAlert size={14} />
          <span>Security & Alerts</span>
          {categoryTab === 'security' && totalEvents > 0 && (
            <span className="badge" style={{ backgroundColor: 'rgba(0,0,0,0.2)', color: '#fff', fontSize: '0.6875rem', padding: '0.1rem 0.35rem', marginLeft: '0.25rem' }}>
              {totalEvents}
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => handleTabChange('auth')}
          className={`btn ${categoryTab === 'auth' ? 'btn-primary' : 'btn-secondary'}`}
          style={{
            fontSize: '0.8125rem',
            padding: '0.4rem 0.875rem',
            backgroundColor: categoryTab === 'auth' ? 'var(--copper)' : undefined,
            color: categoryTab === 'auth' ? '#fff' : undefined,
            borderColor: categoryTab === 'auth' ? 'var(--copper)' : undefined,
            gap: '0.35rem'
          }}
        >
          <Lock size={14} />
          <span>Logins & Sessions</span>
          {categoryTab === 'auth' && totalEvents > 0 && (
            <span className="badge" style={{ backgroundColor: 'rgba(0,0,0,0.2)', color: '#fff', fontSize: '0.6875rem', padding: '0.1rem 0.35rem', marginLeft: '0.25rem' }}>
              {totalEvents}
            </span>
          )}
        </button>
      </div>

      {/* ================= FILTERS & VIEW MODE CONTROLS ================= */}
      <div className="panel" style={{ padding: '0.75rem 1rem', marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap', flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Filter size={14} color="var(--text-muted)" />
              <select
                className="input-field"
                value={outcomeFilter}
                onChange={(e) => {
                  setOutcomeFilter(e.target.value);
                  setPage(1);
                }}
                style={{ width: 'auto', padding: '0.35rem 0.75rem', fontSize: '0.8125rem' }}
              >
                <option value="">All Outcomes</option>
                <option value="success">Success</option>
                <option value="denied">Denied / Forbidden</option>
                <option value="failure">Failure / Error</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, minWidth: '180px' }}>
              <select
                className="input-field"
                value={actionFilter}
                onChange={(e) => {
                  setActionFilter(e.target.value);
                  setPage(1);
                }}
                style={{ width: '100%', padding: '0.35rem 0.75rem', fontSize: '0.8125rem' }}
              >
                <option value="">{categoryTab === 'all' ? 'All Action Types' : `All in ${categoryTab}`}</option>
                <optgroup label="Document Lifecycle">
                  <option value="document.upload">document.upload (Creation & Upload)</option>
                  <option value="document.delete">document.delete (Destruction & Purge)</option>
                  <option value="document.download">document.download (Authorized Download)</option>
                  <option value="document.download.denied">document.download.denied (Unauthorized Attempt)</option>
                  <option value="document.version.create">document.version.create (Version Revision)</option>
                  <option value="document.preview">document.preview (In-App View)</option>
                </optgroup>
                <optgroup label="Access & Sharing">
                  <option value="permission.grant">permission.grant (Access Granted)</option>
                  <option value="permission.revoke">permission.revoke (Access Revoked)</option>
                  <option value="access_request.create">access_request.create</option>
                  <option value="access_request.approve">access_request.approve</option>
                  <option value="access_request.reject">access_request.reject</option>
                  <option value="access_review.decision">access_review.decision (Access Review)</option>
                </optgroup>
                <optgroup label="Security & Administration">
                  <option value="emergency_access.activated">emergency_access.activated (Break-Glass)</option>
                  <option value="emergency_access.revoked">emergency_access.revoked</option>
                  <option value="emergency_access.reviewed">emergency_access.reviewed</option>
                  <option value="alert.created">alert.created (Security Detection)</option>
                  <option value="backup.create">backup.create</option>
                  <option value="backup.restore">backup.restore</option>
                </optgroup>
                <optgroup label="Authentication & Sessions">
                  <option value="auth.login.success">auth.login.success</option>
                  <option value="auth.login.failed">auth.login.failed</option>
                  <option value="session.created">session.created</option>
                  <option value="session.revoked_all">session.revoked_all</option>
                </optgroup>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              <Calendar size={13} />
              <input
                type="date"
                className="input-field"
                value={dateFrom}
                onChange={(e) => setDateFrom(e.target.value)}
                style={{ padding: '0.3rem 0.5rem', fontSize: '0.75rem', width: '130px' }}
                title="Events From"
              />
              <span>to</span>
              <input
                type="date"
                className="input-field"
                value={dateTo}
                onChange={(e) => {
                  setDateTo(e.target.value);
                  setPage(1);
                }}
                style={{ padding: '0.3rem 0.5rem', fontSize: '0.75rem', width: '130px' }}
                title="Events To"
              />
            </div>

            {hasActiveFilters && (
              <button
                type="button"
                onClick={handleResetFilters}
                className="btn btn-secondary btn-sm"
                style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem', gap: '0.25rem' }}
                title="Reset all filters"
              >
                <RotateCcw size={12} />
                <span>Reset</span>
              </button>
            )}
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
        <>
          {viewMode === 'table' ? (
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
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.25rem',
                          fontWeight: 600, 
                          fontFamily: 'var(--font-mono)', 
                          fontSize: '0.75rem',
                          padding: '0.2rem 0.5rem',
                          borderRadius: 'var(--radius-xs)',
                          ...getActionBadgeStyle(e.action)
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
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
                          {e.structured_metadata?.title || e.structured_metadata?.filename ? (
                            <span style={{ fontWeight: 600, fontSize: '0.8125rem', color: 'var(--graphite)', wordBreak: 'break-word' }}>
                              {e.structured_metadata.title || e.structured_metadata.filename}
                            </span>
                          ) : e.structured_metadata?.target_user_email ? (
                            <span style={{ fontWeight: 600, fontSize: '0.8125rem', color: 'var(--graphite)' }}>
                              User: {e.structured_metadata.target_user_email}
                            </span>
                          ) : e.structured_metadata?.email ? (
                            <span style={{ fontWeight: 600, fontSize: '0.8125rem', color: 'var(--graphite)' }}>
                              {e.structured_metadata.email}
                            </span>
                          ) : null}
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                            {e.resource_type} {e.resource_id ? `(${e.resource_id.substring(0, 8)}...)` : ''}
                          </span>
                        </div>
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
                const blockNumber = totalEvents - ((page - 1) * pageSize + idx);
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
                            BLOCK #{blockNumber}
                          </span>

                          <span style={{ 
                            fontWeight: 700, 
                            fontSize: '0.875rem', 
                            fontFamily: 'var(--font-mono)',
                            padding: '0.2rem 0.5rem',
                            borderRadius: 'var(--radius-xs)',
                            ...getActionBadgeStyle(e.action)
                          }}>
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
                          {e.structured_metadata?.title || e.structured_metadata?.filename ? (
                            <strong style={{ color: 'var(--graphite)' }}>
                              {e.structured_metadata.title || e.structured_metadata.filename}{' '}
                            </strong>
                          ) : (
                            <strong>{e.resource_type}{' '}</strong>
                          )}
                          {e.resource_id && <code style={{ fontSize: '0.75rem' }}>({e.resource_type} · {e.resource_id.substring(0, 10)}...)</code>}
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
          )}

          {/* ================= PAGINATION CONTROLS ================= */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginTop: '1.25rem',
            padding: '0.875rem 1.25rem',
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-md)',
            boxShadow: 'var(--shadow-sm)',
            flexWrap: 'wrap',
            gap: '1rem',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                Showing <strong>{totalEvents === 0 ? 0 : (page - 1) * pageSize + 1}</strong> to{' '}
                <strong>{Math.min(page * pageSize, totalEvents)}</strong> of <strong>{totalEvents}</strong> events
              </span>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                <span>Per page:</span>
                <select
                  value={pageSize}
                  onChange={(e) => {
                    setPageSize(Number(e.target.value));
                    setPage(1);
                  }}
                  className="input-field"
                  style={{ width: 'auto', padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                >
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                style={{ padding: '0.35rem 0.65rem', gap: '0.25rem' }}
              >
                <ChevronLeft size={14} />
                <span>Previous</span>
              </button>

              <span style={{ fontSize: '0.8125rem', color: 'var(--text-primary)', fontWeight: 600, padding: '0 0.5rem' }}>
                Page {page} of {totalPages}
              </span>

              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                style={{ padding: '0.35rem 0.65rem', gap: '0.25rem' }}
              >
                <span>Next</span>
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        </>
      ) : (
        <div className="panel" style={{ textAlign: 'center', padding: '3.5rem 1rem', color: 'var(--text-muted)' }}>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.75rem' }}>
            <FileText size={36} color="var(--border-dark)" />
            <div style={{ fontWeight: 600, fontSize: '1rem', color: 'var(--graphite)' }}>No audit events found</div>
            <p style={{ fontSize: '0.8125rem', maxWidth: '400px', margin: 0 }}>
              {hasActiveFilters 
                ? 'No events match the selected filters or category. Try clearing filters to view all recorded ledger entries.'
                : 'No audit records have been generated yet.'}
            </p>
            {hasActiveFilters && (
              <button
                type="button"
                onClick={handleResetFilters}
                className="btn btn-secondary btn-sm"
                style={{ marginTop: '0.5rem', gap: '0.25rem' }}
              >
                <RotateCcw size={12} />
                <span>Reset Filters</span>
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
