import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { 
  AlertTriangle, 
  CheckCircle2, 
  Clock, 
  UserX, 
  Search, 
  Eye, 
  RefreshCw, 
  Lock, 
  ShieldCheck, 
  ChevronLeft, 
  ChevronRight, 
  X, 
  Info
} from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../features/auth/AuthContext';
import { useToast } from '../context/ToastContext';
import type { AdminSecurityAlert } from '../types';

export const SecurityAlertsPage: React.FC = () => {
  const { user } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  // Filters & Pagination State
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [page, setPage] = useState<number>(0);
  const pageSize = 15;

  // Modals State
  const [selectedAlert, setSelectedAlert] = useState<AdminSecurityAlert | null>(null);
  const [isResolveModalOpen, setIsResolveModalOpen] = useState(false);
  const [resolutionNotes, setResolutionNotes] = useState('');
  const [isRevokeModalOpen, setIsRevokeModalOpen] = useState(false);

  // Queries
  const { data: metrics, refetch: refetchMetrics } = useQuery({
    queryKey: ['securityAlertMetrics'],
    queryFn: () => api.getSecurityAlertMetrics(),
    enabled: user?.role === 'admin',
    refetchInterval: 15000,
  });

  const { data: alertList, isLoading, isFetching, refetch: refetchAlerts } = useQuery({
    queryKey: ['securityAlertsList', severityFilter, statusFilter, eventTypeFilter, page],
    queryFn: () => api.listSecurityAlerts({
      severity: severityFilter !== 'all' ? severityFilter : undefined,
      status: statusFilter !== 'all' ? statusFilter : undefined,
      event_type: eventTypeFilter !== 'all' ? eventTypeFilter : undefined,
      skip: page * pageSize,
      limit: pageSize,
    }),
    enabled: user?.role === 'admin',
    refetchInterval: 15000,
  });

  // Mutations
  const acknowledgeMutation = useMutation({
    mutationFn: (alertId: string) => api.acknowledgeSecurityAlert(alertId),
    onSuccess: (updatedAlert) => {
      toast.success(`Alert ${updatedAlert.id.slice(0, 8)} marked under investigation.`);
      queryClient.invalidateQueries({ queryKey: ['securityAlertsList'] });
      queryClient.invalidateQueries({ queryKey: ['securityAlertMetrics'] });
      if (selectedAlert && selectedAlert.id === updatedAlert.id) {
        setSelectedAlert(updatedAlert);
      }
    },
    onError: (err: any) => {
      toast.error(err.message || 'Failed to acknowledge alert.');
    },
  });

  const resolveMutation = useMutation({
    mutationFn: ({ alertId, notes }: { alertId: string; notes: string }) =>
      api.resolveSecurityAlert(alertId, notes),
    onSuccess: (updatedAlert) => {
      toast.success(`Alert ${updatedAlert.id.slice(0, 8)} successfully resolved.`);
      setIsResolveModalOpen(false);
      setResolutionNotes('');
      queryClient.invalidateQueries({ queryKey: ['securityAlertsList'] });
      queryClient.invalidateQueries({ queryKey: ['securityAlertMetrics'] });
      if (selectedAlert && selectedAlert.id === updatedAlert.id) {
        setSelectedAlert(updatedAlert);
      }
    },
    onError: (err: any) => {
      toast.error(err.message || 'Failed to resolve alert.');
    },
  });

  const revokeSessionsMutation = useMutation({
    mutationFn: (alertId: string) => api.revokeUserSessionsForAlert(alertId),
    onSuccess: (data) => {
      toast.success(data.message || 'User sessions terminated successfully.');
      setIsRevokeModalOpen(false);
      queryClient.invalidateQueries({ queryKey: ['securityAlertsList'] });
      queryClient.invalidateQueries({ queryKey: ['securityAlertMetrics'] });
      if (selectedAlert) {
        // Refresh alert details
        api.getSecurityAlertDetails(selectedAlert.id).then((fresh) => {
          setSelectedAlert(fresh);
        }).catch(() => {});
      }
    },
    onError: (err: any) => {
      toast.error(err.message || 'Failed to terminate user sessions.');
    },
  });

  if (user?.role !== 'admin') {
    return (
      <div className="container" style={{ padding: '4rem 0', textAlign: 'center' }}>
        <div className="panel" style={{ maxWidth: '480px', margin: '0 auto', padding: '2.5rem' }}>
          <div style={{
            width: '46px',
            height: '46px',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'var(--danger-bg)',
            border: '1px solid var(--danger-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--danger)',
            margin: '0 auto 1rem',
          }}>
            <Lock size={22} />
          </div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--graphite)', marginBottom: '0.5rem' }}>
            Access Restricted
          </h2>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            Security alerts console is strictly limited to authorized administrative personnel.
          </p>
        </div>
      </div>
    );
  }

  // Filter in-memory by search query (actor email, summary, or ID)
  const alerts = (alertList?.alerts || []).filter((alert) => {
    if (!searchQuery.trim()) return true;
    const query = searchQuery.toLowerCase();
    return (
      alert.id.toLowerCase().includes(query) ||
      alert.summary.toLowerCase().includes(query) ||
      (alert.actor_email && alert.actor_email.toLowerCase().includes(query)) ||
      (alert.target_user_email && alert.target_user_email.toLowerCase().includes(query)) ||
      alert.event_type.toLowerCase().includes(query)
    );
  });

  const totalPages = Math.ceil((alertList?.total || 0) / pageSize);

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev) {
      case 'critical': return 'badge-danger';
      case 'high': return 'badge-copper';
      case 'medium': return 'badge-yellow';
      case 'low': return 'badge-blue';
      default: return 'badge-gray';
    }
  };

  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case 'open': return 'badge-danger';
      case 'investigating': return 'badge-copper';
      case 'resolved': return 'badge-green';
      default: return 'badge-gray';
    }
  };

  const formatTimestamp = (ts: string) => {
    try {
      const d = new Date(ts);
      return d.toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata',
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true,
      }) + ' IST';
    } catch {
      return ts;
    }
  };

  return (
    <div className="container" style={{ maxWidth: '1200px', margin: '0 auto', paddingBottom: '3rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.75rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{
            fontSize: '0.75rem',
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '0.08em',
            color: 'var(--copper-dark)',
            marginBottom: '0.25rem',
          }}>
            Confidential Security Operations
          </div>
          <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--graphite)', letterSpacing: '-0.02em', margin: 0 }}>
            Security Alerts & Detection
          </h1>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.25rem', marginBottom: 0 }}>
            Automated heuristic detection for credential brute-force, unauthorized access spikes, and policy anomalies.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <button
            onClick={() => {
              refetchMetrics();
              refetchAlerts();
            }}
            disabled={isFetching}
            className="btn btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.8125rem' }}
          >
            <RefreshCw size={14} className={isFetching ? 'spin' : ''} />
            <span>Refresh Feed</span>
          </button>
        </div>
      </div>

      {/* Metrics Banner */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '1rem',
        marginBottom: '1.75rem',
      }}>
        <div className="panel" style={{ padding: '1.25rem', borderLeft: '4px solid var(--graphite)' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
            Total Incidents
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--graphite)', marginTop: '0.25rem' }}>
            {metrics?.total_alerts ?? 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Recorded security events
          </div>
        </div>

        <div className="panel" style={{ padding: '1.25rem', borderLeft: '4px solid #B91C1C' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#B91C1C', textTransform: 'uppercase' }}>
            Open Alerts
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#B91C1C', marginTop: '0.25rem' }}>
            {metrics?.open_alerts ?? 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Requiring immediate triage
          </div>
        </div>

        <div className="panel" style={{ padding: '1.25rem', borderLeft: '4px solid #C05621' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--copper-dark)', textTransform: 'uppercase' }}>
            Critical / High
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--copper-dark)', marginTop: '0.25rem' }}>
            {metrics?.critical_alerts ?? 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            High-severity breaches
          </div>
        </div>

        <div className="panel" style={{ padding: '1.25rem', borderLeft: '4px solid #3182CE' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#2B6CB0', textTransform: 'uppercase' }}>
            Investigating
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#2B6CB0', marginTop: '0.25rem' }}>
            {metrics?.investigating_alerts ?? 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Under active administrator review
          </div>
        </div>

        <div className="panel" style={{ padding: '1.25rem', borderLeft: '4px solid #2F855A' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#276749', textTransform: 'uppercase' }}>
            Resolved
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#276749', marginTop: '0.25rem' }}>
            {metrics?.resolved_alerts ?? 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Mitigated & archived
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="panel" style={{ padding: '1rem 1.25rem', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.875rem', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center', flex: 1, minWidth: '280px' }}>
            {/* Search Input */}
            <div style={{ position: 'relative', flex: '1 1 240px', maxWidth: '340px' }}>
              <Search size={15} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                type="text"
                placeholder="Search actor, email, or summary..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="input"
                style={{ paddingLeft: '2.25rem', fontSize: '0.8125rem' }}
              />
            </div>

            {/* Severity Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Severity:</span>
              <select
                value={severityFilter}
                onChange={(e) => {
                  setSeverityFilter(e.target.value);
                  setPage(0);
                }}
                className="input"
                style={{ padding: '0.375rem 0.625rem', fontSize: '0.8125rem', width: 'auto' }}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            {/* Status Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Status:</span>
              <select
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value);
                  setPage(0);
                }}
                className="input"
                style={{ padding: '0.375rem 0.625rem', fontSize: '0.8125rem', width: 'auto' }}
              >
                <option value="all">All Statuses</option>
                <option value="open">Open</option>
                <option value="investigating">Investigating</option>
                <option value="resolved">Resolved</option>
              </select>
            </div>

            {/* Event Type Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Event Type:</span>
              <select
                value={eventTypeFilter}
                onChange={(e) => {
                  setEventTypeFilter(e.target.value);
                  setPage(0);
                }}
                className="input"
                style={{ padding: '0.375rem 0.625rem', fontSize: '0.8125rem', width: 'auto' }}
              >
                <option value="all">All Rule Types</option>
                <option value="auth.repeated_failed_logins">Failed Logins</option>
                <option value="document.repeated_denied_access">Denied Doc Access</option>
                <option value="access_reference.invalid_probe">Invalid Reference Probing</option>
                <option value="permissions.burst_change">Permission Change Burst</option>
                <option value="auth.rapid_sessions">Rapid Session Creation</option>
                <option value="document.cross_owner_probe">Cross-Owner Document Probe</option>
              </select>
            </div>
          </div>

          <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
            Showing <strong>{alerts.length}</strong> incident(s)
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
        {isLoading ? (
          <div style={{ padding: '3.5rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <RefreshCw size={24} className="spin" style={{ margin: '0 auto 0.75rem', display: 'block', color: 'var(--copper)' }} />
            Loading security incident feed...
          </div>
        ) : alerts.length === 0 ? (
          <div style={{ padding: '4rem 2rem', textAlign: 'center' }}>
            <ShieldCheck size={40} style={{ color: '#2F855A', margin: '0 auto 1rem', display: 'block' }} />
            <h3 style={{ fontSize: '1.125rem', fontWeight: 600, color: 'var(--graphite)', marginBottom: '0.25rem' }}>
              No Suspicious Activity Detected
            </h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', maxWidth: '420px', margin: '0 auto' }}>
              No security alerts match the current filter criteria. All telemetry monitors are operational.
            </p>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8125rem' }}>
              <thead>
                <tr style={{ backgroundColor: 'var(--bg-warm)', borderBottom: '1px solid var(--border-color)', color: 'var(--text-secondary)', fontWeight: 600 }}>
                  <th style={{ padding: '0.75rem 1rem' }}>Severity</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Event Type</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Summary</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Actor / Target</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Detected (IST)</th>
                  <th style={{ padding: '0.75rem 1rem' }}>Status</th>
                  <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    style={{
                      borderBottom: '1px solid var(--border-color)',
                      transition: 'background-color 0.15s ease',
                      backgroundColor: alert.status === 'open' ? 'rgba(239, 68, 68, 0.02)' : 'transparent',
                    }}
                  >
                    <td style={{ padding: '0.875rem 1rem', whiteSpace: 'nowrap' }}>
                      <span className={`badge ${getSeverityBadgeClass(alert.severity)}`} style={{ textTransform: 'uppercase', fontSize: '0.6875rem', fontWeight: 700 }}>
                        {alert.severity}
                      </span>
                    </td>
                    <td style={{ padding: '0.875rem 1rem', whiteSpace: 'nowrap', fontFamily: 'monospace', fontSize: '0.75rem', color: 'var(--graphite)' }}>
                      {alert.event_type}
                    </td>
                    <td style={{ padding: '0.875rem 1rem', maxWidth: '320px' }}>
                      <div style={{ fontWeight: 600, color: 'var(--graphite)', marginBottom: '0.125rem' }}>
                        {alert.summary}
                      </div>
                      <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                        ID: {alert.id.slice(0, 8)}...
                      </div>
                    </td>
                    <td style={{ padding: '0.875rem 1rem', whiteSpace: 'nowrap' }}>
                      {alert.actor_email ? (
                        <div>
                          <div style={{ fontWeight: 500, color: 'var(--graphite)' }}>{alert.actor_email}</div>
                          {alert.actor_name && <div style={{ fontSize: '0.6875rem', color: 'var(--text-secondary)' }}>{alert.actor_name}</div>}
                        </div>
                      ) : alert.target_user_email ? (
                        <div>
                          <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>Target: </span>
                          <span style={{ fontWeight: 500, color: 'var(--graphite)' }}>{alert.target_user_email}</span>
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>Unauthenticated actor</span>
                      )}
                    </td>
                    <td style={{ padding: '0.875rem 1rem', whiteSpace: 'nowrap', color: 'var(--text-secondary)' }}>
                      {formatTimestamp(alert.timestamp)}
                    </td>
                    <td style={{ padding: '0.875rem 1rem', whiteSpace: 'nowrap' }}>
                      <span className={`badge ${getStatusBadgeClass(alert.status)}`} style={{ textTransform: 'capitalize', fontSize: '0.6875rem', fontWeight: 600 }}>
                        {alert.status}
                      </span>
                    </td>
                    <td style={{ padding: '0.875rem 1rem', textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <button
                        onClick={() => setSelectedAlert(alert)}
                        className="btn btn-secondary"
                        style={{ padding: '0.3125rem 0.625rem', fontSize: '0.75rem', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}
                      >
                        <Eye size={13} />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Controls */}
        {totalPages > 1 && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0.875rem 1.25rem',
            borderTop: '1px solid var(--border-color)',
            backgroundColor: 'var(--bg-warm)',
          }}>
            <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
              Page {page + 1} of {totalPages}
            </span>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
                className="btn btn-secondary"
                style={{ padding: '0.3125rem 0.625rem', fontSize: '0.75rem' }}
              >
                <ChevronLeft size={14} />
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                className="btn btn-secondary"
                style={{ padding: '0.3125rem 0.625rem', fontSize: '0.75rem' }}
              >
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Alert Investigation Modal */}
      {selectedAlert && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.55)',
          backdropFilter: 'blur(3px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '1.5rem',
        }}>
          <div className="panel" style={{
            width: '100%',
            maxWidth: '720px',
            maxHeight: '90vh',
            overflowY: 'auto',
            padding: 0,
            boxShadow: 'var(--shadow-xl)',
            border: '1px solid var(--copper-border)',
          }}>
            {/* Modal Header */}
            <div style={{
              display: 'flex',
              alignItems: 'flex-start',
              justifyContent: 'space-between',
              padding: '1.25rem 1.5rem',
              borderBottom: '1px solid var(--border-color)',
              backgroundColor: 'var(--bg-warm)',
            }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                  <span className={`badge ${getSeverityBadgeClass(selectedAlert.severity)}`} style={{ textTransform: 'uppercase', fontSize: '0.6875rem' }}>
                    {selectedAlert.severity}
                  </span>
                  <span className={`badge ${getStatusBadgeClass(selectedAlert.status)}`} style={{ textTransform: 'capitalize', fontSize: '0.6875rem' }}>
                    {selectedAlert.status}
                  </span>
                  <span style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    ID: {selectedAlert.id}
                  </span>
                </div>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--graphite)', margin: 0 }}>
                  {selectedAlert.summary}
                </h3>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: '0.25rem' }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {/* Event Metadata Grid */}
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                gap: '1rem',
                backgroundColor: 'var(--bg-warm)',
                padding: '1rem',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border-color)',
                fontSize: '0.8125rem',
              }}>
                <div>
                  <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.6875rem', textTransform: 'uppercase' }}>Event Type</span>
                  <span style={{ fontWeight: 600, fontFamily: 'monospace', color: 'var(--graphite)' }}>{selectedAlert.event_type}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.6875rem', textTransform: 'uppercase' }}>Detected At (IST)</span>
                  <span style={{ fontWeight: 600, color: 'var(--graphite)' }}>{formatTimestamp(selectedAlert.timestamp)}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.6875rem', textTransform: 'uppercase' }}>Actor</span>
                  <span style={{ fontWeight: 600, color: 'var(--graphite)' }}>{selectedAlert.actor_email || selectedAlert.actor_id || 'Anonymous / External'}</span>
                </div>
                {selectedAlert.target_user_email && (
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.6875rem', textTransform: 'uppercase' }}>Target User</span>
                    <span style={{ fontWeight: 600, color: 'var(--graphite)' }}>{selectedAlert.target_user_email}</span>
                  </div>
                )}
                {selectedAlert.target_document_title && (
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.6875rem', textTransform: 'uppercase' }}>Target Document</span>
                    <span style={{ fontWeight: 600, color: 'var(--graphite)' }}>{selectedAlert.target_document_title}</span>
                  </div>
                )}
                {selectedAlert.request_id && (
                  <div>
                    <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.6875rem', textTransform: 'uppercase' }}>Request Correlation ID</span>
                    <span style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'var(--graphite)' }}>{selectedAlert.request_id}</span>
                  </div>
                )}
              </div>

              {/* Investigation Metadata JSON Box */}
              <div>
                <h4 style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--graphite)', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                  <Info size={14} color="var(--copper)" />
                  Investigation Telemetry & Heuristic Proof
                </h4>
                <div style={{
                  backgroundColor: '#1E293B',
                  color: '#F1F5F9',
                  padding: '1rem',
                  borderRadius: 'var(--radius-sm)',
                  fontFamily: 'monospace',
                  fontSize: '0.75rem',
                  overflowX: 'auto',
                  lineHeight: 1.5,
                  maxHeight: '220px',
                }}>
                  <pre style={{ margin: 0 }}>
                    {JSON.stringify(selectedAlert.investigation_metadata, null, 2)}
                  </pre>
                </div>
                <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: '0.375rem', display: 'block' }}>
                  Sensitive values (passwords, tokens, and storage keys) are automatically scrubbed prior to storage.
                </span>
              </div>

              {/* Triage / Resolution History */}
              <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '1rem' }}>
                <h4 style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--graphite)', marginBottom: '0.5rem' }}>
                  Triage History
                </h4>
                <div style={{ fontSize: '0.8125rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {selectedAlert.acknowledged_at ? (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--copper-dark)' }}>
                      <Clock size={14} />
                      <span>Investigated by <strong>{selectedAlert.acknowledged_by_name || 'Admin'}</strong> on {formatTimestamp(selectedAlert.acknowledged_at)}</span>
                    </div>
                  ) : (
                    <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>Pending acknowledgment by security team.</span>
                  )}

                  {selectedAlert.resolved_at && (
                    <div style={{ marginTop: '0.25rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#276749' }}>
                        <CheckCircle2 size={14} />
                        <span>Resolved by <strong>{selectedAlert.resolved_by_name || 'Admin'}</strong> on {formatTimestamp(selectedAlert.resolved_at)}</span>
                      </div>
                      {selectedAlert.resolution_notes && (
                        <div style={{
                          backgroundColor: 'var(--bg-warm)',
                          padding: '0.625rem 0.875rem',
                          borderRadius: 'var(--radius-sm)',
                          marginTop: '0.375rem',
                          border: '1px solid var(--border-color)',
                          color: 'var(--text-primary)',
                        }}>
                          {selectedAlert.resolution_notes}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Modal Actions Footer */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '1rem 1.5rem',
              borderTop: '1px solid var(--border-color)',
              backgroundColor: 'var(--bg-warm)',
              flexWrap: 'wrap',
              gap: '0.75rem',
            }}>
              <div>
                {/* Emergency Session Revocation button if user identified */}
                {(selectedAlert.target_user_id || selectedAlert.actor_id) && (
                  <button
                    onClick={() => setIsRevokeModalOpen(true)}
                    className="btn btn-secondary"
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.375rem',
                      color: 'var(--danger)',
                      borderColor: 'var(--danger-border)',
                      fontSize: '0.8125rem',
                    }}
                  >
                    <UserX size={14} />
                    <span>Revoke User Sessions</span>
                  </button>
                )}
              </div>

              <div style={{ display: 'flex', gap: '0.625rem' }}>
                {selectedAlert.status === 'open' && (
                  <button
                    onClick={() => acknowledgeMutation.mutate(selectedAlert.id)}
                    disabled={acknowledgeMutation.isPending}
                    className="btn btn-secondary"
                    style={{ fontSize: '0.8125rem' }}
                  >
                    Mark Investigating
                  </button>
                )}

                {selectedAlert.status !== 'resolved' && (
                  <button
                    onClick={() => setIsResolveModalOpen(true)}
                    className="btn btn-primary"
                    style={{ fontSize: '0.8125rem', backgroundColor: '#2F855A', borderColor: '#276749' }}
                  >
                    Resolve Incident
                  </button>
                )}

                <button
                  onClick={() => setSelectedAlert(null)}
                  className="btn btn-secondary"
                  style={{ fontSize: '0.8125rem' }}
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Resolution Notes Modal */}
      {isResolveModalOpen && selectedAlert && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.65)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1100,
          padding: '1.5rem',
        }}>
          <div className="panel" style={{ width: '100%', maxWidth: '480px', padding: '1.5rem' }}>
            <h3 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--graphite)', marginBottom: '0.5rem' }}>
              Resolve Security Alert
            </h3>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
              Provide incident findings or remediation notes for audit compliance before closing alert #{selectedAlert.id.slice(0, 8)}.
            </p>

            <textarea
              rows={4}
              value={resolutionNotes}
              onChange={(e) => setResolutionNotes(e.target.value)}
              placeholder="E.g., Investigated probe origins. IP address belongs to internal penetration testing team. Confirmed no compromise."
              className="input"
              style={{ width: '100%', resize: 'vertical', fontSize: '0.8125rem', marginBottom: '1.25rem' }}
            />

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
              <button
                onClick={() => {
                  setIsResolveModalOpen(false);
                  setResolutionNotes('');
                }}
                className="btn btn-secondary"
                style={{ fontSize: '0.8125rem' }}
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  if (resolutionNotes.trim().length < 3) {
                    toast.error('Resolution notes must be at least 3 characters.');
                    return;
                  }
                  resolveMutation.mutate({
                    alertId: selectedAlert.id,
                    notes: resolutionNotes.trim(),
                  });
                }}
                disabled={resolveMutation.isPending || resolutionNotes.trim().length < 3}
                className="btn btn-primary"
                style={{ fontSize: '0.8125rem', backgroundColor: '#2F855A', borderColor: '#276749' }}
              >
                {resolveMutation.isPending ? 'Resolving...' : 'Confirm Resolution'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Revoke Sessions Confirmation Modal */}
      {isRevokeModalOpen && selectedAlert && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.65)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1100,
          padding: '1.5rem',
        }}>
          <div className="panel" style={{ width: '100%', maxWidth: '480px', padding: '1.5rem' }}>
            <div style={{
              width: '42px',
              height: '42px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--danger-bg)',
              border: '1px solid var(--danger-border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--danger)',
              marginBottom: '1rem',
            }}>
              <AlertTriangle size={22} />
            </div>

            <h3 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--graphite)', marginBottom: '0.5rem' }}>
              Revoke User's Active Sessions?
            </h3>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '1.25rem' }}>
              This will immediately terminate all active authentication sessions and tokens for user{' '}
              <strong>{selectedAlert.target_user_email || selectedAlert.actor_email || selectedAlert.target_user_id || selectedAlert.actor_id}</strong>.
              The user will be required to re-authenticate. This action is logged to the immutable audit chain.
            </p>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
              <button
                onClick={() => setIsRevokeModalOpen(false)}
                className="btn btn-secondary"
                style={{ fontSize: '0.8125rem' }}
              >
                Cancel
              </button>
              <button
                onClick={() => revokeSessionsMutation.mutate(selectedAlert.id)}
                disabled={revokeSessionsMutation.isPending}
                className="btn btn-danger-solid"
                style={{ fontSize: '0.8125rem', backgroundColor: '#B91C1C', color: '#FFFFFF', borderColor: '#991B1B' }}
              >
                {revokeSessionsMutation.isPending ? 'Terminating...' : 'Terminate All Sessions'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
