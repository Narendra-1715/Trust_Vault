import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, CheckCircle, RefreshCw, Lock } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../features/auth/AuthContext';
import { useToast } from '../context/ToastContext';
import type { AuditVerificationReport } from '../types';

export const AdminPage: React.FC = () => {
  const { user } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [verificationReport, setVerificationReport] = useState<AuditVerificationReport | null>(null);

  // Queries
  const { data: allUsers, refetch: refetchUsers } = useQuery({
    queryKey: ['adminUsers'],
    queryFn: () => api.listAllUsersAdmin(),
  });

  const { data: adminDocs } = useQuery({
    queryKey: ['adminDocs'],
    queryFn: () => api.listDocuments({ admin_inventory: true }),
  });

  const { data: auditEvents } = useQuery({
    queryKey: ['adminAuditEvents'],
    queryFn: () => api.listAuditEvents({ page_size: 100 }),
  });

  // Verify Audit Chain Mutation
  const verifyMutation = useMutation({
    mutationFn: () => api.verifyAuditIntegrity(),
    onSuccess: (data) => {
      setVerificationReport(data);
      if (data.is_valid) {
        toast.success(`Audit integrity verified: all ${data.total_events} events valid.`);
      } else {
        toast.error(`Audit chain corrupted at index ${data.event_index}!`);
      }
    },
    onError: (err: any) => toast.error(err.message || 'Verification failed'),
  });

  // Update User Role/Status Mutation
  const updateUserMutation = useMutation({
    mutationFn: ({ userId, data }: { userId: string; data: { role?: string; is_active?: boolean } }) =>
      api.updateUserRoleStatus(userId, data),
    onSuccess: () => {
      refetchUsers();
      queryClient.invalidateQueries({ queryKey: ['adminAuditEvents'] });
      toast.success('User status/role updated successfully.');
    },
    onError: (err: any) => toast.error(err.message || 'Update failed'),
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
            Administrative privilege required to view the security operations console.
          </p>
        </div>
      </div>
    );
  }

  // Real Database Metrics Calculation
  const totalUsers = allUsers?.length || 0;
  const activeUsers = allUsers?.filter(u => u.is_active).length || 0;
  const totalDocs = adminDocs?.total || 0;
  const totalAuditEvents = auditEvents?.total || 0;
  const deniedAttempts = auditEvents?.events?.filter(e => e.outcome === 'denied').length || 0;

  return (
    <div className="container">
      {/* Page Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.75rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{
            fontSize: '0.75rem',
            fontWeight: 700,
            textTransform: 'uppercase',
            color: 'var(--copper-dark)',
            letterSpacing: '0.06em',
            marginBottom: '0.25rem',
          }}>
            System Operational Console
          </div>
          <h1 style={{ fontSize: '1.625rem', fontWeight: 700, letterSpacing: '-0.025em', color: 'var(--graphite)', margin: 0 }}>
            Security Administration
          </h1>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginTop: '0.25rem', margin: '0.25rem 0 0' }}>
            User management, operational directory inspection, and cryptographic audit ledger verification.
          </p>
        </div>

        <button
          className="btn btn-primary"
          onClick={() => verifyMutation.mutate()}
          disabled={verifyMutation.isPending}
          style={{ padding: '0.5625rem 1rem' }}
        >
          <RefreshCw size={15} color="var(--copper)" className={verifyMutation.isPending ? 'spin' : ''} />
          <span>{verifyMutation.isPending ? 'Verifying Chain...' : 'Verify Cryptographic Audit Chain'}</span>
        </button>
      </div>

      {/* Verification Status Banner */}
      {verificationReport && (
        <div style={{
          backgroundColor: verificationReport.is_valid ? 'var(--success-bg)' : 'var(--danger-bg)',
          border: `1px solid ${verificationReport.is_valid ? 'var(--success-border)' : 'var(--danger-border)'}`,
          borderRadius: 'var(--radius-lg)',
          padding: '1.25rem 1.5rem',
          marginBottom: '1.75rem',
          display: 'flex',
          alignItems: 'center',
          gap: '1rem',
          boxShadow: 'var(--shadow-sm)',
        }}>
          {verificationReport.is_valid ? (
            <CheckCircle size={22} style={{ color: 'var(--success)', flexShrink: 0 }} />
          ) : (
            <AlertTriangle size={22} style={{ color: 'var(--danger)', flexShrink: 0 }} />
          )}

          <div>
            <div style={{ fontWeight: 700, fontSize: '0.9375rem', color: verificationReport.is_valid ? 'var(--success)' : 'var(--danger)' }}>
              {verificationReport.is_valid ? 'Audit Hash Chain Verified' : 'Integrity Failure Detected'}
            </div>
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-primary)', marginTop: '0.125rem' }}>
              Total consecutive events checked: {verificationReport.total_events}. All cryptographic hashes match.
            </div>
          </div>
        </div>
      )}

      {/* Real Real-Time Metric Panels */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
        <div className="panel" style={{ padding: '1.25rem' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Registered Users
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--graphite)', marginTop: '0.25rem' }}>
            {totalUsers}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--success)', marginTop: '0.25rem', fontWeight: 500 }}>
            {activeUsers} active accounts
          </div>
        </div>

        <div className="panel" style={{ padding: '1.25rem' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Vault Documents
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--graphite)', marginTop: '0.25rem' }}>
            {totalDocs}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Stored in private vault
          </div>
        </div>

        <div className="panel" style={{ padding: '1.25rem' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Logged Audit Events
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--graphite)', marginTop: '0.25rem' }}>
            {totalAuditEvents}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--copper-dark)', marginTop: '0.25rem', fontWeight: 500 }}>
            SHA-256 hash chained
          </div>
        </div>

        <div className="panel" style={{ padding: '1.25rem' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Refused Access Probes
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: deniedAttempts > 0 ? 'var(--danger)' : 'var(--graphite)', marginTop: '0.25rem' }}>
            {deniedAttempts}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Logged &amp; prevented by policy
          </div>
        </div>
      </div>

      {/* User and Role Management Section */}
      <div style={{ marginBottom: '2.5rem' }}>
        <h2 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--graphite)', marginBottom: '0.75rem' }}>
          User Directory &amp; Scope Assignments
        </h2>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>User Identity</th>
                <th>Role Assignment</th>
                <th>Status</th>
                <th>Enrolled Date</th>
                <th style={{ textAlign: 'right' }}>Security Action</th>
              </tr>
            </thead>
            <tbody>
              {allUsers?.map((u) => (
                <tr key={u.id}>
                  <td>
                    <div style={{ fontWeight: 600, color: 'var(--graphite)' }}>{u.display_name}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{u.email}</div>
                  </td>
                  <td>
                    <select
                      className="input-field"
                      value={u.role}
                      onChange={(e) => updateUserMutation.mutate({ userId: u.id, data: { role: e.target.value } })}
                      style={{ width: 'auto', padding: '0.25rem 0.5rem', fontSize: '0.8125rem' }}
                    >
                      <option value="owner">Owner</option>
                      <option value="viewer">Viewer</option>
                      <option value="admin">Admin</option>
                    </select>
                  </td>
                  <td>
                    <span className={`badge ${u.is_active ? 'badge-green' : 'badge-red'}`}>
                      {u.is_active ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                    {new Date(u.created_at).toLocaleDateString()}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      className={`btn btn-sm ${u.is_active ? 'btn-danger' : 'btn-secondary'}`}
                      onClick={() => updateUserMutation.mutate({ userId: u.id, data: { is_active: !u.is_active } })}
                      disabled={u.id === user.id} // Cannot disable oneself
                    >
                      {u.is_active ? 'Disable Account' : 'Reactivate'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
