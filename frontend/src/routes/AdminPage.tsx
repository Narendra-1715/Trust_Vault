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
          <Lock size={36} color="var(--danger)" style={{ margin: '0 auto 1rem' }} />
          <h2 style={{ fontSize: '1.25rem', fontWeight: 600, marginBottom: '0.5rem' }}>Access Restricted</h2>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
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
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-main)' }}>
            Security Administration Console
          </h1>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
            System configuration, user role management, and cryptographic audit monitoring.
          </p>
        </div>

        <button
          className="btn btn-primary"
          onClick={() => verifyMutation.mutate()}
          disabled={verifyMutation.isPending}
        >
          <RefreshCw size={15} />
          <span>{verifyMutation.isPending ? 'Verifying...' : 'Verify Cryptographic Audit Chain'}</span>
        </button>
      </div>

      {/* Verification Status Banner */}
      {verificationReport && (
        <div style={{
          backgroundColor: verificationReport.is_valid ? 'var(--success-bg)' : 'var(--danger-bg)',
          border: `1px solid ${verificationReport.is_valid ? 'var(--success-border)' : 'var(--danger-border)'}`,
          borderRadius: 'var(--radius-md)',
          padding: '1.25rem',
          marginBottom: '1.75rem',
          display: 'flex',
          alignItems: 'center',
          gap: '1rem'
        }}>
          {verificationReport.is_valid ? (
            <CheckCircle size={22} style={{ color: 'var(--success)' }} />
          ) : (
            <AlertTriangle size={22} style={{ color: 'var(--danger)' }} />
          )}

          <div>
            <div style={{ fontWeight: 700, fontSize: '0.9375rem', color: verificationReport.is_valid ? 'var(--success)' : 'var(--danger)' }}>
              {verificationReport.is_valid ? 'Audit Hash Chain Verified' : 'Integrity Failure Detected'}
            </div>
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
              Total consecutive events checked: {verificationReport.total_events}. All cryptographic hashes match.
            </div>
          </div>
        </div>
      )}

      {/* Real Real-Time Metric Panels */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
        <div className="panel" style={{ padding: '1.25rem' }}>
          <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', fontWeight: 500 }}>Total Registered Users</div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)', marginTop: '0.25rem' }}>{totalUsers}</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--success)', marginTop: '0.25rem' }}>{activeUsers} active accounts</div>
        </div>

        <div className="panel" style={{ padding: '1.25rem' }}>
          <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', fontWeight: 500 }}>Confidential Documents</div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)', marginTop: '0.25rem' }}>{totalDocs}</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>Stored in private storage</div>
        </div>

        <div className="panel" style={{ padding: '1.25rem' }}>
          <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', fontWeight: 500 }}>Logged Audit Events</div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-main)', marginTop: '0.25rem' }}>{totalAuditEvents}</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>SHA-256 chained</div>
        </div>

        <div className="panel" style={{ padding: '1.25rem' }}>
          <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', fontWeight: 500 }}>Denied Access Attempts</div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, color: deniedAttempts > 0 ? 'var(--danger)' : 'var(--text-main)', marginTop: '0.25rem' }}>
            {deniedAttempts}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>Logged &amp; prevented</div>
        </div>
      </div>

      {/* User and Role Management Section */}
      <div style={{ marginBottom: '2.5rem' }}>
        <h2 style={{ fontSize: '1.125rem', fontWeight: 600, marginBottom: '0.75rem' }}>
          User &amp; Global Role Management
        </h2>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Status</th>
                <th>Created</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {allUsers?.map((u) => (
                <tr key={u.id}>
                  <td>
                    <div style={{ fontWeight: 600 }}>{u.display_name}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{u.email}</div>
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
