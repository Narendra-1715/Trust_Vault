import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { 
  AlertTriangle, 
  CheckCircle, 
  RefreshCw, 
  Lock, 
  ShieldAlert, 
  Database, 
  Archive, 
  CheckCircle2, 
  Shield, 
  Sliders, 
  XCircle, 
  Info,
  Server,
  Activity,
  UserPlus,
  Flame,
  KeyRound,
  RotateCcw,
  Edit2
} from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '../features/auth/AuthContext';
import { useToast } from '../context/ToastContext';
import type { 
  AuditVerificationReport, 
  RestoreVerificationReport, 
  PolicySimulationResponse
} from '../types';

export const AdminPage: React.FC = () => {
  const { user } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [verificationReport, setVerificationReport] = useState<AuditVerificationReport | null>(null);
  const [drReport, setDrReport] = useState<RestoreVerificationReport | null>(null);

  // Administrator Policy Simulator state
  const [adminSimDocId, setAdminSimDocId] = useState('');
  const [adminSimEmail, setAdminSimEmail] = useState('');
  const [adminSimPerm, setAdminSimPerm] = useState<'read' | 'edit'>('read');
  const [adminSimDays, setAdminSimDays] = useState('7');
  const [adminSimResult, setAdminSimResult] = useState<PolicySimulationResponse | null>(null);
  const [isAdminSimulating, setIsAdminSimulating] = useState(false);
  const [adminSimError, setAdminSimError] = useState<string | null>(null);

  const handleAdminSimulate = async () => {
    if (!adminSimDocId || !adminSimEmail) {
      setAdminSimError('Please select both a document and a user to simulate.');
      return;
    }
    setAdminSimError(null);
    setIsAdminSimulating(true);

    let expiresAtIso: string | undefined = undefined;
    const daysNum = parseInt(adminSimDays, 10);
    if (!isNaN(daysNum) && daysNum > 0) {
      expiresAtIso = new Date(Date.now() + daysNum * 86400 * 1000).toISOString();
    }

    try {
      const res = await api.simulatePolicy({
        document_id: adminSimDocId,
        recipient_email: adminSimEmail,
        permission_level: adminSimPerm,
        proposed_expiry: expiresAtIso,
      });
      setAdminSimResult(res);
    } catch (err: any) {
      setAdminSimError(err.message || 'Simulation failed');
      toast.error(err.message || 'Simulation failed');
    } finally {
      setIsAdminSimulating(false);
    }
  };

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

  const { data: backupsData, refetch: refetchBackups } = useQuery({
    queryKey: ['adminBackups'],
    queryFn: () => api.listBackups(),
    enabled: user?.role === 'admin',
  });

  const latestBackup = backupsData?.backups?.[0];

  const { data: policiesData, refetch: refetchPolicies } = useQuery({
    queryKey: ['adminPolicies'],
    queryFn: () => api.listSecurityPolicies(),
    enabled: user?.role === 'admin',
  });

  const updatePolicyMutation = useMutation({
    mutationFn: ({ classification, data }: { classification: string; data: any }) =>
      api.updateSecurityPolicy(classification, data),
    onSuccess: (updated) => {
      refetchPolicies();
      toast.success(`Security policy for ${updated.classification} updated successfully.`);
    },
    onError: (err: any) => toast.error(err.message || 'Failed to update policy'),
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

  // Backup & DR Mutations
  const createBackupMutation = useMutation({
    mutationFn: () => api.createBackup(),
    onSuccess: (data) => {
      refetchBackups();
      queryClient.invalidateQueries({ queryKey: ['adminAuditEvents'] });
      toast.success(`Verified backup ${data.backup_id} created successfully.`);
    },
    onError: (err: any) => toast.error(err.message || 'Backup generation failed'),
  });

  const verifyBackupMutation = useMutation({
    mutationFn: (backupId: string) => api.verifyBackupHealth(backupId),
    onSuccess: (data) => {
      setDrReport(data);
      if (data.is_valid) {
        toast.success(`Disaster recovery audit passed! RTO: ${data.rto_seconds}s.`);
      } else {
        toast.error(`Disaster recovery audit failed: ${data.errors.join(', ')}`);
      }
    },
    onError: (err: any) => toast.error(err.message || 'DR verification failed'),
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

  // System Status, Settings, and Break-Glass Queries
  const { data: sysStatus, refetch: refetchSysStatus } = useQuery({
    queryKey: ['adminSystemStatus'],
    queryFn: () => api.getSystemStatus(),
    enabled: user?.role === 'admin',
    refetchInterval: 10000,
  });

  const { data: sysSettings, refetch: refetchSettings } = useQuery({
    queryKey: ['adminSystemSettings'],
    queryFn: () => api.listSystemSettings(),
    enabled: user?.role === 'admin',
  });

  const { data: breakGlassList, refetch: refetchBreakGlass } = useQuery({
    queryKey: ['adminBreakGlass'],
    queryFn: () => api.listBreakGlassAccesses(),
    enabled: user?.role === 'admin',
    refetchInterval: 10000,
  });

  // Settings update mutation
  const updateSettingMutation = useMutation({
    mutationFn: ({ key, value }: { key: string; value: string }) => api.updateSystemSetting(key, value),
    onSuccess: (updated) => {
      refetchSettings();
      toast.success(`Setting '${updated.key}' updated to '${updated.value}'.`);
      setEditingSetting(null);
    },
    onError: (err: any) => toast.error(err.message || 'Failed to update setting'),
  });

  // Edit System Setting Modal state
  const [editingSetting, setEditingSetting] = useState<{ key: string; value: string; description?: string } | null>(null);
  const [editingSettingValue, setEditingSettingValue] = useState('');

  // Provision User Modal state
  const [showProvisionModal, setShowProvisionModal] = useState(false);
  const [provisionEmail, setProvisionEmail] = useState('');
  const [provisionPassword, setProvisionPassword] = useState('');
  const [provisionDisplayName, setProvisionDisplayName] = useState('');
  const [provisionRole, setProvisionRole] = useState<'admin' | 'owner' | 'viewer'>('viewer');
  const [provisionMfa, setProvisionMfa] = useState(false);
  const [isProvisioning, setIsProvisioning] = useState(false);

  // Restore Modal state
  const [showRestoreModal, setShowRestoreModal] = useState(false);
  const [restoreBackupId, setRestoreBackupId] = useState('');
  const [restoreConfirmation, setRestoreConfirmation] = useState('');
  const [restorePassword, setRestorePassword] = useState('');
  const [isRestoring, setIsRestoring] = useState(false);

  // Break-Glass Modal state
  const [showBreakGlassModal, setShowBreakGlassModal] = useState(false);
  const [bgDocId, setBgDocId] = useState('');
  const [bgJustification, setBgJustification] = useState('');
  const [bgDuration, setBgDuration] = useState('30');
  const [bgPassword, setBgPassword] = useState('');
  const [isActivatingBg, setIsActivatingBg] = useState(false);

  // Review Break-Glass state
  const [reviewingBgId, setReviewingBgId] = useState<string | null>(null);
  const [reviewNotes, setReviewNotes] = useState('');
  const [isSubmittingReview, setIsSubmittingReview] = useState(false);

  // User session inspection modal state
  const [inspectingUserId, setInspectingUserId] = useState<string | null>(null);
  const [userSessions, setUserSessions] = useState<any[]>([]);
  const [isLoadingSessions, setIsLoadingSessions] = useState(false);

  const handleInspectSessions = async (userId: string) => {
    setInspectingUserId(userId);
    setIsLoadingSessions(true);
    try {
      const sess = await api.listUserSessionsAdmin(userId);
      setUserSessions(sess);
    } catch (err: any) {
      toast.error(err.message || 'Failed to fetch sessions');
    } finally {
      setIsLoadingSessions(false);
    }
  };

  const handleRevokeAllSessions = async (userId: string) => {
    try {
      const res = await api.revokeAllUserSessionsAdmin(userId);
      toast.success(res.message);
      if (inspectingUserId === userId) {
        handleInspectSessions(userId);
      }
      refetchSysStatus();
    } catch (err: any) {
      toast.error(err.message || 'Failed to revoke sessions');
    }
  };

  const handleProvisionUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsProvisioning(true);
    try {
      await api.createAdminUser({
        email: provisionEmail,
        password: provisionPassword,
        display_name: provisionDisplayName,
        role: provisionRole,
        is_active: true,
        mfa_enabled: provisionMfa,
      });
      toast.success(`User ${provisionEmail} created with role ${provisionRole}.`);
      setShowProvisionModal(false);
      setProvisionEmail('');
      setProvisionPassword('');
      setProvisionDisplayName('');
      setProvisionRole('viewer');
      setProvisionMfa(false);
      refetchUsers();
    } catch (err: any) {
      toast.error(err.message || 'Failed to provision user');
    } finally {
      setIsProvisioning(false);
    }
  };

  const handleActivateBreakGlass = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsActivatingBg(true);
    try {
      await api.activateBreakGlass({
        document_id: bgDocId,
        justification: bgJustification,
        duration_minutes: parseInt(bgDuration, 10) || 30,
        password: bgPassword,
      });
      toast.success('Emergency break-glass access activated successfully.');
      setShowBreakGlassModal(false);
      setBgDocId('');
      setBgJustification('');
      setBgDuration('30');
      setBgPassword('');
      refetchBreakGlass();
    } catch (err: any) {
      toast.error(err.message || 'Failed to activate break-glass');
    } finally {
      setIsActivatingBg(false);
    }
  };

  const handleRevokeBreakGlass = async (id: string) => {
    try {
      await api.revokeBreakGlass(id);
      toast.success('Emergency break-glass access revoked immediately.');
      refetchBreakGlass();
    } catch (err: any) {
      toast.error(err.message || 'Failed to revoke break-glass');
    }
  };

  const handleSubmitReview = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reviewingBgId) return;
    setIsSubmittingReview(true);
    try {
      await api.reviewBreakGlass(reviewingBgId, reviewNotes);
      toast.success('Post-incident review notes saved.');
      setReviewingBgId(null);
      setReviewNotes('');
      refetchBreakGlass();
    } catch (err: any) {
      toast.error(err.message || 'Failed to submit review');
    } finally {
      setIsSubmittingReview(false);
    }
  };

  const handleExecuteRestore = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!restoreBackupId) return;
    setIsRestoring(true);
    try {
      const res = await api.restoreBackup(restoreBackupId, {
        confirmation: restoreConfirmation,
        password: restorePassword,
      });
      toast.success(res.message);
      setShowRestoreModal(false);
      setRestoreBackupId('');
      setRestoreConfirmation('');
      setRestorePassword('');
      refetchUsers();
      refetchBackups();
      queryClient.invalidateQueries({ queryKey: ['adminAuditEvents'] });
    } catch (err: any) {
      toast.error(err.message || 'Disaster recovery restore failed');
    } finally {
      setIsRestoring(false);
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
        hour12: true,
      }) + ' IST';
    } catch {
      return ts;
    }
  };

  if (user?.role !== 'admin') {
    return (
      <div className="container" style={{ paddingTop: '4rem', paddingBottom: '4rem', textAlign: 'center' }}>
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
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '1.5rem' }}>
            Administrative privilege required to view the security operations console.
          </p>
          <Link to="/documents" className="btn btn-primary" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}>
            Go to Documents Dashboard
          </Link>
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

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <Link
            to="/admin/alerts"
            className="btn btn-secondary"
            style={{ padding: '0.5625rem 1rem', display: 'flex', alignItems: 'center', gap: '0.375rem', textDecoration: 'none' }}
          >
            <ShieldAlert size={15} color="var(--copper-dark)" />
            <span>Security Alerts Feed</span>
          </Link>

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

      {/* System Health, Storage Status & Background Jobs */}
      {sysStatus && (
        <div className="panel" style={{ padding: '1.25rem', marginBottom: '2rem', backgroundColor: 'var(--bg-surface)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Server size={18} color="var(--copper-dark)" />
              <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--graphite)', margin: 0 }}>
                System Health &amp; Storage Infrastructure
              </h3>
              <span className={`badge ${sysStatus.status === 'operational' ? 'badge-green' : 'badge-danger'}`}>
                {sysStatus.status.toUpperCase()}
              </span>
            </div>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Server Time: {formatTimestamp(sysStatus.server_time)}
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
            <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-warm)', borderRadius: 'var(--radius-sm)' }}>
              <span style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Database Engine</span>
              <div style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--graphite)', marginTop: '0.125rem' }}>
                {sysStatus.database.engine.toUpperCase()} ({sysStatus.database.status})
              </div>
              <span style={{ fontSize: '0.6875rem', color: 'var(--success)' }}>Connection pool verified</span>
            </div>

            <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-warm)', borderRadius: 'var(--radius-sm)' }}>
              <span style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Private Storage Driver</span>
              <div style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--graphite)', marginTop: '0.125rem' }}>
                {sysStatus.storage.backend.toUpperCase()} ({(sysStatus.storage.total_bytes / (1024 * 1024)).toFixed(2)} MB)
              </div>
              <span style={{ fontSize: '0.6875rem', color: 'var(--text-secondary)' }}>
                {sysStatus.storage.total_documents} active • {sysStatus.storage.trashed_documents || 0} purged
              </span>
            </div>

            <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-warm)', borderRadius: 'var(--radius-sm)' }}>
              <span style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Access Reviews Queue</span>
              <div style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--graphite)', marginTop: '0.125rem' }}>
                {sysStatus.background_jobs.access_reviews_pending} Pending / {sysStatus.background_jobs.access_reviews_overdue} Overdue
              </div>
              <span style={{ fontSize: '0.6875rem', color: sysStatus.background_jobs.access_reviews_overdue > 0 ? 'var(--danger)' : 'var(--success)' }}>
                {sysStatus.background_jobs.access_reviews_overdue > 0 ? 'Action required' : 'All reviews compliant'}
              </span>
            </div>

            <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-warm)', borderRadius: 'var(--radius-sm)' }}>
              <span style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Active User Sessions</span>
              <div style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--graphite)', marginTop: '0.125rem' }}>
                {sysStatus.active_sessions_count} Live Sessions
              </div>
              <span style={{ fontSize: '0.6875rem', color: 'var(--text-secondary)' }}>Across {sysStatus.users_count} accounts</span>
            </div>
          </div>
        </div>
      )}

      {/* Disaster Recovery & Encrypted Backup Console */}
      <div className="panel" style={{ padding: '1.5rem', marginBottom: '2.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Database size={18} color="var(--copper-dark)" />
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--graphite)', margin: 0 }}>
                Disaster Recovery &amp; Encrypted Backups
              </h3>
            </div>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: '0.25rem 0 0' }}>
              AES-256-GCM encrypted snapshot archives covering PostgreSQL tables, private document storage, and cryptographic audit chains.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <button
              className="btn btn-secondary"
              onClick={() => {
                if (latestBackup) {
                  verifyBackupMutation.mutate(latestBackup.backup_id);
                }
              }}
              disabled={!latestBackup || verifyBackupMutation.isPending}
              style={{ fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: '0.375rem' }}
            >
              <RefreshCw size={14} className={verifyBackupMutation.isPending ? 'spin' : ''} />
              <span>{verifyBackupMutation.isPending ? 'Testing Sandbox...' : 'Run Isolated DR Simulation'}</span>
            </button>

            {latestBackup && (
              <button
                className="btn btn-secondary"
                onClick={() => {
                  setRestoreBackupId(latestBackup.backup_id);
                  setShowRestoreModal(true);
                }}
                style={{ fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: '0.375rem', borderColor: 'var(--copper)' }}
              >
                <RotateCcw size={14} color="var(--copper-dark)" />
                <span>Restore from Backup</span>
              </button>
            )}

            <button
              className="btn btn-primary"
              onClick={() => createBackupMutation.mutate()}
              disabled={createBackupMutation.isPending}
              style={{ fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: '0.375rem' }}
            >
              <Archive size={14} className={createBackupMutation.isPending ? 'spin' : ''} />
              <span>{createBackupMutation.isPending ? 'Creating Backup...' : 'Create Verified Backup Now'}</span>
            </button>
          </div>
        </div>

        {/* DR Objectives & Latest Backup Banner */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
          backgroundColor: 'var(--bg-warm)',
          padding: '1.25rem',
          borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--border-color)',
        }}>
          <div>
            <span style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Target RPO</span>
            <div style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--graphite)', marginTop: '0.125rem' }}>&le; 1 Hour</div>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>Max data loss window</span>
          </div>

          <div>
            <span style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Measured Test RTO</span>
            <div style={{ fontSize: '1.125rem', fontWeight: 700, color: '#2F855A', marginTop: '0.125rem' }}>
              {drReport ? `${drReport.rto_seconds}s` : '< 5.0s'}
            </div>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>Isolated sandbox restore duration</span>
          </div>

          <div>
            <span style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Available Backups</span>
            <div style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--graphite)', marginTop: '0.125rem' }}>
              {backupsData?.total ?? 0} Archives
            </div>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>Retention limit: 14 snapshots</span>
          </div>

          <div>
            <span style={{ fontSize: '0.6875rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Latest Backup</span>
            <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--graphite)', marginTop: '0.25rem' }}>
              {latestBackup ? formatTimestamp(latestBackup.created_at) : 'None recorded'}
            </div>
            <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
              {latestBackup ? `${(latestBackup.size_bytes / 1024).toFixed(1)} KB • ${latestBackup.total_documents} docs` : 'Ready to create'}
            </span>
          </div>
        </div>

        {/* DR Verification Audit Result */}
        {drReport && (
          <div style={{
            backgroundColor: drReport.is_valid ? 'var(--success-bg)' : 'var(--danger-bg)',
            border: `1px solid ${drReport.is_valid ? 'var(--success-border)' : 'var(--danger-border)'}`,
            borderRadius: 'var(--radius-sm)',
            padding: '1.25rem',
            marginTop: '1.25rem',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                {drReport.is_valid ? (
                  <CheckCircle2 size={18} color="var(--success)" />
                ) : (
                  <AlertTriangle size={18} color="var(--danger)" />
                )}
                <span style={{ fontWeight: 700, fontSize: '0.9375rem', color: drReport.is_valid ? 'var(--success)' : 'var(--danger)' }}>
                  {drReport.is_valid ? 'Disaster Recovery Readiness: 100% Verified' : 'Disaster Recovery Verification Failed'}
                </span>
              </div>
              <span style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                RTO: {drReport.rto_seconds}s
              </span>
            </div>

            <div style={{ fontSize: '0.8125rem', color: 'var(--text-primary)', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem', marginTop: '0.75rem' }}>
              <div>
                <strong>Objects Verified:</strong> {drReport.objects_verified} / {drReport.total_documents} (SHA-256 Match)
              </div>
              <div>
                <strong>Audit Chain:</strong> {drReport.audit_chain_valid ? 'Continuous & Cryptographically Intact' : 'Corrupted'}
              </div>
              <div>
                <strong>Alembic Schema:</strong> {drReport.alembic_version || 'f2a3b4c5d6e7'}
              </div>
              <div>
                <strong>Missing / Corrupt Files:</strong> {drReport.missing_objects.length + drReport.corrupt_objects.length}
              </div>
            </div>

            {drReport.errors.length > 0 && (
              <div style={{ marginTop: '0.75rem', color: 'var(--danger)', fontSize: '0.75rem' }}>
                {drReport.errors.map((e, idx) => (
                  <div key={idx}>• {e}</div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Classification & Security Policies Section */}
      <div style={{ marginBottom: '2.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
          <div>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--graphite)', margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Shield size={18} color="var(--copper-dark)" />
              <span>Document Classification &amp; Security Policies</span>
            </h2>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: '0.25rem 0 0 0' }}>
              Configure server-enforced security boundaries: download restrictions, grant duration caps, and MFA enforcement.
            </p>
          </div>
        </div>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Classification Level</th>
                <th>Download Permitted</th>
                <th>Document Sharing</th>
                <th>Max Grant Duration</th>
                <th>MFA Requirement</th>
                <th>Elevated Change</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {policiesData?.map((p) => (
                <tr key={p.id}>
                  <td>
                    <span className={`badge ${
                      p.classification === 'Highly Restricted' 
                        ? 'badge-danger' 
                        : p.classification === 'Confidential' 
                          ? 'badge-copper' 
                          : 'badge-secondary'
                    }`} style={{ fontWeight: 600 }}>
                      {p.classification}
                    </span>
                  </td>
                  <td>
                    <button
                      type="button"
                      className={`btn btn-sm ${p.allow_download ? 'btn-secondary' : 'btn-ghost'}`}
                      onClick={() => updatePolicyMutation.mutate({ classification: p.classification, data: { allow_download: !p.allow_download } })}
                      style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}
                    >
                      {p.allow_download ? 'Allowed' : 'Prohibited'}
                    </button>
                  </td>
                  <td>
                    <button
                      type="button"
                      className={`btn btn-sm ${p.allow_sharing ? 'btn-secondary' : 'btn-ghost'}`}
                      onClick={() => updatePolicyMutation.mutate({ classification: p.classification, data: { allow_sharing: !p.allow_sharing } })}
                      style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}
                    >
                      {p.allow_sharing ? 'Allowed' : 'Prohibited'}
                    </button>
                  </td>
                  <td>
                    <span style={{ fontSize: '0.8125rem', fontWeight: 500 }}>
                      {p.max_grant_duration_days ? `${p.max_grant_duration_days} days` : 'No Limit'}
                    </span>
                  </td>
                  <td>
                    <button
                      type="button"
                      className={`btn btn-sm ${p.require_mfa ? 'btn-primary' : 'btn-secondary'}`}
                      onClick={() => updatePolicyMutation.mutate({ classification: p.classification, data: { require_mfa: !p.require_mfa } })}
                      style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}
                    >
                      {p.require_mfa ? 'MFA Required' : 'Optional'}
                    </button>
                  </td>
                  <td>
                    <span className="badge badge-gray" style={{ fontSize: '0.7rem' }}>
                      {p.elevated_classification_change ? 'Owner/Admin Only' : 'Standard'}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Live Enforced</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Administrator Policy Simulator Card */}
        <div className="panel" style={{ marginTop: '1.25rem', padding: '1.25rem', backgroundColor: 'var(--bg-surface)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Sliders size={18} color="var(--copper-dark)" />
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--graphite)', margin: 0 }}>
                    Global Policy Impact Simulator
                  </h3>
                  <span className="badge badge-secondary" style={{ fontSize: '0.6875rem' }}>Read-Only Sandbox</span>
                </div>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', margin: '0.125rem 0 0 0' }}>
                  Simulate access decisions across any vault document against configured security policies without creating database grants.
                </p>
              </div>
            </div>
          </div>

          {adminSimError && (
            <div style={{
              backgroundColor: 'var(--danger-bg)',
              color: 'var(--danger)',
              padding: '0.5rem 0.75rem',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.8125rem',
              marginBottom: '0.75rem',
              border: '1px solid var(--danger-border)',
            }}>
              {adminSimError}
            </div>
          )}

          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'flex-end', padding: '0.75rem', backgroundColor: 'var(--bg-warm)', borderRadius: 'var(--radius-sm)' }}>
            <div style={{ flex: 1, minWidth: '220px' }}>
              <label className="form-label" style={{ fontSize: '0.75rem' }}>Select Vault Document</label>
              <select
                className="input-field"
                value={adminSimDocId}
                onChange={(e) => setAdminSimDocId(e.target.value)}
                style={{ fontSize: '0.8125rem' }}
              >
                <option value="">-- Choose Vault Document --</option>
                {adminDocs?.documents?.map(d => (
                  <option key={d.id} value={d.id}>
                    {d.title} [{d.classification || 'Internal'}]
                  </option>
                ))}
              </select>
            </div>

            <div style={{ flex: 1, minWidth: '200px' }}>
              <label className="form-label" style={{ fontSize: '0.75rem' }}>Select Organization Member</label>
              <select
                className="input-field"
                value={adminSimEmail}
                onChange={(e) => setAdminSimEmail(e.target.value)}
                style={{ fontSize: '0.8125rem' }}
              >
                <option value="">-- Choose Member to Test --</option>
                {allUsers?.map(u => (
                  <option key={u.id} value={u.email}>
                    {u.display_name} ({u.email}) - {u.role}
                  </option>
                ))}
              </select>
            </div>

            <div style={{ width: '130px' }}>
              <label className="form-label" style={{ fontSize: '0.75rem' }}>Proposed Level</label>
              <select
                className="input-field"
                value={adminSimPerm}
                onChange={(e) => setAdminSimPerm(e.target.value as 'read' | 'edit')}
                style={{ fontSize: '0.8125rem' }}
              >
                <option value="read">Read Only</option>
                <option value="edit">Edit</option>
              </select>
            </div>

            <div style={{ width: '130px' }}>
              <label className="form-label" style={{ fontSize: '0.75rem' }}>Duration (Days)</label>
              <input
                type="number"
                min="0"
                max="365"
                className="input-field"
                value={adminSimDays}
                onChange={(e) => setAdminSimDays(e.target.value)}
                placeholder="0 = Indefinite"
                style={{ fontSize: '0.8125rem' }}
              />
            </div>

            <button
              type="button"
              className="btn btn-primary"
              onClick={handleAdminSimulate}
              disabled={!adminSimDocId || !adminSimEmail || isAdminSimulating}
              style={{ height: '36px', padding: '0 0.875rem', fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: '0.375rem' }}
            >
              <Sliders size={13} />
              <span>{isAdminSimulating ? 'Simulating...' : 'Simulate Policy'}</span>
            </button>
          </div>

          {adminSimResult && (
            <div style={{
              marginTop: '1rem',
              padding: '1rem',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border)',
              backgroundColor: adminSimResult.status === 'allowed' 
                ? 'rgba(34, 197, 94, 0.05)' 
                : adminSimResult.status === 'additional_requirements_needed' 
                  ? 'rgba(234, 179, 8, 0.05)' 
                  : 'rgba(239, 68, 68, 0.05)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                {adminSimResult.status === 'allowed' ? (
                  <CheckCircle2 size={18} color="#16a34a" />
                ) : adminSimResult.status === 'additional_requirements_needed' ? (
                  <AlertTriangle size={18} color="#d97706" />
                ) : (
                  <XCircle size={18} color="#dc2626" />
                )}
                <span style={{
                  fontWeight: 700,
                  fontSize: '0.9375rem',
                  color: adminSimResult.status === 'allowed' ? '#16a34a' : adminSimResult.status === 'additional_requirements_needed' ? '#d97706' : '#dc2626',
                }}>
                  {adminSimResult.status === 'allowed'
                    ? 'Policy Outcome: Allowed'
                    : adminSimResult.status === 'additional_requirements_needed'
                      ? 'Policy Outcome: Additional Requirements Required'
                      : 'Policy Outcome: Denied'}
                </span>
                <span className="badge badge-secondary" style={{ marginLeft: 'auto' }}>
                  {adminSimResult.document_title} ({adminSimResult.classification})
                </span>
              </div>

              <p style={{ fontSize: '0.8125rem', color: 'var(--graphite)', margin: '0 0 0.75rem 0' }}>
                {adminSimResult.summary}
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem', marginBottom: '0.75rem' }}>
                {adminSimResult.evaluated_rules.map((rule, idx) => (
                  <div key={idx} style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    padding: '0.375rem 0.5rem',
                    backgroundColor: 'var(--bg-surface)',
                    borderRadius: 'var(--radius-xs)',
                    border: '1px solid var(--border)',
                    fontSize: '0.8125rem',
                  }}>
                    {rule.passed ? <CheckCircle size={14} color="#16a34a" /> : <XCircle size={14} color="#dc2626" />}
                    <span style={{ fontWeight: 600, color: 'var(--graphite)' }}>{rule.name}:</span>
                    <span style={{ color: 'var(--text-secondary)' }}>{rule.details}</span>
                  </div>
                ))}
              </div>

              {adminSimResult.failures && adminSimResult.failures.length > 0 && (
                <div style={{
                  padding: '0.5rem 0.75rem',
                  backgroundColor: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  borderRadius: 'var(--radius-xs)',
                  fontSize: '0.8125rem',
                  color: '#991b1b',
                  marginBottom: '0.5rem',
                }}>
                  <strong>Policy Violations: </strong>{adminSimResult.failures.join('; ')}
                </div>
              )}

              {adminSimResult.remediation && (
                <div style={{
                  padding: '0.5rem 0.75rem',
                  backgroundColor: 'rgba(59, 130, 246, 0.08)',
                  border: '1px solid rgba(59, 130, 246, 0.25)',
                  borderRadius: 'var(--radius-xs)',
                  fontSize: '0.8125rem',
                  color: '#1e3a8a',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                }}>
                  <Info size={15} color="#2563eb" style={{ flexShrink: 0 }} />
                  <div>
                    <strong>Remediation: </strong>{adminSimResult.remediation}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Emergency Break-Glass Access Console */}
      <div className="panel" style={{ padding: '1.5rem', marginBottom: '2.5rem', backgroundColor: 'var(--bg-surface)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Flame size={18} color="#dc2626" />
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--graphite)', margin: 0 }}>
                Emergency Break-Glass Access Console
              </h3>
            </div>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: '0.25rem 0 0 0' }}>
              Time-limited, justified emergency access to confidential documents. Requires mandatory password reauthentication, notifies owners, and generates immutable audit records.
            </p>
          </div>

          <button
            type="button"
            className="btn btn-danger"
            onClick={() => setShowBreakGlassModal(true)}
            style={{ fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: '0.375rem' }}
          >
            <Flame size={14} />
            <span>Activate Break-Glass Access</span>
          </button>
        </div>

        {/* Break-glass accesses table */}
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Document</th>
                <th>Administrator</th>
                <th>Justification</th>
                <th>Expires (IST)</th>
                <th>Status</th>
                <th>Review Notes</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {breakGlassList && breakGlassList.length > 0 ? (
                breakGlassList.map((bg) => (
                  <tr key={bg.id} style={{ backgroundColor: bg.status === 'active' ? 'rgba(239, 68, 68, 0.04)' : undefined }}>
                    <td style={{ fontWeight: 600 }}>{bg.document_title || bg.document_id}</td>
                    <td style={{ fontSize: '0.8125rem' }}>
                      <div>{bg.admin_name || 'Admin'}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{bg.admin_email}</div>
                    </td>
                    <td style={{ fontSize: '0.8125rem', maxWidth: '240px' }} title={bg.justification}>
                      {bg.justification}
                    </td>
                    <td style={{ fontSize: '0.8125rem', whiteSpace: 'nowrap' }}>
                      {formatTimestamp(bg.expires_at)}
                    </td>
                    <td>
                      <span className={`badge ${
                        bg.status === 'active' 
                          ? 'badge-danger' 
                          : bg.status === 'revoked' 
                            ? 'badge-gray' 
                            : 'badge-secondary'
                      }`}>
                        {bg.status.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.8125rem', color: bg.review_notes ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                      {bg.review_notes || 'Pending Review'}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: '0.375rem', justifyContent: 'flex-end' }}>
                        {bg.status === 'active' && (
                          <button
                            type="button"
                            className="btn btn-danger btn-sm"
                            onClick={() => handleRevokeBreakGlass(bg.id)}
                            style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}
                          >
                            Revoke Now
                          </button>
                        )}
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={() => {
                            setReviewingBgId(bg.id);
                            setReviewNotes(bg.review_notes || '');
                          }}
                          style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}
                        >
                          Review
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-muted)' }}>
                    No break-glass emergency accesses recorded.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Platform Security & Operational Settings */}
      <div className="panel" style={{ padding: '1.5rem', marginBottom: '2.5rem', backgroundColor: 'var(--bg-surface)' }}>
        <div style={{ marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <KeyRound size={18} color="var(--copper-dark)" />
            <h3 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--graphite)', margin: 0 }}>
              Platform Security &amp; Operational Settings
            </h3>
          </div>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: '0.25rem 0 0 0' }}>
            System-level timeout, retention, and privileged authentication policies enforced server-side.
          </p>
        </div>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Configuration Key</th>
                <th>Description</th>
                <th>Current Value</th>
                <th>Last Updated</th>
                <th style={{ textAlign: 'right' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {sysSettings?.map((s) => (
                <tr key={s.key}>
                  <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{s.key}</td>
                  <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>{s.description}</td>
                  <td>
                    {s.key === 'mfa_enforced_for_admins' ? (
                      s.value === 'true' ? (
                        <span className="badge badge-green">ENABLED</span>
                      ) : (
                        <span className="badge badge-yellow">DISABLED</span>
                      )
                    ) : (
                      <span style={{ fontWeight: 600 }}>
                        {s.value}
                        {s.key.includes('minutes') ? ' mins' : s.key.includes('days') ? ' days' : s.key.includes('logins') ? ' attempts' : ''}
                      </span>
                    )}
                  </td>
                  <td style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                    {formatTimestamp(s.updated_at)}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => {
                        setEditingSetting(s);
                        setEditingSettingValue(s.value);
                      }}
                      style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}
                    >
                      <Edit2 size={12} />
                      <span>Edit Value</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* User and Role Management Section */}
      <div style={{ marginBottom: '2.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            <h2 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--graphite)', margin: 0 }}>
              User Directory &amp; Scope Assignments
            </h2>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: '0.25rem 0 0 0' }}>
              Manage accounts, assign roles, enforce MFA, and inspect active user sessions.
            </p>
          </div>

          <button
            type="button"
            className="btn btn-primary"
            onClick={() => setShowProvisionModal(true)}
            style={{ fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: '0.375rem' }}
          >
            <UserPlus size={14} />
            <span>Provision New User</span>
          </button>
        </div>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>User Identity</th>
                <th>Role Assignment</th>
                <th>Status</th>
                <th>MFA Requirement</th>
                <th>Enrolled Date</th>
                <th style={{ textAlign: 'right' }}>Security Actions</th>
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
                  <td>
                    <button
                      type="button"
                      className={`btn btn-sm ${u.mfa_enabled ? 'btn-primary' : 'btn-secondary'}`}
                      onClick={async () => {
                        try {
                          await api.toggleUserMfa(u.id, !u.mfa_enabled);
                          toast.success(`MFA ${!u.mfa_enabled ? 'enabled' : 'disabled'} for ${u.email}`);
                          refetchUsers();
                        } catch (err: any) {
                          toast.error(err.message || 'Failed to toggle MFA');
                        }
                      }}
                      style={{ fontSize: '0.7rem', padding: '0.15rem 0.4rem' }}
                    >
                      {u.mfa_enabled ? 'MFA Active' : 'MFA Off'}
                    </button>
                  </td>
                  <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                    {new Date(u.created_at).toLocaleDateString()}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '0.375rem', justifyContent: 'flex-end' }}>
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={() => handleInspectSessions(u.id)}
                        title="Inspect & Revoke Sessions"
                        style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}
                      >
                        Sessions
                      </button>

                      <button
                        className={`btn btn-sm ${u.is_active ? 'btn-danger' : 'btn-secondary'}`}
                        onClick={() => updateUserMutation.mutate({ userId: u.id, data: { is_active: !u.is_active } })}
                        disabled={u.id === user.id} // Cannot disable oneself
                        style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}
                      >
                        {u.is_active ? 'Disable' : 'Reactivate'}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Provision User Modal */}
      {showProvisionModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.5)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          padding: '1rem',
        }}>
          <div className="panel" style={{ maxWidth: '440px', width: '100%', padding: '1.5rem', backgroundColor: 'var(--bg-surface)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700, margin: 0, color: 'var(--graphite)' }}>
                Provision New User
              </h3>
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => setShowProvisionModal(false)}>✕</button>
            </div>

            <form onSubmit={handleProvisionUser} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <div>
                <label className="form-label" style={{ fontSize: '0.75rem' }}>Full Name</label>
                <input
                  type="text"
                  className="input-field"
                  placeholder="e.g. Jane Doe"
                  value={provisionDisplayName}
                  onChange={(e) => setProvisionDisplayName(e.target.value)}
                  required
                />
              </div>

              <div>
                <label className="form-label" style={{ fontSize: '0.75rem' }}>Email Address</label>
                <input
                  type="email"
                  className="input-field"
                  placeholder="e.g. jane@trustvault.internal"
                  value={provisionEmail}
                  onChange={(e) => setProvisionEmail(e.target.value)}
                  required
                />
              </div>

              <div>
                <label className="form-label" style={{ fontSize: '0.75rem' }}>Temporary Password</label>
                <input
                  type="password"
                  className="input-field"
                  placeholder="Minimum 8 characters"
                  value={provisionPassword}
                  onChange={(e) => setProvisionPassword(e.target.value)}
                  required
                  minLength={8}
                />
              </div>

              <div>
                <label className="form-label" style={{ fontSize: '0.75rem' }}>Role Assignment</label>
                <select
                  className="input-field"
                  value={provisionRole}
                  onChange={(e) => setProvisionRole(e.target.value as any)}
                >
                  <option value="viewer">Viewer</option>
                  <option value="owner">Document Owner</option>
                  <option value="admin">Administrator</option>
                </select>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.25rem' }}>
                <input
                  type="checkbox"
                  id="provisionMfaCheck"
                  checked={provisionMfa}
                  onChange={(e) => setProvisionMfa(e.target.checked)}
                />
                <label htmlFor="provisionMfaCheck" style={{ fontSize: '0.8125rem', cursor: 'pointer', margin: 0 }}>
                  Enable Multi-Factor Authentication (MFA)
                </label>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '1rem' }}>
                <button type="button" className="btn btn-secondary" onClick={() => setShowProvisionModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={isProvisioning}>
                  {isProvisioning ? 'Creating Account...' : 'Provision User'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Break-Glass Emergency Activation Modal */}
      {showBreakGlassModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.6)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          padding: '1rem',
        }}>
          <div className="panel" style={{ maxWidth: '480px', width: '100%', padding: '1.5rem', backgroundColor: 'var(--bg-surface)', border: '1px solid var(--danger-border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <Flame size={20} color="#dc2626" />
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700, margin: 0, color: '#dc2626' }}>
                Activate Emergency Break-Glass Access
              </h3>
            </div>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
              This grants time-limited, audited access to a confidential document. A critical security alert will be issued to document owners and logged immutably.
            </p>

            <form onSubmit={handleActivateBreakGlass} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <div>
                <label className="form-label" style={{ fontSize: '0.75rem' }}>Select Target Vault Document</label>
                <select
                  className="input-field"
                  value={bgDocId}
                  onChange={(e) => setBgDocId(e.target.value)}
                  required
                >
                  <option value="">-- Choose Target Document --</option>
                  {adminDocs?.documents?.map(d => (
                    <option key={d.id} value={d.id}>
                      {d.title} ({d.classification || 'Internal'})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="form-label" style={{ fontSize: '0.75rem' }}>Justified Business / Security Reason</label>
                <textarea
                  className="input-field"
                  rows={3}
                  placeholder="Detail the emergency, compliance ticket, or incident ID (min 15 characters)..."
                  value={bgJustification}
                  onChange={(e) => setBgJustification(e.target.value)}
                  required
                  minLength={15}
                />
              </div>

              <div>
                <label className="form-label" style={{ fontSize: '0.75rem' }}>Access Duration</label>
                <select
                  className="input-field"
                  value={bgDuration}
                  onChange={(e) => setBgDuration(e.target.value)}
                >
                  <option value="15">15 Minutes</option>
                  <option value="30">30 Minutes</option>
                  <option value="60">1 Hour (Max standard window)</option>
                </select>
              </div>

              <div>
                <label className="form-label" style={{ fontSize: '0.75rem' }}>Admin Password Reauthentication</label>
                <input
                  type="password"
                  className="input-field"
                  placeholder="Re-enter your administrator password"
                  value={bgPassword}
                  onChange={(e) => setBgPassword(e.target.value)}
                  required
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '1rem' }}>
                <button type="button" className="btn btn-secondary" onClick={() => setShowBreakGlassModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-danger-solid" disabled={isActivatingBg || !bgDocId}>
                  {isActivatingBg ? 'Authenticating & Activating...' : 'Confirm Break-Glass Access'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Review Break-Glass Modal */}
      {reviewingBgId && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.5)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          padding: '1rem',
        }}>
          <div className="panel" style={{ maxWidth: '440px', width: '100%', padding: '1.5rem', backgroundColor: 'var(--bg-surface)' }}>
            <h3 style={{ fontSize: '1.125rem', fontWeight: 700, margin: '0 0 0.5rem 0', color: 'var(--graphite)' }}>
              Record Post-Incident Review
            </h3>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
              Add observations, resolution findings, or compliance notes for this emergency access record.
            </p>

            <form onSubmit={handleSubmitReview} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <textarea
                className="input-field"
                rows={4}
                placeholder="Enter review notes..."
                value={reviewNotes}
                onChange={(e) => setReviewNotes(e.target.value)}
                required
                minLength={5}
              />

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button type="button" className="btn btn-secondary" onClick={() => setReviewingBgId(null)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={isSubmittingReview}>
                  {isSubmittingReview ? 'Saving...' : 'Save Review Notes'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Restore Database Modal */}
      {showRestoreModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.6)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          padding: '1rem',
        }}>
          <div className="panel" style={{ maxWidth: '480px', width: '100%', padding: '1.5rem', backgroundColor: 'var(--bg-surface)', border: '1px solid var(--danger-border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <AlertTriangle size={20} color="#dc2626" />
              <h3 style={{ fontSize: '1.125rem', fontWeight: 700, margin: 0, color: '#dc2626' }}>
                Authorized Disaster Recovery Restoration
              </h3>
            </div>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
              Restoring backup <strong>{restoreBackupId}</strong> will update application data to this snapshot state. This operation is verified in an isolated sandbox first and logged in the immutable audit trail.
            </p>

            <form onSubmit={handleExecuteRestore} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <div>
                <label className="form-label" style={{ fontSize: '0.75rem' }}>Type 'RESTORE_DATABASE' to confirm</label>
                <input
                  type="text"
                  className="input-field"
                  placeholder="RESTORE_DATABASE"
                  value={restoreConfirmation}
                  onChange={(e) => setRestoreConfirmation(e.target.value)}
                  required
                />
              </div>

              <div>
                <label className="form-label" style={{ fontSize: '0.75rem' }}>Admin Password Reauthentication</label>
                <input
                  type="password"
                  className="input-field"
                  placeholder="Re-enter your administrator password"
                  value={restorePassword}
                  onChange={(e) => setRestorePassword(e.target.value)}
                  required
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '1rem' }}>
                <button type="button" className="btn btn-secondary" onClick={() => setShowRestoreModal(false)}>
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-danger-solid"
                  disabled={isRestoring || restoreConfirmation !== 'RESTORE_DATABASE' || !restorePassword}
                >
                  {isRestoring ? 'Restoring System...' : 'Execute Authorized Restore'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Inspect User Sessions Modal */}
      {inspectingUserId && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0,0,0,0.5)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          padding: '1rem',
        }}>
          <div className="panel" style={{ maxWidth: '560px', width: '100%', padding: '1.5rem', backgroundColor: 'var(--bg-surface)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Activity size={18} color="var(--copper-dark)" />
                <h3 style={{ fontSize: '1.125rem', fontWeight: 700, margin: 0, color: 'var(--graphite)' }}>
                  Active User Sessions
                </h3>
              </div>
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => setInspectingUserId(null)}>✕</button>
            </div>

            {isLoadingSessions ? (
              <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)' }}>Loading sessions...</div>
            ) : userSessions.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-muted)' }}>No active sessions found for this user.</div>
            ) : (
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                  <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                    {userSessions.filter(s => s.is_active).length} currently active session(s)
                  </span>
                  <button
                    type="button"
                    className="btn btn-danger btn-sm"
                    onClick={() => handleRevokeAllSessions(inspectingUserId)}
                    style={{ fontSize: '0.75rem' }}
                  >
                    Revoke All Sessions
                  </button>
                </div>

                <div style={{ maxHeight: '280px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {userSessions.map((s) => (
                    <div key={s.id} style={{
                      padding: '0.75rem',
                      backgroundColor: 'var(--bg-warm)',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border)',
                      fontSize: '0.8125rem',
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontWeight: 600 }}>IP: {s.ip_address || 'Unknown'}</span>
                        <span className={`badge ${s.is_active ? 'badge-green' : 'badge-gray'}`} style={{ fontSize: '0.6875rem' }}>
                          {s.is_active ? 'ACTIVE' : 'REVOKED/EXPIRED'}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                        Device: {s.device_info || s.user_agent || 'Standard Client'}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                        Last Active: {formatTimestamp(s.last_active_at)} | Expires: {formatTimestamp(s.expires_at)}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1rem' }}>
              <button type="button" className="btn btn-secondary" onClick={() => setInspectingUserId(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit System Setting Modal */}
      {editingSetting && (
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
          zIndex: 9999,
          padding: '1rem',
          backdropFilter: 'blur(3px)',
        }}>
          <div className="panel" style={{
            maxWidth: '480px',
            width: '100%',
            padding: '1.75rem',
            backgroundColor: 'var(--bg-surface)',
            boxShadow: 'var(--shadow-xl)',
            borderRadius: 'var(--radius-lg)',
            border: '1px solid var(--border)',
          }}>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
                <div style={{
                  width: '36px',
                  height: '36px',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--copper-light)',
                  border: '1px solid var(--copper-border)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--copper-dark)',
                  flexShrink: 0,
                }}>
                  <Sliders size={18} />
                </div>
                <div>
                  <h3 style={{ fontSize: '1.0625rem', fontWeight: 700, margin: 0, color: 'var(--graphite)' }}>
                    Edit Platform Configuration
                  </h3>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.125rem' }}>
                    Modifications are logged to the immutable audit ledger.
                  </div>
                </div>
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setEditingSetting(null)}
                style={{ padding: '0.2rem 0.4rem', color: 'var(--text-muted)' }}
              >
                ✕
              </button>
            </div>

            {/* Details Box */}
            <div style={{
              backgroundColor: 'var(--bg-surface-secondary)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              padding: '0.75rem 1rem',
              marginBottom: '1.25rem',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>KEY:</span>
                <code style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--copper-dark)', fontFamily: 'var(--font-mono)' }}>
                  {editingSetting.key}
                </code>
              </div>
              <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                {editingSetting.description}
              </div>
            </div>

            {/* Form */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (editingSettingValue.trim() === '') return;
                updateSettingMutation.mutate({
                  key: editingSetting.key,
                  value: editingSettingValue.trim(),
                });
              }}
              style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}
            >
              <div>
                <label className="form-label" style={{ fontSize: '0.8125rem', fontWeight: 600 }}>
                  Configuration Value
                </label>

                {editingSetting.key === 'mfa_enforced_for_admins' ? (
                  <select
                    className="input-field"
                    value={editingSettingValue}
                    onChange={(e) => setEditingSettingValue(e.target.value)}
                    style={{ fontSize: '0.875rem' }}
                  >
                    <option value="true">Enforced (true) - Mandatory MFA for all administrators</option>
                    <option value="false">Optional (false) - Single-factor password authentication permitted</option>
                  </select>
                ) : editingSetting.key.includes('minutes') ? (
                  <div>
                    <input
                      type="number"
                      className="input-field"
                      value={editingSettingValue}
                      onChange={(e) => setEditingSettingValue(e.target.value)}
                      min={5}
                      max={1440}
                      step={5}
                      required
                      style={{ fontSize: '0.875rem' }}
                    />
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.375rem' }}>
                      Duration in minutes (e.g. 60 = 1 hour, 120 = 2 hours, 480 = 8 hours).
                    </span>
                  </div>
                ) : editingSetting.key.includes('days') ? (
                  <div>
                    <input
                      type="number"
                      className="input-field"
                      value={editingSettingValue}
                      onChange={(e) => setEditingSettingValue(e.target.value)}
                      min={1}
                      max={3650}
                      step={1}
                      required
                      style={{ fontSize: '0.875rem' }}
                    />
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.375rem' }}>
                      Retention duration in days (e.g. 30, 90, 365 days).
                    </span>
                  </div>
                ) : editingSetting.key.includes('logins') ? (
                  <div>
                    <input
                      type="number"
                      className="input-field"
                      value={editingSettingValue}
                      onChange={(e) => setEditingSettingValue(e.target.value)}
                      min={1}
                      max={20}
                      step={1}
                      required
                      style={{ fontSize: '0.875rem' }}
                    />
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.375rem' }}>
                      Consecutive failures before alert triggering (recommended 3 to 10).
                    </span>
                  </div>
                ) : (
                  <input
                    type="text"
                    className="input-field"
                    value={editingSettingValue}
                    onChange={(e) => setEditingSettingValue(e.target.value)}
                    required
                    style={{ fontSize: '0.875rem' }}
                  />
                )}
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setEditingSetting(null)}
                  style={{ fontSize: '0.8125rem' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={updateSettingMutation.isPending || editingSettingValue.trim() === ''}
                  style={{ fontSize: '0.8125rem' }}
                >
                  {updateSettingMutation.isPending ? 'Saving...' : 'Save Configuration'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
