import React, { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { 
  Laptop, 
  Smartphone, 
  Monitor, 
  ShieldAlert, 
  X, 
  LogOut, 
  CheckCircle2, 
  Clock, 
  Globe 
} from 'lucide-react';
import { api } from '../../lib/api';
import { formatToIST } from '../../lib/date';
import { useToast } from '../../context/ToastContext';
import { ConfirmModal } from '../common/ConfirmModal';
import type { UserSession } from '../../types';

interface SessionManagementModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const SessionManagementModal: React.FC<SessionManagementModalProps> = ({ isOpen, onClose }) => {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [isRevokingAll, setIsRevokingAll] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  // In-App Confirmation Modal state
  const [confirmConfig, setConfirmConfig] = useState<{
    isOpen: boolean;
    title: string;
    message: string;
    confirmLabel: string;
    variant: 'danger' | 'warning' | 'primary';
    isLoading: boolean;
    action: () => Promise<void>;
  }>({
    isOpen: false,
    title: '',
    message: '',
    confirmLabel: 'Confirm',
    variant: 'danger',
    isLoading: false,
    action: async () => {},
  });

  const { data: sessions, isLoading, refetch } = useQuery({
    queryKey: ['userSessions'],
    queryFn: () => api.listSessions(),
    enabled: isOpen,
  });

  if (!isOpen) return null;

  const handleRevokeSingle = (session: UserSession) => {
    setConfirmConfig({
      isOpen: true,
      title: 'Revoke Device Session',
      message: `Revoke session from "${session.device_info || 'Unknown Device'}"? Any ongoing requests will be immediately denied.`,
      confirmLabel: 'Revoke Session',
      variant: 'danger',
      isLoading: false,
      action: async () => {
        setConfirmConfig(prev => ({ ...prev, isLoading: true }));
        setRevokingId(session.id);
        try {
          await api.revokeSession(session.id);
          toast.success(`Session on ${session.device_info || 'device'} revoked successfully.`);
          queryClient.invalidateQueries({ queryKey: ['userSessions'] });
          refetch();
          setConfirmConfig(prev => ({ ...prev, isOpen: false, isLoading: false }));
        } catch (err: any) {
          toast.error(err.message || 'Failed to revoke session');
          setConfirmConfig(prev => ({ ...prev, isLoading: false }));
        } finally {
          setRevokingId(null);
        }
      },
    });
  };

  const handleRevokeOthers = () => {
    setConfirmConfig({
      isOpen: true,
      title: 'Revoke All Other Sessions',
      message: 'Revoke all other active sessions across other browsers and devices? Only this current session will remain active.',
      confirmLabel: 'Revoke Other Sessions',
      variant: 'danger',
      isLoading: false,
      action: async () => {
        setConfirmConfig(prev => ({ ...prev, isLoading: true }));
        setIsRevokingAll(true);
        try {
          const res = await api.revokeOtherSessions();
          toast.success(res.message || 'All other active sessions have been revoked.');
          queryClient.invalidateQueries({ queryKey: ['userSessions'] });
          refetch();
          setConfirmConfig(prev => ({ ...prev, isOpen: false, isLoading: false }));
        } catch (err: any) {
          toast.error(err.message || 'Failed to revoke remote sessions');
          setConfirmConfig(prev => ({ ...prev, isLoading: false }));
        } finally {
          setIsRevokingAll(false);
        }
      },
    });
  };

  const getDeviceIcon = (deviceInfo?: string) => {
    const info = (deviceInfo || '').toLowerCase();
    if (info.includes('iphone') || info.includes('android') || info.includes('mobile')) {
      return <Smartphone size={18} color="var(--copper-dark)" />;
    }
    if (info.includes('mac') || info.includes('windows') || info.includes('linux')) {
      return <Laptop size={18} color="var(--copper-dark)" />;
    }
    return <Monitor size={18} color="var(--copper-dark)" />;
  };

  const otherActiveCount = sessions?.filter(s => !s.is_current && s.is_active).length || 0;

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(28, 29, 30, 0.7)',
      backdropFilter: 'blur(3px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 100,
      padding: '1rem',
    }}>
      <div style={{
        backgroundColor: '#FFFFFF',
        borderRadius: 'var(--radius-md)',
        boxShadow: 'var(--shadow-lg)',
        maxWidth: '720px',
        width: '100%',
        maxHeight: '90vh',
        display: 'flex',
        flexDirection: 'column',
        border: '1px solid var(--border)',
        overflow: 'hidden',
      }}>
        {/* Modal Header */}
        <div style={{
          padding: '1.25rem 1.5rem',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          backgroundColor: 'var(--bg-warm)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
            <div style={{
              width: '32px',
              height: '32px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'rgba(217, 154, 103, 0.15)',
              border: '1px solid rgba(217, 154, 103, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <ShieldAlert size={18} color="var(--copper-dark)" />
            </div>
            <div>
              <h2 style={{ fontSize: '1.0625rem', fontWeight: 600, color: 'var(--graphite)', margin: 0 }}>
                Active Login Sessions
              </h2>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', margin: 0 }}>
                Review and revoke active devices authenticated to your account
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="btn btn-secondary btn-sm"
            style={{ padding: '0.35rem 0.5rem', minHeight: 'auto' }}
          >
            <X size={16} />
          </button>
        </div>

        {/* Modal Body */}
        <div style={{ padding: '1.5rem', overflowY: 'auto', flex: 1 }}>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '1.25rem',
            paddingBottom: '0.75rem',
            borderBottom: '1px solid var(--border)',
          }}>
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
              Showing {sessions?.length || 0} recognized login sessions
            </div>
            {otherActiveCount > 0 && (
              <button
                className="btn btn-danger btn-sm"
                onClick={handleRevokeOthers}
                disabled={isRevokingAll}
                style={{ gap: '0.375rem' }}
              >
                <LogOut size={13} />
                <span>{isRevokingAll ? 'Revoking...' : `Revoke All Other Sessions (${otherActiveCount})`}</span>
              </button>
            )}
          </div>

          {isLoading ? (
            <div style={{ textAlign: 'center', padding: '3rem 0', color: 'var(--text-muted)' }}>
              Loading active sessions...
            </div>
          ) : !sessions || sessions.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '3rem 0', color: 'var(--text-muted)' }}>
              No active sessions found.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
              {sessions.map((sess) => (
                <div
                  key={sess.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '1rem',
                    borderRadius: 'var(--radius-sm)',
                    border: sess.is_current 
                      ? '1px solid var(--copper-dark)' 
                      : '1px solid var(--border)',
                    backgroundColor: sess.is_current ? 'rgba(217, 154, 103, 0.05)' : '#FFFFFF',
                    opacity: sess.is_active ? 1 : 0.6,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.875rem' }}>
                    <div style={{
                      padding: '0.5rem',
                      borderRadius: 'var(--radius-sm)',
                      backgroundColor: 'var(--bg-warm)',
                      border: '1px solid var(--border)',
                      marginTop: '2px',
                    }}>
                      {getDeviceIcon(sess.device_info)}
                    </div>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                        <span style={{ fontWeight: 600, color: 'var(--graphite)', fontSize: '0.875rem' }}>
                          {sess.device_info || 'Unknown Client'}
                        </span>
                        {sess.is_current && (
                          <span className="badge badge-copper" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.6875rem' }}>
                            <CheckCircle2 size={11} />
                            <span>This Device</span>
                          </span>
                        )}
                        {!sess.is_active && (
                          <span className="badge" style={{ backgroundColor: '#F3F4F6', color: '#6B7280', border: '1px solid #E5E7EB', fontSize: '0.6875rem' }}>
                            Revoked / Expired
                          </span>
                        )}
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginTop: '0.375rem', fontSize: '0.75rem', color: 'var(--text-secondary)', flexWrap: 'wrap' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                          <Globe size={12} color="var(--text-muted)" />
                          <span>{sess.ip_address || 'IP Unknown'}</span>
                        </span>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                          <Clock size={12} color="var(--text-muted)" />
                          <span>Active: {formatToIST(sess.last_active_at)}</span>
                        </span>
                      </div>
                    </div>
                  </div>

                  <div>
                    {sess.is_current ? (
                      <span style={{ fontSize: '0.75rem', color: 'var(--copper-dark)', fontWeight: 600 }}>
                        Current Session
                      </span>
                    ) : sess.is_active ? (
                      <button
                        className="btn btn-danger btn-sm"
                        onClick={() => handleRevokeSingle(sess)}
                        disabled={revokingId === sess.id}
                        style={{ fontSize: '0.75rem', padding: '0.35rem 0.625rem' }}
                      >
                        {revokingId === sess.id ? 'Revoking...' : 'Revoke'}
                      </button>
                    ) : (
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        Inactive
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div style={{
          padding: '0.875rem 1.5rem',
          borderTop: '1px solid var(--border)',
          display: 'flex',
          justifyContent: 'flex-end',
          backgroundColor: 'var(--bg-warm)',
        }}>
          <button className="btn btn-secondary btn-sm" onClick={onClose}>
            Close
          </button>
        </div>
      </div>

      {/* Confirmation Modal */}
      <ConfirmModal
        isOpen={confirmConfig.isOpen}
        title={confirmConfig.title}
        message={confirmConfig.message}
        confirmLabel={confirmConfig.confirmLabel}
        variant={confirmConfig.variant}
        isLoading={confirmConfig.isLoading}
        onConfirm={confirmConfig.action}
        onCancel={() => setConfirmConfig(prev => ({ ...prev, isOpen: false }))}
      />
    </div>
  );
};
