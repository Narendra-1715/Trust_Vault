import React, { useState, useRef, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { 
  Bell, 
  Check, 
  CheckCheck, 
  ShieldAlert, 
  Info, 
  AlertTriangle, 
  AlertOctagon, 
  Clock 
} from 'lucide-react';
import { api } from '../../lib/api';
import { formatToIST } from '../../lib/date';
import { useToast } from '../../context/ToastContext';
import type { SecurityAlert } from '../../types';

export const NotificationBell: React.FC = () => {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [isOpen, setIsOpen] = useState(false);
  const [unreadOnly, setUnreadOnly] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Poll unread count every 30 seconds
  const { data: countData } = useQuery({
    queryKey: ['unreadNotificationCount'],
    queryFn: () => api.getUnreadNotificationCount(),
    refetchInterval: 30000,
  });

  const unreadCount = countData?.unread_count || 0;

  // Query notifications when dropdown is open
  const { data: notifications, isLoading, refetch } = useQuery({
    queryKey: ['notifications', unreadOnly],
    queryFn: () => api.listNotifications(unreadOnly),
    enabled: isOpen,
  });

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  const handleMarkAsRead = async (alert: SecurityAlert) => {
    if (alert.is_read) return;
    try {
      await api.markNotificationRead(alert.id);
      queryClient.invalidateQueries({ queryKey: ['unreadNotificationCount'] });
      queryClient.invalidateQueries({ queryKey: ['notifications'] });
    } catch (err: any) {
      toast.error(err.message || 'Failed to update alert state');
    }
  };

  const handleMarkAllRead = async () => {
    try {
      const res = await api.markAllNotificationsRead();
      toast.success(res.message || 'All notifications marked as read.');
      queryClient.invalidateQueries({ queryKey: ['unreadNotificationCount'] });
      queryClient.invalidateQueries({ queryKey: ['notifications'] });
      refetch();
    } catch (err: any) {
      toast.error(err.message || 'Failed to mark all as read');
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
      case 'danger':
        return (
          <span className="badge badge-danger" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.2rem', fontSize: '0.625rem' }}>
            <AlertOctagon size={10} />
            <span>High Risk</span>
          </span>
        );
      case 'warning':
        return (
          <span className="badge" style={{ backgroundColor: '#FDF6B2', color: '#723B13', border: '1px solid #FCE96A', display: 'inline-flex', alignItems: 'center', gap: '0.2rem', fontSize: '0.625rem' }}>
            <AlertTriangle size={10} />
            <span>Warning</span>
          </span>
        );
      case 'info':
      default:
        return (
          <span className="badge badge-copper" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.2rem', fontSize: '0.625rem' }}>
            <Info size={10} />
            <span>Notice</span>
          </span>
        );
    }
  };

  return (
    <div style={{ position: 'relative' }} ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="btn btn-secondary btn-sm"
        title="Security Activity Alerts"
        style={{
          position: 'relative',
          padding: '0.35rem 0.5rem',
          backgroundColor: isOpen ? 'var(--copper-light)' : undefined,
          borderColor: isOpen ? 'var(--copper)' : undefined,
        }}
      >
        <Bell size={15} color={unreadCount > 0 ? 'var(--copper-dark)' : 'var(--text-secondary)'} />
        {unreadCount > 0 && (
          <span style={{
            position: 'absolute',
            top: '-4px',
            right: '-4px',
            backgroundColor: '#DC2626',
            color: '#FFFFFF',
            borderRadius: '9999px',
            fontSize: '0.625rem',
            fontWeight: 700,
            minWidth: '16px',
            height: '16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '0 3px',
            boxShadow: '0 1px 2px rgba(0,0,0,0.2)',
          }}>
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {/* Alerts Dropdown Panel */}
      {isOpen && (
        <div style={{
          position: 'absolute',
          top: 'calc(100% + 8px)',
          right: 0,
          width: '380px',
          maxWidth: '90vw',
          backgroundColor: '#FFFFFF',
          borderRadius: 'var(--radius-md)',
          boxShadow: 'var(--shadow-lg)',
          border: '1px solid var(--border)',
          zIndex: 100,
          display: 'flex',
          flexDirection: 'column',
          maxHeight: '480px',
          overflow: 'hidden',
        }}>
          {/* Header */}
          <div style={{
            padding: '0.875rem 1rem',
            borderBottom: '1px solid var(--border)',
            backgroundColor: 'var(--bg-warm)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <ShieldAlert size={16} color="var(--copper-dark)" />
              <span style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--graphite)' }}>
                Security Alerts
              </span>
              {unreadCount > 0 && (
                <span className="badge badge-copper" style={{ fontSize: '0.625rem', padding: '0.1rem 0.4rem' }}>
                  {unreadCount} unread
                </span>
              )}
            </div>

            {unreadCount > 0 && (
              <button
                onClick={handleMarkAllRead}
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  fontSize: '0.75rem',
                  color: 'var(--copper-dark)',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.25rem',
                  padding: 0,
                }}
              >
                <CheckCheck size={13} />
                <span>Mark all read</span>
              </button>
            )}
          </div>

          {/* Filter Bar */}
          <div style={{
            display: 'flex',
            padding: '0.375rem 0.75rem',
            backgroundColor: '#FFFFFF',
            borderBottom: '1px solid var(--border)',
            gap: '0.5rem',
          }}>
            <button
              onClick={() => setUnreadOnly(false)}
              style={{
                fontSize: '0.75rem',
                padding: '0.2rem 0.5rem',
                borderRadius: 'var(--radius-sm)',
                border: 'none',
                cursor: 'pointer',
                backgroundColor: !unreadOnly ? 'var(--graphite)' : 'transparent',
                color: !unreadOnly ? '#FFFFFF' : 'var(--text-secondary)',
                fontWeight: !unreadOnly ? 600 : 400,
              }}
            >
              All Alerts
            </button>
            <button
              onClick={() => setUnreadOnly(true)}
              style={{
                fontSize: '0.75rem',
                padding: '0.2rem 0.5rem',
                borderRadius: 'var(--radius-sm)',
                border: 'none',
                cursor: 'pointer',
                backgroundColor: unreadOnly ? 'var(--graphite)' : 'transparent',
                color: unreadOnly ? '#FFFFFF' : 'var(--text-secondary)',
                fontWeight: unreadOnly ? 600 : 400,
              }}
            >
              Unread Only
            </button>
          </div>

          {/* Alert List */}
          <div style={{ overflowY: 'auto', flex: 1, padding: '0.5rem 0' }}>
            {isLoading ? (
              <div style={{ padding: '2rem 1rem', textAlign: 'center', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                Loading activity alerts...
              </div>
            ) : !notifications || notifications.length === 0 ? (
              <div style={{ padding: '2.5rem 1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
                <Check size={24} color="var(--success)" style={{ margin: '0 auto 0.5rem auto', display: 'block' }} />
                No security alerts found.
              </div>
            ) : (
              notifications.map((alert) => (
                <div
                  key={alert.id}
                  onClick={() => handleMarkAsRead(alert)}
                  style={{
                    padding: '0.75rem 1rem',
                    borderBottom: '1px solid var(--border)',
                    backgroundColor: alert.is_read ? '#FFFFFF' : 'rgba(217, 154, 103, 0.04)',
                    cursor: alert.is_read ? 'default' : 'pointer',
                    transition: 'background-color 0.15s ease',
                    position: 'relative',
                  }}
                  onMouseEnter={(e) => {
                    if (!alert.is_read) e.currentTarget.style.backgroundColor = 'rgba(217, 154, 103, 0.08)';
                  }}
                  onMouseLeave={(e) => {
                    if (!alert.is_read) e.currentTarget.style.backgroundColor = 'rgba(217, 154, 103, 0.04)';
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                      {!alert.is_read && (
                        <span style={{
                          width: '6px',
                          height: '6px',
                          borderRadius: '50%',
                          backgroundColor: 'var(--copper-dark)',
                          display: 'inline-block',
                          flexShrink: 0,
                        }} />
                      )}
                      <span style={{ fontWeight: 600, fontSize: '0.8125rem', color: 'var(--graphite)' }}>
                        {alert.title}
                      </span>
                    </div>
                    {getSeverityBadge(alert.severity)}
                  </div>

                  <p style={{
                    fontSize: '0.75rem',
                    color: 'var(--text-primary)',
                    margin: '0 0 0.375rem 0',
                    lineHeight: 1.35,
                  }}>
                    {alert.message}
                  </p>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                    <Clock size={11} />
                    <span>{formatToIST(alert.created_at)}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
};
