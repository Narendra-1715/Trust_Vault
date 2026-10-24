import React, { useState } from 'react';
import { Outlet, Link, useLocation, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '../features/auth/AuthContext';
import { Shield, FileText, Activity, Users, LogOut, Lock, Laptop, KeyRound, ShieldAlert } from 'lucide-react';
import { SessionManagementModal } from '../features/auth/SessionManagementModal';
import { NotificationBell } from '../features/notifications/NotificationBell';
import { api } from '../lib/api';

export const AppLayout: React.FC = () => {
  const { user, logout, isAuthenticated } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [isSessionsOpen, setIsSessionsOpen] = useState(false);

  const { data: pendingRequests } = useQuery({
    queryKey: ['incomingRequests', 'pending'],
    queryFn: () => api.getIncomingAccessRequests('pending'),
    enabled: isAuthenticated,
    refetchInterval: 15000,
  });
  const pendingCount = pendingRequests?.length || 0;

  const { data: alertMetrics } = useQuery({
    queryKey: ['securityAlertMetricsNav'],
    queryFn: () => api.getSecurityAlertMetrics(),
    enabled: isAuthenticated && user?.role === 'admin',
    refetchInterval: 15000,
  });
  const openAlertsCount = alertMetrics?.open_alerts || 0;

  const handleSignOut = () => {
    logout();
    navigate('/login');
  };

  const isAuthPage = location.pathname === '/login';

  // For the dedicated two-column login experience
  if (isAuthPage) {
    return (
      <div style={{ minHeight: '100vh', backgroundColor: 'var(--bg-warm)' }}>
        <Outlet />
      </div>
    );
  }

  const isActive = (path: string) => location.pathname === path || location.pathname.startsWith(`${path}/`);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', backgroundColor: 'var(--bg-warm)' }}>
      {/* ================= COMPACT ENTERPRISE HEADER ================= */}
      <header style={{
        backgroundColor: '#FFFFFF',
        borderBottom: '1px solid var(--border)',
        position: 'sticky',
        top: 0,
        zIndex: 40,
        boxShadow: 'var(--shadow-sm)',
      }}>
        <div className="container" style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          height: '3.75rem',
        }}>
          {/* Brand & Left Navigation */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
            <Link 
              to={isAuthenticated ? "/documents" : "/"} 
              style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}
            >
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--graphite)',
                border: '1px solid var(--border-dark)',
                color: 'var(--copper)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: 'var(--shadow-sm)',
                flexShrink: 0,
              }}>
                <Shield size={17} strokeWidth={2.2} />
              </div>
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                <span style={{ 
                  fontSize: '1rem', 
                  fontWeight: 700, 
                  letterSpacing: '-0.02em', 
                  color: 'var(--graphite)',
                  lineHeight: 1.15,
                }}>
                  TrustVault
                </span>
                <span style={{ 
                  fontSize: '0.5625rem', 
                  color: 'var(--copper-dark)', 
                  fontWeight: 700, 
                  letterSpacing: '0.06em', 
                  textTransform: 'uppercase',
                }}>
                  Confidential Core
                </span>
              </div>
            </Link>

            {/* Main Navigation Links */}
            {isAuthenticated && (
              <nav style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                <Link
                  to="/documents"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.375rem',
                    padding: '0.375rem 0.75rem',
                    fontSize: '0.8125rem',
                    fontWeight: isActive('/documents') ? 600 : 500,
                    color: isActive('/documents') ? 'var(--graphite)' : 'var(--text-secondary)',
                    backgroundColor: isActive('/documents') ? 'var(--copper-light)' : 'transparent',
                    border: `1px solid ${isActive('/documents') ? 'var(--copper-border)' : 'transparent'}`,
                    borderRadius: 'var(--radius-sm)',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <FileText size={15} color={isActive('/documents') ? 'var(--copper-dark)' : 'currentColor'} />
                  <span>Documents</span>
                </Link>

                <Link
                  to="/requests"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.375rem',
                    padding: '0.375rem 0.75rem',
                    fontSize: '0.8125rem',
                    fontWeight: isActive('/requests') ? 600 : 500,
                    color: isActive('/requests') ? 'var(--graphite)' : 'var(--text-secondary)',
                    backgroundColor: isActive('/requests') ? 'var(--copper-light)' : 'transparent',
                    border: `1px solid ${isActive('/requests') ? 'var(--copper-border)' : 'transparent'}`,
                    borderRadius: 'var(--radius-sm)',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <KeyRound size={15} color={isActive('/requests') ? 'var(--copper-dark)' : 'currentColor'} />
                  <span>Requests</span>
                  {pendingCount > 0 && (
                    <span style={{
                      backgroundColor: 'var(--copper)',
                      color: '#FFFFFF',
                      fontSize: '0.625rem',
                      fontWeight: 700,
                      padding: '0.0625rem 0.375rem',
                      borderRadius: '10px',
                      lineHeight: 1.3,
                    }}>
                      {pendingCount}
                    </span>
                  )}
                </Link>

                <Link
                  to="/audit"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.375rem',
                    padding: '0.375rem 0.75rem',
                    fontSize: '0.8125rem',
                    fontWeight: isActive('/audit') ? 600 : 500,
                    color: isActive('/audit') ? 'var(--graphite)' : 'var(--text-secondary)',
                    backgroundColor: isActive('/audit') ? 'var(--copper-light)' : 'transparent',
                    border: `1px solid ${isActive('/audit') ? 'var(--copper-border)' : 'transparent'}`,
                    borderRadius: 'var(--radius-sm)',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <Activity size={15} color={isActive('/audit') ? 'var(--copper-dark)' : 'currentColor'} />
                  <span>Audit Trail</span>
                </Link>

                {user?.role === 'admin' && (
                  <>
                    <Link
                      to="/admin/alerts"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.375rem',
                        padding: '0.375rem 0.75rem',
                        fontSize: '0.8125rem',
                        fontWeight: isActive('/admin/alerts') ? 600 : 500,
                        color: isActive('/admin/alerts') ? 'var(--graphite)' : 'var(--text-secondary)',
                        backgroundColor: isActive('/admin/alerts') ? 'var(--copper-light)' : 'transparent',
                        border: `1px solid ${isActive('/admin/alerts') ? 'var(--copper-border)' : 'transparent'}`,
                        borderRadius: 'var(--radius-sm)',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      <ShieldAlert size={15} color={isActive('/admin/alerts') ? 'var(--copper-dark)' : 'currentColor'} />
                      <span>Security Alerts</span>
                      {openAlertsCount > 0 && (
                        <span style={{
                          backgroundColor: '#B91C1C',
                          color: '#FFFFFF',
                          fontSize: '0.625rem',
                          fontWeight: 700,
                          padding: '0.0625rem 0.375rem',
                          borderRadius: '10px',
                          lineHeight: 1.3,
                        }}>
                          {openAlertsCount}
                        </span>
                      )}
                    </Link>

                    <Link
                      to="/admin"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.375rem',
                        padding: '0.375rem 0.75rem',
                        fontSize: '0.8125rem',
                        fontWeight: isActive('/admin') && !isActive('/admin/alerts') ? 600 : 500,
                        color: isActive('/admin') && !isActive('/admin/alerts') ? 'var(--graphite)' : 'var(--text-secondary)',
                        backgroundColor: isActive('/admin') && !isActive('/admin/alerts') ? 'var(--copper-light)' : 'transparent',
                        border: `1px solid ${isActive('/admin') && !isActive('/admin/alerts') ? 'var(--copper-border)' : 'transparent'}`,
                        borderRadius: 'var(--radius-sm)',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      <Users size={15} color={isActive('/admin') && !isActive('/admin/alerts') ? 'var(--copper-dark)' : 'currentColor'} />
                      <span>Admin</span>
                    </Link>
                  </>
                )}
              </nav>
            )}
          </div>

          {/* Right Controls: User Profile & Actions */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            {isAuthenticated ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
                <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column' }}>
                  <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {user?.display_name}
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', justifyContent: 'flex-end' }}>
                    <span className={`badge ${
                      user?.role === 'admin' 
                        ? 'badge-copper' 
                        : user?.role === 'owner' 
                        ? 'badge-green' 
                        : 'badge-gray'
                    }`} style={{ textTransform: 'uppercase', fontSize: '0.625rem', padding: '0.1rem 0.4rem' }}>
                      {user?.role}
                    </span>
                  </div>
                </div>

                <NotificationBell />

                <button
                  onClick={() => setIsSessionsOpen(true)}
                  className="btn btn-secondary btn-sm"
                  title="Manage Active Login Sessions"
                  style={{ gap: '0.375rem', padding: '0.35rem 0.625rem' }}
                >
                  <Laptop size={14} color="var(--copper-dark)" />
                  <span>Sessions</span>
                </button>

                <button
                  onClick={handleSignOut}
                  className="btn btn-secondary btn-sm"
                  title="Sign out of TrustVault"
                  style={{ gap: '0.375rem', padding: '0.35rem 0.625rem' }}
                >
                  <LogOut size={14} color="var(--text-secondary)" />
                  <span>Sign out</span>
                </button>
              </div>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <Link to="/login" className="btn btn-primary btn-sm" style={{ gap: '0.375rem' }}>
                  <Lock size={14} />
                  <span>Sign in</span>
                </Link>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* ================= MAIN CONTENT ================= */}
      <main style={{ flex: 1, padding: '2rem 0' }}>
        <Outlet />
      </main>

      {/* ================= CORPORATE FOOTER ================= */}
      <footer style={{
        backgroundColor: '#FFFFFF',
        borderTop: '1px solid var(--border)',
        padding: '1.25rem 0',
        fontSize: '0.8125rem',
        color: 'var(--text-muted)',
      }}>
        <div className="container" style={{
          display: 'flex',
          flexDirection: 'row',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontWeight: 600, color: 'var(--graphite)' }}>TrustVault</span>
            <span>&bull;</span>
            <span>Confidential Document Security Architecture &copy; 2026.</span>
          </div>
          <div style={{ display: 'flex', gap: '1.5rem', fontSize: '0.75rem' }}>
            <Link to="/privacy" style={{ color: 'var(--text-secondary)' }} className="hover:underline">
              Privacy Policy
            </Link>
            <Link to="/terms" style={{ color: 'var(--text-secondary)' }} className="hover:underline">
              Terms &amp; Conditions
            </Link>
          </div>
        </div>
      </footer>

      {/* Active Session Management Modal */}
      <SessionManagementModal
        isOpen={isSessionsOpen}
        onClose={() => setIsSessionsOpen(false)}
      />
    </div>
  );
};
