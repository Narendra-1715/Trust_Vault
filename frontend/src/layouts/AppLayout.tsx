import React, { useState, useEffect } from 'react';
import { Outlet, Link, useLocation, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '../features/auth/AuthContext';
import { 
  Shield, 
  FileText, 
  Activity, 
  Users, 
  LogOut, 
  Lock, 
  Laptop, 
  KeyRound, 
  ShieldAlert,
  Menu,
  X
} from 'lucide-react';
import { SessionManagementModal } from '../features/auth/SessionManagementModal';
import { NotificationBell } from '../features/notifications/NotificationBell';
import { useLiveWebSocket } from '../features/notifications/useLiveWebSocket';
import { api } from '../lib/api';

export const AppLayout: React.FC = () => {
  const { user, logout, isAuthenticated } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [isSessionsOpen, setIsSessionsOpen] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  // Initialize Real-Time WebSocket stream
  const { isConnected: isWsLive } = useLiveWebSocket();

  // Close mobile navigation drawer whenever current route changes
  useEffect(() => {
    setIsMobileMenuOpen(false);
  }, [location.pathname]);

  const { data: pendingRequests } = useQuery({
    queryKey: ['incomingRequests', 'pending'],
    queryFn: () => api.getIncomingAccessRequests('pending'),
    enabled: isAuthenticated,
    refetchInterval: 30000,
  });
  const pendingCount = pendingRequests?.length || 0;

  const { data: alertMetrics } = useQuery({
    queryKey: ['securityAlertMetricsNav'],
    queryFn: () => api.getSecurityAlertMetrics(),
    enabled: isAuthenticated && user?.role === 'admin',
    refetchInterval: 30000,
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
      {/* ================= ENTERPRISE HEADER ================= */}
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
          {/* Brand & Desktop Navigation */}
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

            {/* Desktop Navigation Links */}
            {isAuthenticated && (
              <nav className="desktop-nav">
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

          {/* Desktop Right Controls: User Profile & Actions */}
          <div className="desktop-user-actions">
            {isAuthenticated ? (
              <>
                {/* Live WebSocket Status Pill */}
                <div 
                  title={isWsLive ? "Real-time WebSocket stream active" : "Reconnecting to real-time notification stream..."}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.35rem',
                    padding: '0.2rem 0.5rem',
                    borderRadius: '9999px',
                    backgroundColor: isWsLive ? 'var(--success-bg)' : 'var(--bg-surface-secondary)',
                    border: `1px solid ${isWsLive ? 'var(--success-border)' : 'var(--border)'}`,
                    fontSize: '0.6875rem',
                    fontWeight: 600,
                    color: isWsLive ? 'var(--success)' : 'var(--text-muted)',
                    cursor: 'default'
                  }}
                >
                  <span className="pulse-dot" style={{
                    width: '6px',
                    height: '6px',
                    backgroundColor: isWsLive ? 'var(--success)' : 'var(--text-muted)'
                  }}></span>
                  <span>{isWsLive ? 'Live Stream' : 'Connecting'}</span>
                </div>

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
              </>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <Link to="/login" className="btn btn-primary btn-sm" style={{ gap: '0.375rem' }}>
                  <Lock size={14} />
                  <span>Sign in</span>
                </Link>
              </div>
            )}
          </div>

          {/* Mobile Right Controls (< 840px) */}
          <div className="mobile-header-actions">
            {isAuthenticated ? (
              <>
                {/* Compact Pulse Dot */}
                <div 
                  title={isWsLive ? "Real-time WebSocket stream active" : "Reconnecting to live WebSocket..."}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.25rem',
                    padding: '0.2rem 0.35rem',
                    borderRadius: '9999px',
                    backgroundColor: isWsLive ? 'var(--success-bg)' : 'var(--bg-surface-secondary)',
                    border: `1px solid ${isWsLive ? 'var(--success-border)' : 'var(--border)'}`,
                  }}
                >
                  <span className="pulse-dot" style={{
                    width: '6px',
                    height: '6px',
                    backgroundColor: isWsLive ? 'var(--success)' : 'var(--text-muted)'
                  }}></span>
                </div>

                <NotificationBell />

                <button
                  onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
                  className="btn btn-secondary btn-sm mobile-nav-toggle"
                  title="Toggle Navigation Menu"
                  aria-label="Navigation Menu"
                  style={{ padding: '0.4rem 0.5rem' }}
                >
                  {isMobileMenuOpen ? <X size={18} /> : <Menu size={18} />}
                </button>
              </>
            ) : (
              <Link to="/login" className="btn btn-primary btn-sm" style={{ gap: '0.375rem' }}>
                <Lock size={14} />
                <span>Sign in</span>
              </Link>
            )}
          </div>
        </div>

        {/* Mobile Dropdown Drawer */}
        {isAuthenticated && isMobileMenuOpen && (
          <div style={{
            borderTop: '1px solid var(--border)',
            backgroundColor: '#FFFFFF',
            padding: '1rem',
            boxShadow: 'var(--shadow-lg)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.75rem'
          }}>
            {/* User Profile Info Card */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '0.625rem 0.75rem',
              backgroundColor: 'var(--bg-surface-secondary)',
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border)'
            }}>
              <div>
                <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {user?.display_name}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  {user?.email}
                </div>
              </div>
              <span className={`badge ${
                user?.role === 'admin' 
                  ? 'badge-copper' 
                  : user?.role === 'owner' 
                  ? 'badge-green' 
                  : 'badge-gray'
              }`} style={{ textTransform: 'uppercase', fontSize: '0.625rem' }}>
                {user?.role}
              </span>
            </div>

            {/* Navigation links */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
              <Link
                to="/documents"
                onClick={() => setIsMobileMenuOpen(false)}
                className="btn btn-secondary"
                style={{
                  justifyContent: 'flex-start',
                  width: '100%',
                  backgroundColor: isActive('/documents') ? 'var(--copper-light)' : undefined,
                  borderColor: isActive('/documents') ? 'var(--copper-border)' : undefined,
                  fontWeight: isActive('/documents') ? 600 : 500
                }}
              >
                <FileText size={16} color="var(--copper-dark)" />
                <span>Documents</span>
              </Link>

              <Link
                to="/requests"
                onClick={() => setIsMobileMenuOpen(false)}
                className="btn btn-secondary"
                style={{
                  justifyContent: 'space-between',
                  width: '100%',
                  backgroundColor: isActive('/requests') ? 'var(--copper-light)' : undefined,
                  borderColor: isActive('/requests') ? 'var(--copper-border)' : undefined,
                  fontWeight: isActive('/requests') ? 600 : 500
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <KeyRound size={16} color="var(--copper-dark)" />
                  <span>Access Requests</span>
                </div>
                {pendingCount > 0 && (
                  <span className="badge badge-copper" style={{ fontSize: '0.6875rem' }}>
                    {pendingCount}
                  </span>
                )}
              </Link>

              <Link
                to="/audit"
                onClick={() => setIsMobileMenuOpen(false)}
                className="btn btn-secondary"
                style={{
                  justifyContent: 'flex-start',
                  width: '100%',
                  backgroundColor: isActive('/audit') ? 'var(--copper-light)' : undefined,
                  borderColor: isActive('/audit') ? 'var(--copper-border)' : undefined,
                  fontWeight: isActive('/audit') ? 600 : 500
                }}
              >
                <Activity size={16} color="var(--copper-dark)" />
                <span>Audit Trail</span>
              </Link>

              {user?.role === 'admin' && (
                <>
                  <Link
                    to="/admin/alerts"
                    onClick={() => setIsMobileMenuOpen(false)}
                    className="btn btn-secondary"
                    style={{
                      justifyContent: 'space-between',
                      width: '100%',
                      backgroundColor: isActive('/admin/alerts') ? 'var(--copper-light)' : undefined,
                      borderColor: isActive('/admin/alerts') ? 'var(--copper-border)' : undefined,
                      fontWeight: isActive('/admin/alerts') ? 600 : 500
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <ShieldAlert size={16} color="var(--danger)" />
                      <span>Security Alerts</span>
                    </div>
                    {openAlertsCount > 0 && (
                      <span className="badge badge-red" style={{ fontSize: '0.6875rem' }}>
                        {openAlertsCount}
                      </span>
                    )}
                  </Link>

                  <Link
                    to="/admin"
                    onClick={() => setIsMobileMenuOpen(false)}
                    className="btn btn-secondary"
                    style={{
                      justifyContent: 'flex-start',
                      width: '100%',
                      backgroundColor: isActive('/admin') && !isActive('/admin/alerts') ? 'var(--copper-light)' : undefined,
                      borderColor: isActive('/admin') && !isActive('/admin/alerts') ? 'var(--copper-border)' : undefined,
                      fontWeight: isActive('/admin') && !isActive('/admin/alerts') ? 600 : 500
                    }}
                  >
                    <Users size={16} color="var(--copper-dark)" />
                    <span>Admin Console</span>
                  </Link>
                </>
              )}
            </div>

            {/* Quick Actions (Sessions & Sign out) */}
            <div style={{ 
              display: 'grid', 
              gridTemplateColumns: '1fr 1fr', 
              gap: '0.5rem', 
              paddingTop: '0.625rem', 
              borderTop: '1px solid var(--border-subtle)' 
            }}>
              <button
                onClick={() => {
                  setIsMobileMenuOpen(false);
                  setIsSessionsOpen(true);
                }}
                className="btn btn-secondary btn-sm"
                style={{ width: '100%', justifyContent: 'center' }}
              >
                <Laptop size={14} color="var(--copper-dark)" />
                <span>Sessions</span>
              </button>

              <button
                onClick={handleSignOut}
                className="btn btn-secondary btn-sm"
                style={{ width: '100%', justifyContent: 'center', color: 'var(--danger)' }}
              >
                <LogOut size={14} />
                <span>Sign out</span>
              </button>
            </div>

            {/* WebSocket Stream Diagnostic Status */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.4rem',
              fontSize: '0.6875rem',
              color: isWsLive ? 'var(--success)' : 'var(--text-muted)',
              paddingTop: '0.25rem'
            }}>
              <span className="pulse-dot" style={{
                width: '6px',
                height: '6px',
                backgroundColor: isWsLive ? 'var(--success)' : 'var(--text-muted)'
              }}></span>
              <span>WebSocket Stream: {isWsLive ? 'Connected & Live' : 'Connecting...'}</span>
            </div>
          </div>
        )}
      </header>

      {/* ================= MAIN CONTENT ================= */}
      <main className="main-content">
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
