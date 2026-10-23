import React from 'react';
import { Outlet, Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../features/auth/AuthContext';
import { Shield, FileText, Activity, Users, LogOut, Lock } from 'lucide-react';

export const AppLayout: React.FC = () => {
  const { user, logout, isAuthenticated } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

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
                  <Link
                    to="/admin"
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.375rem',
                      padding: '0.375rem 0.75rem',
                      fontSize: '0.8125rem',
                      fontWeight: isActive('/admin') ? 600 : 500,
                      color: isActive('/admin') ? 'var(--graphite)' : 'var(--text-secondary)',
                      backgroundColor: isActive('/admin') ? 'var(--copper-light)' : 'transparent',
                      border: `1px solid ${isActive('/admin') ? 'var(--copper-border)' : 'transparent'}`,
                      borderRadius: 'var(--radius-sm)',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    <Users size={15} color={isActive('/admin') ? 'var(--copper-dark)' : 'currentColor'} />
                    <span>Admin</span>
                  </Link>
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
    </div>
  );
};
