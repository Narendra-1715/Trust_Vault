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

  const isActive = (path: string) => location.pathname === path || location.pathname.startsWith(`${path}/`);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      {/* Top Enterprise Header */}
      <header style={{
        backgroundColor: '#ffffff',
        borderBottom: '1px solid var(--border-main)',
        position: 'sticky',
        top: 0,
        zIndex: 40
      }}>
        <div className="container" style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          height: '4rem'
        }}>
          {/* Brand */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
            <Link to={isAuthenticated ? "/documents" : "/"} style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', fontWeight: 700, fontSize: '1.125rem', color: 'var(--primary)' }}>
              <div style={{
                backgroundColor: '#0f172a',
                color: '#38bdf8',
                padding: '0.375rem',
                borderRadius: 'var(--radius-sm)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                <Shield size={20} strokeWidth={2.2} />
              </div>
              <span style={{ letterSpacing: '-0.02em' }}>TrustVault</span>
            </Link>

            {/* Main Navigation */}
            {isAuthenticated && (
              <nav style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Link
                  to="/documents"
                  className={`btn btn-sm ${isActive('/documents') ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ border: isActive('/documents') ? 'none' : '1px solid transparent' }}
                >
                  <FileText size={16} />
                  <span>Documents</span>
                </Link>

                <Link
                  to="/audit"
                  className={`btn btn-sm ${isActive('/audit') ? 'btn-primary' : 'btn-secondary'}`}
                  style={{ border: isActive('/audit') ? 'none' : '1px solid transparent' }}
                >
                  <Activity size={16} />
                  <span>Audit Trail</span>
                </Link>

                {user?.role === 'admin' && (
                  <Link
                    to="/admin"
                    className={`btn btn-sm ${isActive('/admin') ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ border: isActive('/admin') ? 'none' : '1px solid transparent' }}
                  >
                    <Users size={16} />
                    <span>Admin</span>
                  </Link>
                )}
              </nav>
            )}
          </div>

          {/* Right Controls */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            {isAuthenticated ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column' }}>
                  <span style={{ fontSize: '0.8125rem', fontWeight: 600 }}>{user?.display_name}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', justifyContent: 'flex-end' }}>
                    <span className={`badge ${
                      user?.role === 'admin' ? 'badge-blue' : user?.role === 'owner' ? 'badge-green' : 'badge-gray'
                    }`} style={{ textTransform: 'uppercase', fontSize: '0.6875rem' }}>
                      {user?.role}
                    </span>
                  </div>
                </div>

                <button
                  onClick={handleSignOut}
                  className="btn btn-secondary btn-sm"
                  title="Sign out of TrustVault"
                >
                  <LogOut size={15} />
                  <span>Sign out</span>
                </button>
              </div>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <Link to="/login" className="btn btn-primary btn-sm">
                  <Lock size={15} />
                  <span>Sign in</span>
                </Link>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main style={{ flex: 1, padding: '2rem 0' }}>
        <Outlet />
      </main>

      {/* Footer */}
      <footer style={{
        backgroundColor: '#ffffff',
        borderTop: '1px solid var(--border-main)',
        padding: '1.5rem 0',
        fontSize: '0.8125rem',
        color: 'var(--text-muted)'
      }}>
        <div className="container" style={{
          display: 'flex',
          flexDirection: 'row',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem'
        }}>
          <div>
            <span>TrustVault Confidential Workspace &copy; 2026. Security-First Architecture.</span>
          </div>
          <div style={{ display: 'flex', gap: '1.5rem' }}>
            <Link to="/privacy" style={{ color: 'var(--text-secondary)', textDecoration: 'underline' }}>Privacy Policy</Link>
            <Link to="/terms" style={{ color: 'var(--text-secondary)', textDecoration: 'underline' }}>Terms &amp; Conditions</Link>
          </div>
        </div>
      </footer>
    </div>
  );
};
