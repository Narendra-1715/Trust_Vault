import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider, useAuth } from './features/auth/AuthContext';
import { AppLayout } from './layouts/AppLayout';
import { LandingPage } from './routes/LandingPage';
import { LoginPage } from './routes/LoginPage';
import { DocumentsPage } from './routes/DocumentsPage';
import { DocumentDetailPage } from './routes/DocumentDetailPage';
import { AuditPage } from './routes/AuditPage';
import { AdminPage } from './routes/AdminPage';
import { PrivacyPage } from './routes/PrivacyPage';
import { TermsPage } from './routes/TermsPage';
import { NotFoundPage } from './routes/NotFoundPage';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <div style={{ padding: '4rem', textAlign: 'center' }}>Authenticating session...</div>;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};

export const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<AppLayout />}>
              <Route index element={<LandingPage />} />
              <Route path="login" element={<LoginPage />} />
              
              {/* Protected Routes */}
              <Route path="documents" element={
                <ProtectedRoute>
                  <DocumentsPage />
                </ProtectedRoute>
              } />
              
              <Route path="documents/:id" element={
                <ProtectedRoute>
                  <DocumentDetailPage />
                </ProtectedRoute>
              } />

              <Route path="audit" element={
                <ProtectedRoute>
                  <AuditPage />
                </ProtectedRoute>
              } />

              <Route path="admin" element={
                <ProtectedRoute>
                  <AdminPage />
                </ProtectedRoute>
              } />

              {/* Public Legal Pages */}
              <Route path="privacy" element={<PrivacyPage />} />
              <Route path="terms" element={<TermsPage />} />

              {/* 404 */}
              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
};
