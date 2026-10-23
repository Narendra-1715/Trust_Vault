import React, { createContext, useContext, useState, useEffect } from 'react';
import type { User } from '../../types';
import { api, getAuthToken, clearAuthToken } from '../../lib/api';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, pass: string) => Promise<void>;
  register: (email: string, pass: string, displayName: string, role?: string) => Promise<void>;
  logout: () => void;
  refetchUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchProfile = async () => {
    const token = getAuthToken();
    if (!token) {
      setUser(null);
      setIsLoading(false);
      return;
    }
    try {
      const u = await api.getCurrentUser();
      setUser(u);
    } catch {
      clearAuthToken();
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchProfile();

    // Active session heartbeat: verify session validity every 15s and on window focus
    const checkSession = async () => {
      const token = getAuthToken();
      if (!token) return;
      try {
        await api.getCurrentUser();
      } catch (err: any) {
        if (err?.statusCode === 401 || err?.status === 401) {
          clearAuthToken();
          setUser(null);
          if (window.location.pathname !== '/login' && window.location.pathname !== '/') {
            window.location.href = '/login?expired=true';
          }
        }
      }
    };

    const interval = setInterval(checkSession, 15000);
    window.addEventListener('focus', checkSession);

    return () => {
      clearInterval(interval);
      window.removeEventListener('focus', checkSession);
    };
  }, []);

  const login = async (email: string, pass: string) => {
    await api.login({ email, password: pass });
    await fetchProfile();
  };

  const register = async (email: string, pass: string, displayName: string, role: string = 'viewer') => {
    await api.register({ email, password: pass, display_name: displayName, role });
    await login(email, pass);
  };

  const logout = () => {
    clearAuthToken();
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
        refetchUser: fetchProfile,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
};
