import React, { createContext, useContext, useState, useCallback } from 'react';
import { CheckCircle2, AlertCircle, Info, X } from 'lucide-react';

export type ToastType = 'success' | 'error' | 'info';

export interface ToastItem {
  id: string;
  message: string;
  type: ToastType;
}

interface ToastContextValue {
  showToast: (message: string, type?: ToastType) => void;
  toast: {
    success: (message: string) => void;
    error: (message: string) => void;
    info: (message: string) => void;
  };
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const showToast = useCallback((message: string, type: ToastType = 'success') => {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts((prev) => [...prev, { id, message, type }]);

    // Auto-dismiss after 4 seconds
    setTimeout(() => {
      removeToast(id);
    }, 4000);
  }, [removeToast]);

  const toast = {
    success: useCallback((msg: string) => showToast(msg, 'success'), [showToast]),
    error: useCallback((msg: string) => showToast(msg, 'error'), [showToast]),
    info: useCallback((msg: string) => showToast(msg, 'info'), [showToast]),
  };

  return (
    <ToastContext.Provider value={{ showToast, toast }}>
      {children}
      {/* Workspace Notification Container - Fixed Bottom Right */}
      <div
        style={{
          position: 'fixed',
          bottom: '24px',
          right: '24px',
          zIndex: 99999,
          display: 'flex',
          flexDirection: 'column',
          gap: '10px',
          maxWidth: '420px',
          pointerEvents: 'none',
        }}
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            style={{
              pointerEvents: 'auto',
              backgroundColor: '#242526',
              color: '#F6F3F0',
              borderRadius: '8px',
              padding: '12px 16px',
              boxShadow: '0 20px 25px -5px rgba(28, 29, 30, 0.4), 0 8px 10px -6px rgba(28, 29, 30, 0.3)',
              border: '1px solid #48494A',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '12px',
              animation: 'toastSlideUp 0.25s cubic-bezier(0.16, 1, 0.3, 1) forwards',
              fontFamily: "var(--font-family)",
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1 }}>
              {t.type === 'success' && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: '24px',
                    height: '24px',
                    borderRadius: '50%',
                    backgroundColor: 'rgba(30, 126, 52, 0.2)',
                    flexShrink: 0,
                  }}
                >
                  <CheckCircle2 size={18} color="#22c55e" strokeWidth={2.4} />
                </div>
              )}
              {t.type === 'error' && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: '24px',
                    height: '24px',
                    borderRadius: '50%',
                    backgroundColor: 'rgba(197, 48, 48, 0.2)',
                    flexShrink: 0,
                  }}
                >
                  <AlertCircle size={18} color="#ef4444" strokeWidth={2.4} />
                </div>
              )}
              {t.type === 'info' && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: '24px',
                    height: '24px',
                    borderRadius: '50%',
                    backgroundColor: 'rgba(217, 154, 103, 0.2)',
                    flexShrink: 0,
                  }}
                >
                  <Info size={18} color="#D99A67" strokeWidth={2.4} />
                </div>
              )}
              <span
                style={{
                  fontSize: '0.875rem',
                  fontWeight: 500,
                  lineHeight: '1.4',
                  color: '#F6F3F0',
                }}
              >
                {t.message}
              </span>
            </div>

            <button
              onClick={() => removeToast(t.id)}
              style={{
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                color: '#8B8985',
                padding: '4px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                borderRadius: '4px',
                transition: 'color 0.15s ease',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.color = '#FFFFFF')}
              onMouseLeave={(e) => (e.currentTarget.style.color = '#8B8985')}
              aria-label="Dismiss notification"
            >
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
};

export const useToast = (): ToastContextValue => {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
};
