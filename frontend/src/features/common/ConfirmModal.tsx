import React from 'react';
import { AlertTriangle, X } from 'lucide-react';

interface ConfirmModalProps {
  isOpen: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'danger' | 'warning' | 'primary';
  isLoading?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export const ConfirmModal: React.FC<ConfirmModalProps> = ({
  isOpen,
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  variant = 'danger',
  isLoading = false,
  onConfirm,
  onCancel,
}) => {
  if (!isOpen) return null;

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(28, 29, 30, 0.65)',
      backdropFilter: 'blur(3px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 120,
      padding: '1rem',
    }}>
      <div style={{
        backgroundColor: '#FFFFFF',
        borderRadius: 'var(--radius-md)',
        boxShadow: 'var(--shadow-lg)',
        maxWidth: '460px',
        width: '100%',
        border: '1px solid var(--border)',
        overflow: 'hidden',
      }}>
        {/* Header with Icon */}
        <div style={{
          padding: '1.25rem 1.25rem 0.875rem',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '0.875rem',
        }}>
          <div style={{
            width: '38px',
            height: '38px',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: variant === 'danger' ? 'var(--danger-bg)' : 'rgba(217, 154, 103, 0.15)',
            border: `1px solid ${variant === 'danger' ? 'var(--danger-border)' : 'rgba(217, 154, 103, 0.3)'}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
            color: variant === 'danger' ? 'var(--danger)' : 'var(--copper-dark)',
          }}>
            <AlertTriangle size={20} />
          </div>

          <div style={{ flex: 1 }}>
            <h3 style={{
              fontSize: '1rem',
              fontWeight: 600,
              color: 'var(--graphite)',
              margin: '0 0 0.375rem 0',
            }}>
              {title}
            </h3>
            <p style={{
              fontSize: '0.8125rem',
              color: 'var(--text-secondary)',
              margin: 0,
              lineHeight: 1.45,
            }}>
              {message}
            </p>
          </div>

          <button
            onClick={onCancel}
            disabled={isLoading}
            className="btn btn-secondary btn-sm"
            style={{ padding: '0.25rem', minHeight: 'auto', border: 'none', background: 'transparent' }}
          >
            <X size={16} color="var(--text-muted)" />
          </button>
        </div>

        {/* Footer Actions */}
        <div style={{
          padding: '1rem 1.25rem',
          backgroundColor: 'var(--bg-warm)',
          borderTop: '1px solid var(--border)',
          display: 'flex',
          justifyContent: 'flex-end',
          gap: '0.625rem',
        }}>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={onCancel}
            disabled={isLoading}
            style={{ padding: '0.45rem 0.875rem' }}
          >
            {cancelLabel}
          </button>

          <button
            type="button"
            className={`btn ${variant === 'danger' ? 'btn-danger' : 'btn-primary'} btn-sm`}
            onClick={onConfirm}
            disabled={isLoading}
            style={{ padding: '0.45rem 1rem', minWidth: '90px' }}
          >
            {isLoading ? 'Processing...' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
};
