import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { 
  KeyRound, 
  Clock, 
  CheckCircle, 
  XCircle, 
  AlertCircle, 
  FileText, 
  Check, 
  X, 
  ArrowRight,
  ShieldCheck
} from 'lucide-react';
import { api } from '../lib/api';
import { formatToIST } from '../lib/date';
import { useToast } from '../context/ToastContext';
import { ConfirmModal } from '../features/common/ConfirmModal';
import type { AccessRequest } from '../types';

export const RequestsPage: React.FC = () => {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<'incoming' | 'my'>('incoming');
  const [statusFilter, setStatusFilter] = useState<'all' | 'pending' | 'approved' | 'rejected' | 'cancelled'>('pending');

  // Decision Modal State
  const [approvingRequest, setApprovingRequest] = useState<AccessRequest | null>(null);
  const [approvedPermLevel, setApprovedPermLevel] = useState<'read' | 'edit'>('read');
  const [expiryPreset, setExpiryPreset] = useState<'never' | '1h' | '24h' | '7d' | '30d' | 'custom'>('7d');
  const [customExpiryDate, setCustomExpiryDate] = useState('');
  const [isApproving, setIsApproving] = useState(false);

  const [rejectingRequest, setRejectingRequest] = useState<AccessRequest | null>(null);
  const [rejectionReason, setRejectionReason] = useState('');
  const [isRejecting, setIsRejecting] = useState(false);

  // In-app confirm modal for cancelling
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

  // Queries
  const { data: incomingRequests, isLoading: isIncomingLoading, refetch: refetchIncoming } = useQuery({
    queryKey: ['incomingRequests', statusFilter],
    queryFn: () => api.getIncomingAccessRequests(statusFilter === 'all' ? undefined : statusFilter),
  });

  const { data: myRequests, isLoading: isMyLoading, refetch: refetchMy } = useQuery({
    queryKey: ['myAccessRequests'],
    queryFn: () => api.getMyAccessRequests(),
  });

  const pendingIncomingCount = incomingRequests?.filter(r => r.status === 'pending').length || 0;

  // Handle Approve
  const handleOpenApprove = (req: AccessRequest) => {
    setApprovingRequest(req);
    setApprovedPermLevel(req.requested_permission || 'read');
    if (req.requested_expiry) {
      setExpiryPreset('custom');
      setCustomExpiryDate(req.requested_expiry.slice(0, 16));
    } else {
      setExpiryPreset('7d');
      setCustomExpiryDate('');
    }
  };

  const handleConfirmApprove = async () => {
    if (!approvingRequest) return;
    setIsApproving(true);

    try {
      let finalExpiry: string | undefined = undefined;
      const now = new Date();

      if (expiryPreset === '1h') {
        finalExpiry = new Date(now.getTime() + 60 * 60 * 1000).toISOString();
      } else if (expiryPreset === '24h') {
        finalExpiry = new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString();
      } else if (expiryPreset === '7d') {
        finalExpiry = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();
      } else if (expiryPreset === '30d') {
        finalExpiry = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
      } else if (expiryPreset === 'custom' && customExpiryDate) {
        finalExpiry = new Date(customExpiryDate).toISOString();
      }

      await api.approveAccessRequest(approvingRequest.id, {
        approved_permission: approvedPermLevel,
        approved_expiry: finalExpiry,
      });

      toast.success(`Access granted to ${approvingRequest.requester_name || 'user'}. Permission is now active.`);
      setApprovingRequest(null);
      refetchIncoming();
      queryClient.invalidateQueries({ queryKey: ['auditEvents'] });
      queryClient.invalidateQueries({ queryKey: ['permissions'] });
    } catch (err: any) {
      toast.error(err.message || 'Failed to approve access request');
    } finally {
      setIsApproving(false);
    }
  };

  // Handle Reject
  const handleOpenReject = (req: AccessRequest) => {
    setRejectingRequest(req);
    setRejectionReason('');
  };

  const handleConfirmReject = async () => {
    if (!rejectingRequest) return;
    setIsRejecting(true);

    try {
      await api.rejectAccessRequest(rejectingRequest.id, {
        rejection_reason: rejectionReason.trim() || undefined,
      });

      toast.info('Access request was rejected. No permissions were granted.');
      setRejectingRequest(null);
      refetchIncoming();
      queryClient.invalidateQueries({ queryKey: ['auditEvents'] });
    } catch (err: any) {
      toast.error(err.message || 'Failed to reject access request');
    } finally {
      setIsRejecting(false);
    }
  };

  // Handle Cancel
  const handleCancelRequest = (req: AccessRequest) => {
    setConfirmConfig({
      isOpen: true,
      title: 'Cancel Access Request',
      message: 'Are you sure you want to withdraw your access request? The owner will no longer see this request as pending.',
      confirmLabel: 'Withdraw Request',
      variant: 'warning',
      isLoading: false,
      action: async () => {
        setConfirmConfig(prev => ({ ...prev, isLoading: true }));
        try {
          await api.cancelAccessRequest(req.id);
          toast.success('Access request withdrawn successfully.');
          refetchMy();
          setConfirmConfig(prev => ({ ...prev, isOpen: false, isLoading: false }));
        } catch (err: any) {
          toast.error(err.message || 'Failed to cancel request');
          setConfirmConfig(prev => ({ ...prev, isLoading: false }));
        }
      },
    });
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'pending':
        return (
          <span className="badge badge-warning" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            <Clock size={12} />
            <span>Pending Review</span>
          </span>
        );
      case 'approved':
        return (
          <span className="badge badge-success" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            <CheckCircle size={12} />
            <span>Approved & Active</span>
          </span>
        );
      case 'rejected':
        return (
          <span className="badge badge-danger" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            <XCircle size={12} />
            <span>Declined</span>
          </span>
        );
      case 'cancelled':
        return (
          <span className="badge" style={{ backgroundColor: 'var(--bg-warm)', color: 'var(--text-muted)', border: '1px solid var(--border)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            <AlertCircle size={12} />
            <span>Withdrawn</span>
          </span>
        );
      default:
        return <span className="badge">{status}</span>;
    }
  };

  return (
    <div className="container" style={{ padding: '2rem 0 4rem' }}>
      {/* Page Header */}
      <div style={{ marginBottom: '1.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', marginBottom: '0.375rem' }}>
          <div style={{
            width: '32px',
            height: '32px',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'rgba(217, 154, 103, 0.15)',
            border: '1px solid rgba(217, 154, 103, 0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--copper-dark)',
          }}>
            <KeyRound size={17} />
          </div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, margin: 0, color: 'var(--graphite)' }}>
            Access Requests
          </h1>
        </div>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', margin: 0 }}>
          Manage permission requests for your confidential documents and track your submitted access inquiries.
        </p>
      </div>

      {/* Tabs */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.5rem',
        borderBottom: '1px solid var(--border)',
        marginBottom: '1.5rem',
      }}>
        <button
          onClick={() => setActiveTab('incoming')}
          style={{
            padding: '0.625rem 1rem',
            fontSize: '0.875rem',
            fontWeight: activeTab === 'incoming' ? 600 : 500,
            color: activeTab === 'incoming' ? 'var(--graphite)' : 'var(--text-secondary)',
            borderBottom: `2px solid ${activeTab === 'incoming' ? 'var(--copper)' : 'transparent'}`,
            background: 'none',
            borderTop: 'none',
            borderLeft: 'none',
            borderRight: 'none',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <span>Incoming Requests</span>
          {pendingIncomingCount > 0 && (
            <span style={{
              backgroundColor: 'var(--copper)',
              color: '#FFFFFF',
              fontSize: '0.6875rem',
              fontWeight: 700,
              padding: '0.125rem 0.45rem',
              borderRadius: '10px',
            }}>
              {pendingIncomingCount}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('my')}
          style={{
            padding: '0.625rem 1rem',
            fontSize: '0.875rem',
            fontWeight: activeTab === 'my' ? 600 : 500,
            color: activeTab === 'my' ? 'var(--graphite)' : 'var(--text-secondary)',
            borderBottom: `2px solid ${activeTab === 'my' ? 'var(--copper)' : 'transparent'}`,
            background: 'none',
            borderTop: 'none',
            borderLeft: 'none',
            borderRight: 'none',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <span>My Submitted Requests</span>
          {myRequests && myRequests.length > 0 && (
            <span style={{
              backgroundColor: 'var(--bg-warm)',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border)',
              fontSize: '0.6875rem',
              fontWeight: 600,
              padding: '0.125rem 0.45rem',
              borderRadius: '10px',
            }}>
              {myRequests.length}
            </span>
          )}
        </button>
      </div>

      {/* Tab 1: Incoming Requests (Owner View) */}
      {activeTab === 'incoming' && (
        <div>
          {/* Status Filter Bar */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: '1rem',
            flexWrap: 'wrap',
            gap: '0.75rem',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginRight: '0.25rem' }}>
                Filter:
              </span>
              {(['pending', 'all', 'approved', 'rejected'] as const).map(f => (
                <button
                  key={f}
                  onClick={() => setStatusFilter(f)}
                  className="btn btn-sm"
                  style={{
                    padding: '0.25rem 0.625rem',
                    fontSize: '0.75rem',
                    backgroundColor: statusFilter === f ? 'var(--graphite)' : '#FFFFFF',
                    color: statusFilter === f ? '#FFFFFF' : 'var(--text-secondary)',
                    borderColor: statusFilter === f ? 'var(--graphite)' : 'var(--border)',
                    textTransform: 'capitalize',
                  }}
                >
                  {f}
                </button>
              ))}
            </div>

            <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
              Showing {incomingRequests?.length || 0} request{incomingRequests?.length === 1 ? '' : 's'}
            </span>
          </div>

          {/* List */}
          {isIncomingLoading ? (
            <div className="panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
              Loading incoming access requests...
            </div>
          ) : !incomingRequests || incomingRequests.length === 0 ? (
            <div className="panel" style={{ padding: '3.5rem 2rem', textAlign: 'center' }}>
              <div style={{
                width: '42px',
                height: '42px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'rgba(217, 154, 103, 0.1)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 0.875rem',
                color: 'var(--copper-dark)',
              }}>
                <ShieldCheck size={22} />
              </div>
              <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--graphite)', margin: '0 0 0.375rem 0' }}>
                No {statusFilter !== 'all' ? statusFilter : ''} access requests
              </h3>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: 0, maxWidth: '420px', marginLeft: 'auto', marginRight: 'auto' }}>
                When users in your organization request permission to access documents you own, they will appear here for review.
              </p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {incomingRequests.map(req => (
                <div 
                  key={req.id} 
                  className="panel"
                  style={{
                    padding: '1.25rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.875rem',
                    borderLeft: req.status === 'pending' ? '4px solid var(--copper)' : '1px solid var(--border)',
                  }}
                >
                  {/* Top Bar: Target Document & Status */}
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                        <FileText size={15} color="var(--copper-dark)" />
                        <Link 
                          to={`/documents/${req.document_id}`}
                          style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--graphite)', textDecoration: 'none' }}
                        >
                          {req.document_title || 'Confidential Document'}
                        </Link>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        <span>Requested by: <strong style={{ color: 'var(--text-primary)' }}>{req.requester_name || req.requester_email}</strong> ({req.requester_email})</span>
                        <span>&bull;</span>
                        <span>{formatToIST(req.created_at)}</span>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      {getStatusBadge(req.status)}
                    </div>
                  </div>

                  {/* Justification / Reason */}
                  <div style={{
                    backgroundColor: 'var(--bg-warm)',
                    padding: '0.75rem 1rem',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border)',
                    fontSize: '0.8125rem',
                    lineHeight: 1.5,
                  }}>
                    <span style={{ fontWeight: 600, color: 'var(--graphite)', display: 'block', marginBottom: '0.25rem', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      Business Justification:
                    </span>
                    <span style={{ color: 'var(--text-primary)' }}>{req.reason}</span>
                  </div>

                  {/* Details & Actions Footer */}
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    paddingTop: '0.5rem',
                    borderTop: '1px solid var(--border)',
                    flexWrap: 'wrap',
                    gap: '0.75rem',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      <span>
                        Requested Level: <strong style={{ textTransform: 'uppercase', color: 'var(--copper-dark)' }}>{req.requested_permission}</strong>
                      </span>
                      {req.requested_expiry && (
                        <span>
                          Requested Expiry: <strong>{formatToIST(req.requested_expiry)}</strong>
                        </span>
                      )}
                      {req.decided_at && (
                        <span>
                          Decided on: {formatToIST(req.decided_at)}
                        </span>
                      )}
                      {req.rejection_reason && (
                        <span style={{ color: 'var(--danger)' }}>
                          Reason: {req.rejection_reason}
                        </span>
                      )}
                    </div>

                    {req.status === 'pending' && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleOpenReject(req)}
                          style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem' }}
                        >
                          <X size={13} style={{ marginRight: '4px' }} />
                          <span>Decline</span>
                        </button>
                        <button
                          className="btn btn-primary btn-sm"
                          onClick={() => handleOpenApprove(req)}
                          style={{ padding: '0.35rem 0.875rem', fontSize: '0.75rem' }}
                        >
                          <Check size={13} style={{ marginRight: '4px' }} />
                          <span>Grant Access</span>
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 2: My Submitted Requests */}
      {activeTab === 'my' && (
        <div>
          {isMyLoading ? (
            <div className="panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
              Loading your submitted access requests...
            </div>
          ) : !myRequests || myRequests.length === 0 ? (
            <div className="panel" style={{ padding: '3.5rem 2rem', textAlign: 'center' }}>
              <div style={{
                width: '42px',
                height: '42px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--bg-warm)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 0.875rem',
                color: 'var(--text-muted)',
              }}>
                <KeyRound size={22} />
              </div>
              <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--graphite)', margin: '0 0 0.375rem 0' }}>
                No submitted requests
              </h3>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: 0, maxWidth: '420px', marginLeft: 'auto', marginRight: 'auto' }}>
                You have not requested access to any confidential documents yet. When you request access to an inaccessible document, you can track the review status here.
              </p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {myRequests.map(req => (
                <div 
                  key={req.id} 
                  className="panel"
                  style={{
                    padding: '1.25rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.75rem',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                        <FileText size={15} color="var(--copper-dark)" />
                        <span style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--graphite)' }}>
                          {req.document_title || `Document [${req.document_id.slice(0, 8)}...]`}
                        </span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        <span>Document Owner: <strong>{req.owner_name || req.owner_email || 'Owner'}</strong></span>
                        <span>&bull;</span>
                        <span>Submitted on: {formatToIST(req.created_at)}</span>
                      </div>
                    </div>

                    <div>
                      {getStatusBadge(req.status)}
                    </div>
                  </div>

                  {/* Reason */}
                  <div style={{
                    backgroundColor: 'var(--bg-warm)',
                    padding: '0.625rem 0.875rem',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border)',
                    fontSize: '0.8125rem',
                    color: 'var(--text-primary)',
                  }}>
                    <strong style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Justification: </strong>
                    {req.reason}
                  </div>

                  {/* Decision Info / Actions */}
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    paddingTop: '0.5rem',
                    borderTop: '1px solid var(--border)',
                    flexWrap: 'wrap',
                    gap: '0.75rem',
                  }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      {req.status === 'approved' && (
                        <span style={{ color: 'var(--success-dark)', fontWeight: 500 }}>
                          Access granted: <strong>{req.approved_permission?.toUpperCase()}</strong>
                          {req.approved_expiry ? ` (Expires: ${formatToIST(req.approved_expiry)})` : ' (Permanent)'}
                        </span>
                      )}
                      {req.status === 'rejected' && (
                        <span style={{ color: 'var(--danger)' }}>
                          Declined on {req.decided_at ? formatToIST(req.decided_at) : 'recently'}.
                          {req.rejection_reason && ` Reason: "${req.rejection_reason}"`}
                        </span>
                      )}
                      {req.status === 'cancelled' && (
                        <span style={{ color: 'var(--text-muted)' }}>
                          Withdrawn on {req.cancelled_at ? formatToIST(req.cancelled_at) : 'recently'}.
                        </span>
                      )}
                      {req.status === 'pending' && (
                        <span style={{ color: 'var(--copper-dark)' }}>
                          Awaiting document owner review.
                        </span>
                      )}
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      {req.status === 'pending' && (
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleCancelRequest(req)}
                          style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem' }}
                        >
                          Withdraw Request
                        </button>
                      )}
                      {req.status === 'approved' && (
                        <Link
                          to={`/documents/${req.document_id}`}
                          className="btn btn-primary btn-sm"
                          style={{ padding: '0.35rem 0.875rem', fontSize: '0.75rem', textDecoration: 'none' }}
                        >
                          <span>Open Document</span>
                          <ArrowRight size={13} style={{ marginLeft: '4px' }} />
                        </Link>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ================= APPROVE MODAL ================= */}
      {approvingRequest && (
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
          zIndex: 100,
          padding: '1rem',
        }}>
          <div style={{
            backgroundColor: '#FFFFFF',
            borderRadius: 'var(--radius-md)',
            boxShadow: 'var(--shadow-lg)',
            maxWidth: '520px',
            width: '100%',
            border: '1px solid var(--border)',
            overflow: 'hidden',
          }}>
            <div style={{
              padding: '1.25rem 1.5rem',
              borderBottom: '1px solid var(--border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}>
              <div>
                <h3 style={{ fontSize: '1.0625rem', fontWeight: 600, color: 'var(--graphite)', margin: 0 }}>
                  Grant Access to Document
                </h3>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: '0.25rem 0 0 0' }}>
                  Requester: {approvingRequest.requester_name || approvingRequest.requester_email} ({approvingRequest.requester_email})
                </p>
              </div>
              <button 
                onClick={() => setApprovingRequest(null)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ padding: '1.25rem 1.5rem' }}>
              {/* Document Reference */}
              <div style={{ marginBottom: '1rem', padding: '0.75rem', backgroundColor: 'var(--bg-warm)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>Target Document</span>
                <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--graphite)' }}>{approvingRequest.document_title}</span>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', margin: '0.375rem 0 0 0' }}>
                  Reason: "{approvingRequest.reason}"
                </p>
              </div>

              {/* Permission Level */}
              <div style={{ marginBottom: '1.25rem' }}>
                <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.375rem' }}>
                  Access Level to Grant:
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                  <button
                    type="button"
                    onClick={() => setApprovedPermLevel('read')}
                    className="btn btn-sm"
                    style={{
                      padding: '0.625rem',
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'flex-start',
                      backgroundColor: approvedPermLevel === 'read' ? 'var(--copper-light)' : '#FFFFFF',
                      borderColor: approvedPermLevel === 'read' ? 'var(--copper)' : 'var(--border)',
                      textAlign: 'left',
                    }}
                  >
                    <span style={{ fontWeight: 600, color: approvedPermLevel === 'read' ? 'var(--copper-dark)' : 'var(--graphite)', fontSize: '0.8125rem' }}>
                      Read Only (Least-Privileged)
                    </span>
                    <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: '0.125rem' }}>
                      Can view stream & download. Cannot modify.
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setApprovedPermLevel('edit')}
                    className="btn btn-sm"
                    style={{
                      padding: '0.625rem',
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'flex-start',
                      backgroundColor: approvedPermLevel === 'edit' ? 'var(--copper-light)' : '#FFFFFF',
                      borderColor: approvedPermLevel === 'edit' ? 'var(--copper)' : 'var(--border)',
                      textAlign: 'left',
                    }}
                  >
                    <span style={{ fontWeight: 600, color: approvedPermLevel === 'edit' ? 'var(--copper-dark)' : 'var(--graphite)', fontSize: '0.8125rem' }}>
                      Edit Access
                    </span>
                    <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginTop: '0.125rem' }}>
                      Can view, download, and update metadata.
                    </span>
                  </button>
                </div>
              </div>

              {/* Access Duration / Expiry */}
              <div>
                <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.375rem' }}>
                  Access Duration:
                </label>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.375rem', marginBottom: '0.625rem' }}>
                  {(['1h', '24h', '7d', '30d', 'never', 'custom'] as const).map(preset => (
                    <button
                      key={preset}
                      type="button"
                      onClick={() => setExpiryPreset(preset)}
                      className="btn btn-sm"
                      style={{
                        padding: '0.25rem 0.625rem',
                        fontSize: '0.75rem',
                        backgroundColor: expiryPreset === preset ? 'var(--graphite)' : 'var(--bg-warm)',
                        color: expiryPreset === preset ? '#FFFFFF' : 'var(--text-secondary)',
                        borderColor: expiryPreset === preset ? 'var(--graphite)' : 'var(--border)',
                        textTransform: preset === '1h' ? 'none' : 'capitalize',
                      }}
                    >
                      {preset === '1h' ? '1 Hour' : preset === '24h' ? '24 Hours' : preset === '7d' ? '7 Days' : preset === '30d' ? '30 Days' : preset === 'never' ? 'Permanent' : 'Custom'}
                    </button>
                  ))}
                </div>

                {expiryPreset === 'custom' && (
                  <input
                    type="datetime-local"
                    className="form-input"
                    value={customExpiryDate}
                    onChange={(e) => setCustomExpiryDate(e.target.value)}
                    style={{ fontSize: '0.8125rem' }}
                  />
                )}
              </div>
            </div>

            {/* Footer */}
            <div style={{
              padding: '1rem 1.5rem',
              backgroundColor: 'var(--bg-warm)',
              borderTop: '1px solid var(--border)',
              display: 'flex',
              justifyContent: 'flex-end',
              gap: '0.625rem',
            }}>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => setApprovingRequest(null)}
                disabled={isApproving}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={handleConfirmApprove}
                disabled={isApproving}
              >
                {isApproving ? 'Granting Access...' : 'Confirm & Grant Access'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ================= REJECT MODAL ================= */}
      {rejectingRequest && (
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
          zIndex: 100,
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
            <div style={{
              padding: '1.25rem 1.5rem',
              borderBottom: '1px solid var(--border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}>
              <h3 style={{ fontSize: '1.0625rem', fontWeight: 600, color: 'var(--graphite)', margin: 0 }}>
                Decline Access Request
              </h3>
              <button 
                onClick={() => setRejectingRequest(null)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ padding: '1.25rem 1.5rem' }}>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: '0 0 1rem 0' }}>
                Decline the access request from <strong>{rejectingRequest.requester_name || rejectingRequest.requester_email}</strong> for document <strong>{rejectingRequest.document_title}</strong>. No access will be granted.
              </p>

              <div>
                <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.375rem' }}>
                  Rejection Reason (Optional):
                </label>
                <textarea
                  className="form-input"
                  rows={3}
                  placeholder="e.g. Requester does not require access for current project scope"
                  value={rejectionReason}
                  onChange={(e) => setRejectionReason(e.target.value)}
                  maxLength={500}
                  style={{ fontSize: '0.8125rem', resize: 'vertical' }}
                />
              </div>
            </div>

            <div style={{
              padding: '1rem 1.5rem',
              backgroundColor: 'var(--bg-warm)',
              borderTop: '1px solid var(--border)',
              display: 'flex',
              justifyContent: 'flex-end',
              gap: '0.625rem',
            }}>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => setRejectingRequest(null)}
                disabled={isRejecting}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-danger btn-sm"
                onClick={handleConfirmReject}
                disabled={isRejecting}
              >
                {isRejecting ? 'Declining...' : 'Decline Request'}
              </button>
            </div>
          </div>
        </div>
      )}

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
