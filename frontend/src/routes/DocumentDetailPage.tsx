import React, { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { 
  ArrowLeft, 
  Download, 
  Edit3, 
  Trash2, 
  Shield, 
  Users, 
  Sparkles, 
  History, 
  Check, 
  X, 
  Key
} from 'lucide-react';
import { api } from '../lib/api';
import { formatToIST } from '../lib/date';
import { useAuth } from '../features/auth/AuthContext';
import { useToast } from '../context/ToastContext';
import type { SuggestedGrant } from '../types';

export const DocumentDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const { toast } = useToast();

  const [activeTab, setActiveTab] = useState<'permissions' | 'ai' | 'audit'>('permissions');
  const [isEditingMeta, setIsEditingMeta] = useState(false);
  const [editTitle, setEditTitle] = useState('');
  const [editDesc, setEditDesc] = useState('');
  const [editCat, setEditCat] = useState('');

  // Permission grant form state
  const [selectedUserEmail, setSelectedUserEmail] = useState('');
  const [selectedPermLevel, setSelectedPermLevel] = useState<'read' | 'edit'>('read');
  const [grantError, setGrantError] = useState<string | null>(null);

  // AI recommendations state
  const [pendingSuggestionId, setPendingSuggestionId] = useState<string | null>(null);
  const [aiSuggestions, setAiSuggestions] = useState<SuggestedGrant[]>([]);
  const [aiExplanation, setAiExplanation] = useState<string | null>(null);
  const [aiModel, setAiModel] = useState<string | null>(null);
  const [isMock, setIsMock] = useState<boolean>(false);
  const [isAiLoading, setIsAiLoading] = useState(false);

  // Queries
  const { data: doc, isLoading: isDocLoading, error: docError } = useQuery({
    queryKey: ['document', id],
    queryFn: () => api.getDocument(id!),
    enabled: !!id,
  });

  const { data: permissions, refetch: refetchPerms } = useQuery({
    queryKey: ['permissions', id],
    queryFn: () => api.getDocumentPermissions(id!),
    enabled: !!id,
  });

  const { data: orgUsers } = useQuery({
    queryKey: ['orgUsers'],
    queryFn: () => api.listUsers(),
  });

  const { data: auditEvents } = useQuery({
    queryKey: ['docAudit', id],
    queryFn: () => api.listAuditEvents({ document_id: id }),
    enabled: !!id,
  });

  const isOwner = doc?.owner_id === user?.id;
  const canEdit = isOwner || doc?.effective_permission === 'edit';

  // Handle Download
  const handleDownload = async () => {
    if (!doc) return;
    try {
      await api.downloadDocument(doc.id, doc.original_filename);
      toast.success(`Download started: ${doc.original_filename}`);
    } catch (err: any) {
      toast.error(err.message || 'Download failed');
    }
  };

  // Handle Metadata Update
  const handleStartEdit = () => {
    if (!doc) return;
    setEditTitle(doc.title);
    setEditDesc(doc.description || '');
    setEditCat(doc.category);
    setIsEditingMeta(true);
  };

  const handleSaveMeta = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!doc) return;
    try {
      await api.updateDocumentMetadata(doc.id, {
        title: editTitle,
        description: editDesc,
        category: editCat,
      });
      setIsEditingMeta(false);
      queryClient.invalidateQueries({ queryKey: ['document', id] });
      toast.success('Document metadata updated successfully.');
    } catch (err: any) {
      toast.error(err.message || 'Failed to update metadata');
    }
  };

  // Handle Delete
  const handleDelete = async () => {
    if (!doc) return;
    if (!window.confirm(`Are you sure you want to delete "${doc.title}"? This will permanently remove the private storage file.`)) {
      return;
    }
    try {
      await api.deleteDocument(doc.id);
      toast.success('Document deleted successfully.');
      navigate('/documents');
    } catch (err: any) {
      toast.error(err.message || 'Failed to delete document');
    }
  };

  // Handle Grant Permission
  const handleGrantPermission = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!doc || !selectedUserEmail) return;
    setGrantError(null);
    try {
      await api.grantPermission(doc.id, {
        email: selectedUserEmail,
        permission_level: selectedPermLevel,
      });
      toast.success(`Access granted to ${selectedUserEmail} (${selectedPermLevel}).`);
      setSelectedUserEmail('');
      refetchPerms();
    } catch (err: any) {
      setGrantError(err.message || 'Failed to grant permission');
      toast.error(err.message || 'Failed to grant permission');
    }
  };

  // Handle Revoke Permission
  const handleRevokePermission = async (userId: string, userEmail: string) => {
    if (!doc) return;
    if (!window.confirm(`Immediately revoke access for ${userEmail}? Their next request will be denied.`)) {
      return;
    }
    try {
      await api.revokePermission(doc.id, userId);
      refetchPerms();
      queryClient.invalidateQueries({ queryKey: ['docAudit', id] });
      toast.success(`Access immediately revoked for ${userEmail}.`);
    } catch (err: any) {
      toast.error(err.message || 'Failed to revoke access');
    }
  };

  // Handle AI Recommendation Request
  const handleRequestAi = async () => {
    if (!doc) return;
    setIsAiLoading(true);
    try {
      const res = await api.requestAIRecommendations(doc.id);
      setPendingSuggestionId(res.suggestion_id);
      setAiSuggestions(res.recommendations.suggestions);
      setAiExplanation(res.recommendations.explanation);
      setAiModel(res.recommendations.provider_model);
      setIsMock(res.recommendations.is_mock);
      toast.info('AI policy analysis completed with recommendations.');
    } catch (err: any) {
      toast.error(err.message || 'AI recommendation request failed');
    } finally {
      setIsAiLoading(false);
    }
  };

  // Handle AI Approve
  const handleApproveAi = async () => {
    if (!doc || !pendingSuggestionId) return;
    try {
      const approvedGrants = aiSuggestions.map(s => ({
        user_id: s.user_id,
        permission_level: s.permission_level
      }));
      await api.approveAIRecommendations(doc.id, {
        suggestion_id: pendingSuggestionId,
        approved_grants: approvedGrants,
        decision_notes: 'Approved via TrustVault UI',
      });
      setPendingSuggestionId(null);
      setAiSuggestions([]);
      refetchPerms();
      queryClient.invalidateQueries({ queryKey: ['docAudit', id] });
      toast.success('Approved AI access recommendations applied successfully.');
    } catch (err: any) {
      toast.error(err.message || 'Failed to approve AI suggestions');
    }
  };

  // Handle AI Reject
  const handleRejectAi = async () => {
    if (!doc || !pendingSuggestionId) return;
    try {
      await api.rejectAIRecommendations(doc.id, {
        suggestion_id: pendingSuggestionId,
        rejection_reason: 'Rejected by owner in review.',
      });
      setPendingSuggestionId(null);
      setAiSuggestions([]);
      queryClient.invalidateQueries({ queryKey: ['docAudit', id] });
      toast.info('AI recommendations rejected. Zero permissions were granted.');
    } catch (err: any) {
      toast.error(err.message || 'Failed to reject AI suggestions');
    }
  };

  if (isDocLoading) {
    return <div className="container" style={{ padding: '3rem 0', textAlign: 'center' }}>Loading document...</div>;
  }

  if (docError || !doc) {
    return (
      <div className="container" style={{ padding: '3rem 0', textAlign: 'center' }}>
        <div className="panel" style={{ maxWidth: '500px', margin: '0 auto', padding: '2rem' }}>
          <Shield size={32} style={{ color: 'var(--danger)', margin: '0 auto 1rem' }} />
          <h2 style={{ fontSize: '1.25rem', fontWeight: 600, marginBottom: '0.5rem' }}>Document Inaccessible</h2>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
            This document does not exist, or your access permission has been revoked.
          </p>
          <Link to="/documents" className="btn btn-primary btn-sm">
            <ArrowLeft size={14} />
            <span>Return to Documents</span>
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      {/* Back button */}
      <Link to="/documents" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.8125rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
        <ArrowLeft size={14} />
        <span>Back to authorized documents</span>
      </Link>

      {/* Top Header Card */}
      <div className="panel" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
              <h1 style={{ fontSize: '1.625rem', fontWeight: 700, color: 'var(--text-main)', letterSpacing: '-0.02em' }}>
                {doc.title}
              </h1>
              <span className="badge badge-gray">{doc.category}</span>
              <span className={`badge ${
                doc.effective_permission === 'owner' ? 'badge-green' : 'badge-blue'
              }`} style={{ textTransform: 'capitalize' }}>
                {doc.effective_permission === 'owner' ? 'Document Owner' : `${doc.effective_permission} Access`}
              </span>
            </div>

            {doc.description && (
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', maxWidth: '700px', lineHeight: 1.5 }}>
                {doc.description}
              </p>
            )}
          </div>

          {/* Action buttons */}
          <div style={{ display: 'flex', gap: '0.625rem', flexWrap: 'wrap' }}>
            <button className="btn btn-primary" onClick={handleDownload}>
              <Download size={15} />
              <span>Download File</span>
            </button>

            {canEdit && (
              <button className="btn btn-secondary" onClick={handleStartEdit}>
                <Edit3 size={15} />
                <span>Edit Metadata</span>
              </button>
            )}

            {isOwner && (
              <button className="btn btn-danger" onClick={handleDelete}>
                <Trash2 size={15} />
                <span>Delete</span>
              </button>
            )}
          </div>
        </div>

        {/* Security & File Metadata Bar */}
        <div style={{
          marginTop: '1.5rem',
          paddingTop: '1.25rem',
          borderTop: '1px solid var(--border-main)',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
          fontSize: '0.8125rem'
        }}>
          <div>
            <span style={{ color: 'var(--text-muted)', display: 'block' }}>Original Filename</span>
            <span style={{ fontWeight: 600, fontFamily: 'monospace' }}>{doc.original_filename}</span>
          </div>

          <div>
            <span style={{ color: 'var(--text-muted)', display: 'block' }}>File Size &amp; Type</span>
            <span style={{ fontWeight: 600 }}>{(doc.file_size / 1024).toFixed(1)} KB ({doc.detected_media_type})</span>
          </div>

          <div>
            <span style={{ color: 'var(--text-muted)', display: 'block' }}>SHA-256 Checksum</span>
            <span style={{ fontWeight: 600, fontFamily: 'monospace', fontSize: '0.75rem' }} title={doc.checksum}>
              {doc.checksum.substring(0, 16)}...{doc.checksum.substring(48)}
            </span>
          </div>

          <div>
            <span style={{ color: 'var(--text-muted)', display: 'block' }}>Document Owner</span>
            <span style={{ fontWeight: 600 }}>{doc.owner_name} ({doc.owner_email})</span>
          </div>
        </div>
      </div>

      {/* Tabs Bar */}
      <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid var(--border-main)', marginBottom: '1.5rem' }}>
        <button
          className="btn btn-sm"
          onClick={() => setActiveTab('permissions')}
          style={{
            borderBottom: activeTab === 'permissions' ? '2px solid var(--primary)' : '2px solid transparent',
            borderRadius: '0',
            padding: '0.625rem 1rem',
            fontWeight: activeTab === 'permissions' ? 600 : 500,
            color: activeTab === 'permissions' ? 'var(--primary)' : 'var(--text-muted)'
          }}
        >
          <Users size={16} />
          <span>Sharing &amp; Permissions ({permissions?.length || 0})</span>
        </button>

        <button
          className="btn btn-sm"
          onClick={() => setActiveTab('ai')}
          style={{
            borderBottom: activeTab === 'ai' ? '2px solid var(--primary)' : '2px solid transparent',
            borderRadius: '0',
            padding: '0.625rem 1rem',
            fontWeight: activeTab === 'ai' ? 600 : 500,
            color: activeTab === 'ai' ? 'var(--primary)' : 'var(--text-muted)'
          }}
        >
          <Sparkles size={16} />
          <span>AI Access Recommendations</span>
        </button>

        <button
          className="btn btn-sm"
          onClick={() => setActiveTab('audit')}
          style={{
            borderBottom: activeTab === 'audit' ? '2px solid var(--primary)' : '2px solid transparent',
            borderRadius: '0',
            padding: '0.625rem 1rem',
            fontWeight: activeTab === 'audit' ? 600 : 500,
            color: activeTab === 'audit' ? 'var(--primary)' : 'var(--text-muted)'
          }}
        >
          <History size={16} />
          <span>Document Activity Log</span>
        </button>
      </div>

      {/* TAB 1: PERMISSIONS & SHARING */}
      {activeTab === 'permissions' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {isOwner && (
            <div className="panel" style={{ padding: '1.25rem' }}>
              <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, marginBottom: '0.75rem' }}>
                Grant Explicit Access
              </h3>

              {grantError && (
                <div style={{
                  backgroundColor: 'var(--danger-bg)',
                  color: 'var(--danger)',
                  padding: '0.5rem 0.75rem',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.8125rem',
                  marginBottom: '1rem'
                }}>
                  {grantError}
                </div>
              )}

              <form onSubmit={handleGrantPermission} style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
                <div style={{ flex: 1, minWidth: '220px' }}>
                  <label className="form-label">Select Registered User</label>
                  <select
                    className="input-field"
                    value={selectedUserEmail}
                    onChange={(e) => setSelectedUserEmail(e.target.value)}
                    required
                  >
                    <option value="">-- Choose Organization Member --</option>
                    {orgUsers?.filter(u => u.id !== doc.owner_id).map(u => (
                      <option key={u.id} value={u.email}>
                        {u.display_name} ({u.email}) - {u.role}
                      </option>
                    ))}
                  </select>
                </div>

                <div style={{ width: '140px' }}>
                  <label className="form-label">Permission Level</label>
                  <select
                    className="input-field"
                    value={selectedPermLevel}
                    onChange={(e) => setSelectedPermLevel(e.target.value as 'read' | 'edit')}
                  >
                    <option value="read">Read Only</option>
                    <option value="edit">Edit Metadata</option>
                  </select>
                </div>

                <button type="submit" className="btn btn-primary" style={{ height: '38px' }}>
                  <Key size={15} />
                  <span>Grant Access</span>
                </button>
              </form>
            </div>
          )}

          {/* Active Grants List */}
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Recipient</th>
                  <th>Permission Level</th>
                  <th>Granted By</th>
                  <th>Granted At</th>
                  {isOwner && <th style={{ textAlign: 'right' }}>Revoke</th>}
                </tr>
              </thead>
              <tbody>
                {permissions && permissions.length > 0 ? (
                  permissions.map((p) => (
                    <tr key={p.id}>
                      <td>
                        <div style={{ fontWeight: 600 }}>{p.user_display_name}</div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{p.user_email}</div>
                      </td>
                      <td>
                        <span className={`badge ${p.permission_level === 'edit' ? 'badge-blue' : 'badge-green'}`} style={{ textTransform: 'capitalize' }}>
                          {p.permission_level === 'edit' ? 'Read & Edit' : 'Read Only'}
                        </span>
                      </td>
                      <td style={{ fontSize: '0.8125rem' }}>{p.granted_by_email || 'Owner'}</td>
                      <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                        {formatToIST(p.granted_at)}
                      </td>
                      {isOwner && (
                        <td style={{ textAlign: 'right' }}>
                          <button
                            className="btn btn-danger btn-sm"
                            onClick={() => handleRevokePermission(p.user_id, p.user_email)}
                            title="Immediate permission revocation"
                          >
                            <X size={14} />
                            <span>Revoke Access</span>
                          </button>
                        </td>
                      )}
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={isOwner ? 5 : 4} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                      No explicit permissions have been granted yet. Only the document owner has access.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: AI ACCESS RECOMMENDATIONS */}
      {activeTab === 'ai' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="panel">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem', marginBottom: '1rem' }}>
              <div>
                <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>
                  AI-Powered Permission Recommendations
                </h3>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                  Minimum-necessary privilege suggestions based strictly on metadata categories and organizational roles.
                </p>
              </div>

              {isOwner && (
                <button
                  className="btn btn-primary btn-sm"
                  onClick={handleRequestAi}
                  disabled={isAiLoading}
                >
                  <Sparkles size={14} />
                  <span>{isAiLoading ? 'Analyzing Metadata...' : 'Request AI Recommendations'}</span>
                </button>
              )}
            </div>

            {/* AI Security Notice */}
            <div style={{
              backgroundColor: '#f8fafc',
              border: '1px solid var(--border-main)',
              borderRadius: 'var(--radius-sm)',
              padding: '0.75rem 1rem',
              fontSize: '0.8125rem',
              color: 'var(--text-secondary)',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}>
              <Shield size={16} color="var(--accent)" />
              <span>
                <strong>Zero-Trust AI Guardrail:</strong> AI suggestions are purely advisory. AI has zero capability to alter database permissions directly. Only explicit owner approval will create grants.
              </span>
            </div>

            {/* Active AI Suggestions Box */}
            {aiSuggestions.length > 0 && (
              <div style={{ marginTop: '1.5rem', border: '1px solid var(--border-main)', borderRadius: 'var(--radius-sm)', padding: '1.25rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span 
                      className="badge badge-blue" 
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '0.375rem' }}
                      title={`Engine: ${aiModel || 'TrustVault Policy Intelligence'}`}
                    >
                      <Sparkles size={13} />
                      <span>Policy Engine: Enterprise Access Advisor {isMock ? '(Sandbox Mode)' : '(Active)'}</span>
                    </span>
                    <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                      {aiSuggestions.length} candidates proposed
                    </span>
                  </div>

                  {isOwner && (
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button className="btn btn-secondary btn-sm" onClick={handleRejectAi}>
                        <X size={14} />
                        <span>Reject All</span>
                      </button>
                      <button className="btn btn-primary btn-sm" onClick={handleApproveAi}>
                        <Check size={14} />
                        <span>Approve &amp; Grant Access</span>
                      </button>
                    </div>
                  )}
                </div>

                {aiExplanation && (
                  <div style={{ fontSize: '0.875rem', fontStyle: 'italic', color: 'var(--text-secondary)', marginBottom: '1.25rem', padding: '0.625rem', backgroundColor: '#f1f5f9', borderRadius: 'var(--radius-sm)' }}>
                    "{aiExplanation}"
                  </div>
                )}

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {aiSuggestions.map((s, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '0.875rem',
                        border: '1px solid var(--border-main)',
                        borderRadius: 'var(--radius-sm)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        backgroundColor: '#ffffff'
                      }}
                    >
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span style={{ fontWeight: 600 }}>{s.display_name}</span>
                          <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>({s.email})</span>
                          <span className={`badge ${s.permission_level === 'edit' ? 'badge-blue' : 'badge-green'}`} style={{ textTransform: 'capitalize' }}>
                            Suggested: {s.permission_level}
                          </span>
                        </div>
                        <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                          {s.rationale}
                        </p>
                      </div>

                      <div style={{ textAlign: 'right' }}>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block' }}>
                          Confidence: {(s.confidence * 100).toFixed(0)}%
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: AUDIT HISTORY */}
      {activeTab === 'audit' && (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp (IST)</th>
                <th>Action</th>
                <th>Actor</th>
                <th>Outcome</th>
                <th>Cryptographic Event Hash</th>
              </tr>
            </thead>
            <tbody>
              {auditEvents?.events && auditEvents.events.length > 0 ? (
                auditEvents.events.map((e) => (
                  <tr key={e.id}>
                    <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                      {formatToIST(e.timestamp)}
                    </td>
                    <td>
                      <span style={{ fontWeight: 600, fontFamily: 'monospace' }}>{e.action}</span>
                    </td>
                    <td style={{ fontSize: '0.8125rem' }}>
                      {e.actor_email || 'System'}
                    </td>
                    <td>
                      <span className={`badge ${e.outcome === 'success' ? 'badge-green' : 'badge-red'}`}>
                        {e.outcome}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                      {e.event_hash.substring(0, 16)}...
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                    No activity recorded yet for this document.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Edit Metadata Modal */}
      {isEditingMeta && (
        <div className="modal-overlay" onClick={() => setIsEditingMeta(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <h2 style={{ fontSize: '1.125rem', fontWeight: 600 }}>Edit Document Metadata</h2>
              <button onClick={() => setIsEditingMeta(false)}><X size={18} /></button>
            </div>

            <form onSubmit={handleSaveMeta}>
              <div className="form-group">
                <label className="form-label">Title</label>
                <input
                  type="text"
                  className="input-field"
                  value={editTitle}
                  onChange={(e) => setEditTitle(e.target.value)}
                  required
                />
              </div>

              <div className="form-group">
                <label className="form-label">Category</label>
                <select
                  className="input-field"
                  value={editCat}
                  onChange={(e) => setEditCat(e.target.value)}
                >
                  <option value="Financial">Financial</option>
                  <option value="Legal">Legal</option>
                  <option value="Executive">Executive</option>
                  <option value="Engineering">Engineering</option>
                  <option value="HR">HR</option>
                  <option value="General">General</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Description</label>
                <textarea
                  className="input-field"
                  rows={3}
                  value={editDesc}
                  onChange={(e) => setEditDesc(e.target.value)}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1.5rem' }}>
                <button type="button" className="btn btn-secondary" onClick={() => setIsEditingMeta(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Save Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
