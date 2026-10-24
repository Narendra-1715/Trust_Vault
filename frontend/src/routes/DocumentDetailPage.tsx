import React, { useState, useEffect, useCallback, useRef } from 'react';
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
  Key,
  Eye,
  Copy,
  CheckCircle,
  Clock,
  Link2,
  Plus,
  Ban,
  Layers,
  UploadCloud,
  RotateCcw,
  Sliders,
  AlertTriangle,
  XCircle,
  Info,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  MoreVertical
} from 'lucide-react';
import { api, clearAuthToken } from '../lib/api';
import { formatToIST } from '../lib/date';
import { useAuth } from '../features/auth/AuthContext';
import { useToast } from '../context/ToastContext';
import { ConfirmModal } from '../features/common/ConfirmModal';
import type { SuggestedGrant, RequestLinkListItem, RequestLinkCreatedResponse, PolicySimulationResponse } from '../types';

export const DocumentDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const { toast } = useToast();

  const [activeTab, setActiveTab] = useState<'permissions' | 'versions' | 'ai' | 'audit' | 'links'>('permissions');

  // Action dropdown menu state
  const [isActionMenuOpen, setIsActionMenuOpen] = useState(false);
  const actionMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isActionMenuOpen) return;

    const handleClickOutside = (event: MouseEvent) => {
      if (actionMenuRef.current && !actionMenuRef.current.contains(event.target as Node)) {
        setIsActionMenuOpen(false);
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsActionMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isActionMenuOpen]);

  // Version management state
  const [newVersionFile, setNewVersionFile] = useState<File | null>(null);
  const [newVersionSummary, setNewVersionSummary] = useState('');
  const [isUploadingVersion, setIsUploadingVersion] = useState(false);
  const [copiedVersionChecksum, setCopiedVersionChecksum] = useState<string | null>(null);
  const [isEditingMeta, setIsEditingMeta] = useState(false);
  const [editTitle, setEditTitle] = useState('');
  const [editDesc, setEditDesc] = useState('');
  const [editCat, setEditCat] = useState('');
  const [editClassification, setEditClassification] = useState('Internal');
  const [copiedChecksum, setCopiedChecksum] = useState(false);

  // Permission grant form state
  const [selectedUserEmail, setSelectedUserEmail] = useState('');
  const [selectedPermLevel, setSelectedPermLevel] = useState<'read' | 'edit'>('read');
  const [expiryPreset, setExpiryPreset] = useState<'never' | '1h' | '24h' | '7d' | '30d' | 'custom'>('never');
  const [customExpiryDate, setCustomExpiryDate] = useState('');
  const [grantError, setGrantError] = useState<string | null>(null);

  // Access Policy Simulator state
  const [showSimulator, setShowSimulator] = useState(false);
  const [simUserEmail, setSimUserEmail] = useState('');
  const [simPermLevel, setSimPermLevel] = useState<'read' | 'edit'>('read');
  const [simExpiryPreset, setSimExpiryPreset] = useState<'never' | '1h' | '24h' | '7d' | '30d' | 'custom'>('7d');
  const [simCustomExpiry, setSimCustomExpiry] = useState('');
  const [isSimulating, setIsSimulating] = useState(false);
  const [simResult, setSimResult] = useState<PolicySimulationResponse | null>(null);
  const [simError, setSimError] = useState<string | null>(null);

  // In-App Confirmation Modal state
  const [confirmConfig, setConfirmConfig] = useState<{
    isOpen: boolean;
    title: string;
    message: string;
    confirmLabel: string;
    variant: 'danger' | 'warning';
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

  // AI recommendations state
  const [pendingSuggestionId, setPendingSuggestionId] = useState<string | null>(null);
  const [aiSuggestions, setAiSuggestions] = useState<SuggestedGrant[]>([]);
  const [aiExplanation, setAiExplanation] = useState<string | null>(null);
  const [aiModel, setAiModel] = useState<string | null>(null);
  const [isMock, setIsMock] = useState<boolean>(false);
  const [isAiLoading, setIsAiLoading] = useState(false);

  // Secure In-Browser Preview state (Phase 8: Sandboxed Raster & Watermark)
  const [isPreviewOpen, setIsPreviewOpen] = useState(false);
  const [previewBlobUrl, setPreviewBlobUrl] = useState<string | null>(null);
  const [previewCurrentPage, setPreviewCurrentPage] = useState(1);
  const [previewTotalPages, setPreviewTotalPages] = useState(1);
  const [previewTimestamp, setPreviewTimestamp] = useState<string>('');
  const [isPreviewLoading, setIsPreviewLoading] = useState(false);

  const handleClosePreview = useCallback(() => {
    if (previewBlobUrl) {
      URL.revokeObjectURL(previewBlobUrl);
    }
    setIsPreviewOpen(false);
    setPreviewBlobUrl(null);
    setPreviewCurrentPage(1);
    setPreviewTotalPages(1);
  }, [previewBlobUrl]);

  // Queries - Actively re-verifies server authorization & session validity every 6s
  const { data: doc, isLoading: isDocLoading, error: docError } = useQuery({
    queryKey: ['document', id],
    queryFn: () => api.getDocument(id!),
    enabled: !!id,
    refetchInterval: 6000,
    refetchOnWindowFocus: true,
    retry: false,
  });

  const { data: permissions, refetch: refetchPerms } = useQuery({
    queryKey: ['permissions', id],
    queryFn: () => api.getDocumentPermissions(id!),
    enabled: !!id,
    refetchInterval: 6000,
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

  const { data: versionsData, isLoading: versionsLoading } = useQuery({
    queryKey: ['document-versions', id],
    queryFn: () => api.getDocumentVersions(id!),
    enabled: !!id,
  });

  // Access Revocation & Session Expiry Watcher
  // When an access grant expires, is revoked by owner, or session ends, immediately destroy preview & lock page
  useEffect(() => {
    if (docError) {
      handleClosePreview();
      const err = docError as any;
      if (err?.statusCode === 401 || err?.status === 401) {
        clearAuthToken();
        if (window.location.pathname !== '/login') {
          window.location.href = '/login?expired=true';
        }
      }
    }
  }, [docError, handleClosePreview]);

  const isOwner = doc?.owner_id === user?.id;
  const canEdit = isOwner || doc?.effective_permission === 'edit';
  const canDownload = isOwner || ['read', 'edit', 'break_glass'].includes(doc?.effective_permission || '');

  // Request Link State (Owner only)
  const [newLinkName, setNewLinkName] = useState('');
  const [newLinkDuration, setNewLinkDuration] = useState<'1h' | '24h' | '7d' | '30d' | 'never' | 'custom'>('7d');
  const [newLinkCustomExpiry, setNewLinkCustomExpiry] = useState('');
  const [newLinkMaxUses, setNewLinkMaxUses] = useState<string>('');
  const [isCreatingLink, setIsCreatingLink] = useState(false);
  const [createdLinkInfo, setCreatedLinkInfo] = useState<RequestLinkCreatedResponse | null>(null);
  const [copiedLink, setCopiedLink] = useState(false);

  const { data: requestLinks, refetch: refetchRequestLinks } = useQuery<RequestLinkListItem[]>({
    queryKey: ['document-request-links', id],
    queryFn: () => api.getDocumentRequestLinks(id!),
    enabled: !!id && isOwner,
  });

  const handleCreateRequestLink = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!doc) return;
    setIsCreatingLink(true);
    try {
      let finalExpiry: string | undefined = undefined;
      const now = new Date();
      if (newLinkDuration === '1h') finalExpiry = new Date(now.getTime() + 3600 * 1000).toISOString();
      else if (newLinkDuration === '24h') finalExpiry = new Date(now.getTime() + 24 * 3600 * 1000).toISOString();
      else if (newLinkDuration === '7d') finalExpiry = new Date(now.getTime() + 7 * 86400 * 1000).toISOString();
      else if (newLinkDuration === '30d') finalExpiry = new Date(now.getTime() + 30 * 86400 * 1000).toISOString();
      else if (newLinkDuration === 'custom' && newLinkCustomExpiry) finalExpiry = new Date(newLinkCustomExpiry).toISOString();

      const maxUsesNum = newLinkMaxUses ? parseInt(newLinkMaxUses, 10) : undefined;

      const res = await api.createDocumentRequestLink(doc.id, {
        name: newLinkName.trim() || undefined,
        expires_at: finalExpiry,
        max_uses: maxUsesNum && !isNaN(maxUsesNum) ? maxUsesNum : undefined,
      });

      setCreatedLinkInfo(res);
      setNewLinkName('');
      setNewLinkDuration('7d');
      setNewLinkCustomExpiry('');
      setNewLinkMaxUses('');
      refetchRequestLinks();
      toast.success('Secure request link generated successfully.');
    } catch (err: any) {
      toast.error(err.message || 'Failed to create request link');
    } finally {
      setIsCreatingLink(false);
    }
  };

  const handleRevokeRequestLink = (linkId: string, prefix: string) => {
    setConfirmConfig({
      isOpen: true,
      title: 'Revoke Request Link',
      message: `Are you sure you want to revoke request link ref_${prefix}? Any user who tries to use this link in the future will be denied.`,
      confirmLabel: 'Revoke Link',
      variant: 'danger',
      isLoading: false,
      action: async () => {
        setConfirmConfig(prev => ({ ...prev, isLoading: true }));
        try {
          await api.revokeDocumentRequestLink(linkId);
          refetchRequestLinks();
          toast.success('Request link revoked successfully.');
        } catch (err: any) {
          toast.error(err.message || 'Failed to revoke link');
        } finally {
          setConfirmConfig(prev => ({ ...prev, isOpen: false, isLoading: false }));
        }
      }
    });
  };

  const handleCopyGeneratedLink = (token: string) => {
    const fullUrl = `${window.location.origin}/request-access/${token}`;
    navigator.clipboard.writeText(fullUrl);
    setCopiedLink(true);
    toast.info('Request link copied to clipboard.');
    setTimeout(() => setCopiedLink(false), 2500);
  };

  const handleCopyChecksum = () => {
    if (doc?.checksum) {
      navigator.clipboard.writeText(doc.checksum);
      setCopiedChecksum(true);
      toast.info('SHA-256 Checksum copied to clipboard.');
      setTimeout(() => setCopiedChecksum(false), 2500);
    }
  };

  // Handle Sandboxed Page Loading
  const loadPreviewPage = async (targetPage: number) => {
    if (!doc) return;
    setIsPreviewLoading(true);
    try {
      const blob = await api.fetchDocumentPagePreview(doc.id, targetPage);
      if (previewBlobUrl) {
        URL.revokeObjectURL(previewBlobUrl);
      }
      const objectUrl = URL.createObjectURL(blob);
      setPreviewBlobUrl(objectUrl);
      setPreviewCurrentPage(targetPage);
    } catch (err: any) {
      toast.error(err.message || ("Failed to load preview page " + targetPage));
    } finally {
      setIsPreviewLoading(false);
    }
  };

  // Handle Secure Preview with Dynamic Pixel Watermarking (Phase 8 Sandboxed Pipeline)
  const handleOpenPreview = async () => {
    if (!doc) return;
    setIsPreviewOpen(true);
    setIsPreviewLoading(true);
    if (previewBlobUrl) {
      URL.revokeObjectURL(previewBlobUrl);
      setPreviewBlobUrl(null);
    }
    setPreviewTimestamp(formatToIST(new Date()));

    try {
      // 1. Fetch preview info (total page count)
      const info = await api.getDocumentPreviewInfo(doc.id);
      setPreviewTotalPages(info.total_pages || 1);

      // 2. Fetch page 1 raster image
      const blob = await api.fetchDocumentPagePreview(doc.id, 1);
      const objectUrl = URL.createObjectURL(blob);
      setPreviewBlobUrl(objectUrl);
      setPreviewCurrentPage(1);
      toast.info('Secure watermarked preview generated.');
    } catch (err: any) {
      toast.error(err.message || 'Failed to open preview');
      setIsPreviewOpen(false);
    } finally {
      setIsPreviewLoading(false);
      queryClient.invalidateQueries({ queryKey: ['docAudit', id] });
      queryClient.invalidateQueries({ queryKey: ['auditEvents'] });
    }
  };

  // Handle Download
  const handleDownload = async () => {
    if (!doc) return;
    try {
      await api.downloadDocument(doc.id, doc.original_filename);
      toast.success(`Download started: ${doc.original_filename}`);
    } catch (err: any) {
      toast.error(err.message || 'Download failed');
    } finally {
      queryClient.invalidateQueries({ queryKey: ['docAudit', id] });
      queryClient.invalidateQueries({ queryKey: ['auditEvents'] });
    }
  };

  // Handle Metadata Update
  const handleStartEdit = () => {
    if (!doc) return;
    setEditTitle(doc.title);
    setEditDesc(doc.description || '');
    setEditCat(doc.category);
    setEditClassification(doc.classification || 'Internal');
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
        classification: (isOwner || user?.role === 'admin') ? editClassification : undefined,
      });
      setIsEditingMeta(false);
      queryClient.invalidateQueries({ queryKey: ['document', id] });
      toast.success('Document metadata updated successfully.');
    } catch (err: any) {
      toast.error(err.message || 'Failed to update metadata');
    }
  };

  // Handle Delete
  const handleDelete = () => {
    if (!doc) return;
    setConfirmConfig({
      isOpen: true,
      title: 'Delete Protected Document',
      message: `Are you sure you want to permanently delete "${doc.title}"? This will permanently remove the private storage file from the vault.`,
      confirmLabel: 'Delete Permanently',
      variant: 'danger',
      isLoading: false,
      action: async () => {
        setConfirmConfig(prev => ({ ...prev, isLoading: true }));
        try {
          await api.deleteDocument(doc.id);
          queryClient.invalidateQueries({ queryKey: ['documents'] });
          queryClient.invalidateQueries({ queryKey: ['trashedDocuments'] });
          toast.success('Document deleted successfully.');
          navigate('/documents');
        } catch (err: any) {
          toast.error(err.message || 'Failed to delete document');
          setConfirmConfig(prev => ({ ...prev, isOpen: false, isLoading: false }));
        }
      }
    });
  };

  // Handle Document Versions
  const handleUploadVersion = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newVersionFile || !id) return;

    setIsUploadingVersion(true);
    try {
      const formData = new FormData();
      formData.append('file', newVersionFile);
      if (newVersionSummary.trim()) {
        formData.append('change_summary', newVersionSummary.trim());
      }
      await api.uploadDocumentVersion(id, formData);
      toast.success('New document revision uploaded successfully');
      setNewVersionFile(null);
      setNewVersionSummary('');
      queryClient.invalidateQueries({ queryKey: ['document', id] });
      queryClient.invalidateQueries({ queryKey: ['document-versions', id] });
      queryClient.invalidateQueries({ queryKey: ['docAudit', id] });
    } catch (err: any) {
      toast.error(err.message || 'Failed to upload revision');
    } finally {
      setIsUploadingVersion(false);
    }
  };

  const handleDownloadVersion = async (versionId: string, filename: string) => {
    if (!id) return;
    try {
      toast.info(`Preparing version download for ${filename}...`);
      await api.downloadDocumentVersion(id, versionId, filename);
      toast.success('Version download initiated');
    } catch (err: any) {
      toast.error(err.message || 'Failed to download version');
    }
  };

  const handleRestoreVersion = (versionId: string, versionNumber: number) => {
    if (!id) return;
    setConfirmConfig({
      isOpen: true,
      title: `Restore Version ${versionNumber}`,
      message: `Are you sure you want to restore version ${versionNumber}? This will create a new current version from its content without altering historical versions.`,
      confirmLabel: 'Restore to Current',
      variant: 'warning',
      isLoading: false,
      action: async () => {
        try {
          await api.restoreDocumentVersion(id, versionId);
          toast.success(`Successfully restored version ${versionNumber} as new current version`);
          queryClient.invalidateQueries({ queryKey: ['document', id] });
          queryClient.invalidateQueries({ queryKey: ['document-versions', id] });
          queryClient.invalidateQueries({ queryKey: ['docAudit', id] });
          setConfirmConfig(prev => ({ ...prev, isOpen: false }));
        } catch (err: any) {
          toast.error(err.message || 'Failed to restore version');
        }
      }
    });
  };

  // Access Policy Simulation Handler
  const handleRunSimulation = async (targetEmail?: string, targetPerm?: 'read' | 'edit', targetPreset?: string, targetCustomDate?: string) => {
    if (!doc) return;
    const email = targetEmail !== undefined ? targetEmail : simUserEmail;
    const perm = targetPerm || simPermLevel;
    const preset = targetPreset || simExpiryPreset;
    const customDate = targetCustomDate !== undefined ? targetCustomDate : simCustomExpiry;

    if (!email) {
      setSimError('Please select a recipient user to simulate.');
      setShowSimulator(true);
      return;
    }
    setSimError(null);
    setIsSimulating(true);
    setShowSimulator(true);

    let expiresAtIso: string | undefined = undefined;
    if (preset === '1h') {
      expiresAtIso = new Date(Date.now() + 3600 * 1000).toISOString();
    } else if (preset === '24h') {
      expiresAtIso = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    } else if (preset === '7d') {
      expiresAtIso = new Date(Date.now() + 7 * 86400 * 1000).toISOString();
    } else if (preset === '30d') {
      expiresAtIso = new Date(Date.now() + 30 * 86400 * 1000).toISOString();
    } else if (preset === 'custom' && customDate) {
      expiresAtIso = new Date(customDate).toISOString();
    }

    try {
      const res = await api.simulatePolicy({
        document_id: doc.id,
        recipient_email: email,
        permission_level: perm,
        proposed_expiry: expiresAtIso,
      });
      setSimResult(res);
      setSimUserEmail(email);
      setSimPermLevel(perm);
      setSimExpiryPreset(preset as any);
      if (customDate) setSimCustomExpiry(customDate);
    } catch (err: any) {
      setSimError(err.message || 'Policy simulation failed');
      toast.error(err.message || 'Policy simulation failed');
    } finally {
      setIsSimulating(false);
    }
  };

  const handleApplySimToGrant = () => {
    if (!simResult) return;
    if (simResult.recipient_email) {
      setSelectedUserEmail(simResult.recipient_email);
    }
    setSelectedPermLevel(simResult.proposed_permission as 'read' | 'edit');
    setExpiryPreset(simExpiryPreset);
    if (simExpiryPreset === 'custom') {
      setCustomExpiryDate(simCustomExpiry);
    }
    toast.success('Simulated parameters copied to Grant Access form.');
  };

  // Handle Grant Permission
  const handleGrantPermission = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!doc || !selectedUserEmail) return;
    setGrantError(null);

    let expiresAtIso: string | undefined = undefined;
    if (expiryPreset === '1h') {
      expiresAtIso = new Date(Date.now() + 3600 * 1000).toISOString();
    } else if (expiryPreset === '24h') {
      expiresAtIso = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    } else if (expiryPreset === '7d') {
      expiresAtIso = new Date(Date.now() + 7 * 86400 * 1000).toISOString();
    } else if (expiryPreset === '30d') {
      expiresAtIso = new Date(Date.now() + 30 * 86400 * 1000).toISOString();
    } else if (expiryPreset === 'custom') {
      if (!customExpiryDate) {
        setGrantError('Please select a valid future expiry date and time');
        return;
      }
      const customDate = new Date(customExpiryDate);
      if (isNaN(customDate.getTime()) || customDate.getTime() <= Date.now()) {
        setGrantError('Expiry date must be in the future');
        return;
      }
      expiresAtIso = customDate.toISOString();
    }

    try {
      await api.grantPermission(doc.id, {
        email: selectedUserEmail,
        permission_level: selectedPermLevel,
        expires_at: expiresAtIso,
      });
      toast.success(`Access granted to ${selectedUserEmail} (${selectedPermLevel}${expiresAtIso ? ', time-limited' : ''}).`);
      setSelectedUserEmail('');
      setExpiryPreset('never');
      setCustomExpiryDate('');
      refetchPerms();
    } catch (err: any) {
      setGrantError(err.message || 'Failed to grant permission');
      toast.error(err.message || 'Failed to grant permission');
    }
  };

  // Handle Revoke Permission
  const handleRevokePermission = (userId: string, userEmail: string) => {
    if (!doc) return;
    setConfirmConfig({
      isOpen: true,
      title: 'Revoke Explicit Access',
      message: `Immediately revoke access for ${userEmail}? Their next request will be denied.`,
      confirmLabel: 'Revoke Access',
      variant: 'danger',
      isLoading: false,
      action: async () => {
        setConfirmConfig(prev => ({ ...prev, isLoading: true }));
        try {
          await api.revokePermission(doc.id, userId);
          refetchPerms();
          queryClient.invalidateQueries({ queryKey: ['docAudit', id] });
          toast.success(`Access immediately revoked for ${userEmail}.`);
        } catch (err: any) {
          toast.error(err.message || 'Failed to revoke access');
        } finally {
          setConfirmConfig(prev => ({ ...prev, isOpen: false, isLoading: false }));
        }
      }
    });
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
    return (
      <div className="container" style={{ paddingTop: '4rem', paddingBottom: '4rem', textAlign: 'center', color: 'var(--text-muted)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
          <span className="pulse-dot" style={{ backgroundColor: 'var(--copper)', width: '10px', height: '10px' }}></span>
          <span style={{ fontSize: '0.875rem' }}>Loading confidential document...</span>
        </div>
      </div>
    );
  }

  if (docError || !doc) {
    return (
      <div className="container" style={{ paddingTop: '3.5rem', paddingBottom: '3.5rem', textAlign: 'center' }}>
        <div className="panel" style={{ maxWidth: '480px', margin: '0 auto', padding: '2.5rem' }}>
          <div style={{
            width: '46px',
            height: '46px',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'var(--danger-bg)',
            border: '1px solid var(--danger-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--danger)',
            margin: '0 auto 1rem',
          }}>
            <Shield size={22} />
          </div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--graphite)', marginBottom: '0.5rem' }}>
            Document Inaccessible
          </h2>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1.5rem', lineHeight: 1.5 }}>
            This document does not exist, or your access permission has been revoked by the owner.
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
      {/* Back Link */}
      <Link 
        to="/documents" 
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.375rem',
          fontSize: '0.8125rem',
          fontWeight: 500,
          color: 'var(--text-secondary)',
          marginBottom: '1.25rem',
          transition: 'color 0.15s ease',
        }}
      >
        <ArrowLeft size={14} />
        <span>Back to authorized documents</span>
      </Link>

      {/* ================= PRIMARY DOCUMENT HEADER CARD ================= */}
      <div className="panel" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1.25rem' }}>
          <div style={{ flex: 1, minWidth: '280px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', marginBottom: '0.5rem', flexWrap: 'wrap' }}>
              <h1 style={{ fontSize: '1.625rem', fontWeight: 700, color: 'var(--graphite)', letterSpacing: '-0.025em', margin: 0 }}>
                {doc.title}
              </h1>
              <span className="badge badge-gray">{doc.category}</span>
              <span className={`badge ${
                doc.effective_permission === 'owner' ? 'badge-green' : 'badge-copper'
              }`} style={{ textTransform: 'capitalize' }}>
                {doc.effective_permission === 'owner' ? 'Document Owner' : `${doc.effective_permission} Access`}
              </span>
              <span className={`badge ${
                doc.classification === 'Highly Restricted' 
                  ? 'badge-danger' 
                  : doc.classification === 'Confidential' 
                    ? 'badge-copper' 
                    : 'badge-secondary'
              }`} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', fontWeight: 600 }}>
                <Shield size={12} />
                <span>{doc.classification || 'Internal'}</span>
              </span>
            </div>

            {doc.description ? (
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', maxWidth: '720px', lineHeight: 1.55, margin: 0 }}>
                {doc.description}
              </p>
            ) : (
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', fontStyle: 'italic', margin: 0 }}>
                No description provided.
              </p>
            )}
          </div>

            {doc.classification === 'Highly Restricted' && (
              <div style={{
                width: '100%',
                marginTop: '0.75rem',
                padding: '0.625rem 0.875rem',
                backgroundColor: 'rgba(239, 68, 68, 0.08)',
                border: '1px solid rgba(239, 68, 68, 0.25)',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.8125rem',
                color: '#b91c1c',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem'
              }}>
                <Shield size={14} />
                <span>
                  <strong>Highly Restricted Policy:</strong> Direct downloads prohibited for non-owners (use Secure Preview). Max grant duration 7 days. MFA required.
                </span>
              </div>
            )}

          {/* Action Menu (Vertical Three-Dot Dropdown) */}
          <div style={{ position: 'relative' }} ref={actionMenuRef}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setIsActionMenuOpen(prev => !prev)}
              aria-label="Document actions"
              aria-haspopup="true"
              aria-expanded={isActionMenuOpen}
              title="More actions"
              style={{
                padding: '0.45rem 0.6rem',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                backgroundColor: isActionMenuOpen ? 'var(--bg-surface-secondary)' : undefined,
                borderColor: isActionMenuOpen ? 'var(--border-dark)' : undefined,
              }}
            >
              <MoreVertical size={18} color="var(--graphite)" />
            </button>

            {isActionMenuOpen && (
              <div
                style={{
                  position: 'absolute',
                  top: 'calc(100% + 6px)',
                  right: 0,
                  minWidth: '200px',
                  backgroundColor: '#FFFFFF',
                  borderRadius: 'var(--radius-md)',
                  boxShadow: 'var(--shadow-lg)',
                  border: '1px solid var(--border)',
                  zIndex: 50,
                  padding: '0.375rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.125rem',
                }}
              >
                {/* 1. Secure Preview */}
                <button
                  type="button"
                  onClick={() => {
                    setIsActionMenuOpen(false);
                    handleOpenPreview();
                  }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.625rem',
                    width: '100%',
                    padding: '0.5rem 0.75rem',
                    fontSize: '0.8125rem',
                    fontWeight: 500,
                    color: 'var(--graphite)',
                    backgroundColor: 'transparent',
                    border: 'none',
                    borderRadius: 'var(--radius-sm)',
                    cursor: 'pointer',
                    textAlign: 'left',
                    transition: 'background-color 0.15s ease',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-warm)')}
                  onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                >
                  <Eye size={15} color="var(--copper-dark)" />
                  <span>Secure Preview</span>
                </button>

                {/* 2. Download File */}
                <button
                  type="button"
                  onClick={() => {
                    setIsActionMenuOpen(false);
                    handleDownload();
                  }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.625rem',
                    width: '100%',
                    padding: '0.5rem 0.75rem',
                    fontSize: '0.8125rem',
                    fontWeight: 500,
                    color: 'var(--graphite)',
                    backgroundColor: 'transparent',
                    border: 'none',
                    borderRadius: 'var(--radius-sm)',
                    cursor: 'pointer',
                    textAlign: 'left',
                    transition: 'background-color 0.15s ease',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-warm)')}
                  onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                >
                  <Download size={15} color="var(--copper)" />
                  <span>Download File</span>
                </button>

                {/* 3. Edit Metadata */}
                {canEdit && (
                  <button
                    type="button"
                    onClick={() => {
                      setIsActionMenuOpen(false);
                      handleStartEdit();
                    }}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.625rem',
                      width: '100%',
                      padding: '0.5rem 0.75rem',
                      fontSize: '0.8125rem',
                      fontWeight: 500,
                      color: 'var(--graphite)',
                      backgroundColor: 'transparent',
                      border: 'none',
                      borderRadius: 'var(--radius-sm)',
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'background-color 0.15s ease',
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-warm)')}
                    onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                  >
                    <Edit3 size={15} color="var(--text-secondary)" />
                    <span>Edit Metadata</span>
                  </button>
                )}

                {/* 4. Share Request Link */}
                {isOwner && (
                  <button
                    type="button"
                    onClick={() => {
                      setIsActionMenuOpen(false);
                      setActiveTab('links');
                      window.scrollTo({ top: 400, behavior: 'smooth' });
                    }}
                    title="Create or manage secure request links"
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.625rem',
                      width: '100%',
                      padding: '0.5rem 0.75rem',
                      fontSize: '0.8125rem',
                      fontWeight: 500,
                      color: 'var(--graphite)',
                      backgroundColor: 'transparent',
                      border: 'none',
                      borderRadius: 'var(--radius-sm)',
                      cursor: 'pointer',
                      textAlign: 'left',
                      transition: 'background-color 0.15s ease',
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-warm)')}
                    onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                  >
                    <Link2 size={15} color="var(--copper-dark)" />
                    <span>Share Request Link</span>
                  </button>
                )}

                {/* 5. Delete (red text, separated by a divider) */}
                {isOwner && (
                  <>
                    <div style={{ height: '1px', backgroundColor: 'var(--border)', margin: '0.25rem 0' }} />
                    <button
                      type="button"
                      onClick={() => {
                        setIsActionMenuOpen(false);
                        handleDelete();
                      }}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.625rem',
                        width: '100%',
                        padding: '0.5rem 0.75rem',
                        fontSize: '0.8125rem',
                        fontWeight: 500,
                        color: '#DC2626',
                        backgroundColor: 'transparent',
                        border: 'none',
                        borderRadius: 'var(--radius-sm)',
                        cursor: 'pointer',
                        textAlign: 'left',
                        transition: 'background-color 0.15s ease',
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(239, 68, 68, 0.08)')}
                      onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                    >
                      <Trash2 size={15} color="#DC2626" />
                      <span>Delete</span>
                    </button>
                  </>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Security & File Metadata Grid */}
        <div style={{
          marginTop: '1.5rem',
          paddingTop: '1.25rem',
          borderTop: '1px solid var(--border)',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '1rem',
          fontSize: '0.8125rem',
        }}>
          <div>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem', marginBottom: '0.125rem' }}>
              Original Filename
            </span>
            <span style={{ fontWeight: 600, fontFamily: 'var(--font-mono)', color: 'var(--graphite)', wordBreak: 'break-all' }}>
              {doc.original_filename}
            </span>
          </div>

          <div>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem', marginBottom: '0.125rem' }}>
              Size &amp; Format
            </span>
            <span style={{ fontWeight: 600, color: 'var(--graphite)' }}>
              {(doc.file_size / 1024).toFixed(1)} KB ({doc.detected_media_type})
            </span>
          </div>

          <div>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem', marginBottom: '0.125rem' }}>
              SHA-256 Checksum
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <span 
                style={{ 
                  fontWeight: 600, 
                  fontFamily: 'var(--font-mono)', 
                  fontSize: '0.75rem', 
                  color: 'var(--graphite)',
                  backgroundColor: 'var(--bg-surface-secondary)',
                  padding: '0.125rem 0.375rem',
                  borderRadius: 'var(--radius-xs)',
                  border: '1px solid var(--border)',
                }} 
                title={doc.checksum}
              >
                {doc.checksum.substring(0, 10)}...{doc.checksum.substring(54)}
              </span>
              <button
                type="button"
                onClick={handleCopyChecksum}
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  padding: '2px',
                  color: copiedChecksum ? 'var(--success)' : 'var(--text-muted)',
                  display: 'flex',
                  alignItems: 'center',
                }}
                title="Copy complete SHA-256 Checksum"
              >
                {copiedChecksum ? <CheckCircle size={14} /> : <Copy size={14} />}
              </button>
            </div>
          </div>

          <div>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.75rem', marginBottom: '0.125rem' }}>
              Document Owner
            </span>
            <span style={{ fontWeight: 600, color: 'var(--graphite)' }}>
              {doc.owner_name} <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>({doc.owner_email})</span>
            </span>
          </div>
        </div>
      </div>

      {/* ================= REFINED TAB NAVIGATION ================= */}
      <div style={{ 
        display: 'flex', 
        gap: '0.375rem', 
        borderBottom: '1px solid var(--border)', 
        marginBottom: '1.5rem',
      }}>
        <button
          className="btn btn-sm"
          onClick={() => setActiveTab('permissions')}
          style={{
            borderBottom: activeTab === 'permissions' ? '2px solid var(--copper)' : '2px solid transparent',
            borderRadius: '0',
            padding: '0.625rem 1rem',
            fontWeight: activeTab === 'permissions' ? 600 : 500,
            color: activeTab === 'permissions' ? 'var(--graphite)' : 'var(--text-secondary)',
            backgroundColor: activeTab === 'permissions' ? 'rgba(217, 154, 103, 0.08)' : 'transparent',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            transition: 'all 0.15s ease',
          }}
        >
          <Users size={15} color={activeTab === 'permissions' ? 'var(--copper-dark)' : 'currentColor'} />
          <span>Sharing &amp; Permissions ({permissions?.length || 0})</span>
        </button>

        <button
          className="btn btn-sm"
          onClick={() => setActiveTab('versions')}
          style={{
            borderBottom: activeTab === 'versions' ? '2px solid var(--copper)' : '2px solid transparent',
            borderRadius: '0',
            padding: '0.625rem 1rem',
            fontWeight: activeTab === 'versions' ? 600 : 500,
            color: activeTab === 'versions' ? 'var(--graphite)' : 'var(--text-secondary)',
            backgroundColor: activeTab === 'versions' ? 'rgba(217, 154, 103, 0.08)' : 'transparent',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            transition: 'all 0.15s ease',
          }}
        >
          <Layers size={15} color={activeTab === 'versions' ? 'var(--copper-dark)' : 'currentColor'} />
          <span>Version History ({versionsData?.total || doc?.version_count || 1})</span>
        </button>

        <button
          className="btn btn-sm"
          onClick={() => setActiveTab('ai')}
          style={{
            borderBottom: activeTab === 'ai' ? '2px solid var(--copper)' : '2px solid transparent',
            borderRadius: '0',
            padding: '0.625rem 1rem',
            fontWeight: activeTab === 'ai' ? 600 : 500,
            color: activeTab === 'ai' ? 'var(--graphite)' : 'var(--text-secondary)',
            backgroundColor: activeTab === 'ai' ? 'rgba(217, 154, 103, 0.08)' : 'transparent',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            transition: 'all 0.15s ease',
          }}
        >
          <Sparkles size={15} color={activeTab === 'ai' ? 'var(--copper-dark)' : 'currentColor'} />
          <span>AI Access Recommendations</span>
        </button>

        <button
          className="btn btn-sm"
          onClick={() => setActiveTab('audit')}
          style={{
            borderBottom: activeTab === 'audit' ? '2px solid var(--copper)' : '2px solid transparent',
            borderRadius: '0',
            padding: '0.625rem 1rem',
            fontWeight: activeTab === 'audit' ? 600 : 500,
            color: activeTab === 'audit' ? 'var(--graphite)' : 'var(--text-secondary)',
            backgroundColor: activeTab === 'audit' ? 'rgba(217, 154, 103, 0.08)' : 'transparent',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            transition: 'all 0.15s ease',
          }}
        >
          <History size={15} color={activeTab === 'audit' ? 'var(--copper-dark)' : 'currentColor'} />
          <span>Document Activity Log</span>
        </button>

        {isOwner && (
          <button
            className="btn btn-sm"
            onClick={() => setActiveTab('links')}
            style={{
              borderBottom: activeTab === 'links' ? '2px solid var(--copper)' : '2px solid transparent',
              borderRadius: '0',
              padding: '0.625rem 1rem',
              fontWeight: activeTab === 'links' ? 600 : 500,
              color: activeTab === 'links' ? 'var(--graphite)' : 'var(--text-secondary)',
              backgroundColor: activeTab === 'links' ? 'rgba(217, 154, 103, 0.08)' : 'transparent',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              transition: 'all 0.15s ease',
            }}
          >
            <Link2 size={15} color={activeTab === 'links' ? 'var(--copper-dark)' : 'currentColor'} />
            <span>Request Links ({requestLinks?.filter(l => l.is_active).length || 0})</span>
          </button>
        )}
      </div>

      {/* ================= TAB 1: PERMISSIONS & SHARING ================= */}
      {activeTab === 'permissions' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {isOwner && (
            <div className="panel" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                <Key size={16} color="var(--copper-dark)" />
                <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--graphite)', margin: 0 }}>
                  Grant Explicit Access
                </h3>
              </div>

              {grantError && (
                <div style={{
                  backgroundColor: 'var(--danger-bg)',
                  color: 'var(--danger)',
                  padding: '0.5rem 0.75rem',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.8125rem',
                  marginBottom: '1rem',
                  border: '1px solid var(--danger-border)',
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

                <div style={{ width: '160px' }}>
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

                <div style={{ width: '170px' }}>
                  <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                    <Clock size={12} color="var(--copper-dark)" />
                    <span>Access Expiry</span>
                  </label>
                  <select
                    className="input-field"
                    value={expiryPreset}
                    onChange={(e) => setExpiryPreset(e.target.value as any)}
                  >
                    <option value="never">Never (Indefinite)</option>
                    <option value="1h">1 Hour</option>
                    <option value="24h">24 Hours</option>
                    <option value="7d">7 Days</option>
                    <option value="30d">30 Days</option>
                    <option value="custom">Custom Date & Time</option>
                  </select>
                </div>

                {expiryPreset === 'custom' && (
                  <div style={{ width: '200px' }}>
                    <label className="form-label">Expiry Date & Time</label>
                    <input
                      type="datetime-local"
                      className="input-field"
                      value={customExpiryDate}
                      onChange={(e) => setCustomExpiryDate(e.target.value)}
                      required
                    />
                  </div>
                )}

                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    style={{ height: '38px', padding: '0 0.875rem', display: 'flex', alignItems: 'center', gap: '0.375rem' }}
                    onClick={() => handleRunSimulation(selectedUserEmail, selectedPermLevel, expiryPreset, customExpiryDate)}
                    disabled={!selectedUserEmail || isSimulating}
                    title="Simulate this proposed grant against current security policies"
                  >
                    <Sliders size={14} color="var(--copper-dark)" />
                    <span>{isSimulating ? 'Simulating...' : 'Simulate First'}</span>
                  </button>

                  <button type="submit" className="btn btn-primary" style={{ height: '38px', padding: '0 1rem' }}>
                  <Key size={14} color="var(--copper)" />
                  <span>Grant Access</span>
                </button>
                </div>
              </form>
            </div>
          )}

          {/* Access Policy Simulator Workbench */}
          {(isOwner || user?.role === 'admin') && (
            <div className="panel" style={{ padding: '1.25rem', border: '1px solid var(--border)', backgroundColor: 'var(--bg-surface)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Sliders size={18} color="var(--copper-dark)" />
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--graphite)', margin: 0 }}>
                        Access Policy Simulator
                      </h3>
                      <span className="badge badge-secondary" style={{ fontSize: '0.6875rem' }}>Read-Only Sandbox</span>
                    </div>
                    <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', margin: '0.125rem 0 0 0' }}>
                      Test proposed grants or policy evaluations without mutating database state or creating real permissions.
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  onClick={() => setShowSimulator(!showSimulator)}
                  style={{ fontSize: '0.75rem' }}
                >
                  {showSimulator ? 'Collapse Simulator' : 'Expand Simulator'}
                </button>
              </div>

              {showSimulator && (
                <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {simError && (
                    <div style={{
                      backgroundColor: 'var(--danger-bg)',
                      color: 'var(--danger)',
                      padding: '0.5rem 0.75rem',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '0.8125rem',
                      border: '1px solid var(--danger-border)',
                    }}>
                      {simError}
                    </div>
                  )}

                  <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'flex-end', padding: '0.75rem', backgroundColor: 'var(--bg-warm)', borderRadius: 'var(--radius-sm)' }}>
                    <div style={{ flex: 1, minWidth: '200px' }}>
                      <label className="form-label" style={{ fontSize: '0.75rem' }}>Simulated Recipient</label>
                      <select
                        className="input-field"
                        value={simUserEmail}
                        onChange={(e) => setSimUserEmail(e.target.value)}
                        style={{ fontSize: '0.8125rem' }}
                      >
                        <option value="">-- Choose Member to Test --</option>
                        {orgUsers?.filter(u => u.id !== doc.owner_id).map(u => (
                          <option key={u.id} value={u.email}>
                            {u.display_name} ({u.email}) - {u.role}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div style={{ width: '140px' }}>
                      <label className="form-label" style={{ fontSize: '0.75rem' }}>Proposed Level</label>
                      <select
                        className="input-field"
                        value={simPermLevel}
                        onChange={(e) => setSimPermLevel(e.target.value as 'read' | 'edit')}
                        style={{ fontSize: '0.8125rem' }}
                      >
                        <option value="read">Read Only</option>
                        <option value="edit">Edit Metadata</option>
                      </select>
                    </div>

                    <div style={{ width: '150px' }}>
                      <label className="form-label" style={{ fontSize: '0.75rem' }}>Proposed Expiry</label>
                      <select
                        className="input-field"
                        value={simExpiryPreset}
                        onChange={(e) => setSimExpiryPreset(e.target.value as any)}
                        style={{ fontSize: '0.8125rem' }}
                      >
                        <option value="never">Never (Indefinite)</option>
                        <option value="1h">1 Hour</option>
                        <option value="24h">24 Hours</option>
                        <option value="7d">7 Days</option>
                        <option value="30d">30 Days</option>
                        <option value="custom">Custom Date</option>
                      </select>
                    </div>

                    {simExpiryPreset === 'custom' && (
                      <div style={{ width: '180px' }}>
                        <label className="form-label" style={{ fontSize: '0.75rem' }}>Custom Date</label>
                        <input
                          type="datetime-local"
                          className="input-field"
                          value={simCustomExpiry}
                          onChange={(e) => setSimCustomExpiry(e.target.value)}
                          style={{ fontSize: '0.8125rem' }}
                        />
                      </div>
                    )}

                    <button
                      type="button"
                      className="btn btn-primary"
                      onClick={() => handleRunSimulation()}
                      disabled={!simUserEmail || isSimulating}
                      style={{ height: '36px', padding: '0 0.875rem', fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: '0.375rem' }}
                    >
                      <Sliders size={13} />
                      <span>{isSimulating ? 'Simulating...' : 'Run Simulation'}</span>
                    </button>
                  </div>

                  {simResult && (
                    <div style={{
                      padding: '1rem',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border)',
                      backgroundColor: simResult.status === 'allowed' 
                        ? 'rgba(34, 197, 94, 0.05)' 
                        : simResult.status === 'additional_requirements_needed' 
                          ? 'rgba(234, 179, 8, 0.05)' 
                          : 'rgba(239, 68, 68, 0.05)',
                    }}>
                      {/* Status Banner */}
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.75rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          {simResult.status === 'allowed' ? (
                            <CheckCircle2 size={18} color="#16a34a" />
                          ) : simResult.status === 'additional_requirements_needed' ? (
                            <AlertTriangle size={18} color="#d97706" />
                          ) : (
                            <XCircle size={18} color="#dc2626" />
                          )}
                          <span style={{
                            fontWeight: 700,
                            fontSize: '0.9375rem',
                            color: simResult.status === 'allowed' ? '#16a34a' : simResult.status === 'additional_requirements_needed' ? '#d97706' : '#dc2626',
                          }}>
                            {simResult.status === 'allowed'
                              ? 'Simulation Allowed: Proposal Meets All Security Policies'
                              : simResult.status === 'additional_requirements_needed'
                                ? 'Simulation Flagged: Additional Requirements Required'
                                : 'Simulation Denied: Prohibited by Policy'}
                          </span>
                        </div>

                        {simResult.is_allowed && isOwner && (
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={handleApplySimToGrant}
                            style={{ fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}
                          >
                            <Key size={12} />
                            <span>Pre-fill Grant Form</span>
                          </button>
                        )}
                      </div>

                      <p style={{ fontSize: '0.8125rem', color: 'var(--graphite)', margin: '0 0 0.75rem 0' }}>
                        {simResult.summary}
                      </p>

                      {/* Diff & Access Comparison Card */}
                      <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
                        gap: '0.75rem',
                        padding: '0.75rem',
                        backgroundColor: 'var(--bg-surface)',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid var(--border)',
                        marginBottom: '0.75rem',
                        fontSize: '0.8125rem',
                      }}>
                        <div>
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem', display: 'block', textTransform: 'uppercase' }}>Classification</span>
                          <span className={`badge ${
                            simResult.classification === 'Highly Restricted' ? 'badge-danger' : simResult.classification === 'Confidential' ? 'badge-copper' : 'badge-secondary'
                          }`} style={{ marginTop: '0.25rem', display: 'inline-block' }}>
                            {simResult.classification}
                          </span>
                        </div>
                        <div>
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem', display: 'block', textTransform: 'uppercase' }}>Current Access</span>
                          <span style={{ fontWeight: 600, color: 'var(--graphite)', textTransform: 'capitalize' }}>
                            {simResult.current_permission_level || 'None'}
                          </span>
                        </div>
                        <div>
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem', display: 'block', textTransform: 'uppercase' }}>Proposed Access</span>
                          <span style={{ fontWeight: 600, color: 'var(--copper-dark)', textTransform: 'capitalize' }}>
                            {simResult.proposed_permission}
                          </span>
                        </div>
                        <div>
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem', display: 'block', textTransform: 'uppercase' }}>Access Impact</span>
                          <span style={{ fontWeight: 500, color: 'var(--text-secondary)' }}>
                            {simResult.current_permission_level === simResult.proposed_permission 
                              ? 'No change in level' 
                              : simResult.current_permission_level 
                                ? 'Permission level updated' 
                                : 'New access grant'}
                          </span>
                        </div>
                      </div>

                      {/* Evaluated Rules Checklist */}
                      <div style={{ marginBottom: '0.75rem' }}>
                        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '0.375rem' }}>
                          Policy Rules Evaluated ({simResult.evaluated_rules.length})
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
                          {simResult.evaluated_rules.map((rule, idx) => (
                            <div key={idx} style={{
                              display: 'flex',
                              alignItems: 'flex-start',
                              gap: '0.5rem',
                              padding: '0.375rem 0.5rem',
                              backgroundColor: 'var(--bg-surface)',
                              borderRadius: 'var(--radius-xs)',
                              border: '1px solid var(--border)',
                              fontSize: '0.8125rem',
                            }}>
                              <span style={{ marginTop: '2px' }}>
                                {rule.passed ? <CheckCircle size={14} color="#16a34a" /> : <XCircle size={14} color="#dc2626" />}
                              </span>
                              <div>
                                <span style={{ fontWeight: 600, color: 'var(--graphite)', marginRight: '0.5rem' }}>{rule.name}:</span>
                                <span style={{ color: 'var(--text-secondary)' }}>{rule.details}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Failures and Remediation */}
                      {simResult.failures && simResult.failures.length > 0 && (
                        <div style={{
                          padding: '0.5rem 0.75rem',
                          backgroundColor: 'rgba(239, 68, 68, 0.1)',
                          border: '1px solid rgba(239, 68, 68, 0.3)',
                          borderRadius: 'var(--radius-xs)',
                          marginBottom: '0.5rem',
                        }}>
                          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#dc2626', marginBottom: '0.25rem' }}>
                            Policy Violations / Unmet Requirements:
                          </div>
                          {simResult.failures.map((f, i) => (
                            <div key={i} style={{ fontSize: '0.8125rem', color: '#991b1b' }}>• {f}</div>
                          ))}
                        </div>
                      )}

                      {simResult.remediation && (
                        <div style={{
                          padding: '0.5rem 0.75rem',
                          backgroundColor: 'rgba(59, 130, 246, 0.08)',
                          border: '1px solid rgba(59, 130, 246, 0.25)',
                          borderRadius: 'var(--radius-xs)',
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: '0.5rem',
                          fontSize: '0.8125rem',
                        }}>
                          <Info size={15} color="#2563eb" style={{ flexShrink: 0, marginTop: '2px' }} />
                          <div>
                            <strong style={{ color: '#1d4ed8' }}>Remediation: </strong>
                            <span style={{ color: '#1e3a8a' }}>{simResult.remediation}</span>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Active Grants Table */}
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Recipient</th>
                  <th>Permission Level</th>
                  <th>Granted By</th>
                  <th>Granted At</th>
                  <th>Access Expiry</th>
                  <th>Status</th>
                  {isOwner && <th style={{ textAlign: 'right' }}>Action</th>}
                </tr>
              </thead>
              <tbody>
                {permissions && permissions.length > 0 ? (
                  permissions.map((p) => {
                    const isRevoked = !!p.revoked_at || p.status === 'revoked';
                    const isExpired = p.is_expired || p.status === 'expired';
                    return (
                      <tr key={p.id} style={{ opacity: isRevoked ? 0.6 : 1 }}>
                        <td>
                          <div style={{ fontWeight: 600, color: 'var(--graphite)' }}>{p.user_display_name}</div>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{p.user_email}</div>
                        </td>
                        <td>
                          <span className={`badge ${p.permission_level === 'edit' ? 'badge-copper' : 'badge-green'}`} style={{ textTransform: 'capitalize' }}>
                            {p.permission_level === 'edit' ? 'Read & Edit' : 'Read Only'}
                          </span>
                        </td>
                        <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                          {p.granted_by_email || 'Owner'}
                        </td>
                        <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                          {formatToIST(p.granted_at)}
                        </td>
                        <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                          {p.expires_at ? (
                            <div>
                              <div>{formatToIST(p.expires_at)}</div>
                              <div style={{ fontSize: '0.7rem', color: isExpired ? 'var(--danger)' : 'var(--text-muted)' }}>
                                {isExpired ? 'Expired' : 'Time-limited'}
                              </div>
                            </div>
                          ) : (
                            <span style={{ color: 'var(--text-muted)' }}>Never</span>
                          )}
                        </td>
                        <td>
                          {isRevoked ? (
                            <span className="badge badge-danger">Revoked</span>
                          ) : isExpired ? (
                            <span className="badge" style={{ backgroundColor: '#FDF6B2', color: '#723B13', border: '1px solid #FCE96A' }}>Expired</span>
                          ) : (
                            <span className="badge badge-green">Active</span>
                          )}
                        </td>
                        {isOwner && (
                          <td style={{ textAlign: 'right' }}>
                            {!isRevoked ? (
                              <button
                                className="btn btn-danger btn-sm"
                                onClick={() => handleRevokePermission(p.user_id, p.user_email)}
                                title="Immediate permission revocation"
                              >
                                <X size={13} />
                                <span>Revoke</span>
                              </button>
                            ) : (
                              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                                Revoked
                              </span>
                            )}
                          </td>
                        )}
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={isOwner ? 7 : 6} style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                      No explicit permissions have been granted yet. Only the document owner has access.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ================= TAB: VERSION HISTORY ================= */}
      {activeTab === 'versions' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Upload Revision Card for editors/owners */}
          {canEdit && (
            <div className="panel" style={{ padding: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                <UploadCloud size={16} color="var(--copper-dark)" />
                <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--graphite)', margin: 0 }}>
                  Upload New Revision
                </h3>
              </div>
              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                Uploading a revision creates an immutable new version and sets it as current. Previous versions remain preserved and can be restored at any time.
              </p>
              <form onSubmit={handleUploadVersion} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 500, marginBottom: '0.375rem' }}>
                      Select File *
                    </label>
                    <input
                      type="file"
                      className="form-input"
                      required
                      onChange={(e) => setNewVersionFile(e.target.files?.[0] || null)}
                    />
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 500, marginBottom: '0.375rem' }}>
                      Change Summary / Reason (Optional)
                    </label>
                    <input
                      type="text"
                      className="form-input"
                      placeholder="e.g. Added section 4 review feedback"
                      value={newVersionSummary}
                      onChange={(e) => setNewVersionSummary(e.target.value)}
                    />
                  </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={!newVersionFile || isUploadingVersion}
                    style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                  >
                    {isUploadingVersion ? (
                      <>
                        <Clock size={15} className="spin" />
                        <span>Uploading Revision...</span>
                      </>
                    ) : (
                      <>
                        <UploadCloud size={15} />
                        <span>Upload Revision</span>
                      </>
                    )}
                  </button>
                </div>
              </form>
            </div>
          )}

          {/* Versions Table */}
          <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ padding: '1.25rem', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--graphite)', margin: 0 }}>
                  Revision History
                </h3>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: '0.25rem 0 0 0' }}>
                  Immutable record of all revisions with SHA-256 cryptographic verification.
                </p>
              </div>
              <span className="badge badge-secondary">
                {versionsData?.total || 0} {versionsData?.total === 1 ? 'version' : 'versions'}
              </span>
            </div>

            {versionsLoading ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
                Loading version history...
              </div>
            ) : !versionsData?.versions || versionsData.versions.length === 0 ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
                No versions found.
              </div>
            ) : (
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Version</th>
                      <th>Filename</th>
                      <th>Uploaded (IST)</th>
                      <th>Uploader</th>
                      <th>Size</th>
                      <th>SHA-256 Integrity</th>
                      <th>Notes</th>
                      <th style={{ textAlign: 'right' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {versionsData.versions.map((ver) => (
                      <tr key={ver.id} style={{ backgroundColor: ver.is_current ? 'rgba(217, 154, 103, 0.05)' : undefined }}>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <span style={{ fontWeight: 600, fontFamily: 'monospace' }}>v{ver.version_number}</span>
                            {ver.is_current && (
                              <span className="badge badge-success" style={{ fontSize: '0.7rem', padding: '0.15rem 0.4rem' }}>
                                Current
                              </span>
                            )}
                          </div>
                        </td>
                        <td style={{ fontWeight: 500 }}>{ver.original_filename}</td>
                        <td style={{ fontSize: '0.8125rem', whiteSpace: 'nowrap' }}>
                          {formatToIST(ver.created_at)}
                        </td>
                        <td style={{ fontSize: '0.8125rem' }}>
                          <div>{ver.uploader_name || 'System'}</div>
                          {ver.uploader_email && (
                            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{ver.uploader_email}</div>
                          )}
                        </td>
                        <td style={{ fontSize: '0.8125rem', whiteSpace: 'nowrap' }}>
                          {(ver.file_size / 1024).toFixed(1)} KB
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                            <span title="Integrity Verified" style={{ display: 'inline-flex' }}>
                              <CheckCircle size={14} color="#16a34a" />
                            </span>
                            <code style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                              {ver.checksum.substring(0, 8)}...{ver.checksum.substring(ver.checksum.length - 6)}
                            </code>
                            <button
                              type="button"
                              className="btn btn-ghost btn-sm"
                              style={{ padding: '0.15rem 0.35rem' }}
                              onClick={() => {
                                navigator.clipboard.writeText(ver.checksum);
                                setCopiedVersionChecksum(ver.id);
                                setTimeout(() => setCopiedVersionChecksum(null), 2000);
                              }}
                              title="Copy full SHA-256 hash"
                            >
                              {copiedVersionChecksum === ver.id ? <Check size={12} color="#16a34a" /> : <Copy size={12} />}
                            </button>
                          </div>
                        </td>
                        <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', maxWidth: '200px' }}>
                          {ver.change_summary || '-'}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <div style={{ display: 'inline-flex', gap: '0.5rem', justifyContent: 'flex-end' }}>
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              onClick={() => handleDownloadVersion(ver.id, ver.original_filename)}
                              title="Download this version"
                              style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', padding: '0.25rem 0.5rem' }}
                            >
                              <Download size={13} />
                              <span>Download</span>
                            </button>
                            {canEdit && !ver.is_current && (
                              <button
                                type="button"
                                className="btn btn-ghost btn-sm"
                                onClick={() => handleRestoreVersion(ver.id, ver.version_number)}
                                title="Restore this version as new current version"
                                style={{ display: 'flex', alignItems: 'center', gap: '0.25rem', padding: '0.25rem 0.5rem' }}
                              >
                                <RotateCcw size={13} />
                                <span>Restore</span>
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ================= TAB 2: AI ACCESS RECOMMENDATIONS ================= */}
      {activeTab === 'ai' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="panel">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem', marginBottom: '1rem' }}>
              <div>
                <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--graphite)', margin: 0 }}>
                  AI-Assisted Access Recommendations
                </h3>
                <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                  Minimum-necessary privilege suggestions based strictly on metadata classification.
                </p>
              </div>

              {isOwner && (
                <button
                  className="btn btn-primary btn-sm"
                  onClick={handleRequestAi}
                  disabled={isAiLoading}
                >
                  <Sparkles size={14} color="var(--copper)" />
                  <span>{isAiLoading ? 'Analyzing Policy...' : 'Request AI Recommendations'}</span>
                </button>
              )}
            </div>

            {/* AI Security Notice */}
            <div style={{
              backgroundColor: 'var(--bg-surface-secondary)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-sm)',
              padding: '0.75rem 1rem',
              fontSize: '0.8125rem',
              color: 'var(--text-secondary)',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
            }}>
              <Shield size={16} color="var(--copper-dark)" style={{ flexShrink: 0 }} />
              <span>
                <strong>Human-in-the-Loop Invariant:</strong> AI suggestions are purely advisory. The model receives zero document file bytes and has zero database write permissions. Only explicit human owner approval can create grants.
              </span>
            </div>

            {/* Active AI Suggestions Box */}
            {aiSuggestions.length > 0 && (
              <div style={{ marginTop: '1.5rem', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '1.25rem', backgroundColor: 'var(--bg-surface)' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span 
                      className="badge badge-copper" 
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '0.375rem' }}
                      title={`Engine: ${aiModel || 'TrustVault Policy Intelligence'}`}
                    >
                      <Sparkles size={13} />
                      <span>Advisor: Enterprise Policy {isMock ? '(Sandbox)' : '(Active)'}</span>
                    </span>
                    <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                      {aiSuggestions.length} candidates suggested
                    </span>
                  </div>

                  {isOwner && (
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button className="btn btn-secondary btn-sm" onClick={handleRejectAi}>
                        <X size={14} />
                        <span>Reject All</span>
                      </button>
                      <button className="btn btn-primary btn-sm" onClick={handleApproveAi}>
                        <Check size={14} color="var(--copper)" />
                        <span>Approve &amp; Grant Access</span>
                      </button>
                    </div>
                  )}
                </div>

                {aiExplanation && (
                  <div style={{ 
                    fontSize: '0.8125rem', 
                    fontStyle: 'italic', 
                    color: 'var(--text-secondary)', 
                    marginBottom: '1rem', 
                    padding: '0.625rem 0.875rem', 
                    backgroundColor: 'var(--bg-warm)', 
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border-subtle)',
                  }}>
                    "{aiExplanation}"
                  </div>
                )}

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
                  {aiSuggestions.map((s, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '0.75rem 1rem',
                        border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-sm)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        backgroundColor: '#FFFFFF',
                      }}
                    >
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span style={{ fontWeight: 600, color: 'var(--graphite)' }}>{s.display_name}</span>
                          <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>({s.email})</span>
                          <span className={`badge ${s.permission_level === 'edit' ? 'badge-copper' : 'badge-green'}`} style={{ textTransform: 'capitalize' }}>
                            Suggested: {s.permission_level}
                          </span>
                        </div>
                        <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginTop: '0.25rem', margin: '0.25rem 0 0' }}>
                          {s.rationale}
                        </p>
                      </div>

                      <div style={{ textAlign: 'right' }}>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
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

      {/* ================= TAB 3: AUDIT HISTORY ================= */}
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
                    <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                      {formatToIST(e.timestamp)}
                    </td>
                    <td>
                      <span style={{ fontWeight: 600, fontFamily: 'var(--font-mono)', fontSize: '0.8125rem', color: 'var(--graphite)' }}>
                        {e.action}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                      {e.actor_email || 'System'}
                    </td>
                    <td>
                      <span className={`badge ${e.outcome === 'success' ? 'badge-green' : 'badge-red'}`}>
                        {e.outcome}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }} title={e.event_hash}>
                      {e.event_hash.substring(0, 16)}...
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                    No activity recorded yet for this document.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* ================= TAB 4: REQUEST LINKS ================= */}
      {activeTab === 'links' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Newly Created Link Alert Banner */}
          {createdLinkInfo && (
            <div style={{
              backgroundColor: 'rgba(217, 154, 103, 0.08)',
              border: '1px solid var(--copper)',
              borderRadius: '0.5rem',
              padding: '1.25rem',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <CheckCircle size={18} color="var(--copper-dark)" />
                  <span style={{ fontWeight: 600, color: 'var(--graphite)', fontSize: '0.9375rem' }}>
                    Request Link Generated Successfully
                  </span>
                </div>
                <button
                  onClick={() => setCreatedLinkInfo(null)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)' }}
                >
                  <X size={16} />
                </button>
              </div>

              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginBottom: '0.75rem', lineHeight: 1.45 }}>
                Share this secure reference URL with users who need to request access to <strong>"{createdLinkInfo.document_title}"</strong>. For zero-trust security, the raw token is shown only once and cannot be retrieved later.
              </p>

              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                backgroundColor: '#FFFFFF',
                border: '1px solid var(--border)',
                borderRadius: '0.375rem',
                padding: '0.5rem 0.75rem',
              }}>
                <span style={{
                  fontFamily: 'monospace',
                  fontSize: '0.8125rem',
                  color: 'var(--text-primary)',
                  flex: 1,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap'
                }}>
                  {`${window.location.origin}/request-access/${createdLinkInfo.token}`}
                </span>
                <button
                  type="button"
                  onClick={() => handleCopyGeneratedLink(createdLinkInfo.token)}
                  className="btn btn-sm btn-primary"
                  style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', flexShrink: 0 }}
                >
                  {copiedLink ? <Check size={13} /> : <Copy size={13} />}
                  <span>{copiedLink ? 'Copied' : 'Copy Link'}</span>
                </button>
              </div>
            </div>
          )}

          {/* Create Request Link Form Panel */}
          <div className="panel" style={{ padding: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
              <Link2 size={16} color="var(--copper-dark)" />
              <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--graphite)', margin: 0 }}>
                Generate Secure Request Link
              </h3>
            </div>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', marginBottom: '1.25rem', lineHeight: 1.45 }}>
              Create an unpredictable, revocable access reference. Authenticated recipients can view basic metadata and submit an access request without gaining direct document access.
            </p>

            <form onSubmit={handleCreateRequestLink} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-primary)', marginBottom: '0.375rem' }}>
                    Link Label / Context (Optional)
                  </label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="e.g., Q3 Auditor Review, Engineering Onboarding"
                    value={newLinkName}
                    onChange={(e) => setNewLinkName(e.target.value)}
                    maxLength={100}
                    style={{ fontSize: '0.8125rem' }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-primary)', marginBottom: '0.375rem' }}>
                    Max Submissions / Uses (Optional)
                  </label>
                  <input
                    type="number"
                    min="1"
                    max="1000"
                    className="form-input"
                    placeholder="Leave empty for unlimited uses"
                    value={newLinkMaxUses}
                    onChange={(e) => setNewLinkMaxUses(e.target.value)}
                    style={{ fontSize: '0.8125rem' }}
                  />
                </div>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-primary)', marginBottom: '0.375rem' }}>
                  Link Expiration Policy
                </label>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.375rem', marginBottom: '0.5rem' }}>
                  {(['1h', '24h', '7d', '30d', 'never', 'custom'] as const).map(preset => (
                    <button
                      key={preset}
                      type="button"
                      onClick={() => setNewLinkDuration(preset)}
                      className="btn btn-sm"
                      style={{
                        padding: '0.25rem 0.5rem',
                        fontSize: '0.75rem',
                        backgroundColor: newLinkDuration === preset ? 'var(--graphite)' : 'var(--bg-warm)',
                        color: newLinkDuration === preset ? '#FFFFFF' : 'var(--text-secondary)',
                        borderColor: newLinkDuration === preset ? 'var(--graphite)' : 'var(--border)',
                      }}
                    >
                      {preset === '1h' ? '1 Hour' : preset === '24h' ? '24 Hours' : preset === '7d' ? '7 Days' : preset === '30d' ? '30 Days' : preset === 'never' ? 'Permanent' : 'Custom'}
                    </button>
                  ))}
                </div>

                {newLinkDuration === 'custom' && (
                  <input
                    type="datetime-local"
                    className="form-input"
                    value={newLinkCustomExpiry}
                    onChange={(e) => setNewLinkCustomExpiry(e.target.value)}
                    style={{ fontSize: '0.8125rem', maxWidth: '300px' }}
                  />
                )}
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
                <button
                  type="submit"
                  className="btn btn-primary btn-sm"
                  disabled={isCreatingLink}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '0.375rem' }}
                >
                  <Plus size={14} />
                  <span>{isCreatingLink ? 'Generating...' : 'Generate Request Link'}</span>
                </button>
              </div>
            </form>
          </div>

          {/* List of Existing Request Links */}
          <div className="panel" style={{ padding: '0', overflow: 'hidden' }}>
            <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h3 style={{ fontSize: '0.9375rem', fontWeight: 600, color: 'var(--graphite)', margin: 0 }}>
                  Active &amp; Historical Request Links
                </h3>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                  Manage valid tokens and immediately revoke references as needed.
                </span>
              </div>
              <span className="badge badge-gray">
                {requestLinks?.length || 0} Total
              </span>
            </div>

            <div style={{ overflowX: 'auto' }}>
              <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ backgroundColor: 'var(--bg-warm)', textAlign: 'left', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                    <th style={{ padding: '0.75rem 1rem' }}>Label / Reference</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Uses / Cap</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Expires</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Status</th>
                    <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody style={{ fontSize: '0.8125rem' }}>
                  {requestLinks && requestLinks.length > 0 ? (
                    requestLinks.map(link => {
                      const isRevoked = Boolean(link.revoked_at);
                      const isMaxReached = Boolean(link.max_uses && link.use_count >= link.max_uses);
                      const isInactive = !link.is_active;

                      return (
                        <tr key={link.id} style={{ borderBottom: '1px solid var(--border)' }}>
                          <td style={{ padding: '0.75rem 1rem' }}>
                            <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                              {link.name || 'Unnamed Request Link'}
                            </div>
                            <div style={{ fontFamily: 'monospace', fontSize: '0.6875rem', color: 'var(--text-secondary)' }}>
                              ref_{link.token_prefix}...
                            </div>
                          </td>
                          <td style={{ padding: '0.75rem 1rem' }}>
                            <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>
                              {link.use_count}
                            </span>
                            <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>
                              {link.max_uses ? ` / ${link.max_uses}` : ' (unlimited)'}
                            </span>
                          </td>
                          <td style={{ padding: '0.75rem 1rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                            {link.expires_at ? formatToIST(link.expires_at) : 'Never (Permanent)'}
                          </td>
                          <td style={{ padding: '0.75rem 1rem' }}>
                            {isRevoked ? (
                              <span className="badge badge-red" style={{ fontSize: '0.6875rem' }}>
                                Revoked
                              </span>
                            ) : isMaxReached ? (
                              <span className="badge badge-yellow" style={{ fontSize: '0.6875rem' }}>
                                Limit Reached
                              </span>
                            ) : isInactive ? (
                              <span className="badge badge-gray" style={{ fontSize: '0.6875rem' }}>
                                Expired
                              </span>
                            ) : (
                              <span className="badge badge-green" style={{ fontSize: '0.6875rem' }}>
                                Active
                              </span>
                            )}
                          </td>
                          <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                            {link.is_active ? (
                              <button
                                type="button"
                                onClick={() => handleRevokeRequestLink(link.id, link.token_prefix)}
                                className="btn btn-sm"
                                style={{
                                  padding: '0.25rem 0.5rem',
                                  fontSize: '0.6875rem',
                                  color: '#DC2626',
                                  backgroundColor: 'rgba(220, 38, 38, 0.08)',
                                  borderColor: 'rgba(220, 38, 38, 0.2)',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '0.25rem'
                                }}
                              >
                                <Ban size={12} />
                                <span>Revoke</span>
                              </button>
                            ) : (
                              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                —
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={5} style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                        No request links generated for this document yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ================= EDIT METADATA MODAL ================= */}
      {isEditingMeta && (
        <div className="modal-overlay" onClick={() => setIsEditingMeta(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.75rem' }}>
              <h2 style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--graphite)', margin: 0 }}>
                Edit Document Metadata
              </h2>
              <button 
                onClick={() => setIsEditingMeta(false)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)' }}
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleSaveMeta}>
              <div className="form-group">
                <label className="form-label">Document Title</label>
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
                <label className="form-label">Classification Security Policy</label>
                <select
                  className="input-field"
                  value={editClassification}
                  onChange={(e) => setEditClassification(e.target.value)}
                  disabled={!isOwner && user?.role !== 'admin'}
                >
                  <option value="Internal">Internal (Standard confidentiality)</option>
                  <option value="Confidential">Confidential (Max 90 days grant duration)</option>
                  <option value="Highly Restricted">Highly Restricted (No downloads, Max 7 days, MFA required)</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Description</label>
                <textarea
                  className="input-field"
                  rows={3}
                  value={editDesc}
                  onChange={(e) => setEditDesc(e.target.value)}
                  placeholder="Optional confidential notes or business context..."
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

      {/* ================= SECURE FORENSIC PREVIEW MODAL ================= */}
      {isPreviewOpen && (
        <div className="modal-overlay" onClick={handleClosePreview} style={{ zIndex: 9999 }}>
          <div 
            className="modal-content" 
            onClick={(e) => e.stopPropagation()} 
            style={{ 
              maxWidth: '850px', 
              width: '95%', 
              maxHeight: '90vh', 
              display: 'flex', 
              flexDirection: 'column',
              position: 'relative',
              overflow: 'hidden',
              padding: '1.25rem',
            }}
          >
            {/* Modal Header */}
            <div style={{ 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'space-between', 
              marginBottom: '1rem', 
              borderBottom: '1px solid var(--border)', 
              paddingBottom: '0.75rem',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
                <div style={{ 
                  padding: '6px', 
                  borderRadius: 'var(--radius-sm)', 
                  backgroundColor: 'var(--graphite)', 
                  color: 'var(--copper)', 
                  display: 'flex', 
                  alignItems: 'center',
                }}>
                  <Shield size={18} />
                </div>
                <div>
                  <h2 style={{ fontSize: '1.0625rem', fontWeight: 700, margin: 0, color: 'var(--graphite)' }}>
                    Secure Forensic Preview
                  </h2>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    {doc.original_filename} &bull; {doc.detected_media_type}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                {previewTotalPages > 1 && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', marginRight: '0.5rem' }}>
                    <button 
                      type="button" 
                      className="btn btn-secondary btn-sm"
                      disabled={previewCurrentPage <= 1 || isPreviewLoading}
                      onClick={() => loadPreviewPage(previewCurrentPage - 1)}
                      style={{ padding: '0.25rem 0.5rem' }}
                      title="Previous Page"
                    >
                      <ChevronLeft size={14} />
                    </button>
                    <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                      {previewCurrentPage} / {previewTotalPages}
                    </span>
                    <button 
                      type="button" 
                      className="btn btn-secondary btn-sm"
                      disabled={previewCurrentPage >= previewTotalPages || isPreviewLoading}
                      onClick={() => loadPreviewPage(previewCurrentPage + 1)}
                      style={{ padding: '0.25rem 0.5rem' }}
                      title="Next Page"
                    >
                      <ChevronRight size={14} />
                    </button>
                  </div>
                )}
                {canDownload && (
                  <button className="btn btn-primary btn-sm" onClick={handleDownload}>
                    <Download size={13} color="var(--copper)" />
                    <span>Download</span>
                  </button>
                )}
                <button 
                  onClick={handleClosePreview}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px', color: 'var(--text-secondary)' }}
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            {/* Preview Box Container with Watermarked Raster Rendering */}
            <div style={{ 
              position: 'relative', 
              flex: 1, 
              minHeight: '420px', 
              maxHeight: '65vh', 
              overflowY: 'auto', 
              backgroundColor: 'var(--bg-warm)', 
              borderRadius: 'var(--radius-sm)',
              border: '1px solid var(--border)',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'center',
              alignItems: 'center',
              padding: '1rem',
            }}>
              {/* Content Renderers: Client receives ONLY raster images with burned forensic watermarks */}
              {isPreviewLoading ? (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.75rem', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                  <Shield size={28} className="animate-pulse" color="var(--copper)" />
                  <span>Generating sandboxed raster page with burned forensic watermarking...</span>
                </div>
              ) : previewBlobUrl ? (
                <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', width: '100%', height: '100%' }}>
                  <img 
                    src={previewBlobUrl} 
                    alt={`Secure Page ${previewCurrentPage} of ${previewTotalPages}`} 
                    style={{ 
                      maxWidth: '100%', 
                      maxHeight: '60vh', 
                      objectFit: 'contain', 
                      boxShadow: '0 4px 16px rgba(0,0,0,0.12)', 
                      borderRadius: '4px',
                      border: '1px solid var(--border)'
                    }}
                  />
                </div>
              ) : (
                <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  Preview unavailable.
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div style={{ 
              marginTop: '0.75rem', 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'space-between', 
              fontSize: '0.75rem', 
              color: 'var(--text-muted)',
              fontFamily: 'var(--font-mono)',
            }}>
              <span>Session: {previewTimestamp} &bull; Checksum: {doc.checksum.substring(0, 16)}...</span>
              <span style={{ fontFamily: 'var(--font-family)' }}>Screen capture violates organization policy</span>
            </div>
          </div>
        </div>
      )}

      {/* Corporate In-App Confirmation Modal */}
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
