import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { 
  FileText, 
  Plus, 
  Search, 
  Filter, 
  Download, 
  Eye, 
  Lock, 
  ShieldCheck, 
  Database,
  SlidersHorizontal,
  RotateCcw,
  Calendar,
  ArrowUpDown,
  Trash2,
  Clock,
  ShieldAlert,
  X,
  History
} from 'lucide-react';
import { api } from '../lib/api';
import { useToast } from '../context/ToastContext';
import { UploadModal } from '../features/documents/UploadModal';
import type { DocumentItem } from '../types';

export const DocumentsPage: React.FC = () => {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [fileType, setFileType] = useState('all');
  const [permissionFilter, setPermissionFilter] = useState<'all' | 'owned' | 'shared'>('all');
  const [sortBy, setSortBy] = useState<'created_at' | 'title' | 'file_size'>('created_at');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'active' | 'trash'>('active');
  const [inspectingTrashedDoc, setInspectingTrashedDoc] = useState<DocumentItem | null>(null);
  const [docAuditEvents, setDocAuditEvents] = useState<any[]>([]);
  const [isLoadingAudit, setIsLoadingAudit] = useState(false);

  const activeFiltersCount = (selectedCategory !== 'all' ? 1 : 0) +
    (fileType !== 'all' ? 1 : 0) +
    (permissionFilter !== 'all' ? 1 : 0) +
    (sortBy !== 'created_at' || sortOrder !== 'desc' ? 1 : 0) +
    (dateFrom ? 1 : 0) +
    (dateTo ? 1 : 0);

  const handleResetFilters = () => {
    setSearchTerm('');
    setSelectedCategory('all');
    setFileType('all');
    setPermissionFilter('all');
    setSortBy('created_at');
    setSortOrder('desc');
    setDateFrom('');
    setDateTo('');
  };

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['documents', searchTerm, selectedCategory, fileType, permissionFilter, sortBy, sortOrder, dateFrom, dateTo],
    queryFn: () => api.listDocuments({
      query: searchTerm || undefined,
      category: selectedCategory !== 'all' ? selectedCategory : undefined,
      file_type: fileType !== 'all' ? fileType : undefined,
      permission_filter: permissionFilter !== 'all' ? permissionFilter : undefined,
      sort_by: sortBy,
      sort_order: sortOrder,
      date_from: dateFrom ? new Date(dateFrom).toISOString() : undefined,
      date_to: dateTo ? new Date(dateTo + 'T23:59:59').toISOString() : undefined,
    }),
  });

  const { data: trashedData, isLoading: isLoadingTrash } = useQuery({
    queryKey: ['trashedDocuments', searchTerm, selectedCategory],
    queryFn: () => api.listTrashedDocuments({
      query: searchTerm || undefined,
      category: selectedCategory !== 'all' ? selectedCategory : undefined,
    }),
  });

  const handleInspectAudit = async (doc: DocumentItem) => {
    setInspectingTrashedDoc(doc);
    setIsLoadingAudit(true);
    try {
      const res = await api.listAuditEvents({ document_id: doc.id });
      setDocAuditEvents(res.events || []);
    } catch (err: any) {
      toast.error(err.message || 'Failed to load audit events');
    } finally {
      setIsLoadingAudit(false);
    }
  };

  const handleDownload = async (e: React.MouseEvent, doc: DocumentItem) => {
    e.stopPropagation();
    try {
      setDownloadingId(doc.id);
      await api.downloadDocument(doc.id, doc.original_filename);
      toast.success(`Download started: ${doc.original_filename}`);
    } catch (err: any) {
      toast.error(err.message || 'Download failed');
    } finally {
      setDownloadingId(null);
      queryClient.invalidateQueries({ queryKey: ['auditEvents'] });
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="container">
      {/* ================= TOP PAGE HEADER ================= */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '1.5rem',
        flexWrap: 'wrap',
        gap: '1rem',
      }}>
        <div>
          <div style={{
            fontSize: '0.75rem',
            fontWeight: 700,
            textTransform: 'uppercase',
            color: 'var(--copper-dark)',
            letterSpacing: '0.06em',
            marginBottom: '0.25rem',
          }}>
            Confidential Document Repository
          </div>
          <h1 style={{
            fontSize: '1.625rem',
            fontWeight: 700,
            letterSpacing: '-0.025em',
            color: 'var(--graphite)',
            margin: 0,
          }}>
            Protected Documents
          </h1>
          <p style={{
            fontSize: '0.875rem',
            color: 'var(--text-secondary)',
            marginTop: '0.25rem',
            margin: '0.25rem 0 0',
          }}>
            Strict row-level access control with live stream authorization and cryptographic auditing.
          </p>
        </div>

        <button
          className="btn btn-primary"
          onClick={() => setIsUploadOpen(true)}
          style={{ padding: '0.5625rem 1rem' }}
        >
          <Plus size={16} color="var(--copper)" />
          <span>Upload Document</span>
        </button>
      </div>

      {/* ================= METRICS STATUS STRIP ================= */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '0.875rem',
        marginBottom: '1.5rem',
      }}>
        <div className="panel" style={{ padding: '1rem', display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
          <div style={{
            width: '38px',
            height: '38px',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'var(--copper-light)',
            border: '1px solid var(--copper-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--copper-dark)',
            flexShrink: 0,
          }}>
            <FileText size={19} />
          </div>
          <div>
            <div style={{ fontSize: '0.6875rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
              Authorized Assets
            </div>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--graphite)', lineHeight: 1.2 }}>
              {isLoading ? '...' : (data?.documents?.length ?? 0)}
            </div>
            <div style={{ fontSize: '0.725rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Accessible in active scope
            </div>
          </div>
        </div>

        <div className="panel" style={{ padding: '1rem', display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
          <div style={{
            width: '38px',
            height: '38px',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'var(--success-bg)',
            border: '1px solid var(--success-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--success)',
            flexShrink: 0,
          }}>
            <ShieldCheck size={19} />
          </div>
          <div>
            <div style={{ fontSize: '0.6875rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
              Access Policy
            </div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--graphite)', lineHeight: 1.2, display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <span>Zero-Trust RLS</span>
              <span className="badge badge-green" style={{ fontSize: '0.625rem', padding: '0.1rem 0.35rem' }}>Enforced</span>
            </div>
            <div style={{ fontSize: '0.725rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Server evaluates live on every request
            </div>
          </div>
        </div>

        <div className="panel" style={{ padding: '1rem', display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
          <div style={{
            width: '38px',
            height: '38px',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'var(--bg-surface-secondary)',
            border: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--graphite)',
            flexShrink: 0,
          }}>
            <Database size={19} />
          </div>
          <div>
            <div style={{ fontSize: '0.6875rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
              Audit Ledger
            </div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--graphite)', lineHeight: 1.2, display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <span>SHA-256 Chained</span>
              <span className="badge badge-copper" style={{ fontSize: '0.625rem', padding: '0.1rem 0.35rem' }}>Verified</span>
            </div>
            <div style={{ fontSize: '0.725rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Tamper-evident canonical JSON
            </div>
          </div>
        </div>

        <div className="panel" style={{ padding: '1rem', display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
          <div style={{
            width: '38px',
            height: '38px',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'var(--bg-surface-secondary)',
            border: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--graphite)',
            flexShrink: 0,
          }}>
            <Lock size={19} />
          </div>
          <div>
            <div style={{ fontSize: '0.6875rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
              Storage Security
            </div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--graphite)', lineHeight: 1.2, display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <span>Private Vault</span>
              <span className="badge badge-gray" style={{ fontSize: '0.625rem', padding: '0.1rem 0.35rem' }}>Isolated</span>
            </div>
            <div style={{ fontSize: '0.725rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Opaque UUID keys outside web root
            </div>
          </div>
        </div>
      </div>

      {/* ================= REPOSITORY VIEW TABS ================= */}
      <div style={{ display: 'flex', gap: '0.625rem', marginBottom: '1rem', alignItems: 'center' }}>
        <button
          type="button"
          onClick={() => setActiveTab('active')}
          className={`btn ${activeTab === 'active' ? 'btn-primary' : 'btn-secondary'}`}
          style={{
            fontSize: '0.8125rem',
            padding: '0.45rem 1rem',
            gap: '0.4rem',
            display: 'flex',
            alignItems: 'center',
          }}
        >
          <FileText size={15} />
          <span>Active Repository</span>
          {data?.total !== undefined && (
            <span
              className="badge"
              style={{
                backgroundColor: activeTab === 'active' ? 'rgba(0,0,0,0.2)' : 'var(--bg-card)',
                color: activeTab === 'active' ? '#fff' : 'var(--text-secondary)',
                fontSize: '0.6875rem',
                padding: '0.1rem 0.35rem',
                marginLeft: '0.25rem',
              }}
            >
              {data.total}
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('trash')}
          className={`btn ${activeTab === 'trash' ? 'btn-primary' : 'btn-secondary'}`}
          style={{
            fontSize: '0.8125rem',
            padding: '0.45rem 1rem',
            gap: '0.4rem',
            display: 'flex',
            alignItems: 'center',
            backgroundColor: activeTab === 'trash' ? 'var(--danger)' : undefined,
            borderColor: activeTab === 'trash' ? 'var(--danger)' : undefined,
            color: activeTab === 'trash' ? '#fff' : undefined,
          }}
        >
          <Trash2 size={15} />
          <span>Trash & Purged Documents</span>
          {trashedData?.total !== undefined && (
            <span
              className="badge"
              style={{
                backgroundColor: activeTab === 'trash' ? 'rgba(0,0,0,0.25)' : 'var(--bg-card)',
                color: activeTab === 'trash' ? '#fff' : 'var(--text-secondary)',
                fontSize: '0.6875rem',
                padding: '0.1rem 0.35rem',
                marginLeft: '0.25rem',
              }}
            >
              {trashedData.total}
            </span>
          )}
        </button>
      </div>

      {/* ================= SEARCH & FILTER CONTROLS ================= */}
      <div className="panel" style={{ padding: '0.875rem 1rem', marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, minWidth: '240px' }}>
            <Search size={16} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Search documents by title or original filename..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                border: 'none',
                outline: 'none',
                width: '100%',
                fontSize: '0.875rem',
                backgroundColor: 'transparent',
                color: 'var(--text-primary)',
              }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <Filter size={14} color="var(--text-muted)" />
              <select
                className="input-field"
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                style={{ width: 'auto', padding: '0.35rem 0.75rem', fontSize: '0.8125rem' }}
              >
                <option value="all">All Categories</option>
                <option value="Financial">Financial</option>
                <option value="Legal">Legal</option>
                <option value="Executive">Executive</option>
                <option value="Engineering">Engineering</option>
                <option value="HR">HR</option>
                <option value="General">General</option>
              </select>
            </div>

            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
              style={{
                gap: '0.375rem',
                backgroundColor: showAdvancedFilters ? 'var(--copper-light)' : undefined,
                borderColor: showAdvancedFilters ? 'var(--copper)' : undefined,
              }}
            >
              <SlidersHorizontal size={13} color={activeFiltersCount > 0 ? 'var(--copper-dark)' : 'currentColor'} />
              <span>Advanced Filters</span>
              {activeFiltersCount > 0 && (
                <span className="badge badge-copper" style={{ fontSize: '0.625rem', padding: '0.05rem 0.35rem' }}>
                  {activeFiltersCount}
                </span>
              )}
            </button>

            {activeFiltersCount > 0 && (
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={handleResetFilters}
                title="Reset all filters to defaults"
                style={{ gap: '0.25rem', color: 'var(--text-muted)' }}
              >
                <RotateCcw size={12} />
                <span>Reset</span>
              </button>
            )}
          </div>
        </div>

        {/* Expandable Advanced Search Drawer */}
        {showAdvancedFilters && (
          <div style={{
            marginTop: '0.875rem',
            paddingTop: '0.875rem',
            borderTop: '1px solid var(--border)',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: '0.875rem',
          }}>
            <div>
              <label className="form-label" style={{ fontSize: '0.75rem' }}>File Type / Format</label>
              <select
                className="input-field"
                value={fileType}
                onChange={(e) => setFileType(e.target.value)}
                style={{ fontSize: '0.8125rem', padding: '0.35rem 0.5rem' }}
              >
                <option value="all">All Formats</option>
                <option value="pdf">PDF Documents (.pdf)</option>
                <option value="docx">Word (.docx)</option>
                <option value="csv">Data Spreadsheets (.csv)</option>
                <option value="txt">Plain Text (.txt)</option>
                <option value="json">Structured JSON (.json)</option>
                <option value="image">Images (PNG/JPG)</option>
              </select>
            </div>

            <div>
              <label className="form-label" style={{ fontSize: '0.75rem' }}>Ownership Scope</label>
              <select
                className="input-field"
                value={permissionFilter}
                onChange={(e) => setPermissionFilter(e.target.value as any)}
                style={{ fontSize: '0.8125rem', padding: '0.35rem 0.5rem' }}
              >
                <option value="all">All Authorized</option>
                <option value="owned">Owned by Me</option>
                <option value="shared">Shared with Me</option>
              </select>
            </div>

            <div>
              <label className="form-label" style={{ fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <ArrowUpDown size={11} />
                <span>Sort Field &amp; Order</span>
              </label>
              <div style={{ display: 'flex', gap: '0.375rem' }}>
                <select
                  className="input-field"
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as any)}
                  style={{ fontSize: '0.8125rem', padding: '0.35rem 0.5rem', flex: 1 }}
                >
                  <option value="created_at">Date Created</option>
                  <option value="title">Document Title</option>
                  <option value="file_size">File Size</option>
                </select>
                <select
                  className="input-field"
                  value={sortOrder}
                  onChange={(e) => setSortOrder(e.target.value as any)}
                  style={{ fontSize: '0.8125rem', padding: '0.35rem 0.5rem', width: '80px' }}
                >
                  <option value="desc">Desc</option>
                  <option value="asc">Asc</option>
                </select>
              </div>
            </div>

            <div>
              <label className="form-label" style={{ fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <Calendar size={11} />
                <span>Created From</span>
              </label>
              <input
                type="date"
                className="input-field"
                value={dateFrom}
                onChange={(e) => setDateFrom(e.target.value)}
                style={{ fontSize: '0.8125rem', padding: '0.3rem 0.5rem' }}
              />
            </div>

            <div>
              <label className="form-label" style={{ fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <Calendar size={11} />
                <span>Created To</span>
              </label>
              <input
                type="date"
                className="input-field"
                value={dateTo}
                onChange={(e) => setDateTo(e.target.value)}
                style={{ fontSize: '0.8125rem', padding: '0.3rem 0.5rem' }}
              />
            </div>
          </div>
        )}
      </div>

      {/* ================= ACTIVE DOCUMENTS VIEW ================= */}
      {activeTab === 'active' && (
        <>
          {isLoading ? (
            <div className="panel" style={{ textAlign: 'center', padding: '3.5rem', color: 'var(--text-muted)' }}>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
                <span className="pulse-dot" style={{ backgroundColor: 'var(--copper)', width: '10px', height: '10px' }}></span>
                <span style={{ fontSize: '0.875rem' }}>Loading authorized documents...</span>
              </div>
            </div>
          ) : data?.documents && data.documents.length > 0 ? (
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ width: '35%' }}>Document</th>
                    <th>Classification</th>
                    <th>Owner</th>
                    <th>File Size</th>
                    <th>Uploaded</th>
                    <th>Your Access</th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {data.documents.map((doc) => (
                    <tr key={doc.id}>
                      <td>
                        <Link
                          to={`/documents/${doc.id}`}
                          style={{
                            fontWeight: 600,
                            color: 'var(--graphite)',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.5rem',
                          }}
                        >
                          <FileText size={16} color="var(--copper-dark)" />
                          <span>{doc.title}</span>
                        </Link>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.125rem', fontFamily: 'var(--font-mono)' }}>
                          {doc.original_filename}
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', alignItems: 'flex-start' }}>
                          <span className="badge badge-gray">{doc.category}</span>
                          {doc.classification && (
                            <span className={`badge ${
                              doc.classification === 'Highly Restricted' 
                                ? 'badge-danger' 
                                : doc.classification === 'Confidential' 
                                  ? 'badge-copper' 
                                  : 'badge-secondary'
                            }`} style={{ fontSize: '0.675rem', padding: '0.1rem 0.35rem' }}>
                              {doc.classification}
                            </span>
                          )}
                        </div>
                      </td>
                      <td>
                        <div style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                          {doc.owner_name}
                        </div>
                        <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>
                          {doc.owner_email}
                        </div>
                      </td>
                      <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                        {formatFileSize(doc.file_size)}
                      </td>
                      <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                        {new Date(doc.created_at).toLocaleDateString()}
                      </td>
                      <td>
                        <span className={`badge ${
                          doc.effective_permission === 'owner' 
                            ? 'badge-green' 
                            : doc.effective_permission === 'edit'
                            ? 'badge-copper'
                            : 'badge-gray'
                        }`} style={{ textTransform: 'capitalize' }}>
                          {doc.effective_permission === 'owner' ? 'Owner' : `${doc.effective_permission} Access`}
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: '0.375rem' }}>
                          <Link
                            to={`/documents/${doc.id}`}
                            className="btn btn-secondary btn-sm"
                            title="View details & sharing settings"
                          >
                            <Eye size={13} color="var(--text-secondary)" />
                            <span>View</span>
                          </Link>

                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={(e) => handleDownload(e, doc)}
                            disabled={downloadingId === doc.id}
                            title="Stream authorized file"
                          >
                            <Download size={13} color="var(--text-secondary)" />
                            <span>{downloadingId === doc.id ? 'Streaming...' : 'Download'}</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="panel" style={{ textAlign: 'center', padding: '4rem 1.5rem' }}>
              <div style={{
                width: '48px',
                height: '48px',
                borderRadius: 'var(--radius-md)',
                backgroundColor: 'var(--bg-surface-secondary)',
                border: '1px solid var(--border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--text-muted)',
                margin: '0 auto 1rem',
              }}>
                <Lock size={24} />
              </div>
              <h3 style={{ fontSize: '1.0625rem', fontWeight: 600, color: 'var(--graphite)', marginBottom: '0.375rem' }}>
                No authorized documents found
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', maxWidth: '440px', margin: '0 auto 1.5rem', lineHeight: 1.5 }}>
                {searchTerm || selectedCategory !== 'all'
                  ? 'No documents matched your search filter in your authorized scope.'
                  : 'You have not uploaded any documents and no other document owners have granted you access yet.'}
              </p>
              <button className="btn btn-primary" onClick={() => setIsUploadOpen(true)}>
                <Plus size={15} color="var(--copper)" />
                <span>Upload your first document</span>
              </button>
            </div>
          )}
        </>
      )}

      {/* ================= TRASH / PURGED DOCUMENTS VIEW ================= */}
      {activeTab === 'trash' && (
        <>
          <div className="panel" style={{
            padding: '0.875rem 1.125rem',
            marginBottom: '1.25rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.875rem',
            backgroundColor: 'rgba(239, 68, 68, 0.05)',
            border: '1px solid rgba(239, 68, 68, 0.2)',
            borderRadius: 'var(--radius-md)',
          }}>
            <ShieldAlert size={20} color="var(--danger)" style={{ flexShrink: 0 }} />
            <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              <strong style={{ color: 'var(--danger)' }}>Confidential Shredding & Audit Preservation: </strong>
              When documents are deleted, their underlying binary objects are immediately and irreversibly shredded from private S3 object storage to prevent data leakage. Metadata and cryptographic audit trail records are retained for compliance and incident investigations.
            </div>
          </div>

          {isLoadingTrash ? (
            <div className="panel" style={{ textAlign: 'center', padding: '3.5rem', color: 'var(--text-muted)' }}>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
                <span className="pulse-dot" style={{ backgroundColor: 'var(--danger)', width: '10px', height: '10px' }}></span>
                <span style={{ fontSize: '0.875rem' }}>Loading deleted documents archive...</span>
              </div>
            </div>
          ) : trashedData?.documents && trashedData.documents.length > 0 ? (
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ width: '32%' }}>Document</th>
                    <th>Classification</th>
                    <th>Owner</th>
                    <th>Original Size</th>
                    <th>Deleted On</th>
                    <th>Storage State</th>
                    <th style={{ textAlign: 'right' }}>Audit Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {trashedData.documents.map((doc) => (
                    <tr key={doc.id}>
                      <td>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <FileText size={16} color="var(--text-muted)" />
                          <span style={{ textDecoration: 'line-through', color: 'var(--text-secondary)' }}>{doc.title}</span>
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.125rem', fontFamily: 'var(--font-mono)' }}>
                          {doc.original_filename}
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', alignItems: 'flex-start' }}>
                          <span className="badge badge-gray">{doc.category}</span>
                          {doc.classification && (
                            <span className="badge badge-secondary" style={{ fontSize: '0.675rem', padding: '0.1rem 0.35rem' }}>
                              {doc.classification}
                            </span>
                          )}
                        </div>
                      </td>
                      <td>
                        <div style={{ fontSize: '0.8125rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                          {doc.owner_name || 'Owner'}
                        </div>
                        <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>
                          {doc.owner_email}
                        </div>
                      </td>
                      <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                        {formatFileSize(doc.file_size)}
                      </td>
                      <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                          <Clock size={12} color="var(--text-muted)" />
                          <span>{doc.deleted_at ? new Date(doc.deleted_at).toLocaleString() : 'Deleted'}</span>
                        </div>
                      </td>
                      <td>
                        <span className="badge badge-danger" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', fontSize: '0.7rem' }}>
                          <Lock size={10} />
                          <span>Purged from Storage</span>
                        </span>
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleInspectAudit(doc)}
                          style={{ fontSize: '0.75rem', gap: '0.25rem' }}
                        >
                          <History size={13} color="var(--copper-dark)" />
                          <span>Inspect Audit</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="panel" style={{ textAlign: 'center', padding: '4rem 1.5rem' }}>
              <div style={{
                width: '48px',
                height: '48px',
                borderRadius: 'var(--radius-md)',
                backgroundColor: 'var(--bg-surface-secondary)',
                border: '1px solid var(--border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--text-muted)',
                margin: '0 auto 1rem',
              }}>
                <Trash2 size={24} />
              </div>
              <h3 style={{ fontSize: '1.0625rem', fontWeight: 600, color: 'var(--graphite)', marginBottom: '0.375rem' }}>
                No deleted documents
              </h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', maxWidth: '440px', margin: '0 auto', lineHeight: 1.5 }}>
                There are currently no soft-deleted documents in your authorized repository.
              </p>
            </div>
          )}
        </>
      )}

      {/* ================= TRASH AUDIT INSPECTION MODAL ================= */}
      {inspectingTrashedDoc && (
        <div className="modal-overlay" onClick={() => setInspectingTrashedDoc(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '650px', maxHeight: '85vh', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
              <div>
                <h3 style={{ fontSize: '1.125rem', fontWeight: 600, margin: 0, color: 'var(--graphite)' }}>
                  Audit Trail: {inspectingTrashedDoc.title}
                </h3>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: '0.25rem' }}>
                  ID: {inspectingTrashedDoc.id}
                </div>
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => setInspectingTrashedDoc(null)}
                style={{ padding: '0.25rem 0.5rem' }}
              >
                <X size={15} />
              </button>
            </div>

            <div style={{ marginBottom: '1rem', padding: '0.75rem', backgroundColor: 'var(--bg-surface-secondary)', borderRadius: 'var(--radius-sm)', fontSize: '0.8125rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.5rem' }}>
                <div><strong>Classification:</strong> {inspectingTrashedDoc.classification || 'Internal'}</div>
                <div><strong>Category:</strong> {inspectingTrashedDoc.category}</div>
                <div><strong>Owner:</strong> {inspectingTrashedDoc.owner_email || inspectingTrashedDoc.owner_id}</div>
                <div><strong>Deleted At:</strong> {inspectingTrashedDoc.deleted_at ? new Date(inspectingTrashedDoc.deleted_at).toLocaleString() : 'N/A'}</div>
              </div>
            </div>

            <h4 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Recorded Audit Events
            </h4>

            {isLoadingAudit ? (
              <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                Loading audit trail...
              </div>
            ) : docAuditEvents.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                {docAuditEvents.map((ev: any) => (
                  <div key={ev.id} style={{
                    padding: '0.75rem',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: ev.action === 'document.delete' ? 'rgba(239, 68, 68, 0.05)' : 'var(--bg-card)'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                      <span className={`badge ${ev.action === 'document.delete' ? 'badge-danger' : 'badge-copper'}`} style={{ fontSize: '0.75rem' }}>
                        {ev.action}
                      </span>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {new Date(ev.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.8125rem', color: 'var(--text-primary)', marginTop: '0.25rem' }}>
                      <strong>Actor:</strong> {ev.actor?.email || ev.actor_id || 'System'}
                      {ev.ip_address && <span style={{ marginLeft: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>IP: {ev.ip_address}</span>}
                    </div>
                    {ev.metadata && Object.keys(ev.metadata).length > 0 && (
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem', fontFamily: 'var(--font-mono)' }}>
                        {JSON.stringify(ev.metadata)}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
                No direct audit events found for this resource ID.
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1.25rem' }}>
              <button type="button" className="btn btn-secondary" onClick={() => setInspectingTrashedDoc(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ================= UPLOAD MODAL ================= */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onSuccess={() => refetch()}
      />
    </div>
  );
};
