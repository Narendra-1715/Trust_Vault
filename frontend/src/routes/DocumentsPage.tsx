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
  ArrowUpDown
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

      {/* ================= DOCUMENTS TABLE ================= */}
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
                    <span className="badge badge-gray">{doc.category}</span>
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

      {/* ================= UPLOAD MODAL ================= */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onSuccess={() => refetch()}
      />
    </div>
  );
};
