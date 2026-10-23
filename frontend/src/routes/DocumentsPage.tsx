import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { FileText, Plus, Search, Filter, Download, Eye, Lock, ShieldCheck, Database } from 'lucide-react';
import { api } from '../lib/api';
import { useToast } from '../context/ToastContext';
import { UploadModal } from '../features/documents/UploadModal';
import type { DocumentItem } from '../types';

export const DocumentsPage: React.FC = () => {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['documents', searchTerm, selectedCategory],
    queryFn: () => api.listDocuments({
      query: searchTerm || undefined,
      category: selectedCategory !== 'all' ? selectedCategory : undefined,
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
      {/* Top Page Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-main)' }}>
            Confidential Documents
          </h1>
          <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
            Authorized document repository with strict row-level access control.
          </p>
        </div>

        <button
          className="btn btn-primary"
          onClick={() => setIsUploadOpen(true)}
        >
          <Plus size={16} />
          <span>Upload Document</span>
        </button>
      </div>

      {/* Enterprise Security Metrics Bar */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '0.875rem',
        marginBottom: '1.5rem'
      }}>
        <div className="panel" style={{ padding: '0.875rem 1rem', display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
          <div style={{
            width: '38px',
            height: '38px',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'var(--accent-light)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--accent)',
            flexShrink: 0
          }}>
            <FileText size={20} />
          </div>
          <div>
            <div style={{ fontSize: '0.7rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
              Confidential Assets
            </div>
            <div style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-main)', lineHeight: 1.2 }}>
              {isLoading ? '...' : (data?.documents?.length ?? 0)}
            </div>
            <div style={{ fontSize: '0.725rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Authorized in your scope
            </div>
          </div>
        </div>

        <div className="panel" style={{ padding: '0.875rem 1rem', display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
          <div style={{
            width: '38px',
            height: '38px',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'var(--success-bg)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--success)',
            flexShrink: 0
          }}>
            <ShieldCheck size={20} />
          </div>
          <div>
            <div style={{ fontSize: '0.7rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
              Access Enforcement
            </div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-main)', lineHeight: 1.2, display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <span>Zero-Trust RLS</span>
              <span className="badge badge-green" style={{ fontSize: '0.65rem', padding: '0.1rem 0.4rem' }}>Enforced</span>
            </div>
            <div style={{ fontSize: '0.725rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Strict owner & tenant bounds
            </div>
          </div>
        </div>

        <div className="panel" style={{ padding: '0.875rem 1rem', display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
          <div style={{
            width: '38px',
            height: '38px',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'var(--bg-surface-secondary)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--text-main)',
            flexShrink: 0
          }}>
            <Database size={20} />
          </div>
          <div>
            <div style={{ fontSize: '0.7rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
              Ledger Provenance
            </div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-main)', lineHeight: 1.2, display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <span>SHA-256 Chained</span>
              <span className="badge badge-blue" style={{ fontSize: '0.65rem', padding: '0.1rem 0.4rem' }}>Immutable</span>
            </div>
            <div style={{ fontSize: '0.725rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Deterministic tamper audit
            </div>
          </div>
        </div>

        <div className="panel" style={{ padding: '0.875rem 1rem', display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
          <div style={{
            width: '38px',
            height: '38px',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: '#faf5ff',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#7e22ce',
            flexShrink: 0
          }}>
            <Lock size={20} />
          </div>
          <div>
            <div style={{ fontSize: '0.7rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
              Data Loss Prevention
            </div>
            <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-main)', lineHeight: 1.2, display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
              <span>Forensic DLP</span>
              <span className="badge badge-gray" style={{ fontSize: '0.65rem', padding: '0.1rem 0.4rem', backgroundColor: '#f3e8ff', color: '#6b21a8' }}>Active</span>
            </div>
            <div style={{ fontSize: '0.725rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Dynamic watermark tracking
            </div>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="panel" style={{ padding: '0.875rem 1rem', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, minWidth: '240px' }}>
            <Search size={16} color="var(--text-muted)" />
            <input
              type="text"
              className="input-field"
              placeholder="Search documents by title or description..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ border: 'none', padding: '0.25rem 0', boxShadow: 'none' }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Filter size={15} color="var(--text-muted)" />
            <select
              className="input-field"
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              style={{ width: 'auto', padding: '0.375rem 0.75rem' }}
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
        </div>
      </div>

      {/* Documents Table */}
      {isLoading ? (
        <div className="panel" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
          <div>Loading authorized documents...</div>
        </div>
      ) : data?.documents && data.documents.length > 0 ? (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Category</th>
                <th>Owner</th>
                <th>Size</th>
                <th>Uploaded</th>
                <th>Access Level</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {data.documents.map((doc) => (
                <tr key={doc.id}>
                  <td>
                    <Link
                      to={`/documents/${doc.id}`}
                      style={{ fontWeight: 600, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                    >
                      <FileText size={16} color="var(--accent)" />
                      <span>{doc.title}</span>
                    </Link>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.125rem' }}>
                      {doc.original_filename}
                    </div>
                  </td>
                  <td>
                    <span className="badge badge-gray">{doc.category}</span>
                  </td>
                  <td>
                    <div style={{ fontSize: '0.8125rem', fontWeight: 500 }}>{doc.owner_name}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{doc.owner_email}</div>
                  </td>
                  <td style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
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
                        ? 'badge-blue'
                        : 'badge-gray'
                    }`} style={{ textTransform: 'capitalize' }}>
                      {doc.effective_permission === 'owner' ? 'Owner' : `${doc.effective_permission} Access`}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '0.5rem' }}>
                      <Link
                        to={`/documents/${doc.id}`}
                        className="btn btn-secondary btn-sm"
                        title="View details & sharing settings"
                      >
                        <Eye size={14} />
                        <span>View</span>
                      </Link>

                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={(e) => handleDownload(e, doc)}
                        disabled={downloadingId === doc.id}
                        title="Stream authorized file"
                      >
                        <Download size={14} />
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
        <div className="panel" style={{ textAlign: 'center', padding: '3.5rem 1rem' }}>
          <div style={{ color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
            <Lock size={32} style={{ margin: '0 auto' }} />
          </div>
          <h3 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.25rem' }}>
            No authorized documents found
          </h3>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', maxWidth: '400px', margin: '0 auto 1.25rem' }}>
            {searchTerm || selectedCategory !== 'all'
              ? 'No documents matched your search filter.'
              : 'You have not uploaded any documents and no other document owners have granted you access yet.'}
          </p>
          <button className="btn btn-primary btn-sm" onClick={() => setIsUploadOpen(true)}>
            <Plus size={14} />
            <span>Upload your first document</span>
          </button>
        </div>
      )}

      {/* Upload Modal */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onSuccess={() => refetch()}
      />
    </div>
  );
};
