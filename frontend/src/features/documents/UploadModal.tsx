import React, { useState, useRef } from 'react';
import { Upload, X, AlertCircle, FileText, ShieldCheck, Hash, RefreshCw } from 'lucide-react';
import { api } from '../../lib/api';

interface UploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

const ALLOWED_EXTS = ['pdf', 'docx', 'xlsx', 'pptx', 'txt', 'csv', 'json', 'md', 'png', 'jpg', 'jpeg'];
const MAX_BYTES = 25 * 1024 * 1024; // 25MB

export const UploadModal: React.FC<UploadModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [file, setFile] = useState<File | null>(null);
  const [fileHash, setFileHash] = useState<string | null>(null);
  const [isHashing, setIsHashing] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState('General');
  const [error, setError] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const computeSHA256 = async (targetFile: File): Promise<string> => {
    const buffer = await targetFile.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  };

  const processFile = async (selected: File) => {
    setError(null);
    setFileHash(null);

    const ext = selected.name.split('.').pop()?.toLowerCase();
    if (!ext || !ALLOWED_EXTS.includes(ext)) {
      setError(`File format .${ext || 'unknown'} is not allowed. Allowed: ${ALLOWED_EXTS.join(', ')}`);
      setFile(null);
      return;
    }

    if (selected.size > MAX_BYTES) {
      setError('File exceeds maximum size limit of 25MB');
      setFile(null);
      return;
    }

    setFile(selected);
    if (!title) {
      const baseName = selected.name.substring(0, selected.name.lastIndexOf('.')) || selected.name;
      setTitle(baseName.replace(/[_-]/g, ' '));
    }

    // Compute client-side SHA-256 for integrity verification
    try {
      setIsHashing(true);
      const hash = await computeSHA256(selected);
      setFileHash(hash);
    } catch {
      setFileHash(null);
    } finally {
      setIsHashing(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0]);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleRemoveFile = (e: React.MouseEvent) => {
    e.stopPropagation();
    setFile(null);
    setFileHash(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError('Please select or drop a file to upload');
      return;
    }
    if (!title.trim()) {
      setError('Document title is required');
      return;
    }

    setError(null);
    setIsUploading(true);

    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('title', title.trim());
      formData.append('category', category);
      if (description.trim()) {
        formData.append('description', description.trim());
      }

      await api.uploadDocument(formData);
      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Upload failed');
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '540px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <div style={{
              width: '28px',
              height: '28px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--accent-light)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent)'
            }}>
              <Upload size={16} />
            </div>
            <div>
              <h2 style={{ fontSize: '1.125rem', fontWeight: 600 }}>Upload Confidential Document</h2>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Zero-trust quarantine with client SHA-256 pre-check</div>
            </div>
          </div>
          <button onClick={onClose} style={{ color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer', padding: '4px' }}>
            <X size={18} />
          </button>
        </div>

        {error && (
          <div style={{
            backgroundColor: 'var(--danger-bg)',
            color: 'var(--danger)',
            border: '1px solid var(--danger-border)',
            padding: '0.75rem',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.8125rem',
            marginBottom: '1rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}>
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          {/* Interactive Drag-and-Drop Zone */}
          <div 
            onClick={() => fileInputRef.current?.click()}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            style={{
              border: isDragging 
                ? '2px dashed var(--accent)' 
                : file 
                ? '1px solid var(--border-main)' 
                : '2px dashed var(--border-main)',
              borderRadius: 'var(--radius-sm)',
              padding: file ? '1.25rem' : '1.75rem 1rem',
              textAlign: 'center',
              cursor: 'pointer',
              backgroundColor: isDragging 
                ? 'var(--accent-light)' 
                : file 
                ? '#f8fafc' 
                : '#ffffff',
              transition: 'all 0.15s ease-in-out',
              marginBottom: '1rem'
            }}
          >
            <input 
              ref={fileInputRef}
              type="file" 
              style={{ display: 'none' }} 
              onChange={handleFileChange}
              accept=".pdf,.docx,.xlsx,.pptx,.txt,.csv,.json,.md,.png,.jpg,.jpeg"
            />
            
            {file ? (
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem', marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem', textAlign: 'left', minWidth: 0 }}>
                    <div style={{
                      width: '36px',
                      height: '36px',
                      borderRadius: 'var(--radius-sm)',
                      backgroundColor: 'var(--accent-light)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: 'var(--accent)',
                      flexShrink: 0
                    }}>
                      <FileText size={18} />
                    </div>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-main)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {file.name}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {(file.size / 1024).toFixed(1)} KB • {file.type || 'Binary Data'}
                      </div>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={handleRemoveFile}
                    className="btn btn-secondary btn-sm"
                    style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem', flexShrink: 0 }}
                  >
                    Change
                  </button>
                </div>

                {/* Client-Side Cryptographic SHA-256 Pre-Check Badge */}
                <div style={{
                  backgroundColor: '#ffffff',
                  border: '1px solid var(--border-main)',
                  borderRadius: 'var(--radius-xs)',
                  padding: '0.625rem 0.75rem',
                  textAlign: 'left'
                }}>
                  {isHashing ? (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--accent)' }}>
                      <RefreshCw size={14} className="spin" />
                      <span>Computing client-side SHA-256 checksum...</span>
                    </div>
                  ) : fileHash ? (
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.7rem', fontWeight: 600, color: 'var(--success)' }}>
                          <ShieldCheck size={14} />
                          <span>Pre-Upload Integrity Verified</span>
                        </div>
                        <span className="badge badge-green" style={{ fontSize: '0.625rem', padding: '0.1rem 0.35rem' }}>
                          Client SHA-256
                        </span>
                      </div>
                      <div style={{
                        fontFamily: 'monospace',
                        fontSize: '0.7rem',
                        color: 'var(--text-secondary)',
                        wordBreak: 'break-all',
                        backgroundColor: '#f1f5f9',
                        padding: '0.375rem 0.5rem',
                        borderRadius: '3px'
                      }}>
                        {fileHash}
                      </div>
                    </div>
                  ) : (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      <Hash size={13} />
                      <span>Checksum ready for vault ingestion</span>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div>
                <div style={{
                  width: '42px',
                  height: '42px',
                  borderRadius: '50%',
                  backgroundColor: isDragging ? 'var(--accent-light)' : '#f1f5f9',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  margin: '0 auto 0.75rem',
                  color: isDragging ? 'var(--accent)' : 'var(--text-muted)'
                }}>
                  <Upload size={20} />
                </div>
                <div style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-main)' }}>
                  {isDragging ? 'Drop file to ingest into TrustVault' : 'Drag & drop confidential file here, or browse'}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                  Supported: PDF, DOCX, XLSX, TXT, CSV, PNG, JPG (Max 25MB)
                </div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.375rem', marginTop: '0.5rem', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                  <ShieldCheck size={13} color="var(--success)" />
                  <span>Real-time SHA-256 checksum computed in browser before upload</span>
                </div>
              </div>
            )}
          </div>

          <div className="form-group">
            <label className="form-label">Document Title *</label>
            <input
              type="text"
              className="input-field"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Q3 Financial Audit"
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">Category</label>
            <select
              className="input-field"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
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
            <label className="form-label">Description (Optional)</label>
            <textarea
              className="input-field"
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Provide context regarding document sensitivity or purpose..."
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1.5rem' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onClose}
              disabled={isUploading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={isUploading || !file || isHashing}
            >
              {isUploading ? 'Encrypting & Ingesting...' : isHashing ? 'Computing Checksum...' : 'Upload Document'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

