import React, { useState, useRef } from 'react';
import { Upload, X, AlertCircle, FileText } from 'lucide-react';
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
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState('General');
  const [error, setError] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setError(null);
    if (e.target.files && e.target.files[0]) {
      const selected = e.target.files[0];
      const ext = selected.name.split('.').pop()?.toLowerCase();
      
      if (!ext || !ALLOWED_EXTS.includes(ext)) {
        setError(`File format .${ext} is not allowed. Allowed: ${ALLOWED_EXTS.join(', ')}`);
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
        // Default title to filename without extension
        const baseName = selected.name.substring(0, selected.name.lastIndexOf('.')) || selected.name;
        setTitle(baseName.replace(/[_-]/g, ' '));
      }
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a file to upload');
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
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Upload size={18} />
            <h2 style={{ fontSize: '1.125rem', fontWeight: 600 }}>Upload Confidential Document</h2>
          </div>
          <button onClick={onClose} style={{ color: 'var(--text-muted)' }}>
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
          {/* File Picker Zone */}
          <div 
            onClick={() => fileInputRef.current?.click()}
            style={{
              border: '2px dashed var(--border-main)',
              borderRadius: 'var(--radius-sm)',
              padding: '1.5rem',
              textAlign: 'center',
              cursor: 'pointer',
              backgroundColor: file ? '#f8fafc' : '#ffffff',
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
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                <FileText size={20} color="var(--accent)" />
                <div style={{ textAlign: 'left' }}>
                  <div style={{ fontWeight: 600, fontSize: '0.875rem' }}>{file.name}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {(file.size / 1024).toFixed(1)} KB
                  </div>
                </div>
              </div>
            ) : (
              <div>
                <Upload size={24} style={{ color: 'var(--text-muted)', margin: '0 auto 0.5rem' }} />
                <div style={{ fontSize: '0.875rem', fontWeight: 500 }}>Click to browse or drop file here</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                  Allowed: PDF, DOCX, XLSX, TXT, CSV (Max 25MB)
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
              disabled={isUploading || !file}
            >
              {isUploading ? 'Encrypting & Storing...' : 'Upload Document'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
