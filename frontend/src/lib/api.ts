import type { 
  User, 
  DocumentItem, 
  DocumentListResponse, 
  DocumentVersionItem,
  DocumentVersionListResponse,
  DocumentPermission, 
  AuditEvent, 
  AuditVerificationReport,
  AIRecommendationResult,
  UserSession,
  SecurityAlert,
  AccessRequest,
  AccessRequestCreate,
  AccessRequestApprove,
  AccessRequestReject,
  AccessRequestStatusCheck,
  RequestLinkCreate,
  RequestLinkCreatedResponse,
  RequestLinkListItem,
  RequestLinkResolved,
  RequestLinkSubmit,
  AdminSecurityAlert,
  SecurityAlertMetrics,
  SecurityAlertListResponse,
  BackupListResponse,
  RestoreVerificationReport,
  SecurityPolicy,
  SecurityPolicyUpdate,
  AccessReviewItem,
  AccessReviewListResponse,
  PolicySimulationRequest,
  PolicySimulationResponse,
  SystemStatusResponse,
  SystemSettingItem,
  BreakGlassRequest,
  BreakGlassResponse,
  AdminUserCreateRequest,
  AdminUserDetailResponse
} from '../types';

// Dynamically resolve API URL with automated protocol & domain handling for cloud hosting (Render/Vercel)
function resolveApiUrl(raw?: string): string {
  if (!raw) return '';
  let stripped = raw.trim().replace(/\/+$/, '');
  
  if (!stripped.startsWith('http://') && !stripped.startsWith('https://')) {
    // If Render passes an internal service name like "trustvault-api-s6ba" (no dot), append .onrender.com
    if (!stripped.includes('.') && !stripped.includes(':') && stripped !== 'localhost') {
      stripped = `${stripped}.onrender.com`;
    }
    return `https://${stripped}`;
  }
  
  try {
    const parsed = new URL(stripped);
    if (!parsed.hostname.includes('.') && parsed.hostname !== 'localhost') {
      parsed.hostname = `${parsed.hostname}.onrender.com`;
      return parsed.origin;
    }
  } catch {
    // fallback if malformed
  }
  return stripped;
}

const apiUrl = resolveApiUrl(import.meta.env.VITE_API_URL as string | undefined);
const API_BASE = apiUrl + '/api/v1';

export class ApiError extends Error {
  status: number;
  data: any;
  constructor(message: string, status: number, data?: any) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

export function getAuthToken(): string | null {
  return localStorage.getItem('trustvault_token');
}

export function setAuthToken(token: string) {
  localStorage.setItem('trustvault_token', token);
}

export function clearAuthToken() {
  localStorage.removeItem('trustvault_token');
  localStorage.removeItem('trustvault_user');
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = getAuthToken();
  const headers = new Headers(options.headers || {});

  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    clearAuthToken();
    if (window.location.pathname !== '/login' && window.location.pathname !== '/') {
      window.location.href = '/login?expired=true';
    }
    throw new ApiError('Session expired. Please sign in again.', 401);
  }

  if (response.status === 204) {
    return null as T;
  }

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    const errorMsg = data?.detail || response.statusText || 'Request failed';
    throw new ApiError(errorMsg, response.status, data);
  }

  return data as T;
}

export const api = {
  // Auth
  login: async (credentials: { email: string; password: string }) => {
    const res = await request<{ access_token: string; user_id: string; email: string; display_name: string; role: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
    setAuthToken(res.access_token);
    return res;
  },

  register: async (data: { email: string; password: string; display_name: string; role?: string }) => {
    return request<User>('/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  getCurrentUser: () => request<User>('/auth/me'),

  // Sessions
  listSessions: () => request<UserSession[]>('/auth/sessions'),
  revokeSession: (sessionId: string) =>
    request<void>(`/auth/sessions/${sessionId}`, {
      method: 'DELETE',
    }),
  revokeOtherSessions: () =>
    request<{ message: string; revoked_count: number }>('/auth/sessions?exclude_current=true', {
      method: 'DELETE',
    }),

  // Users
  listUsers: () => request<User[]>('/users'),
  listAllUsersAdmin: () => request<User[]>('/users/all'),
  updateUserRoleStatus: (userId: string, data: { role?: string; is_active?: boolean; display_name?: string }) =>
    request<User>(`/users/${userId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  // Documents
  listDocuments: (params: { 
    query?: string; 
    category?: string; 
    file_type?: string;
    owner_id?: string;
    date_from?: string;
    date_to?: string;
    permission_filter?: 'owned' | 'shared' | 'all';
    sort_by?: 'created_at' | 'title' | 'file_size';
    sort_order?: 'asc' | 'desc';
    admin_inventory?: boolean; 
    page?: number; 
    page_size?: number 
  }) => {
    const searchParams = new URLSearchParams();
    if (params.query) searchParams.append('query', params.query);
    if (params.category && params.category !== 'all') searchParams.append('category', params.category);
    if (params.file_type && params.file_type !== 'all') searchParams.append('file_type', params.file_type);
    if (params.owner_id && params.owner_id !== 'all') searchParams.append('owner_id', params.owner_id);
    if (params.date_from) searchParams.append('date_from', params.date_from);
    if (params.date_to) searchParams.append('date_to', params.date_to);
    if (params.permission_filter && params.permission_filter !== 'all') searchParams.append('permission_filter', params.permission_filter);
    if (params.sort_by) searchParams.append('sort_by', params.sort_by);
    if (params.sort_order) searchParams.append('sort_order', params.sort_order);
    if (params.admin_inventory) searchParams.append('admin_inventory', 'true');
    if (params.page) searchParams.append('page', params.page.toString());
    if (params.page_size) searchParams.append('page_size', params.page_size.toString());
    return request<DocumentListResponse>(`/documents?${searchParams.toString()}`);
  },

  listTrashedDocuments: (params?: {
    query?: string;
    category?: string;
    page?: number;
    page_size?: number;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.query) searchParams.append('query', params.query);
    if (params?.category && params.category !== 'all') searchParams.append('category', params.category);
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.page_size) searchParams.append('page_size', params.page_size.toString());
    const qs = searchParams.toString();
    return request<DocumentListResponse>(`/documents/trash${qs ? `?${qs}` : ''}`);
  },

  getDocument: (id: string) => request<DocumentItem>(`/documents/${id}`),

  uploadDocument: async (formData: FormData) => {
    return request<DocumentItem>('/documents/upload', {
      method: 'POST',
      body: formData,
    });
  },

  downloadDocument: async (id: string, originalFilename: string) => {
    const token = getAuthToken();
    const response = await fetch(`${API_BASE}/documents/${id}/download`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      if (response.status === 401) {
        clearAuthToken();
        if (window.location.pathname !== '/login' && window.location.pathname !== '/') {
          window.location.href = '/login?expired=true';
        }
        throw new ApiError('Session expired. Please sign in again.', 401);
      }
      if (response.status === 404 || response.status === 403) {
        throw new ApiError('Document not found or access has been revoked/expired.', response.status);
      }
      let errorMsg = 'Failed to download document';
      try {
        const errData = await response.json();
        if (errData.detail) errorMsg = errData.detail;
      } catch {
        /* ignore parse error */
      }
      throw new ApiError(errorMsg, response.status);
    }

    const blob = await response.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = originalFilename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(downloadUrl);
  },

  fetchDocumentBlob: async (id: string): Promise<Blob> => {
    const token = getAuthToken();
    const response = await fetch(`${API_BASE}/documents/${id}/download`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      if (response.status === 401) {
        clearAuthToken();
        if (window.location.pathname !== '/login' && window.location.pathname !== '/') {
          window.location.href = '/login?expired=true';
        }
        throw new ApiError('Session expired. Please sign in again.', 401);
      }
      if (response.status === 404 || response.status === 403) {
        throw new ApiError('Document not found or access has been revoked/expired.', response.status);
      }
      let errorMsg = 'Failed to fetch document content for preview';
      try {
        const errData = await response.json();
        if (errData.detail) errorMsg = errData.detail;
      } catch {
        /* ignore parse error */
      }
      throw new ApiError(errorMsg, response.status);
    }

    return response.blob();
  },

  updateDocumentMetadata: (id: string, data: { title?: string; description?: string; category?: string; classification?: string }) =>
    request<DocumentItem>(`/documents/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  deleteDocument: (id: string) =>
    request<void>(`/documents/${id}`, {
      method: 'DELETE',
    }),

  // Document Versions
  getDocumentVersions: (documentId: string) =>
    request<DocumentVersionListResponse>(`/documents/${documentId}/versions`),

  uploadDocumentVersion: async (documentId: string, formData: FormData) => {
    return request<DocumentVersionItem>(`/documents/${documentId}/versions`, {
      method: 'POST',
      body: formData,
    });
  },

  downloadDocumentVersion: async (documentId: string, versionId: string, originalFilename: string) => {
    const token = getAuthToken();
    const response = await fetch(`${API_BASE}/documents/${documentId}/versions/${versionId}/download`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      if (response.status === 401) {
        clearAuthToken();
        if (window.location.pathname !== '/login' && window.location.pathname !== '/') {
          window.location.href = '/login?expired=true';
        }
        throw new ApiError('Session expired. Please sign in again.', 401);
      }
      let errorMsg = 'Failed to download document version';
      try {
        const errData = await response.json();
        if (errData.detail) errorMsg = errData.detail;
      } catch {
        /* ignore parse error */
      }
      throw new ApiError(errorMsg, response.status);
    }

    const blob = await response.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = originalFilename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(downloadUrl);
  },

  restoreDocumentVersion: (documentId: string, versionId: string) =>
    request<DocumentVersionItem>(`/documents/${documentId}/versions/${versionId}/restore`, {
      method: 'POST',
    }),

  // Security Policies & Document Classification
  listSecurityPolicies: () =>
    request<SecurityPolicy[]>('/security-policies'),

  updateSecurityPolicy: (classification: string, data: SecurityPolicyUpdate) =>
    request<SecurityPolicy>(`/security-policies/${encodeURIComponent(classification)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  updateDocumentClassification: (documentId: string, classification: string, reason?: string) =>
    request<DocumentItem>(`/security-policies/documents/${documentId}/classification`, {
      method: 'PATCH',
      body: JSON.stringify({ classification, reason }),
    }),

  toggleUserMfa: (userId: string, enabled: boolean) =>
    request<{ user_id: string; mfa_enabled: boolean }>(`/security-policies/users/${userId}/mfa?enabled=${enabled}`, {
      method: 'PATCH',
    }),

  // Periodic Access Reviews
  listAccessReviews: (params?: { status_filter?: string; document_id?: string; all_org?: boolean }) => {
    const searchParams = new URLSearchParams();
    if (params?.status_filter && params.status_filter !== 'all') searchParams.append('status_filter', params.status_filter);
    if (params?.document_id) searchParams.append('document_id', params.document_id);
    if (params?.all_org) searchParams.append('all_org', 'true');
    return request<AccessReviewListResponse>(`/access-reviews?${searchParams.toString()}`);
  },

  generateAccessReviews: (forceAllActive?: boolean) => {
    return request<{ message: string; created_count: number }>(`/access-reviews/generate${forceAllActive ? '?force_all_active=true' : ''}`, {
      method: 'POST',
    });
  },

  submitAccessReviewDecision: (reviewId: string, data: { decision: 'retain' | 'revoke'; decision_notes?: string }) => {
    return request<AccessReviewItem>(`/access-reviews/${reviewId}/decision`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  // Access Policy Simulator
  simulatePolicy: (data: PolicySimulationRequest) =>
    request<PolicySimulationResponse>('/policy-simulator/simulate', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Permissions
  getDocumentPermissions: (documentId: string, includeRevoked: boolean = true) =>
    request<DocumentPermission[]>(`/documents/${documentId}/permissions?include_revoked=${includeRevoked}`),

  grantPermission: (documentId: string, data: { email?: string; user_id?: string; permission_level: 'read' | 'edit'; expires_at?: string }) =>
    request<DocumentPermission>(`/documents/${documentId}/permissions`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  revokePermission: (documentId: string, userId: string) =>
    request<void>(`/documents/${documentId}/permissions/${userId}`, {
      method: 'DELETE',
    }),

  // Audit
  listAuditEvents: (params: { document_id?: string; action?: string; outcome?: string; resource_type?: string; date_from?: string; date_to?: string; page?: number; page_size?: number } = {}) => {
    const searchParams = new URLSearchParams();
    if (params.document_id) searchParams.append('document_id', params.document_id);
    if (params.action) searchParams.append('action', params.action);
    if (params.outcome) searchParams.append('outcome', params.outcome);
    if (params.resource_type) searchParams.append('resource_type', params.resource_type);
    if (params.date_from) searchParams.append('date_from', params.date_from);
    if (params.date_to) searchParams.append('date_to', params.date_to);
    if (params.page) searchParams.append('page', params.page.toString());
    if (params.page_size) searchParams.append('page_size', params.page_size.toString());
    return request<{ total: number; events: AuditEvent[] }>(`/audit/events?${searchParams.toString()}`);
  },

  verifyAuditIntegrity: () => request<AuditVerificationReport>('/audit/verify'),

  exportAuditLog: async (params: { format: 'csv' | 'json'; action?: string; outcome?: string; date_from?: string; date_to?: string; document_id?: string }) => {
    const searchParams = new URLSearchParams();
    searchParams.append('format', params.format);
    if (params.action) searchParams.append('action', params.action);
    if (params.outcome) searchParams.append('outcome', params.outcome);
    if (params.document_id) searchParams.append('document_id', params.document_id);
    if (params.date_from) searchParams.append('date_from', params.date_from);
    if (params.date_to) searchParams.append('date_to', params.date_to);

    const token = getAuthToken();
    const response = await fetch(`${API_BASE}/audit/export?${searchParams.toString()}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      let errorMsg = 'Failed to export audit log';
      try {
        const errData = await response.json();
        if (errData.detail) errorMsg = errData.detail;
      } catch {
        /* ignore parse error */
      }
      throw new ApiError(errorMsg, response.status);
    }

    const blob = await response.blob();
    const filename = `trustvault_audit_${new Date().toISOString().slice(0, 10)}.${params.format}`;
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(downloadUrl);
  },

  // Notifications / Security Alerts
  listNotifications: (unreadOnly: boolean = false) =>
    request<SecurityAlert[]>(`/notifications?unread_only=${unreadOnly}`),

  getUnreadNotificationCount: () =>
    request<{ unread_count: number }>('/notifications/unread-count'),

  markNotificationRead: (id: string) =>
    request<SecurityAlert>(`/notifications/${id}/read`, {
      method: 'PATCH',
    }),

  markAllNotificationsRead: () =>
    request<{ message: string; marked_count: number }>('/notifications/mark-all-read', {
      method: 'POST',
    }),

  // AI Access Recommendations
  requestAIRecommendations: (documentId: string) =>
    request<{ suggestion_id: string; recommendations: AIRecommendationResult }>(`/documents/${documentId}/ai-recommendations`, {
      method: 'POST',
    }),

  approveAIRecommendations: (documentId: string, data: { suggestion_id: string; approved_grants: Array<{ user_id: string; permission_level: 'read' | 'edit' }>; decision_notes?: string }) =>
    request<DocumentPermission[]>(`/documents/${documentId}/ai-recommendations/approve`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  rejectAIRecommendations: (documentId: string, data: { suggestion_id: string; rejection_reason?: string }) =>
    request<{ status: string; suggestion_id: string }>(`/documents/${documentId}/ai-recommendations/reject`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Secure Document Access Request Workflow
  createAccessRequest: (data: AccessRequestCreate) =>
    request<AccessRequest>('/access-requests', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  getMyAccessRequests: () =>
    request<AccessRequest[]>('/access-requests/my'),

  getIncomingAccessRequests: (statusFilter?: string) =>
    request<AccessRequest[]>(statusFilter ? `/access-requests/incoming?status_filter=${statusFilter}` : '/access-requests/incoming'),

  getAccessRequestStatus: (documentId: string) =>
    request<AccessRequestStatusCheck>(`/access-requests/status/${documentId}`),

  getAccessRequestDetails: (requestId: string) =>
    request<AccessRequest>(`/access-requests/${requestId}`),

  approveAccessRequest: (requestId: string, data: AccessRequestApprove) =>
    request<AccessRequest>(`/access-requests/${requestId}/approve`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  rejectAccessRequest: (requestId: string, data: AccessRequestReject) =>
    request<AccessRequest>(`/access-requests/${requestId}/reject`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  cancelAccessRequest: (requestId: string) =>
    request<AccessRequest>(`/access-requests/${requestId}/cancel`, {
      method: 'POST',
    }),

  createDocumentRequestLink: (documentId: string, data: RequestLinkCreate) =>
    request<RequestLinkCreatedResponse>(`/access-requests/links/${documentId}`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  getDocumentRequestLinks: (documentId: string) =>
    request<RequestLinkListItem[]>(`/access-requests/links/${documentId}`),

  revokeDocumentRequestLink: (linkId: string) =>
    request<{ message: string }>(`/access-requests/links/${linkId}/revoke`, {
      method: 'POST',
    }),

  resolveRequestLink: (token: string) =>
    request<RequestLinkResolved>(`/access-requests/resolve-link/${token}`),

  submitAccessRequestViaLink: (token: string, data: RequestLinkSubmit) =>
    request<AccessRequest>(`/access-requests/submit-via-link/${token}`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  listSecurityAlerts: (params?: { severity?: string; status?: string; event_type?: string; skip?: number; limit?: number }) => {
    const q = new URLSearchParams();
    if (params?.severity) q.append('severity', params.severity);
    if (params?.status) q.append('status', params.status);
    if (params?.event_type) q.append('event_type', params.event_type);
    if (params?.skip !== undefined) q.append('skip', String(params.skip));
    if (params?.limit !== undefined) q.append('limit', String(params.limit));
    const qs = q.toString();
    return request<SecurityAlertListResponse>(qs ? `/alerts?${qs}` : '/alerts');
  },

  getSecurityAlertMetrics: () =>
    request<SecurityAlertMetrics>('/alerts/metrics'),

  getSecurityAlertDetails: (alertId: string) =>
    request<AdminSecurityAlert>(`/alerts/${alertId}`),

  acknowledgeSecurityAlert: (alertId: string) =>
    request<AdminSecurityAlert>(`/alerts/${alertId}/acknowledge`, {
      method: 'POST',
    }),

  resolveSecurityAlert: (alertId: string, resolutionNotes: string) =>
    request<AdminSecurityAlert>(`/alerts/${alertId}/resolve`, {
      method: 'POST',
      body: JSON.stringify({ resolution_notes: resolutionNotes }),
    }),

  revokeUserSessionsForAlert: (alertId: string) =>
    request<{ revoked_sessions_count: number; message: string }>(`/alerts/${alertId}/revoke-sessions`, {
      method: 'POST',
    }),

  listBackups: () =>
    request<BackupListResponse>('/backups'),

  createBackup: () =>
    request<{ backup_id: string; message: string; filename: string; size_bytes: number; created_at: string }>('/backups/create', {
      method: 'POST',
    }),

  verifyBackupHealth: (backupId: string) =>
    request<RestoreVerificationReport>(`/backups/${backupId}/verify`, {
      method: 'POST',
    }),

  // Full Administrative Control & Break-Glass
  getSystemStatus: () => request<SystemStatusResponse>('/admin/system-status'),

  listSystemSettings: () => request<SystemSettingItem[]>('/admin/settings'),

  updateSystemSetting: (key: string, value: string) =>
    request<SystemSettingItem>(`/admin/settings/${encodeURIComponent(key)}`, {
      method: 'PATCH',
      body: JSON.stringify({ value }),
    }),

  listBreakGlassAccesses: () => request<BreakGlassResponse[]>('/admin/break-glass'),

  activateBreakGlass: (data: BreakGlassRequest) =>
    request<BreakGlassResponse>('/admin/break-glass', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  revokeBreakGlass: (id: string) =>
    request<BreakGlassResponse>(`/admin/break-glass/${id}/revoke`, {
      method: 'POST',
    }),

  reviewBreakGlass: (id: string, reviewNotes: string) =>
    request<BreakGlassResponse>(`/admin/break-glass/${id}/review`, {
      method: 'POST',
      body: JSON.stringify({ review_notes: reviewNotes }),
    }),

  createAdminUser: (data: AdminUserCreateRequest) =>
    request<User>('/users', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  getAdminUserDetail: (userId: string) =>
    request<AdminUserDetailResponse>(`/users/${userId}`),

  listUserSessionsAdmin: (userId: string) =>
    request<UserSession[]>(`/users/${userId}/sessions`),

  revokeAllUserSessionsAdmin: (userId: string) =>
    request<{ message: string; revoked_count: number }>(`/users/${userId}/sessions`, {
      method: 'DELETE',
    }),

  restoreBackup: (backupId: string, data: { confirmation: string; password: string }) =>
    request<{ success: boolean; backup_id: string; restored_files_count: number; message: string }>(`/backups/${backupId}/restore`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
};
