import type { 
  User, 
  DocumentItem, 
  DocumentListResponse, 
  DocumentPermission, 
  AuditEvent, 
  AuditVerificationReport,
  AIRecommendationResult,
  UserSession,
  SecurityAlert
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

  updateDocumentMetadata: (id: string, data: { title?: string; description?: string; category?: string }) =>
    request<DocumentItem>(`/documents/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  deleteDocument: (id: string) =>
    request<void>(`/documents/${id}`, {
      method: 'DELETE',
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
  listAuditEvents: (params: { document_id?: string; action?: string; outcome?: string; resource_type?: string; page?: number; page_size?: number } = {}) => {
    const searchParams = new URLSearchParams();
    if (params.document_id) searchParams.append('document_id', params.document_id);
    if (params.action) searchParams.append('action', params.action);
    if (params.outcome) searchParams.append('outcome', params.outcome);
    if (params.resource_type) searchParams.append('resource_type', params.resource_type);
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
};
