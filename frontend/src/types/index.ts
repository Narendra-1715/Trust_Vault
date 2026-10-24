export interface User {
  id: string;
  email: string;
  display_name: string;
  role: 'admin' | 'owner' | 'viewer';
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface AuthState {
  user: User | null;
  token: string | null;
}

export interface DocumentItem {
  id: string;
  owner_id: string;
  owner_email?: string;
  owner_name?: string;
  title: string;
  description?: string;
  original_filename: string;
  detected_media_type: string;
  file_size: number;
  checksum: string;
  category: string;
  created_at: string;
  updated_at: string;
  effective_permission: 'owner' | 'edit' | 'read' | 'admin' | 'none';
}

export interface DocumentListResponse {
  total: number;
  page: number;
  page_size: number;
  documents: DocumentItem[];
}

export interface DocumentPermission {
  id: string;
  document_id: string;
  user_id: string;
  user_email: string;
  user_display_name: string;
  permission_level: 'read' | 'edit';
  granted_by?: string;
  granted_by_email?: string;
  granted_at: string;
  updated_at: string;
  revoked_at?: string;
  expires_at?: string;
  is_expired?: boolean;
  status?: 'active' | 'expired' | 'revoked';
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  actor_id?: string;
  actor_email?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  outcome: 'success' | 'denied' | 'failure';
  request_id?: string;
  structured_metadata: Record<string, any>;
  previous_event_hash: string;
  event_hash: string;
}

export interface AuditVerificationReport {
  is_valid: boolean;
  total_events: number;
  tampered_event_id?: string;
  event_index?: number;
  error_reason?: string;
  verified_at_event_id?: string;
}

export interface SuggestedGrant {
  user_id: string;
  email: string;
  display_name: string;
  permission_level: 'read' | 'edit';
  confidence: number;
  rationale: string;
}

export interface AIRecommendationResult {
  document_id: string;
  document_title: string;
  category: string;
  provider_model: string;
  is_mock: boolean;
  explanation: string;
  suggestions: SuggestedGrant[];
}

export interface UserSession {
  id: string;
  user_id: string;
  ip_address?: string;
  user_agent?: string;
  device_info?: string;
  created_at: string;
  last_active_at: string;
  expires_at: string;
  is_current: boolean;
  is_active: boolean;
}

export interface SecurityAlert {
  id: string;
  user_id: string;
  title: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  event_type: string;
  resource_id?: string;
  created_at: string;
  read_at?: string;
  is_read: boolean;
}

export interface AccessRequest {
  id: string;
  document_id: string;
  document_title?: string;
  requester_id: string;
  requester_email?: string;
  requester_name?: string;
  owner_id: string;
  owner_email?: string;
  owner_name?: string;
  reason: string;
  status: 'pending' | 'approved' | 'rejected' | 'cancelled' | 'expired';
  requested_permission: 'read' | 'edit';
  requested_expiry?: string;
  approved_permission?: 'read' | 'edit';
  approved_expiry?: string;
  rejection_reason?: string;
  decided_by?: string;
  decided_by_name?: string;
  decided_at?: string;
  cancelled_at?: string;
  created_at: string;
  updated_at: string;
}

export interface AccessRequestCreate {
  document_id: string;
  reason: string;
  requested_permission?: 'read' | 'edit';
  requested_expiry?: string;
}

export interface AccessRequestApprove {
  approved_permission: 'read' | 'edit';
  approved_expiry?: string;
}

export interface AccessRequestReject {
  rejection_reason?: string;
}

export interface AccessRequestStatusCheck {
  has_pending_request: boolean;
  request_id?: string;
  created_at?: string;
  requested_permission?: string;
  requested_expiry?: string;
}

export interface RequestLinkCreate {
  name?: string;
  expires_at?: string;
  max_uses?: number;
}

export interface RequestLinkCreatedResponse {
  id: string;
  document_id: string;
  document_title: string;
  token: string;
  token_prefix: string;
  name?: string;
  expires_at?: string;
  max_uses?: number;
  use_count: number;
  created_at: string;
}

export interface RequestLinkListItem {
  id: string;
  document_id: string;
  token_prefix: string;
  name?: string;
  expires_at?: string;
  max_uses?: number;
  use_count: number;
  revoked_at?: string;
  is_active: boolean;
  created_at: string;
}

export interface RequestLinkResolved {
  link_id: string;
  token_prefix: string;
  document_id: string;
  document_title: string;
  category?: string;
  owner_id: string;
  owner_name: string;
  owner_email: string;
  is_valid: boolean;
  already_has_access: boolean;
  has_pending_request: boolean;
  pending_request_id?: string;
}

export interface RequestLinkSubmit {
  reason: string;
  requested_permission?: 'read' | 'edit';
  requested_expiry?: string;
}
