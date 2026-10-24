export interface User {
  id: string;
  email: string;
  display_name: string;
  role: 'admin' | 'owner' | 'viewer';
  is_active: boolean;
  mfa_enabled?: boolean;
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
  classification?: 'Internal' | 'Confidential' | 'Highly Restricted' | string;
  created_at: string;
  updated_at: string;
  effective_permission: 'owner' | 'edit' | 'read' | 'admin' | 'none';
  current_version_number?: number;
  version_count?: number;
}

export interface DocumentVersionItem {
  id: string;
  document_id: string;
  version_number: number;
  original_filename: string;
  file_size: number;
  checksum: string;
  detected_media_type: string;
  change_summary?: string;
  uploaded_by?: string;
  uploader_name?: string;
  uploader_email?: string;
  is_current: boolean;
  created_at: string;
}

export interface DocumentVersionListResponse {
  total: number;
  versions: DocumentVersionItem[];
}

export interface SecurityPolicy {
  id: string;
  classification: 'Internal' | 'Confidential' | 'Highly Restricted' | string;
  allow_download: boolean;
  allow_sharing: boolean;
  max_grant_duration_days?: number | null;
  require_mfa: boolean;
  elevated_classification_change: boolean;
  created_at: string;
  updated_at: string;
}

export interface SecurityPolicyUpdate {
  allow_download?: boolean;
  allow_sharing?: boolean;
  max_grant_duration_days?: number | null;
  require_mfa?: boolean;
  elevated_classification_change?: boolean;
}

export interface AccessReviewItem {
  id: string;
  document_id: string;
  document_title: string;
  permission_id: string;
  grantee_id: string;
  grantee_email: string;
  grantee_name: string;
  permission_level: 'read' | 'edit';
  grant_created_at: string;
  grant_expires_at?: string;
  reviewer_id: string;
  reviewer_email?: string;
  status: 'pending' | 'retained' | 'revoked';
  due_date: string;
  is_overdue: boolean;
  decision?: 'retain' | 'revoke';
  decided_at?: string;
  decision_notes?: string;
  next_review_due?: string;
  created_at: string;
}

export interface AccessReviewListResponse {
  total: number;
  pending_count: number;
  overdue_count: number;
  reviews: AccessReviewItem[];
}

export interface RuleEvaluationResult {
  name: string;
  rule: string;
  passed: boolean;
  details: string;
}

export interface PolicySimulationRequest {
  document_id: string;
  recipient_email?: string;
  recipient_user_id?: string;
  permission_level: 'read' | 'edit';
  proposed_expiry?: string | null;
}

export interface PolicySimulationResponse {
  status: 'allowed' | 'denied' | 'additional_requirements_needed';
  is_allowed: boolean;
  summary: string;
  document_id: string;
  document_title: string;
  classification: string;
  proposed_permission: string;
  recipient_email?: string;
  current_permission_level?: string;
  evaluated_rules: RuleEvaluationResult[];
  failures: string[];
  remediation?: string | null;
  simulated_at: string;
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

export interface AdminSecurityAlert {
  id: string;
  event_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'investigating' | 'resolved';
  timestamp: string;
  actor_id?: string;
  actor_name?: string;
  actor_email?: string;
  target_user_id?: string;
  target_user_email?: string;
  target_document_id?: string;
  target_document_title?: string;
  session_id?: string;
  request_id?: string;
  summary: string;
  investigation_metadata: Record<string, any>;
  acknowledged_at?: string;
  acknowledged_by?: string;
  acknowledged_by_name?: string;
  resolved_at?: string;
  resolved_by?: string;
  resolved_by_name?: string;
  resolution_notes?: string;
  created_at: string;
  updated_at: string;
}

export interface SecurityAlertMetrics {
  total_alerts: number;
  open_alerts: number;
  critical_alerts: number;
  investigating_alerts: number;
  resolved_alerts: number;
}

export interface SecurityAlertListResponse {
  total: number;
  alerts: AdminSecurityAlert[];
}

export interface BackupItem {
  backup_id: string;
  filename: string;
  size_bytes: number;
  created_at: string;
  alembic_version?: string;
  total_documents: number;
  total_object_bytes: number;
  table_counts: Record<string, number>;
  is_encrypted: boolean;
  verified: boolean;
}

export interface BackupListResponse {
  total: number;
  backups: BackupItem[];
}

export interface RestoreVerificationReport {
  is_valid: boolean;
  backup_id: string;
  created_at?: string;
  alembic_version?: string;
  app_version?: string;
  total_documents: number;
  objects_verified: number;
  missing_objects: string[];
  corrupt_objects: Array<{ storage_key: string; expected_sha256: string; actual_sha256: string }>;
  orphan_objects: string[];
  database_records_verified: Record<string, number>;
  audit_chain_valid: boolean;
  audit_total_events: number;
  rto_seconds: number;
  errors: string[];
}

export interface SystemStatusResponse {
  status: string;
  database: {
    status: string;
    active_connections: number;
    engine: string;
  };
  storage: {
    status: string;
    backend: string;
    total_documents: number;
    total_bytes: number;
  };
  background_jobs: {
    latest_backup_id?: string | null;
    latest_backup_at?: string | null;
    latest_backup_verified?: boolean | null;
    access_reviews_pending: number;
    access_reviews_overdue: number;
  };
  security_configuration: {
    classification_policies_count: number;
    open_security_alerts: number;
    critical_security_alerts: number;
    mfa_enforced_for_admins: boolean;
  };
  users_count: number;
  active_sessions_count: number;
  server_time: string;
}

export interface SystemSettingItem {
  key: string;
  value: string;
  description?: string;
  updated_at: string;
  updated_by?: string;
}

export interface BreakGlassRequest {
  document_id: string;
  justification: string;
  duration_minutes: number;
  password: string;
}

export interface BreakGlassResponse {
  id: string;
  admin_id: string;
  admin_email?: string;
  admin_name?: string;
  document_id: string;
  document_title?: string;
  justification: string;
  status: 'active' | 'expired' | 'revoked';
  expires_at: string;
  created_at: string;
  revoked_at?: string | null;
  reviewed_at?: string | null;
  reviewed_by?: string | null;
  reviewer_name?: string | null;
  review_notes?: string | null;
}

export interface AdminUserCreateRequest {
  email: string;
  password: string;
  display_name: string;
  role: 'admin' | 'owner' | 'viewer';
  is_active?: boolean;
  mfa_enabled?: boolean;
}

export interface AdminUserDetailResponse {
  id: string;
  email: string;
  display_name: string;
  role: string;
  is_active: boolean;
  mfa_enabled: boolean;
  created_at: string;
  updated_at: string;
  active_sessions_count: number;
  last_active_at?: string | null;
}


