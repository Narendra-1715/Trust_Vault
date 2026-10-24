import { useEffect, useRef, useState, useCallback } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useAuth } from '../auth/AuthContext';
import { useToast } from '../../context/ToastContext';
import { apiUrl, getAuthToken } from '../../lib/api';

export function useLiveWebSocket() {
  const { isAuthenticated, user } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [isConnected, setIsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pingIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const backoffRef = useRef<number>(1000);

  const getWsUrl = useCallback((token: string) => {
    let wsUrl: string;
    if (!apiUrl) {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      wsUrl = `${proto}//${window.location.host}/api/v1/ws`;
    } else {
      const base = apiUrl.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:');
      wsUrl = `${base}/api/v1/ws`;
    }
    return `${wsUrl}?token=${encodeURIComponent(token)}`;
  }, []);

  const connect = useCallback(() => {
    if (!isAuthenticated) return;
    const token = getAuthToken();
    if (!token) return;

    // Prevent duplicate connections
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    try {
      const targetUrl = getWsUrl(token);
      const ws = new WebSocket(targetUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        backoffRef.current = 1000; // Reset backoff on success

        // Keep connection warm with periodic heartbeat ping
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
        pingIntervalRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            try {
              ws.send('ping');
            } catch {
              // ignore
            }
          }
        }, 25000);
      };

      ws.onmessage = (event) => {
        if (event.data === 'pong') return;
        try {
          const payload = JSON.parse(event.data);
          const { type, data } = payload;

          switch (type) {
            case 'NOTIFICATION_RECEIVED': {
              const sev = data?.severity?.toLowerCase();
              const title = data?.title || 'Notification';
              const body = data?.message || '';
              const displayMsg = body ? `${title}: ${body}` : title;

              if (sev === 'critical' || sev === 'danger') {
                toast.error(displayMsg);
              } else {
                toast.info(displayMsg);
              }

              // Invalidate notifications cache immediately
              queryClient.invalidateQueries({ queryKey: ['unreadNotificationCount'] });
              queryClient.invalidateQueries({ queryKey: ['notifications'] });
              break;
            }

            case 'SECURITY_ALERT_CREATED': {
              const summary = data?.summary || 'New high-priority security alert detected!';
              toast.error(`[SECURITY ALERT] ${summary}`);

              // Invalidate central alert queries for admins
              queryClient.invalidateQueries({ queryKey: ['securityAlertMetricsNav'] });
              queryClient.invalidateQueries({ queryKey: ['securityAlerts'] });
              queryClient.invalidateQueries({ queryKey: ['securityAlertMetrics'] });
              queryClient.invalidateQueries({ queryKey: ['unreadNotificationCount'] });
              queryClient.invalidateQueries({ queryKey: ['notifications'] });
              break;
            }

            case 'ACCESS_REQUEST_CREATED': {
              const reqName = data?.requester_name || 'A user';
              const docTitle = data?.document_title || 'your document';
              const perm = data?.permission || 'access';
              toast.info(`${reqName} requested ${perm} permission for "${docTitle}"`);

              // Immediately invalidate incoming access requests cache
              queryClient.invalidateQueries({ queryKey: ['incomingRequests'] });
              queryClient.invalidateQueries({ queryKey: ['unreadNotificationCount'] });
              queryClient.invalidateQueries({ queryKey: ['notifications'] });
              break;
            }

            case 'ACCESS_REQUEST_DECIDED': {
              const isApproved = data?.status === 'approved';
              const docTitle = data?.document_title || 'Document';
              if (isApproved) {
                toast.success(`Access Request Approved: You now have access to "${docTitle}"`);
              } else {
                toast.info(`Access Request Declined for "${docTitle}"`);
              }

              // Invalidate my access requests and available documents list
              queryClient.invalidateQueries({ queryKey: ['myAccessRequests'] });
              queryClient.invalidateQueries({ queryKey: ['documents'] });
              queryClient.invalidateQueries({ queryKey: ['unreadNotificationCount'] });
              queryClient.invalidateQueries({ queryKey: ['notifications'] });
              break;
            }

            default:
              break;
          }
        } catch {
          // Non-JSON message, ignore
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        if (pingIntervalRef.current) {
          clearInterval(pingIntervalRef.current);
          pingIntervalRef.current = null;
        }

        // Auto reconnect with exponential backoff if user is still logged in
        if (isAuthenticated) {
          const timeout = Math.min(backoffRef.current, 15000);
          backoffRef.current = Math.min(backoffRef.current * 1.5, 15000);
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, timeout);
        }
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch {
      setIsConnected(false);
    }
  }, [isAuthenticated, user?.role, getWsUrl, toast, queryClient]);

  useEffect(() => {
    if (isAuthenticated) {
      connect();
    } else {
      setIsConnected(false);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    }

    return () => {
      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current);
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [isAuthenticated, connect]);

  return { isConnected };
}
