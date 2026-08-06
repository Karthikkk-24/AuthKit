import axios from 'axios';

/**
 * Browser calls go through the same-origin BFF proxy (`/api/backend/...`)
 * so the JWT stays in an httpOnly cookie and is never readable by JS (#24).
 * Server-side / direct Nest URL remains available via BACKEND_API_URL.
 */
const BROWSER_BASE = '/api/backend';
const SERVER_BASE =
  process.env.BACKEND_API_URL ??
  process.env.NEXT_PUBLIC_API_URL ??
  'http://localhost:3000/api/v1';

function resolveBase(): string {
  return typeof window === 'undefined' ? SERVER_BASE : BROWSER_BASE;
}

/**
 * Lightweight fetch-based API client used by TanStack Query hooks.
 * Relies on the BFF proxy attaching the Authorization header from the
 * httpOnly session cookie — no localStorage token (#24, #28).
 */
export async function apiClient<T = unknown>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  const res = await fetch(`${resolveBase()}${path}`, {
    ...options,
    headers,
    credentials: 'same-origin',
  });

  if (res.status === 401) {
    if (typeof window !== 'undefined') window.location.href = '/login';
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ message: res.statusText }));
    throw new Error(
      Array.isArray(err.message) ? err.message.join(', ') : (err.message ?? 'Request failed'),
    );
  }

  // 204 / empty body
  if (res.status === 204) return undefined as T;

  const contentType = res.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) return res.json();
  return res.text() as unknown as T;
}

export const api = axios.create({
  // Client-only callers; BFF keeps the JWT in an httpOnly cookie (#24).
  baseURL: BROWSER_BASE,
  withCredentials: true,
});

// ── Auth ──────────────────────────────────────────────────────────────
export const authApi = {
  /** BFF login — sets httpOnly cookies; never exposes the JWT to JS (#24). */
  login: (email: string, password: string, mfaCode?: string) =>
    fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ email, password, mfaCode }),
    }).then(async (r) => {
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        const err: any = new Error(data.message ?? 'Login failed');
        err.response = { data };
        throw err;
      }
      return data;
    }),
  logout: () =>
    fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'same-origin',
    }).then((r) => r.json().catch(() => ({ ok: true }))),
  me: () => api.get('/users/me').then((r) => r.data),
};

// ── Metrics ───────────────────────────────────────────────────────────
export const metricsApi = {
  dashboard: () => api.get('/metrics/dashboard').then((r) => r.data),
  userGrowth: (days = 30) =>
    api.get(`/metrics/user-growth?days=${days}`).then((r) => r.data),
  eventTimeline: (days = 7) =>
    api.get(`/metrics/event-timeline?days=${days}`).then((r) => r.data),
};

// ── Users ─────────────────────────────────────────────────────────────
export const usersApi = {
  list: (params?: { search?: string; page?: number; limit?: number }) =>
    api.get('/users', { params }).then((r) => r.data),
  get: (id: string) => api.get(`/users/${id}`).then((r) => r.data),
  lock: (id: string, reason: string) =>
    api.post(`/users/${id}/lock`, { reason }).then((r) => r.data),
  unlock: (id: string) => api.post(`/users/${id}/unlock`).then((r) => r.data),
  assignRole: (id: string, roleId: string) =>
    api.patch(`/users/${id}/role`, { roleId }).then((r) => r.data),
  delete: (id: string) => api.delete(`/users/${id}`).then((r) => r.data),
};

// ── RBAC ──────────────────────────────────────────────────────────────
export const rbacApi = {
  getRoles: () => api.get('/rbac/roles').then((r) => r.data),
  getPermissions: () => api.get('/rbac/permissions').then((r) => r.data),
  createRole: (data: { name: string; description?: string }) =>
    api.post('/rbac/roles', data).then((r) => r.data),
  updateRole: (id: string, data: Record<string, unknown>) =>
    api.patch(`/rbac/roles/${id}`, data).then((r) => r.data),
  deleteRole: (id: string) => api.delete(`/rbac/roles/${id}`).then((r) => r.data),
  /** Role-owned permission rows — send action/resource pairs (#33, #28). */
  assignPermissions: (
    roleId: string,
    permissions: Array<{ action: string; resource: string }>,
  ) =>
    api
      .patch(`/rbac/roles/${roleId}/permissions`, { permissions })
      .then((r) => r.data),
};

// ── Audit ─────────────────────────────────────────────────────────────
export const auditApi = {
  query: (params?: Record<string, unknown>) =>
    api.get('/audit', { params }).then((r) => r.data),
  exportCsv: (params?: Record<string, unknown>) =>
    api.get('/audit/export', { params, responseType: 'text' }).then((r) => r.data),
};

// ── Webhooks ──────────────────────────────────────────────────────────
export const webhooksApi = {
  list: () => api.get('/webhooks/endpoints').then((r) => r.data),
  create: (data: { url: string; events: string[] }) =>
    api.post('/webhooks/endpoints', data).then((r) => r.data),
  toggle: (id: string, isActive: boolean) =>
    api.patch(`/webhooks/endpoints/${id}/toggle`, { isActive }).then((r) => r.data),
  rotateSecret: (id: string) =>
    api.post(`/webhooks/endpoints/${id}/rotate-secret`).then((r) => r.data),
  delete: (id: string) => api.delete(`/webhooks/endpoints/${id}`).then((r) => r.data),
};

// ── Admin config (#29) ────────────────────────────────────────────────
export const configApi = {
  get: () => apiClient<Record<string, unknown>>('/admin/config'),
  update: (patch: Record<string, unknown>) =>
    apiClient<{ message: string; config: Record<string, unknown> }>('/admin/config', {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),
};
