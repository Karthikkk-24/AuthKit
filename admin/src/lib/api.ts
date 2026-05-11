import axios from 'axios';

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:3000/api/v1';

/**
 * Lightweight fetch-based API client used by TanStack Query hooks.
 * Automatically attaches the JWT token stored in localStorage.
 */
export async function apiClient<T = unknown>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const token = typeof window !== 'undefined' ? localStorage.getItem('ak_token') : null;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${BASE_URL}${path}`, { ...options, headers });

  if (res.status === 401) {
    if (typeof window !== 'undefined') window.location.href = '/login';
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ message: res.statusText }));
    throw new Error(err.message ?? 'Request failed');
  }

  const contentType = res.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) return res.json();
  return res.text() as unknown as T;
}

export const api = axios.create({
  baseURL: BASE_URL,
  withCredentials: true,
});

// Attach JWT from localStorage
api.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('ak_token');
    if (token) config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// ── Auth ──────────────────────────────────────────────────────────────
export const authApi = {
  login: (email: string, password: string) =>
    api.post('/auth/login', { email, password }).then((r) => r.data),
  logout: () => api.post('/auth/logout').then((r) => r.data),
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
  createRole: (data: any) => api.post('/rbac/roles', data).then((r) => r.data),
  updateRole: (id: string, data: any) =>
    api.patch(`/rbac/roles/${id}`, data).then((r) => r.data),
  assignPermissions: (roleId: string, permissionIds: string[]) =>
    api.patch(`/rbac/roles/${roleId}/permissions`, { permissionIds }).then((r) => r.data),
};

// ── Audit ─────────────────────────────────────────────────────────────
export const auditApi = {
  query: (params?: Record<string, any>) =>
    api.get('/audit', { params }).then((r) => r.data),
};

// ── Webhooks ──────────────────────────────────────────────────────────
export const webhooksApi = {
  list: () => api.get('/webhooks/endpoints').then((r) => r.data),
  create: (data: any) => api.post('/webhooks/endpoints', data).then((r) => r.data),
  toggle: (id: string, isActive: boolean) =>
    api.patch(`/webhooks/endpoints/${id}/toggle`, { isActive }).then((r) => r.data),
  rotateSecret: (id: string) =>
    api.post(`/webhooks/endpoints/${id}/rotate-secret`).then((r) => r.data),
  delete: (id: string) => api.delete(`/webhooks/endpoints/${id}`).then((r) => r.data),
};
