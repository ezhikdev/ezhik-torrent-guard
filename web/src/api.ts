import { signal } from './state';

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

let csrf = '';
export const session = signal<{ username: string; version: string } | null | undefined>(undefined);

export const csrfToken = () => csrf;

export function setCsrf(token: string) {
  csrf = token;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') headers['X-CSRF-Token'] = csrf;
  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, 'Панель недоступна. Проверьте соединение.');
  }
  if (response.status === 401 && !path.startsWith('/api/auth/login')) {
    session.set(null);
  }
  const text = await response.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!response.ok) {
    const detail = data?.detail;
    const message = typeof detail === 'string' ? detail : Array.isArray(detail) ? detail.map((d) => d.msg).join('; ') : `Ошибка ${response.status}`;
    throw new ApiError(response.status, message);
  }
  return data as T;
}

export const api = {
  get: <T = any>(path: string) => request<T>('GET', path),
  post: <T = any>(path: string, body: unknown = {}) => request<T>('POST', path, body),
  put: <T = any>(path: string, body: unknown) => request<T>('PUT', path, body),
  patch: <T = any>(path: string, body: unknown) => request<T>('PATCH', path, body),
  del: <T = any>(path: string) => request<T>('DELETE', path),
};

export async function loadSession() {
  try {
    const me = await api.get<{ username: string; csrf: string; version: string }>('/api/auth/me');
    setCsrf(me.csrf);
    session.set({ username: me.username, version: me.version });
  } catch {
    session.set(null);
  }
}

export async function login(username: string, password: string) {
  const result = await api.post<{ username: string; csrf: string }>('/api/auth/login', { username, password });
  setCsrf(result.csrf);
  await loadSession();
}

export async function logout() {
  try {
    await api.post('/api/auth/logout');
  } finally {
    session.set(null);
  }
}
