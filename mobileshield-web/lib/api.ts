import { AnalysisError, CLIENT_REQUEST_TIMEOUT_MS, parseAnalysisResponse, validateMessageRequest } from './analysis';
import type { MessageRequest, MessageResponse } from './analysis';

export type Verdict = 'safe' | 'suspicious' | 'malicious';
export type Confidence = 'low' | 'medium' | 'high';

export interface AnalysisResponse {
  scan_id: number;
  normalized_url: string;
  domain: string;
  final_url: string | null;
  resolved_url?: string | null;
  resolved_domain?: string | null;
  redirect_hops: number;
  risk_score: number;
  status?: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';
  verdict: Verdict;
  confidence: Confidence;
  reasons: string[];
  risk_reasons?: string[];
  is_shortener?: boolean;
  signals: Record<string, unknown>;
  breakdown: { key: string; points: number; description: string }[];
  reputation?: string;
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export type AuthUser = { id?: number | string; email?: string; created_at?: string };
export type LoginResponse = { access_token: string; user?: AuthUser; api_key?: string };
export type RegisterResponse = { access_token: string; user?: AuthUser; api_key?: string };

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ||
  process.env.NEXT_PUBLIC_API_BASE ||
  'http://localhost:8000';

let cachedAuthToken: string | null = null;
let cachedApiKey: string | null = null;

export const getAuthToken = (): string | null => {
  if (cachedAuthToken) return cachedAuthToken;
  if (typeof window === 'undefined') return null;
  const val = localStorage.getItem('jwt');
  cachedAuthToken = val;
  return val;
};

export const setAuthToken = (token: string | null) => {
  cachedAuthToken = token;
  if (typeof window !== 'undefined') {
    if (token) localStorage.setItem('jwt', token);
    else localStorage.removeItem('jwt');
  }
};

export const getApiKey = (): string | null => {
  if (cachedApiKey) return cachedApiKey;
  if (typeof window === 'undefined') return null;
  const val = localStorage.getItem('manual_api_key');
  cachedApiKey = val || null;
  return cachedApiKey;
};

export const setApiKey = (key: string | null) => {
  cachedApiKey = key;
  if (typeof window !== 'undefined') {
    if (key) localStorage.setItem('manual_api_key', key);
    else localStorage.removeItem('manual_api_key');
  }
};

const makeRequestId = () => {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
  return `req_${Math.random().toString(16).slice(2)}`;
};

const buildHeaders = (extra?: Record<string, string>) => {
  const h: Record<string, string> = { 'Content-Type': 'application/json', ...(extra || {}) };
  const token = getAuthToken();
  const key = getApiKey();
  if (token) h['Authorization'] = `Bearer ${token}`;
  else if (key) h['X-API-Key'] = key;
  h['X-Request-Id'] = makeRequestId();
  return h;
};

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: buildHeaders(init?.headers as Record<string, string>),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new ApiError(text || res.statusText, res.status);
  }
  if (res.headers.get('Content-Type')?.includes('application/json')) {
    return (await res.json()) as T;
  }
  return (await res.text()) as unknown as T;
}

export async function analyzeUrl(url: string): Promise<AnalysisResponse> {
  return apiFetch<AnalysisResponse>('/v1/analyze', {
    method: 'POST',
    body: JSON.stringify({ url }),
  });
}

/** Public, ephemeral scan path: unrelated saved account credentials stay private. */
export async function analyzeMessage(input: MessageRequest, signal: AbortSignal): Promise<MessageResponse> {
  const payload = validateMessageRequest(input);
  if (signal.aborted) throw new AnalysisError('cancelled');
  const controller = new AbortController();
  let timedOut = false;
  const cancel = () => controller.abort();
  signal.addEventListener('abort', cancel, { once: true });
  let stopRequest!: () => void;
  const stopped = new Promise<never>((_resolve, reject) => {
    stopRequest = () => reject(new AnalysisError(timedOut ? 'timeout' : 'cancelled'));
    controller.signal.addEventListener('abort', stopRequest, { once: true });
  });
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, CLIENT_REQUEST_TIMEOUT_MS);
  try {
    const operation = (async () => {
      const res = await fetch(`${API_BASE}/v1/analyze-message`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload), signal: controller.signal,
        credentials: 'omit', cache: 'no-store',
      });
      if (!res.ok) {
        const code = res.status === 429 ? 'rate_limit_exceeded'
          : res.status === 503 ? 'analysis_unavailable'
          : res.status === 413 || res.status === 422 ? 'invalid_request' : 'request_failed';
        throw new AnalysisError(code);
      }
      if (!res.headers.get('Content-Type')?.toLowerCase().includes('application/json')) {
        throw new AnalysisError('invalid_response');
      }
      let value: unknown;
      try { value = await res.json(); } catch { throw new AnalysisError('invalid_response'); }
      return parseAnalysisResponse(value);
    })();
    return await Promise.race([operation, stopped]);
  } catch (error) {
    if (error instanceof AnalysisError) throw error;
    if (controller.signal.aborted) throw new AnalysisError(timedOut ? 'timeout' : 'cancelled');
    throw new AnalysisError('network_error');
  } finally {
    clearTimeout(timer);
    signal.removeEventListener('abort', cancel);
    controller.signal.removeEventListener('abort', stopRequest);
  }
}

export async function downloadReport(scanId: number): Promise<Blob> {
  const res = await fetch(`${API_BASE}/v1/scans/${scanId}/report.pdf`, {
    method: 'GET',
    headers: buildHeaders(),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new ApiError(text || res.statusText, res.status);
  }
  return res.blob();
}

export async function checkHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) return false;
    const data = await res.json();
    return Boolean(data?.ok);
  } catch {
    return false;
  }
}

export async function authRegister(email: string, password: string): Promise<RegisterResponse> {
  return apiFetch<RegisterResponse>('/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}

export async function authLogin(email: string, password: string): Promise<LoginResponse> {
  return apiFetch<LoginResponse>('/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
}
