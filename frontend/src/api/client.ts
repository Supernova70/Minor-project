import axios from 'axios';
import type {
  Email,
  EmailDetail,
  Scan,
  HealthStatus,
  FetchEmailsResponse,
} from '../types';

// ─── Axios Instance ───────────────────────────────────────────────────────────

export const apiClient = axios.create({
  baseURL: 'http://127.0.0.1:8080',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.code === 'ECONNREFUSED' || error.code === 'ERR_NETWORK') {
      return Promise.reject(new Error('BACKEND_OFFLINE'));
    }
    return Promise.reject(error);
  }
);

// ─── Health ───────────────────────────────────────────────────────────────────

export const getHealth = async (): Promise<HealthStatus> => {
  const { data } = await apiClient.get<HealthStatus>('/health');
  return data;
};

// ─── Emails ───────────────────────────────────────────────────────────────────

export const getEmails = async (skip = 0, limit = 50): Promise<Email[]> => {
  const { data } = await apiClient.get<{ total: number; emails: Email[] }>('/emails', {
    params: { skip, limit },
  });
  return data.emails ?? [];
};

export const getEmail = async (id: number): Promise<EmailDetail> => {
  const { data } = await apiClient.get<EmailDetail>(`/emails/${id}`);
  return data;
};

export const fetchEmails = async (limit = 20): Promise<FetchEmailsResponse> => {
  const { data } = await apiClient.post<FetchEmailsResponse>(
    `/emails/fetch?limit=${limit}`
  );
  return data;
};

// ─── Scans ────────────────────────────────────────────────────────────────────

export const getScans = async (skip = 0, limit = 50): Promise<Scan[]> => {
  const { data } = await apiClient.get<{ total: number; scans: Scan[] }>('/scans', {
    params: { skip, limit },
  });
  return data.scans ?? [];
};

export const getScan = async (id: number): Promise<Scan> => {
  const { data } = await apiClient.get<Scan>(`/scans/${id}`);
  return data;
};

export const runScan = async (emailId: number): Promise<Scan> => {
  const { data } = await apiClient.post<Scan>(`/scans/${emailId}`);
  return data;
};

// ─── Backend status check ─────────────────────────────────────────────────────

export const checkBackendOnline = async (): Promise<boolean> => {
  try {
    await apiClient.get('/health', { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
};
