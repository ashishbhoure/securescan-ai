/**
 * SecureScan AI - Frontend API Client
 */

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000/api/v1';

export class ApiClient {
  private getToken(): string | null {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('securescan_token');
    }
    return null;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const token = this.getToken();
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const errorJson = await response.json().catch(() => ({}));
      throw new Error(errorJson.message || `Request failed with status ${response.status}`);
    }

    return response.json();
  }

  // Auth
  public async login(email: string, password: string) {
    const res = await this.request<{ token: string; user: any; organization: any }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    if (typeof window !== 'undefined') {
      localStorage.setItem('securescan_token', res.token);
    }
    return res;
  }

  public async register(email: string, password: string, name: string, organizationName?: string) {
    const res = await this.request<{ token: string; user: any; organization: any }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, name, organizationName }),
    });
    if (typeof window !== 'undefined') {
      localStorage.setItem('securescan_token', res.token);
    }
    return res;
  }

  public async getMe() {
    return this.request<{ user: any; currentTenant: any; organizations: any[] }>('/auth/me');
  }

  public logout() {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('securescan_token');
      window.location.href = '/login';
    }
  }

  // Stats & Dashboard
  public async getStats() {
    return this.request<{ metrics: any }>('/organizations/stats');
  }

  // Assets
  public async getAssets() {
    return this.request<{ assets: any[] }>('/assets');
  }

  public async createAsset(targetUrl: string, type = 'WEBSITE') {
    return this.request<{ asset: any }>('/assets', {
      method: 'POST',
      body: JSON.stringify({ targetUrl, type }),
    });
  }

  public async authorizeAsset(assetId: string) {
    return this.request<{ message: string; asset: any }>(`/assets/${assetId}/authorize`, {
      method: 'POST',
      body: JSON.stringify({ confirmedOwnership: true }),
    });
  }

  // Scans
  public async getScans() {
    return this.request<{ scans: any[] }>('/scans');
  }

  public async getScan(id: string) {
    return this.request<{ scan: any }>(`/scans/${id}`);
  }

  public async triggerScan(assetId: string) {
    return this.request<{ message: string; scan: any }>('/scans', {
      method: 'POST',
      body: JSON.stringify({ assetId }),
    });
  }

  // Findings
  public async getFindings(filters: { severity?: string; status?: string; search?: string } = {}) {
    const params = new URLSearchParams();
    if (filters.severity) params.set('severity', filters.severity);
    if (filters.status) params.set('status', filters.status);
    if (filters.search) params.set('search', filters.search);

    const query = params.toString() ? `?${params.toString()}` : '';
    return this.request<{ findings: any[] }>(`/findings${query}`);
  }

  public async getFinding(id: string) {
    return this.request<{ finding: any }>(`/findings/${id}`);
  }

  public async updateFindingStatus(id: string, status: string, justification?: string) {
    return this.request<{ finding: any }>(`/findings/${id}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, justification }),
    });
  }

  // AI Analyst
  public async explainFinding(id: string) {
    return this.request<{ analysis: any }>(`/ai/findings/${id}/explain`, {
      method: 'POST',
    });
  }

  public async askSecurityAI(question: string) {
    return this.request<{ qna: any }>('/ai/qna', {
      method: 'POST',
      body: JSON.stringify({ question }),
    });
  }

  // Reports
  public async generateReport(scanId: string) {
    return this.request<{ report: any }>('/reports', {
      method: 'POST',
      body: JSON.stringify({ scanId }),
    });
  }
}

export const api = new ApiClient();
