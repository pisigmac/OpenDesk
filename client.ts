/**
 * Typed client for PiSigma Auth Service (FastAPI / Python backend).
 *
 * Usage:
 *   const auth = new PisigmaAuth({ baseUrl: 'http://127.0.0.1:8090' })
 *   const result = await auth.login({ email: 'user@example.com', password: 'secret' })
 */

export type AuthClientOptions = {
  baseUrl: string
  apiKey?: string
  fetch?: typeof fetch
}

export type ClientResult<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; error: string; detail?: unknown }

export type TokenResponse = {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

export type UserOut = {
  id: string
  email: string
  display_name: string | null
  is_platform_admin: boolean
  orgs: Array<{ id: string; name: string; role: string; workspace_id: string | null }>
  grants: Array<{ audience: string; role: string }>
}

export type RegisterInput = {
  email: string
  password: string
  display_name?: string
  bootstrap_token?: string
}

export type RegisterResponse = {
  access_token?: string
  refresh_token?: string
  token_type?: string
  expires_in?: number
  verification_required: boolean
}

export type LoginInput = {
  email: string
  password: string
}

export type VerifyEmailInput = {
  token: string
}

export type ForgotPasswordInput = {
  email: string
}

export type ResetPasswordInput = {
  token: string
  password: string
}

export type GrantRequest = {
  user_id: string
  audience: string
  role: string
}

export type AuditLogResponse = {
  total: number
  offset: number
  limit: number
  events: Array<Record<string, unknown>>
}

export class PisigmaAuth {
  private baseUrl: string
  private apiKey?: string
  private fetchFn: typeof fetch

  constructor(opts: AuthClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, '')
    this.apiKey = opts.apiKey
    this.fetchFn = opts.fetch || fetch
  }

  private headers(token?: string): Record<string, string> {
    const h: Record<string, string> = { 'Content-Type': 'application/json' }
    const bearer = token || this.apiKey
    if (bearer) h['Authorization'] = `Bearer ${bearer}`
    return h
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    token?: string,
  ): Promise<ClientResult<T>> {
    const res = await this.fetchFn(`${this.baseUrl}${path}`, {
      method,
      headers: this.headers(token),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
    const json = (await res.json().catch(() => ({}))) as Record<string, unknown>
    if (!res.ok) {
      return {
        ok: false,
        status: res.status,
        error: String(json.detail || json.error || res.statusText),
        detail: json.detail,
      }
    }
    return { ok: true, data: json as T }
  }

  async checkHealth(): Promise<ClientResult<{ status: string; service: string }>> {
    return this.request('GET', '/health')
  }

  async register(input: RegisterInput): Promise<ClientResult<RegisterResponse>> {
    return this.request('POST', '/v1/auth/register', input)
  }

  async login(input: LoginInput): Promise<ClientResult<TokenResponse>> {
    return this.request('POST', '/v1/auth/login', input)
  }

  async refresh(refreshToken: string): Promise<ClientResult<TokenResponse>> {
    return this.request('POST', '/v1/auth/refresh', { refresh_token: refreshToken })
  }

  async logout(refreshToken: string): Promise<ClientResult<{ ok: boolean }>> {
    return this.request('POST', '/v1/auth/logout', { refresh_token: refreshToken })
  }

  async me(token: string): Promise<ClientResult<UserOut>> {
    return this.request('GET', '/v1/auth/me', undefined, token)
  }

  async verifyEmail(input: VerifyEmailInput): Promise<ClientResult<{ ok: boolean; email?: string }>> {
    return this.request('POST', '/v1/auth/verify-email', input)
  }

  async forgotPassword(input: ForgotPasswordInput): Promise<ClientResult<{ ok: boolean }>> {
    return this.request('POST', '/v1/auth/forgot-password', input)
  }

  async resetPassword(input: ResetPasswordInput): Promise<ClientResult<{ ok: boolean }>> {
    return this.request('POST', '/v1/auth/reset-password', input)
  }

  async exportMyData(token: string): Promise<ClientResult<Record<string, unknown>>> {
    return this.request('GET', '/v1/me/export', undefined, token)
  }

  async deleteMyAccount(token: string): Promise<ClientResult<{ ok: boolean }>> {
    return this.request('POST', '/v1/me/delete', undefined, token)
  }

  async updateProfile(
    token: string,
    input: { display_name?: string; email?: string },
  ): Promise<ClientResult<UserOut>> {
    return this.request('PATCH', '/v1/auth/me', input, token)
  }

  async changePassword(
    token: string,
    input: { current_password: string; new_password: string },
  ): Promise<ClientResult<{ ok: boolean }>> {
    return this.request('POST', '/v1/auth/me/change-password', input, token)
  }

  async listSessions(token: string): Promise<ClientResult<Array<Record<string, unknown>>>> {
    return this.request('GET', '/v1/auth/me/sessions', undefined, token)
  }

  async revokeSession(token: string, sessionId: string): Promise<ClientResult<{ ok: boolean }>> {
    return this.request('DELETE', `/v1/auth/me/sessions/${sessionId}`, undefined, token)
  }

  async revokeAllSessions(token: string): Promise<ClientResult<{ ok: boolean; revoked: number }>> {
    return this.request('DELETE', '/v1/auth/me/sessions', undefined, token)
  }

  async listUsers(
    token: string,
    params: { q?: string; limit?: number; offset?: number } = {},
  ): Promise<ClientResult<{ total: number; offset: number; limit: number; users: UserOut[] }>> {
    const qs = new URLSearchParams()
    if (params.q) qs.set('q', params.q)
    if (params.limit !== undefined) qs.set('limit', String(params.limit))
    if (params.offset !== undefined) qs.set('offset', String(params.offset))
    const query = qs.toString() ? `?${qs}` : ''
    return this.request('GET', `/v1/admin/users${query}`, undefined, token)
  }

  async listOrgs(token: string): Promise<ClientResult<Array<{ id: string; name: string; role: string; workspace_id: string | null }>>> {
    return this.request('GET', '/v1/orgs', undefined, token)
  }

  async createOrg(token: string, name: string): Promise<ClientResult<{ id: string; name: string; role: string; workspace_id: string | null }>> {
    return this.request('POST', '/v1/orgs', { name }, token)
  }

  async listOrgMembers(token: string, orgId: string): Promise<ClientResult<{ members: Array<Record<string, unknown>> }>> {
    return this.request('GET', `/v1/orgs/${orgId}/members`, undefined, token)
  }

  async addOrgMember(
    token: string,
    orgId: string,
    input: { user_id: string; role?: string; workspace_id?: string },
  ): Promise<ClientResult<{ ok: boolean }>> {
    return this.request('POST', `/v1/orgs/${orgId}/members`, input, token)
  }

  async removeOrgMember(token: string, orgId: string, userId: string): Promise<ClientResult<{ ok: boolean }>> {
    return this.request('DELETE', `/v1/orgs/${orgId}/members/${userId}`, undefined, token)
  }

  async deleteOrg(token: string, orgId: string): Promise<ClientResult<{ ok: boolean }>> {
    return this.request('DELETE', `/v1/orgs/${orgId}`, undefined, token)
  }

  async setUserActive(
    token: string,
    userId: string,
    isActive: boolean,
  ): Promise<ClientResult<{ ok: boolean; user_id: string; is_active: boolean }>> {
    return this.request('PATCH', `/v1/admin/users/${userId}/active`, { is_active: isActive }, token)
  }

  async setGrant(token: string, input: GrantRequest): Promise<ClientResult<{ ok: boolean }>> {
    return this.request('POST', '/v1/admin/grants', input, token)
  }

  async queryAuditLog(
    token: string,
    params: { action?: string; actor_id?: string; resource_type?: string; limit?: number; offset?: number },
  ): Promise<ClientResult<AuditLogResponse>> {
    const qs = new URLSearchParams()
    if (params.action) qs.set('action', params.action)
    if (params.actor_id) qs.set('actor_id', params.actor_id)
    if (params.resource_type) qs.set('resource_type', params.resource_type)
    if (params.limit !== undefined) qs.set('limit', String(params.limit))
    if (params.offset !== undefined) qs.set('offset', String(params.offset))
    const query = qs.toString() ? `?${qs}` : ''
    return this.request('GET', `/v1/admin/audit${query}`, undefined, token)
  }
}
