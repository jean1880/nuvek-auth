import { ref, shallowRef, type App, type Plugin } from 'vue'
import { Auth0Client, type User } from '@auth0/auth0-spa-js'
import {
  AUTH_KEY,
  getCurrentAuth,
  safeReturnTo,
  setCurrentAuth,
  type AuthContext,
  type AuthPublicConfig,
  type NuvekAuthConfig,
} from './useAuth'

/** Fetch the public auth config from the backend. Throws on a non-2xx response. */
export async function loadAuthConfig(url = '/api/auth/config'): Promise<AuthPublicConfig> {
  const res = await fetch(url, { headers: { Accept: 'application/json' } })
  if (!res.ok) throw new Error(`auth config request failed: ${res.status}`)
  return (await res.json()) as AuthPublicConfig
}

function decodePayload(token: string): Record<string, unknown> {
  try {
    const part = token.split('.')[1]
    if (!part) return {}
    const b64 = part.replace(/-/g, '+').replace(/_/g, '/')
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4)
    const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0))
    return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>
  } catch {
    return {}
  }
}

/**
 * Permissions from the `permissions` claim only, matching the server. `scope` is ignored: with Auth0
 * RBAC off, any requested scope is granted. Display only.
 */
export function permissionsFromToken(token: string): string[] {
  const p = decodePayload(token)
  const out = new Set<string>()
  if (Array.isArray(p.permissions)) {
    for (const v of p.permissions) if (typeof v === 'string') out.add(v)
  }
  return [...out]
}

function offContext(): AuthContext {
  return {
    enforced: false,
    ready: Promise.resolve(),
    isLoading: ref(false),
    isAuthenticated: ref(true),
    user: shallowRef<User | undefined>(undefined),
    error: ref<Error | null>(null),
    permissions: ref<string[]>([]),
    login: async () => {},
    logout: async () => {},
    getToken: async () => null,
    hasPermission: () => true,
  }
}

const TERMINAL_ERRORS = new Set([
  'login_required',
  'missing_refresh_token',
  'invalid_grant',
  'consent_required',
  'mfa_required',
])

function auth0Context(cfg: AuthPublicConfig): AuthContext {
  const domain = cfg.domain ?? (cfg.issuer ? new URL(cfg.issuer).host : null)
  if (!domain || !cfg.client_id || !cfg.audience) {
    throw new Error('createNuvekAuth: oidc config needs domain/issuer, client_id and audience')
  }
  const redirectUri = location.origin + '/'
  const client = new Auth0Client({
    domain,
    clientId: cfg.client_id,
    cacheLocation: 'memory',
    useRefreshTokens: true,
    useRefreshTokensFallback: false,
    // The login transaction (state/nonce/verifier) must survive the redirect; keep it in a
    // short-lived cookie rather than the SDK's default sessionStorage.
    useCookiesForTransactions: true,
    authorizationParams: { audience: cfg.audience, redirect_uri: redirectUri },
  })

  const isLoading = ref(true)
  const isAuthenticated = ref(false)
  const user = shallowRef<User | undefined>(undefined)
  const error = ref<Error | null>(null)
  const permissions = ref<string[]>([])

  const toError = (e: unknown) => (e instanceof Error ? e : new Error(String(e)))

  async function refreshState(): Promise<void> {
    isAuthenticated.value = await client.isAuthenticated()
    user.value = isAuthenticated.value ? await client.getUser() : undefined
    if (!isAuthenticated.value) setPermissions([])
  }

  function setPermissions(next: string[]): void {
    const cur = permissions.value
    if (cur.length !== next.length || cur.some((v, i) => v !== next[i])) permissions.value = next
  }

  async function getToken(): Promise<string | null> {
    try {
      const token = await client.getTokenSilently()
      if (!token) throw new Error('no access token returned')
      setPermissions(permissionsFromToken(token))
      isAuthenticated.value = true
      return token
    } catch (e) {
      error.value = toError(e)
      // Only terminal SDK errors end the session; transient failures keep state.
      const code = (e as { error?: unknown } | null)?.error
      if (typeof code === 'string' && TERMINAL_ERRORS.has(code)) {
        isAuthenticated.value = false
        user.value = undefined
        setPermissions([])
      }
      return null
    }
  }

  async function init(): Promise<void> {
    try {
      const params = new URLSearchParams(location.search)
      if ((params.has('code') || params.has('error')) && params.has('state')) {
        const { appState } = await client.handleRedirectCallback()
        history.replaceState(history.state, '', safeReturnTo(appState?.returnTo))
      }
      await refreshState()
      if (isAuthenticated.value) await getToken()
    } catch (e) {
      error.value = toError(e)
      // Drop the single-use callback params so a reload does not replay them.
      const url = new URL(location.href)
      for (const k of ['code', 'state', 'error', 'error_description']) url.searchParams.delete(k)
      history.replaceState(history.state, '', url.pathname + url.search + url.hash)
    } finally {
      isLoading.value = false
    }
  }

  return {
    enforced: true,
    ready: init(),
    isLoading,
    isAuthenticated,
    user,
    error,
    permissions,
    async login(returnTo?: string) {
      const target = returnTo ?? location.pathname + location.search + location.hash
      await client.loginWithRedirect({ appState: { returnTo: safeReturnTo(target) } })
    },
    async logout() {
      setPermissions([])
      isAuthenticated.value = false
      user.value = undefined
      await client.logout({ logoutParams: { returnTo: redirectUri } })
    },
    getToken,
    hasPermission: (p) => permissions.value.includes(p),
  }
}

/**
 * Create the Vue plugin. Only `oidc` and `oidc+token` start an Auth0 client. `off` and
 * `token` (static machine token; the browser cannot sign in) install the off stub, and
 * the server remains the enforcement point.
 */
export function createNuvekAuth(cfg: NuvekAuthConfig): Plugin {
  const mode: string = cfg.mode
  const interactive = mode === 'oidc' || mode === 'oidc+token'
  // Fail closed: an unknown mode must never silently become the always-authenticated stub.
  if (!interactive && mode !== 'off' && mode !== 'token') {
    throw new Error(`createNuvekAuth: unknown auth mode "${mode}"`)
  }
  return {
    install(app: App) {
      const ctx = interactive ? auth0Context(cfg as AuthPublicConfig) : offContext()
      app.provide(AUTH_KEY, ctx)
      setCurrentAuth(ctx)
      app.onUnmount(() => {
        if (getCurrentAuth() === ctx) setCurrentAuth(null)
      })
    },
  }
}
