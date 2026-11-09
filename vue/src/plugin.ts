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
 * The namespaced permission claim is authoritative when present, matching the server. Native
 * permissions are a fallback only when it is absent. `scope` is ignored. Display only.
 */
export function permissionsFromToken(token: string): string[] {
  const p = decodePayload(token)
  const out = new Set<string>()
  const claim = Object.prototype.hasOwnProperty.call(p, 'https://nuvek.ca/permissions')
    ? p['https://nuvek.ca/permissions']
    : p.permissions
  // The server rejects malformed permission arrays; keep the display empty as well.
  if (!Array.isArray(claim) || claim.some((value) => typeof value !== 'string')) return []
  for (const value of claim) if (value !== '*' && value !== '') out.add(value)
  return [...out].sort()
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

/**
 * Upper bound on install-time sign-in. Some SDK waits have no timeout of their own (the token
 * worker's reply, a lock held by a call that never returns), so without this a stale session can
 * leave the app on its loading state forever with nothing in the console.
 */
// Above the SDK's own worst case for a slow but healthy token exchange (3 attempts × 10 s fetch
// timeout), so only a call that will never settle trips it.
export const INIT_TIMEOUT_MS = 35_000
/** Bound on the local-session cleanup that follows a timeout. */
const CLEANUP_TIMEOUT_MS = 2_000
/** Silent iframe auth gives up well inside INIT_TIMEOUT_MS (the SDK default is 60 s). */
const AUTHORIZE_TIMEOUT_S = 10

/** Install-time sign-in did not finish in time. `error` mirrors the SDK's error-code field. */
export class SignInTimeoutError extends Error {
  readonly error = 'init_timeout'
  constructor(readonly step: string) {
    super(`Sign-in timed out while ${step}.`)
    this.name = 'SignInTimeoutError'
  }
}

/**
 * Rejects with SignInTimeoutError naming the step in progress when `ms` elapses first.
 * `onTimeout` runs synchronously in the timer, before any awaiting code can observe the rejection.
 */
function withTimeout<T>(work: Promise<T>, ms: number, step: () => string, onTimeout?: () => void): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      onTimeout?.()
      reject(new SignInTimeoutError(step()))
    }, ms)
  })
  return Promise.race([work, timeout]).finally(() => clearTimeout(timer))
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
    // A reload empties the memory cache and its refresh token; fall back to silent iframe auth
    // against the Auth0 session. Third-party cookie blocking defeats this unless the issuer is a
    // custom domain on the app's own site (e.g. auth.example.com for app.example.com).
    useRefreshTokensFallback: true,
    // The login transaction (state/nonce/verifier) must survive the redirect; keep it in a
    // short-lived cookie rather than the SDK's default sessionStorage.
    useCookiesForTransactions: true,
    authorizeTimeoutInSeconds: AUTHORIZE_TIMEOUT_S,
    authorizationParams: { audience: cfg.audience, redirect_uri: redirectUri },
  })

  const isLoading = ref(true)
  const isAuthenticated = ref(false)
  const user = shallowRef<User | undefined>(undefined)
  const error = ref<Error | null>(null)
  const permissions = ref<string[]>([])

  const toError = (e: unknown) => (e instanceof Error ? e : new Error(String(e)))

  /** Always true outside install-time sign-in; during it, false once the sign-in was abandoned. */
  type Live = () => boolean
  const always: Live = () => true

  async function refreshState(live: Live = always): Promise<void> {
    const authed = await client.isAuthenticated()
    if (!live()) return
    const next = authed ? await client.getUser() : undefined
    if (!live()) return
    isAuthenticated.value = authed
    user.value = next
    if (!authed) setPermissions([])
  }

  function setPermissions(next: string[]): void {
    const cur = permissions.value
    if (cur.length !== next.length || cur.some((v, i) => v !== next[i])) permissions.value = next
  }

  async function tokenFor(live: Live): Promise<string | null> {
    try {
      const token = await client.getTokenSilently()
      if (!live()) return null
      if (!token) throw new Error('no access token returned')
      setPermissions(permissionsFromToken(token))
      isAuthenticated.value = true
      return token
    } catch (e) {
      if (!live()) return null
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

  const getToken = () => tokenFor(always)

  /** Clears the SDK's local session (memory cache + is-authenticated hint), bounded. */
  const clearLocalSession = () =>
    withTimeout(client.logout({ openUrl: false }), CLEANUP_TIMEOUT_MS, () => 'clearing the session').catch(() => {})

  /**
   * Install-time sign-in. After a timeout it keeps running in the background (nothing can cancel
   * the SDK call it is stuck in), so every step re-checks `live()` and touches no state once the
   * sign-in was abandoned. A late SDK success also rewrites the SDK's own session hint, so the
   * abandoned run clears it again on its way out.
   */
  async function signIn(markStep: (step: string) => void, live: Live): Promise<void> {
    // An abandoned run's late SDK success rewrote the session hint: clear it, unless the app has
    // signed in again since (a later getToken()), whose session must survive.
    const bail = () => {
      if (!isAuthenticated.value) void clearLocalSession()
    }
    const params = new URLSearchParams(location.search)
    if ((params.has('code') || params.has('error')) && params.has('state')) {
      markStep('completing sign-in')
      const { appState } = await client.handleRedirectCallback()
      if (!live()) return bail()
      history.replaceState(history.state, '', safeReturnTo(appState?.returnTo))
    } else {
      // Restore a prior session after a reload. A no-op unless the SDK's is-authenticated
      // cookie exists, and it swallows login_required.
      markStep('restoring the session')
      await client.checkSession()
      if (!live()) return bail()
    }
    markStep('reading the session')
    await refreshState(live)
    if (!live()) return bail()
    if (isAuthenticated.value) {
      markStep('fetching an access token')
      await tokenFor(live)
      if (!live()) return bail()
    }
  }

  async function init(): Promise<void> {
    let step = 'starting'
    let abandoned = false
    const live: Live = () => !abandoned
    try {
      await withTimeout(
        signIn((s) => (step = s), live),
        INIT_TIMEOUT_MS,
        () => step,
        () => (abandoned = true),
      )
    } catch (e) {
      if (e instanceof SignInTimeoutError) {
        // Treat the stuck session as gone: drop the local session marker so the next load starts
        // clean, and leave the user on the sign-in screen with the error instead of a spinner.
        isAuthenticated.value = false
        user.value = undefined
        setPermissions([])
        await clearLocalSession()
      }
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
