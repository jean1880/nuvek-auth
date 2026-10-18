import { computed, hasInjectionContext, inject, type InjectionKey, type Ref } from 'vue'
import type { User } from '@auth0/auth0-spa-js'

/** Shape of `GET /api/auth/config` in oidc modes (mirrors the nuvek-auth Rust crate). */
export interface AuthPublicConfig {
  mode: 'off' | 'token' | 'oidc' | 'oidc+token'
  issuer: string | null
  domain: string | null
  client_id: string | null
  audience: string | null
  permission: string | null
}

/** What `createNuvekAuth` accepts: the server config, or an explicit off stub. */
export type NuvekAuthConfig = AuthPublicConfig | { mode: 'off' }

export interface UseAuth {
  isLoading: Readonly<Ref<boolean>>
  isAuthenticated: Readonly<Ref<boolean>>
  user: Readonly<Ref<User | undefined>>
  error: Readonly<Ref<Error | null>>
  /** Decoded from the access token payload. Display only; the server enforces. */
  permissions: Readonly<Ref<string[]>>
  login(returnTo?: string): Promise<void>
  logout(): Promise<void>
  getToken(): Promise<string | null>
  hasPermission(permission: string): boolean
}

/** Internal context: the public surface plus what the fetch/stream helpers need. */
export interface AuthContext extends UseAuth {
  /** True when an Auth0 client is active (oidc modes); false for the off/token stub. */
  readonly enforced: boolean
  /** Resolves once install-time init (callback handling) finished. */
  ready: Promise<void>
}

export const AUTH_KEY: InjectionKey<AuthContext> = Symbol('nuvek-auth')

let current: AuthContext | null = null

export function setCurrentAuth(ctx: AuthContext | null): void {
  current = ctx
}

/** The installed instance, for non-component code (api clients). */
export function getCurrentAuth(): AuthContext | null {
  return current
}

const CONTROL_CHARS = /[\u0000-\u001f\u007f]/

/**
 * Accept only same-origin absolute paths. Control characters are rejected first (URL
 * parsers strip them, turning `/\t/evil.com` into `//evil.com`); the value is then parsed
 * and the normalised path+search+hash returned. Anything else becomes `/`.
 */
export function safeReturnTo(value: unknown): string {
  if (typeof value !== 'string') return '/'
  if (!value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return '/'
  if (CONTROL_CHARS.test(value)) return '/'
  try {
    const url = new URL(value, location.origin)
    if (url.origin !== location.origin) return '/'
    const out = url.pathname + url.search + url.hash
    return out.startsWith('/') && !out.startsWith('//') ? out : '/'
  } catch {
    return '/'
  }
}

export function useAuth(): UseAuth {
  const ctx = (hasInjectionContext() ? inject(AUTH_KEY, null) : null) ?? current
  if (!ctx) throw new Error('useAuth(): app.use(createNuvekAuth(...)) has not been called')
  // Public surface only: no `ready`/`enforced`, and read-only refs.
  return {
    isLoading: computed(() => ctx.isLoading.value),
    isAuthenticated: computed(() => ctx.isAuthenticated.value),
    user: computed(() => ctx.user.value),
    error: computed(() => ctx.error.value),
    permissions: computed(() => ctx.permissions.value),
    login: (returnTo) => ctx.login(returnTo),
    logout: () => ctx.logout(),
    getToken: () => ctx.getToken(),
    hasPermission: (p) => ctx.hasPermission(p),
  }
}
