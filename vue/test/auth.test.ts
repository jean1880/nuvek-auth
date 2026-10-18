import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createApp, defineComponent, h, nextTick } from 'vue'
import { mount } from '@vue/test-utils'

const mockClient = vi.hoisted(() => ({
  ctorArgs: [] as unknown[],
  loginWithRedirect: vi.fn(async () => {}),
  logout: vi.fn(async () => {}),
  getTokenSilently: vi.fn(async () => 'x'),
  isAuthenticated: vi.fn(async () => true),
  getUser: vi.fn(async () => ({ sub: 'auth0|1' })),
  checkSession: vi.fn(async () => {}),
  handleRedirectCallback: vi.fn(async () => ({ appState: { returnTo: '/dashboard' } })),
}))

vi.mock('@auth0/auth0-spa-js', () => ({
  Auth0Client: class {
    constructor(opts: unknown) {
      mockClient.ctorArgs.push(opts)
    }
    loginWithRedirect = mockClient.loginWithRedirect
    logout = mockClient.logout
    getTokenSilently = mockClient.getTokenSilently
    isAuthenticated = mockClient.isAuthenticated
    getUser = mockClient.getUser
    checkSession = mockClient.checkSession
    handleRedirectCallback = mockClient.handleRedirectCallback
  },
}))

import {
  RequireAuth,
  authEventSourceUrl,
  authFetch,
  authWebSocketUrl,
  createNuvekAuth,
  getTicket,
  useAuth,
  type UseAuth,
} from '../src'

const OIDC = {
  mode: 'oidc' as const,
  issuer: 'https://tenant.example.com/',
  domain: 'tenant.example.com',
  client_id: 'client123',
  audience: 'https://api.example.com',
  permission: 'deb:write',
}

function b64url(obj: unknown): string {
  return btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
const jwt = (payload: unknown) => `${b64url({ alg: 'RS256' })}.${b64url(payload)}.sig`

/** Install the plugin on a real app and return useAuth() as seen from a component. */
async function install(cfg: Parameters<typeof createNuvekAuth>[0]): Promise<UseAuth> {
  let auth!: UseAuth
  const app = createApp(
    defineComponent({
      setup() {
        auth = useAuth()
        return () => h('div')
      },
    }),
  )
  app.use(createNuvekAuth(cfg))
  app.mount(document.createElement('div'))
  // Let install-time init settle.
  for (let i = 0; i < 10; i++) await nextTick()
  await vi.waitFor(() => expect(auth.isLoading.value).toBe(false))
  return auth
}

let fetchMock: ReturnType<typeof vi.fn>
let storageSet: ReturnType<typeof vi.spyOn>[]

beforeEach(() => {
  mockClient.ctorArgs.length = 0
  mockClient.getTokenSilently.mockImplementation(async () => jwt({ permissions: ['deb:write'], scope: 'openid read:x' }))
  mockClient.isAuthenticated.mockImplementation(async () => true)
  fetchMock = vi.fn(async () => new Response('{}', { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
  history.replaceState(null, '', '/')
  storageSet = [
    vi.spyOn(Storage.prototype, 'setItem'),
    vi.spyOn(Storage.prototype, 'removeItem'),
  ]
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('oidc client', () => {
  it('configures memory cache, refresh tokens without fallback, and audience/redirect', async () => {
    await install(OIDC)
    expect(mockClient.ctorArgs[0]).toMatchObject({
      domain: 'tenant.example.com',
      clientId: 'client123',
      cacheLocation: 'memory',
      useRefreshTokens: true,
      useRefreshTokensFallback: false,
      useCookiesForTransactions: true,
      authorizationParams: { audience: OIDC.audience, redirect_uri: location.origin + '/' },
    })
  })

  it('decodes permissions from the permissions claim only, never scope', async () => {
    const auth = await install(OIDC)
    expect(auth.isAuthenticated.value).toBe(true)
    expect(auth.permissions.value).toEqual(['deb:write'])
    expect(auth.hasPermission('read:x')).toBe(false)
    expect(auth.hasPermission('deb:write')).toBe(true)
    expect(auth.hasPermission('nope')).toBe(false)
  })

  it('handles the callback on install and cleans the URL', async () => {
    history.replaceState(null, '', '/?code=abc&state=xyz')
    await install(OIDC)
    expect(mockClient.handleRedirectCallback).toHaveBeenCalled()
    expect(location.pathname + location.search).toBe('/dashboard')
  })

  it('refuses an unsafe returnTo from the callback', async () => {
    mockClient.handleRedirectCallback.mockResolvedValueOnce({ appState: { returnTo: '//evil.example' } })
    history.replaceState(null, '', '/?code=abc&state=xyz')
    await install(OIDC)
    expect(location.pathname).toBe('/')
    expect(location.search).toBe('')
  })

  it('on callback failure sets error and strips only the callback params', async () => {
    mockClient.handleRedirectCallback.mockRejectedValueOnce(new Error('bad state'))
    history.replaceState(null, '', '/some/page?keep=1&code=abc&state=xyz&error=e&error_description=d')
    const auth = await install(OIDC)
    expect(auth.error.value?.message).toBe('bad state')
    expect(location.pathname + location.search).toBe('/some/page?keep=1')
  })

  it('keeps the session on a transient getToken failure', async () => {
    const auth = await install(OIDC)
    mockClient.getTokenSilently.mockRejectedValueOnce(new Error('network down'))
    expect(await auth.getToken()).toBeNull()
    expect(auth.error.value?.message).toBe('network down')
    expect(auth.isAuthenticated.value).toBe(true)
    expect(auth.permissions.value).toContain('deb:write')
  })

  it.each(['login_required', 'missing_refresh_token', 'invalid_grant', 'consent_required', 'mfa_required'])(
    'signs out on terminal error %s',
    async (code) => {
      const auth = await install(OIDC)
      mockClient.getTokenSilently.mockRejectedValueOnce(Object.assign(new Error(code), { error: code }))
      expect(await auth.getToken()).toBeNull()
      expect(auth.isAuthenticated.value).toBe(false)
      expect(auth.permissions.value).toEqual([])
    },
  )
})

describe('mode validation', () => {
  it('throws on an unknown mode instead of failing open', () => {
    expect(() => createNuvekAuth({ mode: 'bogus' } as never)).toThrow(/unknown auth mode/)
  })

  it('treats token mode as the stub (no Auth0 client)', async () => {
    const auth = await install({ mode: 'token', issuer: null, domain: null, client_id: null, audience: null, permission: null })
    expect(mockClient.ctorArgs).toHaveLength(0)
    expect(auth.isAuthenticated.value).toBe(true)
  })

  it('does not leak internals through useAuth()', async () => {
    const auth = await install({ mode: 'off' })
    expect(Object.keys(auth)).not.toContain('ready')
    expect(Object.keys(auth)).not.toContain('enforced')
  })
})

describe('returnTo guard', () => {
  it.each([
    ['/ok?x=1', '/ok?x=1'],
    ['//evil.example', '/'],
    ['/\\evil.example', '/'],
    ['https://evil.example', '/'],
    ['javascript:alert(1)', '/'],
    ['relative', '/'],
    ['/\t/evil.example', '/'],
    ['/\n/evil.example', '/'],
    ['/\r/evil.example', '/'],
    ['/.//evil.example', '/'],
    ['/a/../b#h', '/b#h'],
  ])('login(%s) sends appState.returnTo %s', async (input, expected) => {
    const auth = await install(OIDC)
    await auth.login(input)
    expect(mockClient.loginWithRedirect).toHaveBeenLastCalledWith({ appState: { returnTo: expected } })
  })
})

describe('authFetch', () => {
  it('attaches the bearer on same-origin URLs and returns the Response as-is', async () => {
    await install(OIDC)
    const res = await authFetch('/api/status', { headers: { 'X-A': '1' } })
    const [, init] = fetchMock.mock.calls[0]!
    const headers = new Headers((init as RequestInit).headers)
    expect(headers.get('Authorization')).toMatch(/^Bearer /)
    expect(headers.get('X-A')).toBe('1')
    expect(res.status).toBe(200)
  })

  it('never attaches the bearer to cross-origin URLs', async () => {
    await install(OIDC)
    await authFetch('https://other.example.com/api')
    await authFetch(new URL('https://other.example.com/x'))
    await authFetch('//other.example.com/y')
    for (const [, init] of fetchMock.mock.calls) {
      expect(new Headers((init as RequestInit | undefined)?.headers).has('Authorization')).toBe(false)
    }
    expect(mockClient.getTokenSilently).toHaveBeenCalledTimes(1) // only the init probe
  })

  it('sends the validated snapshot even if the caller mutates the URL afterwards', async () => {
    await install(OIDC)
    const url = new URL('/api/status', location.origin)
    const pending = authFetch(url)
    url.href = 'https://evil.example.com/steal'
    await pending
    const [target, init] = fetchMock.mock.calls[0]!
    expect(String(target)).toBe(`${location.origin}/api/status`)
    expect(new Headers((init as RequestInit).headers).has('Authorization')).toBe(true)
  })

  it('accepts a same-origin Request and keeps its headers', async () => {
    await install(OIDC)
    await authFetch(new Request(`${location.origin}/api/x`, { headers: { 'X-R': '1' } }))
    const [, init] = fetchMock.mock.calls[0]!
    const headers = new Headers((init as RequestInit).headers)
    expect(headers.get('X-R')).toBe('1')
    expect(headers.get('Authorization')).toMatch(/^Bearer /)
  })

  it('does not attach the bearer to a cross-origin Request', async () => {
    await install(OIDC)
    await authFetch(new Request('https://other.example.com/x'))
    const [, init] = fetchMock.mock.calls[0]!
    expect(new Headers((init as RequestInit | undefined)?.headers).has('Authorization')).toBe(false)
  })

  it('returns a 401 untouched', async () => {
    await install(OIDC)
    fetchMock.mockResolvedValueOnce(new Response('no', { status: 401 }))
    expect((await authFetch('/api/status')).status).toBe(401)
  })
})

describe('off mode stub', () => {
  it('is authenticated, tokenless and permits everything', async () => {
    const auth = await install({ mode: 'off' })
    expect(mockClient.ctorArgs).toHaveLength(0)
    expect(auth.isLoading.value).toBe(false)
    expect(auth.isAuthenticated.value).toBe(true)
    expect(await auth.getToken()).toBeNull()
    expect(auth.hasPermission('anything')).toBe(true)
  })

  it('authFetch adds no header in off mode', async () => {
    await install({ mode: 'off' })
    await authFetch('/api/status')
    const [, init] = fetchMock.mock.calls[0]!
    expect(new Headers((init as RequestInit | undefined)?.headers).has('Authorization')).toBe(false)
  })
})

describe('ticket URLs', () => {
  beforeEach(() => {
    fetchMock.mockImplementation(async () => new Response(JSON.stringify({ ticket: 'tk_1-a', expires_in: 30 })))
  })

  it('getTicket POSTs to /api/auth/ticket', async () => {
    await install(OIDC)
    expect(await getTicket()).toBe('tk_1-a')
    const [url, init] = fetchMock.mock.calls[0]!
    expect(String(url)).toBe(`${location.origin}/api/auth/ticket`)
    expect((init as RequestInit).method).toBe('POST')
  })

  it('uses ? or & and a ws(s) scheme for WebSockets', async () => {
    await install(OIDC)
    expect(await authWebSocketUrl('/api/ws')).toBe(`ws://${location.host}/api/ws?ticket=tk_1-a`)
    expect(await authWebSocketUrl('/api/ws?x=1')).toBe(`ws://${location.host}/api/ws?x=1&ticket=tk_1-a`)
  })

  it('builds same-origin EventSource URLs', async () => {
    await install(OIDC)
    expect(await authEventSourceUrl('/api/logs?x=1')).toBe(`${location.origin}/api/logs?x=1&ticket=tk_1-a`)
  })

  it('never leaves the origin for `/.//evil.com/x`', async () => {
    await install(OIDC)
    for (const build of [authEventSourceUrl, authWebSocketUrl]) {
      const out = new URL(await build('/.//evil.com/x'))
      expect(out.hostname).toBe(location.hostname)
      expect(out.searchParams.get('ticket')).toBe('tk_1-a')
    }
  })

  it('rejects cross-origin paths', async () => {
    await install(OIDC)
    await expect(authEventSourceUrl('https://other.example.com/x')).rejects.toThrow(/same-origin/)
  })

  it('returns the plain URL in off mode without requesting a ticket', async () => {
    await install({ mode: 'off' })
    expect(await authEventSourceUrl('/api/logs')).toBe(`${location.origin}/api/logs`)
    expect(await authWebSocketUrl('/api/ws')).toBe(`ws://${location.host}/api/ws`)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('RequireAuth', () => {
  async function render(cfg: Parameters<typeof createNuvekAuth>[0]) {
    const w = mount(RequireAuth, {
      global: { plugins: [createNuvekAuth(cfg)] },
      slots: {
        default: '<span id="in">in</span>',
        loading: '<span id="load">loading</span>',
        unauthenticated: '<template #unauthenticated="{ login }"><button id="out" @click="login()">go</button></template>',
      },
    })
    return w
  }

  it('shows default when authenticated', async () => {
    const w = await render({ mode: 'off' })
    expect(w.find('#in').exists()).toBe(true)
  })

  it('shows loading, then unauthenticated with a working login', async () => {
    mockClient.isAuthenticated.mockImplementation(async () => false)
    const w = await render(OIDC)
    expect(w.find('#load').exists()).toBe(true)
    await vi.waitFor(() => expect(w.find('#out').exists()).toBe(true))
    await w.find('#out').trigger('click')
    expect(mockClient.loginWithRedirect).toHaveBeenCalled()
  })
})

describe('storage', () => {
  it('never writes to localStorage or sessionStorage', async () => {
    const auth = await install(OIDC)
    await auth.getToken()
    await auth.login('/x')
    await auth.logout()
    await authFetch('/api/status')
    expect(storageSet[0]).not.toHaveBeenCalled()
    expect(storageSet[1]).not.toHaveBeenCalled()
    expect(localStorage.length).toBe(0)
    expect(sessionStorage.length).toBe(0)
  })
})
