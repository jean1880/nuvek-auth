# nuvek-auth

Shared authentication for nuvek web apps: a Rust crate (`nuvek-auth`, axum 0.8) that validates Auth0
access tokens and a static machine token, and a Vue 3 package (`@nuvek/auth`) that signs the SPA in
with Auth0 Authorization Code + PKCE.

- Login only. There is no signup path; users are created by an administrator in the Auth0 tenant.
- Secret-free by construction. The issuer, audience and SPA client ID are public. The only secret is
  the optional static API token, which is read from the environment and never logged or Debug-printed.
- Tokens live in memory only. Nothing is written to `localStorage` or `sessionStorage`.

## Rust

```toml
[dependencies]
nuvek-auth = { git = "https://github.com/jean1880/nuvek-auth.git", tag = "v0.2.0" }
```

```rust
// Fails closed: a missing or invalid variable is an error naming the key.
let auth = nuvek_auth::Authenticator::new(nuvek_auth::AuthConfig::from_env("APP_")?)?;

let app = Router::new()
    .merge(public_routes)
    .merge(nuvek_auth::routes(auth.clone()))          // GET /api/auth/config, POST /api/auth/ticket
    .merge(reads.layer(auth.require_user()))
    .merge(streams.layer(auth.require_user_or_ticket()))
    .merge(writes.layer(auth.require_permission("app:write")));
```

Handlers read the caller with the `Principal` extractor. Every successful `require_permission` emits an
audit event on the `nuvek_auth::audit` tracing target (`actor`, `via`, `method`, `path`).

`nuvek_auth::csp::spa_policy(issuer)` returns a strict CSP for the SPA shell (`script-src 'self'`, no
`unsafe-eval`); `nuvek_auth::csp::FILE_SANDBOX` is for user-visible files such as logs. With an issuer
it adds `worker-src 'self' blob:`, which auth0-spa-js needs for its in-memory refresh-token worker; an
app that writes its own CSP must include it, or sign-in hangs after the Auth0 redirect.

### Environment

`{P}` is the prefix passed to `AuthConfig::from_env`, including its trailing underscore (e.g. `DEB_`).

| Variable | Required | Meaning |
|---|---|---|
| `{P}AUTH_MODE` | always | `off`, `token`, `oidc` or `oidc+token`. No default: startup fails if unset or unknown. `off` logs a warning |
| `{P}OIDC_ISSUER` | oidc modes | `https://<tenant>/`; a missing trailing slash is added |
| `{P}OIDC_AUDIENCE` | oidc modes | API identifier the access token must carry in `aud` |
| `{P}OIDC_CLIENT_ID` | oidc modes | Public SPA client ID, served to the browser |
| `{P}ALLOWED_SUBS` | oidc modes, this or the next | Comma-separated Auth0 user IDs allowed in |
| `{P}REQUIRED_PERMISSION` | oidc modes, this or the previous | Permission every user token must carry |
| `{P}REQUIRE_MFA` | no (false) | Require `mfa` in `amr` or `https://nuvek.ca/amr` for permissioned routes |
| `{P}REQUIRE_PASSKEY` | no (false) | Require exact `passkey` in signed `https://nuvek.ca/amr` for every OIDC authentication, including protected reads |
| `{P}API_TOKEN` | token modes | Static machine token (`sub = machine:static`). Empty counts as unset |
| `{P}API_TOKEN_NEXT` | no | Second accepted token, for rotation |
| `{P}AUTH_READS` | no (true) | Gate read routes behind login |
| `{P}PUBLIC_ORIGIN` | unless `off` | Exact origin for the WebSocket `Origin` check, e.g. `https://app.nuvek.ca` |

`{P}API_TOKEN` and `{P}API_TOKEN_NEXT` must be at least 32 characters.

Error bodies are JSON `{"error": "UNAUTHORIZED"|"FORBIDDEN"|"AUTH_UNAVAILABLE"|"TOO_MANY", "message": "…"}`
with 401, 403, 503 and 429 respectively. The static token never depends on Auth0, so it is also the
break-glass path when the tenant is unreachable.

### Auth0 tenant requirements
- Permissions come from signed `https://nuvek.ca/permissions` when present. This claim is authoritative,
  including an empty array; native RBAC cannot restore permissions withheld by the Action. When the
  namespace is absent, the native `permissions` claim remains supported with API RBAC and **Add
  Permissions in the Access Token**. Either claim must be an array of strings; malformed namespaces,
  including explicit null, fail closed. Empty permissions and `*` are discarded, and the selected
  list is deduplicated. `scope` never grants permissions: without RBAC, requested scopes can be
  self-grantable.
- For a Free-plan deployment, an administrator controls `app_metadata` permissions and a trusted
  post-login Action issues `https://nuvek.ca/permissions` only after actual passkey authentication.
  Use the completed authentication methods for that transaction; an enrolled passkey or a successful
  password login is not proof. Denied or unproven transactions must not receive permission grants.
  Never derive grants from `user_metadata`, requested scopes or client-supplied claims.
- Set `{P}REQUIRE_PASSKEY=true` when every protected OIDC request must prove passkey authentication.
  The Action must include literal `passkey` in the signed `https://nuvek.ca/amr` string or string
  array. Missing, malformed or other methods are rejected before a principal is established;
  standard `amr` alone does not satisfy this option. Refresh-token exchanges must preserve verified
  passkey provenance or issue no grants; a missing method must fail closed.
- Passkey policy and MFA policy are independent. A passkey is never converted into `mfa`.
  `{P}REQUIRE_MFA` still checks permissioned OIDC routes only. Static machine tokens remain exempt
  from both interactive requirements and work when Auth0 is unavailable.
- Tokens must be RS256. Signing keys come from `{issuer}.well-known/jwks.json`, refreshed every 10 minutes;
  during an outage the last good key set is used for at most 24 hours.

### Tickets
WebSocket, EventSource and plain links can't carry an `Authorization` header. The SPA exchanges its
token for a single-use 30-second ticket (`POST /api/auth/ticket`) and passes it as `?ticket=`. Each
user may hold 32 live tickets. Tickets travel in URLs, so don't log query strings on ticket routes.

## Vue

```json
"dependencies": { "@nuvek/auth": "github:jean1880/nuvek-auth#v0.2.0" }
```

```ts
import { createNuvekAuth, loadAuthConfig } from '@nuvek/auth'

const app = createApp(App)
app.use(createNuvekAuth(await loadAuthConfig()))
```

`useAuth()` exposes `isLoading`, `isAuthenticated`, `user`, `error`, `permissions`, `login(returnTo?)`,
`logout()`, `getToken()` and `hasPermission(p)`. `authFetch` attaches the bearer to same-origin requests
only. `authWebSocketUrl` / `authEventSourceUrl` add a fresh ticket. `<RequireAuth>` is headless, with
`default`, `loading` and `unauthenticated` (`{ login }`) slots. Permissions in the SPA are for display
only; the server enforces them. The Vue decoder follows the same namespaced-claim precedence,
native fallback, deduplication and wildcard filtering as Rust. It grants nothing for malformed
permission arrays.

In `off` and `token` modes the plugin is a stub: always authenticated, no token, every permission
granted. A browser can't sign in with the static machine token, so in `token` mode the SPA looks signed
in while the server answers 401 to anything gated. Use `off` for local development and tests only, and
set it explicitly. Any other mode value throws at install.

Session behaviour:
- Tokens live in memory, so a page reload drops them. On load the client calls `checkSession()`, which
  (when the hint cookie below is present) restores the session through silent iframe auth against the
  Auth0 session (`useRefreshTokensFallback`). Browsers that block third-party cookies defeat this unless
  the issuer is an Auth0 custom domain on the app's own site (for example `auth.nuvek.ca` for
  `*.nuvek.ca`).
- When silent restore fails, `<RequireAuth>` redirects to Auth0 at once (`autoLogin`, default on;
  `:auto-login="false"` shows the `unauthenticated` slot instead). That top-level redirect carries
  Auth0's first-party session cookie, so a live session comes straight back with no prompt. After a
  failed login (`error` set) it shows the `unauthenticated` slot rather than looping.
- auth0-spa-js keeps the login transaction (state, nonce, PKCE verifier) in a short-lived cookie
  (`useCookiesForTransactions`) and sets its own `auth0.is.authenticated` hint cookie. Neither holds a
  token.

## Secret handling

- Never commit a token, key or `.env`. gitleaks gates every push with the default ruleset and no
  allowlist; test keypairs are generated at runtime.
- Pass the static token through the environment only, never argv or a URL query.
- Treat a token that reached a log, a URL or a chat as exposed and rotate it via `{P}API_TOKEN_NEXT`.

## Development

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
npm ci
npm run typecheck
npm test
npm run build
```

## Licence

MIT
