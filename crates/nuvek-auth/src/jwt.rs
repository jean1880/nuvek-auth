//! RS256 access-token validation.
//!
//! RS256 only (any other header `alg` is rejected), exact `iss`, `aud` containing the audience,
//! required `exp` with 60 s leeway, `nbf` honoured, `sub` required. Permissions come only from
//! the native `permissions` and signed `https://nuvek.ca/permissions` claims; `scope` is never
//! read, because without tenant RBAC Auth0 grants any requested scope.

use jsonwebtoken::{decode, decode_header, errors::ErrorKind, Algorithm, Validation};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::config::OidcConfig;
use crate::error::AuthError;
use crate::jwks::{JwksCache, KeyLookup};
use crate::{Principal, Via, ALL_PERMISSIONS};

/// Leeway applied to `exp` and `nbf`, in seconds.
pub const LEEWAY_SECS: u64 = 60;

/// Namespaced claim Auth0 Actions can use to carry `amr`.
pub const NAMESPACED_AMR_CLAIM: &str = "https://nuvek.ca/amr";

/// Namespaced permissions claim set by a trusted Auth0 Action from administrator-owned metadata.
pub const NAMESPACED_PERMISSIONS_CLAIM: &str = "https://nuvek.ca/permissions";

#[derive(Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    permissions: Option<Vec<String>>,
    #[serde(
        default,
        rename = "https://nuvek.ca/permissions",
        deserialize_with = "present_permissions"
    )]
    namespaced_permissions: Option<Vec<String>>,
    #[serde(default)]
    amr: Option<Value>,
    #[serde(default, rename = "https://nuvek.ca/amr")]
    namespaced_amr: Option<Value>,
}

/// Holds the validation rules built once from the OIDC config.
pub(crate) struct JwtValidator {
    validation: Validation,
}

impl JwtValidator {
    pub(crate) fn new(oidc: &OidcConfig) -> Self {
        // `Validation::new` pins `algorithms` to exactly `[RS256]`.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[oidc.issuer()]);
        validation.set_audience(&[oidc.audience()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.leeway = LEEWAY_SECS;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        Self { validation }
    }

    /// Validates `token` and maps it to a [`Principal`]. Subject allowlist and required
    /// permission and optional passkey assurance are enforced here (403).
    pub(crate) async fn validate(
        &self,
        token: &str,
        oidc: &OidcConfig,
        jwks: &JwksCache,
    ) -> Result<Principal, AuthError> {
        let header =
            decode_header(token).map_err(|_| AuthError::Unauthorized("malformed access token"))?;
        if header.alg != Algorithm::RS256 {
            return Err(AuthError::Unauthorized("unsupported token algorithm"));
        }
        let kid = header
            .kid
            .ok_or(AuthError::Unauthorized("access token has no key id"))?;

        let key = match jwks.key(&kid).await {
            KeyLookup::Found(key) => key,
            KeyLookup::Unknown => return Err(AuthError::Unauthorized("unknown signing key")),
            KeyLookup::Unavailable => {
                return Err(AuthError::Unavailable(
                    "identity provider keys are unavailable",
                ))
            }
        };

        let data = decode::<Claims>(token, key.as_ref(), &self.validation).map_err(|e| {
            let msg = match e.kind() {
                ErrorKind::ExpiredSignature => "access token expired",
                ErrorKind::ImmatureSignature => "access token not yet valid",
                ErrorKind::InvalidIssuer => "access token issuer mismatch",
                ErrorKind::InvalidAudience => "access token audience mismatch",
                ErrorKind::MissingRequiredClaim(_) => "access token is missing a required claim",
                ErrorKind::InvalidSignature => "access token signature invalid",
                _ => "invalid access token",
            };
            tracing::debug!(reason = msg, "access token rejected");
            AuthError::Unauthorized(msg)
        })?;
        let claims = data.claims;

        if claims.sub.is_empty() {
            return Err(AuthError::Unauthorized("access token has an empty subject"));
        }

        // Only signed permission claims count. `scope` is ignored on purpose: with tenant RBAC
        // off, Auth0 grants any scope the client asks for, so it would be self-grantable.
        // An Action may deliberately issue an empty list. Its namespace is authoritative when
        // present; never let native RBAC restore permissions the Action withheld.
        let mut permissions = claims
            .namespaced_permissions
            .or(claims.permissions)
            .unwrap_or_default();
        // The wildcard is reserved for the static token and off mode; never grant it from a JWT.
        permissions.retain(|p| p != ALL_PERMISSIONS && !p.is_empty());
        permissions.sort();
        permissions.dedup();

        let mfa = has_method(claims.amr.as_ref(), "mfa")
            || has_method(claims.namespaced_amr.as_ref(), "mfa");

        // The namespaced assertion comes from the tenant's trusted Action. Standard `amr`,
        // enrolled factors and permissions alone never establish completed passkey login.
        if oidc.require_passkey() && !has_passkey(claims.namespaced_amr.as_ref()) {
            return Err(AuthError::Forbidden("passkey authentication required"));
        }

        if !oidc.allowed_subs().is_empty() && !oidc.allowed_subs().iter().any(|s| s == &claims.sub)
        {
            return Err(AuthError::Forbidden("subject is not allowed"));
        }
        if let Some(required) = oidc.required_permission() {
            if !permissions.iter().any(|p| p == required) {
                return Err(AuthError::Forbidden("missing required permission"));
            }
        }

        Ok(Principal {
            sub: claims.sub,
            permissions,
            mfa,
            via: Via::Oidc,
        })
    }
}

/// Missing namespaces use the field default; any present value must be an array of strings.
/// In particular, explicit null is invalid rather than permission to fall back to native RBAC.
fn present_permissions<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<String>::deserialize(deserializer).map(Some)
}

/// True when an authentication-method claim (a string or an array) contains the exact method.
fn has_method(value: Option<&Value>, method: &str) -> bool {
    match value {
        Some(Value::String(s)) => s == method,
        Some(Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(method)),
        _ => false,
    }
}

/// Passkey assurance requires a well-formed string or string array; MFA compatibility above
/// deliberately keeps its existing behaviour.
fn has_passkey(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Array(items)) if items.iter().any(|item| !item.is_string()) => false,
        value => has_method(value, "passkey"),
    }
}
