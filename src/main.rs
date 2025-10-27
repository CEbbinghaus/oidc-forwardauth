mod oidc_providers;
mod salvo_utils;

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode as jwt_decode, decode_header, DecodingKey, Validation};
use oidc_providers::OIDCProviders;
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{reqwest, EndpointMaybeSet, EndpointNotSet, EndpointSet};
use openidconnect::{
    AccessTokenHash, AuthenticationFlow, AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope, TokenResponse,
};
use salvo::http::cookie::Cookie;
use salvo::http::{HeaderValue, StatusCode};
use salvo::logging::Logger;
use salvo::prelude::{
    handler, Depot, Redirect, Request, Response, Router, Server, TcpListener, Text,
};
use salvo::routing::PathState;
use salvo::{Listener, Service};
use salvo_utils::{get_cookie, get_header, get_query_param, security_middleware};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::{OnceLock, RwLock};
use tinykv::TinyKV;
use tracing::{debug, info, warn};
use urlencoding::decode;

static PROVIDERS: OnceLock<OIDCProviders> = OnceLock::new();
static CACHE: OnceLock<RwLock<TinyKV>> = OnceLock::new();
static ACCESS_TOKEN_COOKIE_NAME: &str = "x_oidc_access_token";
static ID_TOKEN_COOKIE_NAME: &str = "x_oidc_id_token";
static REFRESH_TOKEN_COOKIE_NAME: &str = "x_oidc_refresh_token";
static STATE_COOKIE_NAME: &str = "x_oidc_csrf";

pub type InitializedClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Serialize, Deserialize)]
struct AuthRequestData {
    pub pkce_token: String,
    pub nonce: Nonce,
}

#[derive(Clone, Debug)]
struct ForwardAuthHeaders {
    https: bool,
    protocol: String,
    host: String,
    uri: String,
}

#[handler]
async fn forward_auth_handler(_req: &mut Request, res: &mut Response, depot: &mut Depot) {
    let client = depot.obtain::<InitializedClient>().unwrap().clone();
    let scopes = depot.obtain::<Vec<Scope>>().unwrap().to_owned();
    let headers = depot.obtain::<ForwardAuthHeaders>().unwrap();
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, csrf_state, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scopes(scopes)
        .set_pkce_challenge(pkce_challenge)
        .url();

    let auth_request_data = AuthRequestData {
        pkce_token: pkce_verifier.secret().clone(),
        nonce,
    };

    let mut cache_write = CACHE.get().unwrap().write().expect("Write to be Aquired");

    // TODO: Add auth timeout
    cache_write
        .set(csrf_state.secret(), auth_request_data)
        .expect("Cache write to succeed");

    res.add_cookie(
        Cookie::build((STATE_COOKIE_NAME, csrf_state.secret().to_string()))
            .secure(headers.https)
            .http_only(true)
            .build(),
    );

    debug!("Redirecting client to {}", authorize_url.to_string());

    res.render(Redirect::temporary(authorize_url.to_string()));
}

#[handler]
async fn status_handler(res: &mut Response) {
    res.status_code(StatusCode::NO_CONTENT);
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[handler]
async fn ok_handler(req: &mut Request, res: &mut Response) {
    let headers = res.headers_mut();
    let sub_header = req.headers().get("X-Forwarded-User");

    // Depot would be better, but check_cookie middleware does not support it
    // TODO: Fix with actix migration

    if sub_header.is_some() {
        debug!(
            "X-Forwarded-User: {}",
            &sub_header.clone().unwrap().to_str().unwrap()
        );

        headers.insert("X-Forwarded-User", sub_header.unwrap().to_owned());
    }

    res.status_code(StatusCode::NO_CONTENT);
}

fn has_refresh_token(req: &mut Request, _state: &mut PathState) -> bool {
    let refresh_token = get_cookie(req, REFRESH_TOKEN_COOKIE_NAME);

    !refresh_token.is_empty()
}

#[handler]
async fn renew_access_token(req: &mut Request, res: &mut Response, depot: &mut Depot) {
    let refresh_token = decode(&get_cookie(req, REFRESH_TOKEN_COOKIE_NAME))
        .unwrap()
        .to_string();

    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Htttp Client to build");

    let client = depot.obtain::<InitializedClient>().unwrap();
    let headers = depot.obtain::<ForwardAuthHeaders>().unwrap();
    let scopes = depot.obtain::<Vec<Scope>>().unwrap().to_owned();

    let token_response = match client
        .exchange_refresh_token(&RefreshToken::new(refresh_token.to_owned()))
        .expect("Refresh token to be valid")
        .add_scopes(scopes) // TODO: Test if required
        .request_async(&http_client)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            debug!("Refresh token: {}", &refresh_token);
            warn!("Error exchanging refresh token: {}", err);

            // If the token is invalid, remove the cookie and try again.
            // TODO: Directly redirect to forward_auth_handler
            res.remove_cookie(REFRESH_TOKEN_COOKIE_NAME);
            res.render(Redirect::temporary(format!(
                "{}://{}/{}",
                headers.protocol,
                headers.host,
                headers.uri.trim_start_matches("/")
            )));

            return;
        }
    };

    let access_token = decode(&token_response.access_token().secret())
        .unwrap()
        .into_owned();

    let refresh_token = decode(&token_response.refresh_token().unwrap().secret())
        .unwrap()
        .into_owned();

    if access_token.is_empty() {
        res.status_code(StatusCode::UNAUTHORIZED);
    }

    res.add_cookie(
        Cookie::build((ACCESS_TOKEN_COOKIE_NAME, access_token.to_owned()))
            .secure(headers.https)
            .http_only(true)
            .build(),
    );

    res.add_cookie(
        Cookie::build((REFRESH_TOKEN_COOKIE_NAME, refresh_token))
            .secure(headers.https)
            .http_only(true)
            .build(),
    );

    res.render(Redirect::temporary(format!(
        "{}://{}/{}",
        &headers.protocol,
        &headers.host,
        &headers.uri.trim_start_matches("/")
    )));
}

// TODO: Refactor from path check to middleware
fn check_cookie(req: &mut Request, _state: &mut PathState) -> bool {
    let hostname = get_header(req, "x-forwarded-host");
    let token = get_cookie(req, ACCESS_TOKEN_COOKIE_NAME);

    if token.is_empty() {
        debug!("Cookie key {} is empty.", ACCESS_TOKEN_COOKIE_NAME);
        return false;
    }

    debug!("Received cookie value: {}", &token);

    let oidc_provider = match PROVIDERS.get().unwrap().find_by_hostname(&hostname) {
        Some(val) => val,
        None => {
            debug!("OIDC provider not found for hostname {}.", &hostname);
            return false;
        }
    };

    let header = match decode_header(&token) {
        Ok(val) => val,
        Err(_) => {
            debug!("Error when decoding headers of token: {}", &token);
            return false;
        }
    };

    let key_id = header.kid.unwrap();
    debug!("Token JWK Key ID: {}", &key_id);

    let jwks: JwkSet = oidc_provider.clone().jwks;
    let jwk: &jsonwebtoken::jwk::Jwk = match jwks.keys.iter().find(|k| {
        k.common
            .key_id
            .as_ref()
            .is_some_and(|s| s.eq(key_id.as_str()))
    }) {
        Some(val) => val,
        _ => return false,
    };

    let key = DecodingKey::from_jwk(&jwk).unwrap();
    let mut validation = Validation::new(header.alg);

    validation.set_audience(&oidc_provider.audience.clone());
    validation.set_issuer(&vec![oidc_provider.issuer_url.clone().as_str()]);

    let claims = jwt_decode::<Claims>(&token, &key, &validation);

    if !claims.is_ok() {
        return false;
    }

    let sub = claims.unwrap().claims.sub;

    // Does not work in PathFilter :/
    // depot.inject::<Claims>(myclaims);

    // So we pass it via the request header
    let headers = req.headers_mut();
    headers.insert("X-Forwarded-User", HeaderValue::from_str(&sub).unwrap());

    return true;
}

fn check_params(req: &mut Request, _state: &mut PathState) -> bool {
    let uri = get_header(req, "x-forwarded-uri");
    let cache_read = CACHE.get().unwrap().read().expect("Cache to be readable");
    let state = get_query_param(&uri, "state");
    let code = get_query_param(&uri, "code");

    return !(uri.is_empty()
        || code.is_empty()
        || state.is_empty()
        || !cache_read.contains_key(&state));
}

#[handler]
fn set_cookie(res: &mut Response, depot: &mut Depot) {
    let client = depot.obtain::<InitializedClient>().unwrap();
    let headers = depot.obtain::<ForwardAuthHeaders>().unwrap();

    let http_client = reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Htttp Client to build");

    let code = get_query_param(&headers.uri, "code");
    if code.is_empty() {
        return res
            .status_code(StatusCode::BAD_GATEWAY)
            .render(Text::Plain("No Token in response."));
    }

    let state = get_query_param(&headers.uri, "state");

    let mut cache = CACHE.get().unwrap().write().expect("Cache to be writable");

    // We expect an Ok result since the filter checked the key exists, None means the auth flow ran out of time
    let Ok(Some(auth_state)) = cache.get::<AuthRequestData>(&state) else {
        return res
            .status_code(StatusCode::REQUEST_TIMEOUT)
            .render(Text::Plain("Authentication flow took too long to complete"));
    };

    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .expect("Code to be present")
        .set_pkce_verifier(PkceCodeVerifier::new(auth_state.pkce_token))
        .request(&http_client)
        .unwrap();

    let id_token = token_response.id_token().unwrap().to_owned();
    let id_token_verifier = client.id_token_verifier();

    let Ok(claims) = id_token.claims(&id_token_verifier, &auth_state.nonce) else {
        return res
            .status_code(StatusCode::UNAUTHORIZED)
            .render(Text::Plain("Unable to verify Id Token"));
    };

    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash = AccessTokenHash::from_token(
            token_response.access_token(),
            id_token.signing_alg().unwrap(),
            id_token.signing_key(&id_token_verifier).unwrap(),
        )
        .expect("Token Hash to be constructed");
        if actual_access_token_hash != *expected_access_token_hash {
            return res
                .status_code(StatusCode::UNAUTHORIZED)
                .render(Text::Plain("Invalid Access Token"));
        }
    }

    let access_token = token_response.access_token().secret().to_owned();
    let refresh_token = token_response.refresh_token().unwrap().secret().to_owned();

    res.add_cookie(
        Cookie::build((ACCESS_TOKEN_COOKIE_NAME, access_token))
            .secure(headers.https)
            .http_only(true)
            .build(),
    );

    res.add_cookie(
        Cookie::build((ID_TOKEN_COOKIE_NAME, id_token.to_string()))
            .secure(headers.https)
            .http_only(true)
            .build(),
    );

    res.add_cookie(
        Cookie::build((REFRESH_TOKEN_COOKIE_NAME, refresh_token))
            .secure(headers.https)
            .http_only(true)
            .build(),
    );

    res.remove_cookie(STATE_COOKIE_NAME);

    // Todo: redirect to the page vistited before
    res.render(Redirect::temporary(format!(
        "{}://{}/",
        headers.protocol, headers.host
    )));
}

#[handler]
async fn apply_oauth2_client(req: &mut Request, res: &mut Response, depot: &mut Depot) {
    let forward_headers = ForwardAuthHeaders {
        host: get_header(req, "x-forwarded-host"),
        protocol: get_header(req, "x-forwarded-proto").to_owned(),
        https: get_header(req, "x-forwarded-proto")
            .to_lowercase()
            .eq("https"),
        uri: get_header(req, "x-forwarded-uri"),
    };

    let oidc_provider = match PROVIDERS
        .get()
        .unwrap()
        .find_by_hostname(&forward_headers.host)
    {
        Some(val) => val,
        None => {
            return res
                .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                .render(Text::Plain("No OIDC provider found for hostname."));
        }
    };

    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Htttp Client to build");

    let provider_metadata =
        CoreProviderMetadata::discover_async(oidc_provider.clone().issuer_url, &http_client)
            .await
            .unwrap();

    let client: InitializedClient = CoreClient::from_provider_metadata(
        provider_metadata.clone(),
        oidc_provider.client_id.to_owned(),
        Some(oidc_provider.client_secret.to_owned()),
    )
    .set_redirect_uri(
        RedirectUrl::new(
            format!(
                "{}://{}/auth_callback",
                &forward_headers.protocol, &forward_headers.host
            )
            .to_string(),
        )
        .expect("Invalid redirect URL"),
    );

    depot.inject(forward_headers.clone());
    depot.inject((client, provider_metadata.authorization_endpoint().clone()));
    depot.inject(oidc_provider.scopes.clone());
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let enhanced_security_enabled = match env::var("DISABLE_ENHANCED_SECURITY") {
        Ok(val) => !(val.to_lowercase().eq("true") || val.eq("1")),
        Err(_) => true,
    };

    let store = TinyKV::open("cache.json")
        .expect("cache file to be accessible")
        .with_auto_save();

    CACHE.get_or_init(move || RwLock::new(store));

    let oidc_providers = OIDCProviders::new().await;
    PROVIDERS.get_or_init(move || oidc_providers);

    let router = Router::new()
        .push(Router::with_path("/status").goal(status_handler))
        .push(
            Router::with_path("/verify")
                .hoop(apply_oauth2_client)
                .then(|router| {
                    if enhanced_security_enabled {
                        info!("Enhanced security is enabled.");
                        router.hoop(security_middleware)
                    } else {
                        info!("Enhanced security is disabled.");
                        router
                    }
                })
                .push(Router::with_filter_fn(check_cookie).goal(ok_handler))
                .push(Router::with_filter_fn(has_refresh_token).goal(renew_access_token))
                .push(Router::with_filter_fn(check_params).goal(set_cookie))
                .push(Router::new().goal(forward_auth_handler)),
        );

    let service = Service::new(router).hoop(Logger::new());
    let acceptor = TcpListener::new("0.0.0.0:3000").bind().await;

    Server::new(acceptor).serve(service).await;
}
