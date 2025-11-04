mod oidc_providers;
mod salvo_utils;

use base64::prelude::*;
use k8s_openapi::chrono::{DateTime, Duration, Utc};
use oidc_providers::OIDCProviders;
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{reqwest, AdditionalClaims, EndpointMaybeSet, EndpointNotSet, EndpointSet};
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
use serde_with::{DurationSecondsWithFrac, serde_as};
use std::{env, fs, iter};
use std::sync::OnceLock;
use tracing::{debug, error, info, trace, warn};
use urlencoding::decode;

static PROVIDERS: OnceLock<OIDCProviders> = OnceLock::new();
static AUTHREQUEST_COOKIE_NAME: &str = "x_oidc_authrequest";
static SESSION_COOKIE_NAME: &str = "x_oidc_session";

static CONFIGURATION: OnceLock<Configuration> = OnceLock::new();

pub type InitializedClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Deserialize, Debug)]
struct Configuration {
    session_duration: Duration,
    access_token_refresh_lead: Duration,
    secret: String,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            session_duration: Duration::new(5 * 60 * 60, 0).unwrap(),
            access_token_refresh_lead: Duration::new(5 * 60, 0).unwrap(),
            secret: "SwrFnZSsti^tH6fY%j!h6o!MsA$jnlsKr!I%Zl1b!XzfMrmDdiWe2AjL@rhT0sOVHn1VJcd^&2nL&#xTqGXtmKjfSU5m61SzK6*OBQ13LONO1KhVHTaz0y#Ao8%qpQcz".to_string()
        }
    }
}

impl<T> From<T> for Configuration
where
    T: IntoIterator<Item = OptionalConfiguration>,
{
    fn from(value: T) -> Self {
        let value = value.into_iter();

        let configurations: Vec<OptionalConfiguration> = value
            .chain(iter::once(OptionalConfiguration::default()))
            .collect();
        Configuration {
            session_duration: configurations
                .iter()
                .map(|v| v.session_duration)
                .reduce(Option::or)
                .flatten()
                .unwrap(),
            access_token_refresh_lead: configurations
                .iter()
                .map(|v| v.access_token_refresh_lead)
                .reduce(Option::or)
                .flatten()
                .unwrap(),
            secret: configurations
                .iter()
                .map(|v| v.secret.clone())
                .reduce(Option::or)
                .flatten()
                .unwrap(),
        }
    }
}

#[serde_as]
#[derive(Deserialize)]
struct OptionalConfiguration {
    #[serde_as(as = "Option<DurationSecondsWithFrac<String>>")]
    session_duration: Option<Duration>,
    #[serde_as(as = "Option<DurationSecondsWithFrac<String>>")]
    access_token_refresh_lead: Option<Duration>,
    secret: Option<String>,
}

impl Default for OptionalConfiguration {
    fn default() -> Self {
        Configuration::default().into()
    }
}

impl From<Configuration> for OptionalConfiguration {
    fn from(value: Configuration) -> Self {
        OptionalConfiguration {
            session_duration: Some(value.session_duration),
            access_token_refresh_lead: Some(value.access_token_refresh_lead),
            secret: Some(value.secret),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct AuthRequestData {
    pub csrf_state: String,
    pub pkce_token: String,
    pub nonce: Nonce,
}

#[derive(Serialize, Deserialize)]
struct AuthData {
    pub nonce: Nonce,
    pub refresh_token: String,
    pub access_token_exp: DateTime<Utc>,
    pub subject: String,
    pub name: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub groups: Option<Vec<String>>,
}

/// No additional claims.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
// In order to support serde flatten, this must be an empty struct rather than an empty
// tuple struct.
pub struct GroupAdditionalClaims {
    pub groups: Option<Vec<String>>,
}
impl AdditionalClaims for GroupAdditionalClaims {}

#[derive(Clone, Debug)]
struct ForwardAuthHeaders {
    https: bool,
    protocol: String,
    host: String,
    uri: String,
}

#[derive(Debug)]
enum AuthDataError {
    EmptySession,
    InvalidBase64,
    InvalidDeserialize,
}

fn set_response_by_auth_data_error(res: &mut Response, err: &AuthDataError) {
    match err {
        AuthDataError::EmptySession => res
            .status_code(StatusCode::UNAUTHORIZED)
            .render(Text::Plain("No active Session.")),
        AuthDataError::InvalidBase64 => {
            res.remove_cookie(SESSION_COOKIE_NAME);
            res.status_code(StatusCode::UNAUTHORIZED)
                .render(Text::Plain("Invalid Session"));
        }
        AuthDataError::InvalidDeserialize => {
            res.remove_cookie(SESSION_COOKIE_NAME);
            res.status_code(StatusCode::UNAUTHORIZED)
                .render(Text::Plain("Invalid Session"));
        }
    }
}

fn get_auth_data_from_request(req: &mut Request) -> Result<AuthData, AuthDataError> {
    let session = get_cookie(req, SESSION_COOKIE_NAME);
    if session.is_empty() {
        debug!("Session cookie was empty");
        return Err(AuthDataError::EmptySession);
    }

    debug!("Renewing Access Token for session {session}");

    let auth_data_value = match BASE64_STANDARD.decode(&session) {
        Ok(v) => v,
        Err(err) => {
            error!(
                "Unable to decode session cookie {session} {}",
                err.to_string()
            );
            return Err(AuthDataError::InvalidBase64);
        }
    };

    let auth_data: AuthData = match bincode2::deserialize(&auth_data_value) {
        Ok(v) => v,
        Err(err) => {
            error!("Unable to deserialize cookie {session} {}", err.to_string());
            return Err(AuthDataError::InvalidDeserialize);
        }
    };

    Ok(auth_data)
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
        csrf_state: csrf_state.into_secret(),
        pkce_token: pkce_verifier.secret().clone(),
        nonce,
    };

    let data = match bincode2::serialize(&auth_request_data) {
        Ok(v) => v,
        Err(err) => {
            error!("Failed to serialize auth data: {}", err.to_string());
            return res
                .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                .render(Text::Plain("Unable to serialize auth data"));
        }
    };

    //TODO: Encrypt data

    let cookie_value = BASE64_STANDARD.encode(data);

    res.add_cookie(
        Cookie::build((AUTHREQUEST_COOKIE_NAME, cookie_value))
            .http_only(headers.https)
            .secure(true)
            .build(),
    );

    debug!("Redirecting client to {}", authorize_url.to_string());

    res.render(Redirect::temporary(authorize_url.to_string()));
}

#[handler]
async fn status_handler(res: &mut Response) {
    res.status_code(StatusCode::NO_CONTENT);
}

#[handler]
async fn ok_handler(req: &mut Request, res: &mut Response) {
    let headers = res.headers_mut();

    if let Some(user) = req.headers().get("X-Forwarded-User") {
        trace!("X-Forwarded-User: {}", &user.to_str().unwrap());
        headers.insert("X-Forwarded-User", user.to_owned());
    }

    if let Some(username) = req.headers().get("X-Forwarded-Username") {
        trace!("X-Forwarded-Username: {}", &username.to_str().unwrap());
        headers.insert("X-Forwarded-Username", username.to_owned());
    }

    if let Some(email) = req.headers().get("X-Forwarded-Email") {
        trace!("X-Forwarded-Email: {}", &email.to_str().unwrap());
        headers.insert("X-Forwarded-Email", email.to_owned());
    }

    if let Some(name) = req.headers().get("X-Forwarded-Name") {
        trace!("X-Forwarded-Name: {}", &name.to_str().unwrap());
        headers.insert("X-Forwarded-Name", name.to_owned());
    }

    res.status_code(StatusCode::NO_CONTENT);
}

fn requires_refresh(req: &mut Request, _state: &mut PathState) -> bool {
    let auth_data = match get_auth_data_from_request(req) {
        Ok(v) => v,
        Err(_) => {
            return false;
        }
    };

    auth_data.access_token_exp < Utc::now()
}

#[handler]
async fn renew_access_token(req: &mut Request, res: &mut Response, depot: &mut Depot) {
    let session = get_cookie(req, SESSION_COOKIE_NAME);
    if session.is_empty() {
        debug!("Session cookie was empty");
        return res
            .status_code(StatusCode::UNAUTHORIZED)
            .render(Text::Plain("No active Session."));
    }

    debug!("Renewing Access Token for session {session}");

    let auth_data = match get_auth_data_from_request(req) {
        Ok(v) => v,
        Err(err) => {
            return set_response_by_auth_data_error(res, &err);
        }
    };

    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Htttp Client to build");

    let client = depot.obtain::<InitializedClient>().unwrap();
    let headers = depot.obtain::<ForwardAuthHeaders>().unwrap();
    let scopes = depot.obtain::<Vec<Scope>>().unwrap().to_owned();

    let token_response: openidconnect::StandardTokenResponse<
        openidconnect::IdTokenFields<
            openidconnect::EmptyAdditionalClaims,
            openidconnect::EmptyExtraTokenFields,
            openidconnect::core::CoreGenderClaim,
            openidconnect::core::CoreJweContentEncryptionAlgorithm,
            openidconnect::core::CoreJwsSigningAlgorithm,
        >,
        openidconnect::core::CoreTokenType,
    > = match client
        .exchange_refresh_token(&RefreshToken::new(auth_data.refresh_token.to_owned()))
        .expect("Refresh token to be valid")
        .add_scopes(scopes) // TODO: Test if required
        .request_async(&http_client)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            debug!("Refresh token: {}", auth_data.refresh_token);
            warn!("Error exchanging refresh token: {}", err);

            // TODO: Directly redirect to forward_auth_handler
            // forward_auth_handler.(req, res, depot).await;
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

    let id_token_verifier = client.id_token_verifier();
    let id_token = token_response.id_token().expect("IdToken to exist");

    let Ok(claims) = id_token.claims(&id_token_verifier, &auth_data.nonce) else {
        warn!("Unable to verify id_token '{}'", id_token.to_string());
        return res
            .status_code(StatusCode::UNAUTHORIZED)
            .render(Text::Plain("Invalid id_token"));
    };

    let data = match bincode2::serialize(&AuthData {
        refresh_token,
        access_token_exp: claims.expiration()
            - CONFIGURATION.get().unwrap().access_token_refresh_lead,
        ..auth_data
    }) {
        Ok(v) => v,
        Err(err) => {
            error!("Failed to serialize auth data: {}", err.to_string());
            return res
                .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                .render(Text::Plain("Unable to serialize auth data"));
        }
    };

    //TODO: Encrypt data

    let cookie_value = BASE64_STANDARD.encode(data);

    res.add_cookie(
        Cookie::build((SESSION_COOKIE_NAME, cookie_value))
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
    let session = get_cookie(req, SESSION_COOKIE_NAME);
    if session.is_empty() {
        debug!("unauthenticated request received");
        return false;
    }

    let auth_data = match get_auth_data_from_request(req) {
        Ok(v) => v,
        Err(err) => {
            error!("Unable to retrieve auth_data from cookie {err:?}");
            return false;
        }
    };

    let headers = req.headers_mut();

    headers.insert(
        "X-Forwarded-User",
        HeaderValue::from_str(&auth_data.subject).unwrap(),
    );

    if let Some(username) = &auth_data.username {
        headers.insert(
            "X-Forwarded-Username",
            HeaderValue::from_str(username).unwrap(),
        );
    }

    if let Some(email) = &auth_data.email {
        headers.insert("X-Forwarded-Email", HeaderValue::from_str(email).unwrap());
    }

    if let Some(name) = &auth_data.name {
        headers.insert("X-Forwarded-Name", HeaderValue::from_str(name).unwrap());
    }

    return true;
}

fn check_params(req: &mut Request, _state: &mut PathState) -> bool {
    let uri = get_header(req, "x-forwarded-uri");
    let authrequest_cookie = get_cookie(req, AUTHREQUEST_COOKIE_NAME);
    let state = get_query_param(&uri, "state");
    let code = get_query_param(&uri, "code");

    if authrequest_cookie.is_empty() {
        return false;
    }

    let Ok(decoded) = BASE64_STANDARD.decode(&authrequest_cookie) else {
        return false;
    };

    let Ok(auth_request) = bincode2::deserialize::<AuthRequestData>(&decoded) else {
        return false;
    };

    return !(uri.is_empty()
        || code.is_empty()
        || state.is_empty()
        || auth_request.csrf_state != state);
}

#[handler]
async fn set_cookie(req: &mut Request, res: &mut Response, depot: &mut Depot) {
    let client = depot.obtain::<InitializedClient>().unwrap();
    let headers = depot.obtain::<ForwardAuthHeaders>().unwrap();

    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Http Client to build");

    let code = get_query_param(&headers.uri, "code");
    if code.is_empty() {
        return res
            .status_code(StatusCode::BAD_GATEWAY)
            .render(Text::Plain("No Token in response."));
    }

    let authrequest_cookie = get_cookie(req, AUTHREQUEST_COOKIE_NAME);

    if authrequest_cookie.is_empty() {
        error!("Missing AuthRequest Cookie {AUTHREQUEST_COOKIE_NAME}");
        return res
            .status_code(StatusCode::BAD_REQUEST)
            .render(Text::Plain("Missing Required Cookie"));
    }

    let Ok(decoded) = BASE64_STANDARD.decode(&authrequest_cookie) else {
        error!("Unable to decode AuthRequest Cookie {authrequest_cookie}");
        return res
            .status_code(StatusCode::BAD_REQUEST)
            .render(Text::Plain("Invalid Cookie"));
    };

    let Ok(auth_request) = bincode2::deserialize::<AuthRequestData>(&decoded) else {
        error!("Unable to Deserialize AuthRequest Cookie {authrequest_cookie}");
        return res
            .status_code(StatusCode::BAD_REQUEST)
            .render(Text::Plain("Invalid Cookies"));
    };

    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .expect("Code to be present")
        .set_pkce_verifier(PkceCodeVerifier::new(auth_request.pkce_token))
        .request_async(&http_client)
        .await
        .unwrap();

    let id_token = token_response.id_token().unwrap().to_owned();
    let id_token_verifier = client.id_token_verifier();

    let Ok(claims) = id_token.claims(&id_token_verifier, &auth_request.nonce) else {
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

    let refresh_token = token_response.refresh_token().unwrap().secret().to_owned();

    res.remove_cookie(AUTHREQUEST_COOKIE_NAME);

    let data = match bincode2::serialize(&AuthData {
        nonce: auth_request.nonce,
        refresh_token,
        access_token_exp: claims.expiration()
            - CONFIGURATION.get().unwrap().access_token_refresh_lead,
        subject: claims.subject().to_string(),
        email: claims.email().map(|v| v.to_string()),
        name: claims.name().map(|v| v.get(None).unwrap().to_string()),
        username: claims.preferred_username().map(|v| v.to_string()),
        groups: None,
    }) {
        Ok(v) => v,
        Err(err) => {
            error!("Failed to serialize auth data: {}", err.to_string());
            return res
                .status_code(StatusCode::INTERNAL_SERVER_ERROR)
                .render(Text::Plain("Unable to serialize auth data"));
        }
    };

    //TODO: Encrypt data

    let cookie_value = BASE64_STANDARD.encode(data);

    res.add_cookie(
        Cookie::build((SESSION_COOKIE_NAME, cookie_value))
            .secure(headers.https)
            .http_only(true)
            .build(),
    );

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
    depot.inject(client);
    depot.inject(oidc_provider.scopes.clone());
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config_file_path = std::env::var("CONFIG").unwrap_or("/data/config.toml".to_string());

    if !fs::exists(&config_file_path).unwrap_or(false) {
        error!("Config file at {config_file_path} doesn't exist");
    }

    let contents = match fs::read_to_string(config_file_path) {
        Ok(v) => v,
        Err(err) => {
            error!("Unable to read config file \"{}\"", err.to_string());
            panic!();
        }
    };

    let config: Configuration = vec![
        envy::from_env::<OptionalConfiguration>().expect("Parsing environment variables to work"),
        toml::from_str::<OptionalConfiguration>(&contents).expect("Parsing Config file to work"),
    ]
    .into();

    debug!("Loaded Configuration from ENV & File:\n{config:?}");
    CONFIGURATION.get_or_init(move || config);

    let enhanced_security_enabled = match env::var("DISABLE_ENHANCED_SECURITY") {
        Ok(val) => !(val.to_lowercase().eq("true") || val.eq("1")),
        Err(_) => true,
    };

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
                .push(Router::with_filter_fn(requires_refresh).goal(renew_access_token))
                .push(Router::with_filter_fn(check_params).goal(set_cookie))
                .push(Router::new().goal(forward_auth_handler)),
        );

    let service = Service::new(router).hoop(Logger::new());
    let acceptor = TcpListener::new("0.0.0.0:3000").bind().await;

    Server::new(acceptor).serve(service).await;
}
