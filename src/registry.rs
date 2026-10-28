//! Verification of credentials with a container registry, as `docker login`
//! does: the registry answers an unauthenticated request with the
//! authentication it expects, either basic or tokens from a token server
//! (https://distribution.github.io/distribution/spec/auth/token/).

use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ureq::http::Response;
use ureq::tls::{RootCerts, TlsConfig};
use ureq::{Agent, Body, RequestBuilder};

use crate::check::Status;
use crate::docker::Credentials;

/// Sent to token servers, which require a client id but don't check it.
const CLIENT_ID: &str = "lock-indicator";

pub fn verify(api_url: &str, credentials: &Credentials, timeout: Duration) -> Status {
    match authenticate(api_url, credentials, Instant::now() + timeout) {
        Ok(Verdict::Accepted) => Status::unlocked().with_detail("accepted by the registry"),
        Ok(Verdict::Anonymous) => {
            Status::unlocked().with_detail("the registry does not require credentials")
        }
        Ok(Verdict::Rejected(status)) => {
            Status::locked(format!("rejected by the registry (HTTP {status})"))
        }
        Err(err) => Status::unknown(err),
    }
}

enum Verdict {
    Accepted,
    Anonymous,
    Rejected(u16),
}

fn authenticate(
    api_url: &str,
    credentials: &Credentials,
    deadline: Instant,
) -> Result<Verdict, String> {
    let agent: Agent = Agent::config_builder()
        .http_status_as_error(false)
        // System CA certificates, which private registries often need.
        .tls_config(
            TlsConfig::builder()
                .root_certs(RootCerts::PlatformVerifier)
                .build(),
        )
        .user_agent(concat!("lock-indicator/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let ping = format!("{api_url}/v2/");
    let response = within(agent.get(&ping), deadline)
        .call()
        .map_err(|err| unreachable(&ping, err))?;
    let challenges = match response.status().as_u16() {
        200 => return Ok(Verdict::Anonymous),
        401 => challenges(&response),
        status => return Err(format!("unexpected HTTP {status} from {ping}")),
    };
    let bearer = challenges
        .iter()
        .find(|challenge| challenge.scheme.eq_ignore_ascii_case("bearer"));

    let (url, result) = match (credentials, bearer) {
        // A token from the token server proves the credentials valid.
        (Credentials::Basic { username, password }, Some(challenge)) => {
            let realm = challenge.realm(&ping)?;
            let mut request = agent
                .get(realm)
                .query("account", username)
                .query("client_id", CLIENT_ID)
                .header("Authorization", basic_auth(username, password));
            if let Some(service) = challenge.param("service") {
                request = request.query("service", service);
            }
            (realm, within(request, deadline).call())
        }
        (Credentials::Identity(token), Some(challenge)) => {
            let realm = challenge.realm(&ping)?;
            let mut form = vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", token.as_str()),
                ("client_id", CLIENT_ID),
            ];
            if let Some(service) = challenge.param("service") {
                form.push(("service", service));
            }
            (realm, within(agent.post(realm), deadline).send_form(form))
        }
        (Credentials::Identity(_), None) => {
            return Err("identity token for a registry without token server".into());
        }
        (Credentials::Basic { username, password }, None) => {
            let request = agent
                .get(&ping)
                .header("Authorization", basic_auth(username, password));
            (ping.as_str(), within(request, deadline).call())
        }
        (Credentials::Bearer(token), _) => {
            let request = agent
                .get(&ping)
                .header("Authorization", format!("Bearer {token}"));
            (ping.as_str(), within(request, deadline).call())
        }
    };
    match result
        .map_err(|err| unreachable(url, err))?
        .status()
        .as_u16()
    {
        200 => Ok(Verdict::Accepted),
        // 400: the `invalid_grant` error of an expired or revoked refresh token.
        status @ (400 | 401 | 403) => Ok(Verdict::Rejected(status)),
        status => Err(format!("unexpected HTTP {status} from {url}")),
    }
}

/// Limits the request to the time left before `deadline`.
fn within<B>(request: RequestBuilder<B>, deadline: Instant) -> RequestBuilder<B> {
    let left = deadline.saturating_duration_since(Instant::now());
    request.config().timeout_global(Some(left)).build()
}

fn unreachable(url: &str, err: ureq::Error) -> String {
    format!("cannot reach {url}: {err}")
}

fn basic_auth(username: &str, password: &str) -> String {
    format!(
        "Basic {}",
        STANDARD.encode(format!("{username}:{password}"))
    )
}

/// A `WWW-Authenticate` challenge, e.g.
/// `Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`.
#[derive(Debug, PartialEq, Eq)]
struct Challenge {
    scheme: String,
    params: Vec<(String, String)>,
}

impl Challenge {
    fn parse(header: &str) -> Challenge {
        let header = header.trim();
        let (scheme, mut rest) = header.split_once(' ').unwrap_or((header, ""));
        let mut params = Vec::new();
        loop {
            rest = rest.trim_start_matches([' ', ',']);
            let Some((key, after)) = rest.split_once('=') else {
                break;
            };
            let (value, after) = match after.strip_prefix('"') {
                Some(quoted) => quoted.split_once('"').unwrap_or((quoted, "")),
                None => after.split_once(',').unwrap_or((after, "")),
            };
            params.push((key.trim().to_string(), value.trim().to_string()));
            rest = after;
        }
        Challenge {
            scheme: scheme.to_string(),
            params,
        }
    }

    fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn realm(&self, ping: &str) -> Result<&str, String> {
        self.param("realm")
            .ok_or_else(|| format!("no token server in the challenge of {ping}"))
    }
}

fn challenges(response: &Response<Body>) -> Vec<Challenge> {
    response
        .headers()
        .get_all("www-authenticate")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(Challenge::parse)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;
    use crate::check::State;

    struct Request {
        method: String,
        target: String,
        authorization: Option<String>,
        body: String,
    }

    /// Starts an HTTP server answering each request with `respond`, called with
    /// the server's base URL. Returns that URL.
    fn serve(respond: impl Fn(&str, &Request) -> (u16, String) + Send + 'static) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let base = url.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let request = read_request(&mut BufReader::new(&stream));
                let (status, header) = respond(&base, &request);
                let response = format!(
                    "HTTP/1.1 {status} X\r\n{header}Content-Length: 2\r\nConnection: close\r\n\r\n{{}}"
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        url
    }

    fn read_request(reader: &mut impl BufRead) -> Request {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap().to_string();
        let target = parts.next().unwrap().to_string();
        let (mut authorization, mut length) = (None, 0);
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let Some((name, value)) = line.trim_end().split_once(": ") else {
                break;
            };
            match name.to_ascii_lowercase().as_str() {
                "authorization" => authorization = Some(value.to_string()),
                "content-length" => length = value.parse().unwrap(),
                _ => {}
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        Request {
            method,
            target,
            authorization,
            body: String::from_utf8(body).unwrap(),
        }
    }

    fn basic(password: &str) -> Credentials {
        Credentials::Basic {
            username: "me@example.com".into(),
            password: password.into(),
        }
    }

    fn verify(url: &str, credentials: &Credentials) -> Status {
        super::verify(url, credentials, Duration::from_secs(5))
    }

    #[test]
    fn basic_authentication() {
        let url =
            serve(
                |_, request| match (request.target.as_str(), request.authorization.as_deref()) {
                    ("/v2/", None) => (401, "WWW-Authenticate: Basic realm=\"test\"\r\n".into()),
                    ("/v2/", Some(auth)) if auth == basic_auth("me@example.com", "good") => {
                        (200, String::new())
                    }
                    _ => (401, String::new()),
                },
            );
        assert_eq!(
            verify(&url, &basic("good")),
            Status::unlocked().with_detail("accepted by the registry")
        );
        assert_eq!(
            verify(&url, &basic("bad")),
            Status::locked("rejected by the registry (HTTP 401)")
        );
    }

    #[test]
    fn token_server() {
        let url = serve(|base, request| {
            let challenge = format!(
                "WWW-Authenticate: Bearer realm=\"{base}/token\",service=\"test.registry\"\r\n"
            );
            let valid = request.authorization.as_deref()
                == Some(&basic_auth("me@example.com", "good"))
                && request.target.contains("service=test.registry")
                && request.target.contains("account=me%40example.com");
            match (
                request.target.split('?').next().unwrap(),
                request.method.as_str(),
            ) {
                ("/v2/", _) => (401, challenge),
                ("/token", "GET") if valid => (200, String::new()),
                ("/token", "POST") if request.body.contains("refresh_token=good") => {
                    (200, String::new())
                }
                ("/token", "POST") => (400, String::new()),
                _ => (401, String::new()),
            }
        });
        assert_eq!(verify(&url, &basic("good")).state, State::Unlocked);
        assert_eq!(
            verify(&url, &basic("bad")),
            Status::locked("rejected by the registry (HTTP 401)")
        );
        let identity = |token: &str| Credentials::Identity(token.into());
        assert_eq!(verify(&url, &identity("good")).state, State::Unlocked);
        assert_eq!(
            verify(&url, &identity("bad")),
            Status::locked("rejected by the registry (HTTP 400)")
        );
    }

    #[test]
    fn registry_without_authentication() {
        let url = serve(|_, _| (200, String::new()));
        assert_eq!(
            verify(&url, &basic("any")),
            Status::unlocked().with_detail("the registry does not require credentials")
        );
    }

    #[test]
    fn unreachable_registry() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let status = verify(&url, &basic("any"));
        assert_eq!(status.state, State::Unknown);
        assert!(
            status
                .detail
                .unwrap()
                .starts_with(&format!("cannot reach {url}/v2/"))
        );
    }

    #[test]
    fn parses_challenges() {
        let challenge = Challenge::parse(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:a/b:pull,push""#,
        );
        assert_eq!(challenge.scheme, "Bearer");
        assert_eq!(
            challenge.param("realm"),
            Some("https://auth.docker.io/token")
        );
        assert_eq!(challenge.param("Service"), Some("registry.docker.io"));
        assert_eq!(challenge.param("scope"), Some("repository:a/b:pull,push"));
        let challenge = Challenge::parse("Basic realm=Registry, charset=UTF-8");
        assert_eq!(challenge.scheme, "Basic");
        assert_eq!(challenge.param("realm"), Some("Registry"));
        assert_eq!(challenge.param("charset"), Some("UTF-8"));
        assert_eq!(Challenge::parse("Basic").params, []);
    }
}
