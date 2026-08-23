use std::collections::HashSet;

use url::Url;

/// Guards against open-redirect attacks by validating redirect targets
/// against a set of pre-approved origins.
///
/// After a server performs some work (e.g. login, OAuth callback), it
/// redirects the client back to a target supplied in the request. This
/// guard ensures that target actually belongs to one of the allowed
/// origins before issuing the redirect.
#[derive(Debug, Clone)]
pub struct RedirectGuard {
    base_url: Url,
    allowed_origins: HashSet<Url>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// The input could not be parsed as a URL.
    InvalidUrl(String),
    /// The URL has no origin (e.g. `data:` or relative URLs).
    MissingOrigin,
    /// The origin of the URL is not in the set of allowed origins.
    DisallowedOrigin,
    /// The URL contains userinfo (username/password), which is never
    /// legitimate for a redirect target.
    CredentialsNotAllowed,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::InvalidUrl(input) => write!(f, "invalid redirect url: {input}"),
            ValidationError::MissingOrigin => write!(f, "redirect url has no origin"),
            ValidationError::DisallowedOrigin => write!(f, "redirect origin not allowed"),
            ValidationError::CredentialsNotAllowed => {
                write!(f, "redirect url must not contain credentials")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

impl RedirectGuard {
    /// Creates a new guard with a base URL and a set of allowed origins.
    pub fn new(base_url: Url, allowed_origins: impl IntoIterator<Item = Url>) -> Self {
        Self {
            base_url,
            allowed_origins: allowed_origins.into_iter().collect(),
        }
    }

    /// The base URL this guard was constructed with.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Validates that `input` is a safe redirect target.
    ///
    /// Two kinds of targets are accepted:
    ///
    /// * **Path-relative targets** such as `/home` or `../settings` are
    ///   resolved against the guard's base URL and are always allowed,
    ///   since they can only ever land on the base origin.
    /// * **Absolute URLs** must resolve to one of the allowed origins.
    ///
    /// Returns the successfully resolved [`Url`] on success.
    pub fn validate(&self, input: &str) -> Result<Url, ValidationError> {
        // For special schemes the url crate treats `\` as `/`, so inputs like
        // `\\/evil.com` or `/\\evil.com` are protocol-relative URLs in
        // disguise. Normalize first so the checks below see them as such.
        let raw = input;
        // For special schemes the url crate treats `\` as `/`, so inputs like
        // `\\/evil.com` or `/\\evil.com` are protocol-relative URLs in
        // disguise. Normalize first so the checks below see them as such.
        let input = &*input.replace('\\', "/");

        // Protocol-relative URLs like "//evil.com" look path-like but would
        // inherit an arbitrary scheme; never allow them.
        if input.starts_with("//") {
            return Err(ValidationError::InvalidUrl(raw.to_owned()));
        }
        // Path-like targets (relative or root-relative) resolve against the
        // base URL. This is safe because `Url::join` cannot escape the base
        // origin — no amount of `/..` traversal changes scheme/host/port.
        if input.starts_with('/') || input.starts_with("./") || input.starts_with("../") {
            return self
                .base_url
                .join(input)
                .map_err(|_| ValidationError::InvalidUrl(raw.to_owned()));
        }

        let url = Url::parse(input).map_err(|_| ValidationError::InvalidUrl(raw.to_owned()))?;
        // Opaque origins (e.g. `data:`) can never match a Tuple allowed origin,
        // but reject them explicitly for a clearer error.
        if matches!(url.origin(), url::Origin::Opaque(_)) {
            return Err(ValidationError::MissingOrigin);
        }
        // Userinfo (username/password) has no place in a redirect target; it
        // only enables confusion/phishing even when the host itself is valid.
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ValidationError::CredentialsNotAllowed);
        }
        // Compare canonical origins (scheme/host/port) so path/query/fragment
        // differences don't matter.
        if self
            .allowed_origins
            .iter()
            .any(|allowed| allowed.origin() == url.origin())
        {
            Ok(url)
        } else {
            Err(ValidationError::DisallowedOrigin)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> RedirectGuard {
        RedirectGuard::new(
            Url::parse("https://app.example.com").unwrap(),
            [
                Url::parse("https://app.example.com").unwrap(),
                Url::parse("https://other.example.org").unwrap(),
                Url::parse("http://localhost:3000").unwrap(),
            ],
        )
    }

    #[test]
    fn accepts_allowed_origin() {
        let g = guard();
        assert_eq!(
            g.validate("https://app.example.com/dashboard").unwrap(),
            Url::parse("https://app.example.com/dashboard").unwrap()
        );
        assert!(g.validate("https://other.example.org/path?x=1").is_ok());
        assert!(g.validate("http://localhost:3000/callback").is_ok());
    }

    #[test]
    fn accepts_default_port_equivalence() {
        let g = RedirectGuard::new(
            Url::parse("https://a.example").unwrap(),
            [Url::parse("https://b.example").unwrap()],
        );
        // https default port 443 must be equivalent to an explicit :443.
        assert!(g.validate("https://b.example:443/x").is_ok());
    }

    #[test]
    fn allows_path_relative_targets_against_base() {
        let g = guard();
        assert_eq!(
            g.validate("/home").unwrap(),
            Url::parse("https://app.example.com/home").unwrap()
        );
        assert_eq!(
            g.validate("/a/b?x=1#frag").unwrap(),
            Url::parse("https://app.example.com/a/b?x=1#frag").unwrap()
        );
    }
    #[test]
    fn dot_segments_are_normalized_and_cannot_escape() {
        let g = guard();
        assert_eq!(
            g.validate("/a/../home").unwrap(),
            Url::parse("https://app.example.com/home").unwrap()
        );
        assert_eq!(
            g.validate("../home").unwrap(),
            Url::parse("https://app.example.com/home").unwrap()
        );
    }

    #[test]
    fn rejects_protocol_relative_urls() {
        let g = guard();
        // "//evil.com" looks path-like but is a protocol-relative URL; it has
        // no base to resolve against, so parsing must fail.
        assert_eq!(
            g.validate("//evil.com"),
            Err(ValidationError::InvalidUrl("//evil.com".into()))
        );
    }

    #[test]
    fn rejects_backslash_disguised_protocol_relative_urls() {
        let g = guard();
        // The url crate treats `\\` as `/` for special schemes; all of these
        // are protocol-relative redirects in disguise.
        for input in ["\\//evil.com", "\\/evil.com", "/\\evil.com", "\\\\evil.com"] {
            assert_eq!(
                g.validate(input),
                Err(ValidationError::InvalidUrl(input.to_owned())),
                "input: {input:?}"
            );
        }
    }

    #[test]
    fn backslashes_in_paths_are_harmless() {
        let g = guard();
        // After normalization these stay on the base origin.
        assert_eq!(
            g.validate("\\home").unwrap(),
            Url::parse("https://app.example.com/home").unwrap()
        );
    }
    #[test]
    fn rejects_disallowed_origin() {
        let g = guard();
        assert_eq!(
            g.validate("https://evil.example.net/phish"),
            Err(ValidationError::DisallowedOrigin)
        );
    }

    #[test]
    fn rejects_lookalike_origins() {
        let g = guard();
        // Subdomain and suffix tricks must not pass.
        assert_eq!(
            g.validate("https://evil-app.example.com"),
            Err(ValidationError::DisallowedOrigin)
        );
        assert_eq!(
            g.validate("https://app.example.com.evil.net"),
            Err(ValidationError::DisallowedOrigin)
        );
    }

    #[test]
    fn rejects_scheme_mismatch() {
        let g = guard();
        assert_eq!(
            g.validate("http://app.example.com"),
            Err(ValidationError::DisallowedOrigin)
        );
    }

    #[test]
    fn rejects_userinfo_host_confusion() {
        let g = guard();
        // Everything before `@` is userinfo, so the real host is evil.example.
        // These are rejected as containing credentials (checked first); even
        // without that check the origin comparison would reject them.
        for input in [
            "https://app.example.com@evil.example/",
            "https://app.example.com:443@evil.example/",
            "https://app.example.com%2F@evil.example/",
            "https://user:pass@evil.example/",
            "https://x@y@app.example.com/",
        ] {
            assert_eq!(
                g.validate(input),
                Err(ValidationError::CredentialsNotAllowed),
                "input: {input:?}"
            );
        }
    }

    #[test]
    fn rejects_credentials_in_target() {
        let g = guard();
        // Host is allowed, but credentials in a redirect target are a
        // phishing/confusion hazard.
        assert_eq!(
            g.validate("https://user@app.example.com/home"),
            Err(ValidationError::CredentialsNotAllowed)
        );
        assert_eq!(
            g.validate("https://user:pass@app.example.com/home"),
            Err(ValidationError::CredentialsNotAllowed)
        );
    }
    #[test]
    fn rejects_invalid_urls() {
        let g = guard();
        assert_eq!(
            g.validate("not a url at all"),
            Err(ValidationError::InvalidUrl("not a url at all".into()))
        );
    }

    #[test]
    fn rejects_opaque_origins() {
        let g = guard();
        assert_eq!(
            g.validate("data:text/html,hello"),
            Err(ValidationError::MissingOrigin)
        );
    }

    #[test]
    fn empty_allowlist_rejects_everything() {
        let g = RedirectGuard::new(Url::parse("https://app.example.com").unwrap(), []);
        assert_eq!(
            g.validate("https://app.example.com"),
            Err(ValidationError::DisallowedOrigin)
        );
    }

    #[test]
    fn base_url_accessor() {
        let g = guard();
        assert_eq!(
            g.base_url(),
            &Url::parse("https://app.example.com").unwrap()
        );
    }
}
