#![no_main]

use std::collections::HashSet;
use std::str::FromStr;

use libfuzzer_sys::fuzz_target;
use url::Url;

use fuzz::RedirectGuard;

fuzz_target!(|data: &[u8]| {
    // The input is split at the first newline: the first line selects the
    // base URL / allowlist configuration, the rest is the redirect target
    // under test. This lets one target cover both the path-relative and the
    // absolute-URL code paths with a compact corpus.
    let (config_line, target) = match data.iter().position(|&b| b == b'\n') {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => return,
    };

    let config_line = match std::str::from_utf8(config_line) {
        Ok(s) => s,
        Err(_) => return,
    };
    let target = String::from_utf8_lossy(target);

    let mut lines = config_line.split('|');
    let base: Url = match lines.next().map(Url::from_str) {
        Some(Ok(base)) => base,
        _ => return,
    };
    let allowed: HashSet<Url> = lines.filter_map(|s| s.parse().ok()).collect();
    let allowed_origins: HashSet<url::Origin> = allowed.iter().map(|u| u.origin()).collect();

    let guard = RedirectGuard::new(base.clone(), allowed);
    if let Ok(url) = guard.validate(&target) {
        // Core security invariant: anything `validate` accepts must resolve
        // to the base origin (path-relative targets) or an allowlisted
        // origin (absolute URLs). Anything else is an open redirect bug.
        assert!(
            url.origin() == base.origin() || allowed_origins.contains(&url.origin()),
            "redirect escaped allowlist: {url} (target {target:?}, base {base})"
        );
    }
});
