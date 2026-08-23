# RedirectGuard

A small Rust library that guards against [open-redirect attacks](https://owasp.org/www-community/attacks/Open_redirect).
After a server performs some work (login, OAuth callback, …) it often needs to
redirect the client to a target taken from the request. `RedirectGuard`
validates such a target against a base URL and a set of allowed origins before
the redirect is issued:

* **Path-relative targets** (`/home`, `../settings`) are resolved against the
  guard's base URL and are always accepted — they can only ever land on the
  base origin.
* **Absolute URLs** must resolve to one of the allowlisted origins.
* Everything that smells like an open redirect is rejected: protocol-relative
  URLs (`//evil.com`), backslash-disguised variants (`\//evil.com`), userinfo /
  credential tricks (`https://app.example.com@evil.example/`), opaque schemes
  (`data:`), lookalike hosts, scheme mismatches, and so on.

## Usage

```rust
use url::Url;
use fuzz::RedirectGuard;

let guard = RedirectGuard::new(
    Url::parse("https://app.example.com").unwrap(),
    [Url::parse("https://other.example.org").unwrap()],
);

guard.validate("/dashboard")?;                                  // Ok — lands on the base origin
guard.validate("https://other.example.org/path?x=1")?;          // Ok — allowlisted origin
guard.validate("https://app.example.com@evil.example/")?;       // Err: CredentialsNotAllowed
```

## Fuzz testing

The validation logic is security-critical, so it is continuously fuzz-tested
with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer +
ASan). The fuzzer's invariant: **anything `validate()` accepts must resolve to
the base origin or an explicitly allowlisted origin** — anything else is an
open-redirect bug.

### Setup

Fuzzing requires Rust **nightly** (for `-Zsanitizer=address` and coverage
instrumentation). Nightly is intentionally *not* the default toolchain here —
it is selected per invocation with `cargo +nightly`, so normal development is
unaffected.

```sh
# 1. Nightly toolchain (minimal profile + llvm-tools for coverage)
rustup toolchain install nightly --profile minimal --component llvm-tools-preview

# 2. cargo-fuzz
cargo install cargo-fuzz --locked
```

### Project layout

| Path | Purpose |
| --- | --- |
| `src/lib.rs` | The `RedirectGuard` implementation under test. |
| `fuzz/` | Auto-generated cargo-fuzz crate (workspace member). |
| `fuzz/fuzz_targets/redirect_guard.rs` | The fuzz target (harness). Input format: first line is `base-url\|allowed-origin[\|allowed-origin…]`, everything after the newline is the redirect target under test. Asserts that every URL returned by `validate()` has the base or an allowlisted origin. |
| `fuzz/corpus/redirect_guard/` | Seed corpus plus accumulated fuzzer findings across runs. The initial seeds were derived from the unit tests in `src/lib.rs` (protocol-relative tricks, userinfo confusion, lookalike origins, dot-segment traversal, …). |
| `fuzz/artifacts/redirect_guard/` | Crash artifacts written by libFuzzer when the invariant is violated. **Never delete these** until the finding is resolved. |
| `fuzz/Cargo.toml` | Manifest of the fuzz crate (depends on `libfuzzer-sys` and the root crate). |

### Running

Always invoke through the `+nightly` override:

```sh
# Build check only
cargo +nightly fuzz build

# Replay just the seed corpus / existing corpus (-runs=0 executes no mutations)
cargo +nightly fuzz run redirect_guard -- -runs=0

# Fuzz indefinitely (Ctrl-C to stop); new inputs are added to fuzz/corpus/
cargo +nightly fuzz run redirect_guard

# Fuzz for a bounded time, e.g. 10 minutes (useful locally / in CI)
cargo +nightly fuzz run redirect_guard -- -max_total_time=600

# Only use the existing corpus without growing it indefinitely
cargo +nightly fuzz run redirect_guard -- -max_total_time=60 -rss_limit_mb=4096
```

Useful extras:

```sh
# Shrink a crash artifact to a minimal reproducer
cargo +nightly fuzz tmin redirect_guard fuzz/artifacts/redirect_guard/<crash-file>

# Re-run a specific input to reproduce a finding
cargo +nightly fuzz run redirect_guard fuzz/artifacts/redirect_guard/<crash-file>
```

### If fuzzing finds something

libFuzzer stops on the first violation and writes an artifact such as
`fuzz/artifacts/redirect_guard/crash-<hash>`. The file content *is* the failing
input (first line = config, remainder = target).

1. **Preserve the artifact.** Copy it out of `fuzz/artifacts/` (e.g. into a
   bug report or a new corpus entry) — rerunning the fuzzer may overwrite it.
2. **Reproduce deterministically:**
   ```sh
   cargo +nightly fuzz run redirect_guard fuzz/artifacts/redirect_guard/<crash-file>
   ```
3. **Minimize it** if the input is unwieldy:
   ```sh
   cargo +nightly fuzz tmin redirect_guard fuzz/artifacts/redirect_guard/<crash-file>
   ```
4. **Classify:** decide whether the harness invariant was genuinely broken
   (a real bug in `RedirectGuard`, e.g. a parse confusion that escapes the
   allowlist) or whether the harness itself made a wrong assumption.
5. **Fix and lock in:** add a regression unit test to `src/lib.rs` and a copy
   of the crashing input to `fuzz/corpus/redirect_guard/` so it is replayed on
   every future run.
6. **Resume fuzzing** to confirm the fix and look for further issues.
