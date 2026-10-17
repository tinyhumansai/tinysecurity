//! Normalization of a registered policy's base `forbidden_paths`.
//!
//! The base list is host-authored and may carry entries written for display or
//! portability. Registration folds them into one absolute list so evaluation never
//! interprets a relative or tilde entry against the module's own working directory
//! or environment. The accepted forms and their meaning are specified in
//! `docs/specs/scoped-policies.md`.
use crate::path;
use std::path::{Path, PathBuf};
use tinysecurity_bus::{Error, PolicyConfig, Result};

/// Expand a leading `~` against the registered home, or `None` when `entry` has none.
fn expand_home(entry: &str, home: Option<&Path>) -> Option<Result<PathBuf>> {
    let tail = entry.strip_prefix('~')?;
    let tail = if tail.is_empty() {
        ""
    } else {
        // `~user` and other forms cannot be resolved without the module reading
        // the environment, which it never does.
        tail.strip_prefix(['/', '\\'])?
    };
    Some(home.ok_or(Error::InvalidArguments).map(|home| {
        tail.split(['/', '\\'])
            .filter(|part| !part.is_empty())
            .fold(home.to_path_buf(), |mut path, part| {
                path.push(part);
                path
            })
    }))
}

fn traverses(entry: &str) -> bool {
    entry.contains('\0') || entry.split(['/', '\\']).any(crate::path::parent_segment)
}

fn resolve_entry(entry: &str, action_dir: &Path, home: Option<&Path>) -> Result<PathBuf> {
    if entry.is_empty() || traverses(entry) {
        return Err(Error::InvalidArguments);
    }
    if entry.starts_with('~') {
        return expand_home(entry, home).unwrap_or(Err(Error::InvalidArguments));
    }
    let candidate = Path::new(entry);
    if candidate.is_absolute() {
        return Ok(candidate.to_path_buf());
    }
    // A rooted path without a drive is ambiguous on Windows; joining would discard
    // the action directory, so it is refused rather than guessed.
    if candidate.has_root() || !action_dir.is_absolute() {
        return Err(Error::InvalidArguments);
    }
    // Push component by component so the result uses one native separator.
    Ok(candidate
        .components()
        .fold(action_dir.to_path_buf(), |mut path, part| {
            if let std::path::Component::Normal(name) = part {
                path.push(name);
            }
            path
        }))
}

/// Absolute forbidden roots equivalent to the registered entries.
///
/// `~` expands against `home` (the registered path scope's home, else the command
/// scope's); relative entries resolve against `policy.action_dir`; entries inside
/// the unconditional floor are dropped because the floor already denies them.
///
/// # Errors
/// Rejects empty entries, `..` segments, NUL bytes, `~user` forms, a `~` without a
/// registered home and relative entries that cannot be anchored.
pub(crate) fn effective_forbidden(
    policy: &PolicyConfig,
    home: Option<&Path>,
) -> Result<Vec<String>> {
    let action_dir = Path::new(&policy.action_dir);
    let mut out: Vec<String> = Vec::new();
    for entry in &policy.forbidden_paths {
        // The floor is spelled the same on every OS, so a Unix floor entry in a
        // portable default list is a no-op on Windows rather than "not absolute".
        if !entry.starts_with('~') && !traverses(entry) && !entry.is_empty() && path::floor(entry) {
            continue;
        }
        let resolved = resolve_entry(entry, action_dir, home)?
            .to_string_lossy()
            .into_owned();
        if path::floor(&resolved) {
            continue;
        }
        if !out.contains(&resolved) {
            out.push(resolved);
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "scoped_forbidden_tests.rs"]
mod tests;
