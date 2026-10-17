//! Native filesystem authorization for immutable host scopes.
use std::path::{Path, PathBuf};
use tinysecurity_bus::{
    PathAccess, PathCheckKind, PathErrorCategory as Rejection, PathPolicy, PathValidationResult,
};

pub(crate) fn expand(scope: &PathPolicy, path: &str) -> PathBuf {
    path.strip_prefix("~/")
        .and_then(|tail| {
            scope.home_dir.as_ref().map(|home| {
                tail.split('/').filter(|part| !part.is_empty()).fold(
                    home.clone(),
                    |mut path, part| {
                        path.push(part);
                        path
                    },
                )
            })
        })
        .unwrap_or_else(|| PathBuf::from(path))
}
/// Unconditional acting-scope correctness, credential and critical-system floor.
/// Installation roots (`/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/library`, `/dev`)
/// deliberately remain host-configurable forbidden paths, preserving the host's
/// explicit grants and disabled-policy contract. Bootstrap `Check` retains its
/// separate conservative floor; these are different authorization contracts.
#[must_use]
pub fn protected_path(path: &Path) -> bool {
    let normalized = path
        .to_string_lossy()
        .to_ascii_lowercase()
        .replace('\\', "/");
    let normalized = crate::path::strip_native_namespace(&normalized);
    let segments: Vec<_> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    if normalized.contains('\0')
        || normalized.contains("..%2f")
        || normalized.contains("%2f..")
        || segments
            .iter()
            .any(|segment| crate::path::parent_segment(segment))
        || crate::path::credential_store(&segments)
    {
        return true;
    }
    crate::path::CRITICAL_ROOTS
        .iter()
        .any(|prefix| normalized == *prefix || normalized.starts_with(&format!("{prefix}/")))
        || crate::path::windows_system_root(normalized)
}
/// Resolve prospective paths through their deepest existing ancestor.
///
/// # Errors
/// Returns the filesystem error for broken symlinks, permission errors, or missing roots.
pub fn resolve_ancestor(path: &Path) -> std::io::Result<PathBuf> {
    resolve_ancestor_with(path, Path::canonicalize, |path| {
        path.symlink_metadata().map(|_| ())
    })
}
fn resolve_ancestor_with(
    path: &Path,
    mut canonicalize: impl FnMut(&Path) -> std::io::Result<PathBuf>,
    mut metadata: impl FnMut(&Path) -> std::io::Result<()>,
) -> std::io::Result<PathBuf> {
    let mut ancestor = path.to_path_buf();
    let mut suffix = Vec::new();
    loop {
        match canonicalize(&ancestor) {
            Ok(mut resolved) => {
                for part in suffix.iter().rev() {
                    resolved.push(part);
                }
                return Ok(resolved);
            }
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound {
                    return Err(error);
                }
                match metadata(&ancestor) {
                    Ok(()) => return Err(error),
                    Err(probe) if probe.kind() == std::io::ErrorKind::NotFound => {}
                    Err(probe) => return Err(probe),
                }
                suffix.push(ancestor.file_name().ok_or(error)?.to_os_string());
                if !ancestor.pop() {
                    return Err(std::io::Error::other("no resolvable ancestor"));
                }
            }
        }
    }
}
pub(crate) fn reservation_exception_root(root: &Path, exception: &Path) -> Option<PathBuf> {
    let root = resolve_ancestor(root).ok()?;
    let exception = resolve_ancestor(exception).ok()?;
    (exception != root && exception.starts_with(&root)).then_some(exception)
}
pub(crate) fn canonical_or_original(path: &Path) -> PathBuf {
    resolve_ancestor(path).unwrap_or_else(|_| path.to_path_buf())
}
fn within(path: &Path, root: &Path) -> bool {
    resolve_ancestor(root).is_ok_and(|resolved| path.starts_with(resolved))
}
// Denial comparisons fold conservatively on Windows/macOS, including normalizing
// filesystems. Grants and reservation exceptions remain canonical exact matches.
#[cfg(any(windows, target_os = "macos", test))]
fn denial_fold(value: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    value.nfc().collect::<String>().to_uppercase()
}
#[cfg(any(windows, test))]
fn windows_denial_fold(value: &str) -> String {
    // Prefix components are not filenames (C: and extended/UNC prefixes).
    if (value.len() == 2 && value.as_bytes()[0].is_ascii_alphabetic() && value.ends_with(':'))
        || value.starts_with('\\')
    {
        return denial_fold(value);
    }
    denial_fold(
        value
            .split(':')
            .next()
            .unwrap_or(value)
            .trim_end_matches(['.', ' ']),
    )
}
#[cfg(any(windows, test))]
fn windows_ambiguous_relative(value: &str) -> bool {
    value.starts_with(['/', '\\'])
        || (value.as_bytes().get(1) == Some(&b':') && value.as_bytes()[0].is_ascii_alphabetic())
}
fn ambiguous_native(path: &Path) -> bool {
    #[cfg(windows)]
    {
        !path.is_absolute() && windows_ambiguous_relative(&path.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
}
fn deny_component_eq(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> bool {
    #[cfg(windows)]
    {
        windows_denial_fold(&left.to_string_lossy())
            == windows_denial_fold(&right.to_string_lossy())
    }
    #[cfg(target_os = "macos")]
    {
        denial_fold(&left.to_string_lossy()) == denial_fold(&right.to_string_lossy())
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        left == right
    }
}
pub(crate) fn deny_starts_with(path: &Path, root: &Path) -> bool {
    let mut candidate = path.components();
    root.components().all(|part| {
        candidate
            .next()
            .is_some_and(|next| deny_component_eq(next.as_os_str(), part.as_os_str()))
    })
}
pub(crate) fn within_denied(path: &Path, root: &Path) -> bool {
    deny_starts_with(path, root) || deny_starts_with(path, &canonical_or_original(root))
}
fn candidate(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() || protected_path(path) {
        return None;
    }
    resolve_ancestor(path)
        .ok()
        .filter(|resolved| !protected_path(resolved))
}
fn metadata_present(result: std::io::Result<()>) -> std::result::Result<bool, Rejection> {
    match result {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(Rejection::Resolution),
    }
}
/// Compiled immutable filesystem scope issued by [`crate::PathPolicyRegistry`].
/// Direct external construction is intentionally unavailable:
/// ```compile_fail
/// use tinysecurity_policy::{PathScope, PathPolicy};
/// fn bypass_registration(policy: PathPolicy) -> PathScope { PathScope(policy) }
/// ```
#[derive(Clone, Debug)]
pub struct PathScope(pub(crate) PathPolicy);
impl std::ops::Deref for PathScope {
    type Target = PathPolicy;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl PathScope {
    /// Construct only after the registry has admitted every configured root.
    pub(crate) fn registered(policy: PathPolicy) -> Self {
        Self(policy)
    }
    pub(crate) fn policy(&self) -> &PathPolicy {
        &self.0
    }

    /// Whether the path is under a host state reservation, including aliased/missing descendants.
    #[must_use]
    pub fn internal(&self, path: &Path) -> bool {
        let resolved = canonical_or_original(path);
        self.reserved_paths.iter().any(|reservation| {
            if !within_denied(&resolved, &reservation.path) {
                return false;
            }
            let root = canonical_or_original(&reservation.path);
            if reservation.children_only
                && deny_starts_with(&resolved, &root)
                && resolved.components().count() == root.components().count()
            {
                return false;
            }
            !reservation.exceptions.iter().any(|exception| {
                reservation_exception_root(&reservation.path, exception)
                    .is_some_and(|exception| resolved.starts_with(exception))
            })
        }) || self.reserved_prefixes.iter().any(|reservation| {
            let root = canonical_or_original(&reservation.root);
            if !deny_starts_with(&resolved, &root) {
                return false;
            }
            resolved
                .components()
                .nth(root.components().count())
                .is_some_and(|component| {
                    let name = component.as_os_str().to_string_lossy();
                    #[cfg(any(windows, target_os = "macos"))]
                    let (name, prefix) = (denial_fold(&name), denial_fold(&reservation.prefix));
                    #[cfg(not(any(windows, target_os = "macos")))]
                    let prefix = reservation.prefix.clone();
                    name.strip_prefix(&prefix)
                        .is_some_and(|suffix| !suffix.is_empty())
                })
        })
    }
    /// Whether an explicitly trusted root grants this operation.
    #[must_use]
    pub fn trusted(&self, path: &Path, write: bool) -> bool {
        let Some(resolved) = candidate(path) else {
            return false;
        };
        self.trusted_canonical(&resolved, write)
    }
    pub(crate) fn trusted_canonical(&self, path: &Path, write: bool) -> bool {
        self.trusted_roots.iter().any(|root| {
            (!write || root.access == PathAccess::ReadWrite) && within(path, &root.path)
        })
    }

    /// Resolved-path containment check, independent of approval policy.
    #[must_use]
    pub fn resolved_allowed(&self, path: &Path, write: bool) -> bool {
        let Some(resolved) = candidate(path) else {
            return false;
        };
        let path = resolved.as_path();
        if !self.enabled {
            return true;
        }
        if self.internal(path)
            || (write
                && self
                    .readonly_paths
                    .iter()
                    .any(|root| within_denied(path, root)))
        {
            return false;
        }
        within(path, &self.workspace_dir) || self.trusted_canonical(path, write)
    }
    fn forbidden(&self, path: &Path, write: bool) -> bool {
        if !self.enabled || self.trusted(path, write) {
            return false;
        }
        let workspace = canonical_or_original(&self.workspace_dir);
        self.forbidden_paths.iter().any(|entry| {
            let forbidden = expand(self, entry);
            if forbidden.is_absolute()
                && (deny_starts_with(&workspace, &forbidden)
                    || deny_starts_with(&workspace, &canonical_or_original(&forbidden)))
            {
                return false;
            }
            let forbidden = if forbidden.is_absolute() {
                forbidden
            } else {
                workspace.join(forbidden)
            };
            within_denied(path, &forbidden)
        })
    }
    fn absolute(&self, input: &str) -> PathBuf {
        let expanded = expand(self, input);
        if expanded.is_absolute() {
            expanded
        } else {
            self.action_dir.join(expanded)
        }
    }
    /// String and existing-ancestor policy checks; actual I/O must also use validation.
    #[must_use]
    pub fn string_allowed(&self, input: &str) -> bool {
        if input.is_empty() {
            return false;
        }
        let expanded = expand(self, input);
        if ambiguous_native(&expanded) || protected_path(&expanded) {
            return false;
        }
        if !expanded.is_absolute()
            && expanded
                .components()
                .filter(|part| !matches!(part, std::path::Component::CurDir))
                .count()
                == 1
            && self.reserved_names.iter().any(|name| {
                expanded
                    .file_name()
                    .is_some_and(|file| deny_component_eq(file, std::ffi::OsStr::new(name)))
            })
        {
            return false;
        }
        let absolute = self.absolute(input);
        if protected_path(&absolute) {
            return false;
        }
        if !self.enabled {
            return resolve_ancestor(&absolute).is_ok_and(|resolved| !protected_path(&resolved));
        }
        if self.internal(&absolute) {
            return false;
        }
        let trusted = self.trusted(&expanded, false);
        if self.workspace_only && expanded.is_absolute() && !trusted {
            return false;
        }
        let Ok(resolved) = resolve_ancestor(&absolute) else {
            return false;
        };
        if protected_path(&resolved) || self.internal(&resolved) {
            return false;
        }
        if self.workspace_only
            && !within(&resolved, &self.workspace_dir)
            && !self.trusted(&resolved, false)
        {
            return false;
        }
        if self.forbidden(&resolved, false) {
            return false;
        }
        true
    }
    /// Validate an existing read target or prospective write target.
    #[must_use]
    pub fn validate(&self, input: &str, write: bool) -> PathValidationResult {
        let result = self.validate_inner(input, write);
        match result {
            Ok(resolved) => PathValidationResult::Allowed { resolved },
            Err(category) => PathValidationResult::Denied { category },
        }
    }
    fn validate_inner(&self, input: &str, write: bool) -> std::result::Result<PathBuf, Rejection> {
        if input.is_empty()
            || ambiguous_native(&expand(self, input))
            || (write
                && Path::new(input.strip_prefix("~/").unwrap_or(input))
                    .file_name()
                    .is_none())
        {
            return Err(Rejection::InvalidPath);
        }
        if protected_path(&expand(self, input)) {
            return Err(Rejection::Protected);
        }
        if !self.string_allowed(input) {
            return Err(match resolve_ancestor(&self.absolute(input)) {
                Err(_) => Rejection::Resolution,
                Ok(resolved) if protected_path(&resolved) => Rejection::Protected,
                Ok(_) => Rejection::PolicyDenied,
            });
        }
        let absolute = self.absolute(input);
        let resolved = if write {
            let parent = absolute.parent().ok_or(Rejection::InvalidPath)?;
            let filename = absolute.file_name().ok_or(Rejection::InvalidPath)?;
            // Existing target symlinks must also be checked: writing follows them.
            if metadata_present(absolute.symlink_metadata().map(|_| ()))? {
                absolute.canonicalize().map_err(|_| Rejection::Resolution)?
            } else {
                resolve_ancestor(parent)
                    .map_err(|_| Rejection::Resolution)?
                    .join(filename)
            }
        } else {
            absolute.canonicalize().map_err(|_| Rejection::Resolution)?
        };
        if protected_path(&resolved) {
            return Err(Rejection::Protected);
        }
        if !self.resolved_allowed(&resolved, write) || self.forbidden(&resolved, write) {
            return Err(Rejection::PolicyDenied);
        }
        Ok(resolved)
    }
    /// Evaluate a content-free boolean path query.
    #[must_use]
    pub fn check_path(&self, path: &Path, kind: PathCheckKind) -> bool {
        match kind {
            PathCheckKind::StringAllowed => self.string_allowed(&path.to_string_lossy()),
            PathCheckKind::ResolvedRead => self.resolved_allowed(path, false),
            PathCheckKind::ResolvedWrite => self.resolved_allowed(path, true),
            PathCheckKind::Internal => self.internal(path),
            PathCheckKind::TrustedRead => self.trusted(path, false),
            PathCheckKind::TrustedWrite => self.trusted(path, true),
            PathCheckKind::Protected => protected_path(path),
        }
    }
}
#[cfg(test)]
#[path = "path_scope_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "path_scope_contract_tests.rs"]
mod contract_tests;

#[cfg(test)]
#[path = "path_scope_host_port_tests.rs"]
mod host_port_tests;
