use super::*;

fn abs(tail: &str) -> PathBuf {
    std::env::temp_dir().join(tail)
}

fn text(path: &Path) -> String {
    path.display().to_string()
}

fn policy(action: &str, entries: &[&str]) -> PolicyConfig {
    PolicyConfig {
        enabled: true,
        action_dir: action.into(),
        workspace_dir: action.into(),
        allowed_commands: vec![],
        forbidden_paths: entries.iter().map(|e| (*e).into()).collect(),
    }
}

fn effective(entries: &[&str], home: Option<&Path>) -> Result<Vec<String>> {
    effective_forbidden(&policy(&text(&abs("action")), entries), home)
}

#[test]
fn absolute_entries_pass_through_unchanged_and_deduplicate() {
    let (secret, other) = (text(&abs("secret")), text(&abs("other")));
    assert_eq!(
        effective(&[&secret, &secret, &other], None),
        Ok(vec![secret, other])
    );
}

#[test]
fn tilde_entries_expand_against_the_registered_home() {
    let home = abs("home");
    assert_eq!(
        effective(&["~/.config/app", "~", "~\\win"], Some(&home)),
        Ok(vec![
            text(&home.join(".config").join("app")),
            text(&home),
            text(&home.join("win"))
        ])
    );
}

#[test]
fn tilde_without_a_registered_home_or_with_a_user_form_is_rejected() {
    assert_eq!(effective(&["~/x"], None), Err(Error::InvalidArguments));
    assert_eq!(effective(&["~"], None), Err(Error::InvalidArguments));
    assert_eq!(
        effective(&["~other/x"], Some(&abs("home"))),
        Err(Error::InvalidArguments)
    );
}

#[test]
fn relative_entries_resolve_against_the_action_dir() {
    let action = abs("action");
    assert_eq!(
        effective(&["private", "a/b", "./cur"], None),
        Ok(vec![
            text(&action.join("private")),
            text(&action.join("a").join("b")),
            text(&action.join("cur"))
        ])
    );
}

#[test]
fn relative_entries_cannot_be_anchored_without_an_absolute_action_dir() {
    assert_eq!(
        effective_forbidden(&policy("relative-action", &["private"]), None),
        Err(Error::InvalidArguments)
    );
    // Absolute entries do not need an anchor.
    let abs_entry = text(&abs("abs"));
    assert_eq!(
        effective_forbidden(&policy("relative-action", &[&abs_entry]), None),
        Ok(vec![abs_entry])
    );
}

#[cfg(windows)]
#[test]
fn rooted_entries_without_a_drive_are_refused_on_windows() {
    assert_eq!(effective(&["\\rooted"], None), Err(Error::InvalidArguments));
}

#[test]
fn traversal_nul_and_empty_entries_are_rejected_not_dropped() {
    let home = abs("home");
    for entry in ["", "../up", "a/../b", "/abs/../x", "~/../x", "nul\0byte"] {
        assert_eq!(
            effective(&[entry], Some(&home)),
            Err(Error::InvalidArguments),
            "{entry:?}"
        );
    }
}

#[test]
fn entries_inside_the_unconditional_floor_are_redundant_noops() {
    let (home, kept) = (abs("home"), text(&abs("secret")));
    assert_eq!(
        effective(
            &["/etc/passwd", "~/.ssh", "~/.aws/credentials", &kept],
            Some(&home)
        ),
        Ok(vec![kept])
    );
}

#[test]
fn windows_normalized_traversal_entries_are_rejected_not_dropped() {
    let home = abs("home");
    for entry in ["a/.. /b", "a\\.. \\b", "/abs/.../x", "~/.. ./x"] {
        assert_eq!(
            effective(&[entry], Some(&home)),
            Err(Error::InvalidArguments),
            "{entry:?}"
        );
    }
}
