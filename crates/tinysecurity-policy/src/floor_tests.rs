use super::*;
use std::path::PathBuf;

fn floor(path: &str) -> bool {
    lexical_floor(&PathBuf::from(path))
}

#[test]
fn floor_covers_credentials_system_roots_traversal_and_nul() {
    for path in [
        "/home/u/.ssh/id_rsa",
        "/home/u/.AWS/credentials",
        "/home/u/.netrc",
        "/home/u/.docker/config.json",
        "/etc/passwd",
        "/usr/bin/env",
        "/bin",
        "/dev/null",
        "/private/etc/hosts",
        "/work/../x",
        "/work/a\0b",
        r"C:\Windows\System32",
        r"\\?\C:\Program Files\x",
        "D:/ProgramData/x",
    ] {
        assert!(floor(path), "{path}");
    }
}

#[test]
fn floor_leaves_ordinary_paths_alone() {
    for path in [
        "/home/u/project/src/main.rs",
        "/tmp/x",
        "relative/file",
        "/usrx/a",
    ] {
        assert!(!floor(path), "{path}");
    }
}

#[test]
fn every_vocabulary_entry_is_recognised_by_the_floor() {
    let vocabulary = floor_vocabulary();
    assert!(!vocabulary.components.is_empty() && !vocabulary.files.is_empty());
    for name in vocabulary.components.iter().chain(&vocabulary.files) {
        assert!(floor(&format!("/home/u/{name}")), "{name}");
        assert!(
            floor(&format!("/home/u/{}/deep", name.to_uppercase())),
            "{name}"
        );
    }
    for [parent, child] in &vocabulary.pairs {
        assert!(
            floor(&format!("/home/u/{parent}/{child}")),
            "{parent}/{child}"
        );
    }
    for prefix in &vocabulary.prefixes {
        assert!(prefix.starts_with('/') || prefix.as_bytes().get(1) == Some(&b':'));
        assert_eq!(prefix, &prefix.to_lowercase());
        assert!(floor(prefix), "{prefix}");
        assert!(floor(&format!("{prefix}/child/leaf")), "{prefix}");
    }
}

#[test]
fn vocabulary_splits_directories_from_files_and_keeps_every_constant() {
    let vocabulary = floor_vocabulary();
    for name in [".ssh", ".gnupg", ".aws", ".azure", ".kube", "keychains"] {
        assert!(vocabulary.components.iter().any(|c| c == name), "{name}");
    }
    for name in [".netrc", ".git-credentials", ".pgpass", ".npmrc"] {
        assert!(vocabulary.files.iter().any(|c| c == name), "{name}");
    }
    assert_eq!(
        vocabulary.components.len() + vocabulary.files.len(),
        CREDENTIAL_COMPONENTS.len()
    );
    assert_eq!(vocabulary.pairs.len(), CREDENTIAL_PAIRS.len());
    for prefix in [
        "/etc",
        "/root",
        "/boot",
        "/proc",
        "/sys",
        "/system",
        "/private/etc",
        "/private/var/root",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/usr",
        "/library",
        "/dev",
        "c:/windows",
        "c:/program files",
        "c:/program files (x86)",
        "c:/programdata",
    ] {
        assert!(vocabulary.prefixes.iter().any(|p| p == prefix), "{prefix}");
    }
}

#[test]
fn file_store_subset_stays_within_credential_components() {
    for name in CREDENTIAL_FILE_STORES {
        assert!(CREDENTIAL_COMPONENTS.contains(name), "{name}");
    }
}

#[test]
fn windows_normalized_parent_segments_count_as_traversal() {
    for path in [
        r"C:\safe\.. \Windows\System32",
        r"C:\safe\..\Windows",
        r"C:\safe\... \x",
        r"C:\safe\.. . \x",
        "/work/.. /etc/passwd",
        "/work/.../x",
    ] {
        assert!(floor(path), "{path:?}");
        assert!(crate::protected_path(&PathBuf::from(path)), "{path:?}");
    }
    // Ordinary names that merely contain dots stay usable.
    for path in [
        "/work/my..file.txt",
        "/work/.hidden",
        "/work/a. b",
        "/work/.config.d",
    ] {
        assert!(!floor(path), "{path:?}");
    }
}
