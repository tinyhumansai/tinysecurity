//! Shared-corpus mode coverage with idempotence, no-survivor properties and
//! bounded-work fuzz, driven only through the public `Redactor` API.
use serde_json::json;
use std::time::{Duration, Instant};
use tinysecurity_bus::*;
use tinysecurity_redact::Redactor;
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
fn run(engine: &Redactor, text: &str, mode: &RedactMode) -> tinysecurity_bus::Result<String> {
    engine
        .redact(&RedactRequest {
            text: text.into(),
            mode: mode.clone(),
        })
        .map(|r| r.text)
}
/// Secret-token formats: (full token, distinctive needle that must not survive).
const TOKENS: &[(&str, &str)] = &[
    (
        "sk-ant-api03-Zq9XyWvUtSrQpOnMlKjIh",
        "Zq9XyWvUtSrQpOnMlKjIh",
    ),
    ("ghp_Zq9XyWvUtSrQpOnMlKjIhGfEd", "Zq9XyWvUtSrQpOnMlKjIhGfEd"),
    ("github_pat_Zq9XyWvUtSrQpOnMlKjIh", "Zq9XyWvUtSrQpOnMlKjIh"),
    ("AKIAZQ9XYWVUTSRQPONM", "ZQ9XYWVUTSRQPONM"),
    ("ASIAZQ9XYWVUTSRQPONM", "ZQ9XYWVUTSRQPONM"),
    ("xoxb-123456789012-Zq9XyWvUtSrQ", "Zq9XyWvUtSrQ"),
    ("sk_live_Zq9XyWvUtSrQpOnMlKjIh", "Zq9XyWvUtSrQpOnMlKjIh"),
    (
        "AIzaSyZq9XyWvUtSrQpOnMlKjIhGfEdCbA12345",
        "Zq9XyWvUtSrQpOnMlKjIhGfEdCbA12345",
    ),
    (
        "npm_Zq9XyWvUtSrQpOnMlKjIhGfEdCbA12345678",
        "Zq9XyWvUtSrQpOnMlKjIhGfEdCbA12345678",
    ),
    ("glpat-Zq9XyWvUtSrQpOnMlKjIh", "Zq9XyWvUtSrQpOnMlKjIh"),
    (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ6cTl4eXd2In0.ZnVuLXNpZ25hdHVyZS14eXo",
        "ZnVuLXNpZ25hdHVyZS14eXo",
    ),
    (
        "-----BEGIN PRIVATE KEY-----\nZq9XyWvUtSrQ\n-----END PRIVATE KEY-----",
        "Zq9XyWvUtSrQ",
    ),
];
/// Plain-text wrappers around a secret value `{}`.
const WRAPPERS: &[&str] = &[
    "{}",
    "error: request failed with {} while retrying",
    "Authorization: Bearer {}",
    "Authorization: Basic {}",
    "authorization={}",
    "api_key={}",
    "x-api-key: {}",
    "https://example.com/hook?token={}",
    "\"{}\"",
];
#[test]
fn every_token_format_in_every_wrapper_is_removed_and_stable() -> TestResult {
    let engine = Redactor::new(&RedactorConfig::default())?;
    for (token, needle) in TOKENS {
        for wrapper in WRAPPERS {
            let input = wrapper.replace("{}", token);
            // A bare quote opens a JSON string; a raw newline inside one is malformed
            // structured input, which is refused (covered below) rather than guessed.
            if input.starts_with('"') && input.contains('\n') {
                assert!(run(&engine, &input, &RedactMode::Text).is_err());
                continue;
            }
            let out = run(&engine, &input, &RedactMode::Text)?;
            assert!(!out.contains(needle), "{wrapper:?}/{needle}: {out}");
            assert_eq!(run(&engine, &out, &RedactMode::Text)?, out, "{wrapper:?}");
            // Escaped / embedded / doubly encoded JSON cannot hide the token.
            let flat = json!({"unknown": input, "list": [{"deep": input}]}).to_string();
            let wrapped = json!({"inner": flat}).to_string();
            for doc in [flat, wrapped] {
                for mode in [
                    RedactMode::Text,
                    RedactMode::StructuredArguments,
                    RedactMode::StructuredLogArguments,
                    RedactMode::BrowserResult,
                ] {
                    let out = run(&engine, &doc, &mode);
                    assert!(out.is_ok(), "{mode:?} refused {doc:?}");
                    let out = out?;
                    assert!(!out.contains(needle), "{mode:?}: {out}");
                    let again = run(&engine, &out, &mode);
                    assert_eq!(
                        again.as_ref().ok(),
                        Some(&out),
                        "{mode:?} {out:?} {again:?}"
                    );
                }
            }
        }
    }
    Ok(())
}
#[test]
fn credential_keys_match_across_separator_and_case_spellings() -> TestResult {
    let engine = Redactor::new(&RedactorConfig::default())?;
    let keys = [
        "api_key",
        "apiKey",
        "API-KEY",
        "X-Api-Key",
        "x_api_key",
        "api_secret",
        "token",
        "accessToken",
        "Access_Token",
        "refresh-token",
        "id_token",
        "session_token",
        "Authorization",
        "Proxy-Authorization",
        "password",
        "passwd",
        "client_secret",
        "clientSecret",
        "privateKey",
        "credentials",
        "Cookie",
        "Set-Cookie",
        "bearer",
    ];
    for key in keys {
        let doc = json!({ key: "needle-secret-value", "ordinary": "keep-me"}).to_string();
        for mode in [
            RedactMode::StructuredArguments,
            RedactMode::StructuredLogArguments,
        ] {
            let out = run(&engine, &doc, &mode)?;
            assert!(
                !out.contains("needle-secret-value"),
                "{key}/{mode:?}: {out}"
            );
            assert!(out.contains("keep-me"), "{key}/{mode:?}: {out}");
            assert_eq!(run(&engine, &out, &mode)?, out);
        }
    }
    // A name that merely contains a credential word is ordinary content.
    let out = run(
        &engine,
        &json!({"cancellation_token": "keep-me"}).to_string(),
        &RedactMode::StructuredLogArguments,
    )?;
    assert!(out.contains("keep-me"));
    Ok(())
}

#[test]
fn short_credential_assignments_are_redacted_without_rewriting_source_code() -> TestResult {
    let engine = Redactor::new(&RedactorConfig::default())?;
    let input = "api_key=abc123";
    let out = run(&engine, input, &RedactMode::CredentialsOnly)?;
    assert_eq!(out, "api_key=[REDACTED]");

    for source in [
        "api_key = get_api_key()",
        "token: string",
        "let token = v2;",
        "const token=v2+1;",
    ] {
        assert_eq!(
            run(&engine, source, &RedactMode::CredentialsOnly)?,
            source,
            "source-code text should remain unchanged"
        );
    }
    Ok(())
}
#[test]
fn cookie_headers_are_redacted_as_a_whole_list() -> TestResult {
    let engine = Redactor::new(&RedactorConfig::default())?;
    for input in [
        "Cookie: sid=first-secret; theme=second-secret; csrf=third-secret",
        "Set-Cookie: sid=first-secret; Path=/; HttpOnly; second-secret",
    ] {
        let out = run(&engine, input, &RedactMode::Text)?;
        assert!(!out.contains("secret"), "{out}");
        assert_eq!(run(&engine, &out, &RedactMode::Text)?, out);
    }
    Ok(())
}
#[test]
fn pii_urls_and_home_paths_cover_every_native_dialect() -> TestResult {
    let engine = Redactor::new(&RedactorConfig::default())?;
    let cases: &[(&str, &[&str])] = &[
        (
            "card 4111 1111 1111 1111 ssn 123-45-6789 iban DE89370400440532013000",
            &["4111", "123-45-6789", "DE8937"],
        ),
        ("call +1 415-555-2671 or (415) 555-2671", &["555-2671"]),
        (
            "from 192.168.10.77 to 8.8.4.4",
            &["192.168.10.77", "8.8.4.4"],
        ),
        ("mail Alice.Smith+tag@Example.co.uk now", &["Alice.Smith"]),
        ("lives at 221 Baker Street", &["221 Baker"]),
        ("/home/alice/work /Users/alice/work", &["alice"]),
        ("C:\\Users\\alice\\work c:/users/alice/work", &["alice"]),
        ("\\\\?\\C:\\Users\\alice\\work", &["alice"]),
        (
            "{\"cwd\":\"C:\\\\Users\\\\alice\\\\work\",\"p\":\"\\/home\\/alice\"}",
            &["alice"],
        ),
        (
            "postgres://svc:hunter2pw@db.internal:5432/app?sslmode=x&password=hunter2pw#frag-secret",
            &["hunter2pw", "frag-secret"],
        ),
        (
            "see https://user:pw-secret@api.example.com/v1/items?key=query-secret#f-secret",
            &["pw-secret", "query-secret", "f-secret"],
        ),
    ];
    for (input, needles) in cases {
        let out = run(&engine, input, &RedactMode::Text)?;
        for needle in *needles {
            assert!(!out.contains(needle), "{input:?} kept {needle}: {out}");
        }
        assert_eq!(run(&engine, &out, &RedactMode::Text)?, out, "{input:?}");
    }
    let out = run(&engine, "/Users/alice/x", &RedactMode::HomePath)?;
    assert_eq!(out, "<HOME>/x");
    assert_eq!(run(&engine, &out, &RedactMode::HomePath)?, out);
    Ok(())
}
#[test]
fn endpoint_modes_drop_userinfo_query_and_fragment_and_are_stable() -> TestResult {
    let engine = Redactor::new(&RedactorConfig::default())?;
    for input in [
        "https://user:pw-secret@Api.Example.com:8443/v1/x?k=query-secret#f-secret",
        "wss://api.example.com/socket?token=query-secret",
        "redis://:pw-secret@cache.internal:6379/0",
        "api.example.com/path?token=query-secret",
    ] {
        for mode in [
            RedactMode::Endpoint,
            RedactMode::EndpointOrigin,
            RedactMode::EndpointHost,
        ] {
            let out = run(&engine, input, &mode)?;
            assert!(!out.contains("secret"), "{mode:?}: {out}");
            assert_eq!(run(&engine, &out, &mode)?, out, "{mode:?}");
        }
    }
    Ok(())
}
/// Seeded generator: configured literals embedded in noise built from tokens,
/// separators and structure characters. Failures reproduce from the seed.
#[test]
fn seeded_property_no_secret_survives_and_redaction_is_idempotent() -> TestResult {
    let literals = ["literal-private-key", "Zq9-literal-9qZ"];
    let engine = Redactor::new(&RedactorConfig {
        secrets: literals.iter().map(|s| Secret((*s).into())).collect(),
    })?;
    let atoms = [
        " ",
        "\n",
        "=",
        ":",
        "\"",
        "'",
        "{",
        "}",
        "[",
        "]",
        "\\",
        "/",
        "@",
        "%40",
        "://",
        "&",
        "?",
        "#",
        "🦀",
        "é",
        "\u{200b}",
        "token",
        "password",
        "Bearer ",
        "Authorization: ",
        "/home/",
        "C:\\Users\\",
        "4111111111111111",
        "a@b.co",
        "x.y.z",
    ];
    let mut state = 0x5eed_u64;
    let mut next = move |bound: usize| {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(state >> 33).unwrap_or(0) % bound
    };
    for round in 0..400 {
        let mut text = String::new();
        for _ in 0..(8 + next(40)) {
            text.push_str(atoms[next(atoms.len())]);
            if next(5) == 0 {
                text.push_str(literals[next(literals.len())]);
            }
        }
        text.push_str(literals[round % literals.len()]);
        let json_doc = json!({"v": text, "k": [{literals[0]: text}]}).to_string();
        for (input, mode) in [
            (&text, RedactMode::Text),
            (&json_doc, RedactMode::Text),
            (&json_doc, RedactMode::StructuredArguments),
            (&json_doc, RedactMode::StructuredLogArguments),
        ] {
            let Ok(out) = run(&engine, input, &mode) else {
                continue; // a content-free refusal never leaks
            };
            for literal in literals {
                assert!(!out.contains(literal), "round {round} {mode:?}: {out}");
            }
            assert!(out.len() <= 131_072);
            let again = run(&engine, &out, &mode);
            assert_eq!(
                again.as_ref().ok(),
                Some(&out),
                "round {round} {mode:?}\nin={input:?}\nout={out:?}\nagain={again:?}"
            );
        }
    }
    Ok(())
}
#[test]
fn pathological_inputs_stay_within_bounded_work() -> TestResult {
    let engine = Redactor::new(&RedactorConfig {
        secrets: vec![Secret("abcd".into())],
    })?;
    let limit = 65_536;
    let fill = |unit: &str| unit.repeat(limit / unit.len());
    let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
    let inputs = [
        fill("a@"),
        fill("1 "),
        fill("9-"),
        fill("%40"),
        fill("a."),
        fill("://"),
        fill("token="),
        fill("Authorization: Bearer "),
        fill("Cookie: "),
        fill("/home/"),
        fill("C:\\Users\\"),
        fill("{\"a\":"),
        fill("\"\\u0061\""),
        format!("-----BEGIN PRIVATE KEY-----{}", "x".repeat(limit - 40)),
        deep,
    ];
    for input in &inputs {
        assert!(input.len() <= limit);
        for mode in [
            RedactMode::Text,
            RedactMode::StructuredArguments,
            RedactMode::StructuredLogArguments,
            RedactMode::BrowserResult,
            RedactMode::Endpoint,
            RedactMode::HomePath,
        ] {
            let started = Instant::now();
            if let Ok(out) = run(&engine, input, &mode) {
                assert!(out.len() <= 131_072);
                assert!(!out.contains("abcd"));
            }
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "{mode:?} took {:?}",
                started.elapsed()
            );
        }
    }
    // Over the ceiling is a content-free refusal, not truncation.
    for mode in [RedactMode::Text, RedactMode::StructuredLogArguments] {
        assert!(run(&engine, &"x".repeat(limit + 1), &mode).is_err());
    }
    Ok(())
}
