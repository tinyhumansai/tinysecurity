use super::*;
use std::{net::IpAddr, time::Duration};
use tinysecurity::{ResolveFailure, Resolver};

#[test]
fn configured_answers_advance_once_per_resolution() -> Result<(), std::io::Error> {
    let resolver = FixtureResolver::parse(r#"{"rebind.test":["8.8.8.8","127.0.0.1"]}"#)
        .map_err(|_| std::io::Error::other("fixture should parse"))?;

    assert_eq!(
        resolver.resolve("rebind.test", Duration::from_secs(1), 8),
        Ok(vec![IpAddr::from([8, 8, 8, 8])])
    );
    assert_eq!(
        resolver.resolve("rebind.test", Duration::from_secs(1), 8),
        Ok(vec![IpAddr::from([127, 0, 0, 1])])
    );
    assert_eq!(
        resolver.resolve("rebind.test", Duration::from_secs(1), 8),
        Err(ResolveFailure)
    );
    Ok(())
}

#[test]
fn mixed_case_host_keys_match_canonical_queries() -> Result<(), std::io::Error> {
    let resolver = FixtureResolver::parse(r#"{"Rebind.Test":["8.8.8.8"]}"#)
        .map_err(|_| std::io::Error::other("valid mixed-case hostname should parse"))?;

    assert_eq!(
        resolver.resolve("rebind.test", Duration::from_secs(1), 8),
        Ok(vec![IpAddr::from([8, 8, 8, 8])])
    );
    Ok(())
}

#[test]
fn invalid_fixture_inputs_fail_closed() {
    for input in [
        "",
        "{}",
        r#"{"rebind.test":[]}"#,
        r#"{"bad host":["8.8.8.8"]}"#,
        r#"{"Rebind.Test":["8.8.8.8"],"rebind.test":["127.0.0.1"]}"#,
        r#"{"rebind.test":["8.8.8.8"],"rebind.test":["127.0.0.1"]}"#,
        r#"{"rebind.test":["not-an-ip"]}"#,
        &format!("{{\"{}\":[\"8.8.8.8\"]}}", "a".repeat(254)),
        &format!("{{\"rebind.test\":[{}]}}", ["\"8.8.8.8\""; 9].join(",")),
        &" ".repeat(MAX_FIXTURE_BYTES + 1),
    ] {
        assert!(FixtureResolver::parse(input).is_err());
    }
}

#[test]
fn fixture_bounds_reject_too_many_hosts_and_total_answers() {
    let too_many_hosts = (0..=MAX_HOSTS)
        .map(|index| format!(r#""host{index}.test":["8.8.8.8"]"#))
        .collect::<Vec<_>>()
        .join(",");
    assert!(FixtureResolver::parse(&format!("{{{too_many_hosts}}}")).is_err());

    let too_many_answers = (0..9)
        .map(|index| {
            let answers = [r#""8.8.8.8""#; 8].join(",");
            format!(r#""host{index}.test":[{answers}]"#)
        })
        .collect::<Vec<_>>()
        .join(",");
    assert!(FixtureResolver::parse(&format!("{{{too_many_answers}}}")).is_err());
}

#[test]
fn fixture_parser_rejects_invalid_json_shapes_and_hostnames() {
    let invalid_hosts = [
        "",
        "-leading.test",
        "trailing-.test",
        "two..labels.test",
        &format!("{}.test", "a".repeat(64)),
        "münich.test",
    ];
    for hostname in invalid_hosts {
        let input = format!(r#"{{"{hostname}":["8.8.8.8"]}}"#);
        assert!(
            FixtureResolver::parse(&input).is_err(),
            "accepted {hostname:?}"
        );
    }

    for input in ["[]", "null", r#"{"host.test":null}"#] {
        assert!(FixtureResolver::parse(input).is_err(), "accepted {input}");
    }
}

#[test]
fn resolver_rejects_out_of_range_limits_timeouts_and_unknown_hosts() -> Result<(), std::io::Error> {
    let resolver = FixtureResolver::parse(r#"{"host.test":["8.8.8.8"]}"#)
        .map_err(|_| std::io::Error::other("fixture should parse"))?;
    for (hostname, timeout, limit) in [
        ("host.test", Duration::from_secs(1), 0),
        ("host.test", Duration::from_secs(1), 65),
        ("host.test", Duration::ZERO, 1),
        ("host.test", Duration::from_secs(3), 1),
        (&"h".repeat(254), Duration::from_secs(1), 1),
    ] {
        assert_eq!(
            resolver.resolve(hostname, timeout, limit),
            Err(ResolveFailure)
        );
    }
    assert_eq!(
        resolver.resolve("other.test", Duration::from_secs(1), 1),
        Err(ResolveFailure)
    );
    Ok(())
}

#[test]
fn configured_resolver_accepts_only_a_valid_fixture() {
    let configured = configured_resolver(Some(r#"{"host.test":["8.8.8.8"]}"#));
    assert_eq!(
        configured.resolve("host.test", Duration::from_secs(1), 1),
        Ok(vec![IpAddr::from([8, 8, 8, 8])])
    );

    for invalid in [None, Some("not-json")] {
        let rejecting = configured_resolver(invalid);
        assert_eq!(
            rejecting.resolve("host.test", Duration::from_secs(1), 1),
            Err(ResolveFailure)
        );
    }
}
