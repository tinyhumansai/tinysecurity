//! Private, deterministic DNS answers for native security integration fixtures.
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    sync::{Mutex, OnceLock},
    time::Duration,
};
use tinysecurity::{ResolveFailure, Resolver};

const ENVIRONMENT_VARIABLE: &str = "TINYSECURITY_TEST_DNS_SEQUENCE";
const MAX_FIXTURE_BYTES: usize = 4096;
const MAX_HOSTS: usize = 16;
const MAX_ANSWERS_PER_HOST: usize = 8;
const MAX_TOTAL_ANSWERS: usize = 64;

struct RawAnswers(BTreeMap<String, Vec<String>>);

impl<'de> Deserialize<'de> for RawAnswers {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawAnswersVisitor;

        impl<'de> Visitor<'de> for RawAnswersVisitor {
            type Value = RawAnswers;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a DNS fixture object with unique hostname keys")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut answers = BTreeMap::new();
                while let Some((hostname, values)) = map.next_entry::<String, Vec<String>>()? {
                    if answers.insert(hostname, values).is_some() {
                        return Err(serde::de::Error::custom("duplicate DNS fixture hostname"));
                    }
                    if answers.len() > MAX_HOSTS {
                        return Err(serde::de::Error::custom("too many DNS fixture hostnames"));
                    }
                }
                Ok(RawAnswers(answers))
            }
        }

        deserializer.deserialize_map(RawAnswersVisitor)
    }
}

/// A bounded hostname-to-address script. Each successful lookup consumes one address.
#[derive(Debug)]
struct FixtureResolver {
    answers: BTreeMap<String, Vec<IpAddr>>,
    next_answer: Mutex<HashMap<String, usize>>,
}

impl FixtureResolver {
    fn parse(input: &str) -> Result<Self, ResolveFailure> {
        if input.is_empty() || input.len() > MAX_FIXTURE_BYTES {
            return Err(ResolveFailure);
        }
        let raw = serde_json::from_str::<RawAnswers>(input)
            .map_err(|_| ResolveFailure)?
            .0;
        if raw.is_empty() || raw.len() > MAX_HOSTS {
            return Err(ResolveFailure);
        }

        let mut answers = BTreeMap::new();
        let mut total_answers = 0;
        for (hostname, values) in raw {
            if !valid_hostname(&hostname)
                || values.is_empty()
                || values.len() > MAX_ANSWERS_PER_HOST
            {
                return Err(ResolveFailure);
            }
            total_answers += values.len();
            if total_answers > MAX_TOTAL_ANSWERS {
                return Err(ResolveFailure);
            }
            let addresses = values
                .into_iter()
                .map(|value| value.parse().map_err(|_| ResolveFailure))
                .collect::<Result<Vec<IpAddr>, ResolveFailure>>()?;
            if answers
                .insert(hostname.to_ascii_lowercase(), addresses)
                .is_some()
            {
                return Err(ResolveFailure);
            }
        }

        Ok(Self {
            answers,
            next_answer: Mutex::new(HashMap::new()),
        })
    }
}

impl Resolver for FixtureResolver {
    fn resolve(
        &self,
        hostname: &str,
        timeout: Duration,
        limit: usize,
    ) -> Result<Vec<IpAddr>, ResolveFailure> {
        if hostname.len() > 253
            || limit == 0
            || limit > 64
            || timeout.is_zero()
            || timeout > Duration::from_secs(2)
        {
            return Err(ResolveFailure);
        }
        let hostname = hostname.to_ascii_lowercase();
        let values = self.answers.get(&hostname).ok_or(ResolveFailure)?;
        let mut next_answer = self.next_answer.lock().map_err(|_| ResolveFailure)?;
        let next = next_answer.entry(hostname).or_default();
        let address = *values.get(*next).ok_or(ResolveFailure)?;
        *next += 1;
        Ok(vec![address])
    }
}

#[derive(Debug)]
struct RejectResolver;

impl Resolver for RejectResolver {
    fn resolve(
        &self,
        _hostname: &str,
        _timeout: Duration,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, ResolveFailure> {
        Err(ResolveFailure)
    }
}

#[derive(Debug)]
enum NativeTestResolver {
    Fixture(FixtureResolver),
    Reject(RejectResolver),
}

impl Resolver for NativeTestResolver {
    fn resolve(
        &self,
        hostname: &str,
        timeout: Duration,
        limit: usize,
    ) -> Result<Vec<IpAddr>, ResolveFailure> {
        match self {
            Self::Fixture(resolver) => resolver.resolve(hostname, timeout, limit),
            Self::Reject(resolver) => resolver.resolve(hostname, timeout, limit),
        }
    }
}

/// Return the fixture resolver configured when the native module first loads.
pub(super) fn resolver() -> &'static dyn Resolver {
    static RESOLVER: OnceLock<NativeTestResolver> = OnceLock::new();
    RESOLVER.get_or_init(|| {
        let input = std::env::var(ENVIRONMENT_VARIABLE).ok();
        configured_resolver(input.as_deref())
    })
}

fn configured_resolver(input: Option<&str>) -> NativeTestResolver {
    input
        .and_then(|input| FixtureResolver::parse(input).ok())
        .map_or(
            NativeTestResolver::Reject(RejectResolver),
            NativeTestResolver::Fixture,
        )
}

fn valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 || !hostname.is_ascii() {
        return false;
    }
    hostname.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(test)]
#[path = "native_test_resolver_tests.rs"]
mod tests;
