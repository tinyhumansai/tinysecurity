//! Complete original operation checks; host classification cannot bypass inspection.
use tinysecurity_bus::{
    DataCategory, EgressPolicy, Error, PrivacyMode, RedactMode, RedactRequest, Result,
    ScopedEgressRequest,
};
use tinysecurity_redact::Redactor;
pub(crate) fn check(
    policy: &EgressPolicy,
    request: &ScopedEgressRequest,
    redactor: &Redactor,
) -> Result<()> {
    bounds(request)?;
    if request.transformation.is_some()
        || request.category == DataCategory::Unknown
        || !policy.data_categories.contains(&request.category)
    {
        return Err(Error::InvalidArguments);
    }
    if policy.privacy == PrivacyMode::LocalOnly && request.local_capability.is_none() {
        return Err(Error::InvalidArguments);
    }
    if policy.privacy == PrivacyMode::Sensitive {
        if matches!(
            request.category,
            DataCategory::Credentials
                | DataCategory::Identifiers
                | DataCategory::OpaqueBrowserTraffic
        ) {
            return Err(Error::InvalidArguments);
        }
        inspect_body(request, redactor)?;
        // Inspect the ORIGINAL complete URL, including query/fragment, before
        // canonicalization. Decode path text as well so %40 cannot hide an email.
        reject_changed(&request.url, redactor, true)?;
        let decoded = percent_encoding::percent_decode_str(&request.url)
            .decode_utf8()
            .map_err(|_| Error::InvalidArguments)?;
        reject_changed(&decoded, redactor, true)?;
        for header in &request.headers {
            if [
                "authorization",
                "cookie",
                "set-cookie",
                "x-api-key",
                "x-user-id",
                "x-email",
            ]
            .iter()
            .any(|name| header.name.eq_ignore_ascii_case(name))
            {
                return Err(Error::InvalidArguments);
            }
            reject_changed(
                &format!("{}={}", header.name, header.value),
                redactor,
                false,
            )?;
        }
    }
    Ok(())
}
fn reject_changed(input: &str, redactor: &Redactor, endpoint: bool) -> Result<()> {
    let result = redactor.redact(&RedactRequest {
        text: input.to_owned(),
        mode: RedactMode::Text,
    })?;
    let original = if endpoint {
        input.trim_end_matches('/')
    } else {
        input
    };
    if result.text != original {
        return Err(Error::InvalidArguments);
    }
    Ok(())
}

pub(crate) fn bounds(request: &ScopedEgressRequest) -> Result<()> {
    if !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        .contains(&request.method.as_str())
    {
        return Err(Error::InvalidArguments);
    }
    if request.payload.len() > 65_536
        || request.headers.len() > 64
        || request.url.len() > 8192
        || request.policy_id.0.len() > 64
        || [
            &request.subject.user,
            &request.subject.workspace,
            &request.subject.agent,
        ]
        .iter()
        .any(|part| part.len() > 256)
        || request
            .transformation
            .as_ref()
            .is_some_and(|value| value.len() > 256)
    {
        return Err(Error::InvalidArguments);
    }
    let mut header_bytes = 0;
    for header in &request.headers {
        header_bytes += header.name.len() + header.value.len();
        if header_bytes > 16384
            || header.name.is_empty()
            || header.name.len() > 64
            || header.value.len() > 4096
            || !header
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
            || header.value.chars().any(char::is_control)
            || !header.value.is_ascii()
            || [
                "host",
                "connection",
                "proxy-authorization",
                "proxy-connection",
                "transfer-encoding",
                "content-length",
                "upgrade",
            ]
            .iter()
            .any(|name| header.name.eq_ignore_ascii_case(name))
        {
            return Err(Error::InvalidArguments);
        }
    }
    Ok(())
}

fn inspect_body(request: &ScopedEgressRequest, redactor: &Redactor) -> Result<()> {
    let mut content_type = None;
    let mut encoding = None;
    for header in &request.headers {
        if header.name.eq_ignore_ascii_case("content-type")
            && content_type.replace(header.value.as_str()).is_some()
        {
            return Err(Error::InvalidArguments);
        }
        if header.name.eq_ignore_ascii_case("content-encoding")
            && encoding.replace(header.value.as_str()).is_some()
        {
            return Err(Error::InvalidArguments);
        }
    }
    if encoding.is_some_and(|value| !value.trim().eq_ignore_ascii_case("identity")) {
        return Err(Error::InvalidArguments);
    }
    let mut form = false;
    if let Some(value) = content_type {
        let mut parts = value.split(';');
        let media = parts.next().ok_or(Error::InvalidArguments)?.trim();
        form = media.eq_ignore_ascii_case("application/x-www-form-urlencoded");
        if !form
            && !media.eq_ignore_ascii_case("text/plain")
            && !media.eq_ignore_ascii_case("application/json")
        {
            return Err(Error::InvalidArguments);
        }
        let mut charset = false;
        for part in parts {
            let (key, value) = part.trim().split_once('=').ok_or(Error::InvalidArguments)?;
            if !key.trim().eq_ignore_ascii_case("charset")
                || charset
                || !value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
            {
                return Err(Error::InvalidArguments);
            }
            charset = true;
        }
    }
    reject_changed(&request.payload, redactor, false)?;
    if form {
        // Form decoding is bounded by the original body limit and cannot expand it.
        // Reject malformed escapes rather than accepting a lossy UTF-8 conversion.
        for field in request.payload.split('&') {
            let (key, value) = field.split_once('=').unwrap_or((field, ""));
            let key = decode_form(key)?;
            let value = decode_form(value)?;
            reject_changed(&key, redactor, false)?;
            reject_changed(&value, redactor, false)?;
            reject_changed(&format!("{key}={value}"), redactor, false)?;
        }
    }
    Ok(())
}
fn decode_form(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if bytes.get(index + 1).is_none_or(|b| !b.is_ascii_hexdigit())
                || bytes.get(index + 2).is_none_or(|b| !b.is_ascii_hexdigit())
            {
                return Err(Error::InvalidArguments);
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    let plus = value.replace('+', " ");
    percent_encoding::percent_decode_str(&plus)
        .decode_utf8()
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| Error::InvalidArguments)
}
