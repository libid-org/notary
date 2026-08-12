//! Pull a JWKS response apart into the leaves the contract expects.

use serde_json::Value;

use crate::{
    error::{
        Error,
        Result,
    },
    jwks::ParsedJwk,
};

/// Parse the body of a `oauth2/v3/certs` response into individual JWKs,
/// keeping the raw bytes Google sent us for each one.
///
/// Google currently emits responses that, when pretty-printed, look like:
/// ```json
/// {"keys":[{"alg":"RS256","e":"AQAB","n":"..","kty":"RSA","kid":"..","use":"sig"},{...}]}
/// ```
/// The order of fields inside each key varies, so we don't try to reconstruct
/// the canonical bytes — we slice the original response.
pub fn parse_jwks_body(body: &[u8]) -> Result<Vec<ParsedJwk>> {
    let v: Value = serde_json::from_slice(body)?;
    let keys = v
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| Error::Jwks {
            detail: "no keys[] array".into(),
        })?;

    let mut out = Vec::with_capacity(keys.len());
    for jwk in keys {
        let kid = jwk
            .get("kid")
            .and_then(|s| s.as_str())
            .ok_or_else(|| Error::Jwks {
                detail: "jwk missing kid".into(),
            })?
            .to_string();
        let n_b64 = jwk
            .get("n")
            .and_then(|s| s.as_str())
            .ok_or_else(|| Error::Jwks {
                detail: "jwk missing n".into(),
            })?
            .to_string();
        let raw = find_jwk_object_bytes(body, &kid).ok_or_else(|| Error::Jwks {
            detail: format!("could not slice jwk for kid={kid}"),
        })?;
        out.push(ParsedJwk {
            kid,
            n_b64url: n_b64,
            raw_object_bytes: raw,
        });
    }
    Ok(out)
}

/// Return the slice of `body` that constitutes the JWK object containing the
/// given `kid`. Robust to field-order variation, JSON whitespace, and
/// pretty-printed responses (Google currently emits 2-space indentation).
fn find_jwk_object_bytes(body: &[u8], kid: &str) -> Option<Vec<u8>> {
    // Locate the value bytes via the quoted kid string. JWK objects only
    // contain string fields with unique values (the kid is a 40-char hex)
    // so this lookup is unambiguous.
    let value_needle = format!("\"{kid}\"");
    let pos = body
        .windows(value_needle.len())
        .position(|w| w == value_needle.as_bytes())?;

    // Walk back to the enclosing `{`. JWK objects do not contain nested
    // objects, so the first `{` we encounter is the JWK's opening brace.
    let mut start = pos;
    while start > 0 && body[start] != b'{' {
        start -= 1;
    }
    if start == 0 && body.first() != Some(&b'{') {
        return None;
    }

    // Walk forward to the matching `}`. Same reasoning — no nested objects.
    let mut end = pos + value_needle.len();
    while end < body.len() && body[end - 1] != b'}' {
        end += 1;
    }
    if end > body.len() {
        return None;
    }
    Some(body[start..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = br#"{"keys":[{"alg":"RS256","e":"AQAB","n":"AAA","kty":"RSA","kid":"k1","use":"sig"},{"use":"sig","kty":"RSA","kid":"k2","alg":"RS256","n":"BBB","e":"AQAB"}]}"#;

    #[test]
    fn parses_two_keys() {
        let out = parse_jwks_body(SAMPLE).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].kid, "k1");
        assert_eq!(out[0].n_b64url, "AAA");
        assert!(out[0].raw_object_bytes.starts_with(b"{"));
        assert!(out[0].raw_object_bytes.ends_with(b"}"));
        assert!(std::str::from_utf8(&out[0].raw_object_bytes)
            .unwrap()
            .contains(r#""kid":"k1""#));
    }

    #[test]
    fn handles_field_order_variation() {
        let out = parse_jwks_body(SAMPLE).unwrap();
        assert_eq!(out[1].kid, "k2");
        assert_eq!(out[1].n_b64url, "BBB");
        let s = std::str::from_utf8(&out[1].raw_object_bytes).unwrap();
        assert!(s.contains(r#""n":"BBB""#));
        assert!(s.contains(r#""kid":"k2""#));
    }
}
