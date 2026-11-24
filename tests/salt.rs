//! `salt` (DTG Core Credentials, *Base Structure* and *Digest Encoding — Salting*).
//!
//! Defined only by context `v3`, which sits behind the `context-v3` feature until the
//! registry publishes it. Whatever the build, a `salt` under `v1` or `v2` is refused. With
//! the feature on, every constructor issues under `v3` with a fresh 32-byte salt, and a
//! `v3` credential without one, or with one of the wrong length or encoding, is refused.

use chrono::{DateTime, TimeZone, Utc};
use dtg_credentials::{
    DTG_CONTEXT_V1, DTG_CONTEXT_V2, DTGCredential, DTGCredentialError, IssuerScope,
    W3C_VC_V2_CONTEXT,
};
use serde_json::{Value, json};

/// The context `v3` IRI, spelled out so the feature-off tests can name it too.
const V3: &str = "https://registry.trustoverip.org/dtg/context/v3";

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 6, 10, 0, 0).unwrap()
}

fn grant() -> DTGCredential {
    DTGCredential::new_vmc(
        "did:example:community".into(),
        IssuerScope::Directed,
        "did:example:member".into(),
        t0(),
        None,
        false,
    )
}

/// A minimal grant listing `context` second, with `salt` if given.
fn doc(context: &str, salt: Option<Value>) -> Value {
    let mut doc = json!({
        "@context": [W3C_VC_V2_CONTEXT, context],
        "type": ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
        "issuer": "did:example:community",
        "issuerScope": "public",
        "validFrom": "2026-01-06T10:00:00Z",
        "credentialSubject": { "id": "did:example:member" },
    });
    if let Some(salt) = salt {
        doc["salt"] = salt;
    }
    doc
}

fn parse(doc: Value) -> Result<DTGCredential, DTGCredentialError> {
    DTGCredential::try_from(doc)
}

/// `z` + base-58-btc of `len` bytes.
fn salt_of(len: usize) -> Value {
    json!(multibase::encode(
        multibase::Base::Base58Btc,
        vec![7u8; len]
    ))
}

/// `v1` and `v2` do not define `salt`, so a credential listing either and carrying one is
/// refused — in every build, not only one that knows `v3`. Before, it passed through as an
/// unmodelled member.
#[test]
fn a_salt_under_v1_or_v2_is_refused() {
    for context in [DTG_CONTEXT_V1, DTG_CONTEXT_V2] {
        assert!(
            parse(doc(context, None)).is_ok(),
            "{context} without a salt"
        );
        let err = parse(doc(context, Some(salt_of(32)))).unwrap_err();
        assert!(
            matches!(err, DTGCredentialError::InvalidSalt(_)),
            "{context}: {err:?}"
        );
    }
}

/// [DTGCredential::validate] — and so `sign` — refuses the same, so a salt added to a v1
/// credential after construction cannot be signed.
#[cfg(not(feature = "context-v3"))]
#[test]
fn validate_refuses_a_salt_under_v1() {
    let mut vmc = grant();
    assert_eq!(vmc.credential().salt, None);
    vmc.credential_mut().salt = Some(salt_of(32).as_str().unwrap().to_string());
    assert!(matches!(
        vmc.validate(),
        Err(DTGCredentialError::InvalidSalt(_))
    ));
}

/// Without the feature `v3` is not a recognized context, salted or not, and nothing this
/// library builds carries a salt.
#[cfg(not(feature = "context-v3"))]
#[test]
fn without_the_feature_v3_is_not_recognized_and_nothing_is_salted() {
    for salt in [None, Some(salt_of(32))] {
        assert!(matches!(
            parse(doc(V3, salt)),
            Err(DTGCredentialError::InvalidContext(_))
        ));
    }
    let wire = serde_json::to_value(grant().credential()).unwrap();
    assert_eq!(wire["@context"][1], DTG_CONTEXT_V1);
    assert!(wire.get("salt").is_none());
}

#[cfg(feature = "context-v3")]
mod v3 {
    use super::*;
    use dtg_credentials::{DTG_CONTEXT_V3, SALT_LEN, digest_multibase_json};

    #[test]
    fn the_v3_iri_follows_the_registry_pattern() {
        assert_eq!(DTG_CONTEXT_V3, V3);
        assert_eq!(SALT_LEN, 32);
    }

    /// Every constructor issues under `v3` with a salt of exactly 32 bytes in
    /// base-58-btc multibase, and the result parses.
    #[test]
    fn constructors_issue_under_v3_with_a_32_byte_salt() {
        let vmc = grant();
        let wire = serde_json::to_value(vmc.credential()).unwrap();
        assert_eq!(wire["@context"][1], DTG_CONTEXT_V3);
        let salt = wire["salt"].as_str().expect("a salt");
        assert!(salt.starts_with('z'));
        let (base, bytes) = multibase::decode(salt).unwrap();
        assert_eq!(base, multibase::Base::Base58Btc);
        assert_eq!(bytes.len(), 32);

        vmc.validate().unwrap();
        assert_eq!(
            parse(wire.clone()).unwrap().credential().salt.as_deref(),
            Some(salt)
        );
    }

    /// Fresh for each credential: re-issuing identical claims draws a new salt, and with it
    /// a new digest — which is what stops a digest being tested against guessed content.
    #[test]
    fn re_issuing_draws_a_new_salt_and_a_new_digest() {
        let (a, b) = (grant(), grant());
        assert_ne!(a.credential().salt, b.credential().salt);
        assert_ne!(a.digest_multibase().unwrap(), b.digest_multibase().unwrap());

        // The salt is inside what the digest covers.
        let mut wire = serde_json::to_value(a.credential()).unwrap();
        let salted = digest_multibase_json(&wire).unwrap();
        wire.as_object_mut().unwrap().remove("salt");
        assert_ne!(salted, digest_multibase_json(&wire).unwrap());
    }

    /// A `v3` credential carries a salt, and exactly 32 bytes of base-58-btc.
    #[test]
    fn v3_refuses_a_missing_short_long_or_misencoded_salt() {
        assert!(parse(doc(V3, Some(salt_of(32)))).is_ok());
        let bad = [
            None,
            Some(salt_of(31)),
            Some(salt_of(33)),
            Some(salt_of(0)),
            // 32 bytes, but base-64 rather than base-58-btc.
            Some(json!(multibase::encode(multibase::Base::Base64, [7u8; 32]))),
            Some(json!("not multibase")),
        ];
        for salt in bad {
            let err = parse(doc(V3, salt.clone())).unwrap_err();
            assert!(
                matches!(err, DTGCredentialError::InvalidSalt(_)),
                "{salt:?}: {err:?}"
            );
        }
        assert!(parse(doc(V3, Some(json!(32)))).is_err(), "not a string");
    }

    /// `v1` and `v2` stay accepted without a salt, and the acknowledgement of a salted
    /// grant is itself salted.
    #[test]
    fn v1_and_v2_remain_accepted_and_acknowledgements_are_salted() {
        assert!(parse(doc(DTG_CONTEXT_V1, None)).is_ok());
        assert!(parse(doc(DTG_CONTEXT_V2, None)).is_ok());

        let grant = serde_json::to_value(grant().credential()).unwrap();
        let ack = DTGCredential::new_member_vmc_for(
            &grant,
            "did:example:member",
            IssuerScope::Pairwise,
            t0(),
            None,
        )
        .unwrap();
        assert_eq!(
            ack.credential().context[1],
            DTG_CONTEXT_V3,
            "the acknowledgement lists v3"
        );
        assert!(ack.credential().salt.is_some());
        assert_ne!(
            ack.credential().salt,
            grant["salt"].as_str().map(String::from)
        );
        ack.validate().unwrap();
    }

    /// Narrowing the context of a salted credential to `v1` after construction is refused
    /// before signing.
    #[test]
    fn validate_refuses_a_salted_credential_listing_v1() {
        let mut vmc = grant();
        vmc.credential_mut().context[1] = DTG_CONTEXT_V1.to_string();
        assert!(matches!(
            vmc.validate(),
            Err(DTGCredentialError::InvalidSalt(_))
        ));
        vmc.credential_mut().context[1] = DTG_CONTEXT_V3.to_string();
        vmc.credential_mut().salt = None;
        assert!(matches!(
            vmc.validate(),
            Err(DTGCredentialError::InvalidSalt(_))
        ));
    }

    /// Re-proofing keeps the salt, so a digest computed before still matches: signing is
    /// not where the salt is drawn.
    #[cfg(feature = "affinidi-signing")]
    #[tokio::test]
    async fn re_proofing_keeps_the_salt() {
        use affinidi_secrets_resolver::secrets::Secret;

        let mut vmc = grant();
        let salt = vmc.credential().salt.clone();
        let digest = vmc.digest_multibase().unwrap();

        vmc.sign(&Secret::generate_ed25519(None, None), None)
            .await
            .expect("signs");
        assert_eq!(vmc.credential().salt, salt);
        assert_eq!(vmc.digest_multibase().unwrap(), digest);

        vmc.credential_mut().proof = None;
        vmc.sign(&Secret::generate_ed25519(None, None), None)
            .await
            .expect("re-proofs");
        assert_eq!(vmc.credential().salt, salt);
        assert_eq!(vmc.digest_multibase().unwrap(), digest);
    }
}
