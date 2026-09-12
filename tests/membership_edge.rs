//! Membership edges: what building an acknowledgement establishes, and what it does not.
//!
//! An acknowledgement is built from the grant a member received, in its wire form. The
//! member and the community are read off that grant, which keeps the two halves naming the
//! same pair. [`DTGCredential::new_member_vmc_for`] also takes the member the caller expects
//! and refuses a grant naming anyone else, and refuses an acknowledgement that would outlive
//! the grant it answers.
//!
//! Building is binding, not verification. Nothing here establishes that the community signed
//! the grant; `verify_grant_with_public_key` does, and the cases at the bottom pin it.

use chrono::{DateTime, Duration, TimeZone, Utc};
use dtg_credentials::{
    DTGCredential, DTGCredentialError, DTGCredentialType, digest_multibase_json,
};
use serde_json::{Value, json};

const COMMUNITY: &str = "did:example:community";
const MEMBER: &str = "did:example:member";
const SOMEONE_ELSE: &str = "did:example:someone-else";
const ATTACKER: &str = "did:example:attacker";

fn t(h: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 6, 10, 0, 0).unwrap() + Duration::hours(h)
}

/// A community-issued grant in the wire form a member receives. Nobody has signed it.
fn unsigned_grant(community: &str, member: &str, valid_until: Option<DateTime<Utc>>) -> Value {
    serde_json::to_value(DTGCredential::new_vmc(
        community.into(),
        member.into(),
        t(0),
        valid_until,
        false,
    ))
    .unwrap()
}

/// A grant nobody issued: hand-written by `member`, naming `community` as its issuer and
/// carrying no proof, because the community it names never signed anything. Written out
/// rather than built, since an attacker has no reason to use this library's constructors.
fn forged_grant(community: &str, member: &str) -> Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://firstperson.network/credentials/dtg/v1"
        ],
        "type": ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
        "issuer": community,
        "validFrom": "2026-01-06T10:00:00Z",
        "credentialSubject": { "id": member }
    })
}

/// The ordinary case, and the roles it produces: the member issues, the community is the
/// subject, and the digest binds the exact grant received.
#[test]
fn an_acknowledgement_is_built_for_the_member_the_grant_names() {
    let grant = unsigned_grant(COMMUNITY, MEMBER, None);

    let ack = DTGCredential::new_member_vmc_for(&grant, MEMBER, t(1), None).expect("builds");

    assert_eq!(ack.type_(), DTGCredentialType::Membership);
    assert_eq!(ack.issuer(), MEMBER, "the member is read off the grant");
    assert_eq!(ack.subject(), COMMUNITY, "and so is the community");
    assert_eq!(
        ack.subject_digest(),
        Some(digest_multibase_json(&grant).unwrap().as_str())
    );

    let grant: DTGCredential = serde_json::from_value(grant).unwrap();
    assert!(ack.acknowledges(&grant).unwrap());
}

/// A member answers a grant for itself. A grant naming anybody else is refused, and the
/// error says who was expected and who was found.
#[test]
fn a_grant_naming_someone_else_is_refused() {
    let grant = unsigned_grant(COMMUNITY, SOMEONE_ELSE, None);

    let err = DTGCredential::new_member_vmc_for(&grant, MEMBER, t(1), None).unwrap_err();
    assert!(
        matches!(
            err,
            DTGCredentialError::NotTheGrantSubject { ref expected, ref found }
                if expected == MEMBER && found == SOMEONE_ELSE
        ),
        "got {err:?}"
    );

    // Compared exactly: an identifier that merely begins the same way is someone else.
    let grant = unsigned_grant(COMMUNITY, "did:example:member-2", None);
    let err = DTGCredential::new_member_vmc_for(&grant, MEMBER, t(1), None).unwrap_err();
    assert!(
        matches!(err, DTGCredentialError::NotTheGrantSubject { .. }),
        "got {err:?}"
    );
}

/// An acknowledgement that outlives its grant records consent to a membership that has
/// already ended.
#[test]
fn an_acknowledgement_may_not_outlive_its_grant() {
    let grant = unsigned_grant(COMMUNITY, MEMBER, Some(t(24 * 30)));

    let err =
        DTGCredential::new_member_vmc_for(&grant, MEMBER, t(1), Some(t(24 * 31))).unwrap_err();
    assert!(
        matches!(
            err,
            DTGCredentialError::OutlivesGrant { valid_until: Some(until), grant_valid_until }
                if until == t(24 * 31) && grant_valid_until == t(24 * 30)
        ),
        "got {err:?}"
    );

    // Open-ended, against a grant that expires, outlives it too.
    let err = DTGCredential::new_member_vmc_for(&grant, MEMBER, t(1), None).unwrap_err();
    assert!(
        matches!(
            err,
            DTGCredentialError::OutlivesGrant {
                valid_until: None,
                ..
            }
        ),
        "got {err:?}"
    );

    DTGCredential::new_member_vmc_for(&grant, MEMBER, t(1), Some(t(24 * 30)))
        .expect("ending with the grant is within it");
    DTGCredential::new_member_vmc_for(&grant, MEMBER, t(1), Some(t(24)))
        .expect("ending before the grant is within it");
}

/// A grant with no expiry places no bound on the acknowledgement.
#[test]
fn a_grant_without_an_expiry_bounds_nothing() {
    let grant = unsigned_grant(COMMUNITY, MEMBER, None);

    DTGCredential::new_member_vmc_for(&grant, MEMBER, t(1), None).expect("open-ended");
}

/// An expiry that cannot be read is not the same as no expiry, so it is refused rather than
/// ignored.
#[test]
fn a_grant_with_an_unreadable_expiry_is_refused() {
    let mut grant = unsigned_grant(COMMUNITY, MEMBER, None);
    grant["validUntil"] = json!("next year");

    let err = DTGCredential::new_member_vmc_for(&grant, MEMBER, t(1), Some(t(24))).unwrap_err();
    assert!(
        matches!(err, DTGCredentialError::NotAMembershipGrant(_)),
        "got {err:?}"
    );
}

#[test]
fn an_inverted_window_is_refused() {
    let grant = unsigned_grant(COMMUNITY, MEMBER, None);

    for (from, until) in [(t(24), t(1)), (t(1), t(1))] {
        let err = DTGCredential::new_member_vmc_for(&grant, MEMBER, from, Some(until)).unwrap_err();
        assert!(
            matches!(err, DTGCredentialError::InvalidValidityWindow { .. }),
            "got {err:?}"
        );
    }
}

/// Building an acknowledgement, and `acknowledges`, both check the binding and nothing more.
/// Both succeed against a grant nobody signed, which is why a grant is verified before it is
/// answered, and why an edge is not complete until both proofs have been.
#[test]
fn binding_does_not_establish_that_the_grant_was_signed() {
    let grant = unsigned_grant(COMMUNITY, MEMBER, None);

    let ack = DTGCredential::new_member_vmc_for(&grant, MEMBER, t(1), None).expect("builds");
    let grant: DTGCredential = serde_json::from_value(grant).unwrap();

    assert!(!grant.signed());
    assert!(
        ack.acknowledges(&grant).unwrap(),
        "the binding holds whether or not anybody signed the grant"
    );
}

/// Naming yourself is the one grant the member check cannot refuse: it compares the grant
/// with the identity the caller expects, and an attacker writing its own grant satisfies
/// both sides of that comparison. So the constructor builds, and the binding holds — which
/// is the whole of what building an acknowledgement claims. The step that refuses this
/// grant is verifying it, pinned in
/// `verifying_the_grant::a_grant_its_own_subject_wrote_does_not_verify`.
#[test]
fn a_grant_its_own_subject_wrote_satisfies_the_member_check() {
    let forged = forged_grant(COMMUNITY, ATTACKER);

    let ack = DTGCredential::new_member_vmc_for(&forged, ATTACKER, t(1), None)
        .expect("the expected member and the grant's subject are the same identifier");
    assert_eq!(ack.issuer(), ATTACKER);
    assert_eq!(ack.subject(), COMMUNITY);
    assert_eq!(
        ack.subject_digest(),
        Some(digest_multibase_json(&forged).unwrap().as_str())
    );

    let forged: DTGCredential = serde_json::from_value(forged).unwrap();
    assert!(!forged.signed(), "the community it names never signed it");
    assert!(
        ack.acknowledges(&forged).unwrap(),
        "the binding holds; it is a binding to a document, not to a membership"
    );
}

/// The deprecated constructor keeps its behaviour for existing callers: the member is taken
/// from the grant without comparison, and the grant's expiry is not consulted. Its own window
/// is checked, as every constructor's is.
#[test]
#[allow(deprecated)]
fn the_deprecated_constructor_checks_neither_the_member_nor_the_grant_expiry() {
    let grant = unsigned_grant(COMMUNITY, SOMEONE_ELSE, Some(t(24)));

    let ack = DTGCredential::new_member_vmc(&grant, t(1), None).expect("builds");
    assert_eq!(ack.issuer(), SOMEONE_ELSE);

    assert!(matches!(
        DTGCredential::new_member_vmc(&grant, t(2), Some(t(1))),
        Err(DTGCredentialError::InvalidValidityWindow { .. })
    ));
}

#[cfg(feature = "affinidi-signing")]
mod verifying_the_grant {
    use super::*;
    use affinidi_secrets_resolver::secrets::Secret;
    use dtg_credentials::verify_grant_with_public_key;

    /// A fresh key whose verification method belongs to `did`.
    fn key_of(did: &str) -> Secret {
        Secret::generate_ed25519(Some(&format!("{did}#key-1")), None)
    }

    /// A grant from `community` to `member`, valid for 30 days, signed by `signer`.
    async fn signed_grant(community: &str, member: &str, signer: &Secret) -> Value {
        let mut grant = DTGCredential::new_vmc(
            community.into(),
            member.into(),
            t(0),
            Some(t(24 * 30)),
            false,
        );
        grant.sign(signer, None).await.expect("signs");
        serde_json::to_value(&grant).unwrap()
    }

    #[test]
    fn an_unsigned_grant_does_not_verify() {
        let key = key_of(COMMUNITY);
        let grant = unsigned_grant(COMMUNITY, MEMBER, None);

        let err = verify_grant_with_public_key(&grant, key.get_public_bytes(), t(1)).unwrap_err();
        assert!(matches!(err, DTGCredentialError::NotSigned), "got {err:?}");
    }

    /// A grant its own subject wrote carries no proof from the community it names, so it
    /// does not verify under that community's key. A member that verifies before answering
    /// never reaches the constructor with it.
    #[test]
    fn a_grant_its_own_subject_wrote_does_not_verify() {
        let key = key_of(COMMUNITY);

        let err = verify_grant_with_public_key(
            &forged_grant(COMMUNITY, ATTACKER),
            key.get_public_bytes(),
            t(1),
        )
        .unwrap_err();
        assert!(matches!(err, DTGCredentialError::NotSigned), "got {err:?}");
    }

    /// The whole sequence a member follows: verify the grant, then answer it.
    #[tokio::test]
    async fn a_signed_grant_verifies_and_can_then_be_acknowledged() {
        let key = key_of(COMMUNITY);
        let grant = signed_grant(COMMUNITY, MEMBER, &key).await;

        verify_grant_with_public_key(&grant, key.get_public_bytes(), t(1))
            .expect("signed by its issuer, and in force");

        let ack = DTGCredential::new_member_vmc_for(&grant, MEMBER, t(1), Some(t(24 * 30)))
            .expect("builds");
        let grant: DTGCredential = serde_json::from_value(grant).unwrap();
        assert!(ack.acknowledges(&grant).unwrap());
    }

    #[tokio::test]
    async fn a_grant_altered_after_signing_does_not_verify() {
        let key = key_of(COMMUNITY);
        let mut grant = signed_grant(COMMUNITY, SOMEONE_ELSE, &key).await;
        grant["credentialSubject"]["id"] = json!(MEMBER);

        let err = verify_grant_with_public_key(&grant, key.get_public_bytes(), t(1)).unwrap_err();
        assert!(
            matches!(err, DTGCredentialError::DataIntegrity(_)),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn the_wrong_key_does_not_verify() {
        let grant = signed_grant(COMMUNITY, MEMBER, &key_of(COMMUNITY)).await;
        let other = key_of(COMMUNITY);

        let err = verify_grant_with_public_key(&grant, other.get_public_bytes(), t(1)).unwrap_err();
        assert!(
            matches!(err, DTGCredentialError::DataIntegrity(_)),
            "got {err:?}"
        );
    }

    /// A valid signature is not enough: it has to be the issuer's. A grant naming the
    /// community as issuer but signed with another party's key is refused even when checked
    /// against that party's key.
    #[tokio::test]
    async fn a_proof_by_anyone_but_the_issuer_is_refused() {
        let other = key_of(SOMEONE_ELSE);
        let grant = signed_grant(COMMUNITY, MEMBER, &other).await;

        let err = verify_grant_with_public_key(&grant, other.get_public_bytes(), t(1)).unwrap_err();
        assert!(
            matches!(
                err,
                DTGCredentialError::ProofNotFromIssuer { ref issuer, ref verification_method }
                    if issuer == COMMUNITY && verification_method == "did:example:someone-else#key-1"
            ),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_grant_outside_its_window_does_not_verify() {
        let key = key_of(COMMUNITY);
        let grant = signed_grant(COMMUNITY, MEMBER, &key).await;

        for at in [t(-1), t(24 * 31)] {
            let err = verify_grant_with_public_key(&grant, key.get_public_bytes(), at).unwrap_err();
            assert!(
                matches!(err, DTGCredentialError::NotValidAt { at: when } if when == at),
                "got {err:?}"
            );
        }
    }
}
