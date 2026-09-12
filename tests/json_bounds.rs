//! Bounds on the open JSON a credential carries.
//!
//! Some members of a DTG credential are arbitrary JSON: a VEC's `endorsement`,
//! `credentialStatus`, and any top-level member this library does not model. Digesting,
//! signing and verifying all walk those values recursively, so a value nested deeply enough
//! exhausts the stack — and a stack overflow aborts the process rather than returning an
//! error.
//!
//! [`MAX_JSON_DEPTH`] bounds them, and the check that enforces it does not recurse. The deep
//! cases below run on a deliberately small stack, so a regression that puts a recursive walk
//! back ahead of the check aborts this test binary instead of passing quietly. That is also
//! why these tests are a binary of their own.

use chrono::{DateTime, Duration, TimeZone, Utc};
use dtg_credentials::{DTGCredential, DTGCredentialError, MAX_JSON_DEPTH, digest_multibase_json};
use serde_json::{Value, json};

/// Small enough that recursively cloning or canonicalizing a value [`OVER_DEEP`] levels deep
/// overflows it in a debug build, and large enough for everything else these tests do.
const SMALL_STACK: usize = 256 * 1024;

/// Past [`MAX_JSON_DEPTH`], short of serde_json's parser limit, and deep enough to overflow
/// [`SMALL_STACK`] if walked recursively.
const OVER_DEEP: usize = 200;

// Anything this library signs must parse back under serde_json's default recursion limit,
// or it could never be verified by a stock verifier.
const _: () = assert!(MAX_JSON_DEPTH < 127);

const ISSUER: &str = "did:example:issuer";
const SUBJECT: &str = "did:example:subject";

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 6, 10, 0, 0).unwrap()
}

/// A JSON value `depth` levels deep, counting the value itself as one: `deep(1)` is a
/// string, `deep(2)` an object holding one. Built in a loop rather than recursively.
fn deep(depth: usize) -> Value {
    let mut value = json!("leaf");
    for _ in 1..depth {
        value = json!({ "n": value });
    }
    value
}

/// A VEC carrying `endorsement`, which sits at depth 3 of the document: the credential,
/// then `credentialSubject`, then the member itself.
fn endorsing(endorsement: Value) -> DTGCredential {
    DTGCredential::new_vec(ISSUER.into(), SUBJECT.into(), t0(), None, endorsement)
}

/// Runs `f` on a thread with [`SMALL_STACK`]. An overflow aborts the whole binary, which is
/// the intended way for these tests to fail.
///
/// Hand anything deep back out of `f` so that it is dropped on the caller's stack instead:
/// dropping a `serde_json::Value` recurses too, and that is not what is under test.
fn on_a_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .name("small-stack".into())
        .stack_size(SMALL_STACK)
        .spawn(f)
        .expect("spawns")
        .join()
        .expect("runs to completion")
}

fn is_too_deep<T: std::fmt::Debug>(result: &Result<T, DTGCredentialError>) -> bool {
    matches!(result, Err(DTGCredentialError::JsonTooDeep { max }) if *max == MAX_JSON_DEPTH)
}

#[test]
fn an_endorsement_within_the_bound_is_digested() {
    endorsing(deep(MAX_JSON_DEPTH - 3))
        .digest_multibase()
        .expect("comfortably within the bound");

    let at_the_bound = endorsing(deep(MAX_JSON_DEPTH - 2));
    at_the_bound
        .validate()
        .expect("a document exactly at the bound is accepted");
    at_the_bound
        .digest_multibase()
        .expect("a document exactly at the bound is digested");
}

/// The bound is on the document, not on the member: two levels of envelope sit above an
/// endorsement, so one level more than that crosses it.
#[test]
fn the_bound_counts_from_the_top_of_the_credential() {
    let vec = endorsing(deep(MAX_JSON_DEPTH - 1));

    assert!(is_too_deep(&vec.validate()));
    assert!(is_too_deep(&vec.digest_multibase()));
}

#[test]
fn an_endorsement_beyond_the_bound_is_refused() {
    let vec = endorsing(deep(MAX_JSON_DEPTH + 1));

    assert!(is_too_deep(&vec.validate()));
    assert!(is_too_deep(&vec.digest_multibase()));
    assert!(is_too_deep(&digest_multibase_json(
        &serde_json::to_value(&vec).unwrap()
    )));
}

/// `credentialStatus` is attached after construction, so it is caught where the credential
/// is validated or digested rather than where it is built.
#[test]
fn a_credential_status_beyond_the_bound_is_refused() {
    let vdc = DTGCredential::new_vdc(
        ISSUER.into(),
        SUBJECT.into(),
        t0(),
        t0() + Duration::days(1),
        vec!["sign:invoices".into()],
        None,
    )
    .expect("a bounded grant")
    // A top-level member sits at depth 2, so this takes the document one past the bound.
    .with_credential_status(deep(MAX_JSON_DEPTH));

    assert!(is_too_deep(&vdc.validate()));
    assert!(is_too_deep(&vdc.digest_multibase()));
}

#[test]
fn an_unmodelled_member_beyond_the_bound_is_refused() {
    let mut vmc = DTGCredential::new_vmc(ISSUER.into(), SUBJECT.into(), t0(), None, false);
    vmc.credential_mut()
        .extra
        .insert("evidence".into(), deep(MAX_JSON_DEPTH));

    assert!(is_too_deep(&vmc.validate()));
    assert!(is_too_deep(&vmc.digest_multibase()));
}

/// The case the bound exists for: a document deep enough that walking it recursively would
/// exhaust the stack is refused with an error, not an abort.
#[test]
fn a_deep_document_is_refused_without_exhausting_the_stack() {
    let mut doc = serde_json::to_value(DTGCredential::new_vmc(
        ISSUER.into(),
        SUBJECT.into(),
        t0(),
        None,
        false,
    ))
    .unwrap();
    doc["evidence"] = deep(OVER_DEEP);

    let (digest, doc) = on_a_small_stack(move || (digest_multibase_json(&doc), doc));

    assert!(is_too_deep(&digest), "got {digest:?}");
    drop(doc);
}

#[test]
fn a_deep_endorsement_is_refused_without_exhausting_the_stack() {
    let vec = endorsing(deep(OVER_DEEP));

    let (digest, validated, vec) =
        on_a_small_stack(move || (vec.digest_multibase(), vec.validate(), vec));

    assert!(is_too_deep(&digest), "got {digest:?}");
    assert!(is_too_deep(&validated), "got {validated:?}");
    drop(vec);
}

/// A VAC or VDC received from a counterparty has a member read out of it before it is
/// digested, and reading clones that member. The bound is checked ahead of that as well.
#[test]
fn deriving_from_a_deep_parent_is_refused_without_exhausting_the_stack() {
    let mut vac = serde_json::to_value(
        DTGCredential::new_vac(
            ISSUER.into(),
            SUBJECT.into(),
            ISSUER.into(),
            vec!["read".into()],
            t0(),
            t0() + Duration::days(1),
        )
        .unwrap(),
    )
    .unwrap();
    vac["credentialSubject"]["authority"] = deep(OVER_DEEP);

    let mut vdc = serde_json::to_value(
        DTGCredential::new_vdc(
            ISSUER.into(),
            SUBJECT.into(),
            t0(),
            t0() + Duration::days(1),
            vec!["sign:invoices".into()],
            Some(1),
        )
        .unwrap(),
    )
    .unwrap();
    vdc["credentialSubject"]["delegation"] = deep(OVER_DEEP);

    let (attenuated, redelegated, vac, vdc) = on_a_small_stack(move || {
        let attenuated = DTGCredential::attenuate_from_json(
            &vac,
            "did:example:agent".into(),
            vec!["read".into()],
            t0(),
            t0() + Duration::hours(1),
        );
        let redelegated = DTGCredential::redelegate_from_json(
            &vdc,
            "did:example:agent".into(),
            vec!["sign:invoices".into()],
            t0(),
            t0() + Duration::hours(1),
        );
        (attenuated, redelegated, vac, vdc)
    });

    assert!(is_too_deep(&attenuated), "got {attenuated:?}");
    assert!(is_too_deep(&redelegated), "got {redelegated:?}");
    drop((vac, vdc));
}

/// Answering a grant digests the document the counterparty sent, in the wire form it
/// arrived in. The `_for` constructors reach that digest only after the member and the
/// grant's expiry have been read, so the bound has to hold at the end of that sequence as
/// well as at the start of a derivation.
#[test]
fn answering_a_deep_grant_is_refused_without_exhausting_the_stack() {
    let until = t0() + Duration::days(30);

    let mut membership = serde_json::to_value(DTGCredential::new_vmc(
        ISSUER.into(),
        SUBJECT.into(),
        t0(),
        Some(until),
        false,
    ))
    .unwrap();
    membership["evidence"] = deep(OVER_DEEP);

    let mut delegation = serde_json::to_value(
        DTGCredential::new_vdc(
            ISSUER.into(),
            SUBJECT.into(),
            t0(),
            until,
            vec!["sign:invoices".into()],
            None,
        )
        .unwrap(),
    )
    .unwrap();
    delegation["evidence"] = deep(OVER_DEEP);

    // The subject of each grant answers its own grant, so the member check passes and the
    // digest is reached.
    let (acknowledged, accepted, membership, delegation) = on_a_small_stack(move || {
        let acknowledged =
            DTGCredential::new_member_vmc_for(&membership, SUBJECT, t0(), Some(until));
        let accepted = DTGCredential::new_delegate_vdc_for(&delegation, SUBJECT, t0(), until);
        (acknowledged, accepted, membership, delegation)
    });

    assert!(is_too_deep(&acknowledged), "got {acknowledged:?}");
    assert!(is_too_deep(&accepted), "got {accepted:?}");
    drop((membership, delegation));
}

/// serde_json refuses to parse JSON nested 128 levels deep by default, which is what bounds
/// a credential arriving over the wire before it reaches this library. Pinned, because
/// [`MAX_JSON_DEPTH`] is chosen relative to it.
#[test]
fn serde_json_still_limits_parsing_depth() {
    let nested = |levels: usize| format!("{}1{}", "[".repeat(levels), "]".repeat(levels));

    assert!(serde_json::from_str::<Value>(&nested(127)).is_ok());

    let err = serde_json::from_str::<Value>(&nested(128)).unwrap_err();
    assert!(
        err.to_string().contains("recursion limit exceeded"),
        "{err}"
    );
}

/// Anything within the bound survives the trip a verifier puts it through.
#[test]
fn a_credential_at_the_bound_parses_back() {
    let vec = endorsing(deep(MAX_JSON_DEPTH - 2));
    vec.validate().expect("at the bound");

    let back: DTGCredential =
        serde_json::from_str(&serde_json::to_string(&vec).unwrap()).expect("parses");
    assert_eq!(
        back.digest_multibase().unwrap(),
        vec.digest_multibase().unwrap()
    );
}

/// An endorsement is open vocabulary — the specification does not define its content — so
/// this library bounds its shape and nothing else. Whatever the issuer put there is carried
/// verbatim, and a consumer must verify the proof and the issuer's standing before relying
/// on any of it.
#[test]
fn open_members_are_carried_verbatim_within_the_bound() {
    let endorsement = json!({
        "type": "SkillEndorsement",
        "role": "platform-owner",
        "note": "A".repeat(8192)
    });

    let vec = endorsing(endorsement.clone());
    vec.validate().expect("shallow, however large");

    let wire = serde_json::to_value(&vec).unwrap();
    assert_eq!(wire["credentialSubject"]["endorsement"], endorsement);
}

#[cfg(feature = "affinidi-signing")]
mod signing {
    use super::*;
    use affinidi_secrets_resolver::secrets::Secret;
    use dtg_credentials::verify_grant_with_public_key;

    #[tokio::test]
    async fn sign_refuses_a_deep_endorsement() {
        let secret = Secret::generate_ed25519(None, None);
        let mut vec = endorsing(deep(MAX_JSON_DEPTH + 1));

        assert!(is_too_deep(&vec.sign(&secret, None).await));
        assert!(!vec.signed(), "a refused credential must not carry a proof");
    }

    /// Verifying a grant is the one entry point handed a whole document by a counterparty
    /// before anything about it is established, so it is the one most worth running on a
    /// stack too small to walk a hostile value.
    ///
    /// The grant is signed before the deep member is attached. Without the bound, the
    /// verifier gets as far as cloning the document to strip `proof` from it, and that clone
    /// recurses; an unsigned grant would be refused before reaching it and prove nothing.
    #[tokio::test]
    async fn verifying_a_deep_grant_is_refused_without_exhausting_the_stack() {
        let secret = Secret::generate_ed25519(Some(&format!("{ISSUER}#key-1")), None);
        let mut grant = DTGCredential::new_vmc(ISSUER.into(), SUBJECT.into(), t0(), None, false);
        grant.sign(&secret, None).await.expect("signs");

        let mut grant = serde_json::to_value(&grant).unwrap();
        grant["credentialStatus"] = deep(OVER_DEEP);
        let key = secret.get_public_bytes().to_vec();

        let (verified, grant) =
            on_a_small_stack(move || (verify_grant_with_public_key(&grant, &key, t0()), grant));

        assert!(is_too_deep(&verified), "got {verified:?}");
        drop(grant);
    }

    /// A signed credential given a deep member afterwards is refused before its proof is
    /// examined, rather than walked by the verifier.
    #[tokio::test]
    async fn verification_refuses_a_deep_member() {
        let secret = Secret::generate_ed25519(None, None);
        let mut vmc = DTGCredential::new_vmc(ISSUER.into(), SUBJECT.into(), t0(), None, false);
        vmc.sign(&secret, None).await.expect("signs");

        vmc.set_credential_status(deep(MAX_JSON_DEPTH));

        assert!(is_too_deep(
            &vmc.verify_proof_with_public_key(secret.get_public_bytes())
        ));
    }
}
