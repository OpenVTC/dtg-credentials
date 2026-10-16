//! A proof counts only when it was made by a key of the credential's issuer.
//!
//! A signature that verifies under some key establishes that whoever holds that key signed.
//! A caller resolving the key the proof names and then reading `issuer` would otherwise be
//! trusting a party the document merely names. Both public verification entry points —
//! [`DTGCredential::verify_proof_with_public_key`] and
//! [`dtg_credentials::verify_grant_with_public_key`] — refuse a proof whose
//! `verificationMethod` does not belong to the issuer, with
//! [`DTGCredentialError::ProofNotFromIssuer`].
#![cfg(feature = "affinidi-signing")]

use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Duration, TimeZone, Utc};
use dtg_credentials::{DTGCredential, DTGCredentialError, verify_grant_with_public_key};
use serde_json::{Value, json};

const ISSUER: &str = "did:example:community";
const SUBJECT: &str = "did:example:member";
const SOMEONE_ELSE: &str = "did:example:someone-else";

fn t(h: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 6, 10, 0, 0).unwrap() + Duration::hours(h)
}

/// A fresh key whose verification method is `method`.
fn key(method: &str) -> Secret {
    Secret::generate_ed25519(Some(method), None)
}

/// A membership grant from [ISSUER], signed with `signer`.
async fn signed(signer: &Secret) -> DTGCredential {
    let mut vmc = DTGCredential::new_vmc(ISSUER.into(), SUBJECT.into(), t(0), None, false);
    vmc.sign(signer, Some(t(0))).await.expect("signs");
    vmc
}

fn is_not_from_issuer(err: &DTGCredentialError, method: &str) -> bool {
    matches!(
        err,
        DTGCredentialError::ProofNotFromIssuer { issuer, verification_method }
            if issuer == ISSUER && verification_method == method
    )
}

/// Both entry points, over the same signed credential.
fn verify_both(vmc: &DTGCredential, signer: &Secret) -> [Result<(), DTGCredentialError>; 2] {
    let wire = serde_json::to_value(vmc).unwrap();
    [
        vmc.verify_proof_with_public_key(signer.get_public_bytes()),
        verify_grant_with_public_key(&wire, signer.get_public_bytes(), t(1)),
    ]
}

#[tokio::test]
async fn a_proof_by_a_method_of_another_did_is_refused() {
    let method = format!("{SOMEONE_ELSE}#key-1");
    let signer = key(&method);
    let vmc = signed(&signer).await;

    for result in verify_both(&vmc, &signer) {
        let err = result.expect_err("the signature is valid, but not the issuer's");
        assert!(is_not_from_issuer(&err, &method), "got {err:?}");
    }
}

/// A method that merely starts with the issuer's DID is a different DID.
#[tokio::test]
async fn a_did_extending_the_issuers_is_refused() {
    let method = format!("{ISSUER}-evil#key-1");
    let signer = key(&method);
    let vmc = signed(&signer).await;

    for result in verify_both(&vmc, &signer) {
        let err = result.expect_err("a prefix is not the issuer");
        assert!(is_not_from_issuer(&err, &method), "got {err:?}");
    }
}

/// Comparison is verbatim: a DID URL with a query before the fragment is not the issuer.
#[tokio::test]
async fn a_did_url_with_a_query_is_refused() {
    let method = format!("{ISSUER}?versionId=1#key-1");
    let signer = key(&method);
    let vmc = signed(&signer).await;

    for result in verify_both(&vmc, &signer) {
        let err = result.expect_err("not the issuer verbatim");
        assert!(is_not_from_issuer(&err, &method), "got {err:?}");
    }
}

#[tokio::test]
async fn a_method_of_the_issuer_is_accepted() {
    let signer = key(&format!("{ISSUER}#key-1"));
    let vmc = signed(&signer).await;

    for result in verify_both(&vmc, &signer) {
        result.expect("signed by a method of its issuer");
    }
}

/// A `did:key`-style method that is the issuer itself, with no fragment.
#[tokio::test]
async fn the_issuer_itself_as_the_method_is_accepted() {
    let signer = key(ISSUER);
    let vmc = signed(&signer).await;

    for result in verify_both(&vmc, &signer) {
        result.expect("the method is the issuer");
    }
}

/// A bare `#fragment` is relative, and resolves against the issuer.
#[tokio::test]
async fn a_relative_fragment_resolves_against_the_issuer() {
    let signer = key("#key-1");
    let vmc = signed(&signer).await;

    for result in verify_both(&vmc, &signer) {
        result.expect("a relative method is the issuer's");
    }
}

/// The wire form allows `issuer` as an object with an `id`; the binding reads the `id`.
#[tokio::test]
async fn an_object_form_issuer_is_bound_by_its_id() {
    let unsigned = |issuer: Value| {
        let mut wire = serde_json::to_value(DTGCredential::new_vmc(
            ISSUER.into(),
            SUBJECT.into(),
            t(0),
            None,
            false,
        ))
        .unwrap();
        wire["issuer"] = issuer;
        wire
    };
    let sign = |wire: &Value, signer: &Secret| {
        let wire = wire.clone();
        let signer = signer.clone();
        async move {
            let proof = DataIntegrityProof::sign(&wire, &signer, SignOptions::new())
                .await
                .expect("signs");
            let mut signed = wire;
            signed["proof"] = serde_json::to_value(proof).unwrap();
            signed
        }
    };

    let issuers = key(&format!("{ISSUER}#key-1"));
    let grant = sign(
        &unsigned(json!({ "id": ISSUER, "name": "A community" })),
        &issuers,
    )
    .await;
    verify_grant_with_public_key(&grant, issuers.get_public_bytes(), t(1))
        .expect("an object-form issuer signed by a method of its id");

    let method = format!("{SOMEONE_ELSE}#key-1");
    let someone_else = key(&method);
    let grant = sign(&unsigned(json!({ "id": ISSUER })), &someone_else).await;
    let err = verify_grant_with_public_key(&grant, someone_else.get_public_bytes(), t(1))
        .expect_err("an object-form issuer signed by another DID");
    assert!(is_not_from_issuer(&err, &method), "got {err:?}");
}
