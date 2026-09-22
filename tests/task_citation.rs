//! Citing a trust task: `taskContext` names the exchange, `taskDigestMultibase` binds to it.
//!
//! A VWC issued through `witness/session` + `witness/session/submit` MUST carry both, and
//! the digest MUST be the *task digest* of the `witness/session` document (Trust Tasks
//! §4.9.3): JCS over the document with its top-level `proof` removed, sha2-256, multibase.
//!
//! The vector at the top is not ours. It is the `vetting/session/0.1` example printed in
//! dtgwg-trust-tasks-tf (`specs/vetting/session/0.1/spec.md`, at 5442e97), whose Vetting
//! Statement states the real `taskDigestMultibase` of the session document as printed. A
//! second implementation's output is the only thing a digest vector is worth checking
//! against, and `witness/session/0.1` prints no document to take one from.

use chrono::{DateTime, TimeZone, Utc};
use dtg_credentials::{
    DTGCredential, DTGCredentialError, DTGCredentialType, WitnessContext, digest_multibase_json,
    task_digest_multibase_json,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};

/// The `vetting/session/0.1` request example, verbatim.
const VETTING_SESSION: &str = r#"{
  "id": "urn:uuid:9a7e4c21-5b3d-4e8f-a1c2-3d4e5f6a7b01",
  "type": "https://trusttasks.org/spec/vetting/session/0.1",
  "threadId": "urn:uuid:9a7e4c21-5b3d-4e8f-a1c2-3d4e5f6a7b01",
  "parentThreadId": "urn:uuid:6f1c2b0a-3d4e-4f5a-8b6c-7d8e9f0a1b01",
  "issuer": "did:webvh:QmCarolScid1:kernel-vtc.example:carol",
  "recipient": "did:webvh:QmAliceScid1:alice.example",
  "issuedAt": "2026-09-17T15:02:00Z",
  "payload": {
    "requestId": "urn:uuid:4b2e8f10-7a6c-4d3b-9e21-0f5a6b7c8d01",
    "challenge": "Xq3v9bT0cN2mR8sLk4Jw7pYh1eZa6uGd5fQi0oVxWnE",
    "domain": "did:webvh:QmVtcScid:kernel-vtc.example",
    "method": "video",
    "requiredClaims": ["name.legal"],
    "optionalClaims": ["account.handle"],
    "expiresAt": "2026-09-17T15:17:00Z"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:webvh:QmCarolScid1:kernel-vtc.example:carol#key-1",
    "created": "2026-09-17T15:02:00Z",
    "proofPurpose": "assertionMethod",
    "proofValue": "z63jiSzsVJshBfyZwcr6nUopHo5M1QnBnWJHtwTpdNEFeD7KoX5rezJcGeoY8AVuTSo5Q3uH2KqMoEZk68qqGu3AR"
  }
}"#;

/// The task digest the same specification prints for [VETTING_SESSION].
const VETTING_SESSION_TASK_DIGEST: &str = "zQmWAWEtpUqE3xd3LUpZ8GryGrZMCqH1A5D7bZcayvEfJTK";

/// The Vetting Statement from the same example: a DTG credential carrying
/// `taskContext` and `taskDigestMultibase` at the top level.
const VETTING_STATEMENT: &str = r#"{
  "@context": ["https://www.w3.org/ns/credentials/v2", "https://firstperson.network/credentials/dtg/v1"],
  "id": "urn:uuid:7e5d3c1b-9f8a-4b6c-a2d1-e0f9a8b7c601",
  "type": ["VerifiableCredential", "DTGCredential", "EndorsementCredential"],
  "issuer": "did:webvh:QmCarolScid1:kernel-vtc.example:carol",
  "validFrom": "2026-09-17T15:09:00Z",
  "validUntil": "2027-01-15T15:09:00Z",
  "taskContext": "urn:uuid:9a7e4c21-5b3d-4e8f-a1c2-3d4e5f6a7b01",
  "taskDigestMultibase": "zQmWAWEtpUqE3xd3LUpZ8GryGrZMCqH1A5D7bZcayvEfJTK",
  "credentialSubject": {
    "id": "did:webvh:QmAliceScid1:alice.example",
    "endorsement": {
      "type": "https://firstperson.network/endorsements/identity-vetting/0.1",
      "community": "did:webvh:QmVtcScid:kernel-vtc.example",
      "method": "video",
      "documentClasses": ["passport"],
      "claimsVerified": ["name.legal"],
      "livenessConfirmed": true,
      "identityCommitment": "zQmT7GFcSjCY7YwuK5RP3TNNF8wp7fnCfMMYjMeatbbWo7b",
      "cardDigestMultibase": "zQmYn4rU7vALWT8K9nC4vD8EcSZXFh8ZrCBDFUXgXo2pcH5",
      "declaredRelationship": "communityColleague",
      "attestationTextDigest": "zQmappH2ogZX2jVEmxitPLHKtA82EmxJjkPWo3szBErmNFj"
    }
  }
}"#;

const WITNESS: &str = "did:webvh:QmWitnessScid:witness.example";
const ALICE: &str = "did:peer:2.alice-relationship";
const BOB: &str = "did:peer:2.bob-relationship";
const SESSION_ID: &str = "urn:uuid:0b6f9e2a-4c1d-4e7b-9a3f-5d2c8e1f7a01";
const EDGE_DIGEST: &str = "zQmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n";

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 22, 10, 0, 0).unwrap()
}

/// Alice's `witness/session` document, opening her session with the witness.
fn witness_session() -> Value {
    json!({
        "id": SESSION_ID,
        "type": "https://trusttasks.org/spec/witness/session/0.1",
        "threadId": SESSION_ID,
        "parentThreadId": "urn:uuid:3e1d7c5b-9a2f-4b8e-8c6d-1f0a2b3c4d01",
        "issuer": ALICE,
        "recipient": WITNESS,
        "issuedAt": "2026-09-22T09:59:00Z",
        "payload": { "parties": [ALICE, BOB] }
    })
}

fn vwc_for(session: &Value) -> Result<DTGCredential, DTGCredentialError> {
    DTGCredential::new_vwc_for_session(
        WITNESS.into(),
        ALICE.into(),
        t0(),
        None,
        session,
        EDGE_DIGEST.into(),
        Some(WitnessContext {
            event: None,
            session_id: Some(SESSION_ID.into()),
            method: Some("in-person-proximity".into()),
        }),
    )
}

/// The raw 34-byte multihash of a base58btc `z…` value.
fn multihash_bytes(digest: &str) -> Vec<u8> {
    multibase::decode(digest).unwrap().1
}

// ---------------------------------------------------------------------------------------
// The digest

#[test]
fn task_digest_reproduces_the_published_vetting_session_vector() {
    let session: Value = serde_json::from_str(VETTING_SESSION).unwrap();
    assert_eq!(
        task_digest_multibase_json(&session).unwrap(),
        VETTING_SESSION_TASK_DIGEST
    );
}

/// The four steps, done by hand: sha2-256 over JCS of the document minus its top-level
/// `proof`, a `0x12 0x20` multihash header, base58btc with a `z` prefix.
#[test]
fn task_digest_is_sha2_256_multihash_over_the_proofless_jcs_form() {
    let session: Value = serde_json::from_str(VETTING_SESSION).unwrap();
    let mut proofless = session.clone();
    proofless.as_object_mut().unwrap().remove("proof");
    let canonical = serde_json_canonicalizer::to_vec(&proofless).unwrap();

    let mut expected = vec![0x12, 0x20];
    expected.extend_from_slice(&Sha256::digest(&canonical));

    let digest = task_digest_multibase_json(&session).unwrap();
    assert!(digest.starts_with('z'), "issuers emit base58btc");
    assert_eq!(multihash_bytes(&digest), expected);
}

/// §4.9.3: a document has one task digest whether or not anyone signed it.
#[test]
fn task_digest_ignores_the_top_level_proof() {
    let signed: Value = serde_json::from_str(VETTING_SESSION).unwrap();
    let mut unsigned = signed.clone();
    unsigned.as_object_mut().unwrap().remove("proof");
    let mut resigned = signed.clone();
    resigned["proof"]["proofValue"] = json!("z4differentSignatureOverTheSameContent");

    let digest = task_digest_multibase_json(&signed).unwrap();
    assert_eq!(task_digest_multibase_json(&unsigned).unwrap(), digest);
    assert_eq!(task_digest_multibase_json(&resigned).unwrap(), digest);
}

/// §4.9.3: a `proof` inside `payload` is content and MUST NOT be removed.
#[test]
fn task_digest_keeps_a_proof_nested_in_the_payload() {
    let mut a = witness_session();
    a["payload"]["vp"] = json!({ "proof": { "proofValue": "zA" } });
    let mut b = a.clone();
    b["payload"]["vp"]["proof"]["proofValue"] = json!("zB");

    assert_ne!(
        task_digest_multibase_json(&a).unwrap(),
        task_digest_multibase_json(&b).unwrap()
    );
}

/// Same computation as every other digest-valued member, over a different input.
#[test]
fn task_digest_is_the_digest_encoding_of_dtg_core_credentials() {
    let session = witness_session();
    assert_eq!(
        task_digest_multibase_json(&session).unwrap(),
        digest_multibase_json(&session).unwrap()
    );
}

// ---------------------------------------------------------------------------------------
// Building a VWC for a witness session

#[test]
fn a_session_vwc_carries_both_halves_of_the_citation() {
    let session = witness_session();
    let vwc = vwc_for(&session).unwrap();

    assert_eq!(vwc.type_(), DTGCredentialType::Witness);
    assert_eq!(vwc.task_context(), Some(SESSION_ID));
    assert_eq!(
        vwc.task_digest_multibase(),
        Some(task_digest_multibase_json(&session).unwrap().as_str())
    );
    assert_eq!(vwc.subject_digest(), Some(EDGE_DIGEST));

    let wire = serde_json::to_value(&vwc).unwrap();
    assert_eq!(wire["taskContext"], json!(SESSION_ID));
    assert_eq!(
        wire["taskDigestMultibase"],
        json!(task_digest_multibase_json(&session).unwrap()),
        "`taskDigestMultibase` is a top-level member, beside `taskContext`"
    );
    assert!(
        wire["credentialSubject"]
            .get("taskDigestMultibase")
            .is_none()
    );
}

#[test]
fn a_session_vwc_round_trips_and_still_cites_its_session() {
    let session = witness_session();
    let vwc = vwc_for(&session).unwrap();

    let text = serde_json::to_string(&vwc).unwrap();
    let parsed: DTGCredential = serde_json::from_str(&text).unwrap();

    assert_eq!(parsed.type_(), DTGCredentialType::Witness);
    assert_eq!(parsed.task_context(), vwc.task_context());
    assert_eq!(parsed.task_digest_multibase(), vwc.task_digest_multibase());
    assert!(parsed.cites_task(&session).unwrap());

    // The member is modelled, not carried as an unknown extra: nothing is duplicated
    // and the digest over the model agrees with the digest over the wire form.
    assert!(
        !parsed
            .credential()
            .extra
            .contains_key("taskDigestMultibase")
    );
    assert_eq!(
        parsed.digest_multibase().unwrap(),
        digest_multibase_json(&serde_json::from_str(&text).unwrap()).unwrap()
    );
}

/// The witness may receive the session signed or unsigned; the VWC is the same.
#[test]
fn a_signed_and_an_unsigned_session_give_the_same_vwc_citation() {
    let unsigned = witness_session();
    let mut signed = unsigned.clone();
    signed["proof"] = json!({ "type": "DataIntegrityProof", "proofValue": "z3sig" });

    let a = vwc_for(&unsigned).unwrap();
    let b = vwc_for(&signed).unwrap();
    assert_eq!(a.task_digest_multibase(), b.task_digest_multibase());
    assert!(a.cites_task(&signed).unwrap());
    assert!(b.cites_task(&unsigned).unwrap());
}

#[test]
fn the_submit_document_is_not_the_session() {
    let mut submit = witness_session();
    submit["id"] = json!("urn:uuid:0b6f9e2a-4c1d-4e7b-9a3f-5d2c8e1f7a02");
    submit["type"] = json!("https://trusttasks.org/spec/witness/session/submit/0.1");

    assert!(matches!(
        vwc_for(&submit),
        Err(DTGCredentialError::NotAWitnessSession(_))
    ));
}

#[test]
fn the_witness_response_is_not_the_session() {
    let mut response = witness_session();
    response["type"] = json!("https://trusttasks.org/spec/witness/session/0.1#response");

    assert!(matches!(
        vwc_for(&response),
        Err(DTGCredentialError::NotAWitnessSession(_))
    ));
}

/// The enclosing relationship exchange is the wrong exchange to name (§4.9.1), and a
/// document on some other thread is not the one that opened this session.
#[test]
fn a_document_not_naming_its_own_thread_is_not_the_opening_document() {
    let mut other_thread = witness_session();
    other_thread["threadId"] = json!("urn:uuid:3e1d7c5b-9a2f-4b8e-8c6d-1f0a2b3c4d01");
    assert!(matches!(
        vwc_for(&other_thread),
        Err(DTGCredentialError::NotAWitnessSession(_))
    ));

    let mut no_thread = witness_session();
    no_thread.as_object_mut().unwrap().remove("threadId");
    assert!(matches!(
        vwc_for(&no_thread),
        Err(DTGCredentialError::NotAWitnessSession(_))
    ));
}

#[test]
fn a_session_without_an_id_cannot_be_cited() {
    let mut no_id = witness_session();
    no_id.as_object_mut().unwrap().remove("id");
    assert!(matches!(
        vwc_for(&no_id),
        Err(DTGCredentialError::MalformedTaskDocument(_))
    ));
    assert!(matches!(
        vwc_for(&json!("not a document")),
        Err(DTGCredentialError::MalformedTaskDocument(_))
    ));
}

#[test]
fn an_inverted_window_is_refused_before_the_session_is_read() {
    let refused = DTGCredential::new_vwc_for_session(
        WITNESS.into(),
        ALICE.into(),
        t0(),
        Some(t0() - chrono::Duration::hours(1)),
        &json!(null),
        EDGE_DIGEST.into(),
        None,
    );
    assert!(matches!(
        refused,
        Err(DTGCredentialError::InvalidValidityWindow { .. })
    ));
}

// ---------------------------------------------------------------------------------------
// Verifying a citation

/// A counterfeit reusing the session's `id` with different content fails on the digest.
/// This is the case the digest exists for.
#[test]
fn a_counterfeit_reusing_the_session_id_is_not_cited() {
    let session = witness_session();
    let vwc = vwc_for(&session).unwrap();

    let mut counterfeit = session.clone();
    counterfeit["payload"]["parties"] = json!([ALICE, "did:peer:2.mallory-relationship"]);
    assert_eq!(counterfeit["id"], session["id"]);

    assert!(!vwc.cites_task(&counterfeit).unwrap());
}

#[test]
fn a_different_document_is_not_cited_even_with_a_matching_digest() {
    let session = witness_session();
    let mut vwc = vwc_for(&session).unwrap();
    vwc.credential_mut().task_context = Some("urn:uuid:someone-elses-session".into());

    assert!(!vwc.cites_task(&session).unwrap());
}

/// §4.9.3: never fall back to `id` comparison alone.
#[test]
fn a_credential_with_no_task_digest_cites_nothing() {
    let session = witness_session();
    #[allow(deprecated)]
    let legacy = DTGCredential::new_vwc(
        WITNESS.into(),
        ALICE.into(),
        t0(),
        None,
        SESSION_ID.into(),
        Some(EDGE_DIGEST.into()),
        None,
    );

    assert_eq!(legacy.task_context(), Some(SESSION_ID));
    assert_eq!(legacy.task_digest_multibase(), None);
    assert!(!legacy.cites_task(&session).unwrap());
}

/// A VWC issued before the member existed still parses; it just cites nothing.
#[test]
fn a_vwc_without_task_digest_still_deserializes() {
    let parsed: DTGCredential = serde_json::from_value(json!({
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://firstperson.network/credentials/dtg/v1"],
        "type": ["VerifiableCredential", "DTGCredential", "WitnessCredential"],
        "issuer": WITNESS,
        "validFrom": "2026-09-22T10:00:00Z",
        "taskContext": SESSION_ID,
        "credentialSubject": { "id": ALICE, "digestMultibase": EDGE_DIGEST }
    }))
    .unwrap();
    assert_eq!(parsed.task_digest_multibase(), None);
}

#[test]
fn a_non_string_task_digest_is_refused_at_parse() {
    let parsed = serde_json::from_value::<DTGCredential>(json!({
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://firstperson.network/credentials/dtg/v1"],
        "type": ["VerifiableCredential", "DTGCredential", "WitnessCredential"],
        "issuer": WITNESS,
        "validFrom": "2026-09-22T10:00:00Z",
        "taskContext": SESSION_ID,
        "taskDigestMultibase": { "not": "a string" },
        "credentialSubject": { "id": ALICE, "digestMultibase": EDGE_DIGEST }
    }));
    assert!(parsed.is_err());
}

/// §4.9.3 and DTG Core Credentials §Digest Encoding: compare decoded bytes. A base64url
/// spelling of the same multihash is a different string and the same digest.
#[test]
fn citation_compares_decoded_bytes_not_strings() {
    let session = witness_session();
    let mut vwc = vwc_for(&session).unwrap();

    let base58 = vwc.task_digest_multibase().unwrap().to_string();
    let base64url = multibase::encode(multibase::Base::Base64Url, multihash_bytes(&base58));
    assert!(base64url.starts_with('u'));
    assert_ne!(base64url, base58);

    vwc.credential_mut().task_digest_multibase = Some(base64url);
    assert!(vwc.cites_task(&session).unwrap());
}

/// An algorithm this library does not implement makes the citation unverified — an
/// error, not `Ok(false)` and never a recompute under sha2-256.
#[test]
fn an_unimplemented_hash_leaves_the_citation_unverified() {
    let session = witness_session();
    let mut vwc = vwc_for(&session).unwrap();

    let mut canonical_input = session.clone();
    canonical_input.as_object_mut().unwrap().remove("proof");
    let mut sha512 = vec![0x13, 0x40];
    sha512.extend_from_slice(&Sha512::digest(
        serde_json_canonicalizer::to_vec(&canonical_input).unwrap(),
    ));
    vwc.credential_mut().task_digest_multibase =
        Some(multibase::encode(multibase::Base::Base58Btc, sha512));

    assert!(matches!(
        vwc.cites_task(&session),
        Err(DTGCredentialError::UnsupportedDigestAlgorithm(0x13))
    ));
}

// ---------------------------------------------------------------------------------------
// Another specification's credential

/// The published Vetting Statement parses, models its `taskDigestMultibase`, and cites the
/// published session document — a second implementation's credential verified here.
#[test]
fn the_published_vetting_statement_cites_its_session() {
    let session: Value = serde_json::from_str(VETTING_SESSION).unwrap();
    let statement: DTGCredential = serde_json::from_str(VETTING_STATEMENT).unwrap();

    assert_eq!(statement.type_(), DTGCredentialType::Endorsement);
    assert_eq!(
        statement.task_digest_multibase(),
        Some(VETTING_SESSION_TASK_DIGEST)
    );
    assert!(statement.cites_task(&session).unwrap());
}

/// `with_task_citation` sets both halves from one document, for any credential type.
#[test]
fn with_task_citation_reproduces_the_published_statement_citation() {
    let session: Value = serde_json::from_str(VETTING_SESSION).unwrap();
    let statement = DTGCredential::new_vec(
        "did:webvh:QmCarolScid1:kernel-vtc.example:carol".into(),
        "did:webvh:QmAliceScid1:alice.example".into(),
        t0(),
        None,
        json!({ "type": "https://firstperson.network/endorsements/identity-vetting/0.1" }),
    )
    .with_task_citation(&session)
    .unwrap();

    assert_eq!(
        statement.task_context(),
        Some("urn:uuid:9a7e4c21-5b3d-4e8f-a1c2-3d4e5f6a7b01")
    );
    assert_eq!(
        statement.task_digest_multibase(),
        Some(VETTING_SESSION_TASK_DIGEST)
    );
}
