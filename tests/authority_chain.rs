//! Chain verification for Verifiable Authority Credentials.
//!
//! These tests are the reason the credential is safe to use. Issuing a VAC is a struct and
//! a signature; what stops a holder acquiring authority they were not given is the verifier
//! refusing a chain that widens. So the cases below are mostly *attacks* — each one is a
//! way of getting more than was granted, and each must be refused with a specific error
//! rather than a generic failure, because a verifier's logs are where an escalation attempt
//! becomes visible.

use chrono::{Duration, TimeZone, Utc};
use dtg_credentials::authority::{AuthorityError, MAX_CHAIN_DEPTH, verify_chain};
use dtg_credentials::{DTGCredential, DTGCredentialType};

const ROOM: &str = "did:webvh:zroom:example.com:rooms:7f3a";
const BOB: &str = "did:key:zBob";
const AGENT: &str = "did:key:zBobAgent";
const MALLORY: &str = "did:key:zMallory";

fn t(h: i64) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 6, 10, 0, 0).unwrap() + Duration::hours(h)
}

/// The room grants Bob read+write+curate for a month.
fn root_grant() -> DTGCredential {
    DTGCredential::new_vac(
        ROOM.into(),
        BOB.into(),
        ROOM.into(),
        vec!["read".into(), "write".into(), "curate".into()],
        t(0),
        Some(t(24 * 30)),
    )
    .expect("root grant")
    .with_id("urn:uuid:root-0001")
}

/// Bob equips his agent with read-only for four hours, bound to the agent.
fn agent_grant(parent: &DTGCredential) -> DTGCredential {
    parent
        .attenuate(
            AGENT.into(),
            vec!["read".into()],
            t(0),
            Some(t(4)),
            Some(AGENT.into()),
        )
        .expect("attenuation")
        .with_id("urn:uuid:agent-0001")
}

#[test]
fn a_root_grant_verifies_for_what_it_confers() {
    let root = root_grant();
    let v = verify_chain(&[root], ROOM, ROOM, "write", BOB, t(1)).expect("root should verify");
    assert_eq!(v.subject, BOB);
    assert_eq!(v.governing_party, ROOM);
    assert!(v.actions.contains(&"curate".to_string()));
}

/// The case the whole credential exists for: an agent acting on strictly less authority
/// than the human it works for.
#[test]
fn an_attenuated_agent_credential_verifies_for_its_narrower_grant() {
    let root = root_grant();
    let agent = agent_grant(&root);

    let v = verify_chain(
        &[agent.clone(), root.clone()],
        ROOM,
        ROOM,
        "read",
        AGENT,
        t(1),
    )
    .expect("agent chain should verify for read");
    assert_eq!(v.subject, AGENT);
    assert_eq!(v.actions, vec!["read".to_string()]);

    // ...and not for what it was not given, even though its parent holds it.
    let err = verify_chain(&[agent, root], ROOM, ROOM, "write", AGENT, t(1)).unwrap_err();
    assert!(
        matches!(err, AuthorityError::ActionNotGranted { ref action } if action == "write"),
        "got {err:?}"
    );
}

/// The headline attack. A valid signature on a self-minted credential proves nothing about
/// authority: what makes it worthless is that its chain never reaches the governing party.
#[test]
fn a_self_issued_grant_is_refused_however_well_formed() {
    let forged = DTGCredential::new_vac(
        MALLORY.into(),
        MALLORY.into(),
        ROOM.into(),
        vec!["read".into(), "write".into(), "curate".into()],
        t(0),
        Some(t(24)),
    )
    .expect("mallory can build one")
    .with_id("urn:uuid:forged");

    let err = verify_chain(&[forged], ROOM, ROOM, "write", MALLORY, t(1)).unwrap_err();
    assert!(
        matches!(err, AuthorityError::RootNotGoverning { .. }),
        "a chain not reaching the governing party must be refused: got {err:?}"
    );
}

#[test]
fn attenuation_cannot_add_an_action_the_parent_lacks() {
    let root = DTGCredential::new_vac(
        ROOM.into(),
        BOB.into(),
        ROOM.into(),
        vec!["read".into()],
        t(0),
        Some(t(24)),
    )
    .unwrap()
    .with_id("urn:uuid:read-only-root");

    // Refused at issue time...
    let err = root
        .attenuate(AGENT.into(), vec!["write".into()], t(0), Some(t(4)), None)
        .unwrap_err();
    assert!(
        format!("{err}").contains("not conferred by the parent"),
        "{err}"
    );

    // ...and refused at verification time too, for an implementation that built the JSON by
    // hand. The verifier's check is the authoritative one.
    let widened = DTGCredential::new_vac(
        BOB.into(),
        AGENT.into(),
        ROOM.into(),
        vec!["write".into()],
        t(0),
        Some(t(4)),
    )
    .unwrap()
    .with_id("urn:uuid:widened");
    let mut widened = widened;
    if let Some(g) = widened.credential_mut().authority_mut() {
        g.parent = Some("urn:uuid:read-only-root".into());
    }

    let err = verify_chain(&[widened, root], ROOM, ROOM, "write", AGENT, t(1)).unwrap_err();
    assert!(
        matches!(err, AuthorityError::WidensActions { ref action, .. } if action == "write"),
        "got {err:?}"
    );
}

#[test]
fn attenuation_cannot_outlive_its_parent() {
    let root = root_grant();
    let err = root
        .attenuate(
            AGENT.into(),
            vec!["read".into()],
            t(0),
            Some(t(24 * 365)),
            None,
        )
        .unwrap_err();
    assert!(format!("{err}").contains("beyond the parent's"), "{err}");
}

/// Only the party a grant was made to may attenuate it — otherwise a holder could graft
/// someone else's grant onto their own chain.
#[test]
fn a_link_issued_by_someone_other_than_the_parents_subject_is_refused() {
    let root = root_grant(); // granted to BOB
    let grafted = DTGCredential::new_vac(
        MALLORY.into(), // not BOB
        MALLORY.into(),
        ROOM.into(),
        vec!["read".into()],
        t(0),
        Some(t(4)),
    )
    .unwrap()
    .with_id("urn:uuid:grafted");
    let mut grafted = grafted;
    if let Some(g) = grafted.credential_mut().authority_mut() {
        g.parent = Some("urn:uuid:root-0001".into());
    }

    let err = verify_chain(&[grafted, root], ROOM, ROOM, "read", MALLORY, t(1)).unwrap_err();
    assert!(
        matches!(err, AuthorityError::IssuerNotParentSubject { .. }),
        "got {err:?}"
    );
}

/// Audience binding is what makes a leaked agent credential useless to whoever picks it up.
#[test]
fn an_audience_bound_credential_refuses_another_presenter() {
    let root = root_grant();
    let agent = agent_grant(&root);

    let err = verify_chain(&[agent, root], ROOM, ROOM, "read", MALLORY, t(1)).unwrap_err();
    assert!(
        matches!(err, AuthorityError::WrongAudience { ref presenter, .. } if presenter == MALLORY),
        "got {err:?}"
    );
}

#[test]
fn an_expired_link_is_refused_even_when_its_parent_is_live() {
    let root = root_grant(); // valid 30 days
    let agent = agent_grant(&root); // valid 4 hours

    // Five hours in: the agent's credential has expired, the root has not.
    let err = verify_chain(&[agent, root.clone()], ROOM, ROOM, "read", AGENT, t(5)).unwrap_err();
    assert!(
        matches!(err, AuthorityError::NotValidNow { index: 0, .. }),
        "got {err:?}"
    );

    // The root alone is still good, presented by Bob.
    verify_chain(&[root], ROOM, ROOM, "read", BOB, t(5)).expect("root still live");
}

#[test]
fn authority_in_one_scope_does_not_reach_another() {
    let root = root_grant();
    let other_room = "did:webvh:zroom:example.com:rooms:beef";
    let err = verify_chain(&[root], ROOM, other_room, "read", BOB, t(1)).unwrap_err();
    assert!(
        matches!(err, AuthorityError::ScopeMismatch { .. }),
        "got {err:?}"
    );
}

#[test]
fn a_chain_deeper_than_the_ceiling_is_refused() {
    let root = root_grant();
    let chain: Vec<DTGCredential> = std::iter::repeat_n(root, MAX_CHAIN_DEPTH + 1).collect();
    let err = verify_chain(&chain, ROOM, ROOM, "read", BOB, t(1)).unwrap_err();
    assert!(
        matches!(err, AuthorityError::TooDeep { found } if found == MAX_CHAIN_DEPTH + 1),
        "got {err:?}"
    );
}

#[test]
fn an_empty_chain_confers_nothing() {
    let err = verify_chain(&[], ROOM, ROOM, "read", BOB, t(1)).unwrap_err();
    assert!(matches!(err, AuthorityError::EmptyChain));
}

/// Emptiness is never a wildcard — the failure mode this rule exists to prevent.
#[test]
fn a_vac_conferring_no_actions_is_refused_at_construction() {
    let err = DTGCredential::new_vac(ROOM.into(), BOB.into(), ROOM.into(), vec![], t(0), None)
        .unwrap_err();
    assert!(format!("{err}").contains("confers nothing"), "{err}");
}

#[test]
fn a_vac_round_trips_through_json_with_its_grant_intact() {
    let root = root_grant();
    let json = serde_json::to_string(&root).expect("serialize");
    let back: DTGCredential = serde_json::from_str(&json).expect("deserialize");

    assert!(matches!(back.type_(), DTGCredentialType::Authority));
    let grant = back
        .credential()
        .authority()
        .expect("grant survives the round trip");
    assert_eq!(grant.scope, ROOM);
    assert_eq!(grant.actions.len(), 3);
    assert!(grant.parent.is_none(), "a root carries no parent");

    // And the attenuated form keeps its chain link and its audience.
    let agent = agent_grant(&root);
    let json = serde_json::to_string(&agent).unwrap();
    let back: DTGCredential = serde_json::from_str(&json).unwrap();
    let grant = back.credential().authority().unwrap();
    assert_eq!(grant.parent.as_deref(), Some("urn:uuid:root-0001"));
    assert_eq!(grant.audience.as_deref(), Some(AGENT));
    assert_eq!(grant.actions, vec!["read".to_string()]);
}

/// A VAC with an empty `actions` array must not be constructable by deserialization either
/// — otherwise the constructor's guard is trivially bypassed.
#[test]
fn an_empty_actions_list_is_refused_on_deserialization() {
    let json = serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://firstperson.network/credentials/dtg/v1"
        ],
        "type": ["VerifiableCredential", "DTGCredential", "AuthorityCredential"],
        "issuer": ROOM,
        "validFrom": "2026-01-06T10:00:00Z",
        "credentialSubject": { "id": BOB, "authority": { "scope": ROOM, "actions": [] } }
    })
    .to_string();

    let err = serde_json::from_str::<DTGCredential>(&json).unwrap_err();
    assert!(
        err.to_string().contains("confers nothing"),
        "empty actions must be refused at the deserialization boundary too: {err}"
    );
}
