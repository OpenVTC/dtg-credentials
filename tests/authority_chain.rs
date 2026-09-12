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
use dtg_credentials::{DTGCredential, DTGCredentialError, DTGCredentialType};

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
        t(24 * 30),
    )
    .expect("root grant")
    .with_id("urn:uuid:root-0001")
}

/// Bob equips his agent with read-only for four hours. Naming the agent as `subject` is
/// the whole of the binding: only the agent can present what only the agent is granted.
fn agent_grant(parent: &DTGCredential) -> DTGCredential {
    parent
        .attenuate(AGENT.into(), vec!["read".into()], t(0), t(4))
        .expect("attenuation")
        .with_id("urn:uuid:agent-0001")
}

/// A window that closes before it opens describes a VAC that is never valid. It is refused
/// where it is built, rather than left for each verifier to notice.
#[test]
fn an_inverted_window_is_refused_at_issue() {
    let inverted = DTGCredential::new_vac(
        ROOM.into(),
        BOB.into(),
        ROOM.into(),
        vec!["read".into()],
        t(24),
        t(0),
    )
    .unwrap_err();
    assert!(
        matches!(inverted, DTGCredentialError::InvalidValidityWindow { .. }),
        "got {inverted:?}"
    );

    // An empty window is no better: `validUntil` must be strictly after `validFrom`.
    let empty = DTGCredential::new_vac(
        ROOM.into(),
        BOB.into(),
        ROOM.into(),
        vec!["read".into()],
        t(0),
        t(0),
    )
    .unwrap_err();
    assert!(
        matches!(empty, DTGCredentialError::InvalidValidityWindow { .. }),
        "got {empty:?}"
    );

    // Nor may attenuation produce one, even inside the parent's window.
    let root = root_grant();
    let err = root
        .attenuate(AGENT.into(), vec!["read".into()], t(4), t(2))
        .unwrap_err();
    assert!(
        matches!(err, DTGCredentialError::InvalidValidityWindow { .. }),
        "got {err:?}"
    );

    let err = DTGCredential::attenuate_from_json(
        &serde_json::to_value(&root).unwrap(),
        AGENT.into(),
        vec!["read".into()],
        t(4),
        t(4),
    )
    .unwrap_err();
    assert!(
        matches!(err, DTGCredentialError::InvalidValidityWindow { .. }),
        "got {err:?}"
    );
}

/// Backdating is legitimate — a re-issued credential keeps the date the original took
/// effect — so only the ordering of the two ends is checked, never either against the clock.
#[test]
fn a_backdated_window_is_accepted_at_issue() {
    DTGCredential::new_vac(
        ROOM.into(),
        BOB.into(),
        ROOM.into(),
        vec!["read".into()],
        t(-24 * 365 * 5),
        t(1),
    )
    .expect("a window that opened years ago is well formed");
}

/// The wire form carries whole seconds, so a window narrower than one serializes as an
/// empty window and is refused as one.
#[test]
fn a_window_narrower_than_a_second_is_refused() {
    let err = DTGCredential::new_vac(
        ROOM.into(),
        BOB.into(),
        ROOM.into(),
        vec!["read".into()],
        t(0) + Duration::milliseconds(100),
        t(0) + Duration::milliseconds(900),
    )
    .unwrap_err();
    assert!(
        matches!(err, DTGCredentialError::InvalidValidityWindow { .. }),
        "got {err:?}"
    );
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
        t(24),
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
        t(24),
    )
    .unwrap()
    .with_id("urn:uuid:read-only-root");

    // Refused at issue time...
    let err = root
        .attenuate(AGENT.into(), vec!["write".into()], t(0), t(4))
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
        t(4),
    )
    .unwrap()
    .with_id("urn:uuid:widened");
    // The link is intact — `parent` is the root's digest — so the chain resolves and the
    // widening is what the verifier has to catch. Pointing it somewhere else would fail as
    // a broken link and prove nothing about narrowing.
    let mut widened = widened;
    if let Some(g) = widened.credential_mut().authority_mut() {
        g.parent = Some(root.digest_multibase().unwrap());
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
        .attenuate(AGENT.into(), vec!["read".into()], t(0), t(24 * 365))
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
        t(4),
    )
    .unwrap()
    .with_id("urn:uuid:grafted");
    // Mallory cites Bob's root correctly: the digest matches, so the chain resolves. What
    // must stop her is that she is not the party the root was granted to.
    let mut grafted = grafted;
    if let Some(g) = grafted.credential_mut().authority_mut() {
        g.parent = Some(root.digest_multibase().unwrap());
    }

    let err = verify_chain(&[grafted, root], ROOM, ROOM, "read", MALLORY, t(1)).unwrap_err();
    assert!(
        matches!(err, AuthorityError::IssuerNotParentSubject { .. }),
        "got {err:?}"
    );
}

/// A VAC is not a bearer credential: the leaf must grant to whoever presents it. This is
/// what makes a captured presentation useless to whoever captured it.
#[test]
fn a_chain_presented_by_someone_other_than_its_subject_is_refused() {
    let root = root_grant();
    let agent = agent_grant(&root);

    let err = verify_chain(&[agent, root], ROOM, ROOM, "read", MALLORY, t(1)).unwrap_err();
    assert!(
        matches!(
            err,
            AuthorityError::NotThePresenter { ref subject, ref presenter }
                if subject == AGENT && presenter == MALLORY
        ),
        "got {err:?}"
    );
}

/// The same rule applies to a root presented directly — the case with no attenuation at
/// all, which is where a bearer reading would be easiest to reach for.
#[test]
fn a_root_presented_by_someone_other_than_its_subject_is_refused() {
    let err = verify_chain(&[root_grant()], ROOM, ROOM, "write", MALLORY, t(1)).unwrap_err();
    assert!(
        matches!(err, AuthorityError::NotThePresenter { ref subject, .. } if subject == BOB),
        "got {err:?}"
    );
}

/// The principal may not present what they gave away. Bob holds `read`/`write`/`curate` at
/// the room, but the *leaf* of this chain grants to his agent — so the chain says the agent
/// is acting, and Bob presenting it is as wrong as Mallory doing so. Bob presents his own
/// root instead; that is a different chain.
#[test]
fn the_attenuating_holder_cannot_present_their_agents_chain() {
    let root = root_grant();
    let agent = agent_grant(&root);

    let err = verify_chain(&[agent, root], ROOM, ROOM, "read", BOB, t(1)).unwrap_err();
    assert!(
        matches!(err, AuthorityError::NotThePresenter { ref presenter, .. } if presenter == BOB),
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
    let err = DTGCredential::new_vac(ROOM.into(), BOB.into(), ROOM.into(), vec![], t(0), t(1))
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

    // And the attenuated form keeps its chain link.
    let agent = agent_grant(&root);
    let json = serde_json::to_string(&agent).unwrap();
    let back: DTGCredential = serde_json::from_str(&json).unwrap();
    let grant = back.credential().authority().unwrap();
    assert_eq!(
        grant.parent.as_deref(),
        Some(root.digest_multibase().unwrap().as_str()),
        "`parent` is the digest of the credential attenuated from, not its id"
    );
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

// -------------------------------------------------------------------------------------
// `parent` is a digest (Working Draft 02)
// -------------------------------------------------------------------------------------

/// A chain link names its parent by digest, not by identifier. A digest names nothing that
/// can be fetched, so verification never depends on the network and a verifier cannot be
/// induced to make a request against an address the holder chooses.
#[test]
fn a_link_names_its_parent_by_digest() {
    let root = root_grant();
    let agent = agent_grant(&root);

    let parent = agent
        .credential()
        .authority()
        .unwrap()
        .parent
        .as_deref()
        .expect("an attenuated VAC carries a parent");

    assert!(parent.starts_with('z'), "multibase base58btc: {parent}");
    assert!(dtg_credentials::digests_match(parent, &root.digest_multibase().unwrap()).unwrap());
}

/// A parent no longer needs a top-level `id` to be attenuated — which is precisely why the
/// specification made `parent` a digest.
#[test]
fn a_parent_without_an_id_can_still_be_attenuated() {
    let root = DTGCredential::new_vac(
        ROOM.into(),
        BOB.into(),
        ROOM.into(),
        vec!["read".into(), "write".into()],
        t(0),
        t(24 * 30),
    )
    .unwrap(); // deliberately no `with_id`

    assert!(root.id().is_none());

    let agent = root
        .attenuate(AGENT.into(), vec!["read".into()], t(0), t(4))
        .expect("attenuation does not need the parent to have an id");

    let v = verify_chain(&[agent, root], ROOM, ROOM, "read", AGENT, t(1)).expect("verifies");
    assert_eq!(v.subject, AGENT);
}

/// The digest binds to the parent's *claims*, so re-issuing a parent with different claims
/// orphans the credentials attenuated from the old one — they must be re-derived. For a
/// chain of narrowing authority that is the intended behaviour.
#[test]
fn a_reissued_parent_does_not_carry_its_children() {
    let root = root_grant();
    let agent = agent_grant(&root);

    // Same id, same parties, narrower actions — a different credential.
    let reissued = DTGCredential::new_vac(
        ROOM.into(),
        BOB.into(),
        ROOM.into(),
        vec!["read".into()],
        t(0),
        t(24 * 30),
    )
    .unwrap()
    .with_id("urn:uuid:root-0001");

    let err = verify_chain(&[agent, reissued], ROOM, ROOM, "read", AGENT, t(1)).unwrap_err();
    assert!(
        matches!(err, AuthorityError::BrokenLink { index: 0, .. }),
        "got {err:?}"
    );
}

/// Re-*proofing* a parent leaves its children undisturbed, because the digest excludes
/// `proof`. This is the property that lets a chain survive a key rotation.
#[test]
fn a_reproofed_parent_keeps_its_children() {
    let root = root_grant();
    let agent = agent_grant(&root);

    let mut reproofed = root.clone();
    reproofed.credential_mut().proof = None;

    assert!(
        dtg_credentials::digests_match(
            &root.digest_multibase().unwrap(),
            &reproofed.digest_multibase().unwrap()
        )
        .unwrap(),
        "the digest covers the claims, not a signature over them"
    );

    verify_chain(&[agent, reproofed], ROOM, ROOM, "read", AGENT, t(1)).expect("still verifies");
}

/// A digest that cannot be *read* is not a digest that disagrees. A Working Draft 01
/// `sha256:<hex>` parent reaching this verifier is reported as malformed, not as a
/// widening chain.
#[test]
fn a_superseded_parent_digest_is_reported_as_malformed() {
    let root = root_grant();
    let mut agent = agent_grant(&root);
    if let Some(g) = agent.credential_mut().authority_mut() {
        g.parent =
            Some("sha256:49c9d5135ab4b5659a343bc79d351e37d64f05add58408cae6eef022828495c2".into());
    }

    let err = verify_chain(&[agent, root], ROOM, ROOM, "read", AGENT, t(1)).unwrap_err();
    assert!(
        matches!(err, AuthorityError::Digest { index: 0, .. }),
        "got {err:?}"
    );
}

/// Attenuating a VAC that arrived from a counterparty must digest the bytes received, not
/// a re-serialisation of the parse. A normalized timestamp is enough to make the two differ.
#[test]
fn attenuating_from_json_digests_the_wire_form() {
    let root = root_grant();
    let mut received = serde_json::to_value(root.credential()).unwrap();
    received["validFrom"] = serde_json::Value::String("2026-01-06T10:00:00.000+00:00".to_string());

    let agent = DTGCredential::attenuate_from_json(
        &received,
        AGENT.into(),
        vec!["read".into()],
        t(0),
        t(4),
    )
    .expect("attenuation");

    assert_eq!(
        agent.credential().authority().unwrap().parent.as_deref(),
        Some(
            dtg_credentials::digest_multibase_json(&received)
                .unwrap()
                .as_str()
        ),
        "the parent digest must cover the VAC as it arrived"
    );
    assert_eq!(agent.issuer(), BOB, "the holder is read off the parent");
}

/// The wire-form path enforces the same narrowing rules as the in-process one.
#[test]
fn attenuating_from_json_still_refuses_to_widen() {
    let received = serde_json::to_value(root_grant().credential()).unwrap();

    let err = DTGCredential::attenuate_from_json(
        &received,
        AGENT.into(),
        vec!["delete".into()],
        t(0),
        t(4),
    )
    .unwrap_err();

    assert!(
        format!("{err}").contains("not conferred by the parent"),
        "{err}"
    );
}

/// `validUntil` is REQUIRED on a VAC. Nothing about the subject's current standing is
/// consulted here, so authority that never expires is authority nobody can withdraw by
/// waiting — and a verifier that accepted one would be honouring exactly that.
#[test]
fn a_vac_without_an_expiry_is_refused() {
    let json = serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://firstperson.network/credentials/dtg/v1"
        ],
        "type": ["VerifiableCredential", "DTGCredential", "AuthorityCredential"],
        "issuer": ROOM,
        "validFrom": "2026-01-06T10:00:00Z",
        "credentialSubject": {
            "id": BOB,
            "authority": { "scope": ROOM, "actions": ["read"] }
        }
    });

    let vac: DTGCredential = serde_json::from_value(json).expect("parses");
    let err = verify_chain(&[vac], ROOM, ROOM, "read", BOB, t(1)).unwrap_err();
    assert!(
        matches!(err, AuthorityError::NoExpiry { index: 0 }),
        "got {err:?}"
    );
}
