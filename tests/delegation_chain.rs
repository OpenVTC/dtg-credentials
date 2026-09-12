//! Delegation edges and chains for Verifiable Delegation Credentials.
//!
//! A VDC establishes *representation*, not permission, and the two failure modes that
//! matter are different from a VAC's. A chain that widens lets a delegate speak for the
//! principal about more than they were appointed for; an appointment accepted by nobody
//! lets a delegator manufacture a delegate who never agreed to answer for anything. So the
//! cases below are mostly attacks, and each must be refused with a specific error.

use chrono::{DateTime, Duration, TimeZone, Utc};
use dtg_credentials::delegation::{DelegationError, MAX_CHAIN_DEPTH, verify_chain};
use dtg_credentials::{DTGCredential, DTGCredentialError};
use serde_json::Value;

const ALICE: &str = "did:key:zAlice";
const AGENT: &str = "did:key:zAliceAgent";
const SUBAGENT: &str = "did:key:zAliceSubAgent";
const MALLORY: &str = "did:key:zMallory";

fn t(h: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 6, 10, 0, 0).unwrap() + Duration::hours(h)
}

fn wire(c: &DTGCredential) -> Value {
    serde_json::to_value(c.credential()).unwrap()
}

/// Alice appoints her agent to schedule in her name for 90 days, with one further hop
/// permitted.
fn root_delegation() -> DTGCredential {
    DTGCredential::new_vdc(
        ALICE.into(),
        AGENT.into(),
        t(0),
        t(24 * 90),
        vec!["schedule:read".into(), "schedule:propose".into()],
        Some(1),
    )
    .expect("root delegation")
    .with_id("urn:uuid:vdc-root")
}

#[test]
fn a_root_delegation_verifies_for_what_it_appoints() {
    let root = root_delegation();
    let v = verify_chain(&[root], ALICE, "schedule:propose", AGENT, t(1)).expect("should verify");

    assert_eq!(v.delegate, AGENT);
    assert_eq!(v.principal, ALICE);
    assert!(v.scope.contains(&"schedule:read".to_string()));
}

#[test]
fn an_act_outside_the_appointment_is_refused() {
    let root = root_delegation();
    let err = verify_chain(&[root], ALICE, "schedule:cancel", AGENT, t(1)).unwrap_err();

    assert!(
        matches!(err, DelegationError::ActNotAppointed { ref act } if act == "schedule:cancel"),
        "got {err:?}"
    );
}

/// The chain must resolve to the principal the verifier intends to deal with. A chain that
/// reaches somebody else establishes no representation of Alice, however well formed.
#[test]
fn a_chain_rooted_elsewhere_establishes_nothing() {
    let root = root_delegation();
    let err = verify_chain(&[root], MALLORY, "schedule:read", AGENT, t(1)).unwrap_err();

    assert!(
        matches!(err, DelegationError::RootNotPrincipal { .. }),
        "got {err:?}"
    );
}

// -------------------------------------------------------------------------------------
// The edge: a grant alone appoints nobody
// -------------------------------------------------------------------------------------

/// The delegate's acceptance is what makes the appointment mutually acknowledged. A
/// delegator can always name someone as its delegate; what it cannot do is produce the
/// countersignature.
#[test]
fn an_acceptance_completes_the_edge() {
    let grant = root_delegation();
    let acceptance = DTGCredential::new_delegate_vdc_for(&wire(&grant), AGENT, t(0), t(24 * 90))
        .expect("accepts");

    // Mirrored parties: the delegate issues, the delegator is the subject.
    assert_eq!(acceptance.issuer(), AGENT);
    assert_eq!(acceptance.subject(), ALICE);

    assert!(acceptance.accepts(&grant).unwrap());
}

/// An acceptance carries no scope of its own — what the delegate consented to is the scope
/// of the grant it names. Restating it would need an equality check across two credentials
/// that selective disclosure of either would defeat.
#[test]
fn an_acceptance_restates_no_scope() {
    let grant = root_delegation();
    let acceptance = DTGCredential::new_delegate_vdc_for(&wire(&grant), AGENT, t(0), t(24 * 90))
        .expect("accepts");

    let d = acceptance.credential().delegation().unwrap();
    assert!(d.scope.is_none());
    assert!(d.max_depth.is_none());
    assert!(d.accepts.is_some());
}

/// The acceptance binds to the grant's claims. A re-issued grant carries a different
/// digest, so consent does not carry over to an appointment the delegate never saw.
#[test]
fn a_reissued_grant_is_no_longer_accepted_by_the_old_acceptance() {
    let grant = root_delegation();
    let acceptance = DTGCredential::new_delegate_vdc_for(&wire(&grant), AGENT, t(0), t(24 * 90))
        .expect("accepts");

    // Same parties, wider appointment.
    let reissued = DTGCredential::new_vdc(
        ALICE.into(),
        AGENT.into(),
        t(0),
        t(24 * 90),
        vec![
            "schedule:read".into(),
            "schedule:propose".into(),
            "schedule:cancel".into(),
        ],
        Some(1),
    )
    .unwrap()
    .with_id("urn:uuid:vdc-root");

    assert!(acceptance.accepts(&grant).unwrap());
    assert!(
        !acceptance.accepts(&reissued).unwrap(),
        "consent to one appointment is not consent to a wider one issued under the same id"
    );
}

/// Accepting an acceptance forms no edge.
#[test]
fn an_acceptance_cannot_itself_be_accepted() {
    let grant = root_delegation();
    let acceptance = DTGCredential::new_delegate_vdc_for(&wire(&grant), AGENT, t(0), t(24 * 90))
        .expect("accepts");

    let err = DTGCredential::new_delegate_vdc_for(&wire(&acceptance), ALICE, t(0), t(24 * 90))
        .unwrap_err();
    assert!(
        matches!(err, DTGCredentialError::NotADelegationGrant(_)),
        "got {err:?}"
    );
}

/// A delegate accepts a grant for itself. A grant appointing somebody else is refused before
/// anything is built.
#[test]
fn a_grant_appointing_someone_else_is_refused() {
    let grant = root_delegation(); // appoints AGENT

    let err =
        DTGCredential::new_delegate_vdc_for(&wire(&grant), MALLORY, t(0), t(24 * 90)).unwrap_err();
    assert!(
        matches!(
            err,
            DTGCredentialError::NotTheGrantSubject { ref expected, ref found }
                if expected == MALLORY && found == AGENT
        ),
        "got {err:?}"
    );
}

/// An acceptance that outlives its grant records consent to an appointment that has already
/// ended.
#[test]
fn an_acceptance_may_not_outlive_its_grant() {
    let grant = root_delegation(); // valid until t(24 * 90)

    let err =
        DTGCredential::new_delegate_vdc_for(&wire(&grant), AGENT, t(0), t(24 * 91)).unwrap_err();
    assert!(
        matches!(err, DTGCredentialError::OutlivesGrant { .. }),
        "got {err:?}"
    );

    DTGCredential::new_delegate_vdc_for(&wire(&grant), AGENT, t(0), t(24 * 30))
        .expect("ending before the grant is within it");
}

/// Accepting is binding, not verification: an unsigned grant accepts perfectly well, and
/// fails only when its proof is checked.
#[cfg(feature = "affinidi-signing")]
#[test]
fn an_unsigned_grant_does_not_verify() {
    let grant = wire(&root_delegation());

    DTGCredential::new_delegate_vdc_for(&grant, AGENT, t(0), t(24 * 90)).expect("binds");

    let err = dtg_credentials::verify_grant_with_public_key(&grant, &[0u8; 32], t(1)).unwrap_err();
    assert!(matches!(err, DTGCredentialError::NotSigned), "got {err:?}");
}

/// A pair naming different parties is not an edge, however well the digest matches.
#[test]
fn an_acceptance_from_the_wrong_party_binds_nothing() {
    let grant = root_delegation();
    let mut acceptance =
        DTGCredential::new_delegate_vdc_for(&wire(&grant), AGENT, t(0), t(24 * 90))
            .expect("accepts");
    acceptance.credential_mut().issuer = MALLORY.into();

    assert!(!acceptance.accepts(&grant).unwrap());
}

/// An acceptance is not a grant, and a chain built from them appoints nobody to anything.
#[test]
fn an_acceptance_in_a_chain_is_refused() {
    let grant = root_delegation();
    let acceptance = DTGCredential::new_delegate_vdc_for(&wire(&grant), AGENT, t(0), t(24 * 90))
        .expect("accepts");

    let err = verify_chain(&[acceptance], ALICE, "schedule:read", AGENT, t(1)).unwrap_err();
    assert!(
        matches!(err, DelegationError::AcceptanceInChain { index: 0 }),
        "got {err:?}"
    );
}

/// A VDC is not a bearer token. Whoever captures a presentation must not be able to replay
/// it — and replaying a delegation is worse than replaying authority, because every act it
/// carries is attributed to the principal.
#[test]
fn a_captured_vdc_is_not_replayable_by_its_captor() {
    let root = root_delegation(); // appoints AGENT

    let err = verify_chain(&[root], ALICE, "schedule:read", MALLORY, t(1)).unwrap_err();
    assert!(
        matches!(
            err,
            DelegationError::NotTheDelegate { ref delegate, ref presenter }
                if delegate == AGENT && presenter == MALLORY
        ),
        "got {err:?}"
    );
}

/// The principal is not the delegate either. Alice presenting her own delegation is not
/// acting in her own name via it, and the chain establishes nothing about her.
#[test]
fn the_principal_is_not_the_delegate() {
    let root = root_delegation();

    let err = verify_chain(&[root], ALICE, "schedule:read", ALICE, t(1)).unwrap_err();
    assert!(
        matches!(err, DelegationError::NotTheDelegate { .. }),
        "got {err:?}"
    );
}

/// Only the *leaf's* delegate demonstrates anything. The agent that re-delegated is not
/// present and is asked for nothing — requiring otherwise would defeat re-delegation.
#[test]
fn an_intermediate_delegate_cannot_present_a_chain_below_it() {
    let root = root_delegation();
    let sub = root
        .redelegate(SUBAGENT.into(), vec!["schedule:read".into()], t(0), t(24))
        .expect("redelegation");

    // The sub-agent presents it: accepted.
    verify_chain(
        &[sub.clone(), root.clone()],
        ALICE,
        "schedule:read",
        SUBAGENT,
        t(1),
    )
    .expect("the leaf's delegate may present");

    // The agent above it presents the same chain: refused.
    let err = verify_chain(&[sub, root], ALICE, "schedule:read", AGENT, t(1)).unwrap_err();
    assert!(
        matches!(err, DelegationError::NotTheDelegate { ref delegate, .. } if delegate == SUBAGENT),
        "got {err:?}"
    );
}

// -------------------------------------------------------------------------------------
// Re-delegation is opt-in
// -------------------------------------------------------------------------------------

/// The whole point: a sub-agent acting on strictly less than the agent holds.
#[test]
fn a_permitted_redelegation_verifies() {
    let root = root_delegation();
    let sub = root
        .redelegate(SUBAGENT.into(), vec!["schedule:read".into()], t(0), t(24))
        .expect("redelegation");

    let v =
        verify_chain(&[sub, root], ALICE, "schedule:read", SUBAGENT, t(1)).expect("should verify");
    assert_eq!(v.delegate, SUBAGENT);
    assert_eq!(
        v.principal, ALICE,
        "acts are attributed to Alice, not the agent"
    );
    assert_eq!(v.scope, vec!["schedule:read".to_string()]);
}

/// `maxDepth` narrows on the way down, so the budget cannot be topped back up.
#[test]
fn a_redelegation_spends_the_depth_budget() {
    let root = root_delegation(); // maxDepth 1
    let sub = root
        .redelegate(SUBAGENT.into(), vec!["schedule:read".into()], t(0), t(24))
        .unwrap();

    assert_eq!(sub.credential().delegation().unwrap().max_depth, Some(0));

    let err = sub
        .redelegate(MALLORY.into(), vec!["schedule:read".into()], t(0), t(24))
        .unwrap_err();
    assert!(
        format!("{err}").contains("does not permit re-delegation"),
        "{err}"
    );
}

/// Absence of `maxDepth` prohibits re-delegation — the default is a single hop. This is the
/// opposite default from a VAC's attenuation, deliberately: a delegate speaks in the
/// principal's name, so the principal keeps the register of who may do so.
#[test]
fn absence_of_max_depth_prohibits_redelegation() {
    let root = DTGCredential::new_vdc(
        ALICE.into(),
        AGENT.into(),
        t(0),
        t(24 * 90),
        vec!["schedule:read".into()],
        None,
    )
    .unwrap();

    let err = root
        .redelegate(SUBAGENT.into(), vec!["schedule:read".into()], t(0), t(24))
        .unwrap_err();
    assert!(
        format!("{err}").contains("does not permit re-delegation"),
        "{err}"
    );
}

/// Refused at issue time...
#[test]
fn a_redelegation_cannot_widen_the_scope() {
    let root = root_delegation();
    let err = root
        .redelegate(SUBAGENT.into(), vec!["schedule:cancel".into()], t(0), t(24))
        .unwrap_err();
    assert!(format!("{err}").contains("not in the scope"), "{err}");
}

/// ...and at verification time too, for an implementation that built the JSON by hand. The
/// verifier's check is the authoritative one.
#[test]
fn a_widened_link_is_refused_by_the_verifier() {
    let root = root_delegation();
    let mut widened = DTGCredential::new_vdc(
        AGENT.into(),
        SUBAGENT.into(),
        t(0),
        t(24),
        vec!["schedule:cancel".into()],
        Some(0),
    )
    .unwrap();

    // The link itself is intact — the digest matches — so the widening is what must be
    // caught.
    if let Some(d) = widened.credential_mut().delegation_mut() {
        d.parent = Some(root.digest_multibase().unwrap());
    }

    let err = verify_chain(&[widened, root], ALICE, "schedule:cancel", SUBAGENT, t(1)).unwrap_err();
    assert!(
        matches!(err, DelegationError::WidensScope { ref act, .. } if act == "schedule:cancel"),
        "got {err:?}"
    );
}

/// Only the party a delegation appointed may re-delegate it — otherwise anyone could graft
/// someone else's appointment onto their own chain.
#[test]
fn a_link_issued_by_someone_other_than_the_parents_delegate_is_refused() {
    let root = root_delegation(); // appoints AGENT
    let mut grafted = DTGCredential::new_vdc(
        MALLORY.into(), // not AGENT
        MALLORY.into(),
        t(0),
        t(24),
        vec!["schedule:read".into()],
        Some(0),
    )
    .unwrap();
    if let Some(d) = grafted.credential_mut().delegation_mut() {
        d.parent = Some(root.digest_multibase().unwrap());
    }

    let err = verify_chain(&[grafted, root], ALICE, "schedule:read", MALLORY, t(1)).unwrap_err();
    assert!(
        matches!(err, DelegationError::IssuerNotParentSubject { .. }),
        "got {err:?}"
    );
}

/// A re-delegation may not outlive the appointment it derives from, or an expiry could be
/// escaped simply by re-delegating past it.
#[test]
fn a_redelegation_cannot_outlive_its_parent() {
    let root = root_delegation();
    let err = root
        .redelegate(
            SUBAGENT.into(),
            vec!["schedule:read".into()],
            t(0),
            t(24 * 365),
        )
        .unwrap_err();
    assert!(format!("{err}").contains("beyond the parent's"), "{err}");
}

/// A link must name the credential presented above it. Without this a holder could
/// interleave links from unrelated chains.
#[test]
fn a_link_naming_a_different_parent_is_refused() {
    let root = root_delegation();
    let mut sub = root
        .redelegate(SUBAGENT.into(), vec!["schedule:read".into()], t(0), t(24))
        .unwrap();
    if let Some(d) = sub.credential_mut().delegation_mut() {
        // A well-formed digest of something else entirely.
        d.parent = Some(
            dtg_credentials::digest_multibase_json(&serde_json::json!({"not": "the parent"}))
                .unwrap(),
        );
    }

    let err = verify_chain(&[sub, root], ALICE, "schedule:read", SUBAGENT, t(1)).unwrap_err();
    assert!(
        matches!(err, DelegationError::BrokenLink { index: 0, .. }),
        "got {err:?}"
    );
}

/// A truncated chain establishes no representation of the principal. Presenting only the
/// derived link, the agent is the issuer of what is offered as the root — so the chain
/// resolves to the agent, not to Alice, and that is what the verifier says.
#[test]
fn a_truncated_chain_does_not_resolve_to_the_principal() {
    let root = root_delegation();
    let sub = root
        .redelegate(SUBAGENT.into(), vec!["schedule:read".into()], t(0), t(24))
        .unwrap();

    let err = verify_chain(&[sub], ALICE, "schedule:read", SUBAGENT, t(1)).unwrap_err();
    assert!(
        matches!(err, DelegationError::RootNotPrincipal { .. }),
        "got {err:?}"
    );
}

/// The other half of the same rule: a credential issued by the principal but still naming a
/// `parent` is not a root delegation, and a chain ending there has been cut short.
#[test]
fn a_root_that_names_a_parent_is_refused() {
    let mut root = root_delegation();
    if let Some(d) = root.credential_mut().delegation_mut() {
        d.parent = Some(
            dtg_credentials::digest_multibase_json(&serde_json::json!({"some": "ancestor"}))
                .unwrap(),
        );
    }

    let err = verify_chain(&[root], ALICE, "schedule:read", AGENT, t(1)).unwrap_err();
    assert!(
        matches!(err, DelegationError::BrokenLink { .. }),
        "got {err:?}"
    );
}

// -------------------------------------------------------------------------------------
// Shape rules
// -------------------------------------------------------------------------------------

/// A VDC cannot express an unbounded appointment by emptying its scope, at construction...
#[test]
fn an_empty_scope_is_refused_at_construction() {
    let err =
        DTGCredential::new_vdc(ALICE.into(), AGENT.into(), t(0), t(24), vec![], None).unwrap_err();
    assert!(
        matches!(err, DTGCredentialError::MalformedDelegation(_)),
        "got {err:?}"
    );
}

/// A window that closes before, or as, it opens describes an appointment that is never in
/// force. Every path that builds a VDC refuses one.
#[test]
fn an_inverted_window_is_refused_at_issue() {
    let is_window_error =
        |err: &DTGCredentialError| matches!(err, DTGCredentialError::InvalidValidityWindow { .. });

    let err = DTGCredential::new_vdc(
        ALICE.into(),
        AGENT.into(),
        t(24),
        t(0),
        vec!["schedule:read".into()],
        None,
    )
    .unwrap_err();
    assert!(is_window_error(&err), "got {err:?}");

    let err = DTGCredential::new_vdc(
        ALICE.into(),
        AGENT.into(),
        t(0),
        t(0),
        vec!["schedule:read".into()],
        None,
    )
    .unwrap_err();
    assert!(is_window_error(&err), "got {err:?}");

    let root = root_delegation();
    let err = root
        .redelegate(SUBAGENT.into(), vec!["schedule:read".into()], t(24), t(1))
        .unwrap_err();
    assert!(is_window_error(&err), "got {err:?}");

    let err = DTGCredential::redelegate_from_json(
        &wire(&root),
        SUBAGENT.into(),
        vec!["schedule:read".into()],
        t(1),
        t(1),
    )
    .unwrap_err();
    assert!(is_window_error(&err), "got {err:?}");

    let err = DTGCredential::new_delegate_vdc_for(&wire(&root), AGENT, t(24), t(0)).unwrap_err();
    assert!(is_window_error(&err), "got {err:?}");
}

/// ...nor by deserialization, which would otherwise bypass the constructor's guard.
#[test]
fn an_empty_scope_is_refused_on_deserialization() {
    let json = serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://firstperson.network/credentials/dtg/v1"
        ],
        "type": ["VerifiableCredential", "DTGCredential", "DelegationCredential"],
        "issuer": ALICE,
        "validFrom": "2026-01-06T10:00:00Z",
        "validUntil": "2026-04-06T10:00:00Z",
        "credentialSubject": { "id": AGENT, "delegation": { "scope": [] } }
    });

    let err = serde_json::from_value::<DTGCredential>(json).unwrap_err();
    assert!(err.to_string().contains("at least one"), "{err}");
}

/// Neither a grant nor an acceptance: a `delegation` with neither `scope` nor `accepts`
/// says nothing at all.
#[test]
fn a_delegation_that_is_neither_half_is_refused() {
    let json = serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://firstperson.network/credentials/dtg/v1"
        ],
        "type": ["VerifiableCredential", "DTGCredential", "DelegationCredential"],
        "issuer": ALICE,
        "validFrom": "2026-01-06T10:00:00Z",
        "validUntil": "2026-04-06T10:00:00Z",
        "credentialSubject": { "id": AGENT, "delegation": { "maxDepth": 2 } }
    });

    let err = serde_json::from_value::<DTGCredential>(json).unwrap_err();
    assert!(
        err.to_string()
            .contains("neither a grant nor an acceptance"),
        "{err}"
    );
}

/// An acceptance restating a scope would need a cross-credential equality check that
/// selective disclosure defeats, so carrying both is malformed rather than redundant.
#[test]
fn a_credential_carrying_both_scope_and_accepts_is_refused() {
    let json = serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://firstperson.network/credentials/dtg/v1"
        ],
        "type": ["VerifiableCredential", "DTGCredential", "DelegationCredential"],
        "issuer": AGENT,
        "validFrom": "2026-01-06T10:00:00Z",
        "validUntil": "2026-04-06T10:00:00Z",
        "credentialSubject": {
            "id": ALICE,
            "delegation": {
                "scope": ["schedule:read"],
                "accepts": "zQmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n"
            }
        }
    });

    let err = serde_json::from_value::<DTGCredential>(json).unwrap_err();
    assert!(
        err.to_string().contains("both `accepts` and `scope`"),
        "{err}"
    );
}

/// `validUntil` is REQUIRED on a VDC: an appointment with no expiry cannot be reasoned
/// about by a verifier that cannot reach the delegator.
#[test]
fn a_delegation_without_an_expiry_is_refused() {
    let json = serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://firstperson.network/credentials/dtg/v1"
        ],
        "type": ["VerifiableCredential", "DTGCredential", "DelegationCredential"],
        "issuer": ALICE,
        "validFrom": "2026-01-06T10:00:00Z",
        "credentialSubject": { "id": AGENT, "delegation": { "scope": ["schedule:read"] } }
    });

    let vdc: DTGCredential = serde_json::from_value(json).expect("parses");
    let err = verify_chain(&[vdc], ALICE, "schedule:read", AGENT, t(1)).unwrap_err();
    assert!(
        matches!(err, DelegationError::NoExpiry { index: 0 }),
        "got {err:?}"
    );
}

/// Verification is linear in depth and runs on every presentation, so depth is bounded.
#[test]
fn an_over_deep_chain_is_refused() {
    let root = root_delegation();
    let chain: Vec<DTGCredential> = std::iter::repeat_n(root, MAX_CHAIN_DEPTH + 1).collect();

    let err = verify_chain(&chain, ALICE, "schedule:read", AGENT, t(1)).unwrap_err();
    assert!(
        matches!(err, DelegationError::TooDeep { found } if found == MAX_CHAIN_DEPTH + 1),
        "got {err:?}"
    );
}

/// An expired link is refused wherever it sits — a chain is only as live as its
/// shortest-lived member.
#[test]
fn an_expired_link_is_refused() {
    let root = root_delegation();
    let err = verify_chain(&[root], ALICE, "schedule:read", AGENT, t(24 * 365)).unwrap_err();
    assert!(
        matches!(err, DelegationError::NotValidNow { index: 0, .. }),
        "got {err:?}"
    );
}

/// A VDC round trips through JSON with its appointment intact, in both halves.
#[test]
fn a_vdc_round_trips_through_json() {
    let root = root_delegation();
    let back: DTGCredential = serde_json::from_str(&serde_json::to_string(&root).unwrap()).unwrap();
    let d = back.credential().delegation().expect("grant survives");

    assert_eq!(
        d.scope.as_deref().unwrap(),
        ["schedule:read", "schedule:propose"]
    );
    assert_eq!(d.max_depth, Some(1));
    assert!(d.parent.is_none(), "a root delegation carries no parent");
    assert!(d.accepts.is_none(), "a grant carries no accepts");

    let acceptance = DTGCredential::new_delegate_vdc_for(&wire(&root), AGENT, t(0), t(24 * 90))
        .expect("accepts");
    let back: DTGCredential =
        serde_json::from_str(&serde_json::to_string(&acceptance).unwrap()).unwrap();
    assert!(
        back.accepts(&root).unwrap(),
        "the edge survives the round trip"
    );
}

/// The wire form is what a counterparty digests, so a derivation from a received grant must
/// hash the bytes rather than the parse. A normalized timestamp is enough to make the two
/// differ.
#[test]
fn redelegating_from_json_digests_the_wire_form() {
    let mut grant = wire(&root_delegation());
    grant["validFrom"] = Value::String("2026-01-06T10:00:00.000+00:00".to_string());

    let sub = DTGCredential::redelegate_from_json(
        &grant,
        SUBAGENT.into(),
        vec!["schedule:read".into()],
        t(0),
        t(24),
    )
    .expect("redelegation");

    assert_eq!(
        sub.credential().delegation().unwrap().parent.as_deref(),
        Some(
            dtg_credentials::digest_multibase_json(&grant)
                .unwrap()
                .as_str()
        ),
        "the parent digest must cover the grant as it arrived"
    );
    assert_eq!(sub.issuer(), AGENT, "the delegate is read off the grant");
}
