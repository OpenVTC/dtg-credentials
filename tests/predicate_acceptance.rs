//! Predicate acceptance: a verifier accepts a statement only under a predicate it has been
//! configured to accept, matched byte for byte, and fails closed on everything else.

use chrono::{DateTime, TimeZone, Utc};
use dtg_credentials::{
    DTGCredential, DTGCredentialError, ENDORSES_V1, IssuerScope, PRESENTED_V1, PredicateAcceptList,
    PredicateStatus, StatementObject, VETTED_V1, WITNESSED_V1,
};
use serde_json::{Value, json};

const ISSUER: &str = "did:example:issuer";
const SUBJECT: &str = "did:example:subject";
const OBSERVED: &str = "https://vtc.example/vocab#observedDocument";

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 30, 10, 0, 0).unwrap()
}

fn endorsement(scope: IssuerScope) -> DTGCredential {
    DTGCredential::new_endorses_vsc(
        ISSUER.into(),
        scope,
        SUBJECT.into(),
        json!({ "skill": "chess" }),
        t0(),
        None,
    )
    .unwrap()
}

fn observation(object: StatementObject) -> DTGCredential {
    DTGCredential::new_vsc(
        ISSUER.into(),
        IssuerScope::Directed,
        SUBJECT.into(),
        OBSERVED,
        object,
        t0(),
        None,
    )
    .unwrap()
}

/// The registry's `accept-list.json`, in the shape `meta/accept-list.schema.json` fixes:
/// the two published core predicates, the two being added, and a community one.
fn registry_accept_list() -> Value {
    let task_bound = |object_kind: &str| {
        json!({
            "status": "draft",
            "objectKind": [object_kind],
            "objectSchema": null,
            "taskContextRequired": true,
            "minimumIssuerScope": "directed",
            "additionalMembers": {},
            "supersededBy": null
        })
    };
    let mut witnessed = task_bound("digestMultibase");
    witnessed["additionalMembers"] = json!({
        "witnessContext": {
            "required": false,
            "schema": "https://registry.trustoverip.org/dtg/vsc/witnessed/1/witness-context.schema.json"
        }
    });
    json!({
        "$schema": "https://registry.trustoverip.org/dtg/meta/v1/accept-list.schema.json",
        "namespace": "https://registry.trustoverip.org/dtg/vsc/",
        "revision": "unreleased",
        "commit": "eb29484",
        "generatedAt": "2026-09-30T10:00:00Z",
        "predicates": {
            ENDORSES_V1: {
                "status": "draft",
                "objectKind": ["value"],
                "objectSchema": null,
                "taskContextRequired": false,
                "minimumIssuerScope": null,
                "additionalMembers": {},
                "supersededBy": null
            },
            WITNESSED_V1: witnessed,
            VETTED_V1: task_bound("value"),
            PRESENTED_V1: task_bound("digestMultibase"),
            OBSERVED: {
                "status": "candidate",
                "objectKind": ["value"],
                "objectSchema": null,
                "taskContextRequired": false,
                "minimumIssuerScope": "directed",
                "additionalMembers": { "evidenceRef": { "required": true } },
                "supersededBy": null
            }
        }
    })
}

fn all_statuses() -> [PredicateStatus; 4] {
    [
        PredicateStatus::Draft,
        PredicateStatus::Candidate,
        PredicateStatus::Standard,
        PredicateStatus::Deprecated,
    ]
}

#[test]
fn an_accepted_predicate_is_accepted() {
    let list = PredicateAcceptList::from_iris([ENDORSES_V1]).unwrap();
    let vec = endorsement(IssuerScope::Directed);
    assert_eq!(list.accept(&vec).unwrap(), ENDORSES_V1);
}

/// Rejection is the only conforming outcome for a predicate not configured, however
/// well-formed the statement.
#[test]
fn an_unlisted_predicate_is_rejected() {
    let list = PredicateAcceptList::from_iris([WITNESSED_V1]).unwrap();
    assert!(matches!(
        list.accept(&endorsement(IssuerScope::Directed)),
        Err(DTGCredentialError::PredicateNotAccepted(p)) if p == ENDORSES_V1
    ));

    // An empty list accepts nothing.
    assert!(
        PredicateAcceptList::default()
            .accept(&endorsement(IssuerScope::Directed))
            .is_err()
    );
}

/// Exact byte comparison: no prefix, case, scheme or trailing-slash equivalence, and no
/// version is another version.
#[test]
fn matching_is_exact() {
    for near_miss in [
        "https://registry.trustoverip.org/dtg/vsc/endorses/1/",
        "http://registry.trustoverip.org/dtg/vsc/endorses/1",
        "https://REGISTRY.trustoverip.org/dtg/vsc/endorses/1",
        "https://registry.trustoverip.org/dtg/vsc/endorses/2",
        "https://registry.trustoverip.org/dtg/vsc/endorses",
        "https://registry.trustoverip.org/dtg/vsc/",
    ] {
        let list = PredicateAcceptList::from_iris([near_miss]).unwrap();
        assert!(!list.contains(ENDORSES_V1));
        assert!(
            list.accept(&endorsement(IssuerScope::Directed)).is_err(),
            "`{near_miss}` must not accept `{ENDORSES_V1}`"
        );
    }
}

/// A list naming a compact form could never match a well-formed statement.
#[test]
fn a_list_naming_a_compact_iri_is_refused() {
    assert!(matches!(
        PredicateAcceptList::from_iris(["dtg:endorses"]),
        Err(DTGCredentialError::InvalidPredicate(_))
    ));
}

/// Acceptance is for statements; anything else is a different question.
#[test]
fn a_credential_that_is_not_a_statement_is_refused() {
    let list = PredicateAcceptList::from_iris([ENDORSES_V1]).unwrap();
    let vrc = DTGCredential::new_vrc(
        ISSUER.into(),
        IssuerScope::Pairwise,
        SUBJECT.into(),
        t0(),
        None,
    );
    assert!(matches!(
        list.accept(&vrc),
        Err(DTGCredentialError::WrongCredentialType { .. })
    ));
}

/// A statement mutated out of shape after it was built is refused, not accepted on its
/// predicate alone.
#[test]
fn a_malformed_statement_is_refused_before_its_predicate_is_looked_up() {
    let list = PredicateAcceptList::from_iris([ENDORSES_V1]).unwrap();
    let mut vec = endorsement(IssuerScope::Directed);
    vec.credential_mut().statement_mut().unwrap().object =
        StatementObject::Id("did:example:someone".into());
    assert!(matches!(
        list.accept(&vec),
        Err(DTGCredentialError::ProfileViolation(_))
    ));
}

#[test]
fn the_registry_accept_list_is_read_with_the_verifiers_status_floor() {
    let json = registry_accept_list().to_string();

    let everything = PredicateAcceptList::from_registry_json(&json, &all_statuses()).unwrap();
    assert_eq!(everything.len(), 5);
    assert!(everything.contains(VETTED_V1));
    assert!(
        everything
            .entry(WITNESSED_V1)
            .unwrap()
            .task_context_required
    );

    // The registry's recommended floor, candidate and above, excludes every draft.
    let floor = PredicateAcceptList::from_registry_json(
        &json,
        &[PredicateStatus::Candidate, PredicateStatus::Standard],
    )
    .unwrap();
    assert_eq!(floor.iris().collect::<Vec<_>>(), [OBSERVED]);
    assert!(floor.accept(&endorsement(IssuerScope::Directed)).is_err());

    assert!(
        PredicateAcceptList::from_registry_json(&json, &[])
            .unwrap()
            .is_empty()
    );
}

/// An entry member this library does not know could be a constraint it would otherwise
/// ignore, so the document is refused rather than read leniently.
#[test]
fn an_accept_list_with_an_unknown_constraint_is_refused() {
    let mut list = registry_accept_list();
    list["predicates"][ENDORSES_V1]["maximumIssuerScope"] = json!("directed");
    assert!(matches!(
        PredicateAcceptList::from_registry_json(&list.to_string(), &all_statuses()),
        Err(DTGCredentialError::MalformedAcceptList(_))
    ));

    let mut list = registry_accept_list();
    list["predicates"][ENDORSES_V1]["status"] = json!("approved");
    assert!(PredicateAcceptList::from_registry_json(&list.to_string(), &all_statuses()).is_err());

    assert!(PredicateAcceptList::from_registry_json("[]", &all_statuses()).is_err());
}

/// A community predicate's registry constraints are applied: object kind, minimum scope,
/// and REQUIRED additional members.
#[test]
fn registry_constraints_are_applied() {
    let list = PredicateAcceptList::from_registry_json(
        &registry_accept_list().to_string(),
        &all_statuses(),
    )
    .unwrap();

    // Missing the REQUIRED `evidenceRef`.
    let bare = observation(StatementObject::Value(
        json!({ "documentType": "passport" }),
    ));
    assert!(matches!(
        list.accept(&bare),
        Err(DTGCredentialError::ProfileViolation(_))
    ));

    let mut complete = bare.clone();
    complete
        .credential_mut()
        .statement_mut()
        .unwrap()
        .extra
        .insert("evidenceRef".into(), json!("urn:uuid:evidence"));
    assert_eq!(list.accept(&complete).unwrap(), OBSERVED);

    // An `object.id` where the entry permits only `value`.
    let mut by_id = observation(StatementObject::Id("did:example:document".into()));
    by_id
        .credential_mut()
        .statement_mut()
        .unwrap()
        .extra
        .insert("evidenceRef".into(), json!("urn:uuid:evidence"));
    assert!(matches!(
        list.accept(&by_id),
        Err(DTGCredentialError::ProfileViolation(_))
    ));

    // Below the entry's minimum scope.
    let mut pairwise = complete.clone();
    pairwise.credential_mut().issuer_scope = IssuerScope::Pairwise;
    assert!(matches!(
        list.accept(&pairwise),
        Err(DTGCredentialError::IssuerScopeTooNarrow { .. })
    ));
}

/// A core statement carrying everything its profile requires is accepted from the registry
/// list; the citation the profile requires is checked whether or not the list says so.
#[test]
fn a_witnessed_statement_is_accepted_under_its_registry_entry() {
    let list = PredicateAcceptList::from_registry_json(
        &registry_accept_list().to_string(),
        &all_statuses(),
    )
    .unwrap();
    let session = json!({
        "id": "urn:uuid:session",
        "type": "https://trusttasks.org/spec/witness/session/0.1",
        "threadId": "urn:uuid:session",
    });
    let vrc = serde_json::to_value(DTGCredential::new_vrc(
        SUBJECT.into(),
        IssuerScope::Pairwise,
        "did:example:peer".into(),
        t0(),
        None,
    ))
    .unwrap();
    let vwc = DTGCredential::new_witnessed_vsc(
        "did:example:witness".into(),
        IssuerScope::Public,
        &vrc,
        &session,
        t0(),
        None,
        None,
    )
    .unwrap();
    assert_eq!(list.accept(&vwc).unwrap(), WITNESSED_V1);

    let mut uncited = vwc.clone();
    uncited.credential_mut().task_context = None;
    assert!(matches!(
        PredicateAcceptList::from_iris([WITNESSED_V1])
            .unwrap()
            .accept(&uncited),
        Err(DTGCredentialError::MissingTaskContext)
    ));
}
