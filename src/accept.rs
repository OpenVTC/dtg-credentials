//! Which predicates a verifier accepts: the configuration that turns a well-formed VSC
//! into a meaningful one.
//!
//! A VSC whose signature and status verify is not thereby meaningful. DTG Core Credentials
//! §Predicate Handling requires a verifier to reject a statement whose predicate is not in
//! a vocabulary it has been configured to accept, and gives rejection as the only
//! conforming outcome:
//!
//! - **Exact match.** A predicate is compared byte for byte with the IRIs configured
//!   here. There is no prefix, namespace or case-insensitive match.
//! - **No equivalence.** An `owl:sameAs`, `skos:exactMatch` or similar assertion published
//!   by anyone is not followed. Whether two predicates are treated alike is a governance
//!   decision, and it is made by putting both in the list.
//! - **Never from the credential.** The list is the verifier's; nothing a credential
//!   carries adds to it.
//!
//! A well-formed statement under an unrecognized predicate is the intended shape of an
//! attack that names authority, membership or personhood in a string, so
//! [PredicateAcceptList::accept] fails closed: anything it cannot positively accept is an
//! error.
//!
//! # Two ways to build one
//!
//! - [PredicateAcceptList::from_iris], from a list of IRIs the verifier's governance names.
//! - [PredicateAcceptList::from_registry_json], from the machine-readable `accept-list.json`
//!   the DTG VSC Predicate Registry publishes, keeping the entries whose status the verifier
//!   admits. Entries carry the profile's machine-checkable constraints — permitted `object`
//!   kinds, whether `taskContext` is required, a minimum `issuerScope`, REQUIRED additional
//!   members — and `accept` applies them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::statement::check_constraints;
use crate::{
    DTGCredential, DTGCredentialError, DTGCredentialType, IssuerScope, ObjectKind,
    check_predicate_iri,
};

/// A predicate's lifecycle status in the registry.
///
/// The registry lists every status and leaves the floor to the verifier; `candidate` and
/// above is its recommended default.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum PredicateStatus {
    Draft,
    Candidate,
    Standard,
    Deprecated,
}

/// An additional `credentialSubject` member a profile defines.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdditionalMember {
    /// Whether a statement under the predicate MUST carry it.
    pub required: bool,

    /// A JSON Schema for the member, if the profile publishes one. Not applied here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
}

/// One predicate's entry in the registry's accept-list: its status and machine-checkable
/// constraints.
///
/// # Unknown members are refused
///
/// Deliberately. A registry that adds a constraint this library does not know would
/// otherwise have it silently ignored, and a verifier would accept statements the registry
/// says it must not. Refusing the document makes that a configuration error rather than a
/// fail-open.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptListEntry {
    pub status: PredicateStatus,
    pub object_kind: Vec<ObjectKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_schema: Option<String>,
    pub task_context_required: bool,
    pub minimum_issuer_scope: Option<IssuerScope>,
    pub additional_members: BTreeMap<String, AdditionalMember>,
    pub superseded_by: Option<String>,
}

/// The registry's `accept-list.json`, per its `meta/accept-list.schema.json`.
///
/// Unknown members of the envelope are ignored, so build metadata the registry adds or
/// drops (it dropped `revision` when it stopped tagging releases) never breaks loading.
/// Entries stay strict: an unknown member there could be a constraint this version does
/// not know how to apply, and failing closed is the only safe reading of it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegistryAcceptList {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub namespace: String,
    /// The registry commit the list was built from. Pin this, or the list's digest.
    pub commit: String,
    pub generated_at: String,
    /// Every published predicate version, keyed by IRI.
    pub predicates: BTreeMap<String, AcceptListEntry>,
}

/// The predicates a verifier accepts. See the [module docs](self).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PredicateAcceptList {
    /// IRI → the constraints to apply, where the configuration carries any.
    predicates: BTreeMap<String, Option<AcceptListEntry>>,
}

impl PredicateAcceptList {
    /// An accept-list naming exactly these predicate IRIs.
    ///
    /// No constraints beyond the match are attached, but a statement under a core
    /// predicate ([crate::WITNESSED_V1] and the others) is still held to its profile,
    /// because that is checked whenever a VSC is parsed or validated.
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::InvalidPredicate] for an entry that is not an absolute NFC IRI:
    /// a list containing one could never match a well-formed statement, and is more likely
    /// a configuration mistake than an intent.
    pub fn from_iris<I, S>(iris: I) -> Result<Self, DTGCredentialError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut predicates = BTreeMap::new();
        for iri in iris {
            let iri = iri.into();
            check_predicate_iri(&iri)?;
            predicates.insert(iri, None);
        }
        Ok(PredicateAcceptList { predicates })
    }

    /// An accept-list of the registry entries whose status is one of `statuses`, each
    /// carrying its constraints.
    ///
    /// `statuses` is the verifier's floor, stated explicitly — `&[Candidate, Standard]` for
    /// the registry's recommended default. An empty slice accepts nothing.
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::InvalidPredicate] for a key that is not an absolute NFC IRI.
    pub fn from_registry(
        list: &RegistryAcceptList,
        statuses: &[PredicateStatus],
    ) -> Result<Self, DTGCredentialError> {
        let mut predicates = BTreeMap::new();
        for (iri, entry) in &list.predicates {
            if statuses.contains(&entry.status) {
                check_predicate_iri(iri)?;
                predicates.insert(iri.clone(), Some(entry.clone()));
            }
        }
        Ok(PredicateAcceptList { predicates })
    }

    /// [PredicateAcceptList::from_registry] over the registry's `accept-list.json` text.
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::MalformedAcceptList] if the document does not have the
    /// registry's shape — including a member this library does not know — and the errors
    /// of [PredicateAcceptList::from_registry].
    pub fn from_registry_json(
        json: &str,
        statuses: &[PredicateStatus],
    ) -> Result<Self, DTGCredentialError> {
        let list: RegistryAcceptList = serde_json::from_str(json)
            .map_err(|e| DTGCredentialError::MalformedAcceptList(e.to_string()))?;
        Self::from_registry(&list, statuses)
    }

    /// Is `predicate` accepted, by exact byte comparison?
    pub fn contains(&self, predicate: &str) -> bool {
        self.predicates.contains_key(predicate)
    }

    /// The accepted predicate IRIs.
    pub fn iris(&self) -> impl Iterator<Item = &str> {
        self.predicates.keys().map(String::as_str)
    }

    /// The registry constraints attached to `predicate`, if it is accepted and the list was
    /// built from the registry.
    pub fn entry(&self, predicate: &str) -> Option<&AcceptListEntry> {
        self.predicates.get(predicate).and_then(Option::as_ref)
    }

    /// How many predicates are accepted.
    pub fn len(&self) -> usize {
        self.predicates.len()
    }

    /// Does this list accept nothing?
    pub fn is_empty(&self) -> bool {
        self.predicates.is_empty()
    }

    /// Accepts `vsc` or says why not, failing closed. Returns the accepted predicate.
    ///
    /// In order:
    ///
    /// 1. `vsc` must be a `StatementCredential`, else
    ///    [DTGCredentialError::WrongCredentialType].
    /// 2. It must pass [DTGCredential::validate] — well-formed predicate, the core profile
    ///    where there is one, the window's ordering and the JSON depth bound.
    /// 3. Its `predicate` must be in this list, byte for byte, else
    ///    [DTGCredentialError::PredicateNotAccepted].
    /// 4. Where the entry carries registry constraints, they must hold: the `object` kind
    ///    ([DTGCredentialError::ProfileViolation]), `taskContext` and `taskDigestMultibase`
    ///    ([DTGCredentialError::MissingTaskContext], [DTGCredentialError::MissingTaskDigest]),
    ///    the minimum `issuerScope` ([DTGCredentialError::IssuerScopeTooNarrow]) and every
    ///    REQUIRED additional member ([DTGCredentialError::ProfileViolation]).
    ///
    /// # What this does not check
    ///
    /// The proof, whether the window contains the present instant, revocation, whether the
    /// issuer is one the verifier trusts for this predicate, and any subject–object rule
    /// needing the credential the object names — [DTGCredential::witnesses_issuance_of] and
    /// [DTGCredential::witnesses_presentation_of] are those. Nor does acceptance widen what a
    /// statement means: a VSC attests and never establishes, and a verifier MUST NOT draw a
    /// conclusion its profile does not state.
    pub fn accept<'a>(&self, vsc: &'a DTGCredential) -> Result<&'a str, DTGCredentialError> {
        let (true, Some(statement)) =
            (vsc.type_() == DTGCredentialType::Statement, vsc.statement())
        else {
            return Err(DTGCredentialError::WrongCredentialType {
                expected: DTGCredentialType::Statement.to_string(),
                got: vsc.type_().to_string(),
            });
        };
        vsc.validate()?;

        let Some(entry) = self.predicates.get(&statement.predicate) else {
            return Err(DTGCredentialError::PredicateNotAccepted(
                statement.predicate.clone(),
            ));
        };

        if let Some(entry) = entry {
            check_constraints(
                &entry.object_kind,
                entry.task_context_required,
                entry.minimum_issuer_scope,
                vsc.credential(),
                statement,
            )?;
            for (member, definition) in &entry.additional_members {
                let present = match member.as_str() {
                    "witnessContext" => statement.witness_context.is_some(),
                    other => statement.extra.contains_key(other),
                };
                if definition.required && !present {
                    return Err(DTGCredentialError::ProfileViolation(format!(
                        "`{}` requires `credentialSubject.{member}`",
                        statement.predicate
                    )));
                }
            }
        }

        Ok(&statement.predicate)
    }
}
