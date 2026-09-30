//! Verifiable Statement Credentials (VSC): one type, many predicates.
//!
//! A VSC is the DTG's general-purpose claim — *I witnessed this party issue this
//! credential*, *I endorse this party's skill*, *I vetted this party's identity*. Each is a
//! statement a verifier reads and either believes or does not. Rather than give each
//! predicate a credential type of its own, DTG Core Credentials defines one type,
//! `StatementCredential`, and lets a **predicate profile** fix the constraints of each
//! predicate.
//!
//! ```text
//! credentialSubject: { id, predicate, object: { id | digestMultibase | value }, ...profile members }
//! ```
//!
//! # A predicate is an identifier, matched as one
//!
//! `predicate` is an absolute IRI in Unicode Normalization Form C, compared byte for byte.
//! A compact form — a CURIE such as `dtg:witnessed`, a bare JSON-LD term — is malformed,
//! not unknown: no expansion is performed, so matching never depends on a JSON-LD context.
//! [check_predicate_iri] is the check.
//!
//! Recognizing a predicate is the verifier's configuration, never the credential's: see
//! [crate::PredicateAcceptList], which fails closed.
//!
//! # The core profiles
//!
//! | Constant | `object` | `taskContext` | minimum `issuerScope` | Constructor |
//! |---|---|---|---|---|
//! | [ENDORSES_V1] | `value` | OPTIONAL | — | [DTGCredential::new_endorses_vsc] |
//! | [WITNESSED_V1] | `digestMultibase` | REQUIRED | `directed` | [DTGCredential::new_witnessed_vsc] |
//! | [VETTED_V1] | `value` | REQUIRED | `directed` | [DTGCredential::new_vetted_vsc] |
//! | [PRESENTED_V1] | `digestMultibase` | REQUIRED | `directed` | [DTGCredential::new_presented_vsc] |
//!
//! A statement under one of these is checked against its profile when it is parsed,
//! built, validated and signed. A statement under any other predicate is only checked for
//! shape; whether it means anything is the verifier's accept-list to say.
//!
//! # A statement attests; it never establishes
//!
//! Whatever its predicate says, a VSC does not confer representation, authority,
//! membership, admission or personhood, and is not proof that a trust task completed. A
//! predicate named `mayActFor` is a string.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::create::{check_window, check_witness_session, issuer_of};
use crate::{
    CredentialSubject, DTGCommon, DTGCredential, DTGCredentialError, DTGCredentialType,
    IssuerScope, WitnessContext,
};

/// `dtg:endorses` — the issuer asserts something favourable about the subject: a skill, a
/// standing, a reputation. A VSC under this profile is a verifiable endorsement credential
/// (VEC).
///
/// `object` is a `value` whose schema the governing community's endorsement vocabulary
/// defines. `taskContext` is OPTIONAL and the issuer's scope unconstrained.
pub const ENDORSES_V1: &str = "https://registry.trustoverip.org/dtg/vsc/endorses/1";

/// `dtg:witnessed` — the issuer attests that it observed the subject **issue** the
/// credential `object.digestMultibase` names, under the conditions of the trust task
/// exchange `taskContext` names. A VSC under this profile is a verifiable witness
/// credential (VWC).
///
/// `credentialSubject.id` MUST be that credential's `issuer`; `taskContext` and
/// `taskDigestMultibase` are REQUIRED; `issuerScope` is `directed` at minimum. It MAY carry
/// a `witnessContext`.
pub const WITNESSED_V1: &str = "https://registry.trustoverip.org/dtg/vsc/witnessed/1";

/// `dtg:vetted` — the issuer attests that it checked the subject's claimed identity in a
/// vetting session, by the method and against the document classes `object.value` states.
///
/// The profile of DTG Core Credentials' identity-vetting worked example. `taskContext` and
/// `taskDigestMultibase` are REQUIRED — the vetting exchange a dispute would examine — and
/// `issuerScope` is `directed` at minimum. This library is generic about the payload: it
/// is `object.value`, and its schema lives with the registry definition.
pub const VETTED_V1: &str = "https://registry.trustoverip.org/dtg/vsc/vetted/1";

/// `dtg:presented` — the issuer attests that it observed the subject **present** the
/// credential `object.digestMultibase` names, in the exchange `taskContext` names.
///
/// The counterpart [WITNESSED_V1] points to: there the subject is the referenced
/// credential's issuer, here it is its **subject** — `credentialSubject.id` MUST be the
/// `credentialSubject.id` of the credential the digest names. `taskContext` and
/// `taskDigestMultibase` are REQUIRED; `issuerScope` is `directed` at minimum.
pub const PRESENTED_V1: &str = "https://registry.trustoverip.org/dtg/vsc/presented/1";

/// Which of the three `object` members a statement carries.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum ObjectKind {
    /// `object.id` — a DID or other IRI, when the object is a party or a named thing.
    Id,
    /// `object.digestMultibase` — when the object is another credential.
    DigestMultibase,
    /// `object.value` — a literal or structured payload whose schema the profile states.
    Value,
}

impl std::fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ObjectKind::Id => "id",
            ObjectKind::DigestMultibase => "digestMultibase",
            ObjectKind::Value => "value",
        })
    }
}

/// What a statement says about its subject: **exactly one** of `id`, `digestMultibase` or
/// `value`.
///
/// An object carrying two of them, or none, or any other member, is refused at parse.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum StatementObject {
    /// A DID or other IRI naming a party or a thing.
    Id(String),

    /// The digest of another credential, as [crate::digest_multibase_json] computes it
    /// over that credential excluding its top-level `proof`.
    DigestMultibase(String),

    /// A literal or structured payload. Any JSON, including `null`.
    ///
    /// Defined in the DTG context as `@json`, so it is an opaque JSON literal canonicalized
    /// by JCS rather than a nested graph.
    Value(Value),
}

impl StatementObject {
    /// Which of the three members this is.
    pub fn kind(&self) -> ObjectKind {
        match self {
            StatementObject::Id(_) => ObjectKind::Id,
            StatementObject::DigestMultibase(_) => ObjectKind::DigestMultibase,
            StatementObject::Value(_) => ObjectKind::Value,
        }
    }

    /// `object.id`, if that is what this is.
    pub fn id(&self) -> Option<&str> {
        match self {
            StatementObject::Id(id) => Some(id),
            _ => None,
        }
    }

    /// `object.digestMultibase`, if that is what this is.
    pub fn digest_multibase(&self) -> Option<&str> {
        match self {
            StatementObject::DigestMultibase(digest) => Some(digest),
            _ => None,
        }
    }

    /// `object.value`, if that is what this is.
    pub fn value(&self) -> Option<&Value> {
        match self {
            StatementObject::Value(value) => Some(value),
            _ => None,
        }
    }
}

/// Verifiable Statement Credential subject.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubjectStatement {
    /// DID of the node the statement is about.
    pub id: String,

    /// The absolute IRI fixing the statement's meaning. See [check_predicate_iri].
    pub predicate: String,

    /// What the statement says about the subject.
    pub object: StatementObject,

    /// Context of the witnessing event — the OPTIONAL additional member of [WITNESSED_V1].
    ///
    /// Modelled because the v1 context defines it and the core profile names it. Carried
    /// through a round trip on any statement, and meaningful under `witnessed/1` only.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub witness_context: Option<WitnessContext>,

    /// Members a profile adds that this library does not model, preserved verbatim.
    ///
    /// A verifier MUST ignore additional members a profile does not define, so that a
    /// profile can add optional ones without invalidating credentials for older verifiers.
    /// They are kept rather than dropped so that a digest over a parsed statement agrees
    /// with the one over its wire form.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// The machine-checkable constraints of one predicate profile.
///
/// The four core profiles are [PredicateProfile::core]. A community profile is expressed
/// through [crate::PredicateAcceptList], whose registry entries carry the same constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PredicateProfile {
    /// The predicate IRI.
    pub iri: &'static str,
    /// The `object` kinds the profile permits.
    pub object_kinds: &'static [ObjectKind],
    /// Whether `taskContext` — and with it `taskDigestMultibase` — is REQUIRED.
    pub task_context_required: bool,
    /// The narrowest `issuerScope` the issuer can truthfully declare, if the profile sets
    /// one.
    pub minimum_issuer_scope: Option<IssuerScope>,
}

const CORE_PROFILES: [PredicateProfile; 4] = [
    PredicateProfile {
        iri: ENDORSES_V1,
        object_kinds: &[ObjectKind::Value],
        task_context_required: false,
        minimum_issuer_scope: None,
    },
    PredicateProfile {
        iri: WITNESSED_V1,
        object_kinds: &[ObjectKind::DigestMultibase],
        task_context_required: true,
        minimum_issuer_scope: Some(IssuerScope::Directed),
    },
    PredicateProfile {
        iri: VETTED_V1,
        object_kinds: &[ObjectKind::Value],
        task_context_required: true,
        minimum_issuer_scope: Some(IssuerScope::Directed),
    },
    PredicateProfile {
        iri: PRESENTED_V1,
        object_kinds: &[ObjectKind::DigestMultibase],
        task_context_required: true,
        minimum_issuer_scope: Some(IssuerScope::Directed),
    },
];

impl PredicateProfile {
    /// The core profile for `iri` — [ENDORSES_V1], [WITNESSED_V1], [VETTED_V1] or
    /// [PRESENTED_V1] — matched byte for byte.
    pub fn core(iri: &str) -> Option<&'static PredicateProfile> {
        CORE_PROFILES.iter().find(|profile| profile.iri == iri)
    }

    /// Every core profile this library implements.
    pub fn all_core() -> &'static [PredicateProfile] {
        &CORE_PROFILES
    }

    /// Checks a statement against this profile's constraints.
    ///
    /// Does not check the subject–object relationship, which needs the credential the
    /// object names: see [DTGCredential::witnesses_issuance_of] and
    /// [DTGCredential::witnesses_presentation_of].
    pub(crate) fn check(
        &self,
        common: &DTGCommon,
        subject: &CredentialSubjectStatement,
    ) -> Result<(), DTGCredentialError> {
        check_constraints(
            self.object_kinds,
            self.task_context_required,
            self.minimum_issuer_scope,
            common,
            subject,
        )
    }
}

/// The checks a profile or an accept-list entry applies, whichever holds them.
pub(crate) fn check_constraints(
    object_kinds: &[ObjectKind],
    task_context_required: bool,
    minimum_issuer_scope: Option<IssuerScope>,
    common: &DTGCommon,
    subject: &CredentialSubjectStatement,
) -> Result<(), DTGCredentialError> {
    let kind = subject.object.kind();
    if !object_kinds.contains(&kind) {
        return Err(DTGCredentialError::ProfileViolation(format!(
            "`{}` does not permit an `object.{kind}`",
            subject.predicate
        )));
    }
    if let Some(minimum) = minimum_issuer_scope
        && !common.issuer_scope.satisfies(minimum)
    {
        return Err(DTGCredentialError::IssuerScopeTooNarrow {
            declared: common.issuer_scope,
            minimum,
        });
    }
    if task_context_required {
        if common.task_context.is_none() {
            return Err(DTGCredentialError::MissingTaskContext);
        }
        if common.task_digest_multibase.is_none() {
            return Err(DTGCredentialError::MissingTaskDigest);
        }
    }
    Ok(())
}

/// The statement checks a parse and [DTGCredential::validate] both make: a well-formed
/// predicate and object, and the constraints of the predicate's core profile where it has
/// one.
pub(crate) fn check_statement(
    common: &DTGCommon,
    subject: &CredentialSubjectStatement,
) -> Result<(), DTGCredentialError> {
    check_predicate_iri(&subject.predicate)?;
    if let StatementObject::Id(id) = &subject.object
        && !has_iri_scheme(id)
    {
        return Err(DTGCredentialError::ProfileViolation(format!(
            "`object.id` `{id}` is not a DID or other absolute IRI"
        )));
    }
    match PredicateProfile::core(&subject.predicate) {
        Some(profile) => profile.check(common, subject),
        None => Ok(()),
    }
}

/// Does `s` begin with an RFC 3986 scheme — `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` —
/// followed by `:` and something?
fn has_iri_scheme(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && !rest.is_empty()
}

/// Checks that `predicate` is a well-formed predicate IRI: absolute, not a compact form,
/// and in Unicode Normalization Form C.
///
/// A verifier MUST reject a credential whose `predicate` is not an absolute IRI, and no
/// expansion is performed: a compact form is malformed, not unknown. This library applies
/// that at parse, at issue and when checking against an accept-list.
///
/// # Telling an IRI from a CURIE
///
/// `dtg:witnessed` is syntactically an absolute IRI with the scheme `dtg`, so syntax alone
/// cannot refuse it. The rule applied is structural: the IRI must be hierarchical with an
/// authority (`scheme://authority…`), or use one of the two non-hierarchical schemes a
/// predicate plausibly lives under, `urn:` and `did:`. A predicate MUST resolve to its
/// definition, so this admits every predicate a registry or a community can publish, and
/// refuses every `prefix:term` a JSON-LD context would have to expand.
///
/// # Normalization
///
/// Comparison is on the IRI as written, so two predicates that render identically but
/// differ as byte strings are two predicates. An IRI that is not in NFC could never match
/// its canonical spelling, and is refused rather than normalized.
///
/// # Errors
///
/// [DTGCredentialError::InvalidPredicate], naming what was wrong.
pub fn check_predicate_iri(predicate: &str) -> Result<(), DTGCredentialError> {
    let invalid = |why: &str| {
        Err(DTGCredentialError::InvalidPredicate(format!(
            "`{predicate}` {why}"
        )))
    };

    if !unicode_normalization::is_nfc(predicate) {
        return invalid("is not in Unicode Normalization Form C");
    }
    if let Some(c) = predicate
        .chars()
        .find(|c| c.is_whitespace() || c.is_control() || "<>\"{}|\\^`".contains(*c))
    {
        return invalid(&format!("contains {c:?}, which an IRI cannot"));
    }
    if !has_iri_scheme(predicate) {
        return invalid(
            "is not an absolute IRI — a relative reference or a bare JSON-LD term is never \
             expanded",
        );
    }

    let (scheme, rest) = predicate.split_once(':').expect("has a scheme");
    let hierarchical = rest
        .strip_prefix("//")
        .is_some_and(|authority| !authority.is_empty() && !authority.starts_with('/'));
    let opaque_scheme = scheme.eq_ignore_ascii_case("urn") || scheme.eq_ignore_ascii_case("did");
    if !hierarchical && !opaque_scheme {
        return invalid(
            "is a compact IRI (CURIE); a predicate is always written as the absolute IRI \
             and is never expanded against a context",
        );
    }
    Ok(())
}

impl DTGCredential {
    /// Creates a Verifiable Statement Credential (VSC) under any predicate.
    ///
    /// - `issuer` / `issuer_scope`: the party making the statement, and the correlation
    ///   scope it declares for that identifier.
    /// - `subject`: the DID of the node the statement is about.
    /// - `predicate`: the absolute IRI fixing the statement's meaning — one of the core
    ///   constants ([ENDORSES_V1], [WITNESSED_V1], [VETTED_V1], [PRESENTED_V1]) or a
    ///   predicate a community defines in a namespace it controls.
    /// - `object`: exactly one of `id`, `digestMultibase` or `value`.
    ///
    /// Prefer the profile constructors for the core predicates — [Self::new_endorses_vsc],
    /// [Self::new_witnessed_vsc], [Self::new_vetted_vsc], [Self::new_presented_vsc] — which
    /// set the citation a profile requires and enforce its subject–object rule. This one
    /// checks what it can without them: the predicate, the `object` kind and the minimum
    /// `issuerScope` of a core profile. A profile that REQUIRES `taskContext` is completed
    /// with [DTGCredential::with_task_citation], and [DTGCredential::validate] — so also
    /// [DTGCredential::sign] — refuses it until it is.
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::InvalidPredicate] for a predicate that is not an absolute NFC
    /// IRI, [DTGCredentialError::ProfileViolation] for an `object` a core profile does not
    /// permit, [DTGCredentialError::IssuerScopeTooNarrow] for a scope below a core
    /// profile's minimum, [DTGCredentialError::InvalidValidityWindow] for a window that
    /// closes before it opens, and [DTGCredentialError::JsonTooDeep] for an `object.value`
    /// nested past [crate::MAX_JSON_DEPTH].
    pub fn new_vsc(
        issuer: String,
        issuer_scope: IssuerScope,
        subject: String,
        predicate: impl Into<String>,
        object: StatementObject,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<Self, DTGCredentialError> {
        check_window(valid_from, valid_until)?;
        let predicate = predicate.into();
        check_predicate_iri(&predicate)?;

        let vsc = Self::build(
            DTGCredentialType::Statement,
            issuer,
            issuer_scope,
            valid_from,
            valid_until,
            CredentialSubject::Statement(CredentialSubjectStatement {
                id: subject,
                predicate,
                object,
                witness_context: None,
                extra: serde_json::Map::new(),
            }),
        );
        vsc.credential.check_depth()?;

        // Everything but the citation, which a caller adds afterwards. The profile check
        // proper runs again in `validate`, once the citation is there to check.
        let statement = vsc.statement().expect("built as a statement");
        check_statement_before_citation(&vsc.credential, statement)?;
        Ok(vsc)
    }

    /// Creates a VEC — a statement under [ENDORSES_V1] — endorsing `subject` with
    /// `endorsement` as `object.value`.
    ///
    /// The endorsement's schema is the governing community's vocabulary, and nothing about
    /// it is checked but its depth. A VEC says only that its issuer said this: a verifier
    /// must establish that the issuer is one whose endorsements it accepts for this purpose
    /// before relying on any member of it.
    ///
    /// Not a role grant. A role *confers* something, and conferring is a VAC's job: see
    /// [DTGCredential::new_community_role_vac].
    ///
    /// # Errors
    ///
    /// As [DTGCredential::new_vsc].
    pub fn new_endorses_vsc(
        issuer: String,
        issuer_scope: IssuerScope,
        subject: String,
        endorsement: Value,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<Self, DTGCredentialError> {
        Self::new_vsc(
            issuer,
            issuer_scope,
            subject,
            ENDORSES_V1,
            StatementObject::Value(endorsement),
            valid_from,
            valid_until,
        )
    }

    /// Creates a VWC — a statement under [WITNESSED_V1] — attesting that the witness
    /// observed a party issue `witnessed`, in the `witness/session` that `session` opened.
    ///
    /// Both halves of every binding are read from the documents themselves, so none of
    /// them can disagree:
    ///
    /// - `credentialSubject.id` is `witnessed`'s `issuer` — the profile's subject–object
    ///   rule: the witness observed the subject *issue* it. One VWC per direction, so a
    ///   witnessed VRC pair takes two calls, one with each VRC.
    /// - `object.digestMultibase` is the digest of `witnessed` in its wire form, top-level
    ///   `proof` excluded, as [crate::digest_multibase_json] computes it.
    /// - `taskContext` is the `id` of `session`, and `taskDigestMultibase` its task digest
    ///   (`witness/session/submit` Conformance, item 1).
    ///
    /// `issuer` is the witness — a member, or a VTA acting under VTC policy — and must
    /// declare at least `directed`: a witness's identifier must be recognizable to both
    /// parties and to the community, so `pairwise` cannot describe it truthfully.
    ///
    /// # Errors
    ///
    /// - [DTGCredentialError::IssuerScopeTooNarrow] for `pairwise`.
    /// - [DTGCredentialError::ProfileViolation] if `witnessed` is not a JSON object with an
    ///   `issuer`.
    /// - [DTGCredentialError::MalformedTaskDocument] if `session` is not an object with a
    ///   string `id`; [DTGCredentialError::NotAWitnessSession] if its `type` is not a
    ///   `witness/session` version or its `threadId` is not its own `id` — which catches
    ///   citing the `submit` document, or the relationship exchange the session is nested
    ///   in.
    /// - [DTGCredentialError::InvalidValidityWindow] and [DTGCredentialError::JsonTooDeep].
    ///
    /// # Security
    ///
    /// Pass the session document the witness itself received and answered, not one the
    /// party supplies alongside its submission, and the edge credential the witness itself
    /// observed. The digests are load-bearing because the witness signs them.
    pub fn new_witnessed_vsc(
        issuer: String,
        issuer_scope: IssuerScope,
        witnessed: &Value,
        session: &Value,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        witness_context: Option<WitnessContext>,
    ) -> Result<Self, DTGCredentialError> {
        check_window(valid_from, valid_until)?;
        check_minimum_scope(WITNESSED_V1, issuer_scope)?;
        check_witness_session(session)?;
        crate::check_json_depth(witnessed)?;

        let subject = witnessed.as_object().and_then(issuer_of).ok_or_else(|| {
            DTGCredentialError::ProfileViolation(
                "the witnessed credential has no `issuer`, so there is no party the \
                     witness observed issuing it"
                    .into(),
            )
        })?;

        let mut vwc = Self::new_vsc(
            issuer,
            issuer_scope,
            subject,
            WITNESSED_V1,
            StatementObject::DigestMultibase(crate::digest_multibase_json(witnessed)?),
            valid_from,
            valid_until,
        )?;
        if let Some(statement) = vwc.credential.statement_mut() {
            statement.witness_context = witness_context;
        }
        vwc.with_task_citation(session)
    }

    /// Creates a vetting statement — a statement under [VETTED_V1] — recording that the
    /// issuer checked `subject`'s claimed identity in the vetting exchange `session`
    /// opened.
    ///
    /// `vetting` is `object.value`. This library is generic about it: the payload's schema
    /// is the registry definition's, and a typed payload belongs with the code that fills
    /// it in. `session` is the initiating document of the vetting exchange;
    /// `taskContext` and `taskDigestMultibase` are both read from it.
    ///
    /// `issuer` is the vetter, issuing under the member identifier its VMC names, and must
    /// declare at least `directed`. Whether it was *eligible* to vet is a fact about the
    /// community, checked separately — a community-issued VAC is the credential that
    /// answers it (see [DTGCredential::new_community_role_vac]).
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::IssuerScopeTooNarrow] for `pairwise`,
    /// [DTGCredentialError::MalformedTaskDocument] if `session` has no string `id`, and the
    /// errors of [DTGCredential::new_vsc].
    pub fn new_vetted_vsc(
        issuer: String,
        issuer_scope: IssuerScope,
        subject: String,
        vetting: Value,
        session: &Value,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<Self, DTGCredentialError> {
        check_window(valid_from, valid_until)?;
        check_minimum_scope(VETTED_V1, issuer_scope)?;

        Self::new_vsc(
            issuer,
            issuer_scope,
            subject,
            VETTED_V1,
            StatementObject::Value(vetting),
            valid_from,
            valid_until,
        )?
        .with_task_citation(session)
    }

    /// Creates a statement under [PRESENTED_V1], attesting that the issuer observed a
    /// party present `presented` in the exchange `session` opened.
    ///
    /// As for [DTGCredential::new_witnessed_vsc], both halves of each binding are read
    /// from the documents: `credentialSubject.id` is `presented`'s own
    /// `credentialSubject.id` — the party who holds it, and the profile's subject–object
    /// rule — `object.digestMultibase` its digest, and the citation `session`'s `id` and
    /// task digest.
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::IssuerScopeTooNarrow] for `pairwise`,
    /// [DTGCredentialError::ProfileViolation] if `presented` has no `credentialSubject.id`,
    /// [DTGCredentialError::MalformedTaskDocument] if `session` has no string `id`, and the
    /// errors of [DTGCredential::new_vsc].
    pub fn new_presented_vsc(
        issuer: String,
        issuer_scope: IssuerScope,
        presented: &Value,
        session: &Value,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<Self, DTGCredentialError> {
        check_window(valid_from, valid_until)?;
        check_minimum_scope(PRESENTED_V1, issuer_scope)?;
        crate::check_json_depth(presented)?;

        let subject = subject_of(presented).ok_or_else(|| {
            DTGCredentialError::ProfileViolation(
                "the presented credential has no `credentialSubject.id`, so there is no \
                 holder to name"
                    .into(),
            )
        })?;

        Self::new_vsc(
            issuer,
            issuer_scope,
            subject,
            PRESENTED_V1,
            StatementObject::DigestMultibase(crate::digest_multibase_json(presented)?),
            valid_from,
            valid_until,
        )?
        .with_task_citation(session)
    }

    /// Is this a [WITNESSED_V1] statement about `credential` — the edge credential in its
    /// wire form — and does the profile's subject–object rule hold?
    ///
    /// True when the predicate is `witnessed/1`, `object.digestMultibase` matches
    /// `credential`'s recomputed digest (decoded bytes, not strings), and
    /// `credentialSubject.id` is `credential`'s `issuer`. A verifier holding the referenced
    /// credential MUST check both, and this is those two checks.
    ///
    /// # What this does not check
    ///
    /// The statement's proof, its window, whether its issuer is a witness the verifier
    /// trusts, its `taskContext` against the session (see [DTGCredential::cites_task]), and
    /// whether `credential` is itself valid: a witness attestation is about claims at the
    /// moment of witnessing, not about their being current.
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::InvalidDigest] or [DTGCredentialError::UnsupportedDigestAlgorithm]
    /// if the carried digest cannot be read, rather than `Ok(false)`.
    pub fn witnesses_issuance_of(&self, credential: &Value) -> Result<bool, DTGCredentialError> {
        let named = credential.as_object().and_then(issuer_of);
        self.statement_names(WITNESSED_V1, credential, named)
    }

    /// Is this a [PRESENTED_V1] statement about `credential` in its wire form, with
    /// `credentialSubject.id` equal to `credential`'s own `credentialSubject.id`?
    ///
    /// The [PRESENTED_V1] counterpart of [DTGCredential::witnesses_issuance_of], with the
    /// same caveats.
    pub fn witnesses_presentation_of(
        &self,
        credential: &Value,
    ) -> Result<bool, DTGCredentialError> {
        self.statement_names(PRESENTED_V1, credential, subject_of(credential))
    }

    /// The shared half of the two subject–object checks: the predicate, the digest, and
    /// the party the statement is about.
    fn statement_names(
        &self,
        predicate: &str,
        credential: &Value,
        expected_subject: Option<String>,
    ) -> Result<bool, DTGCredentialError> {
        let Some(statement) = self.statement() else {
            return Ok(false);
        };
        let Some(carried) = statement.object.digest_multibase() else {
            return Ok(false);
        };
        if statement.predicate != predicate
            || expected_subject.as_deref() != Some(statement.id.as_str())
        {
            return Ok(false);
        }
        crate::digests_match(carried, &crate::digest_multibase_json(credential)?)
    }
}

/// The checks [DTGCredential::new_vsc] can make before a citation is attached: every
/// profile constraint but `taskContext`.
fn check_statement_before_citation(
    common: &DTGCommon,
    subject: &CredentialSubjectStatement,
) -> Result<(), DTGCredentialError> {
    check_predicate_iri(&subject.predicate)?;
    match PredicateProfile::core(&subject.predicate) {
        Some(profile) => check_constraints(
            profile.object_kinds,
            false,
            profile.minimum_issuer_scope,
            common,
            subject,
        ),
        None => Ok(()),
    }
}

/// Refuses an `issuer_scope` narrower than the core profile of `predicate` permits, before
/// any document is read.
fn check_minimum_scope(
    predicate: &str,
    issuer_scope: IssuerScope,
) -> Result<(), DTGCredentialError> {
    match PredicateProfile::core(predicate).and_then(|p| p.minimum_issuer_scope) {
        Some(minimum) if !issuer_scope.satisfies(minimum) => {
            Err(DTGCredentialError::IssuerScopeTooNarrow {
                declared: issuer_scope,
                minimum,
            })
        }
        _ => Ok(()),
    }
}

/// `credentialSubject.id` of a credential in its wire form.
fn subject_of(credential: &Value) -> Option<String> {
    credential
        .get("credentialSubject")
        .and_then(|subject| subject.get("id"))
        .and_then(Value::as_str)
        .map(str::to_string)
}
