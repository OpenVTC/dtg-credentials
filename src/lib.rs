/*! Decentralized Trust Graph (DTG) Credentials
*/

use affinidi_data_integrity::DataIntegrityProof;
#[cfg(feature = "affinidi-signing")]
use affinidi_data_integrity::{DataIntegrityError, SignOptions, VerifyOptions};
#[cfg(feature = "affinidi-signing")]
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Utc};
use multibase::Base;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Display;
use std::str::FromStr;
use thiserror::Error;

pub mod accept;
pub mod authority;
pub mod create;
pub mod delegation;
pub mod statement;

pub use accept::{
    AcceptListEntry, AdditionalMember, PredicateAcceptList, PredicateStatus, RegistryAcceptList,
};
pub use statement::{
    CredentialSubjectStatement, ENDORSES_V1, ObjectKind, PRESENTED_V1, PredicateProfile,
    StatementObject, VETTED_V1, WITNESSED_V1, check_predicate_iri,
};

/// The W3C VC Data Model 2.0 context, which a DTG credential lists **first**.
pub const W3C_VC_V2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";

/// The W3C VC Data Model 1.1 context, accepted in first position under DTG Core Credentials
/// §Legacy System Compatibility. This library never emits it.
pub const W3C_VC_V1_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";

/// The frozen DTG credential context, version 1, which a DTG credential lists **second**.
///
/// Published by the DTG VSC Predicate Registry as one byte-frozen document, and compared as
/// an exact string: scheme `https`, host `registry.trustoverip.org` with no `www.`, no
/// trailing slash. Every term this library emits is defined either here or in
/// [W3C_VC_V2_CONTEXT].
///
/// # No other DTG context is recognized
///
/// Credentials issued before the Implementers Draft of DTG Core Credentials are not
/// conformant to it, whatever context they list, and contexts published before `v1` under
/// other IRIs — `https://firstperson.network/credentials/dtg/v1` among them — are not
/// recognized. A credential listing one is refused at parse rather than aliased.
pub const DTG_CONTEXT_V1: &str = "https://registry.trustoverip.org/dtg/context/v1";

/// The correlation scope an issuer declares for its own identifier, carried as the
/// REQUIRED top-level `issuerScope` of every DTG credential (DTG Core Credentials
/// §Correlation Scope).
///
/// # Ordered, narrowest first
///
/// `pairwise < directed < public`, and the derived [Ord] follows it. Where a profile or a
/// credential type states a minimum, a declaration narrower than that minimum does not
/// satisfy it: see [IssuerScope::satisfies].
///
/// # A declaration about the issuer only
///
/// A credential declares the scope of the identifier in `issuer` and of nothing else — not
/// its subject's, not its counterparty's. A verifier that needs the counterparty's scope
/// reads it from a credential the counterparty issued.
///
/// Serialized exactly as `pairwise`, `directed` or `public`, and parsed case-sensitively:
/// `"Public"` is not a declaration, and a credential carrying it is refused.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum IssuerScope {
    /// Known to exactly one counterparty; correlation confined to this one relationship.
    Pairwise,

    /// Known to a set of counterparties the holder chooses, and no further.
    Directed,

    /// Unbounded; ordinarily published so that it can be found.
    Public,
}

impl IssuerScope {
    /// The wire value: `pairwise`, `directed` or `public`.
    pub fn as_str(&self) -> &'static str {
        match self {
            IssuerScope::Pairwise => "pairwise",
            IssuerScope::Directed => "directed",
            IssuerScope::Public => "public",
        }
    }

    /// Does this declaration meet `minimum`? True when it is at least as wide.
    pub fn satisfies(&self, minimum: IssuerScope) -> bool {
        *self >= minimum
    }
}

impl Display for IssuerScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IssuerScope {
    type Err = DTGCredentialError;

    /// Parses the wire value, case-sensitively.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pairwise" => Ok(IssuerScope::Pairwise),
            "directed" => Ok(IssuerScope::Directed),
            "public" => Ok(IssuerScope::Public),
            other => Err(DTGCredentialError::MalformedCredential(format!(
                "`{other}` is not an issuerScope; expected `pairwise`, `directed` or `public`"
            ))),
        }
    }
}

/// What W3C VC Format is the credential using?
#[derive(Clone, Copy, Debug)]
pub enum W3CVCVersion {
    /// <https://www.w3.org/2018/credentials/v1>
    V1_1,

    /// <https://www.w3.org/ns/credentials/v2>
    V2_0,
}

impl TryFrom<&[String]> for W3CVCVersion {
    type Error = DTGCredentialError;

    /// Will return the W3C Version from the context array
    fn try_from(types: &[String]) -> Result<Self, Self::Error> {
        if types.contains(&"https://www.w3.org/2018/credentials/v1".to_string()) {
            Ok(W3CVCVersion::V1_1)
        } else if types.contains(&"https://www.w3.org/ns/credentials/v2".to_string()) {
            Ok(W3CVCVersion::V2_0)
        } else {
            Err(DTGCredentialError::UnknownVCVersion)
        }
    }
}

/// Errors related to DTG Credentials
///
/// New variants may be added in minor releases; match with a wildcard arm.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DTGCredentialError {
    #[error("Unknown credential type")]
    UnknownCredential,

    #[cfg(feature = "affinidi-signing")]
    #[error("Data Integrity Error: {0}")]
    DataIntegrity(#[from] DataIntegrityError),

    #[error("Credential is not signed")]
    NotSigned,

    #[error("Unknown W3C VC Version")]
    UnknownVCVersion,

    /// An AuthorityCredential (VAC) carried an empty `actions` list.
    ///
    /// Emptiness is never a wildcard: a VAC conferring no actions confers nothing, and is
    /// rejected rather than treated as unrestricted.
    #[error("AuthorityCredential carries an empty actions list, which confers nothing")]
    EmptyAuthorityActions,

    /// [DTGCredential::attenuate] was called on a credential that is not a VAC.
    #[error("not an AuthorityCredential, so there is no authority to attenuate")]
    NotAnAuthorityCredential,

    /// [DTGCredential::attenuate] was called on a VAC with no `id`.
    ///
    /// No longer produced. Working Draft 02 makes `authority.parent` a **digest** of the
    /// parent rather than its `id`, precisely so that no credential needs a top-level
    /// identifier merely in order to be referenced.
    #[deprecated(
        since = "0.7.0",
        note = "Never returned. `authority.parent` is a digest as of Working Draft 02, so a \
                parent VAC no longer needs an `id` to be attenuated. This variant will be \
                removed in a future release."
    )]
    #[error("cannot attenuate a credential with no id — the derived VAC could not name it")]
    AttenuationParentHasNoId,

    /// A digest value was not a well-formed `digestMultibase`.
    ///
    /// Either the multibase envelope or the multihash inside it failed to decode. A
    /// `sha256:<hex>` value produced against Working Draft 01 lands here, which is the
    /// intended outcome: it is reported rather than silently compared as unequal.
    #[error("not a well-formed digestMultibase value: {0}")]
    InvalidDigest(String),

    /// A digest named a hash algorithm this library does not implement.
    ///
    /// The specification permits a governing party to require a stronger hash, and carries
    /// the algorithm in the value itself. A verifier MUST reject an algorithm it does not
    /// accept rather than treating it as a mismatch — hence a distinct error.
    #[error("digest uses multihash algorithm 0x{0:x}, which this library does not accept")]
    UnsupportedDigestAlgorithm(u64),

    /// A DelegationCredential (VDC) was not a well-formed grant or acceptance.
    #[error("malformed DelegationCredential: {0}")]
    MalformedDelegation(String),

    /// A delegation acknowledgement was built against something that is not a
    /// delegation grant.
    #[error("Not a delegation grant: {0}")]
    NotADelegationGrant(String),

    /// An attenuation attempted to confer more than its parent held.
    #[error("attenuation would widen the parent grant: {0}")]
    AttenuationWidens(String),

    /// A StatementCredential under a profile that REQUIRES `taskContext` — `witnessed/1`,
    /// `vetted/1`, `presented/1`, or an accept-list entry saying so — carries none.
    #[error("the statement's predicate profile requires taskContext, and it has none")]
    MissingTaskContext,

    /// A credential that REQUIRES `taskContext` carries it without `taskDigestMultibase`,
    /// which DTG Core Credentials makes REQUIRED wherever `taskContext` is.
    #[error("taskContext is required here, and so is taskDigestMultibase, which is absent")]
    MissingTaskDigest,

    /// `@context` does not list the W3C VC context first and [DTG_CONTEXT_V1] second.
    #[error("malformed @context: {0}")]
    InvalidContext(String),

    /// `type` is not `VerifiableCredential`, `DTGCredential` and exactly one concrete
    /// subtype (with `PersonhoodCredential` permitted as a hint on a VMC only), or names a
    /// subtype this specification has retired.
    #[error("malformed type: {0}")]
    InvalidType(String),

    /// `issuerScope` is narrower than the credential type or predicate profile permits.
    ///
    /// A community-issued VMC can only truthfully declare `public`; `witnessed/1`,
    /// `vetted/1` and `presented/1` require `directed` at minimum.
    #[error("issuerScope `{declared}` is narrower than the required minimum `{minimum}`")]
    IssuerScopeTooNarrow {
        declared: IssuerScope,
        minimum: IssuerScope,
    },

    /// A VSC `predicate` is not an absolute IRI in Unicode Normalization Form C.
    ///
    /// A compact form (a CURIE such as `dtg:witnessed`, or a bare JSON-LD term) is
    /// malformed rather than unknown: no expansion is ever performed.
    #[error("invalid predicate: {0}")]
    InvalidPredicate(String),

    /// A VSC does not meet a constraint of its predicate's profile: an `object` kind the
    /// profile does not permit, a REQUIRED member missing, or a subject–object relationship
    /// that does not hold.
    #[error("the statement does not meet its predicate profile: {0}")]
    ProfileViolation(String),

    /// A verifier's accept-list does not contain the statement's predicate.
    ///
    /// Rejection is the only conforming outcome for an unrecognized predicate: it is not
    /// processed as a generic statement, and no published equivalence is followed.
    #[error("predicate `{0}` is not accepted by this verifier")]
    PredicateNotAccepted(String),

    /// A registry accept-list document could not be read.
    #[error("malformed accept-list: {0}")]
    MalformedAcceptList(String),

    /// A document a credential was to cite as its `taskContext` is not a Trust Task
    /// document that can be named: it is not a JSON object, or it has no string `id`.
    #[error("cannot cite this document as a taskContext: {0}")]
    MalformedTaskDocument(String),

    /// [DTGCredential::new_witnessed_vsc] was given something other than the
    /// `witness/session` document that opened the witness session.
    ///
    /// A VWC names the *innermost* exchange that attests the witnessing (Trust Tasks
    /// §4.9.1): the party's own `witness/session`, not the `witness/session/submit`
    /// exchanged on its thread and not the relationship exchange that contains it.
    #[error("not the witness/session document that opened the session: {0}")]
    NotAWitnessSession(String),

    /// The credential could not be canonicalized (JCS, RFC 8785) for digesting
    #[error("Could not canonicalize credential: {0}")]
    Canonicalization(String),

    /// A credential was not of the type an operation requires
    #[error("Expected a {expected}, got a {got}")]
    WrongCredentialType { expected: String, got: String },

    /// A membership acknowledgement was built against something that is not a
    /// community-issued membership grant
    #[error("Not a community-issued membership grant: {0}")]
    NotAMembershipGrant(String),

    /// A credential's `validUntil` is not after its `validFrom`.
    ///
    /// A window that closes before, or at the instant, it opens describes a credential
    /// that is never valid. It is refused where a credential is built or signed rather than
    /// left for every verifier to notice. A `validFrom` in the past is not refused:
    /// backdating is how a re-issued credential keeps the date the original took effect.
    ///
    /// Compared at whole seconds, the precision the wire form carries.
    #[error("validUntil {valid_until} is not after validFrom {valid_from}")]
    InvalidValidityWindow {
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    },

    /// A JSON document was nested more deeply than [`MAX_JSON_DEPTH`] allows.
    ///
    /// Digesting, signing and verifying all walk a credential recursively, so a value deep
    /// enough exhausts the stack and aborts the process. It is refused before any of that
    /// work starts.
    #[error("JSON is nested more than {max} levels deep")]
    JsonTooDeep { max: usize },

    /// A grant names a different party as its subject from the one answering it.
    ///
    /// Returned by [DTGCredential::new_member_vmc_for] and
    /// [DTGCredential::new_delegate_vdc_for]. A party answers a grant for itself, so a grant
    /// naming anyone else is refused rather than answered in that party's name.
    #[error("the grant names `{found}` as its subject, not `{expected}`")]
    NotTheGrantSubject { expected: String, found: String },

    /// An acknowledgement or acceptance would remain valid after the grant it answers.
    ///
    /// `valid_until` is `None` where the answer was open-ended against a grant that expires.
    #[error("would remain valid after the grant it answers, which expires at {grant_valid_until}")]
    OutlivesGrant {
        valid_until: Option<DateTime<Utc>>,
        grant_valid_until: DateTime<Utc>,
    },

    /// A proof verified, but was made with a verification method that does not belong to
    /// the credential's issuer.
    #[error("the proof was made by `{verification_method}`, which is not the issuer `{issuer}`")]
    ProofNotFromIssuer {
        issuer: String,
        verification_method: String,
    },

    /// A credential was not in force at the instant it was checked against.
    #[error("the credential is not valid at {at}")]
    NotValidAt { at: DateTime<Utc> },

    /// A credential in its wire form lacks a member it needs, or carries one that cannot be
    /// read.
    #[error("malformed credential: {0}")]
    MalformedCredential(String),
}

/// Defined DTG Credentials
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(try_from = "Value")]
pub struct DTGCredential {
    /// The DTG Credential inner struct
    #[serde(flatten)]
    credential: DTGCommon,

    /// Type of the credential
    #[serde(skip)]
    type_: DTGCredentialType,

    /// W3C VC Version
    #[serde(skip)]
    version: W3CVCVersion,
}

impl DTGCredential {
    /// get the raw credential
    pub fn credential(&self) -> &DTGCommon {
        &self.credential
    }

    /// Get the raw credential as mutable
    pub fn credential_mut(&mut self) -> &mut DTGCommon {
        &mut self.credential
    }

    /// Has this credential been signed?
    pub fn signed(&self) -> bool {
        self.credential.signed()
    }

    /// get the credential type
    pub fn type_(&self) -> DTGCredentialType {
        self.type_.clone()
    }

    /// This credential's own identifier, if it has one.
    ///
    /// `None` for a credential built by one of the `new_*` constructors and never given one
    /// with [DTGCredential::with_id]. See [DTGCommon::id] for why a counterparty may require
    /// it.
    pub fn id(&self) -> Option<&str> {
        self.credential.id()
    }

    /// Returns the Issuer DID
    pub fn issuer(&self) -> &str {
        self.credential.issuer()
    }

    /// The correlation scope the issuer declares for its own identifier. See [IssuerScope].
    pub fn issuer_scope(&self) -> IssuerScope {
        self.credential.issuer_scope
    }

    /// The statement, when this credential is a VSC. See [DTGCommon::statement].
    pub fn statement(&self) -> Option<&CredentialSubjectStatement> {
        self.credential.statement()
    }

    /// The `predicate` IRI, when this credential is a VSC.
    ///
    /// Compare it byte for byte — [PredicateAcceptList] does — and never by spelling,
    /// prefix or a published equivalence.
    pub fn predicate(&self) -> Option<&str> {
        self.statement().map(|s| s.predicate.as_str())
    }

    /// Returns the Subject DID
    pub fn subject(&self) -> &str {
        self.credential.subject()
    }

    /// Returns the valid_from timestamp
    pub fn valid_from(&self) -> DateTime<Utc> {
        self.credential.valid_from()
    }

    /// Returns the valid until timestamp
    pub fn valid_until(&self) -> Option<DateTime<Utc>> {
        self.credential.valid_until()
    }

    /// The `id` naming the trust task exchange this credential cites, if set. See
    /// [DTGCommon::task_context].
    ///
    /// This is always `Some` for a VSC under a predicate profile that makes `taskContext`
    /// REQUIRED — [WITNESSED_V1], [VETTED_V1] and [PRESENTED_V1].
    pub fn task_context(&self) -> Option<&str> {
        self.credential.task_context()
    }

    /// The task digest of the Trust Task document `taskContext` names, if set. See
    /// [DTGCommon::task_digest_multibase].
    pub fn task_digest_multibase(&self) -> Option<&str> {
        self.credential.task_digest_multibase()
    }

    /// Does this credential cite `document` — the Trust Task document its `taskContext`
    /// names — and is it bound to that document's content?
    ///
    /// Both halves of the citation have to hold:
    ///
    /// 1. `taskContext` equals the document's `id`, which **locates** the exchange;
    /// 2. `taskDigestMultibase` matches the task digest recomputed from `document`, which
    ///    **binds** the credential to it.
    ///
    /// Returns `Ok(false)` where either fails, and where the credential carries no
    /// `taskContext` or no `taskDigestMultibase`. The last case is deliberate: Trust Tasks
    /// §4.9.3 forbids falling back to comparing `id`s alone, because an `id` is a name
    /// anyone may reuse on a counterfeit.
    ///
    /// # Compares bytes, not strings
    ///
    /// The digest is recomputed with the top-level `proof` removed, so a signed and an
    /// unsigned copy of the same document agree, and compared as **decoded multihash bytes**.
    /// A task digest may be base58btc or base64url: two conforming encodings of one digest
    /// are different strings, and a string comparison would reject an honest citation.
    ///
    /// # What this does not check
    ///
    /// That the exchange completed, which needs the outcome evidence of DTG Core
    /// Credentials §Outcome Interpretability, and that the document was attributable, which
    /// needs its own proof. A task digest attests content, not authenticity. It is
    /// load-bearing because it is the credential's issuer who signed it.
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::InvalidDigest] if the carried value is not a well-formed
    /// multibase multihash, and [DTGCredentialError::UnsupportedDigestAlgorithm] if it
    /// names a hash this library does not implement. Trust Tasks §4.9.3 requires such a
    /// citation to be treated as unverified, never recomputed under another algorithm, so
    /// it is reported rather than folded into `Ok(false)`. [DTGCredentialError::JsonTooDeep]
    /// if `document` is nested past [`MAX_JSON_DEPTH`].
    pub fn cites_task(&self, document: &Value) -> Result<bool, DTGCredentialError> {
        let (Some(task_context), Some(carried)) =
            (self.task_context(), self.task_digest_multibase())
        else {
            return Ok(false);
        };

        if document.get("id").and_then(Value::as_str) != Some(task_context) {
            return Ok(false);
        }

        digests_match(carried, &task_digest_multibase_json(document)?)
    }

    /// This credential's digest, in the encoding a credential that references it carries —
    /// a member-issued VMC acknowledging a membership grant, a VSC whose `object` names it
    /// (a VWC attesting an edge credential), or the `parent` of an attenuated VAC.
    ///
    /// Per DTG Core Credentials [Digest Encoding], that is the SHA-256 hash of the
    /// credential's JSON representation **excluding its top-level `proof` member**,
    /// canonicalized with the JSON Canonicalization Scheme
    /// ([JCS, RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785)), wrapped in a
    /// `sha2-256` multihash and encoded base58btc with a multibase `z` prefix.
    ///
    /// [Digest Encoding]: https://github.com/trustoverip/dtgwg-cred-spec
    ///
    /// # Why `proof` is excluded
    ///
    /// The digest binds to what the credential *says*, not to a particular signature over
    /// it. A referencing credential therefore survives a re-proofing of its referent: a
    /// re-signed grant carrying identical claims still satisfies an acknowledgement made
    /// against the earlier signature. It also means the digest can be computed before the
    /// referent is signed, and is stable whichever of its proofs a holder happens to have.
    ///
    /// # Prefer the wire form for a credential you received
    ///
    /// This digests the model. [`DTGCommon::extra`] carries top-level members this library
    /// does not model through a round trip, so for most received credentials the two agree
    /// — but a member *inside* `credentialSubject` that the subject types do not model is
    /// still not represented. Where you still hold the bytes a counterparty sent, digest
    /// those with [`digest_multibase_json`].
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::JsonTooDeep] if an open JSON member takes the credential past
    /// [`MAX_JSON_DEPTH`], checked before the credential is cloned or serialized.
    pub fn digest_multibase(&self) -> Result<String, DTGCredentialError> {
        self.credential.check_depth()?;

        let unsigned = DTGCommon {
            proof: None,
            ..self.credential.clone()
        };
        let value = serde_json::to_value(&unsigned)
            .map_err(|e| DTGCredentialError::Canonicalization(e.to_string()))?;
        digest_multibase_json(&value)
    }

    /// This credential's digest in the superseded `sha256:<hex>` encoding.
    #[deprecated(
        since = "0.7.0",
        note = "Working Draft 02 replaced the `sha256:<hex>` digest with a base58btc \
                multibase multihash under the property name `digestMultibase`. Use \
                DTGCredential::digest_multibase. This method will be removed in a future \
                release."
    )]
    pub fn digest(&self) -> Result<String, DTGCredentialError> {
        self.credential.check_depth()?;

        let unsigned = DTGCommon {
            proof: None,
            ..self.credential.clone()
        };
        let value = serde_json::to_value(&unsigned)
            .map_err(|e| DTGCredentialError::Canonicalization(e.to_string()))?;
        #[allow(deprecated)]
        digest_json(&value)
    }

    /// The digest this credential carries of the credential it references, if it carries one.
    ///
    /// `Some` for a member-issued VMC (which MUST carry one), for a VSC whose `object` is a
    /// `digestMultibase` (a VWC bound to the edge credential it attests, among them), for an
    /// attenuated VAC (`authority.parent`), and for a derived or accepting VDC
    /// (`delegation.parent` / `delegation.accepts`). `None` for a community-issued VMC,
    /// which MUST omit it, and for a credential that references nothing.
    pub fn subject_digest(&self) -> Option<&str> {
        match &self.credential.credential_subject {
            CredentialSubject::Membership(subject) => subject.digest_multibase.as_deref(),
            CredentialSubject::Statement(subject) => subject.object.digest_multibase(),
            CredentialSubject::Authority(subject) => subject.authority.parent.as_deref(),
            CredentialSubject::Delegation(subject) => subject
                .delegation
                .accepts
                .as_deref()
                .or(subject.delegation.parent.as_deref()),
            _ => None,
        }
    }

    /// Checks that the digest this credential carries matches the credential it claims to
    /// reference.
    ///
    /// Answers one question only — whether the hashes agree. It does not check that the two
    /// credentials are of the types the reference requires, nor that their issuers and
    /// subjects line up. For a membership acknowledgement, [DTGCredential::acknowledges]
    /// checks all of that together and is what a verifier completing an edge should call.
    ///
    /// # Compares bytes, not strings
    ///
    /// The specification requires a verifier to decode the multibase envelope and the
    /// multihash inside it, and to compare the algorithm identifier and the raw digest —
    /// never the encoded strings. Two equal digests can be written differently, and a
    /// string comparison would report a mismatch where the credentials agree.
    ///
    /// Returns `Ok(false)` if the digests do not match, or if this credential carries no
    /// digest, in which case there is nothing to rely on.
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::InvalidDigest] if the carried value is not a well-formed
    /// `digestMultibase` — a Working Draft 01 `sha256:<hex>` value among them — and
    /// [DTGCredentialError::UnsupportedDigestAlgorithm] if it names a hash this library
    /// does not implement. Both are reported rather than folded into `Ok(false)`: a digest
    /// that cannot be read is not a digest that disagrees.
    pub fn verify_digest(&self, referenced: &DTGCredential) -> Result<bool, DTGCredentialError> {
        let Some(carried) = self.subject_digest() else {
            return Ok(false);
        };

        digests_match(carried, &referenced.digest_multibase()?)
    }

    /// Does this member-issued VMC acknowledge `grant`, completing that membership edge?
    ///
    /// A membership edge is complete only when both VMCs of the pair exist and are valid:
    /// the community-issued VMC that grants membership, and the member-issued VMC that
    /// acknowledges it. This checks everything that binds the two together:
    ///
    /// 1. `grant` is a `MembershipCredential` carrying no `digest` — a community-issued grant
    /// 2. `self` is a `MembershipCredential` carrying one — a member-issued acknowledgement
    /// 3. the two name the same pair of parties, in mirrored roles: this credential's issuer
    ///    is the grant's subject, and its subject is the grant's issuer
    /// 4. the `digest` matches the grant
    ///
    /// Returns `Ok(false)` where any of those does not hold, rather than distinguishing
    /// them: a caller deciding whether an edge is complete has one decision to make, and
    /// every failing case answers it the same way.
    ///
    /// # What this does not check
    ///
    /// Neither credential's proof, and neither validity window. Both are the caller's to
    /// verify — proof verification needs a resolver this crate does not hold, and whether a
    /// window is current is a question about an instant the caller chooses. An edge is
    /// complete when both VMCs are *valid* as well as bound, and this covers only the
    /// binding.
    ///
    /// # Security
    ///
    /// `Ok(true)` is binding evidence, not membership. A pair binds whether or not anybody
    /// signed either half: an acknowledgement can be built against a grant the community
    /// never issued, and this accepts the two together. Before treating an edge as complete,
    /// verify the grant's proof against the community's key and the acknowledgement's
    /// against the member's — each made by a verification method of that credential's
    /// issuer — and check both windows at the instant you care about.
    /// `verify_grant_with_public_key`, under the `affinidi-signing` feature, does that for
    /// the grant in its wire form.
    pub fn acknowledges(&self, grant: &DTGCredential) -> Result<bool, DTGCredentialError> {
        if !matches!(self.type_, DTGCredentialType::Membership)
            || !matches!(grant.type_, DTGCredentialType::Membership)
        {
            return Ok(false);
        }

        // The grant is the half that MUST omit `digest`; a credential carrying one is an
        // acknowledgement, and an acknowledgement of an acknowledgement is not an edge.
        if grant.subject_digest().is_some() {
            return Ok(false);
        }

        if self.issuer() != grant.subject() || self.subject() != grant.issuer() {
            return Ok(false);
        }

        self.verify_digest(grant)
    }

    /// Does this delegate-issued VDC accept `grant`, completing that delegation edge?
    ///
    /// A delegation edge is complete only when both VDCs exist and are valid: the
    /// delegator's grant, and the delegate's acceptance of it. This checks everything that
    /// binds the two together:
    ///
    /// 1. `grant` is a `DelegationCredential` carrying `scope` and no `accepts` — a grant
    /// 2. `self` is a `DelegationCredential` carrying `accepts` — an acceptance
    /// 3. the two name the same pair of parties in mirrored roles: this credential's issuer
    ///    is the grant's subject, and its subject is the grant's issuer
    /// 4. the `accepts` digest matches the grant
    ///
    /// Returns `Ok(false)` where any of those does not hold, rather than distinguishing
    /// them: a caller deciding whether an edge is complete has one decision to make, and
    /// every failing case answers it the same way.
    ///
    /// # What this does not check
    ///
    /// Neither credential's proof, neither validity window, and neither's revocation
    /// status. Nor does it establish that the *delegator* may perform the act in question
    /// — that is a separate question, asked of the delegator at the time of the act, which
    /// a VDC moves but never answers. This covers the binding.
    ///
    /// # Security
    ///
    /// As with [DTGCredential::acknowledges], `Ok(true)` is binding evidence only. Verify
    /// both proofs, each against a verification method of its own credential's issuer, and
    /// both windows, before accepting anybody as acting under the delegation.
    pub fn accepts(&self, grant: &DTGCredential) -> Result<bool, DTGCredentialError> {
        if !matches!(self.type_, DTGCredentialType::Delegation)
            || !matches!(grant.type_, DTGCredentialType::Delegation)
        {
            return Ok(false);
        }

        let (Some(acceptance), Some(appointment)) =
            (self.credential.delegation(), grant.credential.delegation())
        else {
            return Ok(false);
        };

        // The grant is the half carrying `scope` and no `accepts`; accepting an acceptance
        // is not an edge.
        if appointment.accepts.is_some() || appointment.scope.is_none() {
            return Ok(false);
        }
        let Some(carried) = &acceptance.accepts else {
            return Ok(false);
        };

        if self.issuer() != grant.subject() || self.subject() != grant.issuer() {
            return Ok(false);
        }

        digests_match(carried, &grant.digest_multibase()?)
    }

    /// Returns the proof value if signed else None
    pub fn proof_value(&self) -> Option<&str> {
        if let Some(proof) = &self.credential.proof {
            proof.proof_value.as_deref()
        } else {
            None
        }
    }

    /// Checks the invariants this library holds a credential to before putting a proof on
    /// it.
    ///
    /// - The validity window is well formed: `validUntil`, where present, is after
    ///   `validFrom` ([DTGCredentialError::InvalidValidityWindow]).
    /// - No open JSON member — a statement's `object.value`, `credentialStatus`, an
    ///   unmodelled member — takes the document past [`MAX_JSON_DEPTH`]
    ///   ([DTGCredentialError::JsonTooDeep]). The check does not recurse.
    /// - Everything a parse checks still holds: the `@context` and `type` arrays, the
    ///   subject's shape for the type, `issuerScope` where the type or profile constrains it,
    ///   a VSC's `predicate`, and the constraints of its core profile — `taskContext` and
    ///   `taskDigestMultibase` where [WITNESSED_V1], [VETTED_V1] or [PRESENTED_V1] require
    ///   them. [DTGCredential::credential_mut] can break any of these, and this is where a
    ///   broken credential is caught before it is signed.
    ///
    /// [DTGCredential::sign] calls this first, so this library never signs a credential
    /// that fails it, and [DTGCredential::verify_proof_with_public_key] calls it before
    /// examining a proof. The `new_*` constructors that return a plain `Self` have no way to
    /// refuse, so a credential built by one of them is checked here rather than there. If
    /// you sign with another backend, call this yourself before you do.
    ///
    /// A `validFrom` in the past is accepted. Backdating is legitimate — re-issuing a
    /// credential with the date the original took effect is the usual case — so only the
    /// ordering of the two ends is checked, never either end against the clock.
    pub fn validate(&self) -> Result<(), DTGCredentialError> {
        crate::create::check_window(self.valid_from(), self.valid_until())?;
        self.credential.check_depth()?;
        self.check_conformance()
    }

    /// The structural rules a parse enforces, re-run over the model.
    ///
    /// Shared by `TryFrom<DTGCommon>` and [DTGCredential::validate], so that a credential
    /// this library would refuse to parse is also one it refuses to sign.
    fn check_conformance(&self) -> Result<(), DTGCredentialError> {
        let c = &self.credential;
        check_context(&c.context)?;
        if check_type(&c.type_)? != self.type_ {
            return Err(DTGCredentialError::InvalidType(format!(
                "the type array no longer names a {}",
                self.type_
            )));
        }

        match (&self.type_, &c.credential_subject) {
            (DTGCredentialType::Membership, CredentialSubject::Membership(subject)) => {
                // A community's own identifier can only truthfully be declared `public`: a
                // community that cannot be found cannot be joined. The grant is the half
                // with no digest.
                if subject.digest_multibase.is_none() && c.issuer_scope != IssuerScope::Public {
                    return Err(DTGCredentialError::IssuerScopeTooNarrow {
                        declared: c.issuer_scope,
                        minimum: IssuerScope::Public,
                    });
                }
            }
            (
                DTGCredentialType::Relationship
                | DTGCredentialType::Invitation
                | DTGCredentialType::Persona,
                CredentialSubject::Basic(_),
            ) => {}
            (DTGCredentialType::Statement, CredentialSubject::Statement(subject)) => {
                statement::check_statement(c, subject)?;
            }
            (DTGCredentialType::Authority, CredentialSubject::Authority(subject)) => {
                if subject.authority.actions.is_empty() {
                    // Emptiness is never a wildcard. Refusing here means a caller cannot
                    // construct one by deserialization either.
                    return Err(DTGCredentialError::EmptyAuthorityActions);
                }
            }
            (DTGCredentialType::Delegation, CredentialSubject::Delegation(subject)) => {
                check_delegation_shape(&subject.delegation)?;
            }
            _ => return Err(DTGCredentialError::UnknownCredential),
        }
        Ok(())
    }

    #[cfg(feature = "affinidi-signing")]
    /// Sign the credential using W3C Data Integrity Proof with JCS EdDSA 2022
    /// signing_secret: The secret key to use to sign the credential
    /// create_time: Optional creation time for the proof, defaults to now if None
    ///
    /// # Errors
    ///
    /// Anything [DTGCredential::validate] refuses, before any signing is attempted.
    pub async fn sign(
        &mut self,
        signing_secret: &Secret,
        create_time: Option<DateTime<Utc>>,
    ) -> Result<DataIntegrityProof, DTGCredentialError> {
        self.validate()?;

        let mut options = SignOptions::new();
        if let Some(ts) = create_time {
            options = options.with_created(ts);
        }

        let proof = DataIntegrityProof::sign(self, signing_secret, options).await?;

        self.credential.proof = Some(proof.clone());
        Ok(proof)
    }

    #[cfg(feature = "affinidi-signing")]
    /// Verify the credential if you already know the public key bytes
    /// otherwise use the affinidi_tdk:verify_data() method
    /// public_key_bytes: The public key bytes to use to verify the credential
    ///
    /// # Errors
    ///
    /// Anything [DTGCredential::validate] refuses, before the proof is examined: a
    /// credential this library would not have signed does not verify either.
    pub fn verify_proof_with_public_key(
        &self,
        public_key_bytes: &[u8],
    ) -> Result<(), DTGCredentialError> {
        self.validate()?;

        let proof = if let Some(proof) = &self.credential.proof {
            proof.clone()
        } else {
            use tracing::warn;

            warn!("Trying to verify a DTG Credential that has no proof");
            return Err(DTGCredentialError::NotSigned);
        };

        let unsigned = DTGCommon {
            proof: None,
            ..self.credential.clone()
        };

        proof.verify_with_public_key(&unsigned, public_key_bytes, VerifyOptions::new())?;
        Ok(())
    }

    /// Is this credential a W3C VC Version 1.1 or 2.0 credential?
    pub fn get_w3c_vc_version(&self) -> W3CVCVersion {
        self.version
    }

    /// returns true if this credential a personhood credential (PHC)
    pub fn is_personhood_credential(&self) -> bool {
        if let DTGCredentialType::Membership = self.type_ {
            self.credential
                .type_
                .contains(&"PersonhoodCredential".to_string())
        } else {
            false
        }
    }
}

/// The `sha2-256` multihash code, per the [multicodec] table.
///
/// [multicodec]: https://www.w3.org/TR/cid-1.0/#multihash
const MULTIHASH_SHA2_256: u64 = 0x12;

/// The deepest JSON document this library will digest, sign or verify.
///
/// Depth counts from the top of the credential: the document itself is depth 1, and each
/// value inside an object or array is one deeper than its container. A VSC's `object.value`
/// therefore sits at depth 4, and a top-level member such as `credentialStatus` at depth 2.
///
/// # Why there is a bound
///
/// Digesting, signing and verifying clone, serialize and canonicalize a credential, and each
/// of those recurses once per level of nesting. A value nested a few thousand levels deep
/// exhausts the stack, and a stack overflow aborts the process — it is not an error a caller
/// can handle. The members this library holds as open JSON are where such a value gets in:
/// a VSC's `object.value` and unmodelled subject members, `credentialStatus`, and the
/// unmodelled members in [`DTGCommon::extra`].
///
/// # Why this value
///
/// `serde_json` already refuses to parse JSON nested 128 levels deep, so a credential that
/// arrived over the wire is bounded before it gets here. 64 stays well under that — nothing
/// this library signs is too deep for a stock verifier to parse back — and is still far more
/// than any credential in the specification needs.
///
/// # What it cannot do
///
/// A `serde_json::Value` is dropped recursively as well. A caller already holding a value
/// deep enough to overflow the stack will overflow it when that value goes out of scope,
/// whatever this library returns. The parser is the real boundary: `serde_json` applies its
/// limit by default, so leave it on.
pub const MAX_JSON_DEPTH: usize = 64;

/// Is any value reachable from `roots` deeper than [`MAX_JSON_DEPTH`]?
///
/// Each root is paired with the depth it sits at in the enclosing document. The walk keeps
/// an explicit stack rather than recursing: its job is to refuse a value too deep to process
/// safely, so it must not be what exhausts the call stack.
fn exceeds_max_depth<'a>(roots: impl IntoIterator<Item = (&'a Value, usize)>) -> bool {
    let mut pending: Vec<(&Value, usize)> = roots.into_iter().collect();
    while let Some((value, depth)) = pending.pop() {
        if depth > MAX_JSON_DEPTH {
            return true;
        }
        match value {
            Value::Array(items) => pending.extend(items.iter().map(|item| (item, depth + 1))),
            Value::Object(members) => {
                pending.extend(members.values().map(|member| (member, depth + 1)))
            }
            _ => {}
        }
    }
    false
}

/// Refuses a JSON document nested more deeply than [`MAX_JSON_DEPTH`].
pub(crate) fn check_json_depth(doc: &Value) -> Result<(), DTGCredentialError> {
    if exceeds_max_depth([(doc, 1)]) {
        Err(DTGCredentialError::JsonTooDeep {
            max: MAX_JSON_DEPTH,
        })
    } else {
        Ok(())
    }
}

/// Strips a credential's top-level `proof` member, if it has one.
fn proofless(doc: &Value) -> Value {
    match doc {
        Value::Object(members) => {
            let mut members = members.clone();
            members.remove("proof");
            Value::Object(members)
        }
        // Not an object: canonicalize as-is. A shape check belongs to the caller, which
        // has a better error to give than this would.
        other => other.clone(),
    }
}

/// The digest a DTG credential carries of another credential, computed over that
/// credential in its **wire form**.
///
/// This is the encoding DTG Core Credentials calls `digestMultibase`, and every
/// cross-credential reference in the specification uses it: the member-issued VMC's
/// `digestMultibase` of the grant it acknowledges, a VSC's `object.digestMultibase` (a
/// VWC's, of the edge credential it attests), an attenuated VAC's `authority.parent`, and a
/// VDC's `delegation.parent` and `delegation.accepts`.
///
/// Four steps, per [CID v1.0](https://www.w3.org/TR/cid-1.0/):
///
/// 1. canonicalize `doc` with its top-level `proof` member removed, using JCS (RFC 8785);
/// 2. SHA-256 the resulting UTF-8 bytes;
/// 3. prefix the `sha2-256` multihash header (`0x12`) and the length (`0x20`);
/// 4. encode base58btc with the multibase `z` prefix.
///
/// # Digest what you received, not what you parsed
///
/// Take the document as it arrived. [`DTGCommon::extra`] preserves unmodelled *top-level*
/// members through a round trip, but the subject types do not model every member a
/// `credentialSubject` may carry, so a parse-then-re-serialise of an unusual credential
/// can still differ from the bytes its issuer hashed. Where you hold those bytes, hash
/// them.
///
/// # Why `proof` is excluded
///
/// The digest binds to what the credential says, not to a signature over it, so a
/// reference survives its referent being re-signed. A re-issued credential carries
/// different claims and therefore a different digest, which is what makes renewal force
/// re-acknowledgement.
///
/// # Errors
///
/// [DTGCredentialError::JsonTooDeep] if `doc` is nested more deeply than
/// [`MAX_JSON_DEPTH`], checked before anything clones or canonicalizes it.
pub fn digest_multibase_json(doc: &Value) -> Result<String, DTGCredentialError> {
    check_json_depth(doc)?;

    let canonical = serde_json_canonicalizer::to_vec(&proofless(doc))
        .map_err(|e| DTGCredentialError::Canonicalization(e.to_string()))?;

    let digest = Sha256::digest(&canonical);

    // multihash prefix: 0x12 = sha2-256, 0x20 = 32 byte digest length. Both are varints,
    // and both are single-byte at these values.
    let mut multihash = Vec::with_capacity(2 + digest.len());
    multihash.push(MULTIHASH_SHA2_256 as u8);
    multihash.push(digest.len() as u8);
    multihash.extend_from_slice(&digest);

    Ok(multibase::encode(Base::Base58Btc, &multihash))
}

/// The *task digest* of a Trust Task document, the value a credential carries as
/// `taskDigestMultibase` alongside the `taskContext` that names the document.
///
/// Trust Tasks §4.9.3 *Binding a Citation to the Document It Names* defines it as
///
/// ```text
/// taskDigest = multibase( multihash( H( JCS( document ∖ proof ) ) ) )
/// ```
///
/// where `document ∖ proof` removes the **top-level** `proof` only — a `proof` inside
/// `payload`, in an embedded presentation or credential, is content and stays. That is
/// the computation DTG Core Credentials §Digest Encoding already fixes for every other
/// digest-valued member, with a Trust Task document as the input instead of a credential,
/// so this is [`digest_multibase_json`] under the name of the question it answers: `H` is
/// SHA-256 and the encoding base58btc, the single form an issuer of a DTG credential emits.
///
/// # Not the digest of the document as it arrived
///
/// Trust Tasks names two digests over a document, and they differ only in `proof`. The
/// task digest asks *what the document says*, so a signed and an unsigned copy have one
/// value. A *step digest* asks *which serialization arrived* and includes the `proof` —
/// the document identity `idConflict` is keyed on, and what a `witness/session/submit`
/// response's `vwcDigestMultibase` is taken over. A function computing one of these must
/// never stand in for the other; whichever it picks, it is wrong for the other question.
///
/// # Errors
///
/// [DTGCredentialError::JsonTooDeep] if `document` is nested more deeply than
/// [`MAX_JSON_DEPTH`].
pub fn task_digest_multibase_json(document: &Value) -> Result<String, DTGCredentialError> {
    digest_multibase_json(document)
}

/// Verifies a grant **in its wire form** before it is answered: that its issuer signed it,
/// and that it is in force at `at`.
///
/// Call this on the JSON a community or delegator sent, before passing that JSON to
/// [DTGCredential::new_member_vmc_for] or [DTGCredential::new_delegate_vdc_for]. Those
/// constructors bind an answer to a grant; they do not establish that anybody signed it.
///
/// Checks, in order:
///
/// 1. the document is within [`MAX_JSON_DEPTH`] and carries a `proof`, else
///    [DTGCredentialError::JsonTooDeep] or [DTGCredentialError::NotSigned];
/// 2. the proof verifies under `public_key` over the document with its top-level `proof`
///    removed, else [DTGCredentialError::DataIntegrity];
/// 3. the proof's `verificationMethod` belongs to the grant's `issuer` — the DID before its
///    `#` fragment is exactly the issuer — else [DTGCredentialError::ProofNotFromIssuer];
/// 4. the validity window is well formed and contains `at`, else
///    [DTGCredentialError::InvalidValidityWindow] or [DTGCredentialError::NotValidAt].
///
/// A document with no `issuer` or `validFrom`, or with a timestamp or a single `proof` that
/// cannot be read, is [DTGCredentialError::MalformedCredential].
///
/// # Where `public_key` comes from
///
/// Resolve it from the issuer's DID document, for the verification method the proof names,
/// and confirm that method is authorized for assertion. Step 3 ties the proof to the issuer
/// only as far as the key does: a key taken from the grant itself, or from whoever sent it,
/// establishes nothing about the issuer.
///
/// # What this does not check
///
/// Revocation — a `credentialStatus` entry is not resolved — and the grant's shape beyond
/// the members read above. The constructors check the shape.
#[cfg(feature = "affinidi-signing")]
pub fn verify_grant_with_public_key(
    grant: &Value,
    public_key: &[u8],
    at: DateTime<Utc>,
) -> Result<(), DTGCredentialError> {
    check_json_depth(grant)?;

    let object = grant
        .as_object()
        .ok_or_else(|| DTGCredentialError::MalformedCredential("not a JSON object".into()))?;
    let Some(proof) = object.get("proof") else {
        return Err(DTGCredentialError::NotSigned);
    };
    let proof: DataIntegrityProof = serde_json::from_value(proof.clone())
        .map_err(|e| DTGCredentialError::MalformedCredential(format!("unreadable `proof`: {e}")))?;

    proof.verify_with_public_key(&proofless(grant), public_key, VerifyOptions::new())?;

    let issuer = create::issuer_of(object)
        .ok_or_else(|| DTGCredentialError::MalformedCredential("no `issuer`".into()))?;
    let method_did = proof
        .verification_method
        .split_once('#')
        .map_or(proof.verification_method.as_str(), |(did, _)| did);
    if method_did != issuer {
        return Err(DTGCredentialError::ProofNotFromIssuer {
            issuer,
            verification_method: proof.verification_method,
        });
    }

    let valid_from = create::read_timestamp(object, "validFrom", "issuanceDate")
        .map_err(DTGCredentialError::MalformedCredential)?
        .ok_or_else(|| DTGCredentialError::MalformedCredential("no `validFrom`".into()))?;
    let valid_until = create::read_timestamp(object, "validUntil", "expirationDate")
        .map_err(DTGCredentialError::MalformedCredential)?;
    create::check_window(valid_from, valid_until)?;
    if valid_from > at || valid_until.is_some_and(|until| until < at) {
        return Err(DTGCredentialError::NotValidAt { at });
    }

    Ok(())
}

/// Decodes a `digestMultibase` value into the algorithm it names and the raw digest bytes.
///
/// The specification requires verifiers to compare digests this way rather than as
/// strings, so that two encodings of the same digest are recognised as equal and an
/// algorithm the verifier does not accept is *rejected* rather than reported as a
/// mismatch.
///
/// # Errors
///
/// [DTGCredentialError::InvalidDigest] if the multibase or multihash envelope is
/// malformed, or if the declared length does not match the bytes present.
/// [DTGCredentialError::UnsupportedDigestAlgorithm] if the multihash names anything other
/// than `sha2-256`.
pub fn decode_digest_multibase(digest: &str) -> Result<(u64, Vec<u8>), DTGCredentialError> {
    let (_, bytes) = multibase::decode(digest)
        .map_err(|e| DTGCredentialError::InvalidDigest(format!("multibase: {e}")))?;

    // Both the code and the length are varints. Every algorithm this library accepts has a
    // single-byte code and a single-byte length, so a two-byte header is all that is read;
    // a continuation bit in either is an algorithm we would reject anyway.
    let (&code, rest) = bytes
        .split_first()
        .ok_or_else(|| DTGCredentialError::InvalidDigest("empty multihash".into()))?;
    if code & 0x80 != 0 {
        return Err(DTGCredentialError::InvalidDigest(
            "multi-byte multihash code, which names no algorithm this library accepts".into(),
        ));
    }
    let (&length, raw) = rest
        .split_first()
        .ok_or_else(|| DTGCredentialError::InvalidDigest("multihash has no length".into()))?;

    if code as u64 != MULTIHASH_SHA2_256 {
        return Err(DTGCredentialError::UnsupportedDigestAlgorithm(code as u64));
    }
    if length as usize != raw.len() {
        return Err(DTGCredentialError::InvalidDigest(format!(
            "multihash declares {length} bytes but carries {}",
            raw.len()
        )));
    }

    Ok((code as u64, raw.to_vec()))
}

/// Do two `digestMultibase` values refer to the same credential?
///
/// Decodes both and compares the algorithm and the raw digest bytes, as
/// [`decode_digest_multibase`] describes. Never compares the encoded strings.
pub fn digests_match(left: &str, right: &str) -> Result<bool, DTGCredentialError> {
    Ok(decode_digest_multibase(left)? == decode_digest_multibase(right)?)
}

/// A credential's digest in the superseded `sha256:<hex>` encoding.
#[deprecated(
    since = "0.7.0",
    note = "Working Draft 02 replaced the `sha256:<hex>` digest with a base58btc multibase \
            multihash under the property name `digestMultibase`. Use \
            digest_multibase_json. This function will be removed in a future release."
)]
pub fn digest_json(doc: &Value) -> Result<String, DTGCredentialError> {
    check_json_depth(doc)?;

    let canonical = serde_json_canonicalizer::to_vec(&proofless(doc))
        .map_err(|e| DTGCredentialError::Canonicalization(e.to_string()))?;

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity("sha256:".len() + 64);
    out.push_str("sha256:");
    for byte in Sha256::digest(&canonical) {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(out)
}

/// DTG VC Type Identifiers — the concrete `DTGCredential` subtypes the v1 context defines.
///
/// `PartialEq` is derived so that a consumer can assert by equality
/// (`assert_eq!(cred.credential_type(), &DTGCredentialType::Delegation)`) rather than by
/// pattern (`matches!`), which reports the actual variant on failure.
///
/// # What is no longer here
///
/// `EndorsementCredential` and `WitnessCredential` are not DTG types: DTG Core Credentials
/// replaced them with the [DTGCredentialType::Statement] type under the [ENDORSES_V1] and
/// [WITNESSED_V1] predicate profiles, and a VSC carries its meaning in `predicate` alone so
/// that a type string and a predicate can never disagree. `RCardCredential` is not a DTG
/// credential at all — the r-card is a verifiable data structure. A credential naming any
/// of the three is refused at parse with [DTGCredentialError::InvalidType].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DTGCredentialType {
    /// Verifiable Membership Credential (VMC) — one half of a membership edge.
    Membership,

    /// Verifiable Relationship Credential (VRC) — one half of a relationship edge.
    Relationship,

    /// Verifiable Invitation Credential (VIC).
    Invitation,

    /// Verifiable Persona Credential (VPC).
    Persona,

    /// Verifiable Statement Credential (VSC) — a signed statement by one node about
    /// another, whose meaning is fixed by its `predicate`.
    ///
    /// The VEC and the VWC are VSCs under the [ENDORSES_V1] and [WITNESSED_V1] profiles.
    Statement,

    /// Verifiable Authority Credential (VAC) — confers authority on a party to perform
    /// specified actions within a named scope governed by the issuer.
    ///
    /// Key control at invocation — a VAC is not a bearer credential — and the
    /// `maxAttenuation` ceiling are implemented in [crate::authority::verify_chain].
    /// Revocation via `credentialStatus` is a live lookup the caller performs.
    Authority,

    /// Verifiable Delegation Credential (VDC) — establishes that one entity may act in
    /// another's name.
    Delegation,
}

impl DTGCredentialType {
    /// The `type` string this subtype is named by on the wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            DTGCredentialType::Membership => "MembershipCredential",
            DTGCredentialType::Relationship => "RelationshipCredential",
            DTGCredentialType::Invitation => "InvitationCredential",
            DTGCredentialType::Persona => "PersonaCredential",
            DTGCredentialType::Statement => "StatementCredential",
            DTGCredentialType::Authority => "AuthorityCredential",
            DTGCredentialType::Delegation => "DelegationCredential",
        }
    }

    /// The subtype a `type` string names, if it names one.
    fn from_type_str(type_: &str) -> Option<Self> {
        DTG_TYPES.iter().find(|t| t.as_str() == type_).cloned()
    }
}

impl Display for DTGCredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<&[String]> for DTGCredentialType {
    type Error = DTGCredentialError;

    /// The concrete subtype a `type` array names, under the same rules a parse applies: see
    /// [DTGCredentialError::InvalidType].
    fn try_from(types: &[String]) -> Result<Self, Self::Error> {
        check_type(types)
    }
}

/// Every concrete subtype, in the order the v1 context defines them.
const DTG_TYPES: [DTGCredentialType; 7] = [
    DTGCredentialType::Membership,
    DTGCredentialType::Relationship,
    DTGCredentialType::Delegation,
    DTGCredentialType::Invitation,
    DTGCredentialType::Persona,
    DTGCredentialType::Statement,
    DTGCredentialType::Authority,
];

/// Type strings earlier drafts used for a DTG subtype, refused with a message naming what
/// replaced them rather than as merely unknown.
const RETIRED_TYPES: [(&str, &str); 3] = [
    (
        "EndorsementCredential",
        "replaced by StatementCredential under the endorses/1 predicate",
    ),
    (
        "WitnessCredential",
        "replaced by StatementCredential under the witnessed/1 predicate",
    ),
    (
        "RCardCredential",
        "the r-card is a verifiable data structure, not a DTG credential",
    ),
];

/// The non-authoritative personhood hint a community-issued VMC may carry in `type`.
const PERSONHOOD_HINT: &str = "PersonhoodCredential";

/// Reads the concrete subtype off a `type` array, refusing anything but
/// `VerifiableCredential`, `DTGCredential`, exactly one concrete subtype and — on a VMC
/// only — the `PersonhoodCredential` hint.
///
/// Every other string is refused, retired DTG types and unknown ones alike: a `type` the
/// v1 context does not define is one this library cannot say it understood.
fn check_type(types: &[String]) -> Result<DTGCredentialType, DTGCredentialError> {
    let (mut vc, mut dtg, mut personhood) = (false, false, false);
    let mut concrete: Option<DTGCredentialType> = None;

    for type_ in types {
        let seen = match type_.as_str() {
            "VerifiableCredential" => std::mem::replace(&mut vc, true),
            "DTGCredential" => std::mem::replace(&mut dtg, true),
            PERSONHOOD_HINT => std::mem::replace(&mut personhood, true),
            other => match DTGCredentialType::from_type_str(other) {
                Some(found) => match &concrete {
                    Some(already) if *already == found => true,
                    Some(already) => {
                        return Err(DTGCredentialError::InvalidType(format!(
                            "names both {already} and {found}; a DTG credential has exactly \
                             one concrete subtype"
                        )));
                    }
                    None => {
                        concrete = Some(found);
                        false
                    }
                },
                None => {
                    let reason = RETIRED_TYPES
                        .iter()
                        .find(|(retired, _)| *retired == other)
                        .map_or("not a type the DTG v1 context defines", |(_, why)| why);
                    return Err(DTGCredentialError::InvalidType(format!(
                        "`{other}`: {reason}"
                    )));
                }
            },
        };
        if seen {
            return Err(DTGCredentialError::InvalidType(format!(
                "`{type_}` is listed twice"
            )));
        }
    }

    if !vc || !dtg {
        return Err(DTGCredentialError::InvalidType(
            "must include both `VerifiableCredential` and `DTGCredential`".into(),
        ));
    }
    let concrete = concrete.ok_or(DTGCredentialError::UnknownCredential)?;
    if personhood && concrete != DTGCredentialType::Membership {
        return Err(DTGCredentialError::InvalidType(format!(
            "`{PERSONHOOD_HINT}` is a hint on a MembershipCredential only, not on a {concrete}"
        )));
    }
    Ok(concrete)
}

/// Reads the W3C VC version off an `@context` array that lists the W3C context first and
/// [DTG_CONTEXT_V1] second, refusing any other arrangement.
///
/// Further contexts — a proof suite's, a community vocabulary's — may follow in any number.
fn check_context(context: &[String]) -> Result<W3CVCVersion, DTGCredentialError> {
    let version = match context.first().map(String::as_str) {
        Some(W3C_VC_V2_CONTEXT) => W3CVCVersion::V2_0,
        Some(W3C_VC_V1_CONTEXT) => W3CVCVersion::V1_1,
        _ => return Err(DTGCredentialError::UnknownVCVersion),
    };
    match context.get(1).map(String::as_str) {
        Some(DTG_CONTEXT_V1) => Ok(version),
        Some(other) => Err(DTGCredentialError::InvalidContext(format!(
            "second entry is `{other}`, not `{DTG_CONTEXT_V1}`"
        ))),
        None => Err(DTGCredentialError::InvalidContext(format!(
            "`{DTG_CONTEXT_V1}` is not listed second"
        ))),
    }
}

/// Refuses a `delegation` object that is neither a well-formed grant nor a well-formed
/// acceptance.
fn check_delegation_shape(d: &DelegationGrant) -> Result<(), DTGCredentialError> {
    // The two halves are distinguished by `accepts`, and each half has exactly one shape.
    match (&d.accepts, &d.scope) {
        (Some(_), Some(_)) => Err(DTGCredentialError::MalformedDelegation(
            "carries both `accepts` and `scope`: an acceptance consents to the scope of the \
             grant it names rather than restating it"
                .into(),
        )),
        (Some(_), None) if d.parent.is_some() || d.max_depth.is_some() => {
            Err(DTGCredentialError::MalformedDelegation(
                "an acceptance carries `accepts` and nothing else".into(),
            ))
        }
        (Some(_), None) => Ok(()),
        (None, Some(scope)) if scope.is_empty() => Err(DTGCredentialError::MalformedDelegation(
            "a grant's `scope` MUST contain at least one entry — emptying it is not how an \
             unbounded appointment is expressed, because there is no way to express one"
                .into(),
        )),
        (None, Some(_)) => Ok(()),
        (None, None) => Err(DTGCredentialError::MalformedDelegation(
            "carries neither `scope` nor `accepts`, so it is neither a grant nor an \
             acceptance"
                .into(),
        )),
    }
}

/// All DTG Credentials follow a common structure.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DTGCommon {
    /// JSON-LD links to contexts.
    ///
    /// MUST list [W3C_VC_V2_CONTEXT] first (or, for a v1.1 credential,
    /// [W3C_VC_V1_CONTEXT]) and [DTG_CONTEXT_V1] second, followed by any contexts a proof
    /// type, a predicate profile or a community vocabulary requires. A later context MUST
    /// NOT redefine a term the DTG context protects.
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// Credential type identifiers.
    ///
    /// MUST include `VerifiableCredential`, `DTGCredential` and exactly one concrete
    /// subtype. A community-issued VMC MAY add `PersonhoodCredential` as a non-authoritative
    /// hint; nothing else is accepted.
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// OPTIONAL identifier for this specific credential, per the W3C VC Data Model.
    ///
    /// When present it MUST be a single URL. A `urn:uuid:` URN is the usual choice for a
    /// credential with no dereferenceable home.
    ///
    /// This is the handle a holder or verifier stores the credential *under*, so it is what
    /// makes re-delivery of the same credential idempotent and re-issuance of a different one
    /// recognisable as a renewal rather than a duplicate. A counterparty that keys credentials
    /// by `id` cannot accept one that has none — so issue with an `id` unless you know nobody
    /// on the other side needs it.
    ///
    /// # Set it before signing
    ///
    /// A Data Integrity proof covers the credential minus its `proof`, which includes this
    /// property. Set it while building — [DTGCredential::with_id] — never after
    /// [DTGCredential::sign], which would leave a document whose proof no longer verifies.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub id: Option<String>,

    /// DID of the entity issuing this credential
    pub issuer: String,

    /// The correlation scope the issuer declares for the identifier in `issuer`.
    ///
    /// REQUIRED: a credential without it, or with any value but `pairwise`, `directed` or
    /// `public`, is refused at parse. See [IssuerScope].
    pub issuer_scope: IssuerScope,

    /// ISO 8601 format of when this credentials become valid from
    #[serde(serialize_with = "iso8601_format", alias = "issuanceDate")]
    pub valid_from: DateTime<Utc>,

    /// ISO 8601 format of when these credentials are valid to
    #[serde(serialize_with = "iso8601_format_option")]
    #[serde(
        skip_serializing_if = "Option::is_none",
        alias = "expirationDate",
        default
    )]
    pub valid_until: Option<DateTime<Utc>>,

    /// Names the trust task exchange this credential cites: the `id` of the document that
    /// initiated the innermost exchange attesting what the credential states (Trust Tasks
    /// §4.9.1). For `witness/session` that document's `threadId` is its own `id`, so the
    /// earlier description of this member as the exchange's `threadId` gives the same
    /// value there; it does not in general, since a `threadId` need not be unique.
    ///
    /// Carry [`DTGCommon::task_digest_multibase`] with it, which binds the credential to
    /// the document this only names.
    ///
    /// REQUIRED on a VSC whose predicate profile requires it ([WITNESSED_V1], [VETTED_V1],
    /// [PRESENTED_V1]), OPTIONAL otherwise. A DTG credential without a `taskContext` MUST be
    /// interpretable standing alone, independent of any exchange.
    ///
    /// NOTE: A verifier MUST NOT interpret a `taskContext`-bearing credential as proof that
    /// the associated trust task completed unless the matching trust task outcome evidence is
    /// also present and verified.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub task_context: Option<String>,

    /// The *task digest* of the Trust Task document [`DTGCommon::task_context`] names.
    ///
    /// `taskContext` locates the exchange a credential cites; this binds the credential to
    /// it. An `id` is only a name, and anyone can write a different document that reuses
    /// it, so a verifier pairing a credential with the cited document by `id` alone accepts
    /// a counterfeit.
    ///
    /// Computed as Trust Tasks §4.9.3 *Binding a Citation to the Document It Names* defines
    /// a task digest: the document with its **top-level** `proof` removed (a `proof` inside
    /// `payload` stays), canonicalized with JCS (RFC 8785), hashed, multihash-tagged and
    /// multibase-encoded. An issuer uses `sha2-256` and base58btc, as for every other
    /// digest-valued member of DTG Core Credentials. [`task_digest_multibase_json`] computes
    /// it; [DTGCredential::with_task_citation] sets it together with `taskContext`.
    ///
    /// REQUIRED wherever `taskContext` is REQUIRED, and SHOULD accompany it where it is
    /// OPTIONAL. A VSC under a profile requiring it is refused at parse without one.
    /// [DTGCredential::cites_task] reports a credential without one as citing nothing rather
    /// than falling back to comparing `id`s.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub task_digest_multibase: Option<String>,

    /// The assertion between the entities involved
    pub credential_subject: CredentialSubject,

    /// A W3C VC status mechanism through which a verifier determines whether this
    /// credential has been revoked.
    ///
    /// Held as an opaque [`Value`]: the mechanism is chosen by the governing VTC or VTN,
    /// and this library neither selects one nor resolves it. `BitstringStatusListEntry` is
    /// the common choice.
    ///
    /// CONDITIONAL on a VDC — REQUIRED where the appointment outlives the freshness window
    /// the governing party defines for delegations, and permitted to be absent otherwise,
    /// with short validity and re-issuance preferred wherever the delegator is reachable.
    /// A status check is a live lookup that reveals the verification event to whoever
    /// hosts the status list.
    ///
    /// # Modelled so that digests survive a round trip
    ///
    /// Every VMC issued against a status list carries this, and before it was modelled a
    /// parse-then-re-serialise dropped it silently — producing a digest its issuer would
    /// not recognise. See [`DTGCommon::extra`], which closes the same gap for members this
    /// library does not name at all.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub credential_status: Option<Value>,

    /// Cryptographic proof of credential authenticity
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub proof: Option<DataIntegrityProof>,

    /// Top-level members this library does not model, preserved verbatim.
    ///
    /// A DTG credential may legitimately carry properties beyond the ones named here —
    /// `credentialSchema`, `termsOfUse`, `evidence`, an extension a governing party
    /// defines. Without somewhere to keep them, a parse-then-re-serialise round trip drops
    /// them, and the digest computed over the result matches nothing the issuer signed.
    ///
    /// Capturing them makes [DTGCredential::digest_multibase] agree with
    /// [`digest_multibase_json`] over the wire form for any credential whose extra members
    /// are top-level. It is not a complete answer — the `credentialSubject` types still
    /// reject members they do not model — so where you hold the bytes a counterparty sent,
    /// hashing those remains the safe habit.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl DTGCommon {
    /// Has this credential been signed?
    /// Returns true if a proof exists
    /// NOTE: This does NOT validate the proof itself
    pub fn signed(&self) -> bool {
        self.proof.is_some()
    }

    /// This credential's own identifier, if it has one. See [DTGCommon::id].
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// Returns the issuer DID
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The correlation scope the issuer declares for its own identifier.
    pub fn issuer_scope(&self) -> IssuerScope {
        self.issuer_scope
    }

    /// Returns the subject DID
    pub fn subject(&self) -> &str {
        match &self.credential_subject {
            CredentialSubject::Basic(subject) => &subject.id,
            CredentialSubject::Statement(subject) => &subject.id,
            CredentialSubject::Membership(subject) => &subject.id,
            CredentialSubject::Authority(subject) => &subject.id,
            CredentialSubject::Delegation(subject) => &subject.id,
        }
    }

    /// The statement — `predicate`, `object` and any profile members — when this
    /// credential is a VSC.
    ///
    /// `None` for every other credential type, for the same reason [DTGCommon::authority]
    /// is fallible.
    pub fn statement(&self) -> Option<&CredentialSubjectStatement> {
        match &self.credential_subject {
            CredentialSubject::Statement(subject) => Some(subject),
            _ => None,
        }
    }

    /// Mutable access to the statement, when this credential is a VSC.
    ///
    /// Present for the same reason as [DTGCommon::authority_mut]: a verifier must be
    /// testable against statements this library's own constructors would refuse to build.
    pub fn statement_mut(&mut self) -> Option<&mut CredentialSubjectStatement> {
        match &mut self.credential_subject {
            CredentialSubject::Statement(subject) => Some(subject),
            _ => None,
        }
    }

    /// The `authority` grant, when this credential is a VAC.
    ///
    /// `None` for every other credential type — the accessor is deliberately fallible
    /// rather than panicking, so a caller handed a credential of unknown type can ask
    /// without first matching on `type_`.
    pub fn authority(&self) -> Option<&AuthorityGrant> {
        match &self.credential_subject {
            CredentialSubject::Authority(subject) => Some(&subject.authority),
            _ => None,
        }
    }

    /// Mutable access to the `authority` grant, when this credential is a VAC.
    ///
    /// Present so that a caller can construct chains this library's own
    /// [DTGCredential::attenuate] would refuse — which is exactly what a verifier must be
    /// tested against, since nothing stops another implementation emitting such JSON.
    pub fn authority_mut(&mut self) -> Option<&mut AuthorityGrant> {
        match &mut self.credential_subject {
            CredentialSubject::Authority(subject) => Some(&mut subject.authority),
            _ => None,
        }
    }

    /// The `delegation` object, when this credential is a VDC.
    ///
    /// `None` for every other credential type, for the same reason [DTGCommon::authority]
    /// is fallible: a caller handed a credential of unknown type can ask without first
    /// matching on `type_`.
    pub fn delegation(&self) -> Option<&DelegationGrant> {
        match &self.credential_subject {
            CredentialSubject::Delegation(subject) => Some(&subject.delegation),
            _ => None,
        }
    }

    /// Mutable access to the `delegation` object, when this credential is a VDC.
    ///
    /// Present for the same reason as [DTGCommon::authority_mut]: a verifier must be
    /// testable against chains this library's own constructors would refuse to build,
    /// since nothing stops another implementation emitting such JSON.
    pub fn delegation_mut(&mut self) -> Option<&mut DelegationGrant> {
        match &mut self.credential_subject {
            CredentialSubject::Delegation(subject) => Some(&mut subject.delegation),
            _ => None,
        }
    }

    /// The credential is valid from this timestamp
    pub fn valid_from(&self) -> DateTime<Utc> {
        self.valid_from
    }

    /// The credential is valid until this timestamp, if set
    pub fn valid_until(&self) -> Option<DateTime<Utc>> {
        self.valid_until
    }

    /// The `id` naming the trust task exchange this credential cites, if set. See
    /// [DTGCommon::task_context].
    pub fn task_context(&self) -> Option<&str> {
        self.task_context.as_deref()
    }

    /// The task digest of the document `taskContext` names, if set. See
    /// [DTGCommon::task_digest_multibase].
    pub fn task_digest_multibase(&self) -> Option<&str> {
        self.task_digest_multibase.as_deref()
    }

    /// Refuses a credential whose open JSON members take the document past
    /// [`MAX_JSON_DEPTH`].
    ///
    /// Every other member is a type this library defines, none more than four levels deep,
    /// so the open members are the only place the bound can be crossed.
    fn check_depth(&self) -> Result<(), DTGCredentialError> {
        // The document is depth 1, so a top-level member sits at 2, a member of
        // `credentialSubject` at 3, and `object.value` at 4.
        let mut roots: Vec<(&Value, usize)> =
            self.extra.values().map(|member| (member, 2)).collect();
        if let Some(status) = &self.credential_status {
            roots.push((status, 2));
        }
        if let CredentialSubject::Statement(subject) = &self.credential_subject {
            if let Some(value) = subject.object.value() {
                roots.push((value, 4));
            }
            roots.extend(subject.extra.values().map(|member| (member, 3)));
        }

        if exceeds_max_depth(roots) {
            Err(DTGCredentialError::JsonTooDeep {
                max: MAX_JSON_DEPTH,
            })
        } else {
            Ok(())
        }
    }
}

impl DTGCredential {
    /// The skeleton every `new_*` constructor starts from: the two required contexts, the
    /// three required types, and the members every credential carries.
    ///
    /// There is deliberately no `Default` for [DTGCommon]. A default would have to choose
    /// an `issuerScope`, and a declaration nobody made is the one thing the member exists to
    /// rule out.
    pub(crate) fn build(
        type_: DTGCredentialType,
        issuer: String,
        issuer_scope: IssuerScope,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        credential_subject: CredentialSubject,
    ) -> Self {
        DTGCredential {
            credential: DTGCommon {
                context: vec![W3C_VC_V2_CONTEXT.to_string(), DTG_CONTEXT_V1.to_string()],
                type_: vec![
                    "VerifiableCredential".to_string(),
                    "DTGCredential".to_string(),
                    type_.to_string(),
                ],
                id: None,
                issuer,
                issuer_scope,
                valid_from,
                valid_until,
                task_context: None,
                task_digest_multibase: None,
                credential_subject,
                credential_status: None,
                proof: None,
                extra: serde_json::Map::new(),
            },
            type_,
            version: W3CVCVersion::V2_0,
        }
    }
}

/// Deserialization: `@context` and `type` are checked on the raw document first, so that a
/// credential of a retired type, or under an unrecognized context, is refused with an error
/// that says so — rather than with whatever the subject's shape happens to fail on.
impl TryFrom<Value> for DTGCredential {
    type Error = DTGCredentialError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let strings = |member: &str| -> Option<Vec<String>> {
            value
                .get(member)?
                .as_array()?
                .iter()
                .map(|v| v.as_str().map(str::to_string))
                .collect()
        };
        if let Some(context) = strings("@context") {
            check_context(&context)?;
        }
        if let Some(types) = strings("type") {
            check_type(&types)?;
        }

        let common: DTGCommon = serde_json::from_value(value)
            .map_err(|e| DTGCredentialError::MalformedCredential(e.to_string()))?;
        DTGCredential::try_from(common)
    }
}

/// Post deserialize setup of a CredentialSubject and CredentialType
impl TryFrom<DTGCommon> for DTGCredential {
    type Error = DTGCredentialError;

    fn try_from(value: DTGCommon) -> Result<Self, Self::Error> {
        let version = check_context(&value.context)?;
        let type_ = check_type(&value.type_)?;

        // A VMC's subject is normalized into `Membership`, so a caller matching on the
        // subject of a VMC sees one shape rather than two: `{ id }` — the community-issued
        // grant — is claimed first by the untagged match as `Basic`. See
        // [CredentialSubject::Membership].
        let value = match (&type_, value.credential_subject) {
            (DTGCredentialType::Membership, CredentialSubject::Basic(subject)) => DTGCommon {
                credential_subject: CredentialSubject::Membership(CredentialSubjectMembership {
                    id: subject.id,
                    digest_multibase: None,
                }),
                ..value
            },
            (_, credential_subject) => DTGCommon {
                credential_subject,
                ..value
            },
        };

        let credential = DTGCredential {
            credential: value,
            type_,
            version,
        };
        credential.check_conformance()?;
        Ok(credential)
    }
}

/// This correctly formats timestamps into the correct iso8601 specification for W3C Verifiable
/// Credentials
fn iso8601_format<S>(timestamp: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(
        timestamp
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            .as_str(),
    )
}

fn iso8601_format_option<S>(timestamp: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Some(timestamp) = timestamp {
        s.serialize_str(
            timestamp
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                .as_str(),
        )
    } else {
        s.serialize_none()
    }
}

// ****************************************************************************
// Credential Subject types
// ****************************************************************************
// NOTE: The DTG credential spec overloads the JSON attributes for different credential payloads.
// The following enum will map the credential subject schema to correct Struct type

/// This represents all possible credential subjects
/// The order of the enum is important as it will match on first match
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum CredentialSubject {
    /// Credential Subject of just `id`
    /// Used by a community-issued VMC, and by VRC, VIC and VPC
    Basic(CredentialSubjectBasic),

    /// Verifiable Statement Credential subject: `id`, `predicate`, `object`.
    ///
    /// Unambiguous under the untagged match: no other DTG subject carries a `predicate` or
    /// an `object`, and both are REQUIRED here. Unmodelled members are kept rather than
    /// refused, because a verifier MUST ignore members a profile does not define.
    Statement(CredentialSubjectStatement),

    /// Verifiable Authority Credential subject.
    ///
    /// Unambiguous under the untagged match: no other DTG subject carries an `authority`
    /// member, and `deny_unknown_fields` keeps a subject that does not have one from
    /// landing here.
    Authority(CredentialSubjectAuthority),

    /// Verifiable Delegation Credential subject.
    ///
    /// Unambiguous for the same reason as [CredentialSubject::Authority]: `delegation` is
    /// carried by no other DTG subject.
    Delegation(CredentialSubjectDelegation),

    /// Membership Credential subject, carrying the `digestMultibase` that a member-issued
    /// VMC MUST set and a community-issued one MUST omit.
    ///
    /// # `{ id }` lands on `Basic` first
    ///
    /// The grant's shape is also [CredentialSubject::Basic]'s, which the untagged match
    /// takes first; only the credential's `type` says it is a membership. So
    /// `TryFrom<DTGCommon> for DTGCredential` re-wraps a `Basic` subject as this one when
    /// `type` includes `MembershipCredential`, and a `Membership` subject reaching a matcher
    /// has been through that normalization. The acknowledgement's `{ id, digestMultibase }`
    /// lands here directly.
    Membership(CredentialSubjectMembership),
}

/// id of the credential subject only
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CredentialSubjectBasic {
    pub id: String,
}

/// The `authority` object a [CredentialSubject::Authority] carries.
///
/// # Attenuation
///
/// A holder may derive a narrower VAC from one they hold without involving the issuer. An
/// attenuated VAC sets [AuthorityGrant::parent] to the **digest** of the credential it
/// derives from, and MUST NOT widen `actions`, `scope`, or the validity window. Verification walks
/// the chain to a VAC issued by the party governing the scope — see
/// [crate::authority::verify_chain], which is where the security of this credential
/// actually lives. Issuing one is a struct and a signature; refusing a widening link is the
/// part that matters.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityGrant {
    /// The DID or URI the authority applies to.
    ///
    /// Matched exactly. A verifier rejects a VAC whose `scope` is not the resource being
    /// accessed; nothing here implies containment between scopes.
    pub scope: String,

    /// The permitted actions, from a vocabulary the governing party defines.
    ///
    /// MUST NOT be empty. An empty list confers nothing — emptiness is never a wildcard,
    /// which is the failure mode this rule exists to prevent. Action strings are compared
    /// exactly and case-sensitively, and no action implies another: `admin` does not grant
    /// `write` unless both are listed.
    pub actions: Vec<String>,

    /// The **digest** of the VAC this one was attenuated from, as
    /// [DTGCredential::digest_multibase] computes it.
    ///
    /// Absent means this VAC was issued directly by the party governing the scope, and is
    /// therefore a chain root.
    ///
    /// # A digest, not an identifier
    ///
    /// Working Draft 02 made this deliberate rather than incidental. A digest names
    /// nothing that can be fetched, so verification cannot come to depend on network
    /// availability, a verifier cannot be induced to make a request against an address of
    /// the holder's choosing, and nobody hosting an identifier learns when a credential is
    /// used. It also binds an attenuated VAC to the exact claims its issuer narrowed from:
    /// re-issuing a parent with different claims does not re-parent the children of the
    /// old one, while re-proofing it with identical claims leaves them undisturbed,
    /// because the digest excludes `proof`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub parent: Option<String>,

    /// The number of further attenuations permitted below this VAC.
    ///
    /// `0` prohibits attenuating it at all. **Absence permits** attenuation as far as
    /// [crate::authority::MAX_CHAIN_DEPTH] allows — the opposite default from a VDC's
    /// `maxDepth`, deliberately: an attenuation only narrows and its subject acts as
    /// itself, and forbidding it pushes a holder to lend their own key instead.
    ///
    /// A VAC attenuated from a parent bearing `n` MUST NOT bear more than `n - 1`, and
    /// nothing may lie more than `n` steps below it. Any link may set a lower limit, or set
    /// one where its parent set none; none may raise one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_attenuation: Option<u32>,
}

/// The `delegation` object a [CredentialSubject::Delegation] carries.
///
/// A VDC is one of a **pair**. The delegator issues a *grant* — carrying `scope`, and
/// optionally `parent` and `maxDepth` — and the delegate answers with an *acceptance*
/// carrying `accepts` and nothing else. The two together form a complete DTG edge, and a
/// verifier MUST have both: a grant alone establishes what the delegator appointed, not
/// what the delegate agreed to.
///
/// # A VDC is not authority
///
/// It never supplies permission the delegator did not itself hold. A verifier presented
/// with one substitutes the delegator for the delegate and then asks the permission
/// question it would have asked of the delegator directly — live, at the time of the act.
/// The reach of a delegated act is the *intersection* of what the delegator may do and
/// what the chain appoints the delegate for. See [AuthorityGrant] for the credential that
/// answers the permission question.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DelegationGrant {
    /// The acts the delegate may perform in the delegator's name.
    ///
    /// REQUIRED on a grant and MUST contain at least one entry — a VDC MUST NOT express an
    /// unbounded appointment by omitting or emptying it. MUST be omitted on an acceptance,
    /// which consents to the scope of the grant it names rather than restating it.
    ///
    /// Entries are opaque strings compared for exact equality. The specification defines no
    /// wildcard, prefix or hierarchical semantics, so the subset test on a chain is set
    /// inclusion over exact matches; a governing vocabulary that wants structure must put
    /// it in the terms themselves.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scope: Option<Vec<String>>,

    /// The digest of the VDC this delegation was derived from, when the delegator is
    /// itself acting under a delegation. A VDC with no `parent` is a **root delegation**.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub parent: Option<String>,

    /// The number of further re-delegations permitted below this one.
    ///
    /// `0` prohibits re-delegation, and so does **absence** — the default is a single hop.
    /// Setting it above `0` is the delegator's explicit authorisation to re-delegate;
    /// there is no other. Note that this is the opposite default from a VAC, where
    /// attenuation is permitted unless forbidden: a delegate speaks in the principal's
    /// name, so the principal keeps the register of who may do so.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_depth: Option<u32>,

    /// The digest of the grant being accepted.
    ///
    /// REQUIRED on an acceptance and MUST be omitted on a grant. Its presence is what
    /// distinguishes the two halves of a delegation edge.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub accepts: Option<String>,
}

/// Delegation Credential subject
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSubjectDelegation {
    /// DID of the delegate on a grant; DID of the delegator on an acceptance.
    pub id: String,

    /// The appointment itself.
    pub delegation: DelegationGrant,
}

/// Verifiable Authority Credential (VAC) subject.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSubjectAuthority {
    /// DID of the party receiving the authority.
    pub id: String,

    /// What the subject may do, and where.
    pub authority: AuthorityGrant,
}

/// Membership Credential subject
///
/// The two directions of a membership edge share this shape and are told apart by
/// `digest`: a community-issued VMC (the membership grant) MUST omit it, and a
/// member-issued VMC (the membership acknowledgement) MUST carry it. Where both endpoints
/// are community identifiers, as in VTN membership, `digestMultibase` is the only
/// discriminator — the issuer and subject rules cannot separate the directions.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSubjectMembership {
    pub id: String,

    /// Digest of the community-issued VMC this acknowledges, as
    /// [DTGCredential::digest_multibase] computes it.
    ///
    /// REQUIRED on the member-issued VMC, and MUST be omitted on the community-issued VMC.
    /// `Option` rather than two structs because the same property distinguishes the two
    /// directions: a type that could not represent both could not deserialize the pair.
    ///
    /// Serializes as `digestMultibase`. The Working Draft 01 name `digest` is no longer
    /// accepted: a credential issued before the Implementers Draft is not conformant.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub digest_multibase: Option<String>,
}

/// The `witnessContext` a [WITNESSED_V1] statement MAY carry: context of the witnessing
/// event.
///
/// Every member is OPTIONAL, and the member set is frozen with the predicate version —
/// `witnessed/1`'s schema admits no others, so an unknown member is refused. The terms are
/// defined in [DTG_CONTEXT_V1].
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WitnessContext {
    /// Human-readable event name
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub event: Option<String>,

    /// Session or nonce identifier
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub session_id: Option<String>,

    /// Verification method used
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub method: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::{
        CredentialSubject, DTG_CONTEXT_V1, DTGCommon, DTGCredential, DTGCredentialError,
        DTGCredentialType, ENDORSES_V1, IssuerScope, W3C_VC_V2_CONTEXT, W3CVCVersion, WITNESSED_V1,
        check_predicate_iri, check_type, decode_digest_multibase, digest_multibase_json,
        digests_match,
    };
    use chrono::{DateTime, Utc};
    use multibase::Base;
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_vmc_vc_1_deserialize() {
        // tests deserialize a W3C VC Version 1.1 credential
        let vmc: DTGCredential = match serde_json::from_str(
            r#"{
"@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://registry.trustoverip.org/dtg/context/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "type": ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
  "issuer": "did:web:chess-club.example",
  "issuerScope": "public",
  "issuanceDate": "2026-01-06T10:00:00Z",
  "expirationDate": "2027-01-06T10:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkpTHR8VNs..."
  }
            }"#,
        ) {
            Ok(vmc) => vmc,
            Err(e) => panic!("Couldn't deserialize VMC: {}", e),
        };

        assert!(matches!(vmc.type_, DTGCredentialType::Membership));
        assert!(matches!(
            vmc.credential().credential_subject,
            CredentialSubject::Membership(_)
        ));
        assert!(matches!(vmc.version, W3CVCVersion::V1_1));
        assert!(matches!(vmc.get_w3c_vc_version(), W3CVCVersion::V1_1));
    }

    #[test]
    fn test_missing_w3c_context() {
        // tests deserialize a W3C VC Version 1.1 credential
        assert!(
            serde_json::from_str::<DTGCredential>(
                r#"{
"@context": [
    "https://registry.trustoverip.org/dtg/context/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "type": ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
  "issuer": "did:web:chess-club.example",
  "issuerScope": "public",
  "issuanceDate": "2026-01-06T10:00:00Z",
  "expirationDate": "2027-01-06T10:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkpTHR8VNs..."
  }
            }"#,
            )
            .is_err()
        );
    }

    #[test]
    fn test_mutable_credential() {
        let mut vmc = DTGCredential::new_vmc(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            false,
        );

        let cred = vmc.credential_mut();
        cred.type_.push("PersonhoodCredential".to_string());
        assert!(vmc.is_personhood_credential());
    }

    #[test]
    fn test_vmc_deserialize() {
        let vmc: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2", "https://registry.trustoverip.org/dtg/context/v1"],
                "type": ["VerifiableCredential", "DTGCredential",  "MembershipCredential"],
                "issuer": "did:example:community",
                "issuerScope": "public",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:rDid" }
            }"#,
        ) {
            Ok(vmc) => vmc,
            Err(e) => panic!("Couldn't deserialize VMC: {}", e),
        };

        assert!(!vmc.is_personhood_credential());
        assert!(matches!(vmc.type_, DTGCredentialType::Membership));
        assert!(matches!(
            vmc.credential().credential_subject,
            CredentialSubject::Membership(_)
        ));
        assert!(matches!(vmc.get_w3c_vc_version(), W3CVCVersion::V2_0));
    }

    #[test]
    fn test_vmc_phc_deserialize() {
        let vmc: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2", "https://registry.trustoverip.org/dtg/context/v1"],
                "type": ["VerifiableCredential", "DTGCredential",  "MembershipCredential", "PersonhoodCredential"],
                "issuer": "did:example:community",
                "issuerScope": "public",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:rDid" }
            }"#,
        ) {
            Ok(vmc) => vmc,
            Err(e) => panic!("Couldn't deserialize VMC: {}", e),
        };

        assert!(vmc.is_personhood_credential());
        assert!(matches!(vmc.type_, DTGCredentialType::Membership));
        assert!(matches!(
            vmc.credential().credential_subject,
            CredentialSubject::Membership(_)
        ));
    }

    #[test]
    fn test_vrc_deserialize() {
        let vrc: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2", "https://registry.trustoverip.org/dtg/context/v1"],
                "type": ["VerifiableCredential", "DTGCredential",  "RelationshipCredential"],
                "issuer": "did:example:governmentAgencyDid",
                "issuerScope": "public",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid" }
            }"#,
        ) {
            Ok(vrc) => vrc,
            Err(e) => panic!("Couldn't deserialize VRC: {}", e),
        };

        assert!(matches!(vrc.type_, DTGCredentialType::Relationship));
        assert!(matches!(
            vrc.credential().credential_subject,
            CredentialSubject::Basic(_)
        ));
    }

    #[test]
    fn test_vic_deserialize() {
        let vic: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2", "https://registry.trustoverip.org/dtg/context/v1"],
                "type": ["VerifiableCredential", "DTGCredential",  "InvitationCredential"],
                "issuer": "did:example:governmentAgencyVicDid",
                "issuerScope": "public",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid" }
            }"#,
        ) {
            Ok(vic) => vic,
            Err(e) => panic!("Couldn't deserialize VIC: {}", e),
        };

        assert!(!vic.is_personhood_credential());
        assert!(matches!(vic.type_, DTGCredentialType::Invitation));
        assert!(matches!(
            vic.credential().credential_subject,
            CredentialSubject::Basic(_)
        ));
    }

    #[test]
    fn test_vpc_deserialize() {
        let vpc: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2", "https://registry.trustoverip.org/dtg/context/v1"],
                "type": ["VerifiableCredential", "DTGCredential",  "PersonaCredential"],
                "issuer": "did:example:governmentAgencyDid",
                "issuerScope": "public",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid" }
            }"#,
        ) {
            Ok(vpc) => vpc,
            Err(e) => panic!("Couldn't deserialize VPC: {}", e),
        };

        assert!(matches!(vpc.type_, DTGCredentialType::Persona));
        assert!(matches!(
            vpc.credential().credential_subject,
            CredentialSubject::Basic(_)
        ));
    }

    /// A minimal conformant credential of `type_` with `subject`, for the parse tests below.
    fn doc(type_: &str, scope: &str, subject: Value) -> Value {
        serde_json::json!({
            "@context": [W3C_VC_V2_CONTEXT, DTG_CONTEXT_V1],
            "type": ["VerifiableCredential", "DTGCredential", type_],
            "issuer": "did:example:issuer",
            "issuerScope": scope,
            "validFrom": "2024-06-18T10:00:00Z",
            "credentialSubject": subject,
        })
    }

    fn parse(value: Value) -> Result<DTGCredential, String> {
        serde_json::from_value::<DTGCredential>(value).map_err(|e| e.to_string())
    }

    /// The spec's `dtg:endorses` example parses as a Statement, not as any retired type.
    #[test]
    fn test_vsc_deserialize() {
        let vsc = parse(doc(
            "StatementCredential",
            "directed",
            serde_json::json!({
                "id": "did:example:subject",
                "predicate": ENDORSES_V1,
                "object": { "value": { "type": "SkillEndorsement" } }
            }),
        ))
        .unwrap();

        assert_eq!(vsc.type_(), DTGCredentialType::Statement);
        assert_eq!(vsc.subject(), "did:example:subject");
        assert_eq!(vsc.predicate(), Some(ENDORSES_V1));
        assert_eq!(
            vsc.statement().unwrap().object.value(),
            Some(&serde_json::json!({ "type": "SkillEndorsement" }))
        );
    }

    /// `object` carries exactly one of `id`, `digestMultibase` or `value`.
    #[test]
    fn test_vsc_object_is_exactly_one_member() {
        let with = |object: Value| {
            parse(doc(
                "StatementCredential",
                "directed",
                serde_json::json!({
                    "id": "did:example:subject",
                    "predicate": "https://vtc.example/vocab#p",
                    "object": object
                }),
            ))
        };

        assert!(with(serde_json::json!({ "id": "did:example:thing" })).is_ok());
        assert!(with(serde_json::json!({ "digestMultibase": "zQm" })).is_ok());
        assert!(with(serde_json::json!({ "value": null })).is_ok());

        assert!(with(serde_json::json!({})).is_err(), "no member");
        assert!(
            with(serde_json::json!({ "id": "did:example:a", "value": 1 })).is_err(),
            "two members"
        );
        assert!(
            with(serde_json::json!({ "other": 1 })).is_err(),
            "unknown member"
        );
        assert!(
            with(serde_json::json!({ "id": "not-an-iri" })).is_err(),
            "`object.id` is a DID or other IRI"
        );
    }

    /// A verifier MUST ignore subject members a profile does not define, and a round trip
    /// must keep them or the digest would change.
    #[test]
    fn test_vsc_keeps_unmodelled_subject_members() {
        let wire = doc(
            "StatementCredential",
            "directed",
            serde_json::json!({
                "id": "did:example:subject",
                "predicate": "https://vtc.example/vocab#p",
                "object": { "value": 1 },
                "note": { "added": "by a later profile version" }
            }),
        );
        let vsc = parse(wire.clone()).unwrap();
        assert!(vsc.statement().unwrap().extra.contains_key("note"));
        assert_eq!(
            vsc.digest_multibase().unwrap(),
            digest_multibase_json(&wire).unwrap()
        );
    }

    /// A compact form is malformed, not unknown, and no expansion is performed.
    #[test]
    fn test_vsc_predicate_must_be_an_absolute_nfc_iri() {
        for bad in [
            "dtg:witnessed",
            "witnessed",
            "/dtg/vsc/witnessed/1",
            "https://registry.trustoverip.org/dtg/vsc/witnessed/1 ",
            "https:///no-authority",
            // "e" followed by a combining acute accent: renders as "é", is not NFC.
            "https://vtc.example/vocab#caf\u{0065}\u{0301}",
        ] {
            let result = parse(doc(
                "StatementCredential",
                "public",
                serde_json::json!({
                    "id": "did:example:subject",
                    "predicate": bad,
                    "object": { "value": true }
                }),
            ));
            assert!(result.is_err(), "`{bad}` must be refused");
        }

        for good in [
            WITNESSED_V1,
            "https://vtc.example/vocab/vetting/v1#vetted",
            "https://vtc.example/vocab#caf\u{00e9}",
            "urn:example:predicate:1",
            "did:example:vocab#term",
        ] {
            check_predicate_iri(good).unwrap_or_else(|e| panic!("`{good}`: {e}"));
        }
    }

    /// The core profile constraints hold at parse: `witnessed/1` requires the citation and a
    /// scope of at least `directed`, and names a credential by digest.
    #[test]
    fn test_vsc_witnessed_profile_is_enforced_at_parse() {
        let witnessed = |scope: &str, cited: bool, object: Value| {
            let mut vwc = doc(
                "StatementCredential",
                scope,
                serde_json::json!({
                    "id": "did:example:subject",
                    "predicate": WITNESSED_V1,
                    "object": object,
                    "witnessContext": { "method": "in-person-proximity" }
                }),
            );
            if cited {
                vwc["taskContext"] = serde_json::json!("urn:uuid:session");
                vwc["taskDigestMultibase"] =
                    serde_json::json!("zQmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n");
            }
            serde_json::from_value::<DTGCredential>(vwc)
        };
        let digest = serde_json::json!({ "digestMultibase": "zQmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n" });

        let vwc = witnessed("directed", true, digest.clone()).unwrap();
        assert_eq!(
            vwc.statement()
                .unwrap()
                .witness_context
                .as_ref()
                .unwrap()
                .method
                .as_deref(),
            Some("in-person-proximity")
        );
        assert!(witnessed("public", true, digest.clone()).is_ok());

        assert!(witnessed("pairwise", true, digest.clone()).is_err());
        assert!(witnessed("directed", false, digest.clone()).is_err());
        assert!(witnessed("directed", true, serde_json::json!({ "value": {} })).is_err());

        // Without the digest the citation only names the session, which the profile does
        // not accept either.
        let mut named_only = doc(
            "StatementCredential",
            "directed",
            serde_json::json!({
                "id": "did:example:subject",
                "predicate": WITNESSED_V1,
                "object": digest
            }),
        );
        named_only["taskContext"] = serde_json::json!("urn:uuid:session");
        assert!(matches!(
            parse_err(named_only),
            DTGCredentialError::MissingTaskDigest
        ));
    }

    /// The error a parse fails with, recovered through the model so it can be matched.
    fn parse_err(value: Value) -> DTGCredentialError {
        let mut common: DTGCommon = serde_json::from_value(value).expect("shape parses");
        common.proof = None;
        DTGCredential::try_from(common).expect_err("refused")
    }

    /// Every credential declares `issuerScope`, exactly lowercase.
    #[test]
    fn test_issuer_scope_is_required_and_case_sensitive() {
        let subject = serde_json::json!({ "id": "did:example:subject" });
        for scope in ["pairwise", "directed", "public"] {
            let vrc = parse(doc("RelationshipCredential", scope, subject.clone())).unwrap();
            assert_eq!(vrc.issuer_scope().as_str(), scope);
            assert_eq!(scope.parse::<IssuerScope>().unwrap(), vrc.issuer_scope());
        }

        for scope in ["Public", "PAIRWISE", "community", ""] {
            assert!(
                parse(doc("RelationshipCredential", scope, subject.clone())).is_err(),
                "`{scope}` is not a declaration"
            );
            assert!(scope.parse::<IssuerScope>().is_err());
        }

        let mut missing = doc("RelationshipCredential", "pairwise", subject);
        missing.as_object_mut().unwrap().remove("issuerScope");
        let err = parse(missing).unwrap_err();
        assert!(err.contains("issuerScope"), "{err}");
    }

    /// Narrowest first: a minimum is met by itself and by anything wider.
    #[test]
    fn test_issuer_scope_is_ordered() {
        assert!(IssuerScope::Pairwise < IssuerScope::Directed);
        assert!(IssuerScope::Directed < IssuerScope::Public);
        assert!(IssuerScope::Public.satisfies(IssuerScope::Directed));
        assert!(IssuerScope::Directed.satisfies(IssuerScope::Directed));
        assert!(!IssuerScope::Pairwise.satisfies(IssuerScope::Directed));
        assert_eq!(
            serde_json::to_value(IssuerScope::Directed).unwrap(),
            "directed"
        );
    }

    /// A community's grant can only truthfully declare `public`; the member's
    /// acknowledgement declares whatever the member chose.
    #[test]
    fn test_community_issued_vmc_must_be_public() {
        let grant = |scope| {
            doc(
                "MembershipCredential",
                scope,
                serde_json::json!({ "id": "did:example:member" }),
            )
        };
        assert!(parse(grant("public")).is_ok());
        assert!(matches!(
            parse_err(grant("directed")),
            DTGCredentialError::IssuerScopeTooNarrow {
                declared: IssuerScope::Directed,
                minimum: IssuerScope::Public,
            }
        ));

        let ack = doc(
            "MembershipCredential",
            "pairwise",
            serde_json::json!({
                "id": "did:example:community",
                "digestMultibase": "zQmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n"
            }),
        );
        assert_eq!(parse(ack).unwrap().issuer_scope(), IssuerScope::Pairwise);
    }

    /// The retired subtypes are refused, by name, rather than read as something else.
    #[test]
    fn test_retired_types_are_refused() {
        for (retired, subject) in [
            (
                "EndorsementCredential",
                serde_json::json!({ "id": "did:example:subject", "endorsement": {} }),
            ),
            (
                "WitnessCredential",
                serde_json::json!({ "id": "did:example:subject", "digestMultibase": "zQm" }),
            ),
            (
                "RCardCredential",
                serde_json::json!({ "id": "did:example:subject", "card": [] }),
            ),
        ] {
            let mut vc = doc(retired, "public", subject);
            vc["taskContext"] = serde_json::json!("urn:uuid:session");
            let err = parse(vc).unwrap_err();
            assert!(err.contains(retired), "{retired}: {err}");
        }
    }

    /// Exactly one concrete subtype; `PersonhoodCredential` on a VMC only; nothing unknown.
    #[test]
    fn test_type_array_rules() {
        let subject = serde_json::json!({ "id": "did:example:subject" });
        let with_types = |types: Value| {
            let mut vc = doc("RelationshipCredential", "public", subject.clone());
            vc["type"] = types;
            parse(vc)
        };

        assert!(
            with_types(serde_json::json!([
                "VerifiableCredential",
                "DTGCredential",
                "RelationshipCredential",
                "InvitationCredential"
            ]))
            .is_err(),
            "two concrete subtypes"
        );
        assert!(
            with_types(serde_json::json!([
                "VerifiableCredential",
                "RelationshipCredential"
            ]))
            .is_err(),
            "no DTGCredential"
        );
        assert!(
            with_types(serde_json::json!([
                "VerifiableCredential",
                "DTGCredential",
                "RelationshipCredential",
                "PersonhoodCredential"
            ]))
            .is_err(),
            "the personhood hint belongs on a VMC"
        );
        assert!(
            with_types(serde_json::json!([
                "VerifiableCredential",
                "DTGCredential",
                "RelationshipCredential",
                "SomethingElse"
            ]))
            .is_err(),
            "an undefined type"
        );
        assert!(
            with_types(serde_json::json!([
                "VerifiableCredential",
                "DTGCredential",
                "RelationshipCredential",
                "RelationshipCredential"
            ]))
            .is_err(),
            "listed twice"
        );
    }

    /// The DTG context is listed second, exactly; the pre-v1 context is not recognized.
    #[test]
    fn test_context_rules() {
        let subject = serde_json::json!({ "id": "did:example:subject" });
        let with_context = |context: Value| {
            let mut vc = doc("RelationshipCredential", "public", subject.clone());
            vc["@context"] = context;
            parse(vc)
        };

        assert!(
            with_context(serde_json::json!([
                W3C_VC_V2_CONTEXT,
                DTG_CONTEXT_V1,
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ]))
            .is_ok(),
            "further contexts may follow"
        );
        for bad in [
            serde_json::json!([W3C_VC_V2_CONTEXT]),
            serde_json::json!([DTG_CONTEXT_V1, W3C_VC_V2_CONTEXT]),
            serde_json::json!([
                W3C_VC_V2_CONTEXT,
                "https://firstperson.network/credentials/dtg/v1"
            ]),
            serde_json::json!([
                W3C_VC_V2_CONTEXT,
                "https://www.registry.trustoverip.org/dtg/context/v1"
            ]),
            serde_json::json!([
                W3C_VC_V2_CONTEXT,
                "https://registry.trustoverip.org/dtg/context/v1/"
            ]),
            serde_json::json!([
                W3C_VC_V2_CONTEXT,
                "https://w3id.org/security/suites/ed25519-2020/v1",
                DTG_CONTEXT_V1
            ]),
        ] {
            assert!(with_context(bad.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_deserialize_unknown() {
        match serde_json::from_str::<DTGCredential>(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2", "https://registry.trustoverip.org/dtg/context/v1"],
                "type": ["VerifiableCredential", "DTGCredential"],
                "issuer": "did:example:governmentAgencyDid",
                "issuerScope": "public",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid" }
            }"#,
        ) {
            Ok(_) => panic!("Expected Unknown Credential type"),
            Err(e) => assert_eq!(e.to_string(), "Unknown credential type"),
        };
    }

    /// A subject whose shape does not fit the type is refused rather than coerced.
    #[test]
    fn test_deserialize_mismatched_credential_subject() {
        for (type_, subject) in [
            (
                "StatementCredential",
                serde_json::json!({ "id": "did:example:subject" }),
            ),
            (
                "RelationshipCredential",
                serde_json::json!({ "id": "did:example:s", "predicate": ENDORSES_V1, "object": { "value": 1 } }),
            ),
            (
                "AuthorityCredential",
                serde_json::json!({ "id": "did:example:subject" }),
            ),
        ] {
            assert!(parse(doc(type_, "public", subject)).is_err(), "{type_}");
        }
    }

    #[test]
    fn test_proof_signed() {
        let cred: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2", "https://registry.trustoverip.org/dtg/context/v1"],
                "type": ["VerifiableCredential", "DTGCredential",  "MembershipCredential"],
                "issuer": "did:example:community",
                "issuerScope": "public",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:rDid" },
                "proof": {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "created": "2025-12-04T00:00:00",
                    "verificationMethod": "did:example:test#key-1",
                    "proofPurpose": "assertionMethod",
                    "proofValue": "abcd"
                }
            }"#,
        ) {
            Ok(vmc) => vmc,
            Err(e) => panic!("Couldn't deserialize credential: {}", e),
        };

        assert!(cred.signed());
        assert!(cred.proof_value().is_some());
    }

    #[test]
    fn test_proof_not_signed() {
        let cred = parse(doc(
            "MembershipCredential",
            "public",
            serde_json::json!({ "id": "did:example:rDid" }),
        ))
        .unwrap();

        assert!(!cred.signed());
        assert!(cred.proof_value().is_none());
    }

    #[test]
    fn test_helpers() {
        let cred = parse(doc(
            "MembershipCredential",
            "public",
            serde_json::json!({ "id": "did:example:subject" }),
        ))
        .unwrap();

        assert_eq!(cred.issuer(), "did:example:issuer");
        assert_eq!(cred.issuer_scope(), IssuerScope::Public);
        assert_eq!(cred.subject(), "did:example:subject");
        assert_eq!(
            cred.valid_from()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "2024-06-18T10:00:00Z"
        );
        assert_eq!(cred.valid_until(), None);
    }

    #[test]
    fn test_valid_until() {
        let mut vc = doc(
            "MembershipCredential",
            "public",
            serde_json::json!({ "id": "did:example:subject" }),
        );
        vc["validUntil"] = serde_json::json!("2030-01-01T00:00:00Z");
        let cred = parse(vc).unwrap();

        assert_eq!(
            cred.valid_until()
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "2030-01-01T00:00:00Z"
        );
    }

    #[test]
    fn test_bad_type() {
        assert!(check_type(&["bad_type".to_string()]).is_err());
    }

    /// A model mutated out of shape is refused by `validate`, so it is never signed.
    #[test]
    fn test_badly_constructed_credential_is_refused_by_validate() {
        let mut cred = DTGCredential::new_vrc(
            "did:example:issuer".to_string(),
            IssuerScope::Pairwise,
            "did:example:subject".to_string(),
            Utc::now(),
            None,
        );
        cred.credential_mut().type_[2] = "StatementCredential".to_string();
        assert!(cred.validate().is_err());

        let mut vmc = DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            Utc::now(),
            None,
            false,
        );
        vmc.credential_mut().issuer_scope = IssuerScope::Pairwise;
        assert!(matches!(
            vmc.validate(),
            Err(DTGCredentialError::IssuerScopeTooNarrow { .. })
        ));
    }

    #[test]
    fn test_task_context_round_trip() {
        // taskContext must survive deserialize -> serialize, otherwise a credential signed
        // elsewhere would fail verification here (and vice versa)
        let mut vc = doc(
            "RelationshipCredential",
            "pairwise",
            serde_json::json!({ "id": "did:example:observed" }),
        );
        vc["taskContext"] = serde_json::json!("thread-abc-123");

        let cred = parse(vc).unwrap();
        let out = serde_json::to_string(&cred).unwrap();

        assert!(out.contains(r#""taskContext":"thread-abc-123""#));
    }

    #[test]
    fn test_task_context_optional_on_other_types() {
        // taskContext is OPTIONAL unless a statement's profile requires it
        let vrc = parse(doc(
            "RelationshipCredential",
            "pairwise",
            serde_json::json!({ "id": "did:example:subject" }),
        ))
        .unwrap();

        assert_eq!(vrc.task_context(), None);
        // and it is omitted from the serialization entirely when absent
        assert!(!serde_json::to_string(&vrc).unwrap().contains("taskContext"));

        let vec = parse(doc(
            "StatementCredential",
            "pairwise",
            serde_json::json!({
                "id": "did:example:subject",
                "predicate": ENDORSES_V1,
                "object": { "value": "a good egg" }
            }),
        ))
        .unwrap();
        assert_eq!(vec.task_context(), None);
    }

    #[test]
    fn test_digest_multibase() {
        let vrc = DTGCredential::new_vrc(
            "did:example:issuer".to_string(),
            IssuerScope::Pairwise,
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
        );

        let digest = vrc.digest_multibase().unwrap();

        // base58btc multibase prefix
        assert!(digest.starts_with('z'));

        // decodes to a sha2-256 multihash: 0x12 0x20 followed by 32 digest bytes
        let (base, bytes) = multibase::decode(&digest).unwrap();
        assert_eq!(base, multibase::Base::Base58Btc);
        assert_eq!(bytes.len(), 34);
        assert_eq!(&bytes[..2], &[0x12, 0x20]);

        // stable across calls
        assert_eq!(digest, vrc.digest_multibase().unwrap());

        // and distinct for a different credential
        let other = DTGCredential::new_vrc(
            "did:example:issuer".to_string(),
            IssuerScope::Pairwise,
            "did:example:someone-else".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
        );
        assert_ne!(digest, other.digest_multibase().unwrap());
    }

    #[test]
    fn test_verify_digest() {
        let valid_from = DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let vrc = DTGCredential::new_vrc(
            "did:example:issuer".to_string(),
            IssuerScope::Pairwise,
            "did:example:subject".to_string(),
            valid_from,
            None,
        );

        let session = serde_json::json!({
            "id": "urn:uuid:session",
            "type": "https://trusttasks.org/spec/witness/session/0.1",
            "threadId": "urn:uuid:session",
        });
        let vwc = DTGCredential::new_witnessed_vsc(
            "did:example:witness".to_string(),
            IssuerScope::Public,
            &serde_json::to_value(&vrc).unwrap(),
            &session,
            valid_from,
            None,
            None,
        )
        .unwrap();
        // the DID of the issuer of the VRC being attested
        assert_eq!(vwc.subject(), "did:example:issuer");

        assert!(vwc.verify_digest(&vrc).unwrap());

        // a different VRC must not match
        let other = DTGCredential::new_vrc(
            "did:example:issuer".to_string(),
            IssuerScope::Pairwise,
            "did:example:someone-else".to_string(),
            valid_from,
            None,
        );
        assert!(!vwc.verify_digest(&other).unwrap());
    }

    #[test]
    fn test_verify_digest_without_digest() {
        let valid_from = DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let vrc = DTGCredential::new_vrc(
            "did:example:issuer".to_string(),
            IssuerScope::Pairwise,
            "did:example:subject".to_string(),
            valid_from,
            None,
        );

        // A statement whose object is not a digest references nothing to rely on
        let vec = DTGCredential::new_endorses_vsc(
            "did:example:peer".to_string(),
            IssuerScope::Directed,
            "did:example:issuer".to_string(),
            serde_json::json!({ "skill": "chess" }),
            valid_from,
            None,
        )
        .unwrap();
        assert_eq!(vec.subject_digest(), None);
        let vwc = vec;

        assert!(!vwc.verify_digest(&vrc).unwrap());
    }

    /// The digest encoding is the interoperability surface: a credential referencing another
    /// is compared against a value some other implementation produced. Pinned against a
    /// literal rather than a recomputation, because a test that recomputes agrees with
    /// whatever the code does and would follow the encoding silently if it drifted.
    #[test]
    fn test_digest_is_a_base58btc_multihash_over_the_proofless_jcs_form() {
        let vmc = DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            false,
        )
        .with_id("urn:uuid:2a4e1d90-6e0c-4d3f-9a4a-6d0a8f7c1b52");

        let digest = vmc.digest_multibase().unwrap();

        // Multibase base58btc.
        assert!(digest.starts_with('z'), "multibase base58btc prefix");

        // Decodes to a sha2-256 multihash: 0x12 0x20 followed by 32 digest bytes.
        let (base, bytes) = multibase::decode(&digest).unwrap();
        assert_eq!(base, Base::Base58Btc);
        assert_eq!(bytes.len(), 34);
        assert_eq!(&bytes[..2], &[0x12, 0x20]);

        // Computed outside this crate over the JCS canonical form of the document below,
        // then wrapped per CID v1.0 §2.4-2.5:
        //   {"@context":[...],"credentialSubject":{"id":"did:example:member"},
        //    "id":"urn:uuid:2a4e...","issuer":"did:example:community",
        //    "issuerScope":"public","type":[...],"validFrom":"2025-12-11T00:00:00Z"}
        // whose SHA-256 is efcb1e1022a5dbfd35af908d18ed7cc20af00cef049bd83d8ff955b97f4d07fe.
        assert_eq!(digest, "zQmeUhnd33Xp8egdUiQjPCVgANMXKSL7Nt5sCZbkcs2h2A1");

        // Stable across calls.
        assert_eq!(digest, vmc.digest_multibase().unwrap());
    }

    /// The superseded encoding still produces what it always did, so a caller migrating can
    /// recompute a Working Draft 01 digest to compare against one they stored.
    #[test]
    #[allow(deprecated)]
    fn the_superseded_hex_digest_is_unchanged() {
        let vmc = DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            false,
        )
        .with_id("urn:uuid:2a4e1d90-6e0c-4d3f-9a4a-6d0a8f7c1b52");

        assert_eq!(
            vmc.digest().unwrap(),
            "sha256:efcb1e1022a5dbfd35af908d18ed7cc20af00cef049bd83d8ff955b97f4d07fe"
        );
    }

    /// A Working Draft 01 digest reaching a Working Draft 02 verifier is *reported*, not
    /// silently treated as a mismatch. The two say different things: one is a credential
    /// that disagrees, the other a credential that cannot be read at all.
    #[test]
    fn a_superseded_digest_value_is_rejected_as_malformed() {
        let err = decode_digest_multibase(
            "sha256:49c9d5135ab4b5659a343bc79d351e37d64f05add58408cae6eef022828495c2",
        )
        .unwrap_err();

        assert!(
            matches!(err, DTGCredentialError::InvalidDigest(_)),
            "expected InvalidDigest, got {err:?}"
        );
    }

    /// Digests are compared as decoded bytes, never as strings — the specification requires
    /// it, because one digest has more than one spelling.
    #[test]
    fn digests_are_compared_by_bytes_not_by_string() {
        // The same sha2-256 multihash, encoded base58btc and base16. Identical bytes,
        // different strings.
        let multihash = {
            let mut v = vec![0x12u8, 0x20];
            v.extend_from_slice(&Sha256::digest(b"an edge credential"));
            v
        };
        let b58 = multibase::encode(Base::Base58Btc, &multihash);
        let b16 = multibase::encode(Base::Base16Lower, &multihash);

        assert_ne!(b58, b16, "the two spellings differ as strings");
        assert!(
            digests_match(&b58, &b16).unwrap(),
            "but name the same digest"
        );
    }

    /// An algorithm the library does not implement is *rejected*, not reported as a
    /// mismatch. A verifier that conflated the two would silently downgrade a governing
    /// party's choice of a stronger hash into a failed comparison.
    #[test]
    fn an_unaccepted_hash_algorithm_is_rejected_rather_than_mismatched() {
        // 0x13 is sha2-512 in the multicodec table.
        let mut multihash = vec![0x13u8, 0x40];
        multihash.extend_from_slice(&[0u8; 64]);
        let encoded = multibase::encode(Base::Base58Btc, &multihash);

        assert!(matches!(
            decode_digest_multibase(&encoded),
            Err(DTGCredentialError::UnsupportedDigestAlgorithm(0x13))
        ));
    }

    /// The digest binds to what a credential says, not to a signature over it, so a
    /// re-proofed credential still satisfies a reference made against the earlier one. This
    /// is what lets a member's acknowledgement survive the community re-signing its grant.
    #[cfg(feature = "affinidi-signing")]
    #[tokio::test]
    async fn test_digest_is_unchanged_by_signing() {
        use affinidi_secrets_resolver::secrets::Secret;

        let secret = Secret::generate_ed25519(None, None);

        let mut vmc = DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            Utc::now(),
            None,
            false,
        );

        let before = vmc.digest_multibase().unwrap();
        vmc.sign(&secret, None).await.expect("signs");
        assert!(vmc.signed());
        assert_eq!(before, vmc.digest_multibase().unwrap());
    }

    /// A grant in the wire form a member actually receives.
    fn wire(c: &DTGCredential) -> Value {
        serde_json::to_value(c.credential()).expect("credential serialises")
    }

    /// The whole point of the pair: a grant and the acknowledgement built from it form a
    /// complete membership edge, and the parties are mirrored across the two halves.
    #[test]
    fn test_member_vmc_acknowledges_its_grant() {
        let valid_from = DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let grant = DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            valid_from,
            None,
            false,
        );

        let ack = DTGCredential::new_member_vmc_for(
            &wire(&grant),
            "did:example:member",
            IssuerScope::Directed,
            valid_from,
            None,
        )
        .expect("builds");

        // Roles reversed.
        assert_eq!(ack.issuer(), "did:example:member");
        assert_eq!(ack.subject(), "did:example:community");

        // The grant MUST omit the digest; the acknowledgement MUST carry it.
        assert_eq!(grant.subject_digest(), None);
        assert_eq!(
            ack.subject_digest(),
            Some(grant.digest_multibase().unwrap().as_str())
        );

        assert!(ack.acknowledges(&grant).unwrap());
    }

    /// An acknowledgement completes the edge it names and no other. Each case below verifies
    /// as a credential in its own right; what fails is the binding.
    #[test]
    fn test_acknowledges_rejects_a_mismatched_pair() {
        let valid_from = DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let grant = DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            valid_from,
            None,
            false,
        );
        let ack = DTGCredential::new_member_vmc_for(
            &wire(&grant),
            "did:example:member",
            IssuerScope::Directed,
            valid_from,
            None,
        )
        .expect("builds");

        // A grant to a different member: right community, wrong edge.
        let other_member = DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:someone-else".to_string(),
            valid_from,
            None,
            false,
        );
        assert!(!ack.acknowledges(&other_member).unwrap());

        // A grant from a different community.
        let other_community = DTGCredential::new_vmc(
            "did:example:other-community".to_string(),
            "did:example:member".to_string(),
            valid_from,
            None,
            false,
        );
        assert!(!ack.acknowledges(&other_community).unwrap());

        // A re-issued grant to the same member — different claims, so a different digest.
        // This is what forces re-acknowledgement on renewal rather than letting a stale
        // consent carry over to a membership the member never agreed to.
        let renewed = DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            valid_from + chrono::Duration::days(365),
            None,
            false,
        );
        assert!(!ack.acknowledges(&renewed).unwrap());

        // The acknowledgement is not itself a grant: acknowledging one forms no edge.
        let ack_of_ack = DTGCredential::new_member_vmc_for(
            &wire(&grant),
            "did:example:member",
            IssuerScope::Directed,
            valid_from,
            None,
        )
        .expect("builds");
        assert!(!ack_of_ack.acknowledges(&ack).unwrap());

        // A grant on its own does not complete anything — it carries no digest to check.
        assert!(!grant.acknowledges(&grant).unwrap());
    }

    /// A VDC's `credentialStatus` is CONDITIONAL, not required: a delegation whose validity
    /// exceeds the freshness window the governing VTC or VTN defines MUST carry one, and
    /// one short enough to be bounded by expiry alone MAY omit it. This library does not
    /// know that window, so the entry is attached rather than demanded — and once attached,
    /// it must reach the wire.
    #[test]
    fn a_vdc_carries_the_credential_status_it_is_given() {
        let valid_from = DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let valid_until = DateTime::parse_from_rfc3339("2026-12-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let status = serde_json::json!({
            "id": "https://delegator.example/status#12",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": "12"
        });

        let vdc = DTGCredential::new_vdc(
            "did:example:delegator".to_string(),
            IssuerScope::Directed,
            "did:example:delegate".to_string(),
            valid_from,
            valid_until,
            vec!["sign:invoices".to_string()],
            None,
        )
        .expect("a bounded grant is well formed");

        // Omitting it is legitimate, so the constructor must not invent one.
        assert!(
            vdc.credential().credential_status.is_none(),
            "a VDC MAY omit `credentialStatus`, so the constructor must not supply one"
        );

        let vdc = vdc.with_credential_status(status.clone());
        assert_eq!(vdc.credential().credential_status.as_ref(), Some(&status));
        assert_eq!(wire(&vdc).get("credentialStatus"), Some(&status));

        // And it must survive the trip back, or a verifier reading the wire form loses the
        // only thing that lets it check revocation.
        let parsed: DTGCredential = serde_json::from_value(wire(&vdc)).expect("parses");
        assert_eq!(
            parsed.credential().credential_status.as_ref(),
            Some(&status)
        );
    }

    /// The non-consuming form sets the same field.
    #[test]
    fn set_credential_status_matches_the_builder() {
        let status = serde_json::json!({ "type": "BitstringStatusListEntry" });

        let mut vmc = DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            Utc::now(),
            None,
            false,
        );
        vmc.set_credential_status(status.clone());

        assert_eq!(vmc.credential().credential_status.as_ref(), Some(&status));
    }

    /// `DTGCredentialType` derives `PartialEq` so a consumer can assert by equality rather
    /// than by pattern, and get the actual variant reported on failure.
    #[test]
    fn credential_types_compare_by_equality() {
        let vdc = DTGCredential::new_vdc(
            "did:example:delegator".to_string(),
            IssuerScope::Directed,
            "did:example:delegate".to_string(),
            Utc::now(),
            Utc::now() + chrono::Duration::days(1),
            vec!["sign:invoices".to_string()],
            None,
        )
        .expect("a bounded grant is well formed");

        assert_eq!(vdc.type_(), DTGCredentialType::Delegation);
        assert_ne!(vdc.type_(), DTGCredentialType::Membership);
    }

    /// `credentialStatus` used to be dropped by a parse-then-re-serialise round trip, which
    /// silently changed a credential's digest. [`DTGCommon::credential_status`] models it,
    /// and this pins that it survives.
    #[test]
    fn credential_status_survives_a_round_trip() {
        let valid_from = DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let mut grant = wire(&DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            valid_from,
            None,
            false,
        ));
        let status = serde_json::json!({
            "id": "https://community.example/status#7",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": "7"
        });
        grant["credentialStatus"] = status.clone();

        let parsed: DTGCredential = serde_json::from_value(grant.clone()).expect("parses");
        assert_eq!(
            parsed.credential().credential_status.as_ref(),
            Some(&status)
        );
        assert_eq!(wire(&parsed).get("credentialStatus"), Some(&status));
        assert_eq!(
            parsed.digest_multibase().unwrap(),
            digest_multibase_json(&grant).unwrap(),
            "the digest must not change under a round trip that preserves every member"
        );
    }

    /// Top-level members this library does not model at all are preserved too, by
    /// [`DTGCommon::extra`]. `credentialSchema` stands in for the open set of them.
    #[test]
    fn unmodelled_top_level_members_survive_a_round_trip() {
        let valid_from = DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let mut grant = wire(&DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            valid_from,
            None,
            false,
        ));
        let schema = serde_json::json!({
            "id": "https://community.example/schemas/vmc",
            "type": "JsonSchema"
        });
        grant["credentialSchema"] = schema.clone();

        let parsed: DTGCredential = serde_json::from_value(grant.clone()).expect("parses");
        assert_eq!(
            parsed.credential().extra.get("credentialSchema"),
            Some(&schema)
        );
        assert_eq!(
            parsed.digest_multibase().unwrap(),
            digest_multibase_json(&grant).unwrap()
        );
    }

    /// # Why the wire form is still what gets digested
    ///
    /// [`DTGCommon::extra`] closed the dropped-member hazard, but not the whole of it. A
    /// timestamp is *normalized* on the way out — `2025-12-11T00:00:00.000+00:00` and
    /// `2025-12-11T00:00:00Z` are the same instant and parse to the same
    /// [`chrono::DateTime`], and this library re-serializes both as the latter. The
    /// document that comes back out is therefore equivalent to the one that went in, and
    /// hashes differently.
    ///
    /// An acknowledgement built by digesting the *parsed* grant would carry a digest over a
    /// document the community never issued, and the community would rightly refuse it.
    /// Silently: both credentials verify, and only the digest comparison fails, with
    /// nothing to say why.
    ///
    /// So `new_member_vmc` takes the wire form, and this pins that it digests what it was
    /// handed rather than what it could parse.
    #[test]
    fn the_acknowledgement_digests_the_grant_as_it_arrived() {
        let valid_from = DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let mut grant = wire(&DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            valid_from,
            None,
            false,
        ));
        // The same instant, spelled the way another implementation might.
        grant["validFrom"] = Value::String("2025-12-11T00:00:00.000+00:00".to_string());

        // The parse normalizes it — this is the hazard, asserted rather than assumed.
        let parsed: DTGCredential = serde_json::from_value(grant.clone()).expect("parses");
        assert_ne!(
            wire(&parsed).get("validFrom"),
            grant.get("validFrom"),
            "the model is expected to normalize the timestamp; if it now round-trips \
             verbatim, this test has stopped guarding anything"
        );

        let ack = DTGCredential::new_member_vmc_for(
            &grant,
            "did:example:member",
            IssuerScope::Directed,
            valid_from,
            None,
        )
        .expect("builds");

        assert_eq!(
            ack.subject_digest(),
            Some(digest_multibase_json(&grant).unwrap().as_str()),
            "the acknowledgement must digest the grant as received"
        );
        assert_ne!(
            ack.subject_digest(),
            Some(parsed.digest_multibase().unwrap().as_str()),
            "digesting the parsed model would produce a digest the community cannot match"
        );
    }

    #[test]
    fn digest_multibase_json_agrees_with_digest_where_the_model_is_complete() {
        let vmc = DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            false,
        )
        .with_id("urn:uuid:2a4e1d90-6e0c-4d3f-9a4a-6d0a8f7c1b52");

        assert_eq!(
            vmc.digest_multibase().unwrap(),
            digest_multibase_json(&wire(&vmc)).unwrap()
        );
    }

    /// `acknowledges` answers only about VMC pairs. A VRC edge is completed by its own
    /// reciprocal, not by this.
    #[test]
    fn test_acknowledges_is_membership_only() {
        let valid_from = DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let grant = DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            valid_from,
            None,
            false,
        );
        let ack = DTGCredential::new_member_vmc_for(
            &wire(&grant),
            "did:example:member",
            IssuerScope::Directed,
            valid_from,
            None,
        )
        .expect("builds");

        let vrc = DTGCredential::new_vrc(
            "did:example:member".to_string(),
            IssuerScope::Pairwise,
            "did:example:community".to_string(),
            valid_from,
            None,
        );
        assert!(!ack.acknowledges(&vrc).unwrap());

        // And a VWC bound to the grant is a witness attestation, not a member's consent.
        let vwc = DTGCredential::new_witnessed_vsc(
            "did:example:witness".to_string(),
            IssuerScope::Public,
            &wire(&grant),
            &serde_json::json!({
                "id": "urn:uuid:session",
                "type": "https://trusttasks.org/spec/witness/session/0.1",
                "threadId": "urn:uuid:session",
            }),
            valid_from,
            None,
            None,
        )
        .unwrap();
        assert!(vwc.verify_digest(&grant).unwrap(), "the digest does match");
        assert!(
            !vwc.acknowledges(&grant).unwrap(),
            "but a VWC is not the member's acknowledgement"
        );
    }

    /// A grant built against something that cannot be one is refused at construction, where
    /// the caller can still do something about it — rather than producing an acknowledgement
    /// that verifies as a credential and completes no edge.
    #[test]
    fn test_new_member_vmc_refuses_a_non_grant() {
        let valid_from = DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let vrc = DTGCredential::new_vrc(
            "did:example:a".to_string(),
            IssuerScope::Pairwise,
            "did:example:b".to_string(),
            valid_from,
            None,
        );
        assert!(matches!(
            DTGCredential::new_member_vmc_for(
                &wire(&vrc),
                "did:example:b",
                IssuerScope::Directed,
                valid_from,
                None
            ),
            Err(DTGCredentialError::NotAMembershipGrant(_))
        ));

        let grant = DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            valid_from,
            None,
            false,
        );
        let ack = DTGCredential::new_member_vmc_for(
            &wire(&grant),
            "did:example:member",
            IssuerScope::Directed,
            valid_from,
            None,
        )
        .expect("builds");
        assert!(matches!(
            DTGCredential::new_member_vmc_for(
                &wire(&ack),
                "did:example:community",
                IssuerScope::Directed,
                valid_from,
                None,
            ),
            Err(DTGCredentialError::NotAMembershipGrant(_))
        ));
    }

    /// `{ id, digestMultibase }` is the member-issued half, and lands on `Membership`
    /// directly — no other subject shape has a top-level `digestMultibase` to compete for it.
    #[test]
    fn test_member_issued_vmc_deserializes_as_membership_not_witness() {
        let vmc: DTGCredential = serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2", "https://registry.trustoverip.org/dtg/context/v1"],
                "type": ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
                "issuer": "did:example:member",
                "issuerScope": "directed",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": {
                    "id": "did:example:community",
                    "digestMultibase": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                }
            }"#,
        )
        .expect("deserializes");

        assert!(matches!(vmc.type_, DTGCredentialType::Membership));
        assert!(matches!(
            vmc.credential().credential_subject,
            CredentialSubject::Membership(_)
        ));
        assert_eq!(
            vmc.subject_digest(),
            Some("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(vmc.subject(), "did:example:community");
    }

    /// `witnessContext` belongs to a `witnessed/1` statement. A VMC carrying one is malformed
    /// rather than merely surprising, and is refused instead of being silently read as a grant.
    #[test]
    fn test_membership_credential_rejects_a_witness_context() {
        let result: Result<DTGCredential, _> = serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2", "https://registry.trustoverip.org/dtg/context/v1"],
                "type": ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
                "issuer": "did:example:member",
                "issuerScope": "public",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": {
                    "id": "did:example:community",
                    "digestMultibase": "sha256:e3b0c4",
                    "witnessContext": { "event": "not a membership property" }
                }
            }"#,
        );
        assert!(result.is_err());
    }

    /// The two halves must be distinguishable on the wire by `digestMultibase` alone — that is the
    /// only discriminator where both endpoints are C-DIDs, as in VTN membership.
    #[test]
    fn test_the_two_halves_round_trip_over_the_wire() {
        let valid_from = DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let grant = DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            valid_from,
            None,
            false,
        );
        let ack = DTGCredential::new_member_vmc_for(
            &wire(&grant),
            "did:example:member",
            IssuerScope::Directed,
            valid_from,
            None,
        )
        .expect("builds");

        let grant_json = serde_json::to_value(&grant).unwrap();
        assert!(
            grant_json["credentialSubject"]
                .get("digestMultibase")
                .is_none(),
            "the grant MUST omit `digestMultibase`: {grant_json}"
        );

        let ack_json = serde_json::to_value(&ack).unwrap();
        assert_eq!(
            ack_json["credentialSubject"]["digestMultibase"],
            Value::String(grant.digest_multibase().unwrap()),
        );

        // And the pair still binds after a round trip through JSON, which is how each side
        // actually receives the other's half.
        let grant: DTGCredential = serde_json::from_value(grant_json).expect("grant round trips");
        let ack: DTGCredential = serde_json::from_value(ack_json).expect("ack round trips");
        assert!(ack.acknowledges(&grant).unwrap());
    }

    #[test]
    fn test_iso8601_format_option() {
        let now: DateTime<Utc> = DateTime::parse_from_rfc3339(
            &Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        )
        .unwrap()
        .to_utc();
        let vrc = |valid_until| {
            DTGCredential::new_vrc(
                "did:example:issuer".to_string(),
                IssuerScope::Pairwise,
                "did:example:subject".to_string(),
                now,
                valid_until,
            )
        };

        let value = serde_json::to_value(vrc(Some(now + chrono::Duration::days(1)))).unwrap();
        let cred2: DTGCommon = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(cred2.valid_until, Some(now + chrono::Duration::days(1)));

        let value = serde_json::to_value(vrc(None)).unwrap();
        let cred2: DTGCommon = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(cred2.valid_until, None);
    }

    #[cfg(feature = "affinidi-signing")]
    #[tokio::test]
    async fn test_signing() {
        use affinidi_secrets_resolver::secrets::Secret;

        let secret = Secret::generate_ed25519(None, None);

        let mut cred = DTGCredential::new_vrc(
            "did:example:issuer".to_string(),
            IssuerScope::Pairwise,
            "did:example:subject".to_string(),
            Utc::now(),
            None,
        );

        assert!(cred.sign(&secret, Some(Utc::now())).await.is_ok());

        assert!(
            cred.verify_proof_with_public_key(secret.get_public_bytes())
                .is_ok()
        );

        let secret2 = Secret::generate_ed25519(None, None);
        assert!(
            cred.verify_proof_with_public_key(secret2.get_public_bytes())
                .is_err()
        );
    }

    /// The proof covers `id`, so it must be set *before* signing.
    ///
    /// This is the property that makes [DTGCredential::with_id]'s "set it before signing"
    /// caveat load-bearing rather than advisory: a credential signed without an identifier
    /// cannot be given one afterwards to satisfy a verifier that requires it, because the
    /// document that was signed did not contain it. Tampering with `id` after the fact is
    /// the same operation, and must fail the same way.
    #[cfg(feature = "affinidi-signing")]
    #[tokio::test]
    async fn test_id_is_covered_by_the_proof() {
        use affinidi_secrets_resolver::secrets::Secret;

        let secret = Secret::generate_ed25519(None, None);

        let mut cred = DTGCredential::new_vrc(
            "did:example:issuer".to_string(),
            IssuerScope::Pairwise,
            "did:example:subject".to_string(),
            Utc::now(),
            None,
        )
        .with_id("urn:uuid:1e2d3c4b-5a69-4788-9099-aabbccddeeff");

        cred.sign(&secret, Some(Utc::now()))
            .await
            .expect("signing a credential that carries an id");
        assert!(
            cred.verify_proof_with_public_key(secret.get_public_bytes())
                .is_ok(),
            "an id set before signing verifies"
        );

        // Changing the id after signing — which is what "splice an id into the JSON on the
        // way out" amounts to — invalidates the proof.
        cred.set_id("urn:uuid:00000000-0000-0000-0000-000000000000");
        assert!(
            cred.verify_proof_with_public_key(secret.get_public_bytes())
                .is_err(),
            "an id changed after signing must break the proof"
        );
    }

    #[cfg(feature = "affinidi-signing")]
    #[tokio::test]
    async fn test_signing_error() {
        use affinidi_secrets_resolver::secrets::Secret;

        let secret = Secret::generate_x25519(None, None).unwrap();

        let mut cred = DTGCredential::new_vrc(
            "did:example:issuer".to_string(),
            IssuerScope::Pairwise,
            "did:example:subject".to_string(),
            Utc::now(),
            None,
        );

        assert!(cred.sign(&secret, Some(Utc::now())).await.is_err());
    }

    #[cfg(feature = "affinidi-signing")]
    #[test]
    fn test_signing_no_proof() {
        use crate::DTGCredentialError;
        use affinidi_secrets_resolver::secrets::Secret;

        let cred = DTGCredential::new_vrc(
            "did:example:issuer".to_string(),
            IssuerScope::Pairwise,
            "did:example:subject".to_string(),
            Utc::now(),
            None,
        );

        let secret = Secret::generate_ed25519(None, None);
        match cred.verify_proof_with_public_key(secret.get_public_bytes()) {
            Err(DTGCredentialError::NotSigned) => {
                // Good
            }
            _ => panic!("Expected NotSigned error!"),
        }
    }

    /// The constructors that return a plain `Self` have no way to refuse a malformed
    /// window, so `validate` is where one is caught for them.
    #[test]
    fn validate_refuses_an_inverted_window() {
        let from = DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let vmc = |valid_from, valid_until| {
            DTGCredential::new_vmc(
                "did:example:community".to_string(),
                "did:example:member".to_string(),
                valid_from,
                valid_until,
                false,
            )
        };

        assert!(matches!(
            vmc(from, Some(from - chrono::Duration::hours(1))).validate(),
            Err(DTGCredentialError::InvalidValidityWindow { .. })
        ));
        assert!(matches!(
            vmc(from, Some(from)).validate(),
            Err(DTGCredentialError::InvalidValidityWindow { .. })
        ));

        // Open-ended, and backdated, are both well formed.
        assert!(vmc(from, None).validate().is_ok());
        assert!(
            vmc(from - chrono::Duration::days(3650), Some(from))
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn new_member_vmc_refuses_an_inverted_window() {
        let from = DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let grant = DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            from,
            None,
            false,
        );

        assert!(matches!(
            DTGCredential::new_member_vmc_for(
                &wire(&grant),
                "did:example:member",
                IssuerScope::Directed,
                from,
                Some(from - chrono::Duration::hours(1)),
            ),
            Err(DTGCredentialError::InvalidValidityWindow { .. })
        ));
    }

    /// `sign` runs `validate` first, so this library never puts a proof on a credential
    /// whose window is never open.
    #[cfg(feature = "affinidi-signing")]
    #[tokio::test]
    async fn sign_refuses_an_inverted_window() {
        use affinidi_secrets_resolver::secrets::Secret;

        let secret = Secret::generate_ed25519(None, None);
        let mut vrc = DTGCredential::new_vrc(
            "did:example:issuer".to_string(),
            IssuerScope::Pairwise,
            "did:example:subject".to_string(),
            Utc::now(),
            Some(Utc::now() - chrono::Duration::days(1)),
        );

        assert!(matches!(
            vrc.sign(&secret, None).await,
            Err(DTGCredentialError::InvalidValidityWindow { .. })
        ));
        assert!(!vrc.signed(), "a refused credential must not carry a proof");
    }
}
