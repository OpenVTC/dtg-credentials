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
use thiserror::Error;

pub mod authority;
pub mod create;
pub mod delegation;

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
#[derive(Error, Debug)]
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

    /// A WitnessCredential (VWC) was missing the REQUIRED `taskContext` property
    #[error("WitnessCredential is missing the required taskContext property")]
    MissingTaskContext,

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
}

/// Defined DTG Credentials
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(try_from = "DTGCommon")]
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

    /// The `threadId` of the trust task exchange this credential was issued in, if set
    ///
    /// This is always `Some` for [DTGCredentialType::Witness] credentials, where the spec
    /// makes `taskContext` REQUIRED.
    pub fn task_context(&self) -> Option<&str> {
        self.credential.task_context()
    }

    /// This credential's digest, in the encoding a credential that references it carries —
    /// a member-issued VMC acknowledging a membership grant, a VWC attesting an edge
    /// credential, or the `parent` of an attenuated VAC.
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
    /// `Some` for a member-issued VMC (which MUST carry one), for a VWC bound to the edge
    /// credential it attests, for an attenuated VAC (`authority.parent`), and for a
    /// derived or accepting VDC (`delegation.parent` / `delegation.accepts`). `None` for a
    /// community-issued VMC, which MUST omit it, and for a credential that references
    /// nothing.
    pub fn subject_digest(&self) -> Option<&str> {
        match &self.credential.credential_subject {
            CredentialSubject::Membership(subject) => subject.digest_multibase.as_deref(),
            CredentialSubject::Witness(subject) => subject.digest_multibase.as_deref(),
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
    /// - No open JSON member — `endorsement`, `credentialStatus`, an unmodelled top-level
    ///   member — takes the document past [`MAX_JSON_DEPTH`]
    ///   ([DTGCredentialError::JsonTooDeep]). The check does not recurse.
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
        self.credential.check_depth()
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
/// value inside an object or array is one deeper than its container. A VEC's `endorsement`
/// therefore sits at depth 3, and a top-level member such as `credentialStatus` at depth 2.
///
/// # Why there is a bound
///
/// Digesting, signing and verifying clone, serialize and canonicalize a credential, and each
/// of those recurses once per level of nesting. A value nested a few thousand levels deep
/// exhausts the stack, and a stack overflow aborts the process — it is not an error a caller
/// can handle. The members this library holds as open JSON are where such a value gets in:
/// a VEC's `endorsement`, `credentialStatus`, and the unmodelled members in
/// [`DTGCommon::extra`].
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
/// `digestMultibase` of the grant it acknowledges, the VWC's of the edge credential it
/// attests, an attenuated VAC's `authority.parent`, and a VDC's `delegation.parent` and
/// `delegation.accepts`.
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

/// TDG VC Type Identifiers
///
/// `PartialEq` is derived so that a consumer can assert by equality
/// (`assert_eq!(cred.credential_type(), &DTGCredentialType::Delegation)`) rather than by
/// pattern (`matches!`), which reports the actual variant on failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DTGCredentialType {
    Membership,
    Relationship,
    Invitation,
    Persona,
    Endorsement,
    Witness,

    /// Verifiable Authority Credential (VAC) — confers authority on a party to perform
    /// specified actions within a named scope governed by the issuer.
    ///
    /// Merged into DTG Core Credentials at Working Draft 02
    /// (`trustoverip/dtgwg-cred-spec` PR #29). Key control at invocation — a VAC is not a
    /// bearer credential — is implemented in [crate::authority::verify_chain], ahead of
    /// PR #41 which states it normatively and removes the `audience` property it made
    /// redundant. Two further changes are in flight and not implemented here: revocation
    /// (PR #39) and a `maxAttenuation` ceiling (PR #40).
    Authority,

    /// Verifiable Delegation Credential (VDC) — establishes that one entity may act in
    /// another's name.
    ///
    /// Merged into DTG Core Credentials at Working Draft 02
    /// (`trustoverip/dtgwg-cred-spec` PR #19).
    Delegation,

    /// R-Card is no longer a DTG credential type.
    #[deprecated(
        since = "0.2.0",
        note = "The r-card is a verifiable data structure (VDS), not a DTGCredential subtype. \
                It was removed from the DTG Core Credentials specification in Working Draft 01 \
                and will be defined by the planned DTG Verifiable Data Structures specification. \
                This variant will be removed in a future release."
    )]
    RCard,
}

impl Display for DTGCredentialType {
    #[allow(deprecated)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DTGCredentialType::Membership => write!(f, "MembershipCredential"),
            DTGCredentialType::Relationship => write!(f, "RelationshipCredential"),
            DTGCredentialType::Invitation => write!(f, "InvitationCredential"),
            DTGCredentialType::Persona => write!(f, "PersonaCredential"),
            DTGCredentialType::Endorsement => write!(f, "EndorsementCredential"),
            DTGCredentialType::Witness => write!(f, "WitnessCredential"),
            DTGCredentialType::Authority => write!(f, "AuthorityCredential"),
            DTGCredentialType::Delegation => write!(f, "DelegationCredential"),
            DTGCredentialType::RCard => write!(f, "RCardCredential"),
        }
    }
}

/// This helps with matching the right credential type to the [DTGCredentialType]
const DTG_TYPES: [&str; 9] = [
    "MembershipCredential",
    "RelationshipCredential",
    "InvitationCredential",
    "PersonaCredential",
    "EndorsementCredential",
    "WitnessCredential",
    "AuthorityCredential",
    "DelegationCredential",
    "RCardCredential",
];

impl TryFrom<&[String]> for DTGCredentialType {
    type Error = DTGCredentialError;

    #[allow(deprecated)]
    fn try_from(types: &[String]) -> Result<Self, Self::Error> {
        if let Some(type_) = DTG_TYPES.iter().find(|t| types.contains(&t.to_string())) {
            match *type_ {
                "MembershipCredential" => Ok(DTGCredentialType::Membership),
                "RelationshipCredential" => Ok(DTGCredentialType::Relationship),
                "InvitationCredential" => Ok(DTGCredentialType::Invitation),
                "PersonaCredential" => Ok(DTGCredentialType::Persona),
                "EndorsementCredential" => Ok(DTGCredentialType::Endorsement),
                "WitnessCredential" => Ok(DTGCredentialType::Witness),
                "AuthorityCredential" => Ok(DTGCredentialType::Authority),
                "DelegationCredential" => Ok(DTGCredentialType::Delegation),
                "RCardCredential" => Ok(DTGCredentialType::RCard),
                _ => Err(DTGCredentialError::UnknownCredential),
            }
        } else {
            Err(DTGCredentialError::UnknownCredential)
        }
    }
}

/// All DTG Credentials follow a common structure.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DTGCommon {
    /// JSON-LD links to contexts
    /// Must contain at least:
    /// - <https://www.w3.org/ns/credentials/v2>
    /// - <https://firstperson.network/credentials/dtg/v1>
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// Credential type identifiers
    /// Must contain at least:
    /// DTGCredential
    /// VerifiableCredential
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

    /// Identifier (`threadId`) of the trust task exchange in which this credential was issued.
    ///
    /// REQUIRED for [DTGCredentialType::Witness] credentials, OPTIONAL for all other DTG
    /// credential types. A DTG credential without a `taskContext` MUST be interpretable
    /// standing alone, independent of any exchange.
    ///
    /// NOTE: A verifier MUST NOT interpret a `taskContext`-bearing credential as proof that
    /// the associated trust task completed unless the matching trust task outcome evidence is
    /// also present and verified.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub task_context: Option<String>,

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

    /// Returns the subject DID
    #[allow(deprecated)]
    pub fn subject(&self) -> &str {
        match &self.credential_subject {
            CredentialSubject::Basic(subject) => &subject.id,
            CredentialSubject::Endorsement(subject) => &subject.id,
            CredentialSubject::Witness(subject) => &subject.id,
            CredentialSubject::Membership(subject) => &subject.id,
            CredentialSubject::Authority(subject) => &subject.id,
            CredentialSubject::Delegation(subject) => &subject.id,
            CredentialSubject::RCard(subject) => &subject.id,
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

    /// The `threadId` of the trust task exchange this credential was issued in, if set
    pub fn task_context(&self) -> Option<&str> {
        self.task_context.as_deref()
    }

    /// Refuses a credential whose open JSON members take the document past
    /// [`MAX_JSON_DEPTH`].
    ///
    /// Every other member is a type this library defines, none more than four levels deep,
    /// so the open members are the only place the bound can be crossed.
    #[allow(deprecated)]
    fn check_depth(&self) -> Result<(), DTGCredentialError> {
        // The document is depth 1, so a top-level member sits at 2 and a member of
        // `credentialSubject` at 3.
        let mut roots: Vec<(&Value, usize)> =
            self.extra.values().map(|member| (member, 2)).collect();
        if let Some(status) = &self.credential_status {
            roots.push((status, 2));
        }
        match &self.credential_subject {
            CredentialSubject::Endorsement(subject) => roots.push((&subject.endorsement, 3)),
            CredentialSubject::RCard(subject) => roots.push((&subject.card, 3)),
            _ => {}
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

/// Helps ensure default starting point is correct
impl Default for DTGCommon {
    fn default() -> Self {
        DTGCommon {
            context: vec![
                "https://www.w3.org/ns/credentials/v2".to_string(),
                "https://firstperson.network/credentials/dtg/v1".to_string(),
            ],
            type_: vec![
                "VerifiableCredential".to_string(),
                "DTGCredential".to_string(),
            ],
            id: None,
            issuer: String::new(),
            valid_from: Utc::now(),
            valid_until: None,
            task_context: None,
            credential_subject: CredentialSubject::Basic(CredentialSubjectBasic {
                id: String::new(),
            }),
            credential_status: None,
            proof: None,
            extra: serde_json::Map::new(),
        }
    }
}

/// Post deserialize setup of a CredentialSubject and CredntialType
impl TryFrom<DTGCommon> for DTGCredential {
    type Error = DTGCredentialError;

    #[allow(deprecated)]
    fn try_from(value: DTGCommon) -> Result<Self, Self::Error> {
        match &value.type_.as_slice().try_into()? {
            DTGCredentialType::Membership => {
                // Normalize whichever variant the untagged subject match landed on into
                // `Membership`, so a caller matching on the subject of a VMC sees one shape
                // rather than two. See [CredentialSubject::Membership] for why the untagged
                // match cannot make this decision itself.
                let subject = match &value.credential_subject {
                    // Already normalized — a credential built by `new_vmc` /
                    // `new_member_vmc` rather than deserialized.
                    CredentialSubject::Membership(subject) => subject.clone(),

                    // `{ id }` — the community-issued grant, which MUST omit `digest`.
                    CredentialSubject::Basic(subject) => CredentialSubjectMembership {
                        id: subject.id.clone(),
                        digest_multibase: None,
                    },

                    // `{ id, digest }` — the member-issued acknowledgement. Shape-identical
                    // to a VWC subject, which wins the untagged match; on a
                    // MembershipCredential it is this. A `witnessContext` alongside it is
                    // not: that property belongs to a VWC and has no meaning here, so a VMC
                    // carrying one is malformed rather than merely surprising.
                    CredentialSubject::Witness(subject) if subject.witness_context.is_none() => {
                        CredentialSubjectMembership {
                            id: subject.id.clone(),
                            digest_multibase: subject.digest_multibase.clone(),
                        }
                    }

                    _ => return Err(DTGCredentialError::UnknownCredential),
                };

                Ok(DTGCredential {
                    type_: DTGCredentialType::Membership,
                    version: value.context.as_slice().try_into()?,
                    credential: DTGCommon {
                        credential_subject: CredentialSubject::Membership(subject),
                        ..value
                    },
                })
            }
            DTGCredentialType::Relationship => Ok(DTGCredential {
                type_: DTGCredentialType::Relationship,
                version: value.context.as_slice().try_into()?,
                credential: value,
            }),
            DTGCredentialType::Invitation => Ok(DTGCredential {
                type_: DTGCredentialType::Invitation,
                version: value.context.as_slice().try_into()?,
                credential: value,
            }),
            DTGCredentialType::Persona => Ok(DTGCredential {
                type_: DTGCredentialType::Persona,
                version: value.context.as_slice().try_into()?,
                credential: value,
            }),
            DTGCredentialType::Endorsement => {
                if let CredentialSubject::Endorsement { .. } = &value.credential_subject {
                    Ok(DTGCredential {
                        type_: DTGCredentialType::Endorsement,
                        version: value.context.as_slice().try_into()?,
                        credential: value,
                    })
                } else {
                    Err(DTGCredentialError::UnknownCredential)
                }
            }
            DTGCredentialType::Witness => {
                // taskContext is REQUIRED on a VWC: the meaning of a witness attestation
                // depends on the conditions it was made under, which live in the trust task
                // exchange it is bound to.
                if value.task_context.is_none() {
                    return Err(DTGCredentialError::MissingTaskContext);
                }

                match &value.credential_subject {
                    CredentialSubject::Witness(_) => Ok(DTGCredential {
                        type_: DTGCredentialType::Witness,
                        version: value.context.as_slice().try_into()?,
                        credential: value,
                    }),
                    CredentialSubject::Basic(subject) => {
                        // If Witness CredentialSubject only contains id, it is still valid
                        Ok(DTGCredential {
                            type_: DTGCredentialType::Witness,
                            version: value.context.as_slice().try_into()?,
                            credential: DTGCommon {
                                credential_subject: CredentialSubject::Witness(
                                    CredentialSubjectWitness {
                                        id: subject.id.clone(),
                                        digest_multibase: None,
                                        witness_context: None,
                                    },
                                ),
                                ..value
                            },
                        })
                    }
                    _ => Err(DTGCredentialError::UnknownCredential),
                }
            }
            DTGCredentialType::Authority => {
                // A VAC's subject must actually carry the grant. `Basic` — a bare `{ id }` —
                // is the shape a caller lands on when the `authority` member is missing
                // entirely, and a credential that confers nothing is malformed rather than
                // merely empty. There is no normalization to do here (unlike VMC/VWC, whose
                // shapes collide): `authority` is unique to this subject.
                match &value.credential_subject {
                    CredentialSubject::Authority(subject) => {
                        if subject.authority.actions.is_empty() {
                            // Emptiness is never a wildcard. Refusing here means a caller
                            // cannot construct one by deserialization either.
                            return Err(DTGCredentialError::EmptyAuthorityActions);
                        }
                        Ok(DTGCredential {
                            type_: DTGCredentialType::Authority,
                            version: value.context.as_slice().try_into()?,
                            credential: value,
                        })
                    }
                    _ => Err(DTGCredentialError::UnknownCredential),
                }
            }
            DTGCredentialType::Delegation => {
                // A VDC's subject must carry the appointment. `Basic` — a bare `{ id }` —
                // is where a caller lands when `delegation` is missing entirely, and a
                // credential that appoints nobody to nothing is malformed rather than
                // merely empty.
                match &value.credential_subject {
                    CredentialSubject::Delegation(subject) => {
                        let d = &subject.delegation;

                        // The two halves are distinguished by `accepts`, and each half has
                        // exactly one shape. Refusing the mixtures here means a caller
                        // cannot construct one by deserialization either.
                        match (&d.accepts, &d.scope) {
                            (Some(_), Some(_)) => {
                                return Err(DTGCredentialError::MalformedDelegation(
                                    "carries both `accepts` and `scope`: an acceptance \
                                     consents to the scope of the grant it names rather \
                                     than restating it"
                                        .into(),
                                ));
                            }
                            (Some(_), None) => {
                                if d.parent.is_some() || d.max_depth.is_some() {
                                    return Err(DTGCredentialError::MalformedDelegation(
                                        "an acceptance carries `accepts` and nothing else".into(),
                                    ));
                                }
                            }
                            (None, Some(scope)) => {
                                if scope.is_empty() {
                                    return Err(DTGCredentialError::MalformedDelegation(
                                        "a grant's `scope` MUST contain at least one \
                                         entry — emptying it is not how an unbounded \
                                         appointment is expressed, because there is no \
                                         way to express one"
                                            .into(),
                                    ));
                                }
                            }
                            (None, None) => {
                                return Err(DTGCredentialError::MalformedDelegation(
                                    "carries neither `scope` nor `accepts`, so it is \
                                     neither a grant nor an acceptance"
                                        .into(),
                                ));
                            }
                        }

                        Ok(DTGCredential {
                            type_: DTGCredentialType::Delegation,
                            version: value.context.as_slice().try_into()?,
                            credential: value,
                        })
                    }
                    _ => Err(DTGCredentialError::UnknownCredential),
                }
            }
            DTGCredentialType::RCard => match &value.credential_subject {
                CredentialSubject::RCard { .. } => Ok(DTGCredential {
                    type_: DTGCredentialType::RCard,
                    version: value.context.as_slice().try_into()?,
                    credential: value,
                }),
                _ => Err(DTGCredentialError::UnknownCredential),
            },
        }
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
#[allow(deprecated)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum CredentialSubject {
    /// Verifiable Endorsement Credential subject
    Endorsement(CredentialSubjectEndorsement),

    /// R-Card Credential subject
    #[deprecated(
        since = "0.2.0",
        note = "The r-card is a verifiable data structure (VDS), not a DTGCredential subtype. \
                See DTGCredentialType::RCard. This variant will be removed in a future release."
    )]
    RCard(CredentialSubjectRCard),

    /// Credential Subject of just `id`
    /// Used by a community-issued VMC, and by VRC, VIC and VPC
    Basic(CredentialSubjectBasic),

    /// Verifiable Witness Credential subject
    Witness(CredentialSubjectWitness),

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

    /// Membership Credential subject, carrying the OPTIONAL `digest` that a member-issued
    /// VMC MUST set.
    ///
    /// # Never selected by the untagged match, deliberately
    ///
    /// This variant sits last because its two shapes are already claimed above: `{ id }` is
    /// [CredentialSubject::Basic], and `{ id, digest }` is indistinguishable from a VWC
    /// subject with no `witnessContext`, which [CredentialSubject::Witness] takes first.
    /// Nothing in the subject object itself separates a membership acknowledgement from a
    /// witness attestation — only the credential's `type` does.
    ///
    /// So the shape is not decided here. `TryFrom<DTGCommon> for DTGCredential` normalizes
    /// whichever variant the untagged match landed on into this one when `type` includes
    /// `MembershipCredential`, the same way it already re-wraps a `Basic` subject as
    /// `Witness` on a VWC. Deserialization is therefore deterministic rather than
    /// order-dependent, and a `Membership` subject reaching a matcher has been through that
    /// normalization.
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
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
    /// Serializes as `digestMultibase`. The Working Draft 01 name `digest` is accepted on
    /// the wire so that credentials issued against that draft still parse; the *value*
    /// encoding also changed, so such a credential parses and then fails to compare, with
    /// [DTGCredentialError::InvalidDigest] rather than a silent mismatch.
    #[serde(
        rename = "digestMultibase",
        alias = "digest",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub digest_multibase: Option<String>,
}

/// Endorsement Credential subject
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CredentialSubjectEndorsement {
    pub id: String,
    /// There is no spec for the endorsement content, so we use a generic JSON value
    pub endorsement: Value,
}

/// Witness Credential subject
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSubjectWitness {
    pub id: String,

    /// Digest of the witnessed edge credential, as [DTGCredential::digest_multibase]
    /// computes it. REQUIRED by the specification — a VWC without one names the observed
    /// party and the exchange, but not which edge was witnessed.
    ///
    /// Serializes as `digestMultibase`; the Working Draft 01 name `digest` is accepted on
    /// the wire.
    #[serde(
        rename = "digestMultibase",
        alias = "digest",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub digest_multibase: Option<String>,

    /// There is no spec for the witness context content, so we use a generic JSON value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_context: Option<WitnessContext>,
}

/// Witness Credential Context
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WitnessContext {
    /// Human-readable event name
    pub event: Option<String>,

    /// Session or nonce identifier
    pub session_id: Option<String>,

    ///Verification method used
    pub method: Option<String>,
}

/// R-Card Credential subject
#[deprecated(
    since = "0.2.0",
    note = "The r-card is a verifiable data structure (VDS), not a DTGCredential subtype. \
            See DTGCredentialType::RCard. This struct will be removed in a future release."
)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CredentialSubjectRCard {
    pub id: String,

    /// JCard spec, generic JSON value
    pub card: Value,
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use crate::{
        CredentialSubject, CredentialSubjectRCard, DTGCommon, DTGCredential, DTGCredentialError,
        DTGCredentialType, W3CVCVersion, decode_digest_multibase, digest_multibase_json,
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
    "https://firstperson.network/credentials/dtg/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "type": ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
  "issuer": "did:web:chess-club.example",
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
    "https://firstperson.network/credentials/dtg/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "type": ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
  "issuer": "did:web:chess-club.example",
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
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "MembershipCredential"],
                "issuer": "did:example:community",
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
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "MembershipCredential", "PersonhoodCredential"],
                "issuer": "did:example:community",
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
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "RelationshipCredential"],
                "issuer": "did:example:governmentAgencyDid",
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
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "InvitationCredential"],
                "issuer": "did:example:governmentAgencyVicDid",
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
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "PersonaCredential"],
                "issuer": "did:example:governmentAgencyDid",
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

    #[test]
    fn test_vec_deserialize() {
        let vec: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "EndorsementCredential"],
                "issuer": "did:example:governmentAgencyDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid", "endorsement": {} }
            }"#,
        ) {
            Ok(vec) => vec,
            Err(e) => panic!("Couldn't deserialize VEC: {}", e),
        };

        assert!(matches!(vec.type_, DTGCredentialType::Endorsement));
        assert!(matches!(vec.subject(), "did:example:citizenRDid"));
        assert!(matches!(
            vec.credential().credential_subject,
            CredentialSubject::Endorsement(_)
        ));
    }

    #[test]
    fn test_vec_bad_deserialize() {
        match serde_json::from_str::<DTGCredential>(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "EndorsementCredential"],
                "issuer": "did:example:governmentAgencyDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid", "other": [] }
            }"#,
        ) {
            Ok(_) => panic!("Expected Unknown Credential type"),
            Err(_) => {
                // Good
            }
        };
    }

    #[test]
    fn test_vwc_simple_deserialize() {
        let vwc: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "WitnessCredential"],
                "issuer": "did:example:governmentAgencyDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "taskContext": "thread-abc-123",
                "credentialSubject": { "id": "did:example:citizenRDid" }
            }"#,
        ) {
            Ok(vwc) => vwc,
            Err(e) => panic!("Couldn't deserialize VWC: {}", e),
        };

        assert!(matches!(vwc.type_, DTGCredentialType::Witness));
        assert!(matches!(vwc.subject(), "did:example:citizenRDid"));
        assert_eq!(vwc.task_context(), Some("thread-abc-123"));
        assert!(matches!(
            vwc.credential().credential_subject,
            CredentialSubject::Witness(_)
        ));
    }

    #[test]
    fn test_vwc_full_deserialize() {
        let vwc: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "WitnessCredential"],
                "issuer": "did:example:governmentAgencyDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "taskContext": "thread-abc-123",
                "credentialSubject": { "id": "did:example:citizenRDid", "digestMultibase": "abcdf", "witnessContext": {} }
            }"#,
        ) {
            Ok(vwc) => vwc,
            Err(e) => panic!("Couldn't deserialize VWC: {}", e),
        };

        assert!(matches!(vwc.type_(), DTGCredentialType::Witness));
        assert!(matches!(
            vwc.credential().credential_subject,
            CredentialSubject::Witness(_)
        ));
    }

    #[test]
    fn test_vwc_bad_deserialize() {
        if serde_json::from_str::<DTGCredential>(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "WitnessCredential"],
                "issuer": "did:example:governmentAgencyDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "taskContext": "thread-abc-123",
                "credentialSubject": { "id": "did:example:citizenRDid", "digestMultibase": "abcdf", "wrongContext": {}  }
            }"#,
        ).is_ok() {
            panic!("Should have failed due to wrong CredentialSubject!");
        }
    }

    #[test]
    fn test_rcard_simple_deserialize() {
        let rcard: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "RCardCredential"],
                "issuer": "did:example:governmentAgencyDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid", "card": [] }
            }"#,
        ) {
            Ok(rcard) => rcard,
            Err(e) => panic!("Couldn't deserialize R-Card: {}", e),
        };

        assert!(matches!(rcard.type_(), DTGCredentialType::RCard));
        assert!(matches!(rcard.subject(), "did:example:citizenRDid"));
        assert!(matches!(
            rcard.credential().credential_subject,
            CredentialSubject::RCard(_)
        ));
    }

    #[test]
    fn test_rcard_bad_deserialize() {
        if serde_json::from_str::<DTGCredential>(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "RCardCredential"],
                "issuer": "did:example:governmentAgencyDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid"  }
            }"#,
        )
        .is_ok()
        {
            panic!("Should have failed due to wrong CredentialSubject!");
        }
    }
    #[test]
    fn test_deserialize_unknown() {
        match serde_json::from_str::<DTGCredential>(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "UnknownCredential"],
                "issuer": "did:example:governmentAgencyDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid" }
            }"#,
        ) {
            Ok(_) => panic!("Expected Unknown Credential type"),
            Err(e) => {
                if e.to_string() == "Unknown credential type" {
                    // test passed
                } else {
                    panic!("Wrong error type returned");
                }
            }
        };
    }

    #[test]
    fn test_deserialize_mismatched_credential_subject() {
        match serde_json::from_str::<DTGCredential>(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "EndorsementCredential"],
                "issuer": "did:example:governmentAgencyDid",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:citizenRDid" }
            }"#,
        ) {
            Ok(_) => panic!("Expected Unknown Credential type"),
            Err(e) => {
                if e.to_string() == "Unknown credential type" {
                    // test passed
                } else {
                    panic!("Wrong error type returned");
                }
            }
        };
    }

    #[test]
    fn test_proof_signed() {
        let cred: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "MembershipCredential"],
                "issuer": "did:example:community",
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
        let cred: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "MembershipCredential"],
                "issuer": "did:example:community",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:rDid" }
            }"#,
        ) {
            Ok(vmc) => vmc,
            Err(e) => panic!("Couldn't deserialize credential: {}", e),
        };

        assert!(!cred.signed());
        assert!(cred.proof_value().is_none());
    }

    #[test]
    fn test_helpers() {
        let cred: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "MembershipCredential"],
                "issuer": "did:example:issuer",
                "validFrom": "2024-06-18T00:00:00Z",
                "credentialSubject": { "id": "did:example:subject" }
            }"#,
        ) {
            Ok(vmc) => vmc,
            Err(e) => panic!("Couldn't deserialize credential: {}", e),
        };

        assert_eq!(cred.issuer(), "did:example:issuer");
        assert_eq!(cred.subject(), "did:example:subject");
        assert_eq!(
            cred.valid_from()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "2024-06-18T00:00:00Z"
        );
        assert_eq!(cred.valid_until(), None);
    }

    #[test]
    fn test_valid_until() {
        let cred: DTGCredential = match serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "MembershipCredential"],
                "issuer": "did:example:issuer",
                "validFrom": "2024-06-18T00:00:00Z",
                "validUntil": "2030-01-01T00:00:00Z",
                "credentialSubject": { "id": "did:example:subject" }
            }"#,
        ) {
            Ok(vmc) => vmc,
            Err(e) => panic!("Couldn't deserialize credential: {}", e),
        };

        assert_eq!(
            cred.valid_until()
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "2030-01-01T00:00:00Z"
        );
    }

    #[test]
    fn test_bad_type() {
        assert!(
            std::convert::TryInto::<DTGCredentialType>::try_into(
                vec!["bad_type".to_string()].as_slice(),
            )
            .is_err()
        );
    }

    #[test]
    fn test_badly_constructed_vwc() {
        let mut cred = DTGCommon::default();
        cred.type_.push("WitnessCredential".to_string());
        // taskContext is set so this exercises the credentialSubject mismatch, not the
        // missing-taskContext path covered by test_vwc_missing_task_context()
        cred.task_context = Some("thread-abc-123".to_string());
        cred.credential_subject = CredentialSubject::RCard(CredentialSubjectRCard {
            id: "did:example:bad".to_string(),
            card: Value::Null,
        });

        assert!(std::convert::TryInto::<DTGCredential>::try_into(cred).is_err());
    }

    #[test]
    fn test_vwc_missing_task_context() {
        // taskContext is REQUIRED on a VWC
        match serde_json::from_str::<DTGCredential>(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "WitnessCredential"],
                "issuer": "did:example:witness",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:observed" }
            }"#,
        ) {
            Ok(_) => panic!("Expected a VWC without taskContext to be rejected"),
            Err(e) => assert_eq!(
                e.to_string(),
                "WitnessCredential is missing the required taskContext property"
            ),
        }
    }

    #[test]
    fn test_task_context_round_trip() {
        // taskContext must survive deserialize -> serialize, otherwise a credential signed
        // elsewhere would fail verification here (and vice versa)
        let raw = r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "WitnessCredential"],
                "issuer": "did:example:witness",
                "validFrom": "2024-06-18T10:00:00Z",
                "taskContext": "thread-abc-123",
                "credentialSubject": { "id": "did:example:observed" }
            }"#;

        let cred: DTGCredential = serde_json::from_str(raw).unwrap();
        let out = serde_json::to_string(&cred).unwrap();

        assert!(out.contains(r#""taskContext":"thread-abc-123""#));
    }

    #[test]
    fn test_task_context_optional_on_other_types() {
        // taskContext is OPTIONAL everywhere except the VWC
        let vrc: DTGCredential = serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential",  "RelationshipCredential"],
                "issuer": "did:example:issuer",
                "validFrom": "2024-06-18T10:00:00Z",
                "credentialSubject": { "id": "did:example:subject" }
            }"#,
        )
        .unwrap();

        assert_eq!(vrc.task_context(), None);
        // and it is omitted from the serialization entirely when absent
        assert!(!serde_json::to_string(&vrc).unwrap().contains("taskContext"));
    }

    #[test]
    fn test_digest_multibase() {
        let vrc = DTGCredential::new_vrc(
            "did:example:issuer".to_string(),
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
            "did:example:subject".to_string(),
            valid_from,
            None,
        );

        let vwc = DTGCredential::new_vwc(
            "did:example:witness".to_string(),
            // the DID of the issuer of the VRC being attested
            "did:example:issuer".to_string(),
            valid_from,
            None,
            "thread-abc-123".to_string(),
            Some(vrc.digest_multibase().unwrap()),
            None,
        );

        assert!(vwc.verify_digest(&vrc).unwrap());

        // a different VRC must not match
        let other = DTGCredential::new_vrc(
            "did:example:issuer".to_string(),
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
            "did:example:subject".to_string(),
            valid_from,
            None,
        );

        // digest is OPTIONAL - with none present there is nothing to rely on
        let vwc = DTGCredential::new_vwc(
            "did:example:witness".to_string(),
            "did:example:issuer".to_string(),
            valid_from,
            None,
            "thread-abc-123".to_string(),
            None,
            None,
        );

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
        //    "type":[...],"validFrom":"2025-12-11T00:00:00Z"}
        // whose SHA-256 is 49c9d5135ab4b5659a343bc79d351e37d64f05add58408cae6eef022828495c2.
        assert_eq!(digest, "zQmTJgyPT2ShMQ2AvCHGDoPGjEWyRC7ZNT3MBpe5PP6Vpvu");

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
            "sha256:49c9d5135ab4b5659a343bc79d351e37d64f05add58408cae6eef022828495c2"
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

        let ack = DTGCredential::new_member_vmc(&wire(&grant), valid_from, None).expect("builds");

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
        let ack = DTGCredential::new_member_vmc(&wire(&grant), valid_from, None).expect("builds");

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
        let ack_of_ack =
            DTGCredential::new_member_vmc(&wire(&grant), valid_from, None).expect("builds");
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

        let ack = DTGCredential::new_member_vmc(&grant, valid_from, None).expect("builds");

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
        let ack = DTGCredential::new_member_vmc(&wire(&grant), valid_from, None).expect("builds");

        let vrc = DTGCredential::new_vrc(
            "did:example:member".to_string(),
            "did:example:community".to_string(),
            valid_from,
            None,
        );
        assert!(!ack.acknowledges(&vrc).unwrap());

        // And a VWC bound to the grant is a witness attestation, not a member's consent.
        let vwc = DTGCredential::new_vwc(
            "did:example:witness".to_string(),
            "did:example:community".to_string(),
            valid_from,
            None,
            "thread-abc-123".to_string(),
            Some(grant.digest_multibase().unwrap()),
            None,
        );
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
            "did:example:b".to_string(),
            valid_from,
            None,
        );
        assert!(matches!(
            DTGCredential::new_member_vmc(&wire(&vrc), valid_from, None),
            Err(DTGCredentialError::NotAMembershipGrant(_))
        ));

        let grant = DTGCredential::new_vmc(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            valid_from,
            None,
            false,
        );
        let ack = DTGCredential::new_member_vmc(&wire(&grant), valid_from, None).expect("builds");
        assert!(matches!(
            DTGCredential::new_member_vmc(&wire(&ack), valid_from, None),
            Err(DTGCredentialError::NotAMembershipGrant(_))
        ));
    }

    /// `{ id, digest }` is shape-identical to a VWC subject, and the untagged enum matches
    /// `Witness` first. On a MembershipCredential the credential's `type` is the only thing
    /// that says otherwise, so the normalization in `TryFrom<DTGCommon>` is what makes this
    /// deserialize as the member-issued half rather than as a witness attestation.
    #[test]
    fn test_member_issued_vmc_deserializes_as_membership_not_witness() {
        let vmc: DTGCredential = serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
                "issuer": "did:example:member",
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

    /// `witnessContext` belongs to a VWC. A VMC carrying one is malformed rather than
    /// merely surprising, and is refused instead of being silently read as a grant.
    #[test]
    fn test_membership_credential_rejects_a_witness_context() {
        let result: Result<DTGCredential, _> = serde_json::from_str(
            r#"{
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
                "issuer": "did:example:member",
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
        let ack = DTGCredential::new_member_vmc(&wire(&grant), valid_from, None).expect("builds");

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
        let cred = DTGCommon {
            valid_until: Some(now),
            ..Default::default()
        };

        let value = serde_json::to_value(&cred).unwrap();
        let cred2: DTGCommon = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(cred2.valid_until, Some(now));

        let cred = DTGCommon::default();
        let value = serde_json::to_value(&cred).unwrap();
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
            DTGCredential::new_member_vmc(
                &wire(&grant),
                from,
                Some(from - chrono::Duration::hours(1))
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
