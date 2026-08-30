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

pub mod create;

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

    /// This credential's digest, as the `digest` property of a credential that references
    /// it — a member-issued VMC acknowledging a membership grant, or a VWC attesting an
    /// edge credential.
    ///
    /// Per DTG Core Credentials, the digest is the SHA-256 hash of the credential's JSON
    /// representation **excluding its top-level `proof` member**, canonicalized with the
    /// JSON Canonicalization Scheme ([JCS, RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785)),
    /// encoded as `sha256:` followed by the lowercase hexadecimal digest.
    ///
    /// # Why `proof` is excluded
    ///
    /// The digest binds to what the credential *says*, not to a particular signature over
    /// it. A referencing credential therefore survives a re-proofing of its referent: a
    /// re-signed grant carrying identical claims still satisfies an acknowledgement made
    /// against the earlier signature. It also means the digest can be computed before the
    /// referent is signed, and is stable whichever of its proofs a holder happens to have.
    /// # ⚠️ Only for a credential this library built
    ///
    /// This digests the *model*, and the model does not carry every member a
    /// credential may have — `credentialStatus`, for one, which every VMC issued
    /// against a status list carries and which `DTGCommon` does not model. Digesting a
    /// credential that was **received** rather than built here therefore hashes a
    /// document with those members missing, producing a digest the sender will not
    /// recognise.
    ///
    /// For a credential that arrived from somewhere else, digest the JSON you received
    /// with [`digest_json`] — never a re-serialisation of a parse of it.
    pub fn digest(&self) -> Result<String, DTGCredentialError> {
        let unsigned = DTGCommon {
            proof: None,
            ..self.credential.clone()
        };
        let value = serde_json::to_value(&unsigned)
            .map_err(|e| DTGCredentialError::Canonicalization(e.to_string()))?;
        digest_json(&value)
    }

    /// The digest this credential carries of the credential it references, if it carries one.
    ///
    /// `Some` for a member-issued VMC (which MUST carry one) and for a VWC bound to the edge
    /// credential it attests; `None` for a community-issued VMC, which MUST omit it, and for
    /// every credential type that has no `digest` property.
    pub fn subject_digest(&self) -> Option<&str> {
        match &self.credential.credential_subject {
            CredentialSubject::Membership(subject) => subject.digest.as_deref(),
            CredentialSubject::Witness(subject) => subject.digest.as_deref(),
            _ => None,
        }
    }

    /// Computes the digest of this credential in the multibase multihash encoding.
    ///
    /// The underlying hash differs from [DTGCredential::digest] in two ways: it is encoded as
    /// a base58btc multibase multihash rather than `sha256:<hex>`, and it covers the
    /// credential *including* its `proof`.
    #[deprecated(
        since = "0.4.0",
        note = "This encoding is not what DTG Core Credentials specifies, so digests \
                produced by it do not interoperate. Use DTGCredential::digest, which \
                returns the conformant `sha256:<lowercase hex>` over the proofless JCS \
                canonical form. This method will be removed in a future release."
    )]
    pub fn digest_multibase(&self) -> Result<String, DTGCredentialError> {
        let canonical = serde_json_canonicalizer::to_vec(&self.credential)
            .map_err(|e| DTGCredentialError::Canonicalization(e.to_string()))?;

        // multihash prefix: 0x12 = sha2-256, 0x20 = 32 byte digest length
        let mut multihash = Vec::with_capacity(34);
        multihash.extend_from_slice(&[0x12, 0x20]);
        multihash.extend_from_slice(&Sha256::digest(&canonical));

        Ok(multibase::encode(Base::Base58Btc, &multihash))
    }

    /// Checks that this credential's `digest` matches the credential it claims to reference.
    ///
    /// Answers one question only — whether the hashes agree. It does not check that the two
    /// credentials are of the types the reference requires, nor that their issuers and
    /// subjects line up. For a membership acknowledgement, [DTGCredential::acknowledges]
    /// checks all of that together and is what a verifier completing an edge should call.
    ///
    /// Returns `Ok(false)` if the digests do not match, or if this credential carries no
    /// `digest`, in which case there is nothing to rely on.
    pub fn verify_digest(&self, referenced: &DTGCredential) -> Result<bool, DTGCredentialError> {
        let Some(digest) = self.subject_digest() else {
            return Ok(false);
        };

        Ok(digest == referenced.digest()?)
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

    /// Returns the proof value if signed else None
    pub fn proof_value(&self) -> Option<&str> {
        if let Some(proof) = &self.credential.proof {
            proof.proof_value.as_deref()
        } else {
            None
        }
    }

    #[cfg(feature = "affinidi-signing")]
    /// Sign the credential using W3C Data Integrity Proof with JCS EdDSA 2022
    /// signing_secret: The secret key to use to sign the credential
    /// create_time: Optional creation time for the proof, defaults to now if None
    pub async fn sign(
        &mut self,
        signing_secret: &Secret,
        create_time: Option<DateTime<Utc>>,
    ) -> Result<DataIntegrityProof, DTGCredentialError> {
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
    pub fn verify_proof_with_public_key(
        &self,
        public_key_bytes: &[u8],
    ) -> Result<(), DTGCredentialError> {
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

/// The digest a DTG credential carries of another credential, computed over a
/// credential in its **wire form**.
///
/// SHA-256 over the RFC 8785 (JCS) canonicalization of `doc` with its top-level `proof`
/// member removed, encoded as `sha256:` followed by the lowercase hexadecimal digest.
/// This is what a member-issued VMC carries of the grant it acknowledges, and what a VWC
/// carries of the edge credential it attests.
///
/// # Digest what you received, not what you parsed
///
/// Take the document as it arrived. A credential may carry members this library does not
/// model — `credentialStatus` is the common one — and a parse-then-re-serialise round
/// trip drops them silently, so the digest would not match the one its issuer computed.
/// [`DTGCredential::digest`] is safe only for a credential built in-process; anything
/// received goes through this.
///
/// # Why `proof` is excluded
///
/// The digest binds to what the credential says, not to a signature over it, so a
/// reference survives its referent being re-signed. A re-issued credential carries
/// different claims and therefore a different digest, which is what makes renewal force
/// re-acknowledgement.
pub fn digest_json(doc: &Value) -> Result<String, DTGCredentialError> {
    let proofless = match doc {
        Value::Object(members) => {
            let mut members = members.clone();
            members.remove("proof");
            Value::Object(members)
        }
        // Not an object: canonicalize as-is. A shape check belongs to the caller, which
        // has a better error to give than this would.
        other => other.clone(),
    };

    let canonical = serde_json_canonicalizer::to_vec(&proofless)
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
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DTGCredentialType {
    Membership,
    Relationship,
    Invitation,
    Persona,
    Endorsement,
    Witness,

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
            DTGCredentialType::RCard => write!(f, "RCardCredential"),
        }
    }
}

/// This helps with matching the right credential type to the [DTGCredentialType]
const DTG_TYPES: [&str; 7] = [
    "MembershipCredential",
    "RelationshipCredential",
    "InvitationCredential",
    "PersonaCredential",
    "EndorsementCredential",
    "WitnessCredential",
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

    /// Cryptographic proof of credential authenticity
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub proof: Option<DataIntegrityProof>,
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
            CredentialSubject::RCard(subject) => &subject.id,
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
            proof: None,
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
                        digest: None,
                    },

                    // `{ id, digest }` — the member-issued acknowledgement. Shape-identical
                    // to a VWC subject, which wins the untagged match; on a
                    // MembershipCredential it is this. A `witnessContext` alongside it is
                    // not: that property belongs to a VWC and has no meaning here, so a VMC
                    // carrying one is malformed rather than merely surprising.
                    CredentialSubject::Witness(subject) if subject.witness_context.is_none() => {
                        CredentialSubjectMembership {
                            id: subject.id.clone(),
                            digest: subject.digest.clone(),
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
                                        digest: None,
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

/// Membership Credential subject
///
/// The two directions of a membership edge share this shape and are told apart by
/// `digest`: a community-issued VMC (the membership grant) MUST omit it, and a
/// member-issued VMC (the membership acknowledgement) MUST carry it. Where both endpoints
/// are C-DIDs, as in VTN membership, `digest` is the only discriminator — the issuer and
/// subject rules cannot separate the directions.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSubjectMembership {
    pub id: String,

    /// Digest of the community-issued VMC this acknowledges, as
    /// [DTGCredential::digest] computes it.
    ///
    /// REQUIRED on the member-issued VMC, and MUST be omitted on the community-issued VMC.
    /// `Option` rather than two structs because the same property distinguishes the two
    /// directions: a type that could not represent both could not deserialize the pair.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub digest: Option<String>,
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

    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

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
        DTGCredentialType, W3CVCVersion, digest_json,
    };
    use chrono::{DateTime, Utc};
    use serde_json::Value;

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
                "credentialSubject": { "id": "did:example:citizenRDid", "digest": "abcdf", "witnessContext": {} }
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
                "credentialSubject": { "id": "did:example:citizenRDid", "digest": "abcdf", "wrongContext": {}  }
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
            Some(vrc.digest().unwrap()),
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
    /// is compared byte-for-byte against a string some other implementation produced. Pinned
    /// against a literal rather than a recomputation, because a test that recomputes agrees
    /// with whatever the code does and would follow the encoding silently if it drifted.
    #[test]
    fn test_digest_is_sha256_hex_over_the_proofless_jcs_form() {
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

        let digest = vmc.digest().unwrap();

        let (scheme, hex) = digest.split_once(':').expect("`sha256:` prefixed");
        assert_eq!(scheme, "sha256");
        assert_eq!(hex.len(), 64, "32 bytes, hex encoded");
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "lowercase hex only, got {hex}"
        );

        // Independently computed over the JCS canonical form of the credential above.
        // Computed outside this crate over the JCS canonical form of the document above:
        //   {"@context":[...],"credentialSubject":{"id":"did:example:member"},
        //    "id":"urn:uuid:2a4e...","issuer":"did:example:community",
        //    "type":[...],"validFrom":"2025-12-11T00:00:00Z"}
        assert_eq!(
            digest,
            "sha256:49c9d5135ab4b5659a343bc79d351e37d64f05add58408cae6eef022828495c2"
        );

        // Stable across calls.
        assert_eq!(digest, vmc.digest().unwrap());
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

        let before = vmc.digest().unwrap();
        vmc.sign(&secret, None).await.expect("signs");
        assert!(vmc.signed());
        assert_eq!(before, vmc.digest().unwrap());
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
        assert_eq!(ack.subject_digest(), Some(grant.digest().unwrap().as_str()));

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

    /// The bug this API shape exists to prevent.
    ///
    /// A real grant carries `credentialStatus` — every VMC issued against a status list
    /// does — and `DTGCommon` does not model it, so a parse-then-re-serialise round trip
    /// drops it. An acknowledgement built by digesting the *parsed* grant would carry a
    /// digest over a document the community never issued, and the community would
    /// rightly refuse it. Silently: both credentials verify, and only the digest
    /// comparison fails, with nothing to say why.
    ///
    /// So `new_member_vmc` takes the wire form, and this pins that it digests what it
    /// was handed rather than what it could parse.
    #[test]
    fn the_acknowledgement_digests_members_the_model_does_not_know() {
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
        grant["credentialStatus"] = serde_json::json!({
            "id": "https://community.example/status#7",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": "7"
        });

        // The parse drops it — this is the hazard, asserted rather than assumed.
        let parsed: DTGCredential = serde_json::from_value(grant.clone()).expect("parses");
        assert!(
            wire(&parsed).get("credentialStatus").is_none(),
            "the model is expected NOT to carry credentialStatus; if it now does, this \
             test has stopped guarding anything and the API can be simplified"
        );

        let ack = DTGCredential::new_member_vmc(&grant, valid_from, None).expect("builds");

        assert_eq!(
            ack.subject_digest(),
            Some(digest_json(&grant).unwrap().as_str()),
            "the acknowledgement must digest the grant as received"
        );
        assert_ne!(
            ack.subject_digest(),
            Some(parsed.digest().unwrap().as_str()),
            "digesting the parsed model would produce a digest the community cannot match"
        );
    }

    /// `digest_json` and `digest` must agree for a credential with nothing outside the
    /// model — otherwise the two entry points would quietly disagree for the easy case
    /// too, and no caller could tell which to trust.
    #[test]
    fn digest_json_agrees_with_digest_where_the_model_is_complete() {
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

        assert_eq!(vmc.digest().unwrap(), digest_json(&wire(&vmc)).unwrap());
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
            Some(grant.digest().unwrap()),
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
                    "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
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
                    "digest": "sha256:e3b0c4",
                    "witnessContext": { "event": "not a membership property" }
                }
            }"#,
        );
        assert!(result.is_err());
    }

    /// The two halves must be distinguishable on the wire by `digest` alone — that is the
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
            grant_json["credentialSubject"].get("digest").is_none(),
            "the grant MUST omit `digest`: {grant_json}"
        );

        let ack_json = serde_json::to_value(&ack).unwrap();
        assert_eq!(
            ack_json["credentialSubject"]["digest"],
            Value::String(grant.digest().unwrap()),
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
}
