/*! Decentralized Trust Graph (DTG) Credentials
*/

use affinidi_data_integrity::DataIntegrityProof;
#[cfg(feature = "affinidi-signing")]
use affinidi_data_integrity::{DataIntegrityError, SignOptions, VerifyOptions};
#[cfg(feature = "affinidi-signing")]
use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use std::fmt::Display;
use thiserror::Error;

pub mod create;

/// What W3C VC Format is the credential using?
#[derive(Clone, Copy, Debug)]
pub enum W3CVCVersion {
    /// https://www.w3.org/2018/credentials/v1
    V1_1,

    /// https://www.w3.org/ns/credentials/v2
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
    RCard,
}

impl Display for DTGCredentialType {
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
    /// https://www.w3.org/ns/credentials/v2
    /// https://firstperson.network/credentials/dtg/v1
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// Credential type identifiers
    /// Must contain at least:
    /// DTGCredential
    /// VerifiableCredential
    #[serde(rename = "type")]
    pub type_: Vec<String>,

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

    /// Returns the issuer DID
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the subject DID
    pub fn subject(&self) -> &str {
        match &self.credential_subject {
            CredentialSubject::Basic(subject) => &subject.id,
            CredentialSubject::Endorsement(subject) => &subject.id,
            CredentialSubject::Witness(subject) => &subject.id,
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
            issuer: String::new(),
            valid_from: Utc::now(),
            valid_until: None,
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

    fn try_from(value: DTGCommon) -> Result<Self, Self::Error> {
        match &value.type_.as_slice().try_into()? {
            DTGCredentialType::Membership => Ok(DTGCredential {
                type_: DTGCredentialType::Membership,
                version: value.context.as_slice().try_into()?,
                credential: value,
            }),
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
            DTGCredentialType::Witness => match &value.credential_subject {
                CredentialSubject::Witness(_) => Ok(DTGCredential {
                    type_: DTGCredentialType::Witness,
                    version: value.context.as_slice().try_into()?,
                    credential: value,
                }),
                CredentialSubject::Basic(subject) => {
                    // If Wtiness CredentialSubject only contains id, it is still valid
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
            },
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
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum CredentialSubject {
    /// Verifiable Endorsement Credential subject
    Endorsement(CredentialSubjectEndorsement),

    /// R-Card Credential subject
    RCard(CredentialSubjectRCard),

    /// Credential Subject of just `id`
    /// Use by  VMC, VRC, VIC and VPC
    Basic(CredentialSubjectBasic),

    /// Verifiable Witness Credential subject
    Witness(CredentialSubjectWitness),
}

/// id of the credential subject only
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CredentialSubjectBasic {
    pub id: String,
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
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CredentialSubjectRCard {
    pub id: String,

    /// JCard spec, generic JSON value
    pub card: Value,
}

#[cfg(test)]
mod tests {
    use crate::{
        CredentialSubject, CredentialSubjectRCard, DTGCommon, DTGCredential, DTGCredentialType,
        W3CVCVersion,
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
            CredentialSubject::Basic(_)
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
            CredentialSubject::Basic(_)
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
            CredentialSubject::Basic(_)
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
                "credentialSubject": { "id": "did:example:citizenRDid" }
            }"#,
        ) {
            Ok(vwc) => vwc,
            Err(e) => panic!("Couldn't deserialize VWC: {}", e),
        };

        assert!(matches!(vwc.type_, DTGCredentialType::Witness));
        assert!(matches!(vwc.subject(), "did:example:citizenRDid"));
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
        cred.credential_subject = CredentialSubject::RCard(CredentialSubjectRCard {
            id: "did:example:bad".to_string(),
            card: Value::Null,
        });

        assert!(std::convert::TryInto::<DTGCredential>::try_into(cred).is_err());
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
