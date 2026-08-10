/*!
*   Builder methods for creating new entities.
*/

#[allow(deprecated)]
use crate::{
    CredentialSubject, CredentialSubjectBasic, CredentialSubjectEndorsement,
    CredentialSubjectRCard, CredentialSubjectWitness, DTGCommon, DTGCredential, DTGCredentialType,
    WitnessContext,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

impl DTGCredential {
    /// Creates a new Verified Memebrship Credential (VMC)
    /// issuer: The issuer DID of the credential
    /// subject: The DID of the subject of this credential
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    /// personhood: Whether this VMC can be used as a form of Personhood Credential
    ///             - Adds PersonhoodCredential to the type array if true
    pub fn new_vmc(
        issuer: String,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        personhood: bool,
    ) -> Self {
        let mut vmc = DTGCommon {
            issuer,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::Basic(CredentialSubjectBasic { id: subject }),
            ..Default::default()
        };

        vmc.type_.push(DTGCredentialType::Membership.to_string());

        if personhood {
            vmc.type_.push("PersonhoodCredential".to_string());
        }

        DTGCredential {
            credential: vmc,
            type_: DTGCredentialType::Membership,
            version: crate::W3CVCVersion::V2_0,
        }
    }

    /// Creates a new Verified Relationship Credential (VRC)
    /// issuer: The issuer DID of the credential
    /// subject: The DID of the subject of this credential
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    pub fn new_vrc(
        issuer: String,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Self {
        let mut vrc = DTGCommon {
            issuer,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::Basic(CredentialSubjectBasic { id: subject }),
            ..Default::default()
        };

        vrc.type_.push(DTGCredentialType::Relationship.to_string());

        DTGCredential {
            credential: vrc,
            type_: DTGCredentialType::Relationship,
            version: crate::W3CVCVersion::V2_0,
        }
    }

    /// Creates a new Verified Invitation Credential (VIC)
    /// issuer: The issuer DID of the credential
    /// subject: The DID of the subject of this credential
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    pub fn new_vic(
        issuer: String,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Self {
        let mut vic = DTGCommon {
            issuer,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::Basic(CredentialSubjectBasic { id: subject }),
            ..Default::default()
        };

        vic.type_.push(DTGCredentialType::Invitation.to_string());

        DTGCredential {
            credential: vic,
            type_: DTGCredentialType::Invitation,
            version: crate::W3CVCVersion::V2_0,
        }
    }

    /// Creates a new Verified Persona Credential (VPC)
    /// issuer: The issuer DID of the credential
    /// subject: The DID of the subject of this credential
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    pub fn new_vpc(
        issuer: String,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Self {
        let mut vpc = DTGCommon {
            issuer,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::Basic(CredentialSubjectBasic { id: subject }),
            ..Default::default()
        };

        vpc.type_.push(DTGCredentialType::Persona.to_string());

        DTGCredential {
            credential: vpc,
            type_: DTGCredentialType::Persona,
            version: crate::W3CVCVersion::V2_0,
        }
    }

    /// Creates a new Verified Endorsement Credential (VEC)
    /// issuer: The issuer DID of the credential
    /// subject: The DID of the subject of this credential
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    /// endorsement: The endorsement details for this credential
    pub fn new_vec(
        issuer: String,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        endorsement: Value,
    ) -> Self {
        let mut vec = DTGCommon {
            issuer,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::Endorsement(CredentialSubjectEndorsement {
                id: subject,
                endorsement,
            }),
            ..Default::default()
        };

        vec.type_.push(DTGCredentialType::Endorsement.to_string());

        DTGCredential {
            credential: vec,
            type_: DTGCredentialType::Endorsement,
            version: crate::W3CVCVersion::V2_0,
        }
    }

    /// Creates a new Verified Witness Credential (VWC)
    /// issuer: The issuer DID of the credential - an M-DID, or the DID of a VTA acting
    ///         according to VTC policy
    /// subject: The DID of the observed party. For a witnessed bi-directional exchange this
    ///          MUST be the issuer of the VRC that this VWC attests (the VRC referenced by
    ///          `digest`), so that the two VWCs of an exchange are unambiguously bound to
    ///          their respective directions. The witness should issue one VWC per direction.
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    /// task_context: Required `threadId` of the trust task exchange the witnessing occurred in
    /// digest: Optional Witness cryptographic hash of the witnessed VRC (prevents misuse).
    ///         Produce this with [DTGCredential::digest_multibase] on the witnessed VRC.
    /// witness_context: Optional Semantic context for the witness
    pub fn new_vwc(
        issuer: String,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        task_context: String,
        digest: Option<String>,
        witness_context: Option<WitnessContext>,
    ) -> Self {
        let mut vwc = DTGCommon {
            issuer,
            valid_from,
            valid_until,
            task_context: Some(task_context),
            credential_subject: CredentialSubject::Witness(CredentialSubjectWitness {
                id: subject,
                digest,
                witness_context,
            }),
            ..Default::default()
        };

        vwc.type_.push(DTGCredentialType::Witness.to_string());

        DTGCredential {
            credential: vwc,
            type_: DTGCredentialType::Witness,
            version: crate::W3CVCVersion::V2_0,
        }
    }

    /// Creates a new Verified RCard Credential (VWC)
    /// issuer: The issuer DID of the credential
    /// subject: The DID of the subject of this credential
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    /// card: JSON Value representing a Jcard (RFC 7095) format
    #[deprecated(
        since = "0.2.0",
        note = "The r-card is a verifiable data structure (VDS), not a DTGCredential subtype. \
                It was removed from the DTG Core Credentials specification in Working Draft 01 \
                and will be defined by the planned DTG Verifiable Data Structures specification. \
                This constructor will be removed in a future release."
    )]
    #[allow(deprecated)]
    pub fn new_rcard(
        issuer: String,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        card: Value,
    ) -> Self {
        let mut rcard = DTGCommon {
            issuer,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::RCard(CredentialSubjectRCard {
                id: subject,
                card,
            }),
            ..Default::default()
        };

        rcard.type_.push(DTGCredentialType::RCard.to_string());

        DTGCredential {
            credential: rcard,
            type_: DTGCredentialType::RCard,
            version: crate::W3CVCVersion::V2_0,
        }
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use crate::{DTGCredential, WitnessContext};
    use chrono::{DateTime, Utc};
    use serde_json::json;

    #[test]
    fn test_vmc_serialization() {
        let vmc = DTGCredential::new_vmc(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            false,
        );

        let txt = serde_json::to_string_pretty(&vmc).unwrap();
        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://firstperson.network/credentials/dtg/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "MembershipCredential"
  ],
  "issuer": "did:example:issuer",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject"
  }
}"#;

        assert_eq!(txt, sample);
    }

    #[test]
    fn test_vmc_phc_serialization() {
        let vmc = DTGCredential::new_vmc(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            true,
        );

        let txt = serde_json::to_string_pretty(&vmc).unwrap();
        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://firstperson.network/credentials/dtg/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "MembershipCredential",
    "PersonhoodCredential"
  ],
  "issuer": "did:example:issuer",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject"
  }
}"#;

        assert_eq!(txt, sample);
    }
    #[test]
    fn test_vrc_serialization() {
        let vrc = DTGCredential::new_vrc(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
        );

        let txt = serde_json::to_string_pretty(&vrc).unwrap();
        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://firstperson.network/credentials/dtg/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "RelationshipCredential"
  ],
  "issuer": "did:example:issuer",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject"
  }
}"#;

        assert_eq!(txt, sample);
    }

    #[test]
    fn test_vic_serialization() {
        let vic = DTGCredential::new_vic(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
        );

        let txt = serde_json::to_string_pretty(&vic).unwrap();
        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://firstperson.network/credentials/dtg/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "InvitationCredential"
  ],
  "issuer": "did:example:issuer",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject"
  }
}"#;

        assert_eq!(txt, sample);
    }

    #[test]
    fn test_vpc_serialization() {
        let vpc = DTGCredential::new_vpc(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
        );

        let txt = serde_json::to_string_pretty(&vpc).unwrap();
        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://firstperson.network/credentials/dtg/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "PersonaCredential"
  ],
  "issuer": "did:example:issuer",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject"
  }
}"#;

        assert_eq!(txt, sample);
    }

    #[test]
    fn test_vec_serialization() {
        let vec = DTGCredential::new_vec(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            json!({
              "type": "SkillEndorsement",
              "name": "Software Development",
              "competencyLevel": "expert"
            }),
        );

        let txt = serde_json::to_string_pretty(&vec).unwrap();
        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://firstperson.network/credentials/dtg/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "EndorsementCredential"
  ],
  "issuer": "did:example:issuer",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject",
    "endorsement": {
      "competencyLevel": "expert",
      "name": "Software Development",
      "type": "SkillEndorsement"
    }
  }
}"#;

        assert_eq!(txt, sample);
    }

    #[test]
    fn test_vwc_serialization() {
        let vwc = DTGCredential::new_vwc(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            "thread-abc-123".to_string(),
            Some("zQmbGXRT3v1RmfWkQ7Y3Z5Uj9pKq2NcXhLd8sVtA4eB6nMw".to_string()),
            Some(WitnessContext {
                event: Some("EthDenver 2024".to_string()),
                session_id: Some("session-8822-nonce".to_string()),
                method: Some("in-person-proximity".to_string()),
            }),
        );

        let txt = serde_json::to_string_pretty(&vwc).unwrap();

        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://firstperson.network/credentials/dtg/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "WitnessCredential"
  ],
  "issuer": "did:example:issuer",
  "validFrom": "2025-12-11T00:00:00Z",
  "taskContext": "thread-abc-123",
  "credentialSubject": {
    "id": "did:example:subject",
    "digest": "zQmbGXRT3v1RmfWkQ7Y3Z5Uj9pKq2NcXhLd8sVtA4eB6nMw",
    "witnessContext": {
      "event": "EthDenver 2024",
      "sessionId": "session-8822-nonce",
      "method": "in-person-proximity"
    }
  }
}"#;

        assert_eq!(txt, sample);
    }

    #[test]
    fn test_rcard_serialization() {
        let rcard = DTGCredential::new_rcard(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            json!([
                "vcard",
                [
                    ["fn", {}, "text", "Alice Smith"],
                    ["email", {}, "text", "alice@example.com"]
                ]
            ]),
        );

        let txt = serde_json::to_string_pretty(&rcard).unwrap();

        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://firstperson.network/credentials/dtg/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "RCardCredential"
  ],
  "issuer": "did:example:issuer",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject",
    "card": [
      "vcard",
      [
        [
          "fn",
          {},
          "text",
          "Alice Smith"
        ],
        [
          "email",
          {},
          "text",
          "alice@example.com"
        ]
      ]
    ]
  }
}"#;

        assert_eq!(txt, sample);
    }
}
