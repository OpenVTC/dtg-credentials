/*!
*   Builder methods for creating new entities.
*/

#[allow(deprecated)]
use crate::{
    AuthorityGrant, CredentialSubject, CredentialSubjectAuthority, CredentialSubjectBasic,
    CredentialSubjectEndorsement, CredentialSubjectMembership, CredentialSubjectRCard,
    CredentialSubjectWitness, DTGCommon, DTGCredential, DTGCredentialError, DTGCredentialType,
    WitnessContext,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

impl DTGCredential {
    /// Creates a new community-issued Verifiable Membership Credential (VMC) — the
    /// membership **grant**, the community → member half of a membership edge.
    ///
    /// A membership edge is a *pair* of VMCs, and this is only one of them. The member
    /// answers with [DTGCredential::new_member_vmc], and the edge is not complete until
    /// they have: a community can always issue a credential naming somebody as a member,
    /// but it cannot produce the acknowledgement without that party's signature. The pair
    /// is what makes an unconsented membership claim unprovable.
    ///
    /// The grant MUST NOT carry a `digest` — that property is what marks the other
    /// direction — and this constructor does not set one.
    ///
    /// issuer: The C-DID of the VTC or VTN granting membership
    /// subject: The M-DID of the member, or the member VTC's C-DID for VTN membership
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    /// personhood: Whether this VMC can be used as a form of Personhood Credential
    ///             - Adds PersonhoodCredential to the type array if true
    ///
    /// # Give it an `id`
    ///
    /// Chain [DTGCredential::with_id] on: the member stores the grant under its `id`, and
    /// re-issuing is only recognisable as a renewal rather than a duplicate if there is one.
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
            credential_subject: CredentialSubject::Membership(CredentialSubjectMembership {
                id: subject,
                digest: None,
            }),
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

    /// Creates a new member-issued Verifiable Membership Credential (VMC) — the membership
    /// **acknowledgement**, the member → community half of a membership edge.
    ///
    /// The roles of [DTGCredential::new_vmc] are reversed (the member issues, the community
    /// is the subject) and the subject carries a `digest` of the grant being acknowledged.
    /// That digest is what binds the two halves into one edge: an acknowledgement whose
    /// digest matches no valid grant does not complete anything, and the binding forces an
    /// order — the grant must exist before this can reference it.
    ///
    /// This is the member's consent artifact. Because the member is its issuer, withdrawing
    /// consent needs no cooperation from the community.
    ///
    /// # Takes the grant in its wire form, deliberately
    ///
    /// `grant` is the JSON the community sent, not a parsed [DTGCredential]. The digest has
    /// to cover the document the community will recompute it over, and this library does
    /// not model every member a credential may carry — `credentialStatus`, which every VMC
    /// issued against a status list carries, is dropped by a parse-then-re-serialise round
    /// trip. Building the acknowledgement from a parsed grant would produce a digest that
    /// verifies nowhere, and would do it silently.
    ///
    /// So: keep the bytes you were given, and pass them here.
    ///
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::NotAMembershipGrant] if `grant` is not a JSON object, does not
    /// carry `MembershipCredential` in its `type`, has no `issuer` or
    /// `credentialSubject.id`, or already carries a `digest` — that last is an
    /// acknowledgement, and acknowledging one does not form an edge.
    ///
    /// # Give it an `id`
    ///
    /// Chain [DTGCredential::with_id] on before signing. A community keys a member's VMC by
    /// `id` to tell a re-send from a renewal.
    pub fn new_member_vmc(
        grant: &Value,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<Self, DTGCredentialError> {
        let object = grant
            .as_object()
            .ok_or_else(|| DTGCredentialError::NotAMembershipGrant("not a JSON object".into()))?;

        let is_membership = object
            .get("type")
            .and_then(Value::as_array)
            .is_some_and(|types| {
                types
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|t| t == "MembershipCredential")
            });
        if !is_membership {
            return Err(DTGCredentialError::NotAMembershipGrant(
                "`type` does not include `MembershipCredential`".into(),
            ));
        }

        let subject = object
            .get("credentialSubject")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                DTGCredentialError::NotAMembershipGrant("no `credentialSubject`".into())
            })?;

        if subject.contains_key("digest") {
            return Err(DTGCredentialError::NotAMembershipGrant(
                "the credential carries a `digest`, so it is itself a member-issued \
                 acknowledgement rather than a community-issued grant"
                    .into(),
            ));
        }

        // The member is the grant's subject and the community its issuer: reading both off
        // the grant is what keeps the two halves naming the same pair. Taking them as
        // parameters would let a caller acknowledge one grant while naming the parties of
        // another, which verifies as a digest match and means nothing.
        let member = subject
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                DTGCredentialError::NotAMembershipGrant("no `credentialSubject.id`".into())
            })?
            .to_string();

        // `issuer` is a string or an object with an `id`, per the W3C data model.
        let community = object
            .get("issuer")
            .and_then(|i| {
                i.as_str()
                    .map(str::to_string)
                    .or_else(|| i.get("id").and_then(Value::as_str).map(str::to_string))
            })
            .ok_or_else(|| DTGCredentialError::NotAMembershipGrant("no `issuer`".into()))?;

        let mut vmc = DTGCommon {
            issuer: member,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::Membership(CredentialSubjectMembership {
                id: community,
                digest: Some(crate::digest_json(grant)?),
            }),
            ..Default::default()
        };

        vmc.type_.push(DTGCredentialType::Membership.to_string());

        Ok(DTGCredential {
            credential: vmc,
            type_: DTGCredentialType::Membership,
            version: crate::W3CVCVersion::V2_0,
        })
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

    /// Creates a new Verifiable Authority Credential (VAC) — a chain root.
    ///
    /// The issuer is the party governing `scope`. To derive a narrower VAC from one you
    /// already hold, use [DTGCredential::attenuate] instead: a chain root is a grant made
    /// by the governing party, and minting one directly is how a self-issued grant of
    /// arbitrary authority gets in.
    ///
    /// `actions` MUST NOT be empty — an empty list confers nothing rather than everything.
    ///
    /// Tracks a draft (`trustoverip/dtgwg-cred-spec` PR #29); the shape may move.
    pub fn new_vac(
        issuer: String,
        subject: String,
        scope: String,
        actions: Vec<String>,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<Self, DTGCredentialError> {
        if actions.is_empty() {
            return Err(DTGCredentialError::EmptyAuthorityActions);
        }
        let mut vac = DTGCommon {
            issuer,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::Authority(CredentialSubjectAuthority {
                id: subject,
                authority: AuthorityGrant {
                    scope,
                    actions,
                    parent: None,
                    audience: None,
                },
            }),
            ..Default::default()
        };

        vac.type_.push(DTGCredentialType::Authority.to_string());

        Ok(DTGCredential {
            credential: vac,
            type_: DTGCredentialType::Authority,
            version: crate::W3CVCVersion::V2_0,
        })
    }

    /// Derive a narrower VAC from one this holder already holds.
    ///
    /// This is what lets a member equip an agent, a device, or a short-lived session with
    /// only the authority that task needs, rather than lending it their own. The derived
    /// credential is issued by the *holder*, not by the party governing the scope, and
    /// carries `parent` so a verifier can walk back to a root.
    ///
    /// Refuses anything that would widen. The checks here mirror
    /// [crate::authority::verify_chain] on purpose: a holder should be unable to *build* a
    /// chain a verifier would reject, so the failure surfaces at issue time rather than at
    /// use — but the verifier's checks remain authoritative, because nothing stops a
    /// different implementation constructing the JSON by hand.
    ///
    /// - `self` must be a VAC, and must carry an `id` (a parent with no identifier cannot
    ///   be pointed at).
    /// - `actions` must be a subset of what `self` confers.
    /// - `valid_until` must not exceed `self`'s.
    /// - `audience` binds the derived credential to one presenter; strongly recommended
    ///   when equipping an agent, since it makes a leaked credential useless to anyone else.
    pub fn attenuate(
        &self,
        subject: String,
        actions: Vec<String>,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        audience: Option<String>,
    ) -> Result<Self, DTGCredentialError> {
        let parent_grant = self
            .credential()
            .authority()
            .ok_or(DTGCredentialError::NotAnAuthorityCredential)?;

        let parent_id = self
            .id()
            .ok_or(DTGCredentialError::AttenuationParentHasNoId)?
            .to_string();

        if actions.is_empty() {
            return Err(DTGCredentialError::EmptyAuthorityActions);
        }
        for action in &actions {
            if !parent_grant.actions.contains(action) {
                return Err(DTGCredentialError::AttenuationWidens(format!(
                    "action `{action}` is not conferred by the parent"
                )));
            }
        }
        if let (Some(until), Some(parent_until)) = (valid_until, self.credential().valid_until())
            && until > parent_until
        {
            return Err(DTGCredentialError::AttenuationWidens(format!(
                "validUntil {until} is beyond the parent's {parent_until}"
            )));
        }

        let mut vac = DTGCommon {
            // The holder issues: they are the subject of the parent grant.
            issuer: self.credential().subject().to_string(),
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::Authority(CredentialSubjectAuthority {
                id: subject,
                authority: AuthorityGrant {
                    // Scope never changes down a chain.
                    scope: parent_grant.scope.clone(),
                    actions,
                    parent: Some(parent_id),
                    audience,
                },
            }),
            ..Default::default()
        };

        vac.type_.push(DTGCredentialType::Authority.to_string());

        Ok(DTGCredential {
            credential: vac,
            type_: DTGCredentialType::Authority,
            version: crate::W3CVCVersion::V2_0,
        })
    }

    /// Creates a new Verifiable Delegation Credential (VDC).
    ///
    /// Establishes that `subject` may act **in the issuer's name**. This is not authority:
    /// a VDC never supplies permission the delegator did not itself hold, and a verifier
    /// must settle the two questions separately. See [DTGCredential::new_vac].
    ///
    /// Tracks a draft (`trustoverip/dtgwg-cred-spec` PR #19); the shape may move.
    pub fn new_vdc(
        issuer: String,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Self {
        let mut vdc = DTGCommon {
            issuer,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::Basic(CredentialSubjectBasic { id: subject }),
            ..Default::default()
        };

        vdc.type_.push(DTGCredentialType::Delegation.to_string());

        DTGCredential {
            credential: vdc,
            type_: DTGCredentialType::Delegation,
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
    /// digest: Cryptographic hash of the witnessed edge credential, binding this VWC to the
    ///         specific edge. Produce it with [DTGCredential::digest] on that credential.
    ///         REQUIRED by the specification; `Option` here because a VWC that predates the
    ///         requirement still has to deserialize. A VWC without one identifies the
    ///         observed party and the exchange, but not which edge was witnessed.
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

    /// Sets this credential's own identifier, consuming and returning it so it chains onto
    /// any of the `new_*` constructors above.
    ///
    /// `id` MUST be a single URL per the W3C VC Data Model; `urn:uuid:<uuid>` is the usual
    /// choice for a credential with no dereferenceable home. This crate does not validate it.
    ///
    /// ```
    /// # use chrono::Utc;
    /// # use dtg_credentials::DTGCredential;
    /// let vmc = DTGCredential::new_vmc(
    ///     "did:example:member".to_string(),
    ///     "did:example:community".to_string(),
    ///     Utc::now(),
    ///     None,
    ///     false,
    /// )
    /// .with_id("urn:uuid:2a4e1d90-6e0c-4d3f-9a4a-6d0a8f7c1b52");
    /// assert_eq!(vmc.id(), Some("urn:uuid:2a4e1d90-6e0c-4d3f-9a4a-6d0a8f7c1b52"));
    /// ```
    ///
    /// # Set it before signing
    ///
    /// A Data Integrity proof covers the credential minus its `proof`, so `id` is part of what
    /// is signed. Chain this onto the constructor, before [DTGCredential::sign] — adding an id
    /// to an already-signed credential leaves a document whose proof no longer verifies.
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.credential.id = Some(id.into());
        self
    }

    /// Sets this credential's own identifier in place.
    ///
    /// The non-consuming form of [DTGCredential::with_id]; the same "before signing" caveat
    /// applies.
    pub fn set_id(&mut self, id: impl Into<String>) {
        self.credential.id = Some(id.into());
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
    /// `id` is OPTIONAL, and a credential that was never given one must keep serializing the
    /// shape it always did — no `"id": null`, no empty string.
    #[test]
    fn test_vmc_without_id_omits_the_property() {
        let vmc = DTGCredential::new_vmc(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            false,
        );

        assert_eq!(vmc.id(), None);
        let value: serde_json::Value = serde_json::to_value(&vmc).unwrap();
        assert!(
            value.get("id").is_none(),
            "an unset id must not appear on the wire at all: {value}"
        );
    }

    /// `with_id` puts the identifier at the top level of the credential — a sibling of
    /// `issuer`, not something nested under `credentialSubject` (which carries the *subject's*
    /// id, a different thing entirely).
    #[test]
    fn test_vmc_with_id_serialization() {
        let vmc = DTGCredential::new_vmc(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            None,
            false,
        )
        .with_id("urn:uuid:1e2d3c4b-5a69-4788-9099-aabbccddeeff");

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
  "id": "urn:uuid:1e2d3c4b-5a69-4788-9099-aabbccddeeff",
  "issuer": "did:example:issuer",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject"
  }
}"#;

        assert_eq!(txt, sample);
    }

    /// The identifier has to survive a round trip. It arrives on the wire and is read back
    /// through `TryFrom<DTGCommon>`, which is where `taskContext` was previously being dropped
    /// — a field that deserializes into nothing breaks signing and verification silently.
    #[test]
    fn test_id_round_trips_through_deserialization() {
        let vmc = DTGCredential::new_vmc(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            Utc::now(),
            None,
            false,
        )
        .with_id("urn:uuid:1e2d3c4b-5a69-4788-9099-aabbccddeeff");

        let txt = serde_json::to_string(&vmc).unwrap();
        let parsed: DTGCredential = serde_json::from_str(&txt).unwrap();
        assert_eq!(
            parsed.id(),
            Some("urn:uuid:1e2d3c4b-5a69-4788-9099-aabbccddeeff")
        );
    }

    /// A credential with no `id` still deserializes — the property is OPTIONAL, and every
    /// credential issued before this field existed has none.
    #[test]
    fn test_missing_id_deserializes_as_none() {
        let parsed: DTGCredential = serde_json::from_str(
            r#"{
              "@context": ["https://www.w3.org/ns/credentials/v2"],
              "type": ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
              "issuer": "did:example:issuer",
              "validFrom": "2025-12-11T00:00:00Z",
              "credentialSubject": { "id": "did:example:subject" }
            }"#,
        )
        .unwrap();
        assert_eq!(parsed.id(), None);
    }

    /// `set_id` is the in-place form of `with_id`; both write the same property.
    #[test]
    fn test_set_id_matches_with_id() {
        let build = || {
            DTGCredential::new_vrc(
                "did:example:issuer".to_string(),
                "did:example:subject".to_string(),
                DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                None,
            )
        };
        let mut in_place = build();
        in_place.set_id("urn:uuid:abc");
        assert_eq!(
            serde_json::to_value(&in_place).unwrap(),
            serde_json::to_value(build().with_id("urn:uuid:abc")).unwrap()
        );
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
