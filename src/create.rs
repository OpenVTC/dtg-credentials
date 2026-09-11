/*!
*   Builder methods for creating new entities.
*/

#[allow(deprecated)]
use crate::{
    AuthorityGrant, CredentialSubject, CredentialSubjectAuthority, CredentialSubjectBasic,
    CredentialSubjectDelegation, CredentialSubjectEndorsement, CredentialSubjectMembership,
    CredentialSubjectRCard, CredentialSubjectWitness, DTGCommon, DTGCredential, DTGCredentialError,
    DTGCredentialType, DelegationGrant, WitnessContext,
};
use chrono::{DateTime, SubsecRound, Utc};
use serde_json::Value;

/// Refuses a validity window that closes before, or at the instant, it opens.
///
/// Only the ordering is checked. A `valid_from` in the past is legitimate — backdating is
/// how a re-issued credential keeps the date the original took effect — and whether a
/// window is current is a question about an instant the verifier chooses.
///
/// Both ends are compared at whole seconds, because that is all the wire form carries: a
/// window a few hundred milliseconds wide in memory serializes as an empty one.
pub(crate) fn check_window(
    valid_from: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
) -> Result<(), DTGCredentialError> {
    match valid_until {
        Some(valid_until) if valid_until.trunc_subsecs(0) <= valid_from.trunc_subsecs(0) => {
            Err(DTGCredentialError::InvalidValidityWindow {
                valid_from,
                valid_until,
            })
        }
        _ => Ok(()),
    }
}

/// The issuer of a credential in its wire form: a string, or an object carrying an `id`, per
/// the W3C data model.
pub(crate) fn issuer_of(credential: &serde_json::Map<String, Value>) -> Option<String> {
    credential.get("issuer").and_then(|issuer| {
        issuer
            .as_str()
            .or_else(|| issuer.get("id").and_then(Value::as_str))
            .map(str::to_string)
    })
}

/// Reads an RFC 3339 timestamp off a credential in its wire form, under its W3C VC 2.0 name
/// or its 1.1 alias.
///
/// `Ok(None)` when neither is present. A value that is present but unreadable is an error
/// rather than an absence: an expiry that cannot be read must not be treated as no expiry.
pub(crate) fn read_timestamp(
    credential: &serde_json::Map<String, Value>,
    name: &str,
    alias: &str,
) -> Result<Option<DateTime<Utc>>, String> {
    let Some(value) = credential.get(name).or_else(|| credential.get(alias)) else {
        return Ok(None);
    };
    value
        .as_str()
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| Some(t.with_timezone(&Utc)))
        .ok_or_else(|| format!("`{name}` is not an RFC 3339 timestamp"))
}

/// The `validUntil` of a grant in its wire form, if it has one.
fn grant_valid_until(grant: &Value) -> Result<Option<DateTime<Utc>>, String> {
    match grant.as_object() {
        Some(object) => read_timestamp(object, "validUntil", "expirationDate"),
        None => Ok(None),
    }
}

/// Refuses an answer to a grant — an acknowledgement or an acceptance — that would remain
/// valid after the grant it answers has expired.
///
/// Open-ended counts as outliving a grant that expires. Compared at whole seconds, the
/// precision the wire form carries.
fn check_within_grant(
    valid_until: Option<DateTime<Utc>>,
    grant_valid_until: Option<DateTime<Utc>>,
) -> Result<(), DTGCredentialError> {
    let Some(grant_valid_until) = grant_valid_until else {
        return Ok(());
    };
    match valid_until {
        Some(until) if until.trunc_subsecs(0) <= grant_valid_until.trunc_subsecs(0) => Ok(()),
        _ => Err(DTGCredentialError::OutlivesGrant {
            valid_until,
            grant_valid_until,
        }),
    }
}

impl DTGCredential {
    /// Creates a new community-issued Verifiable Membership Credential (VMC) — the
    /// membership **grant**, the community → member half of a membership edge.
    ///
    /// A membership edge is a *pair* of VMCs, and this is only one of them. The member
    /// answers with [DTGCredential::new_member_vmc_for], and the edge is not complete until
    /// they have: a community can always issue a credential naming somebody as a member,
    /// but it cannot produce the acknowledgement without that party's signature. The pair
    /// is what makes an unconsented membership claim unprovable.
    ///
    /// The grant MUST NOT carry a `digestMultibase` — that property is what marks the
    /// other direction — and this constructor does not set one.
    ///
    /// issuer: The identifier of the VTC or VTN granting membership
    /// subject: The member's identifier, or the member VTC's own for VTN membership
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
                digest_multibase: None,
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
    /// is the subject) and the subject carries a `digestMultibase` of the grant being
    /// acknowledged.
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
    /// member: The member acknowledging — the party whose key will sign this. Refused unless
    ///         the grant names exactly this identifier as its subject.
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until. Must not be later
    ///              than the grant's own `validUntil`, and must be set if the grant's is.
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::NotAMembershipGrant] if `grant` is not a JSON object, does not
    /// carry `MembershipCredential` in its `type`, has no `issuer` or
    /// `credentialSubject.id`, or already carries a `digest` — that last is an
    /// acknowledgement, and acknowledging one does not form an edge.
    ///
    /// It is also [DTGCredentialError::NotAMembershipGrant] if the grant carries a
    /// `validUntil` that is not an RFC 3339 timestamp.
    ///
    /// [DTGCredentialError::NotTheGrantSubject] if the grant's `credentialSubject.id` is not
    /// `member`.
    ///
    /// [DTGCredentialError::OutlivesGrant] if the grant expires and `valid_until` is later
    /// than it, or absent.
    ///
    /// [DTGCredentialError::InvalidValidityWindow] if `valid_until` is not after
    /// `valid_from`, and [DTGCredentialError::JsonTooDeep] if the grant is nested more deeply
    /// than [crate::MAX_JSON_DEPTH].
    ///
    /// # Give it an `id`
    ///
    /// Chain [DTGCredential::with_id] on before signing. A community keys a member's VMC by
    /// `id` to tell a re-send from a renewal.
    ///
    /// # Security
    ///
    /// The result is binding evidence, not membership. This constructor does not verify the
    /// grant's proof, so it builds an acknowledgement of a grant nobody signed as readily as
    /// of one the community did. Verify the grant first — with
    /// `verify_grant_with_public_key` under the `affinidi-signing` feature, or against your
    /// own resolver — and treat the edge as complete only once both proofs and both windows
    /// have verified.
    ///
    /// Pass as `member` the identity whose key will sign the acknowledgement, established
    /// independently of the grant. An identifier read out of the grant would make the check
    /// compare the grant with itself.
    pub fn new_member_vmc_for(
        grant: &Value,
        member: &str,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<Self, DTGCredentialError> {
        check_window(valid_from, valid_until)?;

        let (found, community) = Self::read_membership_grant(grant)?;
        if found != member {
            return Err(DTGCredentialError::NotTheGrantSubject {
                expected: member.to_string(),
                found,
            });
        }
        let grant_valid_until =
            grant_valid_until(grant).map_err(DTGCredentialError::NotAMembershipGrant)?;
        check_within_grant(valid_until, grant_valid_until)?;

        Self::assemble_member_vmc(grant, found, community, valid_from, valid_until)
    }

    /// Creates a member-issued VMC without checking who the grant names or when it expires.
    ///
    /// Identical to [DTGCredential::new_member_vmc_for] except that the member is taken from
    /// the grant with nothing to compare it against, and the grant's `validUntil` is not
    /// consulted.
    #[deprecated(
        since = "0.9.2",
        note = "Takes the member from the grant without comparing it to anything, and lets \
                the acknowledgement outlive the grant. Use DTGCredential::new_member_vmc_for, \
                which takes the member you expect and refuses a grant naming anyone else. \
                This constructor will be removed in a future release."
    )]
    pub fn new_member_vmc(
        grant: &Value,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<Self, DTGCredentialError> {
        check_window(valid_from, valid_until)?;

        let (member, community) = Self::read_membership_grant(grant)?;
        Self::assemble_member_vmc(grant, member, community, valid_from, valid_until)
    }

    /// Reads the member and the community off a membership grant in its wire form, refusing
    /// anything that is not a community-issued grant.
    fn read_membership_grant(grant: &Value) -> Result<(String, String), DTGCredentialError> {
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

        // Both spellings: `digestMultibase` is the Working Draft 02 name, `digest` the
        // Working Draft 01 one this library also accepts on the wire. Probing only the
        // current name would let an acknowledgement issued against the older draft be
        // acknowledged in turn, which forms no edge.
        if subject.contains_key("digestMultibase") || subject.contains_key("digest") {
            return Err(DTGCredentialError::NotAMembershipGrant(
                "the credential carries a digest of another credential, so it is itself a \
                 member-issued acknowledgement rather than a community-issued grant"
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

        let community = issuer_of(object)
            .ok_or_else(|| DTGCredentialError::NotAMembershipGrant("no `issuer`".into()))?;

        Ok((member, community))
    }

    /// Assembles the acknowledgement once the grant has been read and every check has passed.
    fn assemble_member_vmc(
        grant: &Value,
        member: String,
        community: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<Self, DTGCredentialError> {
        let mut vmc = DTGCommon {
            issuer: member,
            valid_from,
            valid_until,
            credential_subject: CredentialSubject::Membership(CredentialSubjectMembership {
                id: community,
                digest_multibase: Some(crate::digest_multibase_json(grant)?),
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
    /// # `valid_until` is required
    ///
    /// Not optional, unlike the base structure and unlike every other `new_*` constructor
    /// here. Nothing about the subject's current standing is consulted when a VAC is
    /// verified, so authority that does not expire is authority nobody can withdraw by
    /// waiting.
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::InvalidValidityWindow] if `valid_until` is not after
    /// `valid_from`, and [DTGCredentialError::EmptyAuthorityActions] if `actions` is empty.
    pub fn new_vac(
        issuer: String,
        subject: String,
        scope: String,
        actions: Vec<String>,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, DTGCredentialError> {
        check_window(valid_from, Some(valid_until))?;

        if actions.is_empty() {
            return Err(DTGCredentialError::EmptyAuthorityActions);
        }
        let mut vac = DTGCommon {
            issuer,
            valid_from,
            valid_until: Some(valid_until),
            credential_subject: CredentialSubject::Authority(CredentialSubjectAuthority {
                id: subject,
                authority: AuthorityGrant {
                    scope,
                    actions,
                    parent: None,
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
    /// carries `parent` — the **digest** of the credential it narrows — so a verifier can
    /// walk back to a root.
    ///
    /// Refuses anything that would widen. The checks here mirror
    /// [crate::authority::verify_chain] on purpose: a holder should be unable to *build* a
    /// chain a verifier would reject, so the failure surfaces at issue time rather than at
    /// use — but the verifier's checks remain authoritative, because nothing stops a
    /// different implementation constructing the JSON by hand.
    ///
    /// - `self` must be a VAC.
    /// - `actions` must be a subset of what `self` confers.
    /// - `valid_until` must not exceed `self`'s.
    ///
    /// # Binding the derivative to the agent is `subject`, not a separate field
    ///
    /// A VAC is not a bearer credential: [crate::authority::verify_chain] requires the
    /// party presenting the leaf to be its subject. So equipping an agent means naming the
    /// agent in `subject`, and there is nothing further to bind. An earlier version of this
    /// method took an `audience` for that job; it was removed with the property.
    ///
    /// # Digests the model
    ///
    /// The `parent` digest is computed with [DTGCredential::digest_multibase], which hashes
    /// this in-memory credential. That is right for a VAC this process built and signed.
    /// For one that **arrived from a counterparty**, use
    /// [DTGCredential::attenuate_from_json] and give it the bytes you received — the same
    /// distinction [DTGCredential::new_member_vmc_for] draws, and for the same reason.
    pub fn attenuate(
        &self,
        subject: String,
        actions: Vec<String>,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, DTGCredentialError> {
        let parent_grant = self
            .credential()
            .authority()
            .ok_or(DTGCredentialError::NotAnAuthorityCredential)?;

        Self::attenuate_inner(
            parent_grant.clone(),
            self.credential().subject().to_string(),
            self.credential().valid_until(),
            self.digest_multibase()?,
            subject,
            actions,
            valid_from,
            valid_until,
        )
    }

    /// Derive a narrower VAC from a parent in its **wire form**.
    ///
    /// Identical to [DTGCredential::attenuate] except that the parent is the JSON a
    /// counterparty sent rather than a parsed credential, so the `parent` digest covers
    /// the document the verifier will recompute it over. Use this whenever the VAC being
    /// narrowed came from somewhere else.
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::NotAnAuthorityCredential] if `parent` is not a JSON object
    /// carrying `AuthorityCredential` in its `type` and a well-formed
    /// `credentialSubject.authority`, and the same widening errors as
    /// [DTGCredential::attenuate].
    pub fn attenuate_from_json(
        parent: &Value,
        subject: String,
        actions: Vec<String>,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, DTGCredentialError> {
        // Before any member is read out: reading clones one, and cloning recurses.
        crate::check_json_depth(parent)?;

        let object = parent
            .as_object()
            .ok_or(DTGCredentialError::NotAnAuthorityCredential)?;

        let is_authority = object
            .get("type")
            .and_then(Value::as_array)
            .is_some_and(|types| {
                types
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|t| t == "AuthorityCredential")
            });
        if !is_authority {
            return Err(DTGCredentialError::NotAnAuthorityCredential);
        }

        let parent_subject = object
            .get("credentialSubject")
            .and_then(Value::as_object)
            .ok_or(DTGCredentialError::NotAnAuthorityCredential)?;

        // The holder attenuating is the parent's subject; reading it off the parent is what
        // keeps a derived VAC from citing a chain its issuer never held.
        let holder = parent_subject
            .get("id")
            .and_then(Value::as_str)
            .ok_or(DTGCredentialError::NotAnAuthorityCredential)?
            .to_string();

        let parent_grant: AuthorityGrant = parent_subject
            .get("authority")
            .ok_or(DTGCredentialError::NotAnAuthorityCredential)
            .and_then(|a| {
                serde_json::from_value(a.clone())
                    .map_err(|_| DTGCredentialError::NotAnAuthorityCredential)
            })?;

        let parent_until = object
            .get("validUntil")
            .or_else(|| object.get("expirationDate"))
            .and_then(Value::as_str)
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.with_timezone(&Utc));

        Self::attenuate_inner(
            parent_grant,
            holder,
            parent_until,
            crate::digest_multibase_json(parent)?,
            subject,
            actions,
            valid_from,
            valid_until,
        )
    }

    /// The narrowing checks and the assembly, shared by both attenuation entry points.
    #[allow(clippy::too_many_arguments)]
    fn attenuate_inner(
        parent_grant: AuthorityGrant,
        holder: String,
        parent_until: Option<DateTime<Utc>>,
        parent_digest: String,
        subject: String,
        actions: Vec<String>,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, DTGCredentialError> {
        check_window(valid_from, Some(valid_until))?;

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
        if let Some(parent_until) = parent_until
            && valid_until > parent_until
        {
            return Err(DTGCredentialError::AttenuationWidens(format!(
                "validUntil {valid_until} is beyond the parent's {parent_until}"
            )));
        }

        let mut vac = DTGCommon {
            // The holder issues: they are the subject of the parent grant.
            issuer: holder,
            valid_from,
            valid_until: Some(valid_until),
            credential_subject: CredentialSubject::Authority(CredentialSubjectAuthority {
                id: subject,
                authority: AuthorityGrant {
                    // Scope never changes down a chain.
                    scope: parent_grant.scope.clone(),
                    actions,
                    parent: Some(parent_digest),
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

    /// Creates a new Verifiable Delegation Credential (VDC) — the delegation **grant**,
    /// the delegator → delegate half of a delegation edge.
    ///
    /// Establishes that `subject` may act **in the issuer's name**, for the acts named in
    /// `scope`, until `valid_until`. Within that scope what the delegate does is
    /// attributable to the delegator.
    ///
    /// # This is not authority
    ///
    /// A VDC never supplies permission the delegator did not itself hold. A verifier
    /// substitutes the delegator for the delegate and then asks the permission question it
    /// would have asked of the delegator directly — so withdrawing the delegator's own
    /// permission ends the delegate's ability to act immediately, without revoking
    /// anything. See [DTGCredential::new_vac] for the credential that answers that
    /// question.
    ///
    /// # The edge is not complete without the acceptance
    ///
    /// This is one half. The delegate answers with [DTGCredential::new_delegate_vdc_for], and
    /// a verifier MUST obtain and verify that half before accepting any party as acting
    /// under the delegation: a grant alone establishes what the delegator appointed, not
    /// what the delegate agreed to. Same consent rule as a membership edge, and for the
    /// same reason — a delegator can always name someone as its delegate, but cannot
    /// produce the countersignature.
    ///
    /// `scope` MUST NOT be empty: a VDC cannot express an unbounded appointment by
    /// omitting it.
    ///
    /// `max_depth` is the number of further re-delegations permitted below this one.
    /// `None` and `Some(0)` both prohibit re-delegation — the default is a single hop, and
    /// setting it above zero is the delegator's explicit authorisation, of which there is
    /// no other kind.
    ///
    /// # `valid_until` is required
    ///
    /// An appointment with no expiry cannot be reasoned about by a verifier that cannot
    /// reach the delegator.
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::MalformedDelegation] if `scope` is empty, and
    /// [DTGCredentialError::InvalidValidityWindow] if `valid_until` is not after
    /// `valid_from`.
    pub fn new_vdc(
        issuer: String,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        scope: Vec<String>,
        max_depth: Option<u32>,
    ) -> Result<Self, DTGCredentialError> {
        check_window(valid_from, Some(valid_until))?;

        if scope.is_empty() {
            return Err(DTGCredentialError::MalformedDelegation(
                "a grant MUST carry at least one `scope` entry — a VDC cannot express an \
                 unbounded appointment by emptying it"
                    .into(),
            ));
        }

        let mut vdc = DTGCommon {
            issuer,
            valid_from,
            valid_until: Some(valid_until),
            credential_subject: CredentialSubject::Delegation(CredentialSubjectDelegation {
                id: subject,
                delegation: DelegationGrant {
                    scope: Some(scope),
                    parent: None,
                    max_depth,
                    accepts: None,
                },
            }),
            ..Default::default()
        };

        vdc.type_.push(DTGCredentialType::Delegation.to_string());

        Ok(DTGCredential {
            credential: vdc,
            type_: DTGCredentialType::Delegation,
            version: crate::W3CVCVersion::V2_0,
        })
    }

    /// Derive a further VDC from one this delegate already holds — a **re-delegation**.
    ///
    /// Only permitted where the held VDC sets `maxDepth` above zero, and only for a subset
    /// of the acts it was itself appointed for. The default is a single hop: a delegate
    /// that needs a further delegate and is not authorised to re-delegate asks the
    /// principal, who issues a fresh root delegation directly — so that the principal
    /// always holds the complete register of who may speak in its name.
    ///
    /// The derived VDC carries `parent`, the digest of the VDC it derives from, and a
    /// `maxDepth` one less than its parent's.
    ///
    /// Like [DTGCredential::attenuate], this digests the in-memory model; for a grant that
    /// arrived from a counterparty, use [DTGCredential::redelegate_from_json].
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::MalformedDelegation] if `self` is not a delegation grant, if
    /// it does not permit re-delegation, if `scope` is empty or not a subset of the
    /// parent's, or if `valid_until` is later than the parent's.
    /// [DTGCredentialError::InvalidValidityWindow] if `valid_until` is not after
    /// `valid_from`.
    pub fn redelegate(
        &self,
        subject: String,
        scope: Vec<String>,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, DTGCredentialError> {
        let parent = self.credential().delegation().ok_or_else(|| {
            DTGCredentialError::MalformedDelegation("not a DelegationCredential".into())
        })?;

        Self::redelegate_inner(
            parent.clone(),
            self.credential().subject().to_string(),
            self.credential().valid_until(),
            self.digest_multibase()?,
            subject,
            scope,
            valid_from,
            valid_until,
        )
    }

    /// Derive a further VDC from a parent grant in its **wire form**.
    ///
    /// Identical to [DTGCredential::redelegate] except that the parent is the JSON the
    /// delegator sent, so the `parent` digest covers the document a verifier will
    /// recompute it over.
    pub fn redelegate_from_json(
        parent: &Value,
        subject: String,
        scope: Vec<String>,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, DTGCredentialError> {
        let (delegate, grant, parent_until) = Self::read_delegation_json(parent)?;

        Self::redelegate_inner(
            grant,
            delegate,
            parent_until,
            crate::digest_multibase_json(parent)?,
            subject,
            scope,
            valid_from,
            valid_until,
        )
    }

    /// The narrowing checks and the assembly, shared by both re-delegation entry points.
    #[allow(clippy::too_many_arguments)]
    fn redelegate_inner(
        parent_grant: DelegationGrant,
        holder: String,
        parent_until: Option<DateTime<Utc>>,
        parent_digest: String,
        subject: String,
        scope: Vec<String>,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, DTGCredentialError> {
        check_window(valid_from, Some(valid_until))?;

        if parent_grant.accepts.is_some() {
            return Err(DTGCredentialError::MalformedDelegation(
                "the parent is an acceptance, not a grant — an acceptance appoints nobody \
                 and cannot be re-delegated from"
                    .into(),
            ));
        }

        // Absence prohibits re-delegation just as `0` does. This is the opposite default
        // from a VAC, deliberately: a delegate speaks in the principal's name, so the
        // principal keeps the register of who may do so.
        let parent_depth = parent_grant.max_depth.unwrap_or(0);
        if parent_depth == 0 {
            return Err(DTGCredentialError::MalformedDelegation(
                "the parent does not permit re-delegation — `maxDepth` is absent or zero, \
                 and setting it above zero is the delegator's only way to authorise one"
                    .into(),
            ));
        }

        if scope.is_empty() {
            return Err(DTGCredentialError::MalformedDelegation(
                "a grant MUST carry at least one `scope` entry".into(),
            ));
        }
        let parent_scope = parent_grant.scope.as_deref().unwrap_or(&[]);
        for act in &scope {
            if !parent_scope.contains(act) {
                return Err(DTGCredentialError::MalformedDelegation(format!(
                    "`{act}` is not in the scope this delegation derives from"
                )));
            }
        }
        if let Some(parent_until) = parent_until
            && valid_until > parent_until
        {
            return Err(DTGCredentialError::MalformedDelegation(format!(
                "validUntil {valid_until} is beyond the parent's {parent_until}"
            )));
        }

        let mut vdc = DTGCommon {
            issuer: holder,
            valid_from,
            valid_until: Some(valid_until),
            credential_subject: CredentialSubject::Delegation(CredentialSubjectDelegation {
                id: subject,
                delegation: DelegationGrant {
                    scope: Some(scope),
                    parent: Some(parent_digest),
                    max_depth: Some(parent_depth - 1),
                    accepts: None,
                },
            }),
            ..Default::default()
        };

        vdc.type_.push(DTGCredentialType::Delegation.to_string());

        Ok(DTGCredential {
            credential: vdc,
            type_: DTGCredentialType::Delegation,
            version: crate::W3CVCVersion::V2_0,
        })
    }

    /// Creates the delegate-issued half of a delegation edge — the **acceptance**.
    ///
    /// The roles of [DTGCredential::new_vdc] are reversed (the delegate issues, the
    /// delegator is the subject) and the subject carries `accepts`, the digest of the
    /// grant being taken on. That digest is what binds the two halves into one edge.
    ///
    /// An acceptance carries no `scope` of its own. What the delegate consented to is the
    /// scope of the grant it names, which a verifier holds in any case; restating it would
    /// require an equality check across the two credentials that cannot be satisfied under
    /// selective disclosure of either.
    ///
    /// This is the delegate's consent artifact, and its accountability for acting in
    /// another's name. Because a delegator cannot produce it, a party holding only the
    /// delegate's key cannot manufacture appointments either.
    ///
    /// # Takes the grant in its wire form, deliberately
    ///
    /// Same reasoning as [DTGCredential::new_member_vmc_for]: the digest has to cover the
    /// document the delegator will recompute it over. Keep the bytes you were given and
    /// pass them here.
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::NotADelegationGrant] if `grant` is not a JSON object carrying
    /// `DelegationCredential` in its `type`, has no `issuer` or `credentialSubject.id`, or
    /// already carries `accepts` — that last is itself an acceptance, and accepting one
    /// forms no edge.
    ///
    /// It is also [DTGCredentialError::NotADelegationGrant] if the grant carries a
    /// `validUntil` that is not an RFC 3339 timestamp.
    ///
    /// [DTGCredentialError::NotTheGrantSubject] if the grant's `credentialSubject.id` is not
    /// `delegate`.
    ///
    /// [DTGCredentialError::OutlivesGrant] if `valid_until` is later than the grant's.
    ///
    /// [DTGCredentialError::InvalidValidityWindow] if `valid_until` is not after
    /// `valid_from`, and [DTGCredentialError::JsonTooDeep] if the grant is nested more deeply
    /// than [crate::MAX_JSON_DEPTH].
    ///
    /// # Security
    ///
    /// The result is binding evidence, not an appointment. This constructor does not verify
    /// the grant's proof, so it builds an acceptance of a grant nobody signed as readily as of
    /// one the delegator did. Verify the grant first — with `verify_grant_with_public_key`
    /// under the `affinidi-signing` feature, or against your own resolver — and treat the edge
    /// as complete only once both proofs and both windows have verified.
    ///
    /// Pass as `delegate` the identity whose key will sign the acceptance, established
    /// independently of the grant. An identifier read out of the grant would make the check
    /// compare the grant with itself.
    pub fn new_delegate_vdc_for(
        grant: &Value,
        delegate: &str,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, DTGCredentialError> {
        check_window(valid_from, Some(valid_until))?;

        let (found, delegator) = Self::read_delegation_grant(grant)?;
        if found != delegate {
            return Err(DTGCredentialError::NotTheGrantSubject {
                expected: delegate.to_string(),
                found,
            });
        }
        let grant_valid_until =
            grant_valid_until(grant).map_err(DTGCredentialError::NotADelegationGrant)?;
        check_within_grant(Some(valid_until), grant_valid_until)?;

        Self::assemble_delegate_vdc(grant, found, delegator, valid_from, valid_until)
    }

    /// Creates a delegate-issued acceptance without checking who the grant appoints or when it
    /// expires.
    ///
    /// Identical to [DTGCredential::new_delegate_vdc_for] except that the delegate is taken
    /// from the grant with nothing to compare it against, and the grant's `validUntil` is not
    /// consulted.
    #[deprecated(
        since = "0.9.2",
        note = "Takes the delegate from the grant without comparing it to anything, and lets \
                the acceptance outlive the grant. Use DTGCredential::new_delegate_vdc_for, \
                which takes the delegate you expect and refuses a grant appointing anyone \
                else. This constructor will be removed in a future release."
    )]
    pub fn new_delegate_vdc(
        grant: &Value,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, DTGCredentialError> {
        check_window(valid_from, Some(valid_until))?;

        let (delegate, delegator) = Self::read_delegation_grant(grant)?;
        Self::assemble_delegate_vdc(grant, delegate, delegator, valid_from, valid_until)
    }

    /// Reads the delegate and the delegator off a delegation grant in its wire form, refusing
    /// anything that is not a grant.
    fn read_delegation_grant(grant: &Value) -> Result<(String, String), DTGCredentialError> {
        let object = grant
            .as_object()
            .ok_or_else(|| DTGCredentialError::NotADelegationGrant("not a JSON object".into()))?;

        let is_delegation = object
            .get("type")
            .and_then(Value::as_array)
            .is_some_and(|types| {
                types
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|t| t == "DelegationCredential")
            });
        if !is_delegation {
            return Err(DTGCredentialError::NotADelegationGrant(
                "`type` does not include `DelegationCredential`".into(),
            ));
        }

        let subject = object
            .get("credentialSubject")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                DTGCredentialError::NotADelegationGrant("no `credentialSubject`".into())
            })?;

        let delegation = subject
            .get("delegation")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                DTGCredentialError::NotADelegationGrant("no `credentialSubject.delegation`".into())
            })?;

        if delegation.contains_key("accepts") {
            return Err(DTGCredentialError::NotADelegationGrant(
                "the credential carries `accepts`, so it is itself an acceptance rather \
                 than a grant"
                    .into(),
            ));
        }
        if !delegation.contains_key("scope") {
            return Err(DTGCredentialError::NotADelegationGrant(
                "the grant carries no `scope`, so there is no appointment to accept".into(),
            ));
        }

        // The delegate is the grant's subject and the delegator its issuer. Reading both
        // off the grant is what keeps the two halves naming the same pair — taking them as
        // parameters would let a caller accept one grant while naming the parties of
        // another, which verifies as a digest match and means nothing.
        let delegate = subject
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                DTGCredentialError::NotADelegationGrant("no `credentialSubject.id`".into())
            })?
            .to_string();

        let delegator = issuer_of(object)
            .ok_or_else(|| DTGCredentialError::NotADelegationGrant("no `issuer`".into()))?;

        Ok((delegate, delegator))
    }

    /// Assembles the acceptance once the grant has been read and every check has passed.
    fn assemble_delegate_vdc(
        grant: &Value,
        delegate: String,
        delegator: String,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, DTGCredentialError> {
        let mut vdc = DTGCommon {
            issuer: delegate,
            valid_from,
            valid_until: Some(valid_until),
            credential_subject: CredentialSubject::Delegation(CredentialSubjectDelegation {
                id: delegator,
                delegation: DelegationGrant {
                    scope: None,
                    parent: None,
                    max_depth: None,
                    accepts: Some(crate::digest_multibase_json(grant)?),
                },
            }),
            ..Default::default()
        };

        vdc.type_.push(DTGCredentialType::Delegation.to_string());

        Ok(DTGCredential {
            credential: vdc,
            type_: DTGCredentialType::Delegation,
            version: crate::W3CVCVersion::V2_0,
        })
    }

    /// Reads the delegate, the grant, and the parent's expiry off a VDC in its wire form.
    fn read_delegation_json(
        doc: &Value,
    ) -> Result<(String, DelegationGrant, Option<DateTime<Utc>>), DTGCredentialError> {
        // Before any member is read out: reading clones one, and cloning recurses.
        crate::check_json_depth(doc)?;

        let object = doc
            .as_object()
            .ok_or_else(|| DTGCredentialError::MalformedDelegation("not a JSON object".into()))?;

        let is_delegation = object
            .get("type")
            .and_then(Value::as_array)
            .is_some_and(|types| {
                types
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|t| t == "DelegationCredential")
            });
        if !is_delegation {
            return Err(DTGCredentialError::MalformedDelegation(
                "`type` does not include `DelegationCredential`".into(),
            ));
        }

        let subject = object
            .get("credentialSubject")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                DTGCredentialError::MalformedDelegation("no `credentialSubject`".into())
            })?;

        let delegate = subject
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                DTGCredentialError::MalformedDelegation("no `credentialSubject.id`".into())
            })?
            .to_string();

        let grant: DelegationGrant = subject
            .get("delegation")
            .ok_or_else(|| {
                DTGCredentialError::MalformedDelegation("no `credentialSubject.delegation`".into())
            })
            .and_then(|d| {
                serde_json::from_value(d.clone()).map_err(|e| {
                    DTGCredentialError::MalformedDelegation(format!("malformed `delegation`: {e}"))
                })
            })?;

        let until = object
            .get("validUntil")
            .or_else(|| object.get("expirationDate"))
            .and_then(Value::as_str)
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.with_timezone(&Utc));

        Ok((delegate, grant, until))
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
    ///
    /// # Security
    ///
    /// `endorsement` is embedded verbatim. The specification does not define its content,
    /// so its shape is the issuer's to choose and this library checks nothing about it but
    /// its depth. A VEC says only that its issuer said this: a consumer must verify the
    /// proof, *and* establish that the issuer is one whose endorsements it accepts for this
    /// purpose, before relying on any member of it.
    ///
    /// Build it from input you control. Nesting past [crate::MAX_JSON_DEPTH] is refused
    /// when the credential is validated, digested or signed rather than here, because this
    /// constructor cannot return an error.
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
    /// issuer: The issuer DID of the credential - a member's identifier, or the DID of a
    ///         VTA acting according to VTC policy
    /// subject: The DID of the observed party. For a witnessed bi-directional exchange this
    ///          MUST be the issuer of the VRC that this VWC attests (the VRC referenced by
    ///          `digestMultibase`), so that the two VWCs of an exchange are unambiguously bound to
    ///          their respective directions. The witness should issue one VWC per direction.
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    /// task_context: Required `threadId` of the trust task exchange the witnessing occurred in
    /// digest: Cryptographic hash of the witnessed edge credential, binding this VWC to the
    ///         specific edge. Produce it with [DTGCredential::digest_multibase] on that
    ///         credential, or [crate::digest_multibase_json] on the bytes you received.
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
                digest_multibase: digest,
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

    /// Attaches the status mechanism through which a verifier determines whether this
    /// credential has been revoked.
    ///
    /// The entry is opaque to this library: the mechanism is chosen by the governing VTC
    /// or VTN, and nothing here selects one or resolves it. `BitstringStatusListEntry` is
    /// the common choice.
    ///
    /// ```
    /// # use chrono::{Duration, Utc};
    /// # use dtg_credentials::DTGCredential;
    /// # use serde_json::json;
    /// let vdc = DTGCredential::new_vdc(
    ///     "did:example:delegator".to_string(),
    ///     "did:example:delegate".to_string(),
    ///     Utc::now(),
    ///     Utc::now() + Duration::days(90),
    ///     vec!["sign:invoices".to_string()],
    ///     None,
    /// )
    /// .unwrap()
    /// .with_credential_status(json!({
    ///     "id": "https://example.com/status/3#94567",
    ///     "type": "BitstringStatusListEntry",
    ///     "statusPurpose": "revocation",
    ///     "statusListIndex": "94567",
    ///     "statusListCredential": "https://example.com/status/3"
    /// }));
    /// assert!(vdc.credential().credential_status.is_some());
    /// ```
    ///
    /// # When a VDC needs one
    ///
    /// CONDITIONAL, not required. A verifier MUST be able to establish that an appointment
    /// is in force without contacting the delegator, and either of two things satisfies
    /// that: a `validUntil` short enough that expiry alone bounds the exposure, or a status
    /// entry the verifier can check. A VDC MUST carry one where its validity period exceeds
    /// the freshness window the governing VTC or VTN defines for delegations, and MAY omit
    /// it otherwise.
    ///
    /// That window is governance this library does not know, so it cannot decide for a
    /// caller which side of the condition a given VDC falls on — hence a setter rather than
    /// a constructor parameter. Prefer short validity and re-issuance wherever the
    /// delegator is reachable: a status check is a live lookup that reveals the
    /// verification event to whoever hosts the status list. A long-lived appointment made
    /// in advance of a delegator's unavailability is the case this exists for.
    ///
    /// # Set it before signing
    ///
    /// Same caveat as [DTGCredential::with_id] — a Data Integrity proof covers the
    /// credential minus its `proof`, so attaching a status entry to an already-signed
    /// credential leaves a document whose proof no longer verifies.
    ///
    /// # This library does not check it
    ///
    /// Neither [`crate::delegation::verify_chain`] nor [`crate::authority::verify_chain`]
    /// resolves a status entry; both verify structure, scope and validity only. Revocation
    /// is a live lookup the caller performs.
    ///
    /// # Security
    ///
    /// The entry is embedded verbatim and nothing about it is checked when it is attached.
    /// It tells a verifier where to look, so a verifier must check the credential's proof
    /// before following it, and should apply its own policy to where it leads. Nesting past
    /// [crate::MAX_JSON_DEPTH] is refused when the credential is validated, digested or
    /// signed, because this setter cannot return an error.
    pub fn with_credential_status(mut self, status: Value) -> Self {
        self.credential.credential_status = Some(status);
        self
    }

    /// Attaches a revocation status mechanism in place.
    ///
    /// The non-consuming form of [DTGCredential::with_credential_status]; the same "before
    /// signing" caveat, the same CONDITIONAL rule and the same security notes apply.
    pub fn set_credential_status(&mut self, status: Value) {
        self.credential.credential_status = Some(status);
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
    "digestMultibase": "zQmbGXRT3v1RmfWkQ7Y3Z5Uj9pKq2NcXhLd8sVtA4eB6nMw",
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
