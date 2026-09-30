/*!
*   Builder methods for creating new entities.
*/

use crate::{
    AuthorityGrant, CredentialSubject, CredentialSubjectAuthority, CredentialSubjectBasic,
    CredentialSubjectDelegation, CredentialSubjectMembership, DTGCredential, DTGCredentialError,
    DTGCredentialType, DelegationGrant, IssuerScope,
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

/// The `type` prefix every version of `witness/session` shares.
const WITNESS_SESSION_TYPE_PREFIX: &str = "https://trusttasks.org/spec/witness/session/";

/// Refuses anything but the `witness/session` document that opened a witness session.
///
/// Two checks, both about naming the right exchange. The `type` must be
/// `witness/session/<major>.<minor>` exactly — `witness/session/submit/0.1` shares the
/// prefix and is the likeliest wrong document to hold, and a `#response` fragment is the
/// witness's answer, not the opening document. And `threadId` must equal `id`, which
/// `witness/session` Conformance, item 1, requires of the opening document.
pub(crate) fn check_witness_session(session: &Value) -> Result<(), DTGCredentialError> {
    let object = session
        .as_object()
        .ok_or_else(|| DTGCredentialError::MalformedTaskDocument("not a JSON object".into()))?;
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| DTGCredentialError::MalformedTaskDocument("no string `id`".into()))?;

    let type_ = object
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let is_version = |v: &str| {
        v.split_once('.').is_some_and(|(major, minor)| {
            !major.is_empty()
                && !minor.is_empty()
                && major.bytes().all(|b| b.is_ascii_digit())
                && minor.bytes().all(|b| b.is_ascii_digit())
        })
    };
    if !type_
        .strip_prefix(WITNESS_SESSION_TYPE_PREFIX)
        .is_some_and(is_version)
    {
        return Err(DTGCredentialError::NotAWitnessSession(format!(
            "`type` is `{type_}`"
        )));
    }

    match object.get("threadId").and_then(Value::as_str) {
        Some(thread_id) if thread_id == id => Ok(()),
        Some(thread_id) => Err(DTGCredentialError::NotAWitnessSession(format!(
            "`threadId` `{thread_id}` is not the document's own `id` `{id}`"
        ))),
        None => Err(DTGCredentialError::NotAWitnessSession(
            "no `threadId`; the opening document names its own thread".into(),
        )),
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

/// The prefix of the action a community-issued role VAC confers: `role:<name>`.
pub const ROLE_ACTION_PREFIX: &str = "role:";

/// The action string conferring role `name`: `role:<name>`, as
/// [DTGCredential::new_community_role_vac] issues it. `role_action("vetter")` is
/// `"role:vetter"`.
///
/// A convention, not a vocabulary this library enforces: actions are compared exactly,
/// and the governing party defines what each one means.
pub fn role_action(name: &str) -> String {
    format!("{ROLE_ACTION_PREFIX}{name}")
}

/// What the holder asks for when attenuating, gathered so the two entry points share one
/// narrowing check.
struct Attenuation {
    issuer_scope: IssuerScope,
    subject: String,
    actions: Vec<String>,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    max_attenuation: Option<u32>,
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
    /// # `issuerScope` is always `public`
    ///
    /// A community's own identifier can only truthfully be declared `public` — a community
    /// that cannot be found cannot be joined — so there is no parameter for it: the grant
    /// declares `public`, and a grant declaring anything else is refused at parse. The
    /// member declares its own scope in the acknowledgement.
    ///
    /// issuer: The identifier of the VTC or VTN granting membership
    /// subject: The member's identifier, or the member VTC's own for VTN membership
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    /// personhood: Whether this VMC can be used as a form of Personhood Credential
    ///             - Adds PersonhoodCredential to the type array if true, as the
    ///               non-authoritative hint DTG Core Credentials permits. PHC status is
    ///               determined by governance and trust registries, never by this string.
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
        let mut vmc = Self::build(
            DTGCredentialType::Membership,
            issuer,
            IssuerScope::Public,
            valid_from,
            valid_until,
            CredentialSubject::Membership(CredentialSubjectMembership {
                id: subject,
                digest_multibase: None,
            }),
        );

        if personhood {
            vmc.credential
                .type_
                .push(crate::PERSONHOOD_HINT.to_string());
        }
        vmc
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
    /// issuer_scope: The correlation scope the member declares for `member` — its own
    ///         choice, which this specification does not constrain. Declare the same scope
    ///         on every credential issued under one identifier.
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until. Must not be later
    ///              than the grant's own `validUntil`, and must be set if the grant's is.
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::NotAMembershipGrant] if `grant` is not a JSON object, does not
    /// carry `MembershipCredential` in its `type`, has no `issuer` or
    /// `credentialSubject.id`, or already carries a `digestMultibase` — that last is an
    /// acknowledgement, and acknowledging one does not form an edge. Also if its
    /// `issuerScope` is not `public`, the only scope a community-issued grant can carry.
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
        issuer_scope: IssuerScope,
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

        Self::assemble_member_vmc(
            grant,
            found,
            issuer_scope,
            community,
            valid_from,
            valid_until,
        )
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

        // A community-issued grant declares `public`, the only scope a community can
        // truthfully declare. One that declares anything else is not a conformant grant.
        match object.get("issuerScope").and_then(Value::as_str) {
            Some("public") => {}
            Some(other) => {
                return Err(DTGCredentialError::NotAMembershipGrant(format!(
                    "the grant declares issuerScope `{other}`; a community-issued VMC is \
                     always `public`"
                )));
            }
            None => {
                return Err(DTGCredentialError::NotAMembershipGrant(
                    "no `issuerScope`".into(),
                ));
            }
        }

        Ok((member, community))
    }

    /// Assembles the acknowledgement once the grant has been read and every check has passed.
    fn assemble_member_vmc(
        grant: &Value,
        member: String,
        issuer_scope: IssuerScope,
        community: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<Self, DTGCredentialError> {
        Ok(Self::build(
            DTGCredentialType::Membership,
            member,
            issuer_scope,
            valid_from,
            valid_until,
            CredentialSubject::Membership(CredentialSubjectMembership {
                id: community,
                digest_multibase: Some(crate::digest_multibase_json(grant)?),
            }),
        ))
    }

    /// Creates a new Verified Relationship Credential (VRC)
    /// issuer: The DID of the source party
    /// issuer_scope: The scope the source party declares for `issuer`. `pairwise` is
    ///               RECOMMENDED; a wider declaration is a disclosure made deliberately.
    /// subject: The DID of the target party as used in this relationship
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    pub fn new_vrc(
        issuer: String,
        issuer_scope: IssuerScope,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Self {
        Self::build(
            DTGCredentialType::Relationship,
            issuer,
            issuer_scope,
            valid_from,
            valid_until,
            CredentialSubject::Basic(CredentialSubjectBasic { id: subject }),
        )
    }

    /// Creates a new Verified Invitation Credential (VIC)
    /// issuer: The DID of the VTC or VTN, or of an authorized member or member VTC
    /// issuer_scope: The scope the issuer declares for `issuer` — `public` where the issuer
    ///               is the VTC or VTN itself
    /// subject: The DID of the prospective member or member VTC
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until. Keep it short:
    ///              an invitation should be single-use and short-lived.
    pub fn new_vic(
        issuer: String,
        issuer_scope: IssuerScope,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Self {
        Self::build(
            DTGCredentialType::Invitation,
            issuer,
            issuer_scope,
            valid_from,
            valid_until,
            CredentialSubject::Basic(CredentialSubjectBasic { id: subject }),
        )
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
    /// `issuer_scope` is the governing party's declaration for its own identifier —
    /// `public` where the issuer is the party governing the scope, which a chain root's
    /// issuer is. For a community conferring a role on a member,
    /// [DTGCredential::new_community_role_vac] fixes it.
    ///
    /// Attenuation below this VAC is permitted by default. To bound or forbid it, chain
    /// [DTGCredential::with_max_attenuation] on before signing.
    ///
    /// ```
    /// # use chrono::{Duration, Utc};
    /// # use dtg_credentials::{DTGCredential, IssuerScope};
    /// let vac = DTGCredential::new_vac(
    ///     "did:example:room".to_string(),
    ///     IssuerScope::Public,
    ///     "did:example:member".to_string(),
    ///     "did:example:room".to_string(),
    ///     vec!["read".to_string(), "write".to_string()],
    ///     Utc::now(),
    ///     Utc::now() + Duration::days(30),
    /// )
    /// .unwrap();
    /// assert_eq!(vac.credential().authority().unwrap().actions, ["read", "write"]);
    /// ```
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
        issuer_scope: IssuerScope,
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
        Ok(Self::build(
            DTGCredentialType::Authority,
            issuer,
            issuer_scope,
            valid_from,
            Some(valid_until),
            CredentialSubject::Authority(CredentialSubjectAuthority {
                id: subject,
                authority: AuthorityGrant {
                    scope,
                    actions,
                    parent: None,
                    max_attenuation: None,
                },
            }),
        ))
    }

    /// Creates the VAC a community issues to confer a **role** on one of its members: a
    /// chain root with `scope` the community's own DID and `actions` the single
    /// `role:<name>` action [role_action] spells.
    ///
    /// A role is authority, not reputation. It is conferred by the party governing the
    /// scope — the community — and a verifier reads it as a decision that party made,
    /// which is what a VAC is and an endorsement is not. So the vetter role a community
    /// makes a member eligible for is:
    ///
    /// ```
    /// # use chrono::{Duration, Utc};
    /// # use dtg_credentials::{DTGCredential, IssuerScope};
    /// let vac = DTGCredential::new_community_role_vac(
    ///     "did:example:community".to_string(),
    ///     "did:example:member".to_string(),
    ///     "vetter",
    ///     Utc::now(),
    ///     Utc::now() + Duration::days(90),
    /// )
    /// .unwrap();
    ///
    /// assert_eq!(vac.issuer_scope(), IssuerScope::Public);
    /// let authority = vac.credential().authority().unwrap();
    /// assert_eq!(authority.scope, "did:example:community");
    /// assert_eq!(authority.actions, ["role:vetter"]);
    /// ```
    ///
    /// `issuerScope` is `public`, the only scope a community can truthfully declare. The
    /// role is checked like any other action — exactly and case-sensitively, through
    /// [crate::authority::verify_chain] with `requested_scope` the community's DID and
    /// `requested_action` the `role:<name>` string. A member holding several roles holds
    /// several VACs, or one built with [DTGCredential::new_vac] listing every role action:
    /// `actions` stays a plain string set, and nothing here privileges the `role:`
    /// convention over any other action a community defines.
    ///
    /// Membership is a separate credential. A role VAC does not attest that its subject is
    /// a member, and a verifier requiring both asks for both.
    ///
    /// # Errors
    ///
    /// As [DTGCredential::new_vac]. `role` is not validated beyond being non-empty.
    pub fn new_community_role_vac(
        community: String,
        member: String,
        role: &str,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, DTGCredentialError> {
        if role.is_empty() {
            return Err(DTGCredentialError::EmptyAuthorityActions);
        }
        Self::new_vac(
            community.clone(),
            IssuerScope::Public,
            member,
            community,
            vec![role_action(role)],
            valid_from,
            valid_until,
        )
    }

    /// Sets `authority.maxAttenuation` on a VAC: the number of further attenuations
    /// permitted below it, with `0` forbidding attenuation outright.
    ///
    /// For a chain root, where any value is the governing party's to choose. On a VAC this
    /// library attenuated, pass the limit to [DTGCredential::attenuate] instead, which
    /// refuses one above what the parent permits; set here, an over-limit value is not
    /// caught until [crate::authority::verify_chain] rejects the chain.
    ///
    /// # Set it before signing
    ///
    /// Same caveat as [DTGCredential::with_id].
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::NotAnAuthorityCredential] on anything but a VAC.
    pub fn with_max_attenuation(
        mut self,
        max_attenuation: u32,
    ) -> Result<Self, DTGCredentialError> {
        self.credential
            .authority_mut()
            .ok_or(DTGCredentialError::NotAnAuthorityCredential)?
            .max_attenuation = Some(max_attenuation);
        Ok(self)
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
    /// - `self` must be a VAC, and must not bear `maxAttenuation` `0`.
    /// - `actions` must be a subset of what `self` confers.
    /// - `valid_until` must not exceed `self`'s.
    /// - `max_attenuation` must not exceed one less than `self`'s, where `self` bears one.
    ///   `None` takes that ceiling — the strictest the chain already imposes — or, where
    ///   `self` bears none, leaves the derived VAC unbounded too.
    ///
    /// `issuer_scope` is the attenuating holder's own declaration for its identifier: the
    /// derived VAC's issuer is `self`'s subject, and it is that party's scope to declare.
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
        issuer_scope: IssuerScope,
        subject: String,
        actions: Vec<String>,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        max_attenuation: Option<u32>,
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
            Attenuation {
                issuer_scope,
                subject,
                actions,
                valid_from,
                valid_until,
                max_attenuation,
            },
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
        issuer_scope: IssuerScope,
        subject: String,
        actions: Vec<String>,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        max_attenuation: Option<u32>,
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
            Attenuation {
                issuer_scope,
                subject,
                actions,
                valid_from,
                valid_until,
                max_attenuation,
            },
        )
    }

    /// The narrowing checks and the assembly, shared by both attenuation entry points.
    fn attenuate_inner(
        parent_grant: AuthorityGrant,
        holder: String,
        parent_until: Option<DateTime<Utc>>,
        parent_digest: String,
        derived: Attenuation,
    ) -> Result<Self, DTGCredentialError> {
        let Attenuation {
            issuer_scope,
            subject,
            actions,
            valid_from,
            valid_until,
            max_attenuation,
        } = derived;
        check_window(valid_from, Some(valid_until))?;

        // `maxAttenuation` is a ceiling every link inherits: `0` forbids a child at all, and
        // a child of `n` may bear at most `n - 1`. Absent on the parent, the child may set
        // any limit or none.
        let max_attenuation = match (parent_grant.max_attenuation, max_attenuation) {
            (Some(0), _) => {
                return Err(DTGCredentialError::AttenuationWidens(
                    "the parent bears `maxAttenuation` 0, which forbids attenuating it".into(),
                ));
            }
            (Some(n), Some(requested)) if requested > n - 1 => {
                return Err(DTGCredentialError::AttenuationWidens(format!(
                    "`maxAttenuation` {requested} exceeds the {} the parent's {n} permits",
                    n - 1
                )));
            }
            (Some(n), None) => Some(n - 1),
            (_, requested) => requested,
        };

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

        Ok(Self::build(
            DTGCredentialType::Authority,
            // The holder issues: they are the subject of the parent grant.
            holder,
            issuer_scope,
            valid_from,
            Some(valid_until),
            CredentialSubject::Authority(CredentialSubjectAuthority {
                id: subject,
                authority: AuthorityGrant {
                    // Scope never changes down a chain.
                    scope: parent_grant.scope.clone(),
                    actions,
                    parent: Some(parent_digest),
                    max_attenuation,
                },
            }),
        ))
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
    /// `issuer_scope` is the delegator's declaration for `issuer`. A VDC is presented to
    /// every verifier the delegate acts toward, so `pairwise` is seldom truthful and
    /// `directed` is the ordinary declaration.
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
        issuer_scope: IssuerScope,
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

        Ok(Self::build(
            DTGCredentialType::Delegation,
            issuer,
            issuer_scope,
            valid_from,
            Some(valid_until),
            CredentialSubject::Delegation(CredentialSubjectDelegation {
                id: subject,
                delegation: DelegationGrant {
                    scope: Some(scope),
                    parent: None,
                    max_depth,
                    accepts: None,
                },
            }),
        ))
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
    /// `issuer_scope` is the re-delegating delegate's own declaration for its identifier.
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
        issuer_scope: IssuerScope,
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
            issuer_scope,
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
        issuer_scope: IssuerScope,
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
            issuer_scope,
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
        issuer_scope: IssuerScope,
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

        Ok(Self::build(
            DTGCredentialType::Delegation,
            holder,
            issuer_scope,
            valid_from,
            Some(valid_until),
            CredentialSubject::Delegation(CredentialSubjectDelegation {
                id: subject,
                delegation: DelegationGrant {
                    scope: Some(scope),
                    parent: Some(parent_digest),
                    max_depth: Some(parent_depth - 1),
                    accepts: None,
                },
            }),
        ))
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
        issuer_scope: IssuerScope,
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

        Self::assemble_delegate_vdc(
            grant,
            found,
            issuer_scope,
            delegator,
            valid_from,
            valid_until,
        )
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
        issuer_scope: IssuerScope,
        delegator: String,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<Self, DTGCredentialError> {
        Ok(Self::build(
            DTGCredentialType::Delegation,
            delegate,
            issuer_scope,
            valid_from,
            Some(valid_until),
            CredentialSubject::Delegation(CredentialSubjectDelegation {
                id: delegator,
                delegation: DelegationGrant {
                    scope: None,
                    parent: None,
                    max_depth: None,
                    accepts: Some(crate::digest_multibase_json(grant)?),
                },
            }),
        ))
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
    /// issuer: The DID under which the persona is asserted
    /// issuer_scope: The scope declared for `issuer` — ordinarily `directed`, since a
    ///               persona exists to be recognized across counterparties the holder chooses
    /// subject: The DID of the counterparty as used in the relationship
    /// valid_from: The datetime from which this credential is valid
    /// valid_until: Optional: The datetime this credential is valid until
    pub fn new_vpc(
        issuer: String,
        issuer_scope: IssuerScope,
        subject: String,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Self {
        Self::build(
            DTGCredentialType::Persona,
            issuer,
            issuer_scope,
            valid_from,
            valid_until,
            CredentialSubject::Basic(CredentialSubjectBasic { id: subject }),
        )
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
    ///     "did:example:community".to_string(),
    ///     "did:example:member".to_string(),
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

    /// Cites a Trust Task document: sets `taskContext` to its `id` and
    /// `taskDigestMultibase` to its task digest, together.
    ///
    /// Use it for any credential whose meaning depends on an exchange — a VSC under a
    /// profile requiring `taskContext`, such as a VWC or a statement a `vetting/session`
    /// produces. Name the **innermost** exchange that attests
    /// what the credential states, by the document that initiated it (Trust Tasks §4.9.1).
    /// Setting both halves from one document is the point: the `id` locates the exchange
    /// and the digest binds the credential to it, and a pair taken from two places binds
    /// nothing. See [crate::task_digest_multibase_json] for how the digest is computed.
    ///
    /// Replaces a `taskContext` and `taskDigestMultibase` already set.
    ///
    /// # Set it before signing
    ///
    /// Both members are covered by the credential's proof, as for [DTGCredential::with_id].
    ///
    /// # Errors
    ///
    /// [DTGCredentialError::MalformedTaskDocument] if `document` is not an object with a
    /// string `id`; [DTGCredentialError::JsonTooDeep] if it is nested past
    /// [crate::MAX_JSON_DEPTH].
    pub fn with_task_citation(mut self, document: &Value) -> Result<Self, DTGCredentialError> {
        self.set_task_citation(document)?;
        Ok(self)
    }

    /// Cites a Trust Task document in place.
    ///
    /// The non-consuming form of [DTGCredential::with_task_citation]; the same caveats
    /// apply. On error, the credential is left unchanged.
    pub fn set_task_citation(&mut self, document: &Value) -> Result<(), DTGCredentialError> {
        let id = document
            .as_object()
            .ok_or_else(|| DTGCredentialError::MalformedTaskDocument("not a JSON object".into()))?
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| DTGCredentialError::MalformedTaskDocument("no string `id`".into()))?
            .to_string();
        let digest = crate::task_digest_multibase_json(document)?;

        self.credential.task_context = Some(id);
        self.credential.task_digest_multibase = Some(digest);
        Ok(())
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
    /// # use dtg_credentials::{DTGCredential, IssuerScope};
    /// # use serde_json::json;
    /// let vdc = DTGCredential::new_vdc(
    ///     "did:example:delegator".to_string(),
    ///     IssuerScope::Directed,
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
mod tests {
    use crate::{
        DTGCredential, DTGCredentialError, ENDORSES_V1, IssuerScope, StatementObject, WITNESSED_V1,
        WitnessContext,
    };
    use chrono::{DateTime, Duration, Utc};
    use serde_json::json;

    fn t0() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2025-12-11T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn vmc() -> DTGCredential {
        DTGCredential::new_vmc(
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            t0(),
            None,
            false,
        )
    }

    #[test]
    fn test_vmc_serialization() {
        let txt = serde_json::to_string_pretty(&vmc()).unwrap();
        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://registry.trustoverip.org/dtg/context/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "MembershipCredential"
  ],
  "issuer": "did:example:issuer",
  "issuerScope": "public",
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
            t0(),
            None,
            true,
        );

        let txt = serde_json::to_string_pretty(&vmc).unwrap();
        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://registry.trustoverip.org/dtg/context/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "MembershipCredential",
    "PersonhoodCredential"
  ],
  "issuer": "did:example:issuer",
  "issuerScope": "public",
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
        let vmc = vmc();
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
        let vmc = vmc().with_id("urn:uuid:1e2d3c4b-5a69-4788-9099-aabbccddeeff");

        let txt = serde_json::to_string_pretty(&vmc).unwrap();
        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://registry.trustoverip.org/dtg/context/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "MembershipCredential"
  ],
  "id": "urn:uuid:1e2d3c4b-5a69-4788-9099-aabbccddeeff",
  "issuer": "did:example:issuer",
  "issuerScope": "public",
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
        let vmc = vmc().with_id("urn:uuid:1e2d3c4b-5a69-4788-9099-aabbccddeeff");

        let txt = serde_json::to_string(&vmc).unwrap();
        let parsed: DTGCredential = serde_json::from_str(&txt).unwrap();
        assert_eq!(
            parsed.id(),
            Some("urn:uuid:1e2d3c4b-5a69-4788-9099-aabbccddeeff")
        );
    }

    /// A credential with no `id` still deserializes — the property is OPTIONAL.
    #[test]
    fn test_missing_id_deserializes_as_none() {
        let parsed: DTGCredential = serde_json::from_str(
            r#"{
              "@context": ["https://www.w3.org/ns/credentials/v2", "https://registry.trustoverip.org/dtg/context/v1"],
              "type": ["VerifiableCredential", "DTGCredential", "MembershipCredential"],
              "issuer": "did:example:issuer",
              "issuerScope": "public",
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
                IssuerScope::Pairwise,
                "did:example:subject".to_string(),
                t0(),
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

    /// VRC, VIC and VPC share one shape and differ in their concrete type and in the scope
    /// their issuer declares.
    #[test]
    fn test_basic_subject_serialization() {
        for (vc, type_, scope) in [
            (
                DTGCredential::new_vrc(
                    "did:example:issuer".to_string(),
                    IssuerScope::Pairwise,
                    "did:example:subject".to_string(),
                    t0(),
                    None,
                ),
                "RelationshipCredential",
                "pairwise",
            ),
            (
                DTGCredential::new_vic(
                    "did:example:issuer".to_string(),
                    IssuerScope::Public,
                    "did:example:subject".to_string(),
                    t0(),
                    None,
                ),
                "InvitationCredential",
                "public",
            ),
            (
                DTGCredential::new_vpc(
                    "did:example:issuer".to_string(),
                    IssuerScope::Directed,
                    "did:example:subject".to_string(),
                    t0(),
                    None,
                ),
                "PersonaCredential",
                "directed",
            ),
        ] {
            let txt = serde_json::to_string_pretty(&vc).unwrap();
            let sample = format!(
                r#"{{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://registry.trustoverip.org/dtg/context/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "{type_}"
  ],
  "issuer": "did:example:issuer",
  "issuerScope": "{scope}",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {{
    "id": "did:example:subject"
  }}
}}"#
            );
            assert_eq!(txt, sample);
            let parsed: DTGCredential = serde_json::from_str(&txt).unwrap();
            assert_eq!(parsed.issuer_scope(), vc.issuer_scope());
        }
    }

    /// The spec's `dtg:endorses` example, byte for byte in shape.
    #[test]
    fn test_endorses_vsc_serialization() {
        let vec = DTGCredential::new_endorses_vsc(
            "did:example:issuer".to_string(),
            IssuerScope::Directed,
            "did:example:subject".to_string(),
            json!({
              "type": "SkillEndorsement",
              "name": "Software Development",
              "competencyLevel": "expert"
            }),
            t0(),
            None,
        )
        .unwrap();

        let txt = serde_json::to_string_pretty(&vec).unwrap();
        let sample = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://registry.trustoverip.org/dtg/context/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "StatementCredential"
  ],
  "issuer": "did:example:issuer",
  "issuerScope": "directed",
  "validFrom": "2025-12-11T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:subject",
    "predicate": "https://registry.trustoverip.org/dtg/vsc/endorses/1",
    "object": {
      "value": {
        "competencyLevel": "expert",
        "name": "Software Development",
        "type": "SkillEndorsement"
      }
    }
  }
}"#;

        assert_eq!(txt, sample);
    }

    /// The spec's `dtg:witnessed` example, in shape: the citation at the top level, the
    /// digest under `object`, and `witnessContext` beside them in the subject.
    #[test]
    fn test_witnessed_vsc_serialization() {
        let session = json!({
            "id": "urn:uuid:2c7f5d19-6e0b-4c3d-8a41-9b2e6f0d4c88",
            "type": "https://trusttasks.org/spec/witness/session/0.1",
            "threadId": "urn:uuid:2c7f5d19-6e0b-4c3d-8a41-9b2e6f0d4c88",
        });
        let vrc = serde_json::to_value(DTGCredential::new_vrc(
            "did:example:subject".to_string(),
            IssuerScope::Pairwise,
            "did:example:peer".to_string(),
            t0(),
            None,
        ))
        .unwrap();

        let vwc = DTGCredential::new_witnessed_vsc(
            "did:example:witness".to_string(),
            IssuerScope::Public,
            &vrc,
            &session,
            t0(),
            None,
            Some(WitnessContext {
                event: Some("EthDenver 2024".to_string()),
                session_id: Some("session-8822-nonce".to_string()),
                method: Some("in-person-proximity".to_string()),
            }),
        )
        .unwrap();

        let txt = serde_json::to_string_pretty(&vwc).unwrap();
        let sample = format!(
            r#"{{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://registry.trustoverip.org/dtg/context/v1"
  ],
  "type": [
    "VerifiableCredential",
    "DTGCredential",
    "StatementCredential"
  ],
  "issuer": "did:example:witness",
  "issuerScope": "public",
  "validFrom": "2025-12-11T00:00:00Z",
  "taskContext": "urn:uuid:2c7f5d19-6e0b-4c3d-8a41-9b2e6f0d4c88",
  "taskDigestMultibase": "{}",
  "credentialSubject": {{
    "id": "did:example:subject",
    "predicate": "https://registry.trustoverip.org/dtg/vsc/witnessed/1",
    "object": {{
      "digestMultibase": "{}"
    }},
    "witnessContext": {{
      "event": "EthDenver 2024",
      "sessionId": "session-8822-nonce",
      "method": "in-person-proximity"
    }}
  }}
}}"#,
            crate::task_digest_multibase_json(&session).unwrap(),
            crate::digest_multibase_json(&vrc).unwrap(),
        );

        assert_eq!(txt, sample);
        assert!(vwc.witnesses_issuance_of(&vrc).unwrap());
    }

    /// A generic statement under a predicate this library has no profile for is built and
    /// checked for shape only.
    #[test]
    fn test_community_predicate_vsc() {
        let vsc = DTGCredential::new_vsc(
            "did:example:observer".to_string(),
            IssuerScope::Directed,
            "did:example:subject".to_string(),
            "https://vtc.example/vocab#observedDocument",
            StatementObject::Value(json!({ "documentType": "passport" })),
            t0(),
            None,
        )
        .unwrap();
        assert_eq!(
            vsc.predicate(),
            Some("https://vtc.example/vocab#observedDocument")
        );
        vsc.validate().unwrap();
    }

    /// A core profile's `object` kind and minimum scope are refused at construction.
    #[test]
    fn test_new_vsc_enforces_core_profile_shape() {
        let witnessed_with_value = DTGCredential::new_vsc(
            "did:example:witness".to_string(),
            IssuerScope::Public,
            "did:example:subject".to_string(),
            WITNESSED_V1,
            StatementObject::Value(json!(true)),
            t0(),
            None,
        );
        assert!(matches!(
            witnessed_with_value,
            Err(DTGCredentialError::ProfileViolation(_))
        ));

        let pairwise_witness = DTGCredential::new_vsc(
            "did:example:witness".to_string(),
            IssuerScope::Pairwise,
            "did:example:subject".to_string(),
            WITNESSED_V1,
            StatementObject::DigestMultibase(
                "zQmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n".into(),
            ),
            t0(),
            None,
        );
        assert!(matches!(
            pairwise_witness,
            Err(DTGCredentialError::IssuerScopeTooNarrow {
                declared: IssuerScope::Pairwise,
                minimum: IssuerScope::Directed,
            })
        ));

        // `endorses/1` sets no minimum.
        DTGCredential::new_vsc(
            "did:example:peer".to_string(),
            IssuerScope::Pairwise,
            "did:example:subject".to_string(),
            ENDORSES_V1,
            StatementObject::Value(json!({})),
            t0(),
            None,
        )
        .unwrap();
    }

    /// A witnessed statement built generically is refused at validation — and so at signing —
    /// until the citation the profile requires is attached.
    #[test]
    fn test_generic_witnessed_vsc_needs_its_citation() {
        let vsc = DTGCredential::new_vsc(
            "did:example:witness".to_string(),
            IssuerScope::Directed,
            "did:example:subject".to_string(),
            WITNESSED_V1,
            StatementObject::DigestMultibase(
                "zQmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n".into(),
            ),
            t0(),
            None,
        )
        .unwrap();
        assert!(matches!(
            vsc.validate(),
            Err(DTGCredentialError::MissingTaskContext)
        ));

        let cited = vsc
            .with_task_citation(&json!({ "id": "urn:uuid:session" }))
            .unwrap();
        cited.validate().unwrap();
    }

    /// The community-issued role VAC: issued by the community, `public`, scoped to the
    /// community, conferring `role:<name>`.
    #[test]
    fn test_community_role_vac_serialization() {
        let vac = DTGCredential::new_community_role_vac(
            "did:example:community".to_string(),
            "did:example:member".to_string(),
            "vetter",
            t0(),
            t0() + Duration::days(90),
        )
        .unwrap();

        assert_eq!(
            serde_json::to_value(&vac).unwrap(),
            json!({
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://registry.trustoverip.org/dtg/context/v1"
                ],
                "type": ["VerifiableCredential", "DTGCredential", "AuthorityCredential"],
                "issuer": "did:example:community",
                "issuerScope": "public",
                "validFrom": "2025-12-11T00:00:00Z",
                "validUntil": "2026-03-11T00:00:00Z",
                "credentialSubject": {
                    "id": "did:example:member",
                    "authority": {
                        "scope": "did:example:community",
                        "actions": ["role:vetter"]
                    }
                }
            })
        );
    }
}
