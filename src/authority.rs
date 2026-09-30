//! Verifying a chain of Verifiable Authority Credentials.
//!
//! # Why this module is the important one
//!
//! Issuing a VAC is a struct and a signature. The security of the whole credential is in
//! *refusing* a chain that widens — because attenuation is only a narrowing if somebody
//! walks it. A verifier that checks only the credential it was handed accepts a
//! **self-issued grant of arbitrary authority**: anyone can mint a VAC naming any scope and
//! any actions, and it will verify perfectly as a signed credential. What makes it
//! worthless is that its chain does not reach the party governing the scope.
//!
//! So the rules below are not stylistic. Each of them closes a way to get authority you
//! were not given:
//!
//! | Rule | What it stops |
//! |---|---|
//! | Chain must reach a root issued by the governing party | a self-issued grant |
//! | No link may add an action absent from its parent | privilege escalation by re-issue |
//! | No link may widen `scope` | authority earned in one room used in another |
//! | No link may outlive its parent | an expiry escaped by re-delegation |
//! | Each link's issuer must be its parent's subject | grafting someone else's grant onto your own |
//! | The leaf's subject must be the presenter | a captured presentation replayed by whoever caught it |
//! | Depth is bounded | a denial-of-service against the verifier, which walks every link |
//! | No link lies further below an ancestor than its `maxAttenuation` permits | a governing party's "decide this personally" overridden by a holder |
//! | No link raises the `maxAttenuation` it inherits | the same, one link at a time |
//! | Every link must carry `validUntil` | authority nobody can withdraw by waiting |
//!
//! # Bearer-side resolution
//!
//! The holder presents every link. This module **never dereferences**
//! [`crate::AuthorityGrant::parent`] to fetch a credential it was not given, and
//! [`verify_chain`] takes the chain as a slice for exactly that reason.
//!
//! Working Draft 02 made that structural rather than merely required: `parent` is a
//! **digest**, and a digest names nothing that can be fetched. So verification cannot come
//! to depend on availability, a verifier cannot be induced to make a request against an
//! address the *holder* chooses, and nobody hosting an identifier learns when a credential
//! is used. The digest also binds a link to the exact claims its issuer narrowed from,
//! which an identifier could not do: a parent re-issued with different claims does not
//! carry its old children with it.
//!
//! # A VAC is not a bearer credential
//!
//! [`verify_chain`] takes a `presenter` and requires the leaf to grant to it. That is the
//! rule [PR #41](https://github.com/trustoverip/dtgwg-cred-spec/pull/41) states normatively
//! — *a verifier MUST NOT accept a party as holding the authority a VAC confers unless that
//! party demonstrates control of the verification method associated with the presented
//! VAC's `credentialSubject.id`* — and it is why this module no longer has an `audience`.
//!
//! An earlier draft of the VAC carried an OPTIONAL `audience` naming the DID that had to
//! present the credential, and this module compared it against `presenter`. Once the
//! presenter must be the subject, that field can only name the same party (adding nothing)
//! or a different one (satisfiable by nobody), so it was removed rather than kept as a
//! weaker second check. The destination question it was sometimes read as answering —
//! *where* may this be presented — is not the credential's to answer; it belongs to the
//! trust task carrying the presentation, which binds its own recipient.
//!
//! **What `presenter` must be.** The identifier of a party whose key control the caller has
//! already established for *this request* — the DID a transport authenticated, or one a
//! signature over the request proved. Passing an identifier the caller merely read out of
//! the request body reduces this check to a string comparison an attacker chooses both
//! sides of.
//!
//! **Only the leaf's subject demonstrates anything.** The parties named in the links above
//! it are not present and are asked for nothing. Requiring otherwise would defeat
//! attenuation, whose whole purpose is that the party who attenuated is not in the loop
//! when its agent acts.
//!
//! # `maxAttenuation` and the global ceiling are both enforced
//!
//! [MAX_CHAIN_DEPTH] is a resource bound every verifier applies; `authority.maxAttenuation`
//! is a policy an issuer sets for its own grant. A chain MUST satisfy both: a chain of five
//! under a root bearing `maxAttenuation` `2` is within the ceiling and still invalid.
//!
//! # Not checked here: revocation
//!
//! A VAC carrying `credentialStatus` MUST be checked against it, and revoking one withdraws
//! everything attenuated below it. Status is a live lookup against a mechanism the governing
//! party chooses, so this module does not perform it: check
//! [`crate::DTGCommon::credential_status`] on every link that carries one.

use chrono::{DateTime, Utc};

use crate::{DTGCredential, DTGCredentialType};

/// Maximum number of VACs in a chain, including the root.
///
/// Verification is linear in depth and runs on every presentation, so an unbounded chain is
/// a denial-of-service surface. The known uses need far less — a person attenuating to an
/// agent is depth 2, and an agent attenuating to a sub-agent is depth 3 — so a chain near
/// this ceiling is a signal that authority is being re-delegated further than intended.
pub const MAX_CHAIN_DEPTH: usize = 8;

/// Why a chain was refused.
///
/// Each variant names a specific way of acquiring authority that was not granted, rather
/// than collapsing into one "invalid" — a verifier's logs are where an escalation attempt
/// becomes visible.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    /// The chain was empty. Nothing to verify.
    #[error("authority chain is empty")]
    EmptyChain,

    /// A link's digest could not be computed, or one it carries could not be read.
    ///
    /// Distinct from [AuthorityError::BrokenLink]: a digest that cannot be *read* is not a
    /// digest that disagrees, and a verifier that conflated the two would report a
    /// malformed chain as a widening one.
    #[error("digest error at index {index}: {reason}")]
    Digest { index: usize, reason: String },

    /// A link carried no `validUntil`, which a VAC MUST have.
    #[error("VAC at index {index} carries no validUntil, which a VAC MUST have")]
    NoExpiry { index: usize },

    /// The chain is longer than [MAX_CHAIN_DEPTH].
    #[error("authority chain is {found} deep, exceeding the maximum of {MAX_CHAIN_DEPTH}")]
    TooDeep {
        /// How many links were presented.
        found: usize,
    },

    /// A credential in the chain was not an `AuthorityCredential`.
    #[error("chain link {index} is a {found}, not an AuthorityCredential")]
    NotAuthority {
        /// Position in the chain, leaf first.
        index: usize,
        /// What was found instead.
        found: String,
    },

    /// The chain root was not issued by the party governing the scope.
    ///
    /// This is the finding that matters most: a chain that does not reach the governing
    /// party is a self-issued grant, however well-formed each link is.
    #[error(
        "chain root was issued by `{root_issuer}`, not by `{expected}` which governs the scope"
    )]
    RootNotGoverning {
        /// Who actually issued the root.
        root_issuer: String,
        /// Who governs the scope being accessed.
        expected: String,
    },

    /// A link's `parent` did not name the credential presented as its parent.
    ///
    /// Both fields are `digestMultibase` values, not identifiers. Working Draft 02 changed
    /// `parent` from an `id` to a digest, so a value here that looks like a `urn:uuid:` or
    /// a WD01 `sha256:<hex>` is a version skew rather than a mismatched chain — see the
    /// upgrade ordering notes in the README.
    #[error("chain link {index} names parent `{named}`, but was presented after `{presented}`")]
    BrokenLink {
        /// Position in the chain, leaf first.
        index: usize,
        /// The `digestMultibase` the link points at, as it was carried.
        named: String,
        /// The digest of the credential actually presented as its parent.
        presented: String,
    },

    /// A link was issued by someone other than its parent's subject.
    ///
    /// Only the party a grant was made to may attenuate it. Without this check a holder
    /// could graft an unrelated grant onto their own chain.
    #[error("chain link {index} was issued by `{issuer}`, but its parent granted to `{subject}`")]
    IssuerNotParentSubject {
        /// Position in the chain, leaf first.
        index: usize,
        /// Who issued the link.
        issuer: String,
        /// Who the parent granted to.
        subject: String,
    },

    /// A link conferred an action its parent did not.
    #[error("chain link {index} adds action `{action}`, which its parent does not confer")]
    WidensActions {
        /// Position in the chain, leaf first.
        index: usize,
        /// The action that was added.
        action: String,
    },

    /// A link named a different scope from its parent.
    #[error("chain link {index} has scope `{scope}`, its parent `{parent_scope}`")]
    WidensScope {
        /// Position in the chain, leaf first.
        index: usize,
        /// The link's scope.
        scope: String,
        /// The parent's scope.
        parent_scope: String,
    },

    /// A link outlived its parent.
    #[error("chain link {index} is valid until {until}, beyond its parent's {parent_until}")]
    OutlivesParent {
        /// Position in the chain, leaf first.
        index: usize,
        /// The link's expiry.
        until: DateTime<Utc>,
        /// The parent's expiry.
        parent_until: DateTime<Utc>,
    },

    /// The requested scope is not the one the chain confers on.
    #[error("chain confers on scope `{granted}`, but `{requested}` was requested")]
    ScopeMismatch {
        /// What the chain grants on.
        granted: String,
        /// What was asked for.
        requested: String,
    },

    /// The chain does not confer the requested action.
    #[error("chain does not confer action `{action}`")]
    ActionNotGranted {
        /// The action that was requested.
        action: String,
    },

    /// The leaf grants to somebody other than the party presenting it.
    ///
    /// A VAC is evidence that authority was conferred on somebody. It is not evidence that
    /// whoever handed it over is that somebody, and a verifier that conflated the two would
    /// authorize every captured presentation.
    #[error("the chain's leaf grants to `{subject}`, but it was presented by `{presenter}`")]
    NotThePresenter {
        /// Who the leaf grants to.
        subject: String,
        /// Who presented it.
        presenter: String,
    },

    /// A link was outside its validity window at the time of the check.
    #[error("chain link {index} is not valid at {at}")]
    NotValidNow {
        /// Position in the chain, leaf first.
        index: usize,
        /// The instant checked against.
        at: DateTime<Utc>,
    },

    /// A link carried an empty `actions` list.
    #[error("chain link {index} confers no actions")]
    NoActions {
        /// Position in the chain, leaf first.
        index: usize,
    },

    /// A link lies further below an ancestor than that ancestor's `maxAttenuation` permits.
    #[error(
        "chain link {index} lies {depth} below link {ancestor}, whose maxAttenuation is {max_attenuation}"
    )]
    ExceedsMaxAttenuation {
        /// The link too far down — always the leaf, which is furthest from every ancestor.
        index: usize,
        /// The ancestor whose limit it breaks.
        ancestor: usize,
        /// How many steps below that ancestor it lies.
        depth: usize,
        /// The ancestor's `maxAttenuation`.
        max_attenuation: u32,
    },

    /// A link bears a `maxAttenuation` above one less than its parent's.
    #[error(
        "chain link {index} bears maxAttenuation {found}, above the {allowed} its parent permits"
    )]
    RaisesMaxAttenuation {
        /// Position in the chain, leaf first.
        index: usize,
        /// What the link bears.
        found: u32,
        /// The most the parent permits.
        allowed: u32,
    },
}

/// What a verified chain permits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthority {
    /// The party the leaf grants to — who may act.
    pub subject: String,
    /// The scope the chain confers on.
    pub scope: String,
    /// The actions the leaf confers, already narrowed by every link above it.
    pub actions: Vec<String>,
    /// The party governing the scope, which issued the chain root.
    pub governing_party: String,
}

/// Verify a chain of VACs and return what it permits.
///
/// `chain` is **leaf first**: `chain[0]` is the credential being presented, and the last
/// element must be the root issued by `governing_party`. Every link the holder relies on
/// must be present — this function never fetches one (see the module docs).
///
/// The signature on each credential is *not* checked here. Verify those first, with
/// [crate::DTGCredential] and the data-integrity suite; this function answers the separate
/// question of whether a set of cryptographically valid credentials adds up to the
/// authority claimed. Both checks are required and neither substitutes for the other.
///
/// Returns [VerifiedAuthority] describing what the chain actually permits, which is never
/// more than the root conferred.
pub fn verify_chain(
    chain: &[DTGCredential],
    governing_party: &str,
    requested_scope: &str,
    requested_action: &str,
    presenter: &str,
    at: DateTime<Utc>,
) -> Result<VerifiedAuthority, AuthorityError> {
    if chain.is_empty() {
        return Err(AuthorityError::EmptyChain);
    }
    if chain.len() > MAX_CHAIN_DEPTH {
        return Err(AuthorityError::TooDeep { found: chain.len() });
    }

    // Every link must be a VAC carrying a grant.
    for (index, link) in chain.iter().enumerate() {
        if !matches!(link.type_(), DTGCredentialType::Authority) {
            return Err(AuthorityError::NotAuthority {
                index,
                found: link.type_().to_string(),
            });
        }
        let grant = link
            .credential()
            .authority()
            .ok_or_else(|| AuthorityError::NotAuthority {
                index,
                found: "AuthorityCredential without an authority grant".to_string(),
            })?;
        if grant.actions.is_empty() {
            return Err(AuthorityError::NoActions { index });
        }
        // Validity window, checked per link: a chain is only as live as its shortest-lived
        // member, and an expired parent does not become live again because its child says so.
        let c = link.credential();
        if c.valid_from() > at {
            return Err(AuthorityError::NotValidNow { index, at });
        }
        // `validUntil` is REQUIRED on a VAC, not merely recommended. Nothing about the
        // subject's current standing is consulted here, so a VAC that never expires is
        // authority nobody can withdraw by waiting — and a verifier that accepted one
        // would be honouring exactly that.
        let Some(until) = c.valid_until() else {
            return Err(AuthorityError::NoExpiry { index });
        };
        if until < at {
            return Err(AuthorityError::NotValidNow { index, at });
        }
    }

    // Key control at invocation: the leaf must grant to whoever is presenting it.
    //
    // Without this a presentation is a bearer object — it names what may be done, not who
    // is doing it — so anyone who observes one inherits everything it confers. The check is
    // only as good as `presenter`: see the module docs on what a caller must have
    // established before passing one.
    let leaf = &chain[0];
    let leaf_grant = leaf.credential().authority().expect("checked above");
    let leaf_subject = leaf.credential().subject();
    if leaf_subject != presenter {
        return Err(AuthorityError::NotThePresenter {
            subject: leaf_subject.to_string(),
            presenter: presenter.to_string(),
        });
    }

    // Walk leaf -> root. Each step checks the link against the credential above it.
    for index in 0..chain.len() - 1 {
        let link = &chain[index];
        let parent = &chain[index + 1];
        let grant = link.credential().authority().expect("checked above");
        let parent_grant = parent.credential().authority().expect("checked above");

        // The link must point at the credential presented as its parent. Without this a
        // holder could interleave links from unrelated chains.
        //
        // `parent` is a digest, not an identifier, so this is a hash comparison over the
        // parent's claims — and the specification requires comparing decoded digest bytes
        // rather than encoded strings, since one digest has more than one spelling.
        let presented_digest = parent
            .digest_multibase()
            .map_err(|e| AuthorityError::Digest {
                index: index + 1,
                reason: e.to_string(),
            })?;
        match &grant.parent {
            Some(named) => {
                let matches = crate::digests_match(named, &presented_digest).map_err(|e| {
                    AuthorityError::Digest {
                        index,
                        reason: e.to_string(),
                    }
                })?;
                if !matches {
                    return Err(AuthorityError::BrokenLink {
                        index,
                        named: named.clone(),
                        presented: presented_digest,
                    });
                }
            }
            None => {
                // A link with no `parent` claims to be a root, but something was presented
                // above it.
                return Err(AuthorityError::BrokenLink {
                    index,
                    named: "<none — link claims to be a root>".to_string(),
                    presented: presented_digest,
                });
            }
        }

        // Only the party a grant was made to may attenuate it.
        if link.credential().issuer() != parent.credential().subject() {
            return Err(AuthorityError::IssuerNotParentSubject {
                index,
                issuer: link.credential().issuer().to_string(),
                subject: parent.credential().subject().to_string(),
            });
        }

        // Narrowing, on all three axes.
        if grant.scope != parent_grant.scope {
            return Err(AuthorityError::WidensScope {
                index,
                scope: grant.scope.clone(),
                parent_scope: parent_grant.scope.clone(),
            });
        }
        for action in &grant.actions {
            if !parent_grant.actions.contains(action) {
                return Err(AuthorityError::WidensActions {
                    index,
                    action: action.clone(),
                });
            }
        }
        // `maxAttenuation` never rises: a link under a parent bearing `n` may bear at most
        // `n - 1`. A link bearing none is not a raise — it does not bear one — and how far
        // below the parent it may lie is the per-ancestor depth rule's to answer, below.
        if let (Some(parent_max), Some(max)) = (parent_grant.max_attenuation, grant.max_attenuation)
            && (parent_max == 0 || max > parent_max - 1)
        {
            return Err(AuthorityError::RaisesMaxAttenuation {
                index,
                found: max,
                allowed: parent_max.saturating_sub(1),
            });
        }

        // Both are present: the loop above rejected any link without one.
        if let (Some(until), Some(parent_until)) = (
            link.credential().valid_until(),
            parent.credential().valid_until(),
        ) && until > parent_until
        {
            return Err(AuthorityError::OutlivesParent {
                index,
                until,
                parent_until,
            });
        }
    }

    // Depth below every ancestor. The leaf is furthest from each, `ancestor` steps below
    // the link at that index, so checking it checks every link between. This is what bounds
    // a chain whose intermediate links bear no `maxAttenuation` of their own, which the
    // per-link rule above cannot see.
    for (ancestor, link) in chain.iter().enumerate().skip(1) {
        let grant = link.credential().authority().expect("checked above");
        if let Some(max_attenuation) = grant.max_attenuation
            && ancestor > max_attenuation as usize
        {
            return Err(AuthorityError::ExceedsMaxAttenuation {
                index: 0,
                ancestor,
                depth: ancestor,
                max_attenuation,
            });
        }
    }

    // The root must be the governing party's, and must claim to be a root.
    let root = chain.last().expect("non-empty");
    let root_grant = root.credential().authority().expect("checked above");
    if root.credential().issuer() != governing_party {
        return Err(AuthorityError::RootNotGoverning {
            root_issuer: root.credential().issuer().to_string(),
            expected: governing_party.to_string(),
        });
    }
    if root_grant.parent.is_some() {
        // The chain was truncated: its "root" points at something not presented.
        return Err(AuthorityError::BrokenLink {
            index: chain.len() - 1,
            named: root_grant.parent.clone().unwrap_or_default(),
            presented: "<nothing — chain ends here>".to_string(),
        });
    }

    // Finally, what was asked for.
    if leaf_grant.scope != requested_scope {
        return Err(AuthorityError::ScopeMismatch {
            granted: leaf_grant.scope.clone(),
            requested: requested_scope.to_string(),
        });
    }
    if !leaf_grant.actions.iter().any(|a| a == requested_action) {
        return Err(AuthorityError::ActionNotGranted {
            action: requested_action.to_string(),
        });
    }

    Ok(VerifiedAuthority {
        subject: leaf.credential().subject().to_string(),
        scope: leaf_grant.scope.clone(),
        actions: leaf_grant.actions.clone(),
        governing_party: governing_party.to_string(),
    })
}
