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
//! | `audience`, where set, must be the presenter | a leaked credential used by whoever holds it |
//! | Depth is bounded | a denial-of-service against the verifier, which walks every link |
//!
//! # Bearer-side resolution
//!
//! The holder presents every link. This module **never dereferences**
//! [`AuthorityGrant::parent`] to fetch a credential it was not given, and
//! [`verify_chain`] takes the chain as a slice for exactly that reason.
//!
//! Deliberate, and worth stating because the alternative is attractive until it isn't:
//! resolving parents over the network would make verification depend on availability, turn
//! every `id` into a request the verifier can be induced to make against an address the
//! *holder* chooses, and signal credential use to whoever hosts the identifier. `id` values
//! in a chain are identifiers, not locators, and need not resolve to anything.
//!
//! Tracks a draft: `trustoverip/dtgwg-cred-spec` PR #29.

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
    #[error("chain link {index} names parent `{named}`, but was presented after `{presented}`")]
    BrokenLink {
        /// Position in the chain, leaf first.
        index: usize,
        /// The `id` the link points at.
        named: String,
        /// The `id` of the credential actually presented as its parent.
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

    /// A link was presented by a party other than its bound audience.
    #[error("chain link {index} is bound to audience `{audience}`, presented by `{presenter}`")]
    WrongAudience {
        /// Position in the chain, leaf first.
        index: usize,
        /// Who the link is bound to.
        audience: String,
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
        if let Some(until) = c.valid_until()
            && until < at
        {
            return Err(AuthorityError::NotValidNow { index, at });
        }
    }

    // The leaf must be presentable by whoever is presenting it.
    let leaf = &chain[0];
    let leaf_grant = leaf.credential().authority().expect("checked above");
    if let Some(audience) = &leaf_grant.audience
        && audience != presenter
    {
        return Err(AuthorityError::WrongAudience {
            index: 0,
            audience: audience.clone(),
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
        match (&grant.parent, parent.id()) {
            (Some(named), Some(presented)) if named == presented => {}
            (Some(named), presented) => {
                return Err(AuthorityError::BrokenLink {
                    index,
                    named: named.clone(),
                    presented: presented.unwrap_or("<no id>").to_string(),
                });
            }
            (None, presented) => {
                // A link with no `parent` claims to be a root, but something was presented
                // above it.
                return Err(AuthorityError::BrokenLink {
                    index,
                    named: "<none — link claims to be a root>".to_string(),
                    presented: presented.unwrap_or("<no id>").to_string(),
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
