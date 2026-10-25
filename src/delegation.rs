//! Verifying a chain of Verifiable Delegation Credentials.
//!
//! # What a VDC chain establishes, and what it does not
//!
//! A delegation chain answers exactly one question: *may this party act in the
//! principal's name, for this act?* It does **not** answer whether the act is permitted.
//! A VDC neither carries authority nor confers it — a verifier substitutes the principal
//! for the delegate and then asks the permission question it would have asked of the
//! principal directly, live, at the time of the act.
//!
//! [`verify_chain`] therefore returns a [`VerifiedDelegation`] naming the principal and
//! the acts the chain appoints for. That is one of two checks. The other — may the
//! *principal* do this? — is the caller's, and a governing party may add a third: whether
//! the delegate must independently qualify. The reach of a delegated act is the
//! **intersection** of what the principal may do and what the chain appoints for; never
//! the union, and never more than either.
//!
//! # Re-delegation is opt-in, unlike attenuation
//!
//! A VAC may be attenuated by default; a VDC may be re-delegated only where its `maxDepth`
//! says so, and absence prohibits it. The asymmetry is deliberate. A delegate speaks in
//! the principal's name, so the principal keeps the register of who may do that and can
//! withdraw any of them; a delegate that needs a further delegate ordinarily asks for a
//! fresh root delegation rather than minting one. Re-delegation exists for when that round
//! trip is unavailable.
//!
//! # Bearer-side resolution
//!
//! As in [`crate::authority`], the holder presents every link and this module never
//! dereferences a `parent` to fetch one. Presenting a derived VDC discloses the whole
//! ancestry, including the principal's identity — which is the other reason a single hop
//! is the default.
//!
//! # A VDC is not a bearer credential
//!
//! [`verify_chain`] takes a `presenter` and requires the leaf to appoint it. That is the
//! **Invocation Binding** rule of Working Draft 02, stated normatively: *a verifier MUST
//! NOT accept a party as acting in the delegator's name unless that party demonstrates
//! control of the verification method associated with `credentialSubject.id` at the time
//! of the request. A VDC presented without such a demonstration is evidence that a
//! delegation exists; it is not evidence that the party presenting it is the delegate.*
//!
//! Same rule, and the same reasoning, as [`crate::authority::verify_chain`]. Acting in
//! another's name is if anything the sharper case: a captured VAC replays whatever it
//! confers, while a captured VDC replays *as somebody*, and every act it carries is
//! attributed to the principal.
//!
//! **What `presenter` must be.** The identifier of a party whose key control the caller
//! has already established for *this request* — the DID a transport authenticated, or one
//! a signature over the request proved. Passing an identifier the caller merely read out
//! of the request body reduces this check to a string comparison an attacker chooses both
//! sides of.
//!
//! **Only the leaf's delegate demonstrates anything.** The parties above it in the chain
//! are not present and are asked for nothing. Requiring otherwise would defeat
//! re-delegation, whose whole purpose is that the delegator is not in the loop when its
//! delegate acts.
//!
//! # Not implemented here
//!
//! **The acceptance.** A delegation edge is complete only when the delegate has
//! countersigned, and a verifier MUST obtain and verify that half before accepting any
//! party as acting under the delegation. This module verifies the grant chain;
//! [`crate::DTGCredential::accepts`] checks an acceptance against its grant, and a
//! verifier needs both.
//!
//! **Revocation.** A VDC's `credentialStatus` is a live lookup this crate does not
//! perform. See [`crate::DTGCommon::credential_status`].
//!
//! Nothing else. Invocation binding used to be listed here; see below.

use affinidi_did_common::scid::same_reference;
use chrono::{DateTime, Utc};

use crate::{DTGCredential, DTGCredentialType};

/// Why a delegation chain was refused.
///
/// Each variant names a specific way of acquiring representation that was not granted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DelegationError {
    /// The chain was empty. Nothing to verify.
    #[error("delegation chain is empty")]
    EmptyChain,

    /// The chain is longer than [MAX_CHAIN_DEPTH].
    #[error("delegation chain is {found} deep, exceeding the maximum of {MAX_CHAIN_DEPTH}")]
    TooDeep { found: usize },

    /// A link was not a DelegationCredential carrying a grant.
    #[error("credential at index {index} is a {found}, not a delegation grant")]
    NotADelegationGrant { index: usize, found: String },

    /// A link carried `accepts`, making it an acceptance rather than a grant.
    ///
    /// An acceptance appoints nobody; it consents to an appointment made elsewhere. A
    /// chain built from them establishes no representation.
    #[error("credential at index {index} is an acceptance, not a grant")]
    AcceptanceInChain { index: usize },

    /// A link's `scope` was empty or absent.
    #[error("delegation at index {index} carries no scope, and so appoints for nothing")]
    NoScope { index: usize },

    /// A link carried no `validUntil`, which a VDC MUST have.
    #[error("VDC at index {index} carries no validUntil, which a VDC MUST have")]
    NoExpiry { index: usize },

    /// A link was outside its validity window at the instant asked about.
    #[error("delegation at index {index} is not valid at {at}")]
    NotValidNow { index: usize, at: DateTime<Utc> },

    /// A link's `parent` did not match the credential presented above it.
    #[error("delegation at index {index} names parent {named}, but {presented} was presented")]
    BrokenLink {
        /// Position in the chain, leaf first.
        index: usize,
        /// The `digestMultibase` the link points at, as it was carried.
        named: String,
        /// The digest of the credential actually presented as its parent.
        presented: String,
    },

    /// A link's digest could not be computed, or one it carries could not be read.
    #[error("digest error at index {index}: {reason}")]
    Digest { index: usize, reason: String },

    /// A link was issued by someone other than the delegate its parent appointed.
    #[error(
        "delegation at index {index} is issued by {issuer}, but its parent appointed {subject}"
    )]
    IssuerNotParentSubject {
        index: usize,
        issuer: String,
        subject: String,
    },

    /// A link appointed for an act absent from its parent's scope.
    #[error("delegation at index {index} adds `{act}`, which its parent does not appoint for")]
    WidensScope { index: usize, act: String },

    /// A link outlived the delegation it derives from.
    #[error(
        "delegation at index {index} is valid until {until}, beyond its parent's {parent_until}"
    )]
    OutlivesParent {
        index: usize,
        until: DateTime<Utc>,
        parent_until: DateTime<Utc>,
    },

    /// A re-delegation was made below a VDC that does not permit one.
    ///
    /// `maxDepth` absent or `0` prohibits it, and there is no other way to authorise one.
    #[error(
        "delegation at index {index} re-delegates below a parent whose maxDepth is {parent_depth}"
    )]
    RedelegationNotPermitted { index: usize, parent_depth: u32 },

    /// A link's `maxDepth` exceeded one less than its parent's.
    #[error(
        "delegation at index {index} bears maxDepth {depth}, above its parent's {parent_depth} - 1"
    )]
    DepthNotNarrowed {
        index: usize,
        depth: u32,
        parent_depth: u32,
    },

    /// The chain's root was not issued by the principal the verifier intends to deal with.
    #[error("chain root is issued by {root_issuer}, not the principal {expected}")]
    RootNotPrincipal {
        root_issuer: String,
        expected: String,
    },

    /// The leaf does not appoint for the act asked about.
    #[error("the delegation does not appoint for `{act}`")]
    ActNotAppointed { act: String },

    /// The leaf appoints somebody other than the party presenting it.
    ///
    /// A VDC is evidence that a delegation exists. It is not evidence that whoever handed
    /// it over is the delegate, and a verifier that conflated the two would let anyone who
    /// ever observed a presentation act in the principal's name.
    #[error("the chain's leaf appoints `{delegate}`, but it was presented by `{presenter}`")]
    NotTheDelegate {
        /// Who the leaf appoints.
        delegate: String,
        /// Who presented it.
        presenter: String,
    },
}

/// Maximum number of VDCs in a chain, including the root delegation.
///
/// The specification bounds depth per-ancestor through `maxDepth` rather than globally,
/// and a conforming chain is bounded by that. This ceiling is a second, blunter bound on
/// the same denial-of-service surface the VAC's has: verification is linear in depth and
/// runs on every presentation.
pub const MAX_CHAIN_DEPTH: usize = 8;

/// What a verified delegation chain establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelegation {
    /// The delegate the chain appoints — the leaf's subject.
    pub delegate: String,

    /// The acts the chain appoints the delegate for, which is never more than the root
    /// delegation conferred.
    pub scope: Vec<String>,

    /// The entity in whose name the acts would be performed, and to whom they are
    /// attributed. The root delegation's issuer.
    pub principal: String,
}

/// Verify a chain of delegation grants and return what it appoints for.
///
/// `chain` is **leaf first**: `chain[0]` is the credential being presented, and the last
/// element must be the root delegation issued by `principal`. Every link the holder relies
/// on must be present — this function never fetches one.
///
/// The signature on each credential is *not* checked here, nor is any acceptance, nor any
/// revocation status. Verify those separately; this function answers whether a set of
/// otherwise valid grants adds up to the representation claimed.
///
/// # This establishes representation, not permission
///
/// A successful return means the delegate may act in `principal`'s name for
/// `requested_act`. Whether *`principal`* may perform that act is a separate question this
/// crate does not answer, and a VDC never influences its outcome.
///
/// # `presenter` must be a party whose key control is already established
///
/// The leaf must appoint `presenter`, or the chain is refused with
/// [`DelegationError::NotTheDelegate`]. Pass the identifier of a party whose control of
/// the associated verification method the caller has established for *this request* — not
/// one read out of the request body. See the module documentation.
pub fn verify_chain(
    chain: &[DTGCredential],
    principal: &str,
    requested_act: &str,
    presenter: &str,
    at: DateTime<Utc>,
) -> Result<VerifiedDelegation, DelegationError> {
    if chain.is_empty() {
        return Err(DelegationError::EmptyChain);
    }
    if chain.len() > MAX_CHAIN_DEPTH {
        return Err(DelegationError::TooDeep { found: chain.len() });
    }

    // Every link must be a delegation *grant* carrying a scope and an expiry.
    for (index, link) in chain.iter().enumerate() {
        if !matches!(link.type_(), DTGCredentialType::Delegation) {
            return Err(DelegationError::NotADelegationGrant {
                index,
                found: link.type_().to_string(),
            });
        }
        let grant =
            link.credential()
                .delegation()
                .ok_or_else(|| DelegationError::NotADelegationGrant {
                    index,
                    found: "DelegationCredential without a delegation object".to_string(),
                })?;

        // An acceptance consents to an appointment; it does not make one. A chain of them
        // establishes nothing.
        if grant.accepts.is_some() {
            return Err(DelegationError::AcceptanceInChain { index });
        }
        if grant.scope.as_ref().is_none_or(|s| s.is_empty()) {
            return Err(DelegationError::NoScope { index });
        }

        let c = link.credential();
        if c.valid_from() > at {
            return Err(DelegationError::NotValidNow { index, at });
        }
        // REQUIRED on a VDC: an appointment with no expiry cannot be reasoned about by a
        // verifier that cannot reach the delegator.
        let Some(until) = c.valid_until() else {
            return Err(DelegationError::NoExpiry { index });
        };
        if until < at {
            return Err(DelegationError::NotValidNow { index, at });
        }
    }

    // Invocation binding: the leaf must appoint whoever is presenting it.
    //
    // Without this a presentation is a bearer object — it names what may be done and in
    // whose name, but not who is doing it — so anyone who observes one can act as the
    // principal. The check is only as good as `presenter`: see the module docs on what a
    // caller must have established before passing one.
    let leaf_delegate = chain[0].credential().subject();
    // Compared by DID: a did:scid party may be named with the `?src=` locator
    // it is resolved through (VTI-KEY-160), which is not part of who it is.
    if !same_reference(leaf_delegate, presenter) {
        return Err(DelegationError::NotTheDelegate {
            delegate: leaf_delegate.to_string(),
            presenter: presenter.to_string(),
        });
    }

    // Walk leaf -> root. Each step checks the link against the credential above it.
    for index in 0..chain.len() - 1 {
        let link = &chain[index];
        let parent = &chain[index + 1];
        let grant = link.credential().delegation().expect("checked above");
        let parent_grant = parent.credential().delegation().expect("checked above");

        // The link must point at the credential presented as its parent, by digest —
        // compared as decoded bytes, never as strings.
        let presented_digest = parent
            .digest_multibase()
            .map_err(|e| DelegationError::Digest {
                index: index + 1,
                reason: e.to_string(),
            })?;
        match &grant.parent {
            Some(named) => {
                let matches = crate::digests_match(named, &presented_digest).map_err(|e| {
                    DelegationError::Digest {
                        index,
                        reason: e.to_string(),
                    }
                })?;
                if !matches {
                    return Err(DelegationError::BrokenLink {
                        index,
                        named: named.clone(),
                        presented: presented_digest,
                    });
                }
            }
            None => {
                // A link with no `parent` claims to be a root delegation, but something
                // was presented above it.
                return Err(DelegationError::BrokenLink {
                    index,
                    named: "<none — link claims to be a root delegation>".to_string(),
                    presented: presented_digest,
                });
            }
        }

        // Only the party a delegation appointed may re-delegate it.
        if !same_reference(link.credential().issuer(), parent.credential().subject()) {
            return Err(DelegationError::IssuerNotParentSubject {
                index,
                issuer: link.credential().issuer().to_string(),
                subject: parent.credential().subject().to_string(),
            });
        }

        // Re-delegation must have been authorised, and each step must narrow the budget.
        let parent_depth = parent_grant.max_depth.unwrap_or(0);
        if parent_depth == 0 {
            return Err(DelegationError::RedelegationNotPermitted {
                index,
                parent_depth,
            });
        }
        if let Some(depth) = grant.max_depth
            && depth > parent_depth - 1
        {
            return Err(DelegationError::DepthNotNarrowed {
                index,
                depth,
                parent_depth,
            });
        }

        // Scope is set inclusion over exact matches: the specification defines no wildcard,
        // prefix or hierarchical semantics, so a governing vocabulary wanting structure
        // must put it in the terms themselves.
        let parent_scope = parent_grant.scope.as_deref().expect("checked above");
        for act in grant.scope.as_deref().expect("checked above") {
            if !parent_scope.contains(act) {
                return Err(DelegationError::WidensScope {
                    index,
                    act: act.clone(),
                });
            }
        }

        // Both are present: the loop above rejected any link without one.
        if let (Some(until), Some(parent_until)) = (
            link.credential().valid_until(),
            parent.credential().valid_until(),
        ) && until > parent_until
        {
            return Err(DelegationError::OutlivesParent {
                index,
                until,
                parent_until,
            });
        }
    }

    // The chain must terminate in a root delegation issued by the principal — the entity
    // in whose name the acts would ultimately be performed. A chain that cannot be
    // resolved to such a root establishes no representation.
    let root = chain.last().expect("non-empty");
    let root_grant = root.credential().delegation().expect("checked above");
    if !same_reference(root.credential().issuer(), principal) {
        return Err(DelegationError::RootNotPrincipal {
            root_issuer: root.credential().issuer().to_string(),
            expected: principal.to_string(),
        });
    }
    if let Some(named) = &root_grant.parent {
        // The chain was truncated: its "root" derives from something not presented.
        return Err(DelegationError::BrokenLink {
            index: chain.len() - 1,
            named: named.clone(),
            presented: "<nothing — chain ends here>".to_string(),
        });
    }

    let leaf = &chain[0];
    let leaf_grant = leaf.credential().delegation().expect("checked above");
    let scope = leaf_grant.scope.clone().expect("checked above");
    if !scope.iter().any(|a| a == requested_act) {
        return Err(DelegationError::ActNotAppointed {
            act: requested_act.to_string(),
        });
    }

    Ok(VerifiedDelegation {
        delegate: leaf.credential().subject().to_string(),
        scope,
        principal: principal.to_string(),
    })
}
