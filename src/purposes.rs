//! Purposes of use on a VAC (DTG Core Credentials, *Purposes of Use*).
//!
//! `authority` says what the subject may do, and where; `purposes` says what for — the
//! purposes for which the subject may use content it obtains by exercising that authority.
//! The member has the meaning the VTI specification gives an access control entry's
//! purposes (VTI-ACL-100 – VTI-ACL-110).
//!
//! A VAC that states no `purposes` grants `any`, and `any` never includes
//! [MODEL_TRAINING]. Along a chain a link that states none takes its parent's, and a link
//! stating wider purposes than its parent's makes the chain invalid; the chain rule is
//! [crate::authority::verify_chain]'s.

use serde::{Deserialize, Serialize};

/// The registered purpose `any` never grants: training, fine-tuning or evaluating a
/// machine-learning model on the content.
pub const MODEL_TRAINING: &str = "modelTraining";

/// The longest purpose this library accepts.
pub const MAX_PURPOSE_LEN: usize = 2048;

/// The most purposes one VAC may list.
pub const MAX_LISTED_PURPOSES: usize = 32;

/// A VAC's purposes: `{"scope": "any"}` or `{"scope": "listed", "purposes": [...]}`.
///
/// The list is never empty, and an empty list is not `any`; [PurposeScope::check] refuses
/// one, and refuses a purpose named twice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "WireScope", into = "WireScope")]
#[non_exhaustive]
pub enum PurposeScope {
    /// Every purpose except [MODEL_TRAINING].
    Any,
    /// Exactly these purposes, compared as exact, case-sensitive strings.
    Listed {
        /// Registered names or absolute IRIs, each named once.
        purposes: Vec<String>,
    },
}

/// The wire form, read strictly. An internally tagged enum would accept
/// `{"scope": "any", "purposes": [...]}` — serde lets a unit variant ignore extra members —
/// and a credential is parsed with no schema in front of it, so the shape is checked here.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireScope {
    scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    purposes: Option<Vec<String>>,
}

impl TryFrom<WireScope> for PurposeScope {
    type Error = String;

    fn try_from(w: WireScope) -> Result<Self, String> {
        match (w.scope.as_str(), w.purposes) {
            ("any", None) => Ok(Self::Any),
            ("any", Some(_)) => Err("`any` carries no `purposes`".into()),
            ("listed", Some(purposes)) => Ok(Self::Listed { purposes }),
            ("listed", None) => Err("`listed` names its `purposes`".into()),
            (other, _) => Err(format!(
                "`{other}` is not a purpose scope: `any` or `listed`"
            )),
        }
    }
}

impl From<PurposeScope> for WireScope {
    fn from(p: PurposeScope) -> Self {
        match p {
            PurposeScope::Any => Self {
                scope: "any".into(),
                purposes: None,
            },
            PurposeScope::Listed { purposes } => Self {
                scope: "listed".into(),
                purposes: Some(purposes),
            },
        }
    }
}

impl Default for PurposeScope {
    /// `any`: what a VAC stating no `purposes` grants.
    fn default() -> Self {
        Self::Any
    }
}

/// Whether `p` is a purpose: a lowerCamelCase name of at most 64 characters, as the VTI
/// purpose registry spells them, or an absolute IRI.
///
/// A well-formed name the registry does not hold is accepted — it equals only itself — so
/// the registry can grow without a new release of this library.
pub fn is_purpose(p: &str) -> bool {
    if p.is_empty() || p.len() > MAX_PURPOSE_LEN {
        return false;
    }
    let mut chars = p.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if let Some((scheme, rest)) = p.split_once(':') {
        return first.is_ascii_alphabetic()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
            && !rest.is_empty()
            && !rest.chars().any(char::is_whitespace);
    }
    first.is_ascii_lowercase() && p.len() <= 64 && chars.all(|c| c.is_ascii_alphanumeric())
}

impl PurposeScope {
    /// A `listed` scope.
    pub fn listed<I, S>(purposes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Listed {
            purposes: purposes.into_iter().map(Into::into).collect(),
        }
    }

    /// The shape rules: a non-empty list of at most [MAX_LISTED_PURPOSES] purposes, each
    /// well formed and named once.
    pub fn check(&self) -> Result<(), String> {
        let Self::Listed { purposes } = self else {
            return Ok(());
        };
        if purposes.is_empty() {
            return Err(
                "a listed purpose scope names no purpose, and an empty list is not `any`".into(),
            );
        }
        if purposes.len() > MAX_LISTED_PURPOSES {
            return Err(format!(
                "a purpose scope lists at most {MAX_LISTED_PURPOSES} purposes"
            ));
        }
        for (i, p) in purposes.iter().enumerate() {
            if !is_purpose(p) {
                return Err(format!(
                    "`{p}` is neither a registered purpose name nor an absolute IRI"
                ));
            }
            if purposes[..i].contains(p) {
                return Err(format!("`{p}` is listed twice"));
            }
        }
        Ok(())
    }

    /// Whether this grants `purpose`: `any` grants every purpose but [MODEL_TRAINING]; a
    /// list grants exactly its members.
    pub fn grants(&self, purpose: &str) -> bool {
        match self {
            Self::Any => purpose != MODEL_TRAINING,
            Self::Listed { purposes } => purposes.iter().any(|p| p == purpose),
        }
    }

    /// Whether a link stating `self` may sit beneath a parent whose effective purposes are
    /// `parent`: `any` only beneath `any`, and a list only of purposes `parent` grants.
    pub fn is_within(&self, parent: &PurposeScope) -> bool {
        match (self, parent) {
            (Self::Any, Self::Any) => true,
            (Self::Any, Self::Listed { .. }) => false,
            (Self::Listed { purposes }, parent) => purposes.iter().all(|p| parent.grants(p)),
        }
    }

    /// The purposes in `self` that `parent` does not grant — `["any"]` for `any` beneath a
    /// list — for a refusal that names them.
    pub fn beyond(&self, parent: &PurposeScope) -> Vec<String> {
        match (self, parent) {
            (Self::Any, Self::Listed { .. }) => vec!["any".to_string()],
            (Self::Any, Self::Any) => Vec::new(),
            (Self::Listed { purposes }, parent) => purposes
                .iter()
                .filter(|p| !parent.grants(p))
                .cloned()
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_two_shapes_round_trip_and_nothing_else_parses() {
        assert_eq!(
            serde_json::to_value(PurposeScope::Any).unwrap(),
            json!({ "scope": "any" })
        );
        let listed: PurposeScope =
            serde_json::from_value(json!({ "scope": "listed", "purposes": ["taskExecution"] }))
                .unwrap();
        assert_eq!(listed, PurposeScope::listed(["taskExecution"]));
        assert!(serde_json::from_value::<PurposeScope>(json!({ "scope": "none" })).is_err());
        assert!(
            serde_json::from_value::<PurposeScope>(json!({ "scope": "any", "purposes": [] }))
                .is_err()
        );
    }

    #[test]
    fn an_empty_list_a_duplicate_or_a_malformed_purpose_is_refused() {
        assert!(PurposeScope::listed(Vec::<String>::new()).check().is_err());
        assert!(
            PurposeScope::listed(["analytics", "analytics"])
                .check()
                .is_err()
        );
        assert!(PurposeScope::listed(["Analytics"]).check().is_err());
        assert!(
            PurposeScope::listed(["https://w3id.org/dpv#ServicePersonalisation", "someNewName"])
                .check()
                .is_ok()
        );
    }

    #[test]
    fn any_never_grants_model_training_and_a_list_grants_exactly_its_members() {
        assert!(!PurposeScope::Any.grants(MODEL_TRAINING));
        assert!(PurposeScope::Any.grants("analytics"));
        let l = PurposeScope::listed(["personalisation"]);
        assert!(l.grants("personalisation"));
        assert!(!l.grants("https://w3id.org/dpv#ServicePersonalisation"));
    }

    #[test]
    fn a_link_narrows_and_never_widens() {
        let pa = PurposeScope::listed(["personalisation", "analytics"]);
        assert!(PurposeScope::Any.is_within(&PurposeScope::Any));
        assert!(pa.is_within(&PurposeScope::Any));
        assert!(PurposeScope::listed(["analytics"]).is_within(&pa));
        assert!(!PurposeScope::Any.is_within(&pa));
        assert!(!PurposeScope::listed([MODEL_TRAINING]).is_within(&PurposeScope::Any));
        assert_eq!(PurposeScope::Any.beyond(&pa), vec!["any".to_string()]);
    }
}
