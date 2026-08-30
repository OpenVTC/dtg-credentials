# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-08-30

Membership is a **pair** of VMCs, and this release is what makes the second one
expressible. DTG Core Credentials defines a community-issued VMC (the membership grant) and
a member-issued VMC (the acknowledgement) whose `credentialSubject.digest` binds it to the
grant; a member-issued VMC whose digest matches no valid grant MUST NOT be treated as
completing a membership edge. This library could not represent that: `CredentialSubjectBasic`
is `deny_unknown_fields` over `id` alone, so an acknowledgement carrying a digest could not
be built or deserialized as a VMC at all.

### Added

- `DTGCredential::new_member_vmc()` builds the member-issued half from the grant it
  acknowledges, computing the digest and reading both parties off the grant — so the two
  halves cannot disagree about who they are between. Refuses anything that is not a
  community-issued grant
- `DTGCredential::acknowledges()` answers whether a member-issued VMC completes a given
  grant's edge: right types, mirrored parties, matching digest. It deliberately checks
  neither proof nor validity window — proof verification needs a resolver this crate does
  not hold, and whether a window is current is a question about an instant the caller
  chooses
- `DTGCredential::digest()`, the specification's digest: `sha256:` + lowercase hex SHA-256
  over the JCS (RFC 8785) canonical form **excluding the top-level `proof`**. One
  computation now serves both places the spec uses a digest — the member-issued VMC and the
  VWC. Excluding `proof` is what lets an acknowledgement survive its grant being re-signed
- `DTGCredential::subject_digest()` reads the `digest` off whichever subject carries one
- `CredentialSubjectMembership`, the VMC subject, carrying the OPTIONAL `digest`

### Changed

- **BREAKING:** a `MembershipCredential` now deserializes with
  `CredentialSubject::Membership`, not `CredentialSubject::Basic`. A `{ id, digest }`
  subject is shape-identical to a VWC subject and the untagged enum matches `Witness`
  first, so the subject object alone cannot say which it is — only the credential's `type`
  can. `TryFrom<DTGCommon>` therefore normalizes whichever variant the untagged match
  landed on, the same way it already re-wrapped a `Basic` subject as `Witness` on a VWC.
  Deserialization is deterministic rather than order-dependent, and code matching on a
  VMC's subject sees one shape rather than two
- **BREAKING:** `CredentialSubject` has a new variant. A match over it must be updated;
  the variant is last and is never selected by the untagged match, so nothing that
  deserializes changes shape beyond the VMC normalization above
- **BREAKING:** a `MembershipCredential` whose subject fits none of those shapes — an
  endorsement subject, or a `witnessContext`, which belongs to a VWC and has no meaning
  here — is now refused as `UnknownCredential` rather than accepted unexamined. The
  `Membership` arm previously took any subject at all
- `new_vmc()` documents itself as the community-issued grant and builds a `Membership`
  subject. The wire form is unchanged: `digest` is absent on a grant, and skipped when
  `None`

### Deprecated

- `DTGCredential::digest_multibase()`. It emits a base58btc multibase multihash over the
  credential *including* its proof — neither the encoding nor the coverage the
  specification requires, so digests it produced never interoperated. This was the known
  divergence documented at the top of the README, which that README no longer carries.
  `verify_digest()` now compares against `digest()`, so a conformant credential from
  another implementation verifies and one built on `digest_multibase()` does not


## [0.3.0] - 2026-08-29

### Added

- `id` property on `DTGCommon`, the OPTIONAL top-level credential identifier of the W3C VC
  Data Model. It was missing entirely, so a credential built with this library could not
  carry one — and a counterparty that keys credentials by `id` had nothing to key on. Every
  reciprocal `MembershipCredential` an OpenVTC member issued was rejected by the VTC for
  exactly this reason, with the rejection arriving as a problem-report the member's client
  discarded, so the failure was silent on both sides
- `DTGCredential::with_id()` and `DTGCredential::set_id()` to set it while building, and
  `DTGCredential::id()` / `DTGCommon::id()` to read it back. `id` is inside what a Data
  Integrity proof covers, so it MUST be set before `sign()`; a test pins that (adding or
  changing it afterwards invalidates the proof)

### Changed

- **BREAKING:** `DTGCommon` has a new public field. Construction through
  `..Default::default()` (as every `new_*` constructor does) is unaffected; an exhaustive
  struct literal will need the extra field

## [0.2.0] - 2026-08-10

### Added

- `taskContext` property on `DTGCommon`, per the Trust Task Context Binding section of the
  new specification. It is REQUIRED on a `WitnessCredential` and OPTIONAL elsewhere.
  Previously this property was silently dropped on deserialization, which broke signing and
  verification of any spec-conformant VWC: `sign()` serializes the credential, so a dropped
  `taskContext` meant issuers signed a document missing the field and verifiers hashed a
  different document than the one that was signed
- `DTGCredential::task_context()` and `DTGCommon::task_context()` accessors
- `DTGCredential::digest_multibase()`, computing the digest of a credential for use as the
  `digest` of a Witness Credential attesting it
- `DTGCredential::verify_digest()`, checking a VWC's `digest` against the credential it
  claims to witness
- `DTGCredentialError::MissingTaskContext` and `DTGCredentialError::Canonicalization`

### Changed

- Tracked the [DTG Core Credentials specification](https://github.com/trustoverip/dtgwg-cred-spec)
  v1.0 Working Draft 01, which supersedes the v0.3 proposal draft this library was built against
- **BREAKING:** `DTGCredential::new_vwc()` takes a required `task_context: String` argument
- **BREAKING:** Deserializing a `WitnessCredential` without a `taskContext` now fails with
  `DTGCredentialError::MissingTaskContext`
- Added `multibase`, `sha2` and `serde_json_canonicalizer` as direct dependencies (all were
  already present transitively via `affinidi-data-integrity`)

### Deprecated

- `DTGCredentialType::RCard`, `CredentialSubject::RCard`, `CredentialSubjectRCard` and
  `DTGCredential::new_rcard()`. Working Draft 01 reclassifies the r-card as a verifiable data
  structure (VDS) rather than a `DTGCredential` subtype, to be defined by the planned
  *DTG Verifiable Data Structures* specification. These will be removed in a future release

### Notes

- **⚠️ KNOWN SPEC DIVERGENCE — VWC `digest` encoding.** WD-01 requires the VWC `digest` to be
  encoded as `sha256:` followed by a lowercase hex digest. This library instead emits a
  multibase-encoded multihash (base58btc, `z...`), matching the W3C `digestMultibase`
  convention used elsewhere in the VC ecosystem. The underlying hash — SHA-256 over the JCS
  (RFC 8785) canonical form — is identical; only the encoding differs.
  **VWCs produced by this library do not interoperate with spec-conformant implementations
  in either direction:** `verify_digest()` rejects conformant VWCs, and conformant verifiers
  reject ours. Unresolved; to be raised with the DTGWG. See README.md

## [0.1.3] - 2026-06-06

### Changed

- Updated `affinidi-data-integrity` dependency from 0.6 to 0.7
- Updated `affinidi-tdk` dev-dependency from 0.6 to 0.7

## [0.1.2] - 2026-04-30

### Changed

- Updated `affinidi-data-integrity` dependency from 0.5 to 0.6

### Fixed

- Migrated to the `affinidi-data-integrity` 0.6 API

## [0.1.1] - 2026-03-29

### Changed

- `DTGCredential::sign()` is now an `async` method (breaking change) to align with upstream `affinidi-data-integrity` v0.5
- Updated `affinidi-data-integrity` dependency from 0.4 to 0.5
- Updated `affinidi-tdk` dev-dependency from 0.5 to 0.6
- Relaxed `tokio` dev-dependency version from 1.49 to 1
- Updated repository URL to `https://github.com/OpenVTC/dtg-credentials`
- Enabled crate publishing (`publish = true`)

## [0.1.0] - 2026-02-25

Never published to crates.io; `publish` was enabled in 0.1.1.

### Added

- Initial release
- Support for W3C VC 1.1 and 2.0 specifications
- DTG credential types: VMC, VRC, VIC, VPC, VEC, VWC, and RCard
- Credential signing via W3C Data Integrity Proof (JCS EdDSA 2022)
- Credential verification with public key bytes
- Optional `affinidi-signing` feature for integrated signing support
