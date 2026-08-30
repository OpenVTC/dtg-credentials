# Decentralized Trust Graph (DTG) Credentials

**_NOTE:_** This is an early implementation of the [DTG Core Credentials
specification](https://github.com/trustoverip/dtgwg-cred-spec) (v1.0, Working
Draft 01), which supersedes the earlier v0.3 proposal draft.

See the [First Person Project Whitepaper](https://www.firstperson.network/white-paper)
for more information.

This library supports both W3C VC 1.1 and 2.0 specifications.

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Credential Type Hierarchy

All credentials inherit from the abstract `DTGCredential`.

```text
VerifiableCredential
└── DTGCredential
    ├── MembershipCredential (VMC)
    ├── RelationshipCredential (VRC)
    ├── InvitationCredential (VIC)
    ├── PersonaCredential (VPC)
    ├── EndorsementCredential (VEC)
    └── WitnessCredential (VWC)
```

**_NOTE:_** The relationship card (R-Card) is **not** a `DTGCredential` subtype.
Working Draft 01 reclassifies it as a verifiable data structure (VDS), to be
defined by the planned *DTG Verifiable Data Structures* specification. The
`RCard` type, `CredentialSubjectRCard` and `new_rcard()` are deprecated in this
library and will be removed in a future release.

## Trust Task Context

Credentials issued inside a multi-step trust task exchange may carry a
`taskContext` property holding the `threadId` of that exchange. It is REQUIRED
on a `WitnessCredential` — deserializing a VWC without one fails with
`DTGCredentialError::MissingTaskContext` — and OPTIONAL on every other type.

A credential without a `taskContext` must be interpretable standing alone. A
credential *with* one must not be read as proof that the trust task completed
unless the matching outcome evidence is also present and verified.

```Rust
let vwc = DTGCredential::new_vwc(
  issuer, subject, valid_from, valid_until,
  "thread-abc-123".to_string(), // taskContext
  digest, witness_context,
);

assert_eq!(vwc.task_context(), Some("thread-abc-123"));
```

## Digests

An edge credential can be referenced by another credential through a `digest` of
it: a member-issued VMC digests the membership grant it acknowledges, and a VWC
digests the edge credential it attests. Both use the same computation.

```Rust
// A credential you received: digest the JSON as it arrived.
let digest = dtg_credentials::digest_json(&grant_json)?;

// A credential this library just built: `digest()` is equivalent.
let digest = grant.digest()?;
```

> [!IMPORTANT]
> Digest what you **received**, not what you parsed. A credential may carry
> members this library does not model — `credentialStatus` is the common one,
> and every VMC issued against a status list has it — and a
> parse-then-re-serialise round trip drops them silently. `digest()` is safe
> only for a credential built in-process; anything that arrived from elsewhere
> goes through `digest_json()`.

That is `sha256:` followed by the lowercase hex SHA-256 of the credential
canonicalized with JCS (RFC 8785), **excluding its top-level `proof`**. Leaving
`proof` out binds the digest to what the credential says rather than to one
signature over it, so a reference survives its referent being re-signed, and the
digest can be computed before signing.

`verify_digest()` checks that a credential's digest matches the one it names:

```Rust
if vwc.verify_digest(&vrc)? {
  println!("this VWC attests that VRC");
}
```

For a membership pair, prefer `acknowledges()` — it checks the digest *and* that
the two halves are of the right types and name the same parties in mirrored
roles. See [Membership edges](#membership-edges).

> [!NOTE]
> `digest_multibase()` is deprecated. It emits a base58btc multibase multihash
> over the credential *including* its proof, which is not what the specification
> requires and does not interoperate. Use `digest()`.

## Membership edges

Membership is a **pair** of VMCs, not a single directed credential:

| | `issuer` | `credentialSubject.id` | `digest` |
| --- | --- | --- | --- |
| **Community-issued** (the grant) | community C-DID | member M-DID | MUST be absent |
| **Member-issued** (the acknowledgement) | member M-DID | community C-DID | MUST be present |

The member-issued half is the member's *consent artifact*. A community can
always issue a credential naming somebody as a member; what it cannot do is
produce the acknowledgement, because that needs the member's signature. So an
unconsented membership claim is unprovable — a community that cannot show the
acknowledgement is visibly asserting a membership nobody agreed to.

```Rust
// Community side: grant membership.
let grant = DTGCredential::new_vmc(
  community_did, member_did, valid_from, valid_until, personhood,
).with_id(format!("urn:uuid:{}", Uuid::new_v4()));
grant.sign(&community_key, None).await?;

// Member side: acknowledge it. `grant_json` is the JSON the community sent —
// the wire form, not a parse of it. The parties are read off the grant, so the
// two halves cannot disagree about who they are between.
let mut ack = DTGCredential::new_member_vmc(&grant_json, Utc::now(), None)?
  .with_id(format!("urn:uuid:{}", Uuid::new_v4()));
ack.sign(&member_key, None).await?;

// Either side: is this edge complete?
assert!(ack.acknowledges(&grant)?);
```

`acknowledges()` checks the binding — types, mirrored parties, and the digest.
It deliberately does **not** check either credential's proof or validity window:
proof verification needs a resolver this crate does not hold, and whether a
window is current is a question about an instant the caller chooses. An edge is
complete when both halves are valid *and* bound; this covers the binding.

Because the digest covers the grant's claims, a **re-issued** grant carries a
different digest and the earlier acknowledgement no longer matches it. Renewal
therefore forces re-acknowledgement rather than letting a stale consent carry
over to a membership the member never agreed to.

## End to End Example

An end-to-end example of creating, signing and verifying a DTG Credential exists
in `examples`

```bash
cargo run --example sign_and_verify
```

## Creating credentials

Each credential type has it's own `new_*()` function to create a new credential
of that type.

Example:

```Rust
let vpc = DTGCredential::new_vpc(issuer, subject, valid_from, valid_to);
```

The created `DTGCredential` can be serialized to JSON using `serde_json` allowing
it to be passed into various signing libraries

## Credential identifiers

A credential may carry its own top-level `id` — the OPTIONAL identifier of the
W3C VC Data Model, distinct from `credentialSubject.id`, which names the
*subject*. When present it MUST be a single URL; `urn:uuid:<uuid>` is the usual
choice for a credential with no dereferenceable home.

The `new_*()` constructors leave it unset. Chain `with_id()` to add one:

```Rust
let vmc = DTGCredential::new_vmc(issuer, subject, valid_from, valid_to, false)
  .with_id(format!("urn:uuid:{}", Uuid::new_v4()));

assert_eq!(vmc.id(), Some(...));
```

Issue with an `id` unless you know no counterparty needs one. It is the handle a
holder or verifier stores the credential *under*, so it is what makes
re-delivery of the same credential idempotent, and re-issuance of a different
one recognisable as a renewal rather than a duplicate. A verifier that keys
credentials by `id` has no way to accept one that has none.

> [!IMPORTANT]
> Set the `id` **before** signing. A Data Integrity proof covers the credential
> minus its `proof`, so the identifier is part of what is signed. Splicing one
> into the JSON after `sign()` produces a document whose proof no longer
> verifies.

## Signing credentials

By default the `affinidi-signing` feature is enabled which allows you to sign a
credential

```Rust
let mut vpc = DTGCredential::new_vpc(issuer, subject, valid_from, valid_to);

vpc.sign(&signing_key).await?;
```

### Verifying credentials

There are two ways to validate a credential:

**Method 1:** If you have the public key bytes that correspond to the signing
key, then you can directly verify the credential:

```Rust
let signing_key = Secret::generate_ed25519(None, None);
let mut vpc = DTGCredential::new_vpc(issuer, subject, valid_from, valid_to);

vpc.sign(&signing_key).await?;

vpc.verify(&signing_key.get_public_bytes())?;
```

**Method 2:** If you do not have the public key material, you are likely going to
need to resolve the DID VerificationMethod and derive the public key bytes used
when creating the credential.

```Rust
let mut credential = serde_json::from_str(<raw_credential_string>);

// Get the proof
let proof = if let Some(proof) = &credential.credential().proof {
  proof.clone()
} else {
    bail!("credential is not signed!");
};

// Strip proof from the credential
let unsigned = DTGCommon {
  proof: None,
  ..credential.credential().clone()
};

tdk.verify_data(&unsigned, None, &proof).await?;
```

## Common functions

You can deal with the raw credential as required.

```Rust
let vrc = DTGCredential::new_vrc(issuer, subject, valid_from, valid_to);

let credential = vrc.credential();
```

You can determine the credential type easily using:

```Rust
let vmc = DTGCredential::new_vmc(issuer, subject, valid_from, valid_to);

if let DTGCredentialType::VMC = vmc.type_() {
  // Good
}
```

Has this Credential been signed?

```Rust
let vmc = DTGCredential::new_vmc(issuer, subject, valid_from, valid_to);

if vmc.signed() {
  println!("Credential has been signed");
} else {
  println!("Credential has not been signed");
}
```
