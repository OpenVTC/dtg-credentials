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

## Witness Digests

A VWC may bind itself to the VRC it witnesses via `credentialSubject.digest`.
Compute it from the witnessed credential:

```Rust
let digest = vrc.digest_multibase()?;
```

This is the SHA-256 hash of the credential canonicalized with JCS (RFC 8785),
wrapped as a multihash and encoded base58btc multibase (`z...`), matching the
W3C `digestMultibase` convention. A verifier can check the binding with:

```Rust
if vwc.verify_digest(&vrc)? {
  println!("VWC attests this VRC");
}
```

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
