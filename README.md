# Decentralized Trust Graph (DTG) Credentials

**_NOTE:_** This is an early implementation of the [DTG Core Credentials
specification](https://github.com/trustoverip/dtgwg-cred-spec) (v1.0, Working
Draft 02), which supersedes the earlier v0.3 proposal draft.

See the [First Person Project Whitepaper](https://www.firstperson.network/white-paper)
for more information.

This library supports both W3C VC 1.1 and 2.0 specifications.

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Examples

```bash
cargo run --example sign_and_verify   # create, sign, verify one credential
cargo run --example data_room         # a whole data room, end to end
```

`data_room` runs the room story in one process with real DIDs, real signed credentials,
real AEAD and real chain verification: a room issues its owner a VAC, invites a member by
VIC, completes the VMC pair on their acknowledgement, seals a record, watches that member
equip an **agent with strictly less authority than they hold themselves**, then appoints a
service to act **in that member's name** by VDC — the same member, two credentials, and a
verifier that can always tell which it was shown — rotates the epoch on removal, and
finally prints exactly what the host can see, which is ciphertext, an epoch number, and
nothing else.

The credential types each have their own tests; `tests/authority_chain.rs` and
`tests/delegation_chain.rs` are mostly *attacks*, since what makes a VAC or a VDC
safe is a verifier refusing a chain that widens.

## Credential Type Hierarchy

All credentials inherit from the abstract `DTGCredential`.

```text
VerifiableCredential
└── DTGCredential
    ├── MembershipCredential (VMC)
    ├── RelationshipCredential (VRC)
    ├── DelegationCredential (VDC)
    ├── InvitationCredential (VIC)
    ├── PersonaCredential (VPC)
    ├── EndorsementCredential (VEC)
    ├── WitnessCredential (VWC)
    └── AuthorityCredential (VAC)
```

Two of those confer rather than assert, and a verifier has to be able to tell
which it was shown:

| | Question it answers | The act is attributed to |
| --- | --- | --- |
| **VAC** (authority) | may this party do this thing, *as itself*? | the party itself |
| **VDC** (delegation) | may this party act *in another's name*? | the entity it stands in for |

Neither implies the other, and a VDC never supplies authority the delegator did
not itself hold. See [Authority](#authority-vac) and [Delegation](#delegation-vdc).

**_NOTE:_** The relationship card (R-Card) is **not** a `DTGCredential` subtype.
It was reclassified as a verifiable data structure (VDS) in Working Draft 01, to
be defined by the planned *DTG Verifiable Data Structures* specification. The
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

A credential can be referenced by another through a `digestMultibase` of it: a
member-issued VMC digests the membership grant it acknowledges, a VWC digests the
edge credential it attests, an attenuated VAC digests the VAC it narrows, and a
VDC digests the delegation it derives from or the grant it accepts. All five use
the same computation.

```Rust
// A credential you received: digest the JSON as it arrived.
let digest = dtg_credentials::digest_multibase_json(&grant_json)?;

// A credential this library just built: `digest_multibase()` is equivalent.
let digest = grant.digest_multibase()?;
```

That is the SHA-256 of the credential canonicalized with JCS (RFC 8785) and
**excluding its top-level `proof`**, wrapped in a `sha2-256` multihash and
encoded base58btc with a multibase `z` prefix — the encoding [VC Data Integrity
§2.6](https://www.w3.org/TR/vc-data-integrity/#resource-integrity) defines for
`digestMultibase`. Leaving `proof` out binds the digest to what the credential
says rather than to one signature over it, so a reference survives its referent
being re-signed, and the digest can be computed before signing.

> [!IMPORTANT]
> Digest what you **received**, not what you parsed, wherever you still hold the
> bytes. `DTGCommon` now models `credentialStatus` and preserves unmodelled
> top-level members through a round trip, so for most credentials the two agree —
> but a timestamp is normalized on the way out, and
> `2026-01-06T10:00:00.000+00:00` hashes differently from the
> `2026-01-06T10:00:00Z` this library re-emits. `digest_multibase()` is safe for a
> credential built in-process; anything that arrived from elsewhere goes through
> `digest_multibase_json()`.

`verify_digest()` checks that a credential's digest matches the one it names:

```Rust
if vwc.verify_digest(&vrc)? {
  println!("this VWC attests that VRC");
}
```

It compares **decoded bytes**, not strings — the specification requires it,
because one digest has more than one spelling. `digests_match()` and
`decode_digest_multibase()` are exposed for callers doing the comparison
themselves.

For a membership pair, prefer `acknowledges()` — it checks the digest *and* that
the two halves are of the right types and name the same parties in mirrored
roles. See [Membership edges](#membership-edges). `accepts()` is its counterpart
for a delegation edge.

> [!NOTE]
> `digest()` and `digest_json()` are deprecated. They emit the Working Draft 01
> `sha256:<lowercase hex>` form, which Working Draft 02 replaced. They are kept
> so a caller migrating can recompute an old digest to compare against one they
> stored; new code uses `digest_multibase()` / `digest_multibase_json()`.
>
> On the wire, `digestMultibase` is what this library emits, and the old property
> name `digest` is still accepted when parsing. A credential carrying an old
> *value* parses and then fails to compare, with `InvalidDigest` rather than a
> silent mismatch.

## Membership edges

Membership is a **pair** of VMCs, not a single directed credential:

| | `issuer` | `credentialSubject.id` | `digestMultibase` |
| --- | --- | --- | --- |
| **Community-issued** (the grant) | community | member | MUST be absent |
| **Member-issued** (the acknowledgement) | member | community | MUST be present |

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

// Member side: verify the grant before answering it. `grant_json` is the JSON the
// community sent — the wire form, not a parse of it — and the key is resolved
// from the community's DID document.
verify_grant_with_public_key(&grant_json, &community_public_key, Utc::now())?;

// Then acknowledge it, as yourself. The parties are read off the grant, so the
// two halves cannot disagree about who they are between, and a grant naming
// anyone but `member_did` is refused.
let mut ack = DTGCredential::new_member_vmc_for(&grant_json, &member_did, Utc::now(), valid_until)?
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

Building the acknowledgement checks the binding too, and does not ask who signed
the grant. What `new_member_vmc_for()` does check is that the grant names the
member you pass — so pass the identity whose key you hold, never one read out of
the grant — and that the acknowledgement does not outlive the grant.
`verify_grant_with_public_key()` (feature `affinidi-signing`) covers the rest
before you answer: the proof, that the proof's verification method belongs to
the grant's issuer, and that the grant is in force.

> [!NOTE]
> `new_member_vmc()` and `new_delegate_vdc()` are deprecated in favour of
> `new_member_vmc_for()` and `new_delegate_vdc_for()`, which take the party you
> expect the grant to name.

Because the digest covers the grant's claims, a **re-issued** grant carries a
different digest and the earlier acknowledgement no longer matches it. Renewal
therefore forces re-acknowledgement rather than letting a stale consent carry
over to a membership the member never agreed to.

## Authority (VAC)

A VAC states what a party **may do** within a scope some node governs. Its holder
can narrow it without involving the governing party — which is what lets a member
equip an agent with four hours of read-only access instead of lending it their own
standing authority.

```Rust
// The governing party grants Bob read+write+curate for a month.
let root = DTGCredential::new_vac(
  room_did, bob_did, room_did.clone(),
  vec!["read".into(), "write".into(), "curate".into()],
  now, now + Duration::days(30),   // validUntil is REQUIRED on a VAC
)?;

// Bob equips his agent with strictly less, bound to that agent.
let agent = root.attenuate(
  agent_did, vec!["read".into()], now, now + Duration::hours(4), Some(agent_did),
)?;
```

`attenuate()` refuses anything that would widen, but **the verifier's check is the
authoritative one** — nothing stops another implementation building the JSON by
hand. `authority::verify_chain` is where the security of this credential lives:

```Rust
let permitted = verify_chain(
  &[agent, root],   // leaf first; the holder presents every link
  room_did, room_did, "read", agent_did, Utc::now(),
)?;
```

Anyone can mint a well-formed VAC naming any scope and any actions, and it will
verify perfectly as a *credential*. What makes it worthless is that its chain does
not reach the party governing the scope. A verifier that checks only the credential
it was handed has verified nothing.

`parent` is a **digest**, not an identifier. So there is nothing a verifier could be
induced to fetch, verification never depends on network availability, and a link
binds to the exact claims its issuer narrowed from — re-issuing a parent with
different claims orphans its children, while re-proofing it leaves them alone.
For a VAC that arrived from a counterparty, use `attenuate_from_json()` and give it
the bytes you received.

**A VAC is not a bearer credential.** `verify_chain()` takes the presenter and requires
the leaf to grant to it, so a captured presentation is worthless to whoever captured it.
Pass an identifier whose key control you have already established for *this* request — the
DID a transport authenticated, or one a signature over the request proved — never one read
out of the request body.

That rule is why there is no `audience`. Equipping an agent means naming the agent in
`subject`; a second field naming who may present could then only repeat the subject or
contradict it. Where a presentation may be *sent* is a different question, and it belongs
to the trust task carrying it rather than to the credential.

> [!NOTE]
> Two upstream changes to the VAC are **not** implemented yet: revocation via
> `credentialStatus`, cascading to everything attenuated below
> ([PR #39](https://github.com/trustoverip/dtgwg-cred-spec/pull/39)); and a
> `maxAttenuation` ceiling
> ([PR #40](https://github.com/trustoverip/dtgwg-cred-spec/pull/40)).

## Delegation (VDC)

A VDC establishes that one party may act **in another's name**. It is not authority,
and the distinction decides which credential to reach for: ask whose name the act is
performed in. The actor's own — that is a VAC. Another entity's — that is a VDC.

Like membership, a delegation is a **pair**:

| | `issuer` | `credentialSubject.id` | carries |
| --- | --- | --- | --- |
| **Grant** | delegator | delegate | `scope`, optionally `maxDepth` |
| **Acceptance** | delegate | delegator | `accepts` only |

```Rust
// Alice appoints her agent, permitting one further hop.
let grant = DTGCredential::new_vdc(
  alice_did, agent_did, now, now + Duration::days(90),
  vec!["schedule:read".into(), "schedule:propose".into()],
  Some(1),                          // maxDepth; None or 0 prohibits re-delegation
)?;

// The agent verifies the grant, then accepts it as itself. `grant_json` is the
// wire form, not a parse of it.
verify_grant_with_public_key(&grant_json, &alice_public_key, now)?;
let acceptance = DTGCredential::new_delegate_vdc_for(&grant_json, &agent_did, now, valid_until)?;
assert!(acceptance.accepts(&grant)?);
```

The acceptance is **required**. A grant alone establishes what the delegator
appointed, not what the delegate agreed to — and a delegator cannot produce the
countersignature. It is also why a party holding only the delegate's key cannot
manufacture new appointments.

Re-delegation is **opt-in**, the opposite default from a VAC's attenuation. A
delegate speaks in the principal's name, so the principal keeps the register of who
may do that; a delegate needing a further delegate ordinarily asks for a fresh root
delegation rather than minting one.

```Rust
let sub = grant.redelegate(subagent_did, vec!["schedule:read".into()], now, until)?;

let appointed = delegation::verify_chain(&[sub, grant], alice_did, "schedule:read", Utc::now())?;
assert_eq!(appointed.principal, alice_did);   // the acts are attributed to Alice
```

### A VDC moves the permission question; it does not answer it

`verify_chain` tells you the chain appoints this delegate to act in the principal's
name for this act. That is one of two checks. The other — *may the principal do this
thing?* — is yours to make, against whatever the act requires of them: membership, a
governance framework, an IDVC, a VAC. This crate does not answer it, and a VDC never
influences its outcome.

The reach of a delegated act is the **intersection** of what the principal may do
and what the chain appoints for. Two consequences worth stating: nothing the
delegator holds is copied to the delegate, and withdrawing the delegator's own
permission stops every delegate at once, without revoking a single VDC.

### A VDC is not a bearer credential

`verify_chain` takes a `presenter` and requires the leaf to appoint it, refusing
otherwise with `NotTheDelegate`. That is Working Draft 02's **Invocation Binding**
rule, and it is the same rule the VAC carries — sharper here, if anything: a captured
VAC replays whatever it confers, while a captured VDC replays *as somebody*, and
every act it carries is attributed to the principal.

Pass the identifier of a party whose key control you have already established for
**this request** — the DID a transport authenticated, or one a signature over the
request proved. An identifier read out of the request body reduces the check to a
string comparison an attacker chooses both sides of.

Only the leaf's delegate is asked for anything. The parties above it in the chain are
not present, which is what keeps re-delegation working.

Not implemented here: revocation — `credentialStatus` is modelled and settable, but
never resolved.

## Upgrading

**Upgrade verifiers before issuers.** Both directions of a version skew are errors,
but only one of them says so clearly.

A new credential reaching an old verifier is the confusing direction. 0.7 changed
`authority.parent` and `delegation.parent` from an `id` to a `digestMultibase`, so a
0.6 verifier compares a digest against an `id`, finds them unequal, and reports a
broken chain:

```
chain link 0 names parent `zQmPvoSXm7pYriaeeE3DRWVybmhYDkMt1UtNrxiRdFfRcrT`,
but was presented after `urn:uuid:064710ef-90ab-4013-9f95-f224af758754`
```

Both values are printed and nothing says they are different *kinds* of identifier, so
it reads exactly like a tampered or interleaved chain. It is not: it is a 0.6 verifier
being handed a 0.7 credential. Old verifiers cannot be taught to say this — the fix is
ordering.

The other direction is safe and loud. An old credential reaching a new verifier fails
with `InvalidDigest`, which names the Working Draft 01 `sha256:<hex>` form explicitly
rather than reporting it as a mismatch.

Since clients commonly upgrade ahead of the services they talk to, that ordering is
worth stating for each breaking release:

| Release | What changed on the wire or at the boundary | Ordering |
| --- | --- | --- |
| 0.7.0 | `parent` became a `digestMultibase`; `digest` → `digestMultibase` | Verifiers first |
| 0.8.0 | `authority::verify_chain` requires the leaf to grant to `presenter`; `audience` removed | Verifiers first |
| 0.9.1 | `delegation::verify_chain` requires the leaf to appoint `presenter` | Verifiers first |
| 0.10.0 | Validity-window and JSON-depth checks at issue and verify; `DTGCredentialError` is `#[non_exhaustive]` | Verifiers first |

Every one of them is *verifiers first*, and for the same reason: each made a verifier
stricter or changed what it reads, so a verifier that moves first accepts everything
it did before and is ready for what issuers send next.

`0.8.0` and `0.9.1` are API breaks rather than wire changes — no credential changes
shape — but they land in the same place: a caller that upgrades gets a compile error
naming the new parameter, which is the intended way to find out.

`0.10.0` breaks the API in a smaller way: `DTGCredentialError` becomes
`#[non_exhaustive]`, so an exhaustive `match` on it needs a wildcard arm. It also refuses
more, on both sides. Every constructor that returns a `Result`, and `sign()`, refuse a
validity window that closes before it opens and JSON nested past `MAX_JSON_DEPTH`;
`verify_proof_with_public_key()` refuses the same before it looks at a proof. A conforming
issuer emits neither, so verifiers-first still holds. `new_member_vmc()` and
`new_delegate_vdc()` are deprecated rather than removed: they still compile, and a build
with `-D warnings` names the `_for` replacement.

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

## Revocation status

A credential may carry `credentialStatus`, the W3C VC mechanism through which a
verifier determines whether it has been revoked. The entry is opaque here: the
mechanism is chosen by the governing VTC or VTN, and this library neither
selects one nor resolves it. `BitstringStatusListEntry` is the common choice.

The `new_*()` constructors leave it unset. Chain `with_credential_status()`:

```Rust
let vdc = DTGCredential::new_vdc(delegator, delegate, valid_from, valid_to, scope, None)?
  .with_credential_status(json!({
      "id": "https://example.com/status/3#94567",
      "type": "BitstringStatusListEntry",
      "statusPurpose": "revocation",
      "statusListIndex": "94567",
      "statusListCredential": "https://example.com/status/3"
  }));
```

On a VDC this is CONDITIONAL, not required. A verifier MUST be able to establish
that an appointment is currently in force without contacting the delegator, and
two things satisfy that: a `validUntil` short enough that expiry alone bounds the
exposure, with the delegator withdrawing by declining to re-issue; or a status
entry the verifier can check. A VDC MUST carry one where its validity period
exceeds the freshness window the governing VTC or VTN defines for delegations,
and MAY omit it otherwise.

That window is governance this library does not know, which is why this is a
setter rather than a constructor parameter — nothing here can tell which side of
the condition a given VDC falls on. Prefer short validity and re-issuance
wherever the delegator is reachable: a status check is a live lookup that reveals
the verification event to whoever hosts the status list. A long-lived appointment
made in advance of a delegator's unavailability is the case status exists for.

> [!IMPORTANT]
> Set it **before** signing, for the same reason as `id`.

> [!NOTE]
> Neither `delegation::verify_chain` nor `authority::verify_chain` resolves a
> status entry — both verify structure, scope and validity only. Revocation is a
> live lookup you perform.

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
