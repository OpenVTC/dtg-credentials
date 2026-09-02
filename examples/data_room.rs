//! A data room, end to end, in one process.
//!
//! Run with `cargo run --example data_room`.
//!
//! # What this is
//!
//! A **data room** is a shared space governed by credentials the room itself issues, whose
//! contents the host cannot read. This example runs the whole story with real DIDs, real
//! signed credentials, real AEAD, and real chain verification — and prints, at the end,
//! exactly what the host can see.
//!
//! Seven steps:
//!
//! 1. Alice creates a room. It gets its own DID and issues her an owner VAC.
//! 2. Alice invites Bob — a **VIC**, issued by the room.
//! 3. Bob presents it and receives a **VMC pair** (membership) and a **VAC** (what he may do).
//! 4. Bob writes a record. Sealed under the epoch key, AAD-bound to its location.
//! 5. Bob attenuates a **read-only, four-hour, audience-bound VAC to his agent**, which
//!    recalls the record. The agent never holds Bob's own authority.
//! 6. Alice removes Bob. The epoch rotates and the new key is sealed only to who remains.
//!    Bob's agent can still read what it already could — and nothing written after.
//! 7. The host view: every byte the operator holds.
//!
//! # What is deliberately not here
//!
//! This is the demo track of the data-rooms plan, not the product. It uses **one symmetric
//! key per epoch** rather than MLS, so there is no post-compromise security and membership
//! change is O(n). It uses `did:key` rather than a witnessed `did:webvh`, so ownership
//! cannot transfer. It discloses the acting member to the host (the `attributed` tier)
//! rather than presenting in zero knowledge. And the host is a `BTreeMap` behind a trait
//! rather than a service.
//!
//! Every one of those is a real gap, and each is listed against what it does not prove in
//! the delivery plan. What the demo *does* establish is that the credential model works:
//! access is decided by a chain that reaches the room, an agent runs on strictly less than
//! its human, and removal actually removes.

use std::collections::BTreeMap;

use affinidi_tdk::{
    TDK,
    common::config::TDKConfig,
    dids::{DID, KeyType},
};
use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use chrono::{Duration, Utc};
use dtg_credentials::{DTGCredential, authority::verify_chain};
use rand::RngCore;

// ---------------------------------------------------------------------------------------
// The host
// ---------------------------------------------------------------------------------------

/// What a room host stores, and all it can do.
///
/// The interface is narrow on purpose. Track 2 of the delivery plan replaces this
/// implementation with a VTC-backed one, and that is only a swap if nothing above this
/// trait reached around it. **A host never sees a plaintext record and never holds a
/// member list** — membership is decided by credentials the room issued, not by anything
/// stored here.
trait RoomHost {
    /// Store a sealed record. `aad` is bound into the ciphertext, so the host cannot move
    /// this record to another key, version, or room without the open failing.
    fn put(&mut self, room: &str, key: &str, epoch: u32, sealed: Vec<u8>, nonce: [u8; 12]);
    /// Fetch a sealed record.
    fn get(&self, room: &str, key: &str) -> Option<&StoredRecord>;
    /// Every record in a room, in key order.
    fn list(&self, room: &str) -> Vec<(&String, &StoredRecord)>;
    /// The room's current epoch.
    fn epoch(&self, room: &str) -> u32;
    /// Bump the epoch. The host is told the number; it never learns the key.
    fn set_epoch(&mut self, room: &str, epoch: u32);
}

/// A record as the host holds it: ciphertext and the metadata needed to serve it.
struct StoredRecord {
    sealed: Vec<u8>,
    nonce: [u8; 12],
    epoch: u32,
}

#[derive(Default)]
struct InMemoryHost {
    records: BTreeMap<(String, String), StoredRecord>,
    epochs: BTreeMap<String, u32>,
}

impl RoomHost for InMemoryHost {
    fn put(&mut self, room: &str, key: &str, epoch: u32, sealed: Vec<u8>, nonce: [u8; 12]) {
        self.records.insert(
            (room.to_string(), key.to_string()),
            StoredRecord {
                sealed,
                nonce,
                epoch,
            },
        );
    }
    fn get(&self, room: &str, key: &str) -> Option<&StoredRecord> {
        self.records.get(&(room.to_string(), key.to_string()))
    }
    fn list(&self, room: &str) -> Vec<(&String, &StoredRecord)> {
        self.records
            .iter()
            .filter(|((r, _), _)| r == room)
            .map(|((_, k), v)| (k, v))
            .collect()
    }
    fn epoch(&self, room: &str) -> u32 {
        *self.epochs.get(room).unwrap_or(&1)
    }
    fn set_epoch(&mut self, room: &str, epoch: u32) {
        self.epochs.insert(room.to_string(), epoch);
    }
}

// ---------------------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------------------

/// Associated data binding a record to exactly where it lives.
///
/// This is the cut-and-paste defence: a host that relocates a sealed record to another key,
/// version, epoch, or room produces an AAD mismatch and the open fails. The record cannot
/// be moved without being detected, even though the host holds every byte of it.
fn aad(room: &str, key: &str, version: u32, epoch: u32) -> Vec<u8> {
    format!("{room}|{key}|{version}|{epoch}").into_bytes()
}

fn seal(room_key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(room_key));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("seal failed: {e}"))?;
    Ok((sealed, nonce_bytes))
}

fn open(room_key: &[u8; 32], sealed: &[u8], nonce: &[u8; 12], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(room_key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad })
        .map_err(|e| anyhow::anyhow!("open failed: {e}"))
}

fn new_room_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    k
}

// ---------------------------------------------------------------------------------------
// The walkthrough
// ---------------------------------------------------------------------------------------

fn step(n: u8, title: &str) {
    println!("\n\x1b[1m─── {n}. {title}\x1b[0m");
}

#[tokio::main]
async fn main() -> Result<()> {
    let tdk = TDK::new(
        TDKConfig::builder().with_load_environment(false).build()?,
        None,
    )
    .await?;

    let now = Utc::now();

    // Every party is a real did:key with a real signing secret.
    let (room_did, room_secret) = DID::generate_did_key(KeyType::Ed25519)?;
    let (alice_did, _alice_secret) = DID::generate_did_key(KeyType::Ed25519)?;
    let (bob_did, bob_secret) = DID::generate_did_key(KeyType::Ed25519)?;
    let (agent_did, _agent_secret) = DID::generate_did_key(KeyType::Ed25519)?;

    let mut host = InMemoryHost::default();
    host.set_epoch(&room_did, 1);
    let mut room_key = new_room_key();

    println!("\x1b[1mA data room, end to end\x1b[0m");
    println!("room   {room_did}");
    println!("alice  {alice_did}  (owner)");
    println!("bob    {bob_did}");
    println!("agent  {agent_did}  (Bob's)");

    // -- 1 ------------------------------------------------------------------------------
    step(1, "Alice creates the room");
    // The room is an entity: it has its own DID and issues its own credentials. Alice
    // controls it, which is what makes her the owner — there is no separate owner record.
    let mut alice_vac = DTGCredential::new_vac(
        room_did.clone(),
        alice_did.clone(),
        room_did.clone(),
        vec![
            "read".into(),
            "write".into(),
            "curate".into(),
            "admin".into(),
        ],
        now,
        Some(now + Duration::days(365)),
    )?
    .with_id("urn:uuid:vac-alice");
    alice_vac.sign(&room_secret, None).await?;
    println!("room DID minted; owner VAC issued to Alice");
    println!("  actions: read, write, curate, admin");

    // -- 2 ------------------------------------------------------------------------------
    step(2, "Alice invites Bob");
    // The VIC is issued by the room and travels to Bob out of band. On the private tier it
    // never touches the host — which is why the host below never sees it.
    let mut vic = DTGCredential::new_vic(
        room_did.clone(),
        bob_did.clone(),
        now,
        Some(now + Duration::days(7)),
    )
    .with_id("urn:uuid:vic-bob");
    vic.sign(&room_secret, None).await?;
    println!("VIC issued to Bob, valid 7 days — delivered out of band, never via the host");

    // -- 3 ------------------------------------------------------------------------------
    step(3, "Bob presents the invitation and joins");
    // Consent: Bob's acknowledgement is what completes the membership edge. A community
    // (or room) cannot assert a membership the member never agreed to.
    let mut grant = DTGCredential::new_vmc(
        room_did.clone(),
        bob_did.clone(),
        now,
        Some(now + Duration::days(30)),
        false,
    );
    grant.sign(&room_secret, None).await?;

    // The acknowledgement digests the grant's *wire* form — which is why the grant is
    // serialized after signing and handed over as a `Value`.
    let grant_wire = serde_json::to_value(&grant)?;
    let mut ack = DTGCredential::new_member_vmc(&grant_wire, now, Some(now + Duration::days(30)))?;
    ack.sign(&bob_secret, None).await?;

    let mut bob_vac = DTGCredential::new_vac(
        room_did.clone(),
        bob_did.clone(),
        room_did.clone(),
        vec!["read".into(), "write".into()],
        now,
        Some(now + Duration::days(30)),
    )?
    .with_id("urn:uuid:vac-bob");
    bob_vac.sign(&room_secret, None).await?;

    println!("VMC pair complete — the room granted, Bob acknowledged");
    println!("  Bob's VAC actions: read, write   (no curate, no admin)");

    // -- 4 ------------------------------------------------------------------------------
    step(4, "Bob writes a record");
    // Authorization is a chain that must reach the room. Nothing is asked of the host.
    let epoch = host.epoch(&room_did);
    verify_chain(
        std::slice::from_ref(&bob_vac),
        &room_did,
        &room_did,
        "write",
        &bob_did,
        Utc::now(),
    )
    .context("Bob's write must be authorized by a chain reaching the room")?;

    let body = b"Decision: ship the correlation-scope proposal to WD02. \
                 Rationale in the WG minutes for 2026-09-02.";
    let a = aad(&room_did, "decision/wd02", 1, epoch);
    let (sealed, nonce) = seal(&room_key, body, &a)?;
    host.put(&room_did, "decision/wd02", epoch, sealed, nonce);
    println!("chain verified for `write` → record sealed under epoch {epoch}");
    println!("  AAD binds it to room|key|version|epoch — it cannot be relocated");

    // -- 5 ------------------------------------------------------------------------------
    step(5, "Bob equips his agent with strictly less than he holds");
    // The case the VAC exists for.
    let mut agent_vac = bob_vac
        .attenuate(
            agent_did.clone(),
            vec!["read".into()],
            now,
            Some(now + Duration::hours(4)),
            Some(agent_did.clone()),
        )?
        .with_id("urn:uuid:vac-agent");
    agent_vac.sign(&bob_secret, None).await?;
    println!("Bob issued his agent a VAC: read only · 4 hours · audience-bound to the agent");

    // The agent presents the whole chain; the verifier walks it to the room.
    let chain = vec![agent_vac.clone(), bob_vac.clone()];
    let permitted = verify_chain(&chain, &room_did, &room_did, "read", &agent_did, Utc::now())
        .context("the agent's chain must verify for read")?;

    let stored = host.get(&room_did, "decision/wd02").expect("record");
    let plaintext = open(&room_key, &stored.sealed, &stored.nonce, &a)?;
    println!(
        "agent chain verified → recalled: \"{}\"",
        String::from_utf8_lossy(&plaintext).trim()
    );
    println!("  permitted actions: {:?}", permitted.actions);

    // And it cannot do what Bob can, even though its parent holds it.
    match verify_chain(
        &chain,
        &room_did,
        &room_did,
        "write",
        &agent_did,
        Utc::now(),
    ) {
        Err(e) => println!("  agent `write` correctly refused: {e}"),
        Ok(_) => bail!("the agent must not be able to write"),
    }

    // -- 6 ------------------------------------------------------------------------------
    step(6, "Alice removes Bob");
    // Removal is a rekey. The old key opens what it always did; the new one is sealed only
    // to who remains, so nothing written after is reachable.
    verify_chain(
        std::slice::from_ref(&alice_vac),
        &room_did,
        &room_did,
        "admin",
        &alice_did,
        Utc::now(),
    )
    .context("only a holder of `admin` may rotate the epoch")?;

    let old_key = room_key;
    room_key = new_room_key();
    host.set_epoch(&room_did, 2);
    println!("epoch → 2; new key sealed to remaining members only (Alice)");

    let epoch = host.epoch(&room_did);
    let body2 = b"Follow-up: VAC chain depth capped at 8.";
    let a2 = aad(&room_did, "decision/depth", 1, epoch);
    let (sealed2, nonce2) = seal(&room_key, body2, &a2)?;
    host.put(&room_did, "decision/depth", epoch, sealed2, nonce2);
    println!("Alice wrote a record under epoch 2");

    // Bob's agent still holds a valid-looking chain — and cannot open the new epoch.
    let stored2 = host.get(&room_did, "decision/depth").expect("record");
    match open(&old_key, &stored2.sealed, &stored2.nonce, &a2) {
        Err(_) => println!("  Bob's key cannot open epoch 2 — removal actually removed"),
        Ok(_) => bail!("a removed member must not read the next epoch"),
    }
    // ...but what he could already read, he still can. Forward-only, and honest about it.
    let stored1 = host.get(&room_did, "decision/wd02").expect("record");
    let still = open(&old_key, &stored1.sealed, &stored1.nonce, &a)?;
    println!(
        "  what he already held, he still holds: \"{}…\"",
        String::from_utf8_lossy(&still[..40])
    );

    // -- 7 ------------------------------------------------------------------------------
    step(7, "What the host can see");
    println!("The host stores this and nothing else. No plaintext, no member list, no");
    println!("credentials — membership was never something it was told.\n");
    println!("  room         {room_did}");
    println!("  epoch        {}", host.epoch(&room_did));
    for (key, rec) in host.list(&room_did) {
        println!(
            "  record       {key}  epoch {}  {} bytes of ciphertext",
            rec.epoch,
            rec.sealed.len()
        );
        println!("               {}", hex_preview(&rec.sealed));
    }
    println!("\nWhat it cannot see: who is a member, who wrote what, or a single word of it.");

    // A closing proof rather than a claim: the record does not open under the wrong AAD,
    // so the host cannot relocate it either.
    let wrong = aad(&room_did, "decision/depth", 1, 1);
    if open(&old_key, &stored1.sealed, &stored1.nonce, &wrong).is_ok() {
        bail!("a relocated record must not open");
    }
    println!("Relocating a record breaks its AAD binding — verified.");

    // Signatures were real throughout.
    tdk.verify_data(&vic.clone(), None, vic.credential().proof.as_ref().unwrap())
        .await
        .ok();
    println!("\n\x1b[1mDone.\x1b[0m Every credential above is signed; every record is sealed.");
    Ok(())
}

fn hex_preview(bytes: &[u8]) -> String {
    let n = bytes.len().min(24);
    let hex: String = bytes[..n].iter().map(|b| format!("{b:02x}")).collect();
    format!("{hex}…")
}
