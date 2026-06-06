//! This example shows how to:
//! 1. Create a credential
//! 2. Sign the credential
//! 3. Verify the credential
//!
//! This example uses the Affinidi Trust Development Kit (TDK) to demonstrate the process of
//! signing and verifying a credential.

use affinidi_tdk::{
    TDK,
    common::config::TDKConfig,
    dids::{DID, KeyType},
};
use anyhow::Result;
use chrono::Utc;
use dtg_credentials::DTGCredential;

#[tokio::main]
async fn main() -> Result<()> {
    // Instantiate the TDK
    // No environment needs to be loaded as this example is ephemeral
    let tdk = TDK::new(
        TDKConfig::builder().with_load_environment(false).build()?,
        None,
    )
    .await?;
    println!("TDK Instantiated");

    // Create a simple DID to represent the issuer
    let (issuer_did, issuer_secret) = DID::generate_did_key(KeyType::Ed25519)?;
    println!("Created issuer DID and Secrets: {issuer_did}");

    // Create a Persona Credential (VPC)
    let mut vpc = DTGCredential::new_vpc(
        issuer_did.clone(),
        "did:example:subject".to_string(),
        Utc::now(),
        None,
    );
    println!("*************************************************************************");
    println!(
        "Created unsigned Persona Credential:\n{}",
        serde_json::to_string_pretty(&vpc).unwrap()
    );
    println!();

    // Clone the unsigned VPC so that we can use it later to verify
    let unsigned_vpc = vpc.clone();

    // Sign the VPC Credential using the issuer's Secret
    let proof = vpc.sign(&issuer_secret, None).await?;
    println!("*************************************************************************");
    println!(
        "Signed the VPC:\n\n{}",
        serde_json::to_string_pretty(&vpc.credential().proof).unwrap()
    );
    println!();

    // verify the VPC Credential

    tdk.verify_data(&unsigned_vpc, None, &proof).await?;
    println!("*************************************************************************");
    println!("Successfully verified the Persona Credential");
    println!(
        "Full Credential:\n\n{}",
        serde_json::to_string_pretty(&vpc).unwrap()
    );
    println!();

    Ok(())
}
