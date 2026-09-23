use frost::keys::Tweak;
use frost_core::keys::PublicKeyPackage;
use frost_secp256k1_tr as frost;
use rand::thread_rng;
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ---------------------------------------------------------
    // FROST SETUP
    // ---------------------------------------------------------
    //
    // We are creating a 2-of-3 threshold group:
    //
    // 3 participants:
    //     Alice -> ID 1
    //     Bob   -> ID 2
    //     Carol -> ID 3
    //
    // Threshold:
    //     At least 2 participants are required to sign.
    //

    let max_signers = 3;
    let min_signers = 2;

    // FROST identifiers distinguish the participants.
    // They are NOT private keys.
    //
    // We can mentally think of:
    //     ID 1 -> Alice
    //     ID 2 -> Bob
    //     ID 3 -> Carol
    //
    let alice = frost::Identifier::try_from(1u16)?;
    let bob = frost::Identifier::try_from(2u16)?;
    let carol = frost::Identifier::try_from(3u16)?;

    // Secure randomness is needed when generating
    // cryptographic secret material.
    let mut rng = thread_rng();

    // =========================================================
    // DKG ROUND 1
    // =========================================================
    //
    // DKG = Distributed Key Generation.
    //
    // The goal of DKG is to let Alice, Bob, and Carol
    // collaboratively create:
    //
    //     Alice -> private signing share
    //     Bob   -> private signing share
    //     Carol -> private signing share
    //
    //     +
    //
    //     ONE shared group public key Y
    //
    // There is NO trusted dealer here.
    // Each participant starts their own part of the protocol.
    //

    // part1() gives Alice:
    //     alice_secret_package -> Alice keeps this private
    //     alice_public         -> shared with other participants
    //
    let (alice_secret_package, alice_public) =
        frost::keys::dkg::part1(alice, max_signers, min_signers, &mut rng)?;

    // Bob does the same thing independently.
    let (bob_secret_package, bob_public) =
        frost::keys::dkg::part1(bob, max_signers, min_signers, &mut rng)?;

    // Carol does the same thing independently.
    let (carol_secret_package, carol_public) =
        frost::keys::dkg::part1(carol, max_signers, min_signers, &mut rng)?;

    println!("Alice has her secret package.");
    println!("Bob has his secret package.");
    println!("Carol has her secret package.");

    // ---------------------------------------------------------
    // ROUND 1 PUBLIC PACKAGES
    // ---------------------------------------------------------
    //
    // Each participant has ONE public package containing protocol data.
    // Secret packages NEVER get shared.
    //
    // We use a BTreeMap here to simulate network transmission:
    //     ID 1 -> Alice's public package
    //     ID 2 -> Bob's public package
    //     ID 3 -> Carol's public package
    //

    let mut round1_packages = BTreeMap::new();

    round1_packages.insert(alice, alice_public);
    round1_packages.insert(bob, bob_public);
    round1_packages.insert(carol, carol_public);

    println!("\nRound 1 public packages:");

    for (identifier, package) in &round1_packages {
        println!("Participant {identifier:?}:");
        println!("{package:#?}");
    }

    // ---------------------------------------------------------
    // SIMULATE ROUND 1 PACKAGE EXCHANGE
    // ---------------------------------------------------------
    //
    // Each participant collects public packages from their peers.
    //
    let alice_received = BTreeMap::from([
        (bob, round1_packages[&bob].clone()),
        (carol, round1_packages[&carol].clone()),
    ]);

    let bob_received = BTreeMap::from([
        (alice, round1_packages[&alice].clone()),
        (carol, round1_packages[&carol].clone()),
    ]);

    let carol_received = BTreeMap::from([
        (alice, round1_packages[&alice].clone()),
        (bob, round1_packages[&bob].clone()),
    ]);

    // =========================================================
    // DKG ROUND 2
    // =========================================================
    //
    // Each participant combines their own Round 1 secret package
    // with the peer public packages to create Round 2 state +
    // targeted packages for each participant.
    //
    let (alice_round2_secret, alice_round2_packages) =
        frost::keys::dkg::part2(alice_secret_package, &alice_received)?;

    let (bob_round2_secret, bob_round2_packages) =
        frost::keys::dkg::part2(bob_secret_package, &bob_received)?;

    let (carol_round2_secret, carol_round2_packages) =
        frost::keys::dkg::part2(carol_secret_package, &carol_received)?;

    println!("\n=== DKG ROUND 2 ===");

    println!("Alice created packages for:");
    for identifier in alice_round2_packages.keys() {
        println!("  Alice -> {identifier:?}");
    }

    println!("Bob created packages for:");
    for identifier in bob_round2_packages.keys() {
        println!("  Bob -> {identifier:?}");
    }

    println!("Carol created packages for:");
    for identifier in carol_round2_packages.keys() {
        println!("  Carol -> {identifier:?}");
    }

    // ---------------------------------------------------------
    // SIMULATE ROUND 2 PACKAGE EXCHANGE
    // ---------------------------------------------------------
    //
    // These packages are targeted specifically per participant recipient.

    let alice_round2_received = BTreeMap::from([
        (bob, bob_round2_packages[&alice].clone()),
        (carol, carol_round2_packages[&alice].clone()),
    ]);

    let bob_round2_received = BTreeMap::from([
        (alice, alice_round2_packages[&bob].clone()),
        (carol, carol_round2_packages[&bob].clone()),
    ]);

    let carol_round2_received = BTreeMap::from([
        (alice, alice_round2_packages[&carol].clone()),
        (bob, bob_round2_packages[&carol].clone()), // FIXED: Carol gets the share Bob sent to Carol
    ]);

    // =========================================================
    // DKG PART 3
    // =========================================================
    //
    // Finalizing DKG. Notice that `frost_secp256k1_tr` internally applies
    // BIP-340/341 Taproot key tweaking during finalization.
    //
    let (alice_key_package, alice_pubkey_package) = frost::keys::dkg::part3(
        &alice_round2_secret,
        &alice_received,
        &alice_round2_received,
    )?;

    let (bob_key_package, bob_pubkey_package) =
        frost::keys::dkg::part3(&bob_round2_secret, &bob_received, &bob_round2_received)?;

    let (carol_key_package, carol_pubkey_package) = frost::keys::dkg::part3(
        &carol_round2_secret,
        &carol_received,
        &carol_round2_received,
    )?;

    // =========================================================
    // DKG COMPLETE
    // =========================================================

    println!("\n=== DKG COMPLETE ===");
    println!("Alice: final KeyPackage created");
    println!("Bob:   final KeyPackage created");
    println!("Carol: final KeyPackage created");

    println!("\nAll participants now have their own private signing share.");
    println!("The group has one shared public key.");

    // ---------------------------------------------------------
    // VERIFY THAT EVERYONE GOT THE SAME GROUP PUBLIC KEY
    // ---------------------------------------------------------

    println!("\n=== GROUP PUBLIC KEY Y ===");
    println!("Alice: {:?}", alice_pubkey_package.verifying_key());
    println!("Bob:   {:?}", bob_pubkey_package.verifying_key());
    println!("Carol: {:?}", carol_pubkey_package.verifying_key());

    sign_message(
        &alice_key_package,
        &bob_key_package,
        &mut rng,
        &alice_pubkey_package,
    )?;

    create_taproot_address(&alice_pubkey_package)?;

    Ok(())
}

fn sign_message(
    alice_key_package: &frost::keys::KeyPackage,
    bob_key_package: &frost::keys::KeyPackage,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    alice_pubkey_package: &frost::keys::PublicKeyPackage,
) -> Result<(), Box<dyn std::error::Error>> {
    let message = b"Hello FROST";

    // =========================================================
    // SIGNING ROUND 1
    // =========================================================

    let (alice_nonces, alice_commitments) =
        frost::round1::commit(alice_key_package.signing_share(), rng);

    let (bob_nonces, bob_commitments) = frost::round1::commit(bob_key_package.signing_share(), rng);

    println!("Alice created her signing nonces and commitments.");
    println!("Bob created his signing nonces and commitments.");

    // ---------------------------------------------------------
    // CREATE THE SIGNING PACKAGE
    // ---------------------------------------------------------

    let mut commitments = BTreeMap::new();
    commitments.insert(alice_key_package.identifier().clone(), alice_commitments);
    commitments.insert(bob_key_package.identifier().clone(), bob_commitments);

    let signing_package = frost::SigningPackage::new(commitments, message);

    // =========================================================
    // SIGNING ROUND 2
    // =========================================================

    let alice_signature_share =
        frost::round2::sign(&signing_package, &alice_nonces, alice_key_package)?;

    let bob_signature_share = frost::round2::sign(&signing_package, &bob_nonces, bob_key_package)?;

    println!("\n=== SIGNING ROUND 2 ===");
    println!("Alice created her signature share.");
    println!("Bob created his signature share.");

    // ---------------------------------------------------------
    // COLLECT THE SIGNATURE SHARES
    // ---------------------------------------------------------

    let mut signature_shares = BTreeMap::new();
    signature_shares.insert(
        alice_key_package.identifier().clone(),
        alice_signature_share,
    );
    signature_shares.insert(bob_key_package.identifier().clone(), bob_signature_share);

    // =========================================================
    // AGGREGATION
    // =========================================================

    let group_signature =
        frost::aggregate(&signing_package, &signature_shares, &alice_pubkey_package)?;

    println!("\n=== FINAL GROUP SIGNATURE ===");
    println!("{group_signature:#?}");

    // =========================================================
    // VERIFY THE FINAL SIGNATURE
    // =========================================================

    alice_pubkey_package
        .verifying_key()
        .verify(message, &group_signature)?;

    println!("Signature verified successfully!");

    Ok(())
}

fn create_taproot_address(
    pubkey_package: &frost::keys::PublicKeyPackage,
) -> Result<(), Box<dyn std::error::Error>> {
    // ---------------------------------------------------------
    // TAPROOT TWEAK DISTINCTION (WALKTHROUGH NOTE):
    // ---------------------------------------------------------
    // In standard Bitcoin Taproot development (e.g., using rust-bitcoin),
    // an internal public key P must be tweaked with a script tree merkle root
    // or an unspendable script hash to produce the final output key Q = P + t*G.
    //
    // However, in FROST using `frost_secp256k1_tr`:
    // 1. The ciphersuite handles Taproot tweaking natively during key generation.
    // 2. `pubkey_package.verifying_key()` returns the key AFTER it has already
    //    been tweaked under the hood (BIP-341 Taproot Key-Path tweaking).
    //
    // Therefore, we MUST NOT re-tweak this key in `rust-bitcoin`.

    let frost_key_bytes = pubkey_package.verifying_key().serialize()?;

    // Deserialize into rust-bitcoin's secp256k1 PublicKey type.
    let bitcoin_pubkey = bitcoin::secp256k1::PublicKey::from_slice(&frost_key_bytes)?;

    // Extract the 32-byte x-only key representation mandated by BIP-340/341 Taproot.
    let (x_only_key, _parity) = bitcoin_pubkey.x_only_public_key();

    println!("\n=== FROST TAPROOT OUTPUT KEY ===");
    println!("{x_only_key}");

    // Because `frost_secp256k1_tr` already applied the Taproot tweak to the
    // internal group key during DKG, `x_only_key` is already Q (the output key).
    // We explicitly call `dangerous_assume_tweaked` to instruct `rust-bitcoin`
    // NOT to apply a second Taproot tweak.
    let output_key = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(x_only_key);

    // Build the P2TR address directly using the pre-tweaked output key.
    let address = bitcoin::Address::p2tr_tweaked(output_key, bitcoin::address::KnownHrp::Regtest);

    println!("\n=== TAPROOT ADDRESS ===");
    println!("{address}");

    Ok(())
}
