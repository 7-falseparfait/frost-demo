use frost_secp256k1_tr as frost;
use rand::thread_rng;
use std::collections::BTreeMap;
// //TRUSTED DEALER KEY GENERATIONS
// fn main() -> Result<(), Box<dyn std::error::Error>> {
//     //Creating a FROST group with 3 participants
//     let max_signers = 3;
//     //This gives us 2 of 3 threshold. so at least 2 participants are required to sign
//     let min_signers = 2;
//     //There is a neeed for randomness to generate participant's secrets shares
//     let rng = thread_rng();
//     // Create the identifiers for the participants.
//     // With 3 participants, we can think of these as:
//     // ID 1 -> Alice
//     // ID 2 -> Bob
//     // ID 3 -> Carol
//     let identifiers = frost::keys::IdentifierList::Default;
//     // The trusted dealer generates:
//     // 1. A ecret signing share for each participant
//     // 2. One group public key for the whole FROST group
//     let (shares, group_public_key) =
//         frost::keys::generate_with_dealer(max_signers, min_signers, identifiers, rng)?;
//     println!("Group public key:");
//     println!("{group_public_key:#?}");

//     println!("\nParticipant shares:");
//     for (identifier, share) in shares {
//         println!("Participant {identifier:?}:");
//         println!("{share:#?}");
//     }
//     Ok(())
// }

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
    //
    // Each participant starts their own part of the protocol.
    //

    // part1() gives Alice:
    //
    //     alice_secret_package -> Alice keeps this private
    //     alice_public         -> shared with other participants
    //
    let (alice_secret_package, alice_public) =
        frost::keys::dkg::part1(alice, max_signers, min_signers, &mut rng)?;

    // Bob does the same thing independently.
    let (bob_secret_package, bob_public) =
        frost::keys::dkg::part1(bob, max_signers, min_signers, &mut rng)?;

    // Carol does the same thing independently.
    //
    // NOTE: this variable is named "carol_secret_package"
    // so that the name is consistent with Alice and Bob.
    let (carol_secret_package, carol_public) =
        frost::keys::dkg::part1(carol, max_signers, min_signers, &mut rng)?;

    println!("Alice has her secret package.");
    println!("Bob has his secret package.");
    println!("Carol has her secret package.");

    // ---------------------------------------------------------
    // ROUND 1 PUBLIC PACKAGES
    // ---------------------------------------------------------
    //
    // Each participant has ONE public package.
    //
    // These public packages are the protocol information
    // that gets shared with the other participants.
    //
    // Secret packages NEVER get shared.
    //
    // We use a BTreeMap here to simulate the communication:
    //
    //     ID 1 -> Alice's public package
    //     ID 2 -> Bob's public package
    //     ID 3 -> Carol's public package
    //
    // In a real system, these would be sent between devices.
    // Our single Rust program is just simulating that network.
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
    // Alice needs the public packages from Bob and Carol.
    //
    // Alice already has her own secret package, so she does
    // not need to send that anywhere.
    //
    // alice_received therefore contains:
    //
    //     Bob's ID   -> Bob's public package
    //     Carol's ID -> Carol's public package
    //
    let alice_received = BTreeMap::from([
        (bob, round1_packages[&bob].clone()),
        (carol, round1_packages[&carol].clone()),
    ]);

    // Bob receives Alice's and Carol's public packages.
    let bob_received = BTreeMap::from([
        (alice, round1_packages[&alice].clone()),
        (carol, round1_packages[&carol].clone()),
    ]);

    // Carol receives Alice's and Bob's public packages.
    let carol_received = BTreeMap::from([
        (alice, round1_packages[&alice].clone()),
        (bob, round1_packages[&bob].clone()),
    ]);

    // =========================================================
    // DKG ROUND 2
    // =========================================================
    //
    // Each participant now combines:
    //
    //     their own Round 1 secret package
    //             +
    //     the public packages received from their peers
    //
    // and runs part2().
    //
    // part2() produces:
    //
    //     1. New private Round 2 state
    //        -> kept by that participant
    //
    //     2. A BTreeMap of packages
    //        -> one package for EACH OTHER participant
    //
    // So Alice gets:
    //
    //     Alice's Round 2 secret state
    //
    //     ID 2 -> package for Bob
    //     ID 3 -> package for Carol
    //
    let (alice_round2_secret, alice_round2_packages) =
        frost::keys::dkg::part2(alice_secret_package, &alice_received)?;

    let (bob_round2_secret, bob_round2_packages) =
        frost::keys::dkg::part2(bob_secret_package, &bob_received)?;

    let (carol_round2_secret, carol_round2_packages) =
        frost::keys::dkg::part2(carol_secret_package, &carol_received)?;

    println!("\n=== DKG ROUND 2 ===");

    // Alice created one package for each of the OTHER participants.
    println!("Alice created packages for:");

    for identifier in alice_round2_packages.keys() {
        println!("  Alice -> {identifier:?}");
    }

    // Bob does the same.
    println!("Bob created packages for:");

    for identifier in bob_round2_packages.keys() {
        println!("  Bob -> {identifier:?}");
    }

    // Carol does the same.
    println!("Carol created packages for:");

    for identifier in carol_round2_packages.keys() {
        println!("  Carol -> {identifier:?}");
    }

    // ---------------------------------------------------------
    // SIMULATE ROUND 2 PACKAGE EXCHANGE
    // ---------------------------------------------------------
    //
    // This time the packages are NOT one public package
    // broadcast to everyone.
    //
    // Each package is specifically intended for one participant.
    //
    // For example:
    //
    //     Alice -> Bob
    //     Alice -> Carol
    //
    // So Alice receives:
    //
    //     Bob's package intended for Alice
    //     Carol's package intended for Alice
    //
    let alice_round2_received = BTreeMap::from([
        (bob, bob_round2_packages[&alice].clone()),
        (carol, carol_round2_packages[&alice].clone()),
    ]);

    // Bob receives:
    //
    //     Alice's package intended for Bob
    //     Carol's package intended for Bob
    //
    let bob_round2_received = BTreeMap::from([
        (alice, alice_round2_packages[&bob].clone()),
        (carol, carol_round2_packages[&bob].clone()),
    ]);

    // Carol receives:
    //
    //     Alice's package intended for Carol
    //     Bob's package intended for Carol
    //
    let carol_round2_received = BTreeMap::from([
        (alice, alice_round2_packages[&carol].clone()),
        (bob, bob_round2_packages[&carol].clone()),
    ]);

    // =========================================================
    // DKG PART 3
    // =========================================================
    //
    // Now each participant has:
    //
    //     their own Round 2 private state
    //             +
    //     the Round 1 information they received
    //             +
    //     the Round 2 packages they received
    //
    // part3() finishes the distributed key-generation process.
    //
    // Each participant gets:
    //
    //     KeyPackage
    //         -> contains their long-lived private signing share
    //
    //     PublicKeyPackage
    //         -> contains public information for the group,
    //            including the shared group public key Y
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
    //
    // We now have:
    //
    //     Alice -> her own private signing share
    //     Bob   -> his own private signing share
    //     Carol -> her own private signing share
    //
    //             +
    //
    //     ONE common group public key Y
    //
    // No participant ever needed to hold everybody else's
    // private signing share.
    //

    println!("\n=== DKG COMPLETE ===");

    println!("Alice: final KeyPackage created");
    println!("Bob:   final KeyPackage created");
    println!("Carol: final KeyPackage created");

    println!("\nAll participants now have their own private signing share.");
    println!("The group has one shared public key.");

    // ---------------------------------------------------------
    // VERIFY THAT EVERYONE GOT THE SAME GROUP PUBLIC KEY
    // ---------------------------------------------------------
    //
    // This is the Y we have been talking about.
    //
    // Alice, Bob, and Carol each have their own private share,
    // but they all end up with the SAME group public key.
    //

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

    Ok(())
}

fn sign_message(
    alice_key_package: &frost::keys::KeyPackage,
    bob_key_package: &frost::keys::KeyPackage,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    alice_pubkey_package: &frost::keys::PublicKeyPackage,
) -> Result<(), Box<dyn std::error::Error>> {
    // The message we want Alice and Bob to sign.
    //
    // FROST signs bytes, so the b"" prefix gives us a byte string.
    let message = b"Hello FROST";

    // =========================================================
    // SIGNING ROUND 1
    // =========================================================
    //
    // Alice and Bob are the two signers for this 2-of-3 group.
    //
    // Each signer uses:
    //     - their long-lived private signing share
    //     - fresh cryptographic randomness
    //
    // to create:
    //
    //     1. signing nonces     -> PRIVATE, keep secret
    //     2. signing commitments -> PUBLIC, share with others
    //
    // The nonces are only for this signing session and must
    // never be reused for another signature.
    //

    let (alice_nonces, alice_commitments) =
        frost::round1::commit(alice_key_package.signing_share(), rng);

    let (bob_nonces, bob_commitments) = frost::round1::commit(bob_key_package.signing_share(), rng);

    println!("Alice created her signing nonces and commitments.");
    println!("Bob created his signing nonces and commitments.");

    // ---------------------------------------------------------
    // CREATE THE SIGNING PACKAGE
    // ---------------------------------------------------------
    //
    // We collect the public commitments from the participants
    // who are signing this message.
    //
    // The map is:
    //
    //     Alice's ID -> Alice's commitment
    //     Bob's ID   -> Bob's commitment
    //
    // Then we combine those commitments with the message.
    //
    // The SigningPackage represents this particular signing
    // session: these signers, these commitments, this message.
    //

    let mut commitments = BTreeMap::new();

    commitments.insert(alice_key_package.identifier().clone(), alice_commitments);

    commitments.insert(bob_key_package.identifier().clone(), bob_commitments);

    let signing_package = frost::SigningPackage::new(commitments, message);

    // =========================================================
    // SIGNING ROUND 2
    // =========================================================
    //
    // Each signer now creates their signature share.
    //
    // Alice uses:
    //     - the SigningPackage
    //     - Alice's private nonces
    //     - Alice's KeyPackage
    //
    // Bob does the same with his own private data.
    //
    // A signature share is NOT the final signature.
    // It is that participant's contribution to the final
    // group signature for this specific message.
    //

    let alice_signature_share =
        frost::round2::sign(&signing_package, &alice_nonces, alice_key_package)?;

    let bob_signature_share = frost::round2::sign(&signing_package, &bob_nonces, bob_key_package)?;

    println!("\n=== SIGNING ROUND 2 ===");
    println!("Alice created her signature share.");
    println!("Bob created his signature share.");

    // ---------------------------------------------------------
    // COLLECT THE SIGNATURE SHARES
    // ---------------------------------------------------------
    //
    // We put the signature shares into a BTreeMap so the
    // protocol can associate each share with its participant.
    //
    //     Alice's ID -> Alice's signature share
    //     Bob's ID   -> Bob's signature share
    //

    let mut signature_shares = BTreeMap::new();

    signature_shares.insert(
        alice_key_package.identifier().clone(),
        alice_signature_share,
    );

    signature_shares.insert(bob_key_package.identifier().clone(), bob_signature_share);

    // =========================================================
    // AGGREGATION
    // =========================================================
    //
    // The individual signature shares are now combined into
    // ONE final Schnorr signature for the message.
    //
    // The PublicKeyPackage contains the group's public
    // verification information, including the group public key Y.
    //

    let group_signature =
        frost::aggregate(&signing_package, &signature_shares, &alice_pubkey_package)?;

    println!("\n=== FINAL GROUP SIGNATURE ===");
    println!("{group_signature:#?}");

    // =========================================================
    // VERIFY THE FINAL SIGNATURE
    // =========================================================
    //
    // The PublicKeyPackage gives us the group verifying key Y:
    //
    //     alice_pubkey_package.verifying_key()
    //
    // We then verify:
    //
    //     message + final signature + Y
    //
    // If verification succeeds, the signature is valid for
    // this exact message under the FROST group public key.
    //

    alice_pubkey_package
        .verifying_key()
        .verify(message, &group_signature)?;

    println!("Signature verified successfully!");

    Ok(())
}
