use bitcoin::{
    Address,
    address::KnownHrp,
    key::TapTweak,
    secp256k1::{Keypair, Secp256k1, SecretKey},
};

fn main() {
    let secp = Secp256k1::new();

    // Demo-only secret key.
    // NEVER use a hard-coded key for real Bitcoin.
    let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();

    let keypair = Keypair::from_secret_key(&secp, &secret_key);

    // This is our Taproot internal key P.
    let (internal_key, _parity) = keypair.x_only_public_key();

    println!("=== INTERNAL KEY P ===");
    println!("{internal_key}");

    // Key-path-only Taproot:
    // no script tree, so the merkle root is None.
    let (output_key, _parity) = internal_key.tap_tweak(&secp, None);

    println!("\n=== OUTPUT KEY Q ===");
    println!("{output_key}");

    let address = Address::p2tr_tweaked(output_key, KnownHrp::Regtest);

    println!("\n=== TAPROOT ADDRESS ===");
    println!("{address}");
}
