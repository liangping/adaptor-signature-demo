use musig2::{AdaptorSignature, KeyAggContext, PartialSignature};
use secp::{MaybeScalar, Point, Scalar};

use musig2::{AggNonce, SecNonce};
fn main() {
    // the borrower: Bob
    let sec_b = Scalar::from_slice(&[0x11; 32]).unwrap();
    let pubkey_b = sec_b.base_point_mul();

    // the DCA
    let sec_dca = Scalar::from_slice(&[0x22; 32]).unwrap();
    let pubkey_dca = sec_dca.base_point_mul();

    // the vault of Bob and DCA
    let key_agg_ctx = KeyAggContext::new([pubkey_b, pubkey_dca]).unwrap();
    let aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();

    // the borrower now can fund the vault with a short time lock (24h).
    // therefore if the DCA dose not collabrate in time, the borrower can withdraw the collateral back.

    // when funding is completed, Bob can initial a loanj
    // Bob randomly pick a secret: `t` as hash lock and create CETs.
    // 1. Liquidated tx, let's skip it here.
    // 2. Loan ends tx, the recipient is the DCA and unlock condition is a hash time lock: ("hash of t" + "loan duration" )
    // so, when loan ends, the DCA can individually move the collateral to his own address if the secret `t` is revealed.

    let adaptor_secret = Scalar::random(&mut rand::thread_rng());
    let adaptor_point = adaptor_secret.base_point_mul(); // send to DCA: T of t

    // Each party generated a nonce for a loan. protect the real priv_key.
    let nonce_b = SecNonce::build([0x23; 32]).build();
    let nonce_dca = SecNonce::build([0x45; 32]).build();

    // share the public nonce to each other and compute aggnonce
    let aggregated_nonce = AggNonce::sum([nonce_b.public_nonce(), nonce_dca.public_nonce()]);

    let message = "preimage of the loan";

    // bob send the partial signature to side chain
    let bob_partial_signature: PartialSignature = musig2::adaptor::sign_partial(
        &key_agg_ctx,
        sec_b.clone(),
        nonce_b.clone(),
        &aggregated_nonce,
        adaptor_point,
        message,
    )
    .unwrap();

    // verify if Bob's signature before DCA signing.
    musig2::adaptor::verify_partial(
        &key_agg_ctx,
        bob_partial_signature,
        &aggregated_nonce,
        adaptor_point.clone(),
        pubkey_b.clone(),
        &nonce_b.public_nonce(),
        message,
    )
    .expect("Bob's partial signature is invalid.");

    let dca_partial_signature: PartialSignature = musig2::adaptor::sign_partial(
        &key_agg_ctx,
        sec_dca,
        nonce_dca,
        &aggregated_nonce,
        adaptor_point,
        message,
    )
    .unwrap();

    // combine all partial signatures and submit to lending contract
    let adaptor_signature: AdaptorSignature = musig2::adaptor::aggregate_partial_signatures(
        &key_agg_ctx,
        &aggregated_nonce,
        adaptor_point,
        [bob_partial_signature, dca_partial_signature],
        &message,
    )
    .expect("failed to aggregate partial adaptor signatures");

    // Verify if the adaptor signature is valid for the given adaptor point and pubkey on side chain
    musig2::adaptor::verify_single(
        aggregated_pubkey,
        &adaptor_signature,
        &message,
        adaptor_point,
    )
    .expect("invalid aggregated adaptor signature");

    // Bob decrypt the signature with the adaptor secret,
    // and submit it to side chain to claim funds from the lending pool
    // if Bob dese not decrypt, nothing will happen.
    let valid_signature = adaptor_signature.adapt(adaptor_secret).unwrap();

    musig2::verify_single(aggregated_pubkey, valid_signature, &message)
        .expect("invalid decrypted adaptor signature");

    // if valid, lending pool send funds to borrower. otherwise rejected

    // The decrypted signature and the adaptor signature allow an
    // observer to deduce the adaptor secret.
    let revealed: MaybeScalar = adaptor_signature
        .reveal_secret(&valid_signature)
        .expect("should compute adaptor secret from decrypted signature");

    assert_eq!(revealed, MaybeScalar::Valid(adaptor_secret));
    println!(
        "{:?}\n {:?}",
        revealed.serialize(),
        adaptor_secret.serialize()
    );

    // DCA can withdraw the BTC collateral with revealed secret only when time lock is expired.

    // =================
    // -   Repayment   -
    // =================

    // Bob send USDC into a pending pool of lending contract.
    // the USDC is locked by hash or Bob's secret.
    // It can be sent to lending pool only when the secret is revealed.
    let repayment_secret = Scalar::random(&mut rand::thread_rng());
    let repayment_adaptor_point = repayment_secret.base_point_mul(); // send to DCA: T of t

    // Each party generated a nonce for a repayment. protect the real priv_key.
    let nonce_b = SecNonce::build([0x23; 32]).build();
    let nonce_dca = SecNonce::build([0x45; 32]).build();

    // share the public nonce to each other and compute aggnonce
    let aggregated_nonce = AggNonce::sum([nonce_b.public_nonce(), nonce_dca.public_nonce()]);

    let message = "txid of repayment tx";

    // bob send the partial signature to side chain
    let bob_partial_signature: PartialSignature = musig2::adaptor::sign_partial(
        &key_agg_ctx,
        sec_b.clone(),
        nonce_b.clone(),
        &aggregated_nonce,
        repayment_adaptor_point,
        message,
    )
    .unwrap();

    // verify if Bob's signature before DCA signing.
    musig2::adaptor::verify_partial(
        &key_agg_ctx,
        bob_partial_signature,
        &aggregated_nonce,
        repayment_adaptor_point.clone(),
        pubkey_b.clone(),
        &nonce_b.public_nonce(),
        message,
    )
    .expect("Bob's partial signature is invalid.");

    let dca_partial_signature: PartialSignature = musig2::adaptor::sign_partial(
        &key_agg_ctx,
        sec_dca,
        nonce_dca,
        &aggregated_nonce,
        repayment_adaptor_point,
        message,
    )
    .unwrap();

    // combine all partial signatures and submit to lending contract
    let adaptor_signature: AdaptorSignature = musig2::adaptor::aggregate_partial_signatures(
        &key_agg_ctx,
        &aggregated_nonce,
        repayment_adaptor_point,
        [bob_partial_signature, dca_partial_signature],
        &message,
    )
    .expect("failed to aggregate partial adaptor signatures");

    // Verify the adaptor signature is valid for the given adaptor point and pubkey on side chain
    musig2::adaptor::verify_single(
        aggregated_pubkey,
        &adaptor_signature,
        &message,
        repayment_adaptor_point,
    )
    .expect("invalid aggregated adaptor signature");

    // Bob decrypt the signature with the adaptor secret,
    // and submit it to bitcoin to claim the collateral from the vault
    // if Bob dese not decrypt, nothing will happen.
    let valid_signature = adaptor_signature.adapt(repayment_secret).unwrap();

    musig2::verify_single(aggregated_pubkey, valid_signature, &message)
        .expect("invalid decrypted adaptor signature");

    // if valid, repayment transaction is accepted on bitcoin. otherwise rejected

    // The decrypted signature and the adaptor signature allow an
    // observer to deduce the adaptor secret.
    let revealed: MaybeScalar = adaptor_signature
        .reveal_secret(&valid_signature)
        .expect("should compute adaptor secret from decrypted signature");

    assert_eq!(revealed, MaybeScalar::Valid(repayment_secret));
    println!(
        "{:?}\n {:?}",
        revealed.serialize(),
        repayment_secret.serialize()
    );

    // the USDC now can be move to lending pool with revealed key.
}
