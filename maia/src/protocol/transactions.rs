use crate::protocol::sighash_ext::SigHashExt;
use crate::protocol::txin_ext::TxInExt;
use crate::protocol::{commit_descriptor, compute_adaptor_pk, lock_descriptor};
use anyhow::{bail, Context, Result};
use bdk::bitcoin::util::psbt::PartiallySignedTransaction;
use bdk::bitcoin::util::sighash::SighashCache;
use bdk::bitcoin::{
    Address, Amount, EcdsaSig, EcdsaSighashType, OutPoint, PublicKey, Sighash, Transaction, TxIn,
    TxOut, XOnlyPublicKey,
};
use bdk::descriptor::Descriptor;
use bdk::miniscript::DescriptorTrait;
use itertools::Itertools;
use maia_core::{Payout, TransactionExt, DUMMY_2OF2_MULTISIG};
use secp256k1_zkp::{self, EcdsaAdaptorSignature, SecretKey, SECP256K1};
use std::collections::HashMap;
use std::iter::FromIterator;
use std::num::NonZeroU8;

/// In satoshi per vbyte.
const SATS_PER_VBYTE: f64 = 1.0;

pub(crate) fn lock_transaction(
    maker_psbt: PartiallySignedTransaction,
    taker_psbt: PartiallySignedTransaction,
    maker_pk: PublicKey,
    taker_pk: PublicKey,
    amount: Amount,
) -> PartiallySignedTransaction {
    let lock_descriptor = lock_descriptor(maker_pk, taker_pk);

    let maker_change = maker_psbt
        .unsigned_tx
        .output
        .into_iter()
        .filter(|out| {
            out.script_pubkey != DUMMY_2OF2_MULTISIG.parse().expect("To be a valid script")
        })
        .collect::<Vec<_>>();

    let taker_change = taker_psbt
        .unsigned_tx
        .output
        .into_iter()
        .filter(|out| {
            out.script_pubkey != DUMMY_2OF2_MULTISIG.parse().expect("To be a valid script")
        })
        .collect::<Vec<_>>();

    let lock_output = TxOut {
        value: amount.as_sat(),
        script_pubkey: lock_descriptor.script_pubkey(),
    };

    let input = vec![maker_psbt.unsigned_tx.input, taker_psbt.unsigned_tx.input].concat();

    let output = std::iter::once(lock_output)
        .chain(maker_change)
        .chain(taker_change)
        .collect();

    let lock_tx = Transaction {
        version: 2,
        lock_time: 0,
        input,
        output,
    };

    PartiallySignedTransaction {
        unsigned_tx: lock_tx,
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        inputs: vec![maker_psbt.inputs, taker_psbt.inputs].concat(),
        outputs: vec![maker_psbt.outputs, taker_psbt.outputs].concat(),
        unknown: Default::default(),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CommitTransaction {
    inner: Transaction,
    descriptor: Descriptor<PublicKey>,
    amount: Amount,
    sighash: Sighash,
    fee: Fee,
}

impl CommitTransaction {
    /// Expected size of signed transaction in virtual bytes, plus a
    /// buffer to account for different signature lengths.
    const SIGNED_VBYTES: f64 = 148.5 + (3.0 * 2.0) / 4.0;

    pub(crate) fn new(
        lock_tx: &Transaction,
        (maker_pk, maker_rev_pk, maker_publish_pk): (PublicKey, PublicKey, PublicKey),
        (taker_pk, taker_rev_pk, taker_publish_pk): (PublicKey, PublicKey, PublicKey),
        fee_rate: u32,
    ) -> Result<Self> {
        let lock_descriptor = lock_descriptor(maker_pk, taker_pk);
        let (lock_outpoint, lock_amount) = {
            let outpoint = lock_tx
                .outpoint(&lock_descriptor.script_pubkey())
                .context("lock script not found in lock tx")?;
            let amount = lock_tx.output[outpoint.vout as usize].value;

            (outpoint, amount)
        };

        let lock_input = TxIn {
            previous_output: lock_outpoint,
            ..Default::default()
        };

        let descriptor = commit_descriptor(
            (maker_pk, maker_rev_pk, maker_publish_pk),
            (taker_pk, taker_rev_pk, taker_publish_pk),
        );

        let output = TxOut {
            value: lock_amount,
            script_pubkey: descriptor.script_pubkey(),
        };

        let mut inner = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![lock_input],
            output: vec![output],
        };
        let fee = Fee::new(Self::SIGNED_VBYTES, fee_rate as f64);

        let commit_tx_amount = lock_amount - fee.as_u64();
        inner.output[0].value = commit_tx_amount;

        let sighash = SighashCache::new(&inner).segwit_signature_hash(
            0,
            &lock_descriptor.script_code()?,
            lock_amount,
            EcdsaSighashType::All,
        )?;

        Ok(Self {
            inner,
            descriptor,
            amount: Amount::from_sat(commit_tx_amount),
            sighash,
            fee,
        })
    }

    pub(crate) fn encsign(
        &self,
        sk: SecretKey,
        publish_them_pk: &PublicKey,
    ) -> EcdsaAdaptorSignature {
        EcdsaAdaptorSignature::encrypt(
            SECP256K1,
            &self.sighash.to_message(),
            &sk,
            &publish_them_pk.inner,
        )
    }

    pub(crate) fn into_inner(self) -> Transaction {
        self.inner
    }

    fn outpoint(&self) -> OutPoint {
        self.inner
            .outpoint(&self.descriptor.script_pubkey())
            .expect("to find commit output in commit tx")
    }

    fn amount(&self) -> Amount {
        self.amount
    }

    fn descriptor(&self) -> Descriptor<PublicKey> {
        self.descriptor.clone()
    }

    fn fee(&self) -> u64 {
        self.fee.as_u64()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ContractExecutionTransaction {
    inner: Transaction,
    index_nonce_pairs: Vec<(NonZeroU8, XOnlyPublicKey)>,
    sighash: Sighash,
}

impl ContractExecutionTransaction {
    /// Expected size of signed transaction in virtual bytes, plus a
    /// buffer to account for different signature lengths.
    const SIGNED_VBYTES: f64 = 206.5 + (3.0 * 2.0) / 4.0;

    pub(crate) fn new(
        commit_tx: &CommitTransaction,
        payout: Payout,
        maker_address: &Address,
        taker_address: &Address,
        nonce_pks: &[XOnlyPublicKey],
        relative_timelock_in_blocks: u32,
    ) -> Result<Self> {
        let index_nonce_pairs: Vec<_> = payout
            .digits()
            .to_indices()
            .into_iter()
            .zip(nonce_pks.iter().cloned())
            .collect();

        let commit_input = TxIn {
            previous_output: commit_tx.outpoint(),
            sequence: relative_timelock_in_blocks,
            ..Default::default()
        };

        let fee = Fee::new_with_default_rate(Self::SIGNED_VBYTES).add(commit_tx.fee() as f64);
        let output = fee
            .subtract_fee(
                maker_address.script_pubkey().dust_value(),
                taker_address.script_pubkey().dust_value(),
                payout.into(),
            )?
            .into_txouts(maker_address, taker_address);

        let tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![commit_input],
            output,
        };

        let sighash = SighashCache::new(&tx).segwit_signature_hash(
            0,
            &commit_tx.descriptor.script_code()?,
            commit_tx.amount.as_sat(),
            EcdsaSighashType::All,
        )?;

        Ok(Self {
            inner: tx,
            index_nonce_pairs,
            sighash,
        })
    }

    pub(crate) fn encsign(
        &self,
        sk: SecretKey,
        oracle_pk: &XOnlyPublicKey,
    ) -> Result<EcdsaAdaptorSignature> {
        let adaptor_point = compute_adaptor_pk(oracle_pk, &self.index_nonce_pairs)?;

        Ok(EcdsaAdaptorSignature::encrypt(
            SECP256K1,
            &self.sighash.to_message(),
            &sk,
            &adaptor_point,
        ))
    }

    pub(crate) fn into_inner(self) -> Transaction {
        self.inner
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RefundTransaction {
    inner: Transaction,
    sighash: Sighash,
}

impl RefundTransaction {
    /// Expected size of signed transaction in virtual bytes, plus a
    /// buffer to account for different signature lengths.
    const SIGNED_VBYTES: f64 = 206.5 + (3.0 * 2.0) / 4.0;

    pub(crate) fn new(
        commit_tx: &CommitTransaction,
        relative_locktime_in_blocks: u32,
        maker_address: &Address,
        taker_address: &Address,
        maker_amount: Amount,
        taker_amount: Amount,
    ) -> Result<Self> {
        let commit_input = TxIn {
            previous_output: commit_tx.outpoint(),
            sequence: relative_locktime_in_blocks,
            ..Default::default()
        };

        let maker_output = TxOut {
            value: maker_amount.as_sat(),
            script_pubkey: maker_address.script_pubkey(),
        };

        let taker_output = TxOut {
            value: taker_amount.as_sat(),
            script_pubkey: taker_address.script_pubkey(),
        };

        let mut tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![commit_input],
            output: vec![maker_output, taker_output],
        };

        let mut fee = Self::SIGNED_VBYTES * SATS_PER_VBYTE;
        fee += commit_tx.fee() as f64;
        tx.output[0].value -= (fee / 2.0) as u64;
        tx.output[1].value -= (fee / 2.0) as u64;

        let sighash = SighashCache::new(&tx).segwit_signature_hash(
            0,
            &commit_tx.descriptor().script_code()?,
            commit_tx.amount().as_sat(),
            EcdsaSighashType::All,
        )?;

        Ok(Self { inner: tx, sighash })
    }

    pub(crate) fn sighash(&self) -> Sighash {
        self.sighash
    }

    pub(crate) fn into_inner(self) -> Transaction {
        self.inner
    }
}

/// Build a transaction which closes the CFD contract.
///
/// This transaction spends directly from the lock transaction. Both
/// parties must agree on the split of coins between `maker_amount`
/// and `taker_amount`.
pub fn close_transaction(
    lock_descriptor: &Descriptor<PublicKey>,
    lock_outpoint: OutPoint,
    lock_amount: Amount,
    (maker_address, maker_amount): (&Address, Amount),
    (taker_address, taker_amount): (&Address, Amount),
    fee_rate: u32,
) -> Result<(Transaction, secp256k1_zkp::Message)> {
    /// Expected size of signed transaction in virtual bytes, plus a
    /// buffer to account for different signature lengths.
    const SIGNED_VBYTES: f64 = 167.5 + (3.0 * 2.0) / 4.0;

    let lock_input = TxIn {
        previous_output: lock_outpoint,
        ..Default::default()
    };

    // TODO: The fee could take into account the network state in this
    // case, since this transaction is to be broadcast immediately
    // after building and signing it
    let fee = Fee::new(SIGNED_VBYTES, fee_rate as f64);

    let PayoutAmounts {
        maker_amount,
        taker_amount,
    } = fee.subtract_fee(
        maker_address.script_pubkey().dust_value(),
        taker_address.script_pubkey().dust_value(),
        PayoutAmounts {
            maker_amount,
            taker_amount,
        },
    )?;

    // We don't include ZERO outputs in the final transaction
    let mut output = vec![];
    if maker_amount > Amount::ZERO {
        output.push(TxOut {
            value: maker_amount.as_sat(),
            script_pubkey: maker_address.script_pubkey(),
        })
    };

    if taker_amount > Amount::ZERO {
        output.push(TxOut {
            value: taker_amount.as_sat(),
            script_pubkey: taker_address.script_pubkey(),
        })
    };

    let tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![lock_input],
        output,
    };

    let script_code = lock_descriptor.script_code()?;
    let sighash = SighashCache::new(&tx)
        .segwit_signature_hash(0, &script_code, lock_amount.as_sat(), EcdsaSighashType::All)?
        .to_message();

    Ok((tx, sighash))
}

pub fn punish_transaction(
    commit_descriptor: &Descriptor<PublicKey>,
    address: &Address,
    encsig: EcdsaAdaptorSignature,
    sk: SecretKey,
    revocation_them_sk: SecretKey,
    pub_them_pk: PublicKey,
    revoked_commit_tx: &Transaction,
) -> Result<Transaction> {
    /// Expected size of signed transaction in virtual bytes, plus a
    /// buffer to account for different signature lengths.
    const SIGNED_VBYTES: f64 = 219.5 + (3.0 * 3.0) / 4.0;

    let input = revoked_commit_tx
        .input
        .clone()
        .into_iter()
        .exactly_one()
        .context("commit transaction inputs != 1")?;

    let publish_them_sk = input
        .find_map_signature(|sig| encsig.recover(SECP256K1, &sig, &pub_them_pk.inner).ok())
        .context("could not recover publish sk from commit tx")?;

    let commit_outpoint = revoked_commit_tx
        .outpoint(&commit_descriptor.script_pubkey())
        .expect("to find commit output in commit tx");
    let commit_amount = revoked_commit_tx.output[commit_outpoint.vout as usize].value;

    let mut punish_tx = {
        let output = TxOut {
            value: commit_amount,
            script_pubkey: address.script_pubkey(),
        };
        let mut tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: commit_outpoint,
                ..Default::default()
            }],
            output: vec![output],
        };

        let fee = SIGNED_VBYTES * SATS_PER_VBYTE;
        tx.output[0].value = commit_amount - fee as u64;

        tx
    };

    let sighash = SighashCache::new(&punish_tx).segwit_signature_hash(
        0,
        &commit_descriptor.script_code()?,
        commit_amount,
        EcdsaSighashType::All,
    )?;

    let satisfier = {
        let pk = {
            let inner = secp256k1_zkp::PublicKey::from_secret_key(SECP256K1, &sk);
            PublicKey {
                compressed: true,
                inner,
            }
        };
        let pk_hash = pk.pubkey_hash().as_hash();
        let sig_sk = SECP256K1.sign_ecdsa(&sighash.to_message(), &sk);

        let pub_them_pk_hash = pub_them_pk.pubkey_hash().as_hash();
        let sig_pub_them = SECP256K1.sign_ecdsa(&sighash.to_message(), &publish_them_sk);

        let rev_them_pk = {
            let inner = secp256k1_zkp::PublicKey::from_secret_key(SECP256K1, &revocation_them_sk);
            PublicKey {
                compressed: true,
                inner,
            }
        };
        let rev_them_pk_hash = rev_them_pk.pubkey_hash().as_hash();
        let sig_rev_them = SECP256K1.sign_ecdsa(&sighash.to_message(), &revocation_them_sk);
        HashMap::from_iter(vec![
            (
                pk_hash,
                (
                    pk,
                    EcdsaSig {
                        sig: sig_sk,
                        hash_ty: EcdsaSighashType::All,
                    },
                ),
            ),
            (
                pub_them_pk_hash,
                (
                    pub_them_pk,
                    EcdsaSig {
                        sig: sig_pub_them,
                        hash_ty: EcdsaSighashType::All,
                    },
                ),
            ),
            (
                rev_them_pk_hash,
                (
                    rev_them_pk,
                    EcdsaSig {
                        sig: sig_rev_them,
                        hash_ty: EcdsaSighashType::All,
                    },
                ),
            ),
        ])
    };

    commit_descriptor.satisfy(&mut punish_tx.input[0], satisfier)?;

    Ok(punish_tx)
}

#[derive(Clone, Debug, Copy)]
pub struct Fee {
    fee: f64,
}

impl Fee {
    pub fn new(signed_vbytes: f64, rate: f64) -> Self {
        let fee = signed_vbytes * rate;
        Self { fee }
    }

    fn new_with_default_rate(signed_vbytes: f64) -> Self {
        Self::new(signed_vbytes, SATS_PER_VBYTE)
    }

    #[must_use]
    fn add(self, number: f64) -> Fee {
        Fee {
            fee: self.fee + number,
        }
    }

    pub fn as_u64(&self) -> u64 {
        // Ceil to prevent going lower than the min relay fee
        self.fee.ceil() as u64
    }

    /// Subtracts fee fairly from given amounts
    ///
    /// We need to consider a few cases:
    /// - If both amounts are >= DUST, they share the fee equally
    /// - If one amount is < DUST, it set to 0 and the other output needs to cover for the fee.
    pub fn subtract_fee(
        &self,
        dust_limit_maker: Amount,
        dust_limit_taker: Amount,
        amounts: PayoutAmounts,
    ) -> Result<PayoutAmounts> {
        let PayoutAmounts {
            maker_amount,
            taker_amount,
        } = amounts;
        let fee = Amount::from_sat(self.fee as u64);
        let (maker_amount, taker_amount) = match (
            maker_amount
                .checked_sub(fee / 2)
                .map(|a| a > dust_limit_maker)
                .unwrap_or(false),
            taker_amount
                .checked_sub(fee / 2)
                .map(|a| a > dust_limit_taker)
                .unwrap_or(false),
        ) {
            (true, true) => (maker_amount - fee / 2, taker_amount - fee / 2),
            (false, true) => (Amount::ZERO, taker_amount - fee + maker_amount),
            (true, false) => (maker_amount - fee + taker_amount, Amount::ZERO),
            (false, false) => bail!("Amounts are too small, could not subtract fee."),
        };
        Ok(PayoutAmounts {
            maker_amount,
            taker_amount,
        })
    }
}

pub struct PayoutAmounts {
    maker_amount: Amount,
    taker_amount: Amount,
}

impl From<Payout> for PayoutAmounts {
    fn from(payout: Payout) -> Self {
        Self {
            maker_amount: *payout.maker_amount(),
            taker_amount: *payout.taker_amount(),
        }
    }
}

impl PayoutAmounts {
    fn into_txouts(self, maker_address: &Address, taker_address: &Address) -> Vec<TxOut> {
        let txouts = [
            (self.maker_amount, maker_address),
            (self.taker_amount, taker_address),
        ]
        .iter()
        .filter_map(|(amount, address)| {
            let script_pubkey = address.script_pubkey();
            let dust_limit = script_pubkey.dust_value();
            (amount >= &dust_limit).then(|| TxOut {
                value: amount.as_sat(),
                script_pubkey,
            })
        })
        .collect::<Vec<_>>();

        txouts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use maia_core::generate_payouts;
    use std::str::FromStr;

    #[test]
    fn given_both_above_dust_then_equal_fee_distribution() {
        let dummy_address = dummy_maker_address();
        let dummy_dust_limit = dummy_address.script_pubkey().dust_value();

        let orig_maker_amount = Amount::from_sat(1000);
        let orig_taker_amount = Amount::from_sat(1000);

        let fee = Fee::new(170.0, 1.0);
        let PayoutAmounts {
            maker_amount,
            taker_amount,
        } = fee
            .subtract_fee(
                dummy_dust_limit,
                dummy_dust_limit,
                PayoutAmounts {
                    maker_amount: orig_maker_amount,
                    taker_amount: orig_taker_amount,
                },
            )
            .unwrap();
        assert_eq!(maker_amount + Amount::from_sat(85), orig_maker_amount);
        assert_eq!(taker_amount + Amount::from_sat(85), orig_taker_amount);
    }

    #[test]
    fn given_first_below_dust_then_second_pays_fee() {
        let dummy_address = dummy_maker_address();
        let dummy_dust_limit = dummy_address.script_pubkey().dust_value();

        let orig_maker_amount = dummy_dust_limit - Amount::ONE_SAT;
        let orig_taker_amount = Amount::from_sat(1000);

        let fee = Fee::new(170.0, 1.0);
        let PayoutAmounts {
            maker_amount,
            taker_amount,
        } = fee
            .subtract_fee(
                dummy_dust_limit,
                dummy_dust_limit,
                PayoutAmounts {
                    maker_amount: orig_maker_amount,
                    taker_amount: orig_taker_amount,
                },
            )
            .unwrap();
        assert_eq!(maker_amount, Amount::ZERO);
        assert_eq!(
            taker_amount,
            orig_taker_amount - Amount::from_sat(170) + orig_maker_amount
        );
    }

    #[test]
    fn given_second_below_dust_then_first_pays_fee() {
        let dummy_address = dummy_maker_address();
        let dummy_dust_limit = dummy_address.script_pubkey().dust_value();

        let orig_maker_amount = Amount::from_sat(1000);
        let orig_taker_amount = dummy_dust_limit - Amount::ONE_SAT;

        let fee = Fee::new(170.0, 1.0);
        let PayoutAmounts {
            maker_amount,
            taker_amount,
        } = fee
            .subtract_fee(
                dummy_dust_limit,
                dummy_dust_limit,
                PayoutAmounts {
                    maker_amount: orig_maker_amount,
                    taker_amount: orig_taker_amount,
                },
            )
            .unwrap();
        assert_eq!(
            maker_amount,
            orig_maker_amount - Amount::from_sat(170) + orig_taker_amount
        );
        assert_eq!(taker_amount, Amount::ZERO);
    }

    #[test]
    fn given_both_below_dust_then_error() {
        let dummy_address = dummy_maker_address();
        let dummy_dust_limit = dummy_address.script_pubkey().dust_value();

        let orig_maker_amount = dummy_dust_limit - Amount::ONE_SAT;
        let orig_taker_amount = dummy_dust_limit - Amount::ONE_SAT;

        let fee = Fee::new(170.0, 1.0);
        assert!(fee
            .subtract_fee(
                dummy_dust_limit,
                dummy_dust_limit,
                PayoutAmounts {
                    maker_amount: orig_maker_amount,
                    taker_amount: orig_taker_amount,
                },
            )
            .is_err());
    }

    #[test]
    fn given_both_amount_zero_then_error() {
        let dummy_address = dummy_maker_address();
        let dummy_dust_limit = dummy_address.script_pubkey().dust_value();

        let orig_maker_amount = Amount::ZERO;
        let orig_taker_amount = Amount::ZERO;

        let fee = Fee::new(170.0, 1.0);
        assert!(fee
            .subtract_fee(
                dummy_dust_limit,
                dummy_dust_limit,
                PayoutAmounts {
                    maker_amount: orig_maker_amount,
                    taker_amount: orig_taker_amount,
                },
            )
            .is_err());
    }

    #[test]
    fn full_close_transaction_test_with_one_amount_below_dust_then_only_one_output_exists() {
        let dummy_descriptor = dummy_descriptor();
        let maker_address = dummy_maker_address();
        let taker_address = dummy_taker_address();

        let amount = Amount::from_sat(100000);
        let maker_amount = Amount::from_sat(100000);
        let taker_amount = Amount::ZERO;
        let (tx, _) = close_transaction(
            &dummy_descriptor,
            OutPoint::default(),
            amount,
            (&maker_address, maker_amount),
            (&taker_address, taker_amount),
            1,
        )
        .unwrap();

        assert_eq!(tx.output[0].script_pubkey, maker_address.script_pubkey());
        assert!(tx.output.get(1).is_none());
    }

    #[test]
    fn full_close_transaction_test_with_both_amounts_above_dust_then_both_outputs_exist() {
        let dummy_descriptor = dummy_descriptor();
        let maker_address = dummy_maker_address();
        let taker_address = dummy_taker_address();

        let amount = Amount::from_sat(100000);
        let maker_amount = Amount::from_sat(100000);
        let taker_amount = Amount::from_sat(100000);
        let (tx, _) = close_transaction(
            &dummy_descriptor,
            OutPoint::default(),
            amount,
            (&maker_address, maker_amount),
            (&taker_address, taker_amount),
            1,
        )
        .unwrap();

        assert_eq!(tx.output[0].script_pubkey, maker_address.script_pubkey());
        assert_eq!(tx.output[1].script_pubkey, taker_address.script_pubkey());
    }

    #[test]
    fn test_fee_subtraction_bigger_than_dust() {
        let key = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
            .parse()
            .unwrap();
        let dummy_address = Address::p2wpkh(&key, Network::Regtest).unwrap();
        let dummy_dust_limit = dummy_address.script_pubkey().dust_value();

        let orig_maker_amount = 1000;
        let orig_taker_amount = 1000;
        let payouts = generate_payouts(
            0..=10_000,
            Amount::from_sat(orig_maker_amount),
            Amount::from_sat(orig_taker_amount),
        )
        .unwrap();
        let fee = Fee::new(100.0, 1.0);

        for payout in payouts {
            let updated_payout = fee
                .subtract_fee(dummy_dust_limit, dummy_dust_limit, payout.into())
                .unwrap();

            assert_eq!(
                updated_payout.maker_amount,
                Amount::from_sat(orig_maker_amount - fee.as_u64() / 2)
            );
            assert_eq!(
                updated_payout.taker_amount,
                Amount::from_sat(orig_taker_amount - fee.as_u64() / 2)
            );
        }
    }

    #[test]
    fn test_fee_subtraction_smaller_than_dust() {
        let key = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
            .parse()
            .unwrap();
        let dummy_address = Address::p2wpkh(&key, Network::Regtest).unwrap();
        let dummy_dust_limit = dummy_address.script_pubkey().dust_value();

        let orig_maker_amount = dummy_dust_limit.as_sat() - 1;
        let orig_taker_amount = 1000;
        let payouts = generate_payouts(
            0..=10_000,
            Amount::from_sat(orig_maker_amount),
            Amount::from_sat(orig_taker_amount),
        )
        .unwrap();
        let fee = Fee::new(100.0, 1.0);

        for payout in payouts {
            let amounts = fee
                .subtract_fee(dummy_dust_limit, dummy_dust_limit, payout.into())
                .unwrap();

            assert_eq!(amounts.maker_amount, Amount::from_sat(0));
            assert_eq!(
                amounts.taker_amount,
                Amount::from_sat(orig_taker_amount - fee.as_u64() + orig_maker_amount)
            );
        }
    }

    fn dummy_descriptor() -> Descriptor<PublicKey> {
        Descriptor::<PublicKey>::from_str(
            "pk(020000000000000000000000000000000000000000000000000000000000000002)",
        )
        .unwrap()
    }
    fn dummy_maker_address() -> Address {
        Address::from_str("bc1qpq2cfgz5lktxzr5zqv7nrzz46hsvq3492ump9pz8rzcl8wqtwqcspx5y6a").unwrap()
    }
    fn dummy_taker_address() -> Address {
        Address::from_str("325zcVBN5o2eqqqtGwPjmtDd8dJRyYP82s").unwrap()
    }
}
