use bdk::wallet::coin_selection::CoinSelectionAlgorithm;
use bdk::wallet::tx_builder::CreateTx;
pub use transaction_ext::TransactionExt;
pub use transactions::{close_transaction, punish_transaction};

use crate::protocol::sighash_ext::SigHashExt;
use crate::protocol::transactions::{
    lock_transaction, CommitTransaction, ContractExecutionTransaction as ContractExecutionTx,
    RefundTransaction,
};
use crate::{interval, oracle};
use anyhow::{bail, Context, Result};
use bdk::bitcoin::hashes::hex::ToHex;
use bdk::bitcoin::util::bip143::SigHashCache;
use bdk::bitcoin::util::psbt::PartiallySignedTransaction;
use bdk::bitcoin::{Address, Amount, PublicKey, SigHashType, Transaction, TxOut};
use bdk::database::BatchDatabase;
use bdk::descriptor::Descriptor;
use bdk::miniscript::descriptor::Wsh;
use bdk::miniscript::DescriptorTrait;
use bdk::TxBuilder;
use itertools::Itertools;
use secp256k1_zkp::{self, schnorrsig, EcdsaAdaptorSignature, SecretKey, Signature, SECP256K1};
use std::collections::HashMap;
use std::hash::Hasher;
use std::iter::FromIterator;
use std::num::NonZeroU8;
use std::ops::RangeInclusive;

mod sighash_ext;
mod transaction_ext;
mod transactions;
mod txin_ext;

/// Static script to be used to create lock tx
const DUMMY_2OF2_MULTISIG: &str =
    "0020b5aa99ed7e0fa92483eb045ab8b7a59146d4d9f6653f21ba729b4331895a5b46";

pub trait TxBuilderExt {
    fn add_2of2_multisig_recipient(&mut self, amount: Amount) -> &mut Self;
}

impl<'w, B, D, CS> TxBuilderExt for TxBuilder<'_, B, D, CS, CreateTx>
where
    D: BatchDatabase,
    CS: CoinSelectionAlgorithm<D>,
{
    fn add_2of2_multisig_recipient(&mut self, amount: Amount) -> &mut Self {
        self.add_recipient(
            DUMMY_2OF2_MULTISIG.parse().expect("Should be valid script"),
            amount.as_sat(),
        )
    }
}

/// Build all the transactions and some of the signatures and
/// encrypted signatures needed to perform the CFD protocol.
///
/// # Arguments
///
/// * `long` - The initial parameters of the party going long.
/// * `long_punish_params` - The punish parameters of the party going long.
/// * `short` - The initial parameters of the party going short.
/// * `short_punish_params` - The punish parameters of the party going short.
/// * `oracle_pk` - The public key of the oracle.
/// * `cet_timelock` - Relative timelock of the CET transaction with respect to the commit
///   transaction.
/// * `refund_timelock` - Relative timelock of the refund transaction with respect to the commit
///   transaction.
/// * `payouts_per_event` - All the possible ways in which the contract can be settled, according to
///   the conditions of the bet. The key is the event at which the oracle will attest the price.
/// * `identity_sk` - The secret key of the caller, used to sign and encsign different transactions.
pub fn create_cfd_transactions(
    (long, long_punish_params): (PartyParams, PunishParams),
    (short, short_punish_params): (PartyParams, PunishParams),
    oracle_pk: schnorrsig::PublicKey,
    (cet_timelock, refund_timelock): (u32, u32),
    payouts_per_event: HashMap<Announcement, Vec<Payout>>,
    identity_sk: SecretKey,
    commit_tx_fee_rate: u32,
) -> Result<CfdTransactions> {
    let lock_tx = lock_transaction(
        long.lock_psbt.clone(),
        short.lock_psbt.clone(),
        long.identity_pk,
        short.identity_pk,
        long.lock_amount + short.lock_amount,
    );

    build_cfds(
        lock_tx,
        (
            long.identity_pk,
            long.lock_amount,
            long.address,
            long_punish_params,
        ),
        (
            short.identity_pk,
            short.lock_amount,
            short.address,
            short_punish_params,
        ),
        oracle_pk,
        (cet_timelock, refund_timelock),
        payouts_per_event,
        identity_sk,
        commit_tx_fee_rate,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn renew_cfd_transactions(
    lock_tx: PartiallySignedTransaction,
    (long_pk, long_lock_amount, long_address, long_punish_params): (
        PublicKey,
        Amount,
        Address,
        PunishParams,
    ),
    (short_pk, short_lock_amount, short_address, short_punish_params): (
        PublicKey,
        Amount,
        Address,
        PunishParams,
    ),
    oracle_pk: schnorrsig::PublicKey,
    (cet_timelock, refund_timelock): (u32, u32),
    payouts_per_event: HashMap<Announcement, Vec<Payout>>,
    identity_sk: SecretKey,
    commit_tx_fee_rate: u32,
) -> Result<CfdTransactions> {
    build_cfds(
        lock_tx,
        (long_pk, long_lock_amount, long_address, long_punish_params),
        (
            short_pk,
            short_lock_amount,
            short_address,
            short_punish_params,
        ),
        oracle_pk,
        (cet_timelock, refund_timelock),
        payouts_per_event,
        identity_sk,
        commit_tx_fee_rate,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_cfds(
    lock_tx: PartiallySignedTransaction,
    (long_pk, long_lock_amount, long_address, long_punish_params): (
        PublicKey,
        Amount,
        Address,
        PunishParams,
    ),
    (short_pk, short_lock_amount, short_address, short_punish_params): (
        PublicKey,
        Amount,
        Address,
        PunishParams,
    ),
    oracle_pk: schnorrsig::PublicKey,
    (cet_timelock, refund_timelock): (u32, u32),
    payouts_per_event: HashMap<Announcement, Vec<Payout>>,
    identity_sk: SecretKey,
    commit_tx_fee_rate: u32,
) -> Result<CfdTransactions> {
    let commit_tx = CommitTransaction::new(
        &lock_tx.global.unsigned_tx,
        (
            long_pk,
            long_punish_params.revocation_pk,
            long_punish_params.publish_pk,
        ),
        (
            short_pk,
            short_punish_params.revocation_pk,
            short_punish_params.publish_pk,
        ),
        commit_tx_fee_rate,
    )
    .context("cannot build commit tx")?;

    let identity_pk = secp256k1_zkp::PublicKey::from_secret_key(SECP256K1, &identity_sk);
    let commit_encsig = if identity_pk == long_pk.key {
        commit_tx.encsign(identity_sk, &short_punish_params.publish_pk)
    } else if identity_pk == short_pk.key {
        commit_tx.encsign(identity_sk, &long_punish_params.publish_pk)
    } else {
        bail!("identity sk does not belong to short or long")
    };

    let refund = {
        let tx = RefundTransaction::new(
            &commit_tx,
            refund_timelock,
            &long_address,
            &short_address,
            long_lock_amount,
            short_lock_amount,
        );

        let sighash = tx.sighash().to_message();
        let sig = SECP256K1.sign(&sighash, &identity_sk);

        (tx.into_inner(), sig)
    };

    let cets = payouts_per_event
        .into_iter()
        .map(|(event, payouts)| {
            let cets = payouts
                .iter()
                .map(|payout| {
                    let cet = ContractExecutionTx::new(
                        &commit_tx,
                        payout.clone(),
                        &long_address,
                        &short_address,
                        event.nonce_pks.as_slice(),
                        cet_timelock,
                    )?;

                    let encsig = cet.encsign(identity_sk, &oracle_pk)?;

                    Ok((cet.into_inner(), encsig, payout.digits.clone()))
                })
                .collect::<Result<Vec<_>>>()
                .context("cannot build and sign all cets")?;

            Ok(Cets { event, cets })
        })
        .collect::<Result<_>>()?;

    Ok(CfdTransactions {
        lock: lock_tx,
        commit: (commit_tx.into_inner(), commit_encsig),
        cets,
        refund,
    })
}

pub fn lock_descriptor(long_pk: PublicKey, short_pk: PublicKey) -> Descriptor<PublicKey> {
    const MINISCRIPT_TEMPLATE: &str = "c:and_v(v:pk(A),pk_k(B))";

    let long_pk = ToHex::to_hex(&long_pk.key);
    let short_pk = ToHex::to_hex(&short_pk.key);

    let miniscript = MINISCRIPT_TEMPLATE
        .replace('A', &long_pk)
        .replace('B', &short_pk);

    let miniscript = miniscript.parse().expect("a valid miniscript");

    Descriptor::Wsh(Wsh::new(miniscript).expect("a valid descriptor"))
}

pub fn commit_descriptor(
    (long_own_pk, long_rev_pk, long_publish_pk): (PublicKey, PublicKey, PublicKey),
    (short_own_pk, short_rev_pk, short_publish_pk): (PublicKey, PublicKey, PublicKey),
) -> Descriptor<PublicKey> {
    let long_own_pk_hash = long_own_pk.pubkey_hash().as_hash();
    let long_own_pk = long_own_pk.key.serialize().to_hex();
    let long_publish_pk_hash = long_publish_pk.pubkey_hash().as_hash();
    let long_rev_pk_hash = long_rev_pk.pubkey_hash().as_hash();

    let short_own_pk_hash = short_own_pk.pubkey_hash().as_hash();
    let short_own_pk = short_own_pk.key.serialize().to_hex();
    let short_publish_pk_hash = short_publish_pk.pubkey_hash().as_hash();
    let short_rev_pk_hash = short_rev_pk.pubkey_hash().as_hash();

    // raw script:
    // or(and(pk(long_own_pk),pk(short_own_pk)),or(and(pk(long_own_pk),and(pk(short_publish_pk),
    // pk(short_rev_pk))),and(pk(short_own_pk),and(pk(long_publish_pk),pk(long_rev_pk)))))
    let full_script = format!("wsh(c:andor(pk({long_own_pk}),pk_k({short_own_pk}),or_i(and_v(v:pkh({long_own_pk_hash}),and_v(v:pkh({short_publish_pk_hash}),pk_h({short_rev_pk_hash}))),and_v(v:pkh({short_own_pk_hash}),and_v(v:pkh({long_publish_pk_hash}),pk_h({long_rev_pk_hash}))))))",
long_own_pk = long_own_pk,
short_own_pk = short_own_pk,
long_own_pk_hash = long_own_pk_hash,
short_own_pk_hash = short_own_pk_hash,
short_publish_pk_hash = short_publish_pk_hash,
short_rev_pk_hash = short_rev_pk_hash,
long_publish_pk_hash = long_publish_pk_hash,
long_rev_pk_hash = long_rev_pk_hash
    );

    full_script.parse().expect("a valid miniscript")
}

pub fn spending_tx_sighash(
    spending_tx: &Transaction,
    spent_descriptor: &Descriptor<PublicKey>,
    spent_amount: Amount,
) -> secp256k1_zkp::Message {
    let sighash = SigHashCache::new(spending_tx).signature_hash(
        0,
        &spent_descriptor.script_code(),
        spent_amount.as_sat(),
        SigHashType::All,
    );
    sighash.to_message()
}

pub fn finalize_spend_transaction(
    mut tx: Transaction,
    spent_descriptor: &Descriptor<PublicKey>,
    (pk_0, sig_0): (PublicKey, Signature),
    (pk_1, sig_1): (PublicKey, Signature),
) -> Result<Transaction> {
    let satisfier = HashMap::from_iter(vec![
        (pk_0, (sig_0, SigHashType::All)),
        (pk_1, (sig_1, SigHashType::All)),
    ]);

    let input = tx
        .input
        .iter_mut()
        .exactly_one()
        .expect("all spend transactions to have one input");
    spent_descriptor.satisfy(input, satisfier)?;

    Ok(tx)
}

#[derive(Clone, Debug)]
pub struct PartyParams {
    pub lock_psbt: PartiallySignedTransaction,
    pub identity_pk: PublicKey,
    pub lock_amount: Amount,
    pub address: Address,
}

#[derive(Debug, Copy, Clone)]
pub struct PunishParams {
    pub revocation_pk: PublicKey,
    pub publish_pk: PublicKey,
}

#[derive(Debug, Clone)]
pub struct CfdTransactions {
    pub lock: PartiallySignedTransaction,
    pub commit: (Transaction, EcdsaAdaptorSignature),
    pub cets: Vec<Cets>,
    pub refund: (Transaction, Signature),
}

/// Group of CETs associated with a particular oracle announcement.
///
/// All of the adaptor signatures included will be _possibly_ unlocked
/// by the attestation corresponding to the announcement. In practice,
/// only one of the adaptor signatures should be unlocked if the
/// payout intervals are constructed correctly. To check if an adaptor
/// signature can be unlocked by a price attestation, verify whether
/// the price attested to lies within its interval.
#[derive(Debug, Clone)]
pub struct Cets {
    pub event: Announcement,
    pub cets: Vec<(Transaction, EcdsaAdaptorSignature, interval::Digits)>,
}

#[derive(Debug, Clone, Eq)]
pub struct Announcement {
    pub id: String,
    pub nonce_pks: Vec<schnorrsig::PublicKey>,
}

impl std::hash::Hash for Announcement {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state)
    }
}

impl PartialEq for Announcement {
    fn eq(&self, other: &Self) -> bool {
        self.id.eq(&other.id)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Payout {
    digits: interval::Digits,
    long_amount: Amount,
    short_amount: Amount,
}

pub fn generate_payouts(
    range: RangeInclusive<u64>,
    long_amount: Amount,
    short_amount: Amount,
) -> Result<Vec<Payout>> {
    let digits = interval::Digits::new(range).context("invalid interval")?;
    Ok(digits
        .into_iter()
        .map(|digits| Payout {
            digits,
            long_amount,
            short_amount,
        })
        .collect())
}

impl Payout {
    pub fn digits(&self) -> &interval::Digits {
        &self.digits
    }

    pub fn long_amount(&self) -> &Amount {
        &self.long_amount
    }

    pub fn short_amount(&self) -> &Amount {
        &self.short_amount
    }

    fn into_txouts(self, long_address: &Address, short_address: &Address) -> Vec<TxOut> {
        let txouts = [
            (self.long_amount, long_address),
            (self.short_amount, short_address),
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

    /// Subtracts fee fairly from both outputs
    ///
    /// We need to consider a few cases:
    /// - If both amounts are >= DUST, they share the fee equally
    /// - If one amount is < DUST, it set to 0 and the other output needs to cover for the fee.
    fn with_updated_fee(
        self,
        fee: Amount,
        dust_limit_long: Amount,
        dust_limit_short: Amount,
    ) -> Result<Self> {
        let long_amount = self.long_amount;
        let short_amount = self.short_amount;

        let mut updated = self;
        match (
            long_amount
                .checked_sub(fee / 2)
                .map(|a| a > dust_limit_long)
                .unwrap_or(false),
            short_amount
                .checked_sub(fee / 2)
                .map(|a| a > dust_limit_short)
                .unwrap_or(false),
        ) {
            (true, true) => {
                updated.long_amount -= fee / 2;
                updated.short_amount -= fee / 2;
            }
            (false, true) => {
                updated.long_amount = Amount::ZERO;
                updated.short_amount = short_amount - (fee + long_amount);
            }
            (true, false) => {
                updated.long_amount = long_amount - (fee + short_amount);
                updated.short_amount = Amount::ZERO;
            }
            (false, false) => bail!("Amounts are too small, could not subtract fee."),
        }
        Ok(updated)
    }
}

pub fn compute_adaptor_pk(
    oracle_pk: &schnorrsig::PublicKey,
    index_nonce_pairs: &[(NonZeroU8, schnorrsig::PublicKey)],
) -> Result<secp256k1_zkp::PublicKey> {
    let attestation_pks = index_nonce_pairs
        .iter()
        .map(|(index, nonce_pk)| oracle::attestation_pk(oracle_pk, nonce_pk, *index))
        .collect::<Result<Vec<_>>>()?;
    let adaptor_pk = secp256k1_zkp::PublicKey::combine_keys(
        attestation_pks.iter().collect::<Vec<_>>().as_slice(),
    )?;

    Ok(adaptor_pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    use bdk::bitcoin::Network;

    // TODO add proptest for this

    #[test]
    fn test_fee_subtraction_bigger_than_dust() {
        let key = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
            .parse()
            .unwrap();
        let dummy_address = Address::p2wpkh(&key, Network::Regtest).unwrap();
        let dummy_dust_limit = dummy_address.script_pubkey().dust_value();

        let orig_long_amount = 1000;
        let orig_short_amount = 1000;
        let payouts = generate_payouts(
            0..=10_000,
            Amount::from_sat(orig_long_amount),
            Amount::from_sat(orig_short_amount),
        )
        .unwrap();
        let fee = 100;

        for payout in payouts {
            let updated_payout = payout
                .with_updated_fee(Amount::from_sat(fee), dummy_dust_limit, dummy_dust_limit)
                .unwrap();

            assert_eq!(
                updated_payout.long_amount,
                Amount::from_sat(orig_long_amount - fee / 2)
            );
            assert_eq!(
                updated_payout.short_amount,
                Amount::from_sat(orig_short_amount - fee / 2)
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

        let orig_long_amount = dummy_dust_limit.as_sat() - 1;
        let orig_short_amount = 1000;
        let payouts = generate_payouts(
            0..=10_000,
            Amount::from_sat(orig_long_amount),
            Amount::from_sat(orig_short_amount),
        )
        .unwrap();
        let fee = 100;

        for payout in payouts {
            let updated_payout = payout
                .with_updated_fee(Amount::from_sat(fee), dummy_dust_limit, dummy_dust_limit)
                .unwrap();

            assert_eq!(updated_payout.long_amount, Amount::from_sat(0));
            assert_eq!(
                updated_payout.short_amount,
                Amount::from_sat(orig_short_amount - (fee + orig_long_amount))
            );
        }
    }
}
