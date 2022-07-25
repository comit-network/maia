use anyhow::{Context, Result};
use bdk::database::BatchDatabase;
use bdk::wallet::coin_selection::CoinSelectionAlgorithm;
use bdk::wallet::tx_builder::CreateTx;
use bdk::TxBuilder;
use std::hash::Hasher;
use std::ops::RangeInclusive;
pub use transaction_ext::TransactionExt;

mod transaction_ext;

use bdk::bitcoin::util::psbt::PartiallySignedTransaction;
use bdk::bitcoin::{Address, Amount, PublicKey, Transaction, XOnlyPublicKey};
use secp256k1_zkp::ecdsa::Signature;
use secp256k1_zkp::EcdsaAdaptorSignature;

use crate::interval;

/// Static script to be used to create lock tx
pub const DUMMY_2OF2_MULTISIG: &str =
    "0020b5aa99ed7e0fa92483eb045ab8b7a59146d4d9f6653f21ba729b4331895a5b46";

pub trait TxBuilderExt {
    fn add_2of2_multisig_recipient(&mut self, amount: Amount) -> &mut Self;
}

impl<D, CS> TxBuilderExt for TxBuilder<'_, D, CS, CreateTx>
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
    pub nonce_pks: Vec<XOnlyPublicKey>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payout {
    digits: interval::Digits,
    maker_amount: Amount,
    taker_amount: Amount,
}

pub fn generate_payouts(
    range: RangeInclusive<u64>,
    maker_amount: Amount,
    taker_amount: Amount,
) -> Result<Vec<Payout>> {
    let digits = interval::Digits::new(range).context("invalid interval")?;
    Ok(digits
        .into_iter()
        .map(|digits| Payout {
            digits,
            maker_amount,
            taker_amount,
        })
        .collect())
}

impl Payout {
    pub fn digits(&self) -> &interval::Digits {
        &self.digits
    }

    pub fn maker_amount(&self) -> &Amount {
        &self.maker_amount
    }

    pub fn taker_amount(&self) -> &Amount {
        &self.taker_amount
    }
}
