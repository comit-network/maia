use bdk::bitcoin::hashes::Hash;
use bdk::bitcoin::SigHash;

pub(crate) trait SigHashExt {
    fn to_message(self) -> secp256k1_zkp::Message;
}

impl SigHashExt for SigHash {
    fn to_message(self) -> secp256k1_zkp::Message {
        let hash = secp256k1_zkp::hashes::sha256d::Hash::from_inner(*self.as_inner());

        hash.into()
    }
}
