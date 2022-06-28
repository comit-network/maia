use bdk::bitcoin::Sighash;

pub(crate) trait SigHashExt {
    fn to_message(self) -> secp256k1_zkp::Message;
}

impl SigHashExt for Sighash {
    fn to_message(self) -> secp256k1_zkp::Message {
        use secp256k1_zkp::hashes::Hash;
        let hash = secp256k1_zkp::hashes::sha256d::Hash::from_inner(*self.as_inner());

        hash.into()
    }
}
