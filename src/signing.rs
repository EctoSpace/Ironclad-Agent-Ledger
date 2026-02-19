// Ed25519 signing of event content hashes for tamper-proof verification.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

pub fn sign_content_hash(signing_key: &SigningKey, content_hash: &str) -> String {
    let sig = signing_key.sign(content_hash.as_bytes());
    hex::encode(sig.to_bytes())
}

pub fn verify_signature(
    public_key_hex: &str,
    content_hash: &str,
    signature_hex: &str,
) -> Result<(), SigningError> {
    let pk_bytes = hex::decode(public_key_hex).map_err(|_| SigningError::InvalidHex)?;
    let vk = VerifyingKey::from_bytes(
        pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SigningError::InvalidKey)?,
    )
    .map_err(|_| SigningError::InvalidKey)?;
    let sig_bytes = hex::decode(signature_hex).map_err(|_| SigningError::InvalidHex)?;
    let sig = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SigningError::InvalidSignature)?,
    );
    vk.verify(content_hash.as_bytes(), &sig)
        .map_err(|_| SigningError::VerificationFailed)
}

pub fn public_key_hex(verifying_key: &VerifyingKey) -> String {
    hex::encode(verifying_key.as_bytes())
}

#[derive(Debug)]
pub enum SigningError {
    InvalidHex,
    InvalidKey,
    InvalidSignature,
    VerificationFailed,
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningError::InvalidHex => write!(f, "invalid hex"),
            SigningError::InvalidKey => write!(f, "invalid public key"),
            SigningError::InvalidSignature => write!(f, "invalid signature"),
            SigningError::VerificationFailed => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for SigningError {}
