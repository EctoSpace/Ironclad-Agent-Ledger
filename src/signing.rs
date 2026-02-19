// Ed25519 signing of event content hashes for tamper-proof verification.
// Key persistence: the signing key is encrypted with AES-256-GCM using a key
// derived from a user-supplied password via Argon2id. The ciphertext is stored at
// <data_dir>/session-<session_id>.key so that a crash does not invalidate the
// cryptographic audit trail of an ongoing session.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

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

// ── Encrypted key file ────────────────────────────────────────────────────────

/// On-disk representation of a password-encrypted Ed25519 signing key.
#[derive(Serialize, Deserialize)]
pub struct EncryptedKeyFile {
    /// Argon2id salt (base64-encoded, stored in the file for self-containment).
    pub salt: String,
    /// AES-256-GCM nonce, hex-encoded.
    pub nonce_hex: String,
    /// AES-256-GCM ciphertext (32-byte key), hex-encoded.
    pub ciphertext_hex: String,
    /// Session UUID this key belongs to.
    pub session_id: String,
}

/// Derive a 32-byte AES key from `password` and a 16-byte `salt` using Argon2id.
fn derive_key(password: &str, salt_str: &SaltString) -> Result<[u8; 32], SigningError> {
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), salt_str)
        .map_err(|e| SigningError::Kdf(e.to_string()))?;
    let hash_output = hash.hash.ok_or_else(|| SigningError::Kdf("no hash output".to_string()))?;
    let bytes = hash_output.as_bytes();
    if bytes.len() < 32 {
        return Err(SigningError::Kdf("hash output too short".to_string()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[..32]);
    Ok(key)
}

/// Encrypt a `SigningKey` with `password` using Argon2id KDF + AES-256-GCM.
pub fn encrypt_signing_key(
    session_id: Uuid,
    key: &SigningKey,
    password: &str,
) -> Result<EncryptedKeyFile, SigningError> {
    let salt = SaltString::generate(&mut OsRng);
    let aes_key_bytes = derive_key(password, &salt)?;
    let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, key.as_bytes().as_ref())
        .map_err(|e| SigningError::Encrypt(e.to_string()))?;
    Ok(EncryptedKeyFile {
        salt: salt.to_string(),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
        session_id: session_id.to_string(),
    })
}

/// Decrypt an `EncryptedKeyFile` with `password` to recover the `SigningKey`.
pub fn decrypt_signing_key(
    enc: &EncryptedKeyFile,
    password: &str,
) -> Result<SigningKey, SigningError> {
    let salt = SaltString::from_b64(&enc.salt)
        .map_err(|e| SigningError::Kdf(e.to_string()))?;
    let aes_key_bytes = derive_key(password, &salt)?;
    let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce_bytes = hex::decode(&enc.nonce_hex).map_err(|_| SigningError::InvalidHex)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct_bytes = hex::decode(&enc.ciphertext_hex).map_err(|_| SigningError::InvalidHex)?;
    let plaintext = cipher
        .decrypt(nonce, ct_bytes.as_ref())
        .map_err(|_| SigningError::Decrypt)?;
    let key_bytes: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| SigningError::InvalidKey)?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

fn key_file_path(key_dir: &Path, session_id: Uuid) -> PathBuf {
    key_dir.join(format!("session-{}.key", session_id))
}

/// Persist a `SigningKey` to disk encrypted with `password`.
pub fn save_session_key(
    key_dir: &Path,
    session_id: Uuid,
    key: &SigningKey,
    password: &str,
) -> Result<(), SigningError> {
    std::fs::create_dir_all(key_dir)
        .map_err(|e| SigningError::Io(e.to_string()))?;
    let enc = encrypt_signing_key(session_id, key, password)?;
    let json = serde_json::to_string_pretty(&enc)
        .map_err(|e| SigningError::Io(e.to_string()))?;
    std::fs::write(key_file_path(key_dir, session_id), json)
        .map_err(|e| SigningError::Io(e.to_string()))?;
    Ok(())
}

/// Load and decrypt a `SigningKey` from disk using `password`.
/// Returns `SigningError::KeyFileNotFound` if the file does not exist (new session).
pub fn load_session_key(
    key_dir: &Path,
    session_id: Uuid,
    password: &str,
) -> Result<SigningKey, SigningError> {
    let path = key_file_path(key_dir, session_id);
    if !path.exists() {
        return Err(SigningError::KeyFileNotFound);
    }
    let json = std::fs::read_to_string(&path)
        .map_err(|e| SigningError::Io(e.to_string()))?;
    let enc: EncryptedKeyFile = serde_json::from_str(&json)
        .map_err(|e| SigningError::Io(e.to_string()))?;
    decrypt_signing_key(&enc, password)
}

/// Prompt the user for a key-protection password, or read it from
/// `IRONCLAD_KEY_PASSWORD`. Returns `None` if the user enters an empty string
/// (key persistence is skipped) or if stdin is not a terminal.
pub fn prompt_or_env_password(prompt_msg: &str) -> Option<String> {
    if let Ok(pw) = std::env::var("IRONCLAD_KEY_PASSWORD") {
        if !pw.is_empty() {
            // Emit a loud, unmissable warning. Environment variables are visible in
            // /proc/self/environ, `ps auxe`, container inspection, and CI logs.
            // This path is provided for non-interactive CI only — never for production.
            eprintln!("╔══════════════════════════════════════════════════════════════╗");
            eprintln!("║  SECURITY WARNING: IRONCLAD_KEY_PASSWORD is set via env var  ║");
            eprintln!("║  This is INSECURE: the password is visible in process        ║");
            eprintln!("║  listings (/proc/self/environ, `ps auxe`, docker inspect).   ║");
            eprintln!("║  Use the interactive password prompt in production.           ║");
            eprintln!("╚══════════════════════════════════════════════════════════════╝");
            return Some(pw);
        }
        return None;
    }
    match rpassword::prompt_password(prompt_msg) {
        Ok(pw) if !pw.is_empty() => Some(pw),
        _ => None,
    }
}

/// Prompt the user to re-enter the password to unlock an existing session key.
pub fn prompt_or_env_password_for_resume(session_id: Uuid) -> Option<String> {
    let prompt = format!("Enter password to unlock signing key for session {} (leave blank to skip): ", session_id);
    if let Ok(pw) = std::env::var("IRONCLAD_KEY_PASSWORD") {
        if !pw.is_empty() {
            eprintln!("╔══════════════════════════════════════════════════════════════╗");
            eprintln!("║  SECURITY WARNING: IRONCLAD_KEY_PASSWORD is set via env var  ║");
            eprintln!("║  This is INSECURE: the password is visible in process        ║");
            eprintln!("║  listings (/proc/self/environ, `ps auxe`, docker inspect).   ║");
            eprintln!("║  Use the interactive password prompt in production.           ║");
            eprintln!("╚══════════════════════════════════════════════════════════════╝");
            return Some(pw);
        }
        return None;
    }
    match rpassword::prompt_password(&prompt) {
        Ok(pw) if !pw.is_empty() => Some(pw),
        _ => None,
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum SigningError {
    InvalidHex,
    InvalidKey,
    InvalidSignature,
    VerificationFailed,
    Kdf(String),
    Encrypt(String),
    Decrypt,
    Io(String),
    KeyFileNotFound,
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningError::InvalidHex => write!(f, "invalid hex"),
            SigningError::InvalidKey => write!(f, "invalid key bytes"),
            SigningError::InvalidSignature => write!(f, "invalid signature"),
            SigningError::VerificationFailed => write!(f, "signature verification failed"),
            SigningError::Kdf(s) => write!(f, "KDF error: {}", s),
            SigningError::Encrypt(s) => write!(f, "encryption error: {}", s),
            SigningError::Decrypt => write!(f, "decryption failed (wrong password or corrupted key file)"),
            SigningError::Io(s) => write!(f, "key file I/O error: {}", s),
            SigningError::KeyFileNotFound => write!(f, "key file not found (new session or key_dir not set)"),
        }
    }
}

impl std::error::Error for SigningError {}
