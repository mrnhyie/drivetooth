//! Key derivation: one Argon2id master key per volume, cheap HKDF subkeys per use.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::Instant;
use zeroize::Zeroize;

use crate::error::{DtError, DtResult};

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 32;
pub const FILE_SALT_LEN: usize = 16;

/// Argon2id cost parameters, stored in the clear inside `volume.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub algo: String,
    /// Memory cost in KiB.
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            algo: "argon2id".to_string(),
            m_kib: 19_456,
            t: 2,
            p: 1,
        }
    }
}

/// Key material that wipes itself when dropped.
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Secret(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(<redacted, {} bytes>)", self.0.len())
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

pub fn random_vec(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

/// Stretch the user password into the volume master key.
pub fn derive_master(password: &str, salt: &[u8], params: &KdfParams) -> DtResult<Secret> {
    if params.algo != "argon2id" {
        return Err(DtError::Format(format!("unknown KDF '{}'", params.algo)));
    }
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
            .map_err(|e| DtError::Crypto(format!("bad KDF parameters: {e}")))?,
    );
    let mut out = vec![0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| DtError::Crypto(format!("key derivation failed: {e}")))?;
    Ok(Secret::new(out))
}

/// Domain-separated subkey from the master key (manifest, names, verify).
pub fn subkey(master: &Secret, label: &str, context: &[u8]) -> DtResult<Secret> {
    let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
    let info = [label.as_bytes(), b"|", context].concat();
    let mut out = vec![0u8; KEY_LEN];
    hk.expand(&info, &mut out)
        .map_err(|e| DtError::Crypto(format!("HKDF expand failed: {e}")))?;
    Ok(Secret::new(out))
}

/// Every file gets its own key, bound to the random salt carried in its header.
pub fn derive_file_key(master: &Secret, file_salt: &[u8]) -> DtResult<Secret> {
    let hk = Hkdf::<Sha256>::new(Some(file_salt), master.as_bytes());
    let mut out = vec![0u8; KEY_LEN];
    hk.expand(b"drivetooth/file", &mut out)
        .map_err(|e| DtError::Crypto(format!("HKDF file key failed: {e}")))?;
    Ok(Secret::new(out))
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(mac.finalize().into_bytes().as_slice());
    out
}

/// `HMAC(master_verify_key, fixed message)` stored in the clear; lets us reject a wrong
/// password before touching any ciphertext.
pub fn compute_verifier(master: &Secret) -> DtResult<[u8; 32]> {
    let vkey = subkey(master, "verify", b"")?;
    Ok(hmac_sha256(vkey.as_bytes(), b"drivetooth/v1/verifier"))
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn check_verifier(master: &Secret, stored: &[u8]) -> DtResult<()> {
    let mine = compute_verifier(master)?;
    if ct_eq(&mine, stored) {
        Ok(())
    } else {
        Err(DtError::WrongPassword)
    }
}

/// Candidate cost settings, weakest first. Chosen so unlocking takes a few hundred
/// milliseconds on the host machine instead of a fixed number that is too weak on new
/// hardware and unusable on old hardware.
const LADDER: &[(u32, u32)] = &[
    (8_192, 2),
    (19_456, 2),
    (19_456, 3),
    (32_768, 3),
    (65_536, 3),
    (65_536, 4),
    (131_072, 4),
];

/// Calibrate to `target_ms` (clamped 100..2000 ms).
pub fn calibrate(target_ms: u64) -> KdfParams {
    let target = target_ms.clamp(100, 2_000);
    let salt = random_bytes::<SALT_LEN>();
    let probe = "drivetooth calibration probe";
    let mut chosen = KdfParams {
        algo: "argon2id".to_string(),
        m_kib: LADDER[0].0,
        t: LADDER[0].1,
        p: 1,
    };
    for (m_kib, t) in LADDER {
        let params = KdfParams {
            algo: "argon2id".to_string(),
            m_kib: *m_kib,
            t: *t,
            p: 1,
        };
        let started = Instant::now();
        match derive_master(probe, &salt, &params) {
            Ok(_) => {
                chosen = params;
                if started.elapsed().as_millis() as u64 >= target {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_is_password_and_salt_dependent() {
        let salt = random_bytes::<SALT_LEN>();
        let params = KdfParams {
            algo: "argon2id".to_string(),
            m_kib: 8_192,
            t: 1,
            p: 1,
        };
        let a = derive_master("hunter2", &salt, &params).unwrap();
        let b = derive_master("hunter2", &salt, &params).unwrap();
        let c = derive_master("hunter3", &salt, &params).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn verifier_accepts_only_the_right_password() {
        let salt = random_bytes::<SALT_LEN>();
        let params = KdfParams {
            algo: "argon2id".to_string(),
            m_kib: 8_192,
            t: 1,
            p: 1,
        };
        let good = derive_master("correct horse", &salt, &params).unwrap();
        let bad = derive_master("wrong horse", &salt, &params).unwrap();
        let stored = compute_verifier(&good).unwrap();
        assert!(check_verifier(&good, &stored).is_ok());
        assert!(matches!(
            check_verifier(&bad, &stored),
            Err(DtError::WrongPassword)
        ));
    }

    #[test]
    fn unknown_kdf_algo_is_rejected() {
        let params = KdfParams {
            algo: "bcrypt".to_string(),
            m_kib: 8_192,
            t: 1,
            p: 1,
        };
        assert!(derive_master("x", &[0u8; SALT_LEN], &params).is_err());
    }
}
