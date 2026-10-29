//! The on-disk envelope: an authenticated fixed header followed by chunked
//! AES-256-GCM ciphertext.
//!
//! Layout (all little-endian):
//!
//! ```text
//!  0   4   magic b"DTC1"
//!  4   1   format version
//!  5   1   cipher suite
//!  6   1   chunk exponent (payload size = 1 << e)
//!  7   1   reserved
//!  8   16  record id (ties the blob to one manifest entry)
//! 24   16  per-file KDF salt
//! 40   12  base nonce
//! 52    8  plaintext length
//! 60    8  chunk count
//! ```
//!
//! The whole header is passed as additional authenticated data for every chunk, so any
//! edit to length, chunking, salt or record id destroys the tags. Chunk nonces are
//! `base[0..4] || be64(index)`; because each blob has its own derived key, the counter
//! alone guarantees no nonce reuse within a key.

use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor, Read, Write};
use std::path::Path;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};

use crate::crypto::kdf::{derive_file_key, random_bytes, Secret, FILE_SALT_LEN};
use crate::error::{DtError, DtResult, IoCtx};

pub const MAGIC: [u8; 4] = *b"DTC1";
pub const FORMAT_VERSION: u8 = 1;
pub const SUITE_CHUNKED_AES256GCM: u8 = 1;
pub const HEADER_LEN: usize = 68;
pub const TAG_LEN: usize = 16;
pub const RECORD_ID_LEN: usize = 16;
/// 1 MiB payload chunks: small enough for resumable progress, large enough that
/// per-chunk overhead stays invisible on removable media.
pub const DEFAULT_CHUNK_EXP: u32 = 20;
/// Reserved record id for the manifest blob itself.
pub const NULL_RECORD: [u8; RECORD_ID_LEN] = [0u8; RECORD_ID_LEN];

pub type CancelCheck<'a> = dyn Fn() -> DtResult<()> + 'a;

fn cancelled() -> impl Fn() -> DtResult<()> {
    || Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub chunk_exp: u8,
    pub record_id: [u8; RECORD_ID_LEN],
    pub file_salt: [u8; FILE_SALT_LEN],
    pub nonce_base: [u8; 12],
    pub plaintext_len: u64,
    pub chunk_count: u64,
}

/// `(chunk_count, total_blob_length)` for a plaintext of `plaintext_len`.
pub fn layout(plaintext_len: u64, chunk_exp: u32) -> (u64, u64) {
    let chunk = 1u64 << chunk_exp;
    let count = if plaintext_len == 0 {
        1
    } else {
        plaintext_len.div_ceil(chunk)
    };
    let total = HEADER_LEN as u64 + plaintext_len + count * TAG_LEN as u64;
    (count, total)
}

impl Header {
    pub fn new(record_id: [u8; RECORD_ID_LEN], plaintext_len: u64, chunk_exp: u32) -> Self {
        let (chunk_count, _) = layout(plaintext_len, chunk_exp);
        Header {
            chunk_exp: chunk_exp as u8,
            record_id,
            file_salt: random_bytes::<FILE_SALT_LEN>(),
            nonce_base: random_bytes::<12>(),
            plaintext_len,
            chunk_count,
        }
    }

    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4] = FORMAT_VERSION;
        out[5] = SUITE_CHUNKED_AES256GCM;
        out[6] = self.chunk_exp;
        out[7] = 0;
        out[8..24].copy_from_slice(&self.record_id);
        out[24..40].copy_from_slice(&self.file_salt);
        out[40..52].copy_from_slice(&self.nonce_base);
        out[52..60].copy_from_slice(&self.plaintext_len.to_le_bytes());
        out[60..68].copy_from_slice(&self.chunk_count.to_le_bytes());
        out
    }

    pub fn parse(raw: &[u8]) -> DtResult<Header> {
        if raw.len() < HEADER_LEN {
            return Err(DtError::Format("data too short for an envelope header".into()));
        }
        if raw[0..4] != MAGIC {
            return Err(DtError::Format("missing DTC1 magic".into()));
        }
        if raw[4] != FORMAT_VERSION {
            return Err(DtError::Format(format!(
                "unsupported envelope version {}",
                raw[4]
            )));
        }
        if raw[5] != SUITE_CHUNKED_AES256GCM {
            return Err(DtError::Format(format!(
                "unsupported cipher suite {}",
                raw[5]
            )));
        }
        let chunk_exp = raw[6];
        if !(4..=26).contains(&chunk_exp) {
            return Err(DtError::Format(format!("absurd chunk exponent {chunk_exp}")));
        }
        let mut record_id = [0u8; RECORD_ID_LEN];
        record_id.copy_from_slice(&raw[8..24]);
        let mut file_salt = [0u8; FILE_SALT_LEN];
        file_salt.copy_from_slice(&raw[24..40]);
        let mut nonce_base = [0u8; 12];
        nonce_base.copy_from_slice(&raw[40..52]);
        let plaintext_len = u64::from_le_bytes(raw[52..60].try_into().unwrap());
        let chunk_count = u64::from_le_bytes(raw[60..68].try_into().unwrap());
        let (expected_count, _) = layout(plaintext_len, chunk_exp as u32);
        if expected_count != chunk_count {
            return Err(DtError::Format(
                "chunk count does not match declared length".into(),
            ));
        }
        Ok(Header {
            chunk_exp,
            record_id,
            file_salt,
            nonce_base,
            plaintext_len,
            chunk_count,
        })
    }

    pub fn chunk_payload(&self, index: u64) -> usize {
        let chunk = 1u64 << self.chunk_exp;
        let start = index * chunk;
        if start >= self.plaintext_len {
            0
        } else {
            chunk.min(self.plaintext_len - start) as usize
        }
    }

    /// Length the blob file must have; used to reject truncation and padding.
    pub fn blob_len(&self) -> u64 {
        let (_, total) = layout(self.plaintext_len, self.chunk_exp as u32);
        total
    }

    pub fn nonce_for(&self, index: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[0..4].copy_from_slice(&self.nonce_base[0..4]);
        n[4..12].copy_from_slice(&index.to_be_bytes());
        n
    }

    fn cipher(&self, master: &Secret) -> DtResult<Aes256Gcm> {
        let key = derive_file_key(master, &self.file_salt)?;
        Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| DtError::Crypto(format!("cipher key setup failed: {e}")))
    }
}

/// Encrypt `src` into `dst`. `plaintext_len` must be exact; the header commits to it.
pub fn encrypt_stream<R: Read, W: Write>(
    mut src: R,
    mut dst: W,
    master: &Secret,
    record_id: [u8; RECORD_ID_LEN],
    plaintext_len: u64,
    chunk_exp: u32,
    cancel: &CancelCheck<'_>,
) -> DtResult<Header> {
    let header = Header::new(record_id, plaintext_len, chunk_exp);
    let raw = header.to_bytes();
    let cipher = header.cipher(master)?;
    dst.write_all(&raw).ctx_pathless()?;

    let mut buf = vec![0u8; 1usize << chunk_exp];
    for index in 0..header.chunk_count {
        cancel()?;
        let take = header.chunk_payload(index);
        let mut filled = 0usize;
        while filled < take {
            let got = src
                .read(&mut buf[filled..take])
                .ctx_pathless()?;
            if got == 0 {
                return Err(DtError::Format(format!(
                    "source ended early: wanted {take} bytes at chunk {index}, got {filled}"
                )));
            }
            filled += got;
        }
        let nonce_bytes = header.nonce_for(index);
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let sealed = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &buf[..take],
                    aad: &raw,
                },
            )
            .map_err(|_| DtError::Crypto(format!("seal failed on chunk {index}")))?;
        dst.write_all(&sealed).ctx_pathless()?;
    }
    dst.flush().ctx_pathless()?;
    Ok(header)
}

/// Decrypt a whole blob, verifying every chunk tag before returning success.
pub fn decrypt_stream<R: Read, W: Write>(
    mut src: R,
    mut dst: W,
    master: &Secret,
    expected_record: Option<[u8; RECORD_ID_LEN]>,
    blob_len: u64,
    cancel: &CancelCheck<'_>,
) -> DtResult<Header> {
    let mut raw = [0u8; HEADER_LEN];
    src.read_exact(&mut raw).ctx_pathless()?;
    let header = Header::parse(&raw)?;
    if let Some(want) = expected_record {
        if header.record_id != want {
            return Err(DtError::Format(
                "blob belongs to a different manifest entry".into(),
            ));
        }
    }
    if header.blob_len() != blob_len {
        return Err(DtError::Format(format!(
            "blob is {} bytes but the header implies {}",
            blob_len,
            header.blob_len()
        )));
    }
    let cipher = header.cipher(master)?;
    let mut buf = vec![0u8; (1usize << header.chunk_exp) + TAG_LEN];
    for index in 0..header.chunk_count {
        cancel()?;
        let take = header.chunk_payload(index);
        let ct_len = take + TAG_LEN;
        src.read_exact(&mut buf[..ct_len]).ctx_pathless()?;
        let nonce_bytes = header.nonce_for(index);
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let open = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &buf[..ct_len],
                    aad: &raw,
                },
            )
            .map_err(|_| {
                DtError::Crypto(format!(
                    "authentication tag rejected on chunk {index} (wrong password or corrupted data)"
                ))
            })?;
        dst.write_all(&open).ctx_pathless()?;
    }
    dst.flush().ctx_pathless()?;
    Ok(header)
}

/// One-shot seal for small values (encrypted path names).
pub fn seal_small(key: &[u8], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> DtResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| DtError::Crypto(format!("name cipher setup failed: {e}")))?;
    let n = GenericArray::from_slice(nonce);
    cipher
        .encrypt(
            n,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| DtError::Crypto("name seal failed".into()))
}

pub fn open_small(key: &[u8], nonce: &[u8; 12], blob: &[u8], aad: &[u8]) -> DtResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| DtError::Crypto(format!("name cipher setup failed: {e}")))?;
    let n = GenericArray::from_slice(nonce);
    cipher
        .decrypt(
            n,
            Payload {
                msg: blob,
                aad,
            },
        )
        .map_err(|_| DtError::Format("name authentication failed".into()))
}

/// File-level helpers used by the lock/unlock engine.
pub fn encrypt_file(
    src_path: &Path,
    dst_path: &Path,
    master: &Secret,
    record_id: [u8; RECORD_ID_LEN],
    plaintext_len: u64,
    chunk_exp: u32,
    cancel: &CancelCheck<'_>,
) -> DtResult<Header> {
    let mut reader = BufReader::with_capacity(
        1usize << chunk_exp,
        File::open(src_path).ctx(src_path)?,
    );
    let mut writer = BufWriter::new(
        File::create(dst_path).ctx(dst_path)?,
    );
    encrypt_stream(
        &mut reader,
        &mut writer,
        master,
        record_id,
        plaintext_len,
        chunk_exp,
        cancel,
    )
}

pub fn decrypt_file(
    src_path: &Path,
    dst_path: &Path,
    master: &Secret,
    expected_record: Option<[u8; RECORD_ID_LEN]>,
    cancel: &CancelCheck<'_>,
) -> DtResult<Header> {
    let blob_len = File::open(src_path)
        .ctx(src_path)?
        .metadata()
        .ctx(src_path)?
        .len();
    let mut reader = BufReader::with_capacity(1usize << 20, File::open(src_path).ctx(src_path)?);
    let mut writer = BufWriter::new(File::create(dst_path).ctx(dst_path)?);
    decrypt_stream(
        &mut reader,
        &mut writer,
        master,
        expected_record,
        blob_len,
        cancel,
    )
}

/// Re-encrypt a blob in memory to prove the key and tags work, discarding plaintext.
pub fn verify_blob(blob_path: &Path, master: &Secret, record_id: [u8; RECORD_ID_LEN]) -> DtResult<u64> {
    let mut sink = Cursor::new(Vec::<u8>::new());
    let mut reader = File::open(blob_path).ctx(blob_path)?;
    let header = decrypt_stream(
        &mut reader,
        &mut sink,
        master,
        Some(record_id),
        std::fs::metadata(blob_path).ctx(blob_path)?.len(),
        &cancelled(),
    )?;
    Ok(header.plaintext_len)
}

trait IoErrHack<T> {
    fn ctx_pathless(self) -> DtResult<T>;
}

impl<T> IoErrHack<T> for std::io::Result<T> {
    fn ctx_pathless(self) -> DtResult<T> {
        self.map_err(|e| DtError::Io {
            path: String::from("(stream)"),
            source: e,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::{derive_master, KdfParams};

    fn test_key() -> Secret {
        let params = KdfParams {
            algo: "argon2id".to_string(),
            m_kib: 8_192,
            t: 1,
            p: 1,
        };
        derive_master("test password", b"0123456789abcdef0123456789abcdef", &params).unwrap()
    }

    fn roundtrip(data: &[u8], chunk_exp: u32) -> (Vec<u8>, Header) {
        let master = test_key();
        let id = random_bytes::<RECORD_ID_LEN>();
        let mut blob = Vec::new();
        let header = encrypt_stream(
            Cursor::new(data.to_vec()),
            &mut blob,
            &master,
            id,
            data.len() as u64,
            chunk_exp,
            &cancelled(),
        )
        .unwrap();
        let mut out = Vec::new();
        let back = decrypt_stream(
            Cursor::new(blob.clone()),
            &mut out,
            &master,
            Some(id),
            blob.len() as u64,
            &cancelled(),
        )
        .unwrap();
        assert_eq!(header, back);
        (out, header)
    }

    #[test]
    fn empty_file_roundtrips_with_one_authenticated_chunk() {
        let (out, header) = roundtrip(b"", 12);
        assert!(out.is_empty());
        assert_eq!(header.chunk_count, 1);
    }

    #[test]
    fn exact_chunk_boundary_roundtrips() {
        let data = vec![7u8; 4096];
        let (out, header) = roundtrip(&data, 12);
        assert_eq!(out, data);
        assert_eq!(header.chunk_count, 1);
    }

    #[test]
    fn multi_chunk_roundtrips() {
        let data: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let (out, header) = roundtrip(&data, 12);
        assert_eq!(out, data);
        assert_eq!(header.chunk_count, 5);
    }

    #[test]
    fn blob_length_matches_layout() {
        let data = vec![3u8; 5_000];
        let master = test_key();
        let mut blob = Vec::new();
        let header = encrypt_stream(
            Cursor::new(&data),
            &mut blob,
            &master,
            random_bytes(),
            data.len() as u64,
            12,
            &cancelled(),
        )
        .unwrap();
        assert_eq!(blob.len() as u64, header.blob_len());
        let (count, total) = layout(data.len() as u64, 12);
        assert_eq!((header.chunk_count, blob.len() as u64), (count, total));
    }

    #[test]
    fn flipped_ciphertext_byte_is_rejected() {
        let data = b"attack at dawn, then encrypt the drive".to_vec();
        let master = test_key();
        let id = random_bytes::<RECORD_ID_LEN>();
        let mut blob = Vec::new();
        encrypt_stream(
            Cursor::new(&data),
            &mut blob,
            &master,
            id,
            data.len() as u64,
            16,
            &cancelled(),
        )
        .unwrap();
        let tail = blob.len() - 1;
        blob[tail] ^= 0x01;
        let mut out = Vec::new();
        let err = decrypt_stream(
            Cursor::new(blob.clone()),
            &mut out,
            &master,
            Some(id),
            blob.len() as u64,
            &cancelled(),
        )
        .unwrap_err();
        assert!(matches!(err, DtError::Crypto(_)), "got {err:?}");
    }

    #[test]
    fn tampered_header_breaks_authentication() {
        let data = b"payload bytes that must not decrypt under a mutated length".to_vec();
        let master = test_key();
        let id = random_bytes::<RECORD_ID_LEN>();
        let mut blob = Vec::new();
        encrypt_stream(
            Cursor::new(&data),
            &mut blob,
            &master,
            id,
            data.len() as u64,
            16,
            &cancelled(),
        )
        .unwrap();
        // Rewriting the declared plaintext length is caught by the blob-length cross-check
        // before any decryption happens.
        let mut forged = blob.clone();
        forged[52..60].copy_from_slice(&(data.len() as u64 - 1).to_le_bytes());
        let mut out = Vec::new();
        let err = decrypt_stream(
            Cursor::new(forged.clone()),
            &mut out,
            &master,
            Some(id),
            forged.len() as u64,
            &cancelled(),
        )
        .unwrap_err();
        assert!(matches!(err, DtError::Format(_)), "got {err:?}");
        assert!(out.is_empty(), "a rejected blob must not leak plaintext");

        // A chunk count that contradicts the length is caught while parsing the header.
        let mut forged = blob.clone();
        forged[60..68].copy_from_slice(&9u64.to_le_bytes());
        let err = Header::parse(&forged[..HEADER_LEN]).unwrap_err();
        assert!(matches!(err, DtError::Format(_)), "got {err:?}");

        // A length-preserving edit (the nonce base) is invisible to every length check, so
        // the header must be caught by authentication: it is AAD for each chunk.
        let mut forged = blob.clone();
        forged[44] ^= 0x01;
        let mut out = Vec::new();
        let err = decrypt_stream(
            Cursor::new(forged.clone()),
            &mut out,
            &master,
            Some(id),
            forged.len() as u64,
            &cancelled(),
        )
        .unwrap_err();
        assert!(matches!(err, DtError::Crypto(_)), "got {err:?}");
        assert!(out.is_empty(), "a rejected blob must not leak plaintext");
    }

    #[test]
    fn truncation_is_detected_from_length() {
        let data = vec![9u8; 10_000];
        let master = test_key();
        let id = random_bytes::<RECORD_ID_LEN>();
        let mut blob = Vec::new();
        encrypt_stream(
            Cursor::new(&data),
            &mut blob,
            &master,
            id,
            data.len() as u64,
            12,
            &cancelled(),
        )
        .unwrap();
        let short = blob[..blob.len() - 512].to_vec();
        let mut out = Vec::new();
        let err = decrypt_stream(
            Cursor::new(short.clone()),
            &mut out,
            &master,
            Some(id),
            short.len() as u64,
            &cancelled(),
        )
        .unwrap_err();
        assert!(matches!(err, DtError::Format(_)), "got {err:?}");
    }

    #[test]
    fn wrong_key_fails_and_leaks_nothing() {
        let data = b"top secret spreadsheet".to_vec();
        let master = test_key();
        let id = random_bytes::<RECORD_ID_LEN>();
        let mut blob = Vec::new();
        encrypt_stream(
            Cursor::new(&data),
            &mut blob,
            &master,
            id,
            data.len() as u64,
            16,
            &cancelled(),
        )
        .unwrap();
        let other = test_key_other();
        let mut out = Vec::new();
        let err = decrypt_stream(
            Cursor::new(blob.clone()),
            &mut out,
            &other,
            Some(id),
            blob.len() as u64,
            &cancelled(),
        )
        .unwrap_err();
        assert!(matches!(err, DtError::Crypto(_)), "got {err:?}");
        assert!(out.is_empty());
    }

    fn test_key_other() -> Secret {
        let params = KdfParams {
            algo: "argon2id".to_string(),
            m_kib: 8_192,
            t: 1,
            p: 1,
        };
        derive_master("a different password", b"0123456789abcdef0123456789abcdef", &params).unwrap()
    }

    #[test]
    fn foreign_blob_record_id_is_refused() {
        let master = test_key();
        let id = random_bytes::<RECORD_ID_LEN>();
        let mut blob = Vec::new();
        let data = b"x".to_vec();
        encrypt_stream(
            Cursor::new(&data),
            &mut blob,
            &master,
            id,
            1,
            16,
            &cancelled(),
        )
        .unwrap();
        let mut out = Vec::new();
        let err = decrypt_stream(
            Cursor::new(blob.clone()),
            &mut out,
            &master,
            Some(random_bytes::<RECORD_ID_LEN>()),
            blob.len() as u64,
            &cancelled(),
        )
        .unwrap_err();
        assert!(matches!(err, DtError::Format(_)));
    }

    #[test]
    fn cancellation_stops_a_stream() {
        let master = test_key();
        let data = vec![1u8; 100_000];
        let mut blob = Vec::new();
        let err = encrypt_stream(
            Cursor::new(&data),
            &mut blob,
            &master,
            random_bytes(),
            data.len() as u64,
            12,
            &|| Err(DtError::Cancel),
        )
        .unwrap_err();
        assert!(matches!(err, DtError::Cancel));
    }

    #[test]
    fn name_seal_binds_to_record_id() {
        let key = random_bytes::<32>();
        let nonce = random_bytes::<12>();
        let blob = seal_small(&key, &nonce, b"Documents/tax-2026.pdf", &key).unwrap();
        assert_eq!(
            open_small(&key, &nonce, &blob, &key).unwrap(),
            b"Documents/tax-2026.pdf".to_vec()
        );
        assert!(open_small(&key, &nonce, &blob, b"wrong aad").is_err());
    }

    #[test]
    fn random_salt_and_nonce_per_blob() {
        let master = test_key();
        let id = random_bytes::<RECORD_ID_LEN>();
        let data = b"same input twice".to_vec();
        let mut a = Vec::new();
        let mut b = Vec::new();
        encrypt_stream(Cursor::new(&data), &mut a, &master, id, data.len() as u64, 16, &cancelled()).unwrap();
        encrypt_stream(Cursor::new(&data), &mut b, &master, id, data.len() as u64, 16, &cancelled()).unwrap();
        assert_ne!(a, b, "identical plaintext must not produce identical ciphertext");
    }

    #[test]
    fn unknown_magic_is_rejected() {
        assert!(matches!(
            Header::parse(&[0u8; HEADER_LEN]),
            Err(DtError::Format(_))
        ));
    }

    #[test]
    fn file_helpers_roundtrip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("plain.bin");
        let blob = dir.path().join("sealed.bin");
        let out = dir.path().join("again.bin");
        let payload: Vec<u8> = (0..50_000u32).map(|i| i as u8).collect();
        std::fs::write(&src, &payload).unwrap();
        let master = test_key();
        let id = random_bytes::<RECORD_ID_LEN>();
        encrypt_file(&src, &blob, &master, id, payload.len() as u64, 14, &cancelled()).unwrap();
        assert_eq!(verify_blob(&blob, &master, id).unwrap(), payload.len() as u64);
        decrypt_file(&blob, &out, &master, Some(id), &cancelled()).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), payload);
        assert!(matches!(
            verify_blob(&blob, &test_key_other(), id),
            Err(DtError::Crypto(_))
        ));
    }

    #[test]
    fn chunk_nonces_are_unique_and_counter_derived() {
        let header = Header::new(random_bytes(), 3 * 4096, 12);
        assert_eq!(header.chunk_count, 3);
        let n0 = header.nonce_for(0);
        let n1 = header.nonce_for(1);
        assert_eq!(&n0[0..4], &n1[0..4]);
        assert_eq!(&n1[4..12], &1u64.to_be_bytes());
        assert_ne!(n0, n1);
    }
}
