//! Windows CSP (BCrypt) primitives only: SHA-256, HMAC-SHA256 and system
//! random. The broker deliberately does not pull any third-party crypto
//! crate; every digest, MAC and nonce below comes from the OS provider.

use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
    BCryptGenRandom, BCryptHashData, BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE,
    BCRYPT_ALG_HANDLE_HMAC_FLAG, BCRYPT_HASH_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    BCRYPT_SHA256_ALGORITHM,
    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};

const SHA256_LEN: usize = 32;

fn check(status: NTSTATUS, what: &str) {
    if !status.is_ok() {
        panic!("{what} failed: NTSTATUS {:#x}", status.0 as u32);
    }
}

pub fn sha256(parts: &[&[u8]]) -> [u8; SHA256_LEN] {
    let mut out = [0u8; SHA256_LEN];
    unsafe {
        let mut alg = BCRYPT_ALG_HANDLE::default();
        check(
            BCryptOpenAlgorithmProvider(
                &mut alg,
                BCRYPT_SHA256_ALGORITHM,
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            ),
            "BCryptOpenAlgorithmProvider(SHA256)",
        );
        let mut hash = BCRYPT_HASH_HANDLE::default();
        check(BCryptCreateHash(alg, &mut hash, None, None, 0), "BCryptCreateHash");
        for part in parts {
            check(BCryptHashData(hash, part, 0), "BCryptHashData");
        }
        check(BCryptFinishHash(hash, &mut out, 0), "BCryptFinishHash");
        check(BCryptDestroyHash(hash), "BCryptDestroyHash");
        check(
            BCryptCloseAlgorithmProvider(alg, 0),
            "BCryptCloseAlgorithmProvider",
        );
    }
    out
}

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; SHA256_LEN] {
    let mut out = [0u8; SHA256_LEN];
    unsafe {
        let mut alg = BCRYPT_ALG_HANDLE::default();
        check(
            BCryptOpenAlgorithmProvider(
                &mut alg,
                BCRYPT_SHA256_ALGORITHM,
                None,
                BCRYPT_ALG_HANDLE_HMAC_FLAG,
            ),
            "BCryptOpenAlgorithmProvider(SHA256/HMAC)",
        );
        let mut hash = BCRYPT_HASH_HANDLE::default();
        check(
            BCryptCreateHash(alg, &mut hash, None, Some(key), 0),
            "BCryptCreateHash(HMAC)",
        );
        for part in parts {
            check(BCryptHashData(hash, part, 0), "BCryptHashData");
        }
        check(BCryptFinishHash(hash, &mut out, 0), "BCryptFinishHash");
        check(BCryptDestroyHash(hash), "BCryptDestroyHash");
        check(
            BCryptCloseAlgorithmProvider(alg, 0),
            "BCryptCloseAlgorithmProvider",
        );
    }
    out
}

/// System-preferred RNG (BCryptGenRandom with the system RNG flag).
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let status = unsafe { BCryptGenRandom(None, &mut buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    check(status, "BCryptGenRandom");
    buf
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Standard-alphabet base64 with padding (RFC 4648); used only for proof MACs.
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Constant-time equality so a proof MAC comparison does not leak prefix
/// matches through timing.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
