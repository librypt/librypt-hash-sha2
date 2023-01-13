mod sha224;
mod sha256;
mod sha384;
mod sha512;
mod sha512_224;
mod sha512_256;

/// SHA-2 hash function.
///
/// NOTE: This type implements 6 variants of SHA-2:
/// * SHA-224
/// * SHA-256
/// * SHA-384
/// * SHA-512
/// * SHA-512/224
/// * SHA-512/256
pub struct Sha2 {
    total: u128,
    state: [u64; 8],
    buffer: (usize, [u8; 128]),
}
