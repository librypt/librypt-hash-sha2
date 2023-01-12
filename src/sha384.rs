use librypt_hash::{Hash, HashFn};

use crate::Sha2;

impl Sha2 {
    pub const SHA_384_STATE: [u64; 8] = [
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4,
    ];
}

impl HashFn<128, 48> for Sha2 {
    fn new() -> Self {
        Self {
            total: 0,
            state: Self::SHA_384_STATE,
            buffer: (0, [0u8; 128]),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total += data.len() as u128;

        for i in 0..data.len() {
            self.buffer.1[self.buffer.0] = data[i];
            self.buffer.0 += 1;

            if self.buffer.0 == 128 {
                self.compute_512();
                self.buffer.0 = 0;
            }
        }
    }

    fn finalize(mut self) -> Hash<48> {
        self.compute_padded_512();

        let mut hash = [0u8; 48];

        for i in 0..6 {
            hash[i * 8..i * 8 + 8].copy_from_slice(&self.state[i].to_be_bytes());
        }

        hash
    }

    fn finalize_reset(&mut self) -> Hash<48> {
        self.compute_padded_512();

        let mut hash = [0u8; 48];

        for i in 0..6 {
            hash[i * 8..i * 8 + 8].copy_from_slice(&self.state[i].to_be_bytes());
        }

        // reset state
        self.total = 0;
        self.state = Self::SHA_384_STATE;
        self.buffer = (0, [0u8; 128]);

        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;

    #[test]
    fn test_sha384() {
        let hash = <Sha2 as HashFn<128, 48>>::hash(b"Hello, world!");

        assert_eq!(
            hash.encode_hex::<String>(),
            "55bc556b0d2fe0fce582ba5fe07baafff035653638c7ac0d5494c2a64c0bea1cc57331c7c12a45cdbca7f4c34a089eeb"
        );
    }
}
