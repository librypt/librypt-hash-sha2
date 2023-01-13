use librypt_hash::{Hash, HashFn};

use crate::Sha2;

impl Sha2 {
    pub const SHA_512_256_STATE: [u64; 8] = [
        0x22312194fc2bf72c,
        0x9f555fa3c84c64c2,
        0x2393b86b6f53b151,
        0x963877195940eabd,
        0x96283ee2a88effe3,
        0xbe5e1e2553863992,
        0x2b0199fc2c85b8aa,
        0x0eb72ddc81c52ca2,
    ];
}

impl HashFn<128, 32> for Sha2 {
    fn new() -> Self {
        Self {
            total: 0,
            state: Self::SHA_512_256_STATE,
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

    fn finalize(mut self) -> Hash<32> {
        self.compute_padded_512();

        let mut hash = [0u8; 32];

        for i in 0..4 {
            hash[i * 8..i * 8 + 8].copy_from_slice(&self.state[i].to_be_bytes());
        }

        hash
    }

    fn finalize_reset(&mut self) -> Hash<32> {
        self.compute_padded_512();

        let mut hash = [0u8; 32];

        for i in 0..4 {
            hash[i * 8..i * 8 + 8].copy_from_slice(&self.state[i].to_be_bytes());
        }

        // reset state
        self.total = 0;
        self.state = Self::SHA_512_256_STATE;
        self.buffer = (0, [0u8; 128]);

        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;

    #[test]
    fn test_sha512_256() {
        let hash = <Sha2 as HashFn<128, 32>>::hash(b"Hello, world!");

        assert_eq!(
            hash.encode_hex::<String>(),
            "330c723f25267587db0b9f493463e017011239169cb57a6db216c63774367115"
        );
    }
}
