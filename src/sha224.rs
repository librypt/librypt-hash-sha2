use librypt_hash::{Hash, HashFn};

use crate::Sha2;

impl Sha2 {
    pub const SHA_224_STATE: [u64; 8] = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
        0xbefa4fa4,
    ];
}

impl HashFn<64, 28> for Sha2 {
    fn new() -> Self {
        Self {
            total: 0,
            state: Self::SHA_224_STATE,
            buffer: (0, [0u8; 128]),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total += data.len() as u128;

        for i in 0..data.len() {
            self.buffer.1[self.buffer.0] = data[i];
            self.buffer.0 += 1;

            if self.buffer.0 == 64 {
                self.compute_256();
                self.buffer.0 = 0;
            }
        }
    }

    fn finalize(mut self) -> Hash<28> {
        self.compute_padded_256();

        let mut hash = [0u8; 28];

        for i in 0..7 {
            hash[i * 4..i * 4 + 4].copy_from_slice(&(self.state[i] as u32).to_be_bytes());
        }

        hash
    }

    fn finalize_reset(&mut self) -> Hash<28> {
        self.compute_padded_256();

        let mut hash = [0u8; 28];

        for i in 0..7 {
            hash[i * 4..i * 4 + 4].copy_from_slice(&(self.state[i] as u32).to_be_bytes());
        }

        // reset state
        self.total = 0;
        self.state = Self::SHA_224_STATE;
        self.buffer = (0, [0u8; 128]);

        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;

    #[test]
    fn test_sha224() {
        let hash = <Sha2 as HashFn<64, 28>>::hash(b"Hello, world!");

        assert_eq!(
            hash.encode_hex::<String>(),
            "8552d8b7a7dc5476cb9e25dee69a8091290764b7f2a64fe6e78e9568"
        );
    }
}
