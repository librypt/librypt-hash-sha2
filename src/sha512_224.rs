use librypt_hash::{Hash, HashFn};

use crate::Sha2;

impl Sha2 {
    pub const SHA_512_224_STATE: [u64; 8] = [
        0x8c3d37c819544da2,
        0x73e1996689dcd4d6,
        0x1dfab7ae32ff9c82,
        0x679dd514582f9fcf,
        0x0f6d2b697bd44da8,
        0x77e36f7304c48942,
        0x3f9d85a86a1d36c8,
        0x1112e6ad91d692a1,
    ];
}

impl HashFn<128, 28> for Sha2 {
    fn new() -> Self {
        Self {
            total: 0,
            state: Self::SHA_512_224_STATE,
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

    fn finalize(mut self) -> Hash<28> {
        self.compute_padded_512();

        let mut hash = [0u8; 28];

        for i in 0..3 {
            hash[i * 8..i * 8 + 8].copy_from_slice(&self.state[i].to_be_bytes());
        }

        hash[24..28].copy_from_slice(&self.state[3].to_be_bytes()[..4]);

        hash
    }

    fn finalize_reset(&mut self) -> Hash<28> {
        self.compute_padded_512();

        let mut hash = [0u8; 28];

        for i in 0..3 {
            hash[i * 8..i * 8 + 8].copy_from_slice(&self.state[i].to_be_bytes());
        }

        hash[24..28].copy_from_slice(&self.state[3].to_be_bytes()[..4]);

        // reset state
        self.total = 0;
        self.state = Self::SHA_512_224_STATE;
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
        let hash = <Sha2 as HashFn<128, 28>>::hash(b"Hello, world!");

        assert_eq!(
            hash.encode_hex::<String>(),
            "32620068b859669b45b31008e08b7384649ad2ca3f5163a3a71e5745"
        );
    }
}
