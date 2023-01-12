use librypt_hash::{Hash, HashFn};

use crate::Sha2;

impl Sha2 {
    pub const SHA_256_RC: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    pub const SHA_256_STATE: [u64; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    pub(crate) fn compute_256(&mut self) {
        let chunk = &self.buffer.1[..64];

        let mut state = [0u32; 8];

        for i in 0..8 {
            state[i] = self.state[i] as u32;
        }

        let mut words = [0u32; 64];

        for (i, word) in chunk.chunks(4).enumerate() {
            words[i] = u32::from_be_bytes(word.try_into().unwrap());
        }

        // extend words
        for i in 16..64 {
            let s0 = (words[i - 15].rotate_right(7))
                ^ (words[i - 15].rotate_right(18))
                ^ (words[i - 15] >> 3);
            let s1 = (words[i - 2].rotate_right(17))
                ^ (words[i - 2].rotate_right(19))
                ^ (words[i - 2] >> 10);

            words[i] = words[i - 16].wrapping_add(s0.wrapping_add(words[i - 7].wrapping_add(s1)));
        }

        for i in 0..64 {
            let s1 = (state[4].rotate_right(6))
                ^ (state[4].rotate_right(11))
                ^ (state[4].rotate_right(25));
            let ch = (state[4] & state[5]) ^ ((!state[4]) & state[6]);
            let temp1 = state[7].wrapping_add(
                s1.wrapping_add(ch.wrapping_add(Self::SHA_256_RC[i].wrapping_add(words[i]))),
            );
            let s0 = (state[0].rotate_right(2))
                ^ (state[0].rotate_right(13))
                ^ (state[0].rotate_right(22));
            let maj = (state[0] & state[1]) ^ (state[0] & state[2]) ^ (state[1] & state[2]);
            let temp2 = s0.wrapping_add(maj);

            state[7] = state[6];
            state[6] = state[5];
            state[5] = state[4];
            state[4] = state[3].wrapping_add(temp1);
            state[3] = state[2];
            state[2] = state[1];
            state[1] = state[0];
            state[0] = temp1.wrapping_add(temp2);
        }

        for i in 0..8 {
            self.state[i] = (self.state[i] as u32).wrapping_add(state[i]) as u64;
        }
    }

    pub(crate) fn compute_padded_256(&mut self) {
        self.buffer.1[self.buffer.0] = 0x80;

        if self.buffer.0 > 55 {
            for i in self.buffer.0 + 1..64 {
                self.buffer.1[i] = 0;
            }

            self.compute_256();

            self.buffer.0 = 0;
        }

        for i in self.buffer.0 + 1..56 {
            self.buffer.1[i] = 0;
        }

        self.buffer.1[56..64].copy_from_slice(&(self.total as u64 * 8).to_be_bytes());

        self.compute_256();
    }
}

impl HashFn<64, 32> for Sha2 {
    fn new() -> Self {
        Self {
            total: 0,
            state: Self::SHA_256_STATE,
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

    fn finalize(mut self) -> Hash<32> {
        self.compute_padded_256();

        let mut hash = [0u8; 32];

        for i in 0..8 {
            hash[i * 4..i * 4 + 4].copy_from_slice(&(self.state[i] as u32).to_be_bytes());
        }

        hash
    }

    fn finalize_reset(&mut self) -> Hash<32> {
        self.compute_padded_256();

        let mut hash = [0u8; 32];

        for i in 0..8 {
            hash[i * 4..i * 4 + 4].copy_from_slice(&(self.state[i] as u32).to_be_bytes());
        }

        // reset state
        self.total = 0;
        self.state = Self::SHA_256_STATE;
        self.buffer = (0, [0u8; 128]);

        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;

    #[test]
    fn test_sha256() {
        let hash = <Sha2 as HashFn<64, 32>>::hash(b"Hello, world!");

        assert_eq!(
            hash.encode_hex::<String>(),
            "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
        );
    }
}
