use librypt_hash::{Hash, HashFn};

use crate::Sha2;

impl Sha2 {
    pub const SHA_512_RC: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    pub const SHA_512_STATE: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    pub(crate) fn compute_512(&mut self) {
        let chunk = &self.buffer.1;

        let mut state = self.state;
        let mut words = [0u64; 80];

        for (i, word) in chunk.chunks(8).enumerate() {
            words[i] = u64::from_be_bytes(word.try_into().unwrap());
        }

        // extend words
        for i in 16..80 {
            let s0 = (words[i - 15].rotate_right(1))
                ^ (words[i - 15].rotate_right(8))
                ^ (words[i - 15] >> 7);
            let s1 = (words[i - 2].rotate_right(19))
                ^ (words[i - 2].rotate_right(61))
                ^ (words[i - 2] >> 6);

            words[i] = words[i - 16].wrapping_add(s0.wrapping_add(words[i - 7].wrapping_add(s1)));
        }

        for i in 0..80 {
            let s1 = (state[4].rotate_right(14))
                ^ (state[4].rotate_right(18))
                ^ (state[4].rotate_right(41));
            let ch = (state[4] & state[5]) ^ ((!state[4]) & state[6]);
            let temp1 = state[7].wrapping_add(
                s1.wrapping_add(ch.wrapping_add(Self::SHA_512_RC[i].wrapping_add(words[i]))),
            );
            let s0 = (state[0].rotate_right(28))
                ^ (state[0].rotate_right(34))
                ^ (state[0].rotate_right(39));
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
            self.state[i] = self.state[i].wrapping_add(state[i]);
        }
    }

    pub(crate) fn compute_padded_512(&mut self) {
        self.buffer.1[self.buffer.0] = 0x80;

        if self.buffer.0 > 111 {
            for i in self.buffer.0 + 1..128 {
                self.buffer.1[i] = 0;
            }

            self.compute_512();

            self.buffer.0 = 0;
        }

        for i in self.buffer.0 + 1..112 {
            self.buffer.1[i] = 0;
        }

        self.buffer.1[112..128].copy_from_slice(&(self.total * 8).to_be_bytes());

        self.compute_512();
    }
}

impl HashFn<128, 64> for Sha2 {
    fn new() -> Self {
        Self {
            total: 0,
            state: Self::SHA_512_STATE,
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

    fn finalize(mut self) -> Hash<64> {
        self.compute_padded_512();

        let mut hash = [0u8; 64];

        for i in 0..8 {
            hash[i * 8..i * 8 + 8].copy_from_slice(&self.state[i].to_be_bytes());
        }

        hash
    }

    fn finalize_reset(&mut self) -> Hash<64> {
        self.compute_padded_512();

        let mut hash = [0u8; 64];

        for i in 0..8 {
            hash[i * 8..i * 8 + 8].copy_from_slice(&self.state[i].to_be_bytes());
        }

        // reset state
        self.total = 0;
        self.state = Self::SHA_512_STATE;
        self.buffer = (0, [0u8; 128]);

        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex::ToHex;

    #[test]
    fn test_sha512() {
        let hash = <Sha2 as HashFn<128, 64>>::hash(b"Hello, world!");

        assert_eq!(
            hash.encode_hex::<String>(),
            "c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421"
        );
    }
}
