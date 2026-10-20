#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Pure Rust implementation of SHA-1 (RFC 3174) for TOTP (RFC 6238) and k-anonymity breach auditing.

/// SHA-1 digest state.
#[derive(Clone, Debug)]
pub struct Sha1 {
    state: [u32; 5],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// Creates a new SHA-1 instance initialized to standard constants.
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Appends data to the running SHA-1 digest.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u64;

        if self.buffer_len > 0 {
            let needed = 64 - self.buffer_len;
            if data.len() >= needed {
                self.buffer[self.buffer_len..64].copy_from_slice(&data[..needed]);
                let block = self.buffer;
                self.process_block(&block);
                self.buffer_len = 0;
                data = &data[needed..];
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
        }

        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            let mut arr = [0u8; 64];
            arr.copy_from_slice(block);
            self.process_block(&arr);
            data = rest;
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Completes the hash calculation and returns the 20-byte digest.
    pub fn finalize(mut self) -> [u8; 20] {
        let total_bits = self.total_len * 8;

        // Append padding bit '1'
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            for b in &mut self.buffer[self.buffer_len..64] {
                *b = 0;
            }
            let block = self.buffer;
            self.process_block(&block);
            self.buffer = [0u8; 64];
            self.buffer_len = 0;
        }

        for b in &mut self.buffer[self.buffer_len..56] {
            *b = 0;
        }

        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let block = self.buffer;
        self.process_block(&block);

        let mut out = [0u8; 20];
        for (i, &word) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Convenience function computing the SHA-1 digest of a byte slice.
    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for (i, &item) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(item);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_standard_vectors() {
        let empty = Sha1::digest(b"");
        assert_eq!(
            hex::encode(empty),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );

        let abc = Sha1::digest(b"abc");
        assert_eq!(hex::encode(abc), "a9993e364706816aba3e25717850c26c9cd0d89d");

        let fox = Sha1::digest(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(hex::encode(fox), "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
    }

    mod hex {
        pub fn encode(bytes: [u8; 20]) -> String {
            bytes.iter().map(|b| format!("{:02x}", b)).collect()
        }
    }
}
