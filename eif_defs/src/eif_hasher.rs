// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(warnings)]

use sha2::Digest;
use std::fmt::Debug;
use std::io::Result as IoResult;
use std::io::Write;
use std::vec::Vec;

use serde::{Deserialize, Serialize};

/// EifHasher class
///
/// A simple serialization/deserialization friendly Hasher class.
/// The only reason this exists is that we can't serialize a Hasher
/// from sha2 crate, so we are going to use the following algorithm:
///
/// 1. Initialize digest with 0.
/// 2. Gather block_size bytes in block field.
/// 3. digest = Hash(Concatenate(digest, block))
/// 4. Goto step 2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EifHasher<T: Digest + Debug + Write + Clone> {
    /// The bytes that have not been hashed yet, they get hashed
    /// once we gather block_size bytes.
    pub block: Vec<u8>,
    /// Intermediary digest for the blocks processed untill now.
    pub digest: Vec<u8>,
    /// The number of bytes we need to gather before hashing, it needs to
    /// be at least twice of the hasher output, since the hash of each output
    /// is fed back into the hasher the size of the block impacts the performance
    /// 0 means nothing is cached and all the bytes are feed to the hasher.
    pub block_size: usize,
    pub output_size: usize,
    #[serde(skip)]
    /// The hasher to be used, it is always in reset state, so we can skip
    /// serialization.
    pub hasher: T,
}

fn initial_digest(len: usize) -> Vec<u8> {
    vec![0; len]
}

impl<T: Digest + Debug + Write + Clone> EifHasher<T> {
    pub fn new(block_size: usize, mut hasher: T) -> Result<Self, String> {
        let output_size = hasher.finalize_reset().len();
        if block_size > 0 && output_size * 2 > block_size {
            return Err("Invalid block_size".to_string());
        }

        Ok(EifHasher {
            block: Vec::with_capacity(block_size),
            digest: initial_digest(output_size),
            block_size,
            output_size,
            hasher,
        })
    }

    /// EifHasher constructor with fixed block size.
    ///
    /// It is needed in order for all clients of this class to use the same
    /// block size if we want to get the same results.
    pub fn new_with_fixed_block_size(hasher: T) -> Result<Self, String> {
        /// This impacts the performance of the hasher, it is a sweet
        /// spot where we get decent performance, 200MB/s, and where are not
        /// forced to keep a large serialized state, 256 bytes for SHA256.
        pub const FIXED_BLOCK_SIZE_HASHER_OUPUT_RATIO: usize = 8;
        Self::new(
            hasher.clone().finalize_reset().len() * FIXED_BLOCK_SIZE_HASHER_OUPUT_RATIO,
            hasher,
        )
    }

    /// EifHasher constructor without cache.
    ///
    /// EIfHasher acts like passthrough passing all the bytes to the actual hasher.
    pub fn new_without_cache(hasher: T) -> Result<Self, String> {
        Self::new(0, hasher)
    }

    pub fn finalize_reset(&mut self) -> IoResult<Vec<u8>> {
        if self.block_size == 0 {
            return Ok(self.hasher.finalize_reset().to_vec());
        }
        if !self.block.is_empty() {
            self.consume_block()?;
        }
        let result = self.digest.clone();
        self.digest = initial_digest(self.output_size);
        Ok(result)
    }

    pub fn tpm_extend_finalize_reset(&mut self) -> IoResult<Vec<u8>> {
        let result = self.finalize_reset()?;
        let mut hasher = self.hasher.clone();

        hasher.write_all(&initial_digest(self.output_size))?;
        hasher.write_all(&result[..])?;
        Ok(hasher.finalize_reset().to_vec())
    }

    fn consume_block(&mut self) -> IoResult<()> {
        self.hasher.write_all(&self.digest[..])?;
        self.hasher.write_all(&self.block[..])?;
        self.block.clear();
        let result = self.hasher.finalize_reset();
        self.digest.copy_from_slice(&result[..]);
        Ok(())
    }
}

impl<T: Digest + Debug + Write + Clone> Write for EifHasher<T> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        if self.block_size == 0 {
            self.hasher.write_all(buf)?;
            return Ok(buf.len());
        }
        let mut remaining = buf;
        while self.block.len() + remaining.len() >= self.block_size {
            let (for_hasher, for_next_iter) =
                remaining.split_at(self.block_size - self.block.len());
            self.block.extend_from_slice(for_hasher);
            self.consume_block()?;
            remaining = for_next_iter;
        }

        self.block.extend_from_slice(remaining);
        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::EifHasher;
    use crate::eif_hasher::initial_digest;
    use sha2::{Digest, Sha256, Sha384, Sha512};
    use std::fmt::Debug;
    use std::io::Write;

    const INPUT_BLOCK_SIZE_SHA256: usize = 64;
    const INPUT_BLOCK_SIZE_SHA384: usize = 128;
    const INPUT_BLOCK_SIZE_SHA512: usize = 128;

    #[test]
    fn invalid_block_size() {
        let hasher = EifHasher::new(31, Sha256::new());
        assert_eq!(hasher.is_err(), true);

        let hasher = EifHasher::new(63, Sha512::new());
        assert_eq!(hasher.is_err(), true);

        let hasher = EifHasher::new(47, Sha384::new());
        assert_eq!(hasher.is_err(), true)
    }

    #[test]
    fn test_hash_less_values_than_block_size() {
        hash_less_values_than_block_size(Sha256::new(), INPUT_BLOCK_SIZE_SHA256);
        hash_less_values_than_block_size(Sha512::new(), INPUT_BLOCK_SIZE_SHA512);
        hash_less_values_than_block_size(Sha384::new(), INPUT_BLOCK_SIZE_SHA384);
    }

    fn hash_less_values_than_block_size<T: Digest + Debug + Write + Clone>(
        mut hasher_alg: T,
        block_size: usize,
    ) {
        let data = vec![78u8; block_size - 1];
        let output_size = hasher_alg.finalize_reset().len();
        let mut hasher = EifHasher::new(block_size, hasher_alg.clone()).unwrap();

        hasher.write_all(&data[..]).unwrap();
        hasher_alg
            .write_all(&initial_digest(output_size)[..])
            .unwrap();
        hasher_alg.write_all(&data[..]).unwrap();

        let mut hasher_clone = hasher.clone();
        let mut hasher_alg_clone = hasher_alg.clone();
        assert_eq!(
            hasher_alg.finalize_reset().to_vec(),
            hasher.finalize_reset().unwrap()
        );

        let result = hasher_alg_clone.finalize_reset();
        hasher_alg_clone
            .write_all(&initial_digest(output_size)[..])
            .unwrap();
        hasher_alg_clone.write_all(&result[..]).unwrap();

        assert_eq!(
            hasher_clone.tpm_extend_finalize_reset().unwrap(),
            hasher_alg_clone.finalize_reset().to_vec()
        );
    }

    #[test]
    fn test_hash_exact_block_size_values() {
        hash_exact_block_size_values(Sha256::new(), INPUT_BLOCK_SIZE_SHA256);
        hash_exact_block_size_values(Sha384::new(), INPUT_BLOCK_SIZE_SHA384);
        hash_exact_block_size_values(Sha512::new(), INPUT_BLOCK_SIZE_SHA512);
    }

    fn hash_exact_block_size_values<T: Digest + Debug + Write + Clone>(
        mut hasher_alg: T,
        block_size: usize,
    ) {
        let data = vec![78u8; block_size];
        let output_size = hasher_alg.finalize_reset().len();
        let mut hasher = EifHasher::new(block_size, hasher_alg.clone()).unwrap();

        hasher.write_all(&data).unwrap();
        hasher_alg
            .write_all(&initial_digest(output_size)[..])
            .unwrap();
        hasher_alg.write_all(&data[..block_size]).unwrap();

        let mut hasher_clone = hasher.clone();
        let mut hasher_alg_clone = hasher_alg.clone();

        assert_eq!(
            hasher_alg.finalize_reset().to_vec(),
            hasher.finalize_reset().unwrap()
        );

        let result = hasher_alg_clone.finalize_reset();
        hasher_alg_clone
            .write_all(&initial_digest(output_size)[..])
            .unwrap();
        hasher_alg_clone.write_all(&result[..]).unwrap();

        assert_eq!(
            hasher_clone.tpm_extend_finalize_reset().unwrap(),
            hasher_alg_clone.finalize_reset().to_vec()
        );
    }

    #[test]
    fn test_hash_more_values_than_block_size() {
        hash_more_values_than_block_size(Sha256::new(), INPUT_BLOCK_SIZE_SHA256);
        hash_more_values_than_block_size(Sha384::new(), INPUT_BLOCK_SIZE_SHA384);
        hash_more_values_than_block_size(Sha512::new(), INPUT_BLOCK_SIZE_SHA512);
    }

    fn hash_more_values_than_block_size<T: Digest + Debug + Write + Clone>(
        mut hasher_alg: T,
        block_size: usize,
    ) {
        let data = vec![78u8; block_size + block_size / 2 - 1];
        let output_size = hasher_alg.finalize_reset().len();
        let (data1, data2) = data.split_at(block_size);
        let mut hasher = EifHasher::new(block_size, hasher_alg.clone()).unwrap();

        hasher.write_all(&data).unwrap();

        hasher_alg.write_all(&initial_digest(output_size)).unwrap();
        hasher_alg.write_all(&data1).unwrap();
        let result = hasher_alg.finalize_reset();
        hasher_alg.write_all(&result).unwrap();
        hasher_alg.write_all(&data2).unwrap();

        let mut hasher_clone = hasher.clone();
        let mut hasher_alg_clone = hasher_alg.clone();

        assert_eq!(
            hasher_alg.finalize_reset().to_vec(),
            hasher.finalize_reset().unwrap()
        );

        let result = hasher_alg_clone.finalize_reset();
        hasher_alg_clone
            .write_all(&initial_digest(output_size)[..])
            .unwrap();
        hasher_alg_clone.write_all(&result[..]).unwrap();

        assert_eq!(
            hasher_clone.tpm_extend_finalize_reset().unwrap(),
            hasher_alg_clone.finalize_reset().to_vec()
        );
    }

    #[test]
    fn test_hash_with_writes_of_different_sizes() {
        hash_with_writes_of_different_sizes(Sha256::new(), INPUT_BLOCK_SIZE_SHA256);
        hash_with_writes_of_different_sizes(Sha384::new(), INPUT_BLOCK_SIZE_SHA512);
        hash_with_writes_of_different_sizes(Sha512::new(), INPUT_BLOCK_SIZE_SHA512);
    }

    fn hash_with_writes_of_different_sizes<T: Digest + Debug + Write + Clone>(
        hasher_alg: T,
        block_size: usize,
    ) {
        let data = vec![78u8; block_size * 256];
        let mut hasher_in_one_go = EifHasher::new(block_size, hasher_alg.clone()).unwrap();
        let mut hasher_in_random_chunks = EifHasher::new(block_size, hasher_alg.clone()).unwrap();
        let mut hasher_one_byte_at_atime = EifHasher::new(block_size, hasher_alg.clone()).unwrap();

        hasher_in_one_go.write_all(&data).unwrap();
        let mut remaining = &data[..];
        let mut iteration = 1;
        while !remaining.is_empty() {
            let chunk_size = std::cmp::max(1, (iteration % remaining.len()) % block_size);
            let (to_be_written, unhandled) = remaining.split_at(chunk_size);
            hasher_in_random_chunks.write_all(&to_be_written).unwrap();

            remaining = unhandled;
            iteration += 1987;
        }

        for x in data {
            hasher_one_byte_at_atime.write_all(&[x]).unwrap();
        }

        let result1 = hasher_in_one_go.finalize_reset().unwrap();
        let result2 = hasher_in_random_chunks.finalize_reset().unwrap();
        let result3 = hasher_one_byte_at_atime.finalize_reset().unwrap();
        assert_eq!(result1, result2);
        assert_eq!(result1, result3);
    }

    #[test]
    fn test_no_cache() {
        let data = vec![78u8; 127 * 256];
        let mut eif_hasher = EifHasher::new_without_cache(Sha384::new()).unwrap();
        let mut hasher = Sha384::new();

        hasher.write_all(&data[..]).unwrap();
        for value in data {
            eif_hasher.write(&[value]).unwrap();
        }

        let result1 = eif_hasher.finalize_reset().unwrap();
        let result2 = hasher.finalize_reset();
        assert_eq!(result1, result2.to_vec());
    }
}
