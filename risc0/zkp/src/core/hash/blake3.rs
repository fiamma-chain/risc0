//! A Blake3 HashSuite.
use super::sha::{Block, Sha256};
use super::{HashFn, HashSuite, Rng, RngFactory};
use crate::core::digest::{Digest, DIGEST_WORDS};
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::marker::PhantomData;
use rand_core::{impls, Error, RngCore};
use risc0_core::field::{
    baby_bear::{BabyBear, BabyBearElem, BabyBearExtElem},
    Elem, ExtElem,
};

/// A Blake3-based [Sha256] implementation.
#[derive(Default, Clone)]
pub struct Blake3Impl {}

impl Sha256 for Blake3Impl {
    type DigestPtr = Box<Digest>;

    fn hash_bytes(bytes: &[u8]) -> Self::DigestPtr {
        let digest = blake3::hash(bytes);
        let words: Vec<u32> = digest
            .as_bytes()
            .chunks(4)
            .map(|chunk| u32::from_ne_bytes(chunk.try_into().unwrap()))
            .collect();
        Box::new(Digest::from(
            <[u32; DIGEST_WORDS]>::try_from(words).unwrap(),
        ))
    }

    #[inline]
    fn hash_raw_data_slice<T: bytemuck::NoUninit>(data: &[T]) -> Self::DigestPtr {
        Self::hash_bytes(bytemuck::cast_slice(data))
    }

    fn compress(state: &Digest, block_half1: &Digest, block_half2: &Digest) -> Self::DigestPtr {
        // Create a Blake3 hasher with the state as key
        let mut hasher = blake3::Hasher::new_keyed(state.as_bytes().try_into().unwrap());

        // Update with both half blocks
        hasher.update(block_half1.as_bytes());
        hasher.update(block_half2.as_bytes());

        // Finalize and convert to our Digest format
        let digest = hasher.finalize();
        let words: Vec<u32> = digest
            .as_bytes()
            .chunks(4)
            .map(|chunk| u32::from_ne_bytes(chunk.try_into().unwrap()))
            .collect();
        Box::new(Digest::from(
            <[u32; DIGEST_WORDS]>::try_from(words).unwrap(),
        ))
    }

    fn compress_slice(state: &Digest, blocks: &[Block]) -> Self::DigestPtr {
        // Create a Blake3 hasher with the state as key
        let mut hasher = blake3::Hasher::new_keyed(state.as_bytes().try_into().unwrap());

        // Update with all blocks
        for block in blocks {
            hasher.update(block.as_bytes());
        }

        // Finalize and convert to our Digest format
        let digest = hasher.finalize();
        let words: Vec<u32> = digest
            .as_bytes()
            .chunks(4)
            .map(|chunk| u32::from_ne_bytes(chunk.try_into().unwrap()))
            .collect();
        Box::new(Digest::from(
            <[u32; DIGEST_WORDS]>::try_from(words).unwrap(),
        ))
    }
}

/// Hash function trait.
pub trait Blake3: Send + Sync {
    /// A function producing a hash from a list of u8.
    fn blake3<T: AsRef<[u8]>>(data: T) -> [u8; 32];
}

/// Implementation of blake3 using CPU.
pub struct Blake3CpuImpl;

/// Type alias for Blake3 HashSuite using CPU.
pub type Blake3CpuHashSuite = Blake3HashSuite<Blake3CpuImpl>;

impl Blake3 for Blake3CpuImpl {
    fn blake3<T: AsRef<[u8]>>(data: T) -> [u8; 32] {
        blake3::hash(data.as_ref()).into()
    }
}

struct Blake3RngFactory<T: Blake3> {
    phantom: PhantomData<T>,
}

impl<T: Blake3> Blake3RngFactory<T> {
    fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<T: Blake3 + 'static> RngFactory<BabyBear> for Blake3RngFactory<T> {
    fn new_rng(&self) -> Box<dyn Rng<BabyBear>> {
        let rng: Blake3Rng<T> = Blake3Rng::new();
        Box::new(rng)
    }
}

/// Blake3 HashSuite.
/// We are using a generic hasher to allow different implementations.
pub struct Blake3HashSuite<T: Blake3> {
    phantom: PhantomData<T>,
}

impl<T: Blake3 + 'static> Blake3HashSuite<T> {
    /// Create a new HashSuite
    pub fn new_suite() -> HashSuite<BabyBear> {
        HashSuite {
            name: "blake3".into(),
            hashfn: Rc::new(Blake3HashFn::<T>::new()),
            rng: Rc::new(Blake3RngFactory::<T>::new()),
        }
    }
}

/// Blake3 HashFn.
struct Blake3HashFn<T: Blake3> {
    phantom: PhantomData<T>,
}

impl<T: Blake3> Blake3HashFn<T> {
    fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<T: Blake3> HashFn<BabyBear> for Blake3HashFn<T> {
    fn hash_pair(&self, a: &Digest, b: &Digest) -> Box<Digest> {
        let concat = [a.as_bytes(), b.as_bytes()].concat();
        Box::new(Digest::from(T::blake3(concat)))
    }

    fn hash_elem_slice(&self, slice: &[BabyBearElem]) -> Box<Digest> {
        let mut data = Vec::<u8>::new();
        for el in slice {
            data.extend_from_slice(el.as_u32_montgomery().to_be_bytes().as_slice());
        }
        Box::new(Digest::from(T::blake3(data)))
    }

    fn hash_ext_elem_slice(&self, slice: &[BabyBearExtElem]) -> Box<Digest> {
        let mut data = Vec::<u8>::new();
        for ext_el in slice {
            for el in ext_el.subelems() {
                data.extend_from_slice(el.as_u32_montgomery().to_be_bytes().as_slice());
            }
        }
        Box::new(Digest::from(T::blake3(data)))
    }
}

/// Blake3-based random number generator.
pub struct Blake3Rng<T: Blake3> {
    current: [u8; 32],
    hasher: PhantomData<T>,
}

impl<T: Blake3> Blake3Rng<T> {
    fn new() -> Self {
        Self {
            current: [0; 32],
            hasher: Default::default(),
        }
    }
}

impl<T: Blake3> Rng<BabyBear> for Blake3Rng<T> {
    fn mix(&mut self, val: &Digest) {
        let concat = [self.current.as_ref(), val.as_bytes()].concat();
        self.current = T::blake3(concat);
    }

    fn random_bits(&mut self, bits: usize) -> u32 {
        ((1 << bits) - 1) & self.next_u32()
    }

    fn random_elem(&mut self) -> BabyBearElem {
        BabyBearElem::random(self)
    }

    fn random_ext_elem(&mut self) -> BabyBearExtElem {
        BabyBearExtElem::random(self)
    }
}

impl<T: Blake3> RngCore for Blake3Rng<T> {
    fn next_u32(&mut self) -> u32 {
        let next = T::blake3(self.current);
        self.current = next;
        ((next[0] as u32) << 24)
            + ((next[1] as u32) << 16)
            + ((next[2] as u32) << 8)
            + (next[3] as u32)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_u32(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
