#![feature(generic_const_exprs)]

use group::Group;
use group::ff::Field;
use rand_core::{CryptoRngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;

pub struct Secret<const N: usize, G: Group> {
    alpha: [G::Scalar; N],
}

pub struct Public<const N: usize, G: Group> {
    u: [G; N],
}

pub struct Statement<const M: usize, const N: usize, G: Group> {
    g: [[G; M]; N],
}

pub struct Proof<const N: usize, G: Group> {
    c: G::Scalar,
    alpha_z: [G::Scalar; N],
}

impl<const M: usize, const N: usize, G: Group + Serialize + Default> Statement<N, M, G>
where
    [(); 32 * N]:,
{
    pub fn sign(&self, secret: &Secret<N, G>, message: &[u8], mut rng: impl CryptoRngCore) -> Proof<N, G> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(message);
        let mut alpha_t: [G::Scalar; N] = [G::Scalar::default(); N];
        for i in 0..N {
            alpha_t[i] = G::Scalar::random(&mut rng);
        }
        let mut u_t: [u8; 32 * N] = [0u8; 32 * N];
        for i in 0..N {
            bincode::serde::encode_into_slice({
                let mut acc = G::identity();
                for j in 0..M {
                    acc += self.g[i][j] * alpha_t[i];
                }
            }, &mut u_t[i * 32 .. (i + 1) * 32]
            , bincode::config::standard()
            ).unwrap();
        }
        hasher.update(&u_t);
        let rng = ChaCha20Rng::from_seed(*hasher.finalize().as_bytes());
        let c = G::Scalar::random(rng);
        
        let mut alpha_z: [G::Scalar; N] = [G::Scalar::default(); N];
        for i in 0..N {
            alpha_z[i] = alpha_t[i] + secret.alpha[i] * c;
        }

        Proof { c, alpha_z }
    }

    pub fn verify(&self, proof: &Proof<N, G>, message: &[u8], public: &Public<N, G>) -> bool {
        let mut hasher = blake3::Hasher::new();
        hasher.update(message);
        let mut u_t: [G; N] = [G::default(); N];
        for i in 0..N {
            let b = {
                let mut acc = G::identity();
                for j in 0..M {
                    acc += self.g[i][j] * proof.alpha_z[j]
                }
                acc
            };
            u_t[i] = b - public.u[i]
        }
        let mut u_t: [u8; 32 * N] = [0u8; 32 * N];
        for i in 0..N {
            bincode::serde::encode_into_slice({
                let mut acc = G::identity();
                for j in 0..M {
                    acc += self.g[i][j] * proof.alpha_z[i];
                }
            }, &mut u_t[i * 32 .. (i + 1) * 32]
            , bincode::config::standard()
            ).unwrap();
        }
        hasher.update(&u_t);
        let rng = ChaCha20Rng::from_seed(*hasher.finalize().as_bytes());
        let c = G::Scalar::random(rng);
        
        c == proof.c
    }
}
