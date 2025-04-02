#![feature(generic_const_exprs)]

use group::Group;
use group::ff::Field;
use rand_core::{CryptoRngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;

pub struct Secret<const N: usize, G: Group> {
    alpha: [G::Scalar; N],
}

impl<const N: usize, G: Group + Default> Secret<N, G> 
where 
    G::Scalar: Default,
{
    pub fn random(mut rng: impl CryptoRngCore) -> Self 
    where
        G::Scalar: Default,
    {
        let mut alpha = vec![G::Scalar::default(); N];
        for i in 0..N {
            alpha[i] = G::Scalar::random(&mut rng);
        }
        Self {
            alpha: alpha.try_into().unwrap(),
        }
    }
}

pub struct Public<const N: usize, G: Group> {
    u: [G; N],
}

pub struct Statement<const M: usize, const N: usize, G: Group> {
    g: [[G; M]; N],
}

impl<const M: usize, const N: usize, G: Group + Default> Statement<M, N, G> 
where
    G::Scalar: Default,
{
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        let mut g = Vec::with_capacity(N);
        for _ in 0..N {
            let mut row = vec![G::default(); M];
            for j in 0..M {
                row[j] = G::generator() * G::Scalar::random(&mut rng);
            }
            g.push(row.try_into().unwrap());
        }
        Self {
            g: g.try_into().unwrap(),
        }
    }
    
    pub fn compute_public(&self, secret: &Secret<N, G>) -> Public<N, G> 
    where
        G: Default,
    {
        let mut u = vec![G::default(); N];
        for i in 0..N {
            let mut acc = G::identity();
            for j in 0..M {
                acc += self.g[i][j] * secret.alpha[j];
            }
            u[i] = acc;
        }
        Public {
            u: u.try_into().unwrap(),
        }
    }
}

pub struct Proof<const N: usize, G: Group> {
    c: G::Scalar,
    alpha_z: [G::Scalar; N],
}

impl<const M: usize, const N: usize, G: Group + Serialize + Default> Statement<M, N, G>
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
        
        let mut u_t: [G; N] = [G::default(); N];
        for i in 0..N {
            let mut acc = G::identity();
            for j in 0..M {
                acc += self.g[i][j] * alpha_t[j];
            }
            u_t[i] = acc;
        }
        
        let mut u_t_bytes: [u8; 32 * N] = [0u8; 32 * N];
        for i in 0..N {
            bincode::serde::encode_into_slice(
                u_t[i],
                &mut u_t_bytes[i * 32 .. (i + 1) * 32],
                bincode::config::standard()
            ).unwrap();
        }
        
        hasher.update(&u_t_bytes);
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
        let mut u_z_minus_cu: [G; N] = [G::default(); N];
        for i in 0..N {
            let b = {
                let mut acc = G::identity();
                for j in 0..M {
                    acc += self.g[i][j] * proof.alpha_z[j];
                }
                acc
            };
            u_z_minus_cu[i] = b - (public.u[i] * proof.c);
        }
        
        let mut u_t_bytes: [u8; 32 * N] = [0u8; 32 * N];
        for i in 0..N {
            bincode::serde::encode_into_slice(
                u_z_minus_cu[i], 
                &mut u_t_bytes[i * 32 .. (i + 1) * 32],
                bincode::config::standard()
            ).unwrap();
        }
        hasher.update(&u_t_bytes);
        let rng = ChaCha20Rng::from_seed(*hasher.finalize().as_bytes());
        let c = G::Scalar::random(rng);
        
        c == proof.c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_POINT,
        ristretto::RistrettoPoint,
        Scalar,
    };
    
   
    #[test]
    fn test_small_statement() {
        // Test with M=1, N=1
        const M: usize = 1;
        const N: usize = 1;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let secret = Secret::<N, RistrettoPoint>::random(&mut rng);
        let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);
        let public = statement.compute_public(&secret);
        
        let message = b"test message";
        let proof = statement.sign(&secret, message, &mut rng);
        
        assert!(statement.verify(&proof, message, &public));
        
        // Test with different message should fail
        let different_message = b"different message";
        assert!(!statement.verify(&proof, different_message, &public));
    }
    
    #[test]
    fn test_medium_statement() {
        // Test with M=2, N=3
        const M: usize = 2;
        const N: usize = 3;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let secret = Secret::<N, RistrettoPoint>::random(&mut rng);
        let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);
        let public = statement.compute_public(&secret);
        
        let message = b"test message for medium-sized statement";
        let proof = statement.sign(&secret, message, &mut rng);
        
        assert!(statement.verify(&proof, message, &public));
    }
    
    #[test]
    fn test_large_statement() {
        // Test with M=5, N=10
        const M: usize = 5;
        const N: usize = 10;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let secret = Secret::<N, RistrettoPoint>::random(&mut rng);
        let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);
        let public = statement.compute_public(&secret);
        
        let message = b"test message for large statement with more parameters";
        let proof = statement.sign(&secret, message, &mut rng);
        
        assert!(statement.verify(&proof, message, &public));
    }
    
    #[test]
    fn test_tampered_proof_challenge() {
        // Test with tampered challenge value
        const M: usize = 2;
        const N: usize = 2;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let secret = Secret::<N, RistrettoPoint>::random(&mut rng);
        let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);
        let public = statement.compute_public(&secret);
        
        let message = b"test message";
        let mut proof = statement.sign(&secret, message, &mut rng);
        
        // Tamper with the challenge value
        proof.c = Scalar::random(&mut rng);
        
        // The tampered proof should not verify
        assert!(!statement.verify(&proof, message, &public));
    }
    
    #[test]
    fn test_tampered_proof_alpha_z() {
        // Test with tampered alpha_z values
        const M: usize = 2;
        const N: usize = 2;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let secret = Secret::<N, RistrettoPoint>::random(&mut rng);
        let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);
        let public = statement.compute_public(&secret);
        
        let message = b"test message";
        let mut proof = statement.sign(&secret, message, &mut rng);
        
        // Tamper with one of the alpha_z values
        proof.alpha_z[0] = Scalar::random(&mut rng);
        
        // The tampered proof should not verify
        assert!(!statement.verify(&proof, message, &public));
    }
    
    #[test]
    fn test_tampered_proof_all_alpha_z() {
        // Test with all alpha_z values tampered
        const M: usize = 3;
        const N: usize = 3;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let secret = Secret::<N, RistrettoPoint>::random(&mut rng);
        let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);
        let public = statement.compute_public(&secret);
        
        let message = b"test message";
        let mut proof = statement.sign(&secret, message, &mut rng);
        
        // Tamper with all alpha_z values
        for i in 0..N {
            proof.alpha_z[i] = Scalar::random(&mut rng);
        }
        
        // The tampered proof should not verify
        assert!(!statement.verify(&proof, message, &public));
    }
    
    #[test]
    fn test_tampered_public_key() {
        // Test with tampered public key
        const M: usize = 2;
        const N: usize = 2;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let secret = Secret::<N, RistrettoPoint>::random(&mut rng);
        let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);
        let mut public = statement.compute_public(&secret);
        
        let message = b"test message";
        let proof = statement.sign(&secret, message, &mut rng);
        
        // Tamper with the public key
        public.u[0] = RistrettoPoint::generator() * Scalar::random(&mut rng);
        
        // The proof should not verify with the tampered public key
        assert!(!statement.verify(&proof, message, &public));
    }
}
