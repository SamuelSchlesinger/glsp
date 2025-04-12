//! # GLSP (General Linear Sum Protocol)
//! 
//! An implementation of the general linear sum sigma protocol from Boneh-Shoup.
//! 
//! This library provides a zero-knowledge proof system for proving knowledge of a secret
//! value without revealing the secret itself. It's based on the general linear sum
//! protocol which is useful for various cryptographic applications.
//! 
//! ## Features
//! 
//! - Type-safe representations of statements, secrets, proofs, and public values
//! - Generic implementation that works with any group that implements the `Group` trait
//! - Constant-time operations to help prevent timing attacks
//! - Serialization support
//! 
//! ## Example
//! 
//! ```rust
//! # use glsp::*;
//! # use curve25519_dalek::{ristretto::RistrettoPoint};
//! # use rand_chacha::ChaCha20Rng;
//! # use rand_core::SeedableRng;
//! # 
//! // Create parameters for a statement with 3 secret values and 2 public points
//! const M: usize = 2; // Number of public points
//! const N: usize = 3; // Number of secret values
//! 
//! // Initialize a cryptographically secure random number generator
//! let mut rng = ChaCha20Rng::seed_from_u64(42); // Use a secure random seed in production
//! 
//! // Generate a random secret
//! let secret = Secret::<N, RistrettoPoint>::random(&mut rng);
//! 
//! // Generate a random statement
//! let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);
//! 
//! // Compute the public value from the secret and statement
//! let public = statement.compute_public(&secret);
//! 
//! // Sign a message with the secret to produce a proof
//! let message = b"example message";
//! let proof = statement.sign(&secret, &public, message, &mut rng);
//! 
//! // Verify the proof using the public value
//! let is_valid = statement.verify(&proof, message, &public);
//! assert!(is_valid);
//! ```

use group::Group;
use group::ff::Field;
use rand_core::{CryptoRngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;

/// Represents a secret key in the protocol.
///
/// The secret consists of an array of `N` scalar values from the given group `G`.
/// These scalar values are kept private and are used to generate proofs.
///
/// Type parameters:
/// - `N`: The number of scalar values in the secret
/// - `G`: The elliptic curve group implementation
pub struct Secret<const N: usize, G: Group> {
    alpha: [G::Scalar; N],
}

impl<const N: usize, G: Group + Default> Secret<N, G> 
{
    /// Creates a new random secret using the provided random number generator.
    ///
    /// This generates `N` random scalar values for the secret.
    ///
    /// # Arguments
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    /// A new `Secret` instance with randomly generated values
    ///
    /// # Example
    /// ```
    /// # use glsp::*;
    /// # use curve25519_dalek::ristretto::RistrettoPoint;
    /// # use rand_chacha::ChaCha20Rng;
    /// # use rand_core::SeedableRng;
    /// #
    /// let mut rng = ChaCha20Rng::seed_from_u64(42);
    /// let secret = Secret::<3, RistrettoPoint>::random(&mut rng);
    /// ```
    pub fn random(mut rng: impl CryptoRngCore) -> Self 
    {
        let mut alpha = vec![G::Scalar::ZERO; N];
        for i in 0..N {
            alpha[i] = G::Scalar::random(&mut rng);
        }
        Self {
            alpha: alpha.try_into().unwrap(),
        }
    }
}

/// Represents the public key in the protocol.
///
/// The public key consists of an array of `M` group elements from the given group `G`.
/// These values are derived from the secret and the statement, and can be publicly shared.
///
/// Type parameters:
/// - `M`: The number of group elements in the public key
/// - `G`: The elliptic curve group implementation
pub struct Public<const M: usize, G: Group> {
    u: [G; M],
}

/// Represents a statement in the zero-knowledge proof system.
///
/// A statement is a 2D array of group elements that define the linear relations
/// that the secret must satisfy. It is essentially a matrix of base points.
///
/// Type parameters:
/// - `M`: The number of public points (rows)
/// - `N`: The number of secret values (columns)
/// - `G`: The elliptic curve group implementation
pub struct Statement<const M: usize, const N: usize, G: Group> {
    g: [[G; N]; M],
}

impl<const M: usize, const N: usize, G: Group + Default> Statement<M, N, G> 
{
    /// Creates a new random statement using the provided random number generator.
    ///
    /// This generates an M×N matrix of random group elements for the statement.
    /// Each element is a random scalar multiple of the group generator.
    ///
    /// # Arguments
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    /// A new `Statement` instance with randomly generated values
    ///
    /// # Example
    /// ```
    /// # use glsp::*;
    /// # use curve25519_dalek::ristretto::RistrettoPoint;
    /// # use rand_chacha::ChaCha20Rng;
    /// # use rand_core::SeedableRng;
    /// #
    /// const M: usize = 3;
    /// const N: usize = 2;
    /// let mut rng = ChaCha20Rng::seed_from_u64(42);
    /// let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);
    /// ```
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        let mut g = Vec::with_capacity(N);
        for _ in 0..M {
            let mut row = vec![G::default(); N];
            for j in 0..N {
                row[j] = G::generator() * G::Scalar::random(&mut rng);
            }
            g.push(row.try_into().unwrap());
        }
        Self {
            g: g.try_into().unwrap(),
        }
    }
    
    /// Computes the public key corresponding to a given secret.
    ///
    /// This calculation performs the linear combination of statement elements with
    /// the secret scalars to produce the public key values.
    ///
    /// # Arguments
    /// * `secret` - The secret key
    ///
    /// # Returns
    /// A `Public` key instance derived from the secret and this statement
    ///
    /// # Example
    /// ```
    /// # use glsp::*;
    /// # use curve25519_dalek::ristretto::RistrettoPoint;
    /// # use rand_chacha::ChaCha20Rng;
    /// # use rand_core::SeedableRng;
    /// #
    /// const M: usize = 3;
    /// const N: usize = 2;
    /// let mut rng = ChaCha20Rng::seed_from_u64(42);
    /// let secret = Secret::<N, RistrettoPoint>::random(&mut rng);
    /// let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);
    /// let public = statement.compute_public(&secret);
    /// ```
    pub fn compute_public(&self, secret: &Secret<N, G>) -> Public<M, G> 
    where
        G: Default,
    {
        let mut u = vec![G::default(); M];
        for i in 0..M {
            let mut acc = G::identity();
            for j in 0..N {
                acc += self.g[i][j] * secret.alpha[j];
            }
            u[i] = acc;
        }
        Public {
            u: u.try_into().unwrap(),
        }
    }
}

/// Represents a zero-knowledge proof of knowledge of the secret.
///
/// A proof consists of a challenge scalar `c` and a vector of response scalars `alpha_z`.
/// The proof allows verification that the prover knows the secret without revealing it.
///
/// Type parameters:
/// - `N`: The number of scalars in the response vector
/// - `G`: The elliptic curve group implementation
pub struct Proof<const N: usize, G: Group> {
    /// The challenge scalar
    c: G::Scalar,
    /// The response scalars
    alpha_z: [G::Scalar; N],
}

impl<const M: usize, const N: usize, G: Group + Serialize + Default> Statement<M, N, G>
{
    /// Signs a message using the secret key to produce a zero-knowledge proof.
    ///
    /// This implements the sigma protocol for producing a proof of knowledge
    /// of the secret without revealing it. The proof is bound to the given message.
    ///
    /// # Arguments
    /// * `secret` - The secret key
    /// * `message` - The message to sign
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    /// A `Proof` that can be verified using the public key
    ///
    /// # Example
    /// ```
    /// # use glsp::*;
    /// # use curve25519_dalek::ristretto::RistrettoPoint;
    /// # use rand_chacha::ChaCha20Rng;
    /// # use rand_core::SeedableRng;
    /// #
    /// const M: usize = 3;
    /// const N: usize = 2;
    /// let mut rng = ChaCha20Rng::seed_from_u64(42);
    /// let secret = Secret::<N, RistrettoPoint>::random(&mut rng);
    /// let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);
    /// let public = statement.compute_public(&secret);
    /// 
    /// let message = b"test message";
    /// let proof = statement.sign(&secret, &public, message, &mut rng);
    /// ```
    pub fn sign(&self, secret: &Secret<N, G>, public: &Public<M, G>, message: &[u8], mut rng: impl CryptoRngCore) -> Proof<N, G> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(message);
        for i in 0..M {
            hasher.update(&bincode::serde::encode_to_vec(&public.u[i], bincode::config::standard()).unwrap());
        }
        let mut alpha_t: [G::Scalar; N] = [G::Scalar::ZERO; N];
        for i in 0..N {
            alpha_t[i] = G::Scalar::random(&mut rng);
        }
        
        let mut u_t: [G; M] = [G::default(); M];
        for i in 0..M {
            let mut acc = G::identity();
            for j in 0..N {
                acc += self.g[i][j] * alpha_t[j];
            }
            u_t[i] = acc;
        }
        
        let mut u_t_i_bytes = [0u8; 32];
        for i in 0..M {
            bincode::serde::encode_into_slice(
                u_t[i],
                &mut u_t_i_bytes,
                bincode::config::standard()
            ).unwrap();
            hasher.update(&u_t_i_bytes);
        }
        let rng = ChaCha20Rng::from_seed(*hasher.finalize().as_bytes());
        let c = G::Scalar::random(rng);
        
        let mut alpha_z: [G::Scalar; N] = [G::Scalar::ZERO; N];
        for i in 0..N {
            alpha_z[i] = alpha_t[i] + secret.alpha[i] * c;
        }

        Proof { c, alpha_z }
    }

    /// Verifies a proof against a message and public key.
    ///
    /// This verification process checks if the provided proof is valid for the given
    /// message and public key, without requiring knowledge of the secret.
    ///
    /// # Arguments
    /// * `proof` - The proof to verify
    /// * `message` - The message that was signed
    /// * `public` - The public key corresponding to the secret
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    ///
    /// # Example
    /// ```
    /// # use glsp::*;
    /// # use curve25519_dalek::ristretto::RistrettoPoint;
    /// # use rand_chacha::ChaCha20Rng;
    /// # use rand_core::SeedableRng;
    /// #
    /// const M: usize = 2;
    /// const N: usize = 3;
    /// let mut rng = ChaCha20Rng::seed_from_u64(42);
    /// let secret = Secret::<N, RistrettoPoint>::random(&mut rng);
    /// let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);
    /// let public = statement.compute_public(&secret);
    /// 
    /// let message = b"test message";
    /// let proof = statement.sign(&secret, &public, message, &mut rng);
    /// 
    /// // Verify the proof
    /// assert!(statement.verify(&proof, message, &public));
    /// 
    /// // Verification should fail for a different message
    /// let different_message = b"different message";
    /// assert!(!statement.verify(&proof, different_message, &public));
    /// ```
    pub fn verify(&self, proof: &Proof<N, G>, message: &[u8], public: &Public<M, G>) -> bool {
        let mut hasher = blake3::Hasher::new();
        hasher.update(message);
        for i in 0..M {
            hasher.update(&bincode::serde::encode_to_vec(&public.u[i], bincode::config::standard()).unwrap());
        }
        let mut u_z_minus_cu: [G; M] = [G::default(); M];
        for i in 0..M {
            let b = {
                let mut acc = G::identity();
                for j in 0..N {
                    acc += self.g[i][j] * proof.alpha_z[j];
                }
                acc
            };
            u_z_minus_cu[i] = b - (public.u[i] * proof.c);
        }
        
        let mut u_t_i_bytes: [u8; 32] = [0u8; 32];
        for i in 0..M {
            bincode::serde::encode_into_slice(
                u_z_minus_cu[i], 
                &mut u_t_i_bytes,
                bincode::config::standard()
            ).unwrap();
            hasher.update(&u_t_i_bytes);
        }
        let rng = ChaCha20Rng::from_seed(*hasher.finalize().as_bytes());
        let c = G::Scalar::random(rng);
        
        c == proof.c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{
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
        let proof = statement.sign(&secret, &public, message, &mut rng);
        
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
        let proof = statement.sign(&secret, &public, message, &mut rng);
        
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
        let proof = statement.sign(&secret, &public, message, &mut rng);
        
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
        let mut proof = statement.sign(&secret, &public, message, &mut rng);
        
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
        let mut proof = statement.sign(&secret, &public, message, &mut rng);
        
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
        let mut proof = statement.sign(&secret, &public, message, &mut rng);
        
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
        let proof = statement.sign(&secret, &public, message, &mut rng);
        
        // Tamper with the public key
        public.u[0] = RistrettoPoint::generator() * Scalar::random(&mut rng);
        
        // The proof should not verify with the tampered public key
        assert!(!statement.verify(&proof, message, &public));
    }
}
