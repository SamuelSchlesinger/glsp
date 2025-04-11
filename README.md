# GLSP (General Linear Sum Protocol)

An implementation of the general linear sum sigma protocol.

## Overview

GLSP is a zero-knowledge proof library for proving knowledge of a secret value
without revealing the secret itself. This Rust library provides a type-safe
implementation based on the general linear sum protocol, which is useful for
various cryptographic applications.

## Features

- Type-safe representations of statements, secrets, proofs, and public values
- Generic implementation that works with any group that implements the `Group` trait
- Constant-time operations to help prevent timing attacks
- Serialization support

## Usage Example

```rust
use glsp::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

// Create parameters for a statement with 2 secret values and 3 public points
const M: usize = 2; // Number of secret values
const N: usize = 3; // Number of public points

// Initialize a cryptographically secure random number generator
let mut rng = ChaCha20Rng::seed_from_u64(42); // Use a secure random seed in production

// Generate a random secret
let secret = Secret::<N, RistrettoPoint>::random(&mut rng);

// Generate a random statement
let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);

// Compute the public value from the secret and statement
let public = statement.compute_public(&secret);

// Sign a message with the secret to produce a proof
let message = b"example message";
let proof = statement.sign(&secret, &public, message, &mut rng);

// Verify the proof using the public value
let is_valid = statement.verify(&proof, message, &public);
assert!(is_valid);
```

## Key Components

- **Secret**: Represents the private key in the protocol, consisting of an
  array of scalar values.
- **Statement**: Defines the linear relations that the secret must satisfy,
  represented as a matrix of group elements.
- **Public**: Represents the public key derived from the secret and statement.
- **Proof**: Contains a challenge scalar and response scalars that allow
  verification without revealing the secret.

## Benchmarks

The repository includes benchmarks to evaluate the performance of the protocol
with various parameter sizes.

## References

This implementation is based on the General Linear Sum Protocol described in
section 19.5.3 of "A Graduate Course in Applied Cryptography" by Dan Boneh and
Victor Shoup.
