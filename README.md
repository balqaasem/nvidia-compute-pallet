# rust-nvtrust

NVIDIA Trusted Computing Library for Rust - A comprehensive solution for confidential computing, attestation, and quote verification.

## Overview

`rust-nvtrust` is a unified Rust library that provides secure, hardware-backed confidential computing capabilities using NVIDIA hardware. It combines attestation, confidential computing, and quote verification into a single, easy-to-use package.

## Features

- **Hardware-based Attestation**
  - TDX (Trust Domain Extensions) support
  - SGX (Software Guard Extensions) support
  - GPU attestation (local and remote)
  - NVSwitch attestation

- **Confidential Computing**
  - Secure matrix multiplication
  - Hardware-accelerated encryption (AES-256-GCM, ChaCha20-Poly1305)
  - Secure machine learning inference
  - Custom confidential operations
  - Data encryption/decryption

- **Quote Verification**
  - Policy-based verification
  - Measurement validation
  - Certificate chain verification
  - Timestamp validation

- **Substrate Integration**
  - Ready-to-use pallet for blockchain integration
  - On-chain confidential compute requests
  - Secure result verification

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
rust-nvtrust = { version = "0.1.0", features = ["std"] }
```

For no_std environments:
```toml
[dependencies]
rust-nvtrust = "0.1.0" # no_std by default
```

## Quick Start

### Basic Usage

```rust
use rust_nvtrust::{
    AttestationService,
    create_confidential_compute,
    ConfidentialOperation,
    create_default_policy_validator,
};

// Initialize attestation
let mut attestation = TDXAttestationService::new();
attestation.initialize(AttestationParams::default())?;

// Create confidential compute instance
let compute = create_confidential_compute(&attestation)?;

// Execute confidential operation
let operation = ConfidentialOperation::MatrixMultiply {
    matrix_a: vec![1.0, 2.0, 3.0, 4.0],
    matrix_b: vec![5.0, 6.0, 7.0, 8.0],
    rows_a: 2,
    cols_a: 2,
    cols_b: 2,
};

let result = compute.execute_confidential(&operation, &input_data)?;
```

### Policy-based Verification

```rust
use rust_nvtrust::verifiers::{PolicyValidatorBuilder, Evidence};

// Create policy validator
let policy = PolicyValidatorBuilder::new()
    .require_measurement("gpu_measurement")
    .allow_algorithm("sha256")
    .allow_device_id("gpu-01")
    .set_max_age(Duration::hours(24))
    .require_certificates(true)
    .build();

// Verify evidence
let is_valid = policy.validate(&evidence)?;
```

### Substrate Pallet Integration

1. Add the pallet to your runtime's dependencies:
```toml
[dependencies]
nvidia-confidential-compute-pallet = { version = "0.1.0", default-features = false }
```

2. Implement the configuration trait:
```rust
impl nvidia_confidential_compute_pallet::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type MaxDataSize = ConstU32<1048576>;
    type AttestationService = TDXAttestationService;
}
```

## Architecture

The library consists of three main components:

1. **Attestation Module**
   - Hardware attestation services
   - Quote generation and verification
   - Evidence collection and validation

2. **Confidential Computing Module**
   - Secure operation execution
   - Data encryption/decryption
   - Hardware-backed security

3. **Verification Module**
   - Policy-based verification
   - Measurement validation
   - Certificate management

## Security Considerations

- Always verify attestation reports before processing data
- Use policy validation for evidence verification
- Keep encryption keys secure
- Regularly update trusted measurements
- Monitor attestation timestamps
- Implement proper error handling

## Contributing

We welcome contributions! Please see our contributing guidelines for more information.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- NVIDIA Corporation
- OpenSSL Project
- Ring Crypto Library

## Support

For support, please:
1. Check the documentation
2. Search existing issues
3. Create a new issue if needed
