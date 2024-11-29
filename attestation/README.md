# NVTrust Attestation

A Rust implementation of the NVTrust attestation framework, providing secure hardware attestation capabilities for NVIDIA GPUs and NVSwitch devices in confidential computing environments.

## Overview

The NVTrust attestation module enables secure verification of NVIDIA hardware components through:
- Hardware-based root of trust
- Cryptographic evidence collection
- Policy-based verification
- Local and remote attestation flows
- Comprehensive measurement validation

## Features

### Core Capabilities
- Hardware-rooted attestation for NVIDIA devices
- Flexible policy validation framework
- JWT-based token management
- Certificate chain verification
- Measurement collection and validation

### Supported Devices
- NVIDIA GPUs (Local & Remote)
- NVSwitch (Local & Remote)
- Future support for DPUs and other NVIDIA hardware

### Verification Types
- Local attestation with direct hardware access
- Remote attestation via attestation service
- Policy-based validation with customizable rules
- Certificate-based identity verification

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
nvtrust-attestation = { version = "0.1.0" }
```

## Usage Examples

### Basic Local GPU Attestation

```rust
use nvtrust_attestation::{
    Attestation,
    Device,
    Environment,
    verifiers::gpu::GpuLocalVerifier,
};

// Initialize attestation context
let mut attestation = Attestation::new(Some("gpu-client"));

// Configure GPU verifier
let verifier = GpuLocalVerifier::new(
    "gpu-0",           // Device ID
    &public_key_pem,   // Device public key
)?;

// Get and verify evidence
let evidence = verifier.get_evidence(false)?;
let is_valid = verifier.verify(&evidence)?;
```

### Custom Policy Validation

```rust
use nvtrust_attestation::verifiers::policy::PolicyValidatorBuilder;

// Build custom policy validator
let validator = PolicyValidatorBuilder::new()
    .require_measurement("PCR0")           // Require specific PCR
    .require_certificate("DEVICE_CERT")    // Require device certificate
    .set_max_age(3600)                    // Evidence must be fresh
    .allow_device_ids(vec!["gpu-0"])      // Whitelist devices
    .allow_algorithms(vec!["SHA384"])      // Allowed hash algorithms
    .build();

// Validate evidence against policy
let is_compliant = validator.validate(&evidence)?;
```

### Remote Attestation Flow

```rust
use nvtrust_attestation::{
    Device,
    Environment,
    verifiers::gpu::GpuRemoteVerifier,
};

// Initialize remote verifier
let verifier = GpuRemoteVerifier::new(
    "https://attestation.example.com",  // Attestation service URL
    "gpu-0",                           // Device ID
    &public_key_pem,                   // Service public key
)?;

// Get evidence from remote device
let evidence = verifier.get_evidence(false)?;

// Verify evidence with remote service
let verification_result = verifier.verify(&evidence)?;

// Generate JWT token for verified device
let token = verifier.generate_token(&evidence)?;
```

## Architecture

### Core Components

#### Attestation
Central struct managing the attestation lifecycle:
- Device registration
- Evidence collection
- Verification coordination
- Token management

#### Verifiers
Trait-based verifier hierarchy:
- `Verifier` - Base trait for all verifiers
- `GpuLocalVerifier` - Local GPU verification
- `GpuRemoteVerifier` - Remote GPU verification
- `NvSwitchLocalVerifier` - Local NVSwitch verification
- `NvSwitchRemoteVerifier` - Remote NVSwitch verification

#### Policy Validation
Flexible policy framework:
- `PolicyValidator` - Trait for validation rules
- `PolicyValidatorBuilder` - Builder pattern for validators
- Support for multiple validation criteria
- Extensible rule system

### Evidence Types
Comprehensive evidence collection:
- Hardware measurements (PCRs)
- Device certificates
- Cryptographic signatures
- Timestamps
- Device metadata

## Security Considerations

### Hardware Root of Trust
- Secure boot measurements
- TPM-based attestation
- Hardware-backed key storage

### Cryptographic Security
- Strong signature algorithms
- Certificate chain validation
- Secure key management
- Fresh nonce generation

### Policy Enforcement
- Strict measurement validation
- Time-based freshness checks
- Device whitelisting
- Algorithm restrictions

## Development

### Building
```bash
cargo build --release
```

### Testing
```bash
cargo test
cargo test --features integration-tests
```

### Documentation
```bash
cargo doc --no-deps --open
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT - Copyright © 2024 Muhammad-Jibril B. Al-Sharif. All rights reserved.
