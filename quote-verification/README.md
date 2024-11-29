# NVTrust Quote Verification

Quote verification module for the NVTrust Rust implementation, providing secure validation of hardware attestation quotes.

## Overview

The quote verification module ensures the authenticity and integrity of hardware attestation quotes from various trusted execution environments. It supports multiple quote formats including TDX, SGX, and SEV.

## Features

### Quote Verification

- TDX quote verification
- SGX quote verification
- SEV quote verification
- Custom quote format support

### Security Features

- Signature validation
- Measurement verification
- Certificate chain validation
- Platform info verification
- TCB version checking

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
rust-nvtrust-quote-verification = { version = "0.1.0" }
```

### Basic Example

```rust
use rust_nvtrust_quote_verification::{
    QuoteVerifier,
    TDXQuoteVerifier,
    QuoteVerificationConfig,
};

// Initialize verifier with root key
let root_key = vec![0; 32]; // Replace with actual root key
let verifier = TDXQuoteVerifier::new(root_key);

// Configure verification parameters
let config = QuoteVerificationConfig {
    allowed_measurements: vec![/* allowed measurements */],
    trusted_certificates: vec![/* trusted certificates */],
    max_quote_age_seconds: 3600,
};

// Verify quote
let result = verifier.verify_quote(&quote, &config)?;
```

### Advanced Usage

```rust
// SEV quote verification
let mut sev_verifier = SEVQuoteVerifier::new(sev_root_key);
sev_verifier.set_platform_info(platform_info);

// Verify attestation report
let result = sev_verifier.verify_attestation_report(&report, &config)?;
```

## Parallel Validation

The quote verification module supports parallel validation of multiple quotes using Rayon. This is particularly useful when verifying a large number of quotes simultaneously.

### Basic Parallel Verification

```rust
use rust_nvtrust_quote_verification::{SEVSNPQuoteVerifier, QuoteVerificationConfig};

let verifier = SEVSNPQuoteVerifier::new(root_key);
let quotes: Vec<&[u8]> = /* multiple quotes */;

// Verify quotes in parallel
let results = verifier.verify_quotes_parallel(&quotes, &config);
```

### Batch Verification

For better performance when verifying multiple quotes, use batch verification:

```rust
// Batch verify quotes
let batch_result = verifier.batch_verify_quotes(&quotes, &config)?;

// Process results
for result in batch_result.results {
    if result.is_valid {
        // Quote is valid
    }
}
```

### Parallel Quote Verifier

The `ParallelQuoteVerifier` supports multiple quote types:

```rust
use rust_nvtrust_quote_verification::{
    ParallelQuoteVerifier,
    TDXQuoteVerifier,
    SEVQuoteVerifier,
    SEVSNPQuoteVerifier,
};

let mut verifier = ParallelQuoteVerifier::new();

// Add verifiers for different quote types
verifier.add_verifier(Box::new(TDXQuoteVerifier::new(tdx_key)));
verifier.add_verifier(Box::new(SEVQuoteVerifier::new(sev_key)));
verifier.add_verifier(Box::new(SEVSNPQuoteVerifier::new(snp_key)));

// Verify multiple quotes in parallel
let results = verifier.verify_quotes_parallel(&quotes, &config);
```

### Performance Considerations

- Parallel validation works best with a large number of quotes
- Each quote is validated independently
- Memory usage scales with the number of quotes
- CPU utilization increases with parallel validation

## Security Considerations

1. Quote Validation
   - Signature verification
   - Measurement checks
   - Timestamp validation
   - Certificate verification

2. Platform Security
   - TCB version validation
   - Platform info verification
   - Policy enforcement

3. Key Management
   - Secure root key storage
   - Regular key updates
   - Key access control

## API Documentation

### QuoteVerifier Trait

The core trait for quote verification:

```rust
pub trait QuoteVerifier {
    fn verify_quote(
        &self,
        quote: &[u8],
        config: &QuoteVerificationConfig,
    ) -> Result<QuoteVerificationResult, QuoteVerificationError>;
    
    fn verify_attestation_report(
        &self,
        report: &AttestationReport,
        config: &QuoteVerificationConfig,
    ) -> Result<QuoteVerificationResult, QuoteVerificationError>;
}
```

### Supported Quote Types

- TDX Quotes
- SGX Quotes
- SEV Quotes
  - Standard SEV
  - SEV-ES
  - SEV-SNP (planned)

## Quote Format Details

### TDX Quote Structure

```rust
Header (16 bytes)
- Version
- SVN
- Policy
- Signature Algorithm

Body (variable)
- Measurement (48 bytes)
- Additional Data
- TCB Info
- Platform Info

Signature (64 bytes)
```

### SEV Quote Structure

```rust
Header (16 bytes)
- Version
- Guest SVN
- Policy
- Signature Algorithm

Body (variable)
- Measurement (48 bytes)
- Host Data
- Launch TCB
- Platform Info

Signature (variable)
```

### SEV-SNP Quote Structure

```rust
Header (20 bytes)
- Version (4 bytes)
- Policy (4 bytes)
- Signature Algorithm (4 bytes)
- Platform Version (4 bytes)
- Platform Info (4 bytes)

Body (variable)
- Measurement (48 bytes)
- Host Data (32 bytes)
- ID Key Digest (32 bytes)
- Author Key Digest (32 bytes)
- Report Data (32 bytes)
- Chip ID (32 bytes)
- Committed TCB (8 bytes)
- Current TCB (8 bytes)
- Platform Info (variable)

Signature (64 bytes)
- ECDSA P256 Signature
```


## Testing

Run the test suite:
```bash
cargo test --package rust-nvtrust-quote-verification
```

## License

Copyright 2024 Muhammad-Jibril B. Al-Sharif. All rights reserved.
