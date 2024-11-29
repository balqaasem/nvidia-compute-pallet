#![cfg_attr(not(feature = "std"), no_std)]

// Re-export attestation module
pub use rust_nvtrust_attestation::{
    AttestationService,
    AttestationReport,
    AttestationError,
    MeasurementType,
    Device,
    Evidence,
    Verifier,
    TDXAttestationService,
    SGXAttestationService,
};

// Re-export confidential module
pub use rust_nvtrust_confidential::{
    ConfidentialCompute,
    ConfidentialContext,
    ConfidentialResult,
    ConfidentialOperation,
    ConfidentialError,
    NvidiaConfidentialCompute,
    EncryptionAlgorithm,
};

// Re-export verifiers
pub mod verifiers {
    pub use rust_nvtrust_attestation::verifiers::{
        GpuLocalVerifier,
        GpuRemoteVerifier,
        PolicyValidator,
        PolicyValidatorBuilder,
        PolicyRequirements,
        VerifierClaims,
    };
}

/// Creates a new NVIDIA confidential compute instance with attestation
pub fn create_confidential_compute<T: AttestationService>(
    attestation: &T,
) -> Result<NvidiaConfidentialCompute, ConfidentialError> {
    let mut compute = NvidiaConfidentialCompute::new();
    compute.initialize(attestation)?;
    Ok(compute)
}

/// Creates a new policy validator with common security requirements
pub fn create_default_policy_validator(
    device_id: &str,
    max_age_hours: i64,
) -> PolicyValidator {
    use chrono::Duration;
    
    verifiers::PolicyValidatorBuilder::new()
        .require_measurement("gpu_measurement")
        .allow_algorithm("sha256")
        .allow_device_id(device_id)
        .set_max_age(Duration::hours(max_age_hours))
        .require_certificates(true)
        .build()
}

/// Convenience function to verify GPU evidence
pub fn verify_gpu_evidence(
    evidence: &Evidence,
    policy: &PolicyValidator,
) -> Result<bool, AttestationError> {
    policy.validate(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_nvtrust_attestation::AttestationParams;

    #[test]
    fn test_create_confidential_compute() {
        let mut attestation = TDXAttestationService::new();
        let params = AttestationParams {
            measurement_type: MeasurementType::TDX,
            nonce: None,
            additional_data: None,
        };
        
        attestation.initialize(params).unwrap();
        let compute = create_confidential_compute(&attestation).unwrap();
    }

    #[test]
    fn test_policy_validation() {
        let device_id = "test_device";
        let policy = create_default_policy_validator(device_id, 24);
        
        // Create test evidence
        let evidence = Evidence::GpuLocal(verifiers::VerifierClaims {
            device_id: device_id.to_string(),
            timestamp: chrono::Utc::now(),
            measurements: vec![],
            algorithm: "sha256".to_string(),
            signature: vec![],
        });
        
        let result = verify_gpu_evidence(&evidence, &policy);
        assert!(result.is_ok());
    }
}
