use super::*;
use crate::verifiers::{
    gpu::{GpuLocalVerifier, GpuRemoteVerifier},
    nvswitch::{NvSwitchLocalVerifier, NvSwitchRemoteVerifier},
    policy::{PolicyValidatorBuilder, CustomPolicyValidator},
};

const TEST_DEVICE_ID: &str = "test-device-001";
const TEST_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9+JzjxWjyJ9K4ZvQ7aJjN9m6jZ9ZQ
aJj0xvBhFoA==
-----END PUBLIC KEY-----";

#[test]
fn test_attestation_lifecycle() {
    let mut attestation = Attestation::new(Some("test-client".to_string()));
    
    // Set up attestation
    attestation.set_name("test-client".to_string());
    assert_eq!(attestation.get_name(), Some("test-client"));
    
    attestation.set_nonce_server("https://nonce.example.com".to_string());
    assert_eq!(attestation.get_nonce_server(), Some("https://nonce.example.com"));
    
    let nonce = attestation.generate_nonce();
    assert_eq!(attestation.get_nonce(), Some(nonce.as_str()));
}

#[test]
fn test_gpu_local_verifier() {
    let verifier = GpuLocalVerifier::new(
        TEST_DEVICE_ID.to_string(),
        TEST_PUBLIC_KEY,
    ).unwrap();
    
    let evidence = verifier.get_evidence(false).unwrap();
    match evidence {
        Evidence::GpuLocal(claims) => {
            assert_eq!(claims.device_id, TEST_DEVICE_ID);
            assert!(!claims.measurements.is_empty());
            assert!(!claims.certificates.is_empty());
        },
        _ => panic!("Wrong evidence type"),
    }
}

#[test]
fn test_policy_validation() {
    let validator = PolicyValidatorBuilder::new()
        .require_measurement("PCR0")
        .require_certificate("DEVICE")
        .set_max_age(3600)
        .allow_device_ids(vec![TEST_DEVICE_ID.to_string()])
        .allow_algorithms(vec!["SHA256".to_string()])
        .build();
    
    let claims = VerifierClaims {
        device_id: TEST_DEVICE_ID.to_string(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        measurements: vec![
            Measurement {
                r#type: "PCR0".to_string(),
                value: "0000".to_string(),
                algorithm: "SHA256".to_string(),
            },
        ],
        certificates: vec![
            Certificate {
                r#type: "DEVICE".to_string(),
                value: TEST_PUBLIC_KEY.to_string(),
            },
        ],
        signature: "0000".to_string(),
    };
    
    assert!(validator.validate(&claims).unwrap());
}

#[test]
fn test_jwt_token_lifecycle() {
    let mut attestation = Attestation::new(Some("test-client".to_string()));
    
    // Create and set token
    let token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...";
    attestation.set_token("test-client", token);
    
    // Get token back
    assert_eq!(attestation.get_token(None), Some(token));
    assert_eq!(attestation.get_token(Some("test-client")), Some(token));
    
    // Decode token (this will fail with our dummy token)
    assert!(attestation.decode_token(token).is_err());
}

#[test]
fn test_evidence_verification() {
    let verifier = GpuLocalVerifier::new(
        TEST_DEVICE_ID.to_string(),
        TEST_PUBLIC_KEY,
    ).unwrap();
    
    let evidence = verifier.get_evidence(false).unwrap();
    assert!(verifier.verify(&evidence).unwrap());
    
    // Test with wrong device ID
    let wrong_verifier = GpuLocalVerifier::new(
        "wrong-device".to_string(),
        TEST_PUBLIC_KEY,
    ).unwrap();
    assert!(!wrong_verifier.verify(&evidence).unwrap());
}
