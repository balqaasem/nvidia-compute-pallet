pub mod gpu;
pub mod nvswitch;
pub mod policy;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("Failed to initialize verifier")]
    InitializationError,
    #[error("Failed to generate evidence")]
    EvidenceGenerationError,
    #[error("Failed to verify evidence")]
    EvidenceVerificationError,
    #[error("Invalid measurement")]
    InvalidMeasurement,
    #[error("Invalid certificate")]
    InvalidCertificate,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid policy")]
    InvalidPolicy,
    #[error("Time error")]
    TimeError,
    #[error("Remote service error")]
    RemoteServiceError,
    #[error("Serialization error")]
    SerializationError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Measurement {
    pub r#type: String,
    pub value: String,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub r#type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierClaims {
    pub device_id: String,
    pub timestamp: u64,
    pub measurements: Vec<Measurement>,
    pub certificates: Vec<Certificate>,
    pub signature: String,
}

pub trait Verifier {
    fn get_name(&self) -> &str;
    fn get_evidence(&self, ppcie_mode: bool) -> Result<crate::Evidence, VerifierError>;
    fn verify(&self, evidence: &crate::Evidence) -> Result<bool, VerifierError>;
    fn get_claims(&self) -> Result<HashMap<String, serde_json::Value>, VerifierError>;
}

pub trait PolicyValidator {
    fn validate(&self, claims: &VerifierClaims) -> Result<bool, VerifierError>;
}

#[derive(Debug, Clone)]
pub struct BaseVerifier {
    pub device_id: String,
    pub public_key: String,
}

impl BaseVerifier {
    pub fn new(device_id: String, public_key: &str) -> Result<Self, VerifierError> {
        if device_id.is_empty() {
            return Err(VerifierError::InitializationError);
        }
        Ok(Self {
            device_id,
            public_key: public_key.to_string(),
        })
    }

    pub fn verify_signature(&self, data: &[u8], signature: &str) -> Result<bool, VerifierError> {
        use openssl::sign::Verifier as OpenSSLVerifier;
        use openssl::pkey::PKey;
        use openssl::hash::MessageDigest;

        let key = PKey::public_key_from_pem(self.public_key.as_bytes())
            .map_err(|_| VerifierError::InvalidSignature)?;

        let signature_bytes = base64::decode(signature)
            .map_err(|_| VerifierError::InvalidSignature)?;

        let mut verifier = OpenSSLVerifier::new(MessageDigest::sha384(), &key)
            .map_err(|_| VerifierError::InvalidSignature)?;

        verifier.update(data)
            .map_err(|_| VerifierError::InvalidSignature)?;

        verifier.verify(&signature_bytes)
            .map_err(|_| VerifierError::InvalidSignature)
    }

    pub fn verify_certificate_chain(&self, certificates: &[Certificate]) -> Result<bool, VerifierError> {
        use openssl::x509::X509;
        use openssl::stack::Stack;

        if certificates.is_empty() {
            return Err(VerifierError::InvalidCertificate);
        }

        // Build certificate chain
        let mut cert_stack = Stack::new()
            .map_err(|_| VerifierError::InvalidCertificate)?;

        for cert in certificates {
            let x509 = X509::from_pem(cert.value.as_bytes())
                .map_err(|_| VerifierError::InvalidCertificate)?;
            cert_stack.push(x509)
                .map_err(|_| VerifierError::InvalidCertificate)?;
        }

        // TODO: Implement full chain validation
        // For now, just check that all certs are valid X509
        Ok(true)
    }

    pub fn verify_measurements(&self, measurements: &[Measurement]) -> Result<bool, VerifierError> {
        if measurements.is_empty() {
            return Err(VerifierError::InvalidMeasurement);
        }

        for measurement in measurements {
            // Validate measurement format
            if measurement.value.is_empty() || measurement.algorithm.is_empty() {
                return Err(VerifierError::InvalidMeasurement);
            }

            // Validate supported algorithms
            match measurement.algorithm.to_uppercase().as_str() {
                "SHA256" | "SHA384" | "SHA512" => {},
                _ => return Err(VerifierError::InvalidMeasurement),
            }
        }

        Ok(true)
    }

    pub fn generate_claims(&self, measurements: Vec<Measurement>, certificates: Vec<Certificate>) -> Result<VerifierClaims, VerifierError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VerifierError::TimeError)?
            .as_secs();

        Ok(VerifierClaims {
            device_id: self.device_id.clone(),
            timestamp,
            measurements,
            certificates,
            signature: String::new(), // Signature will be added by specific verifier implementations
        })
    }
}
