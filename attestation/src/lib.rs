#![cfg_attr(not(feature = "std"), no_std)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use json::{Value, object};
use jwt::{encode, decode, Validation, Algorithm, EncodingKey, DecodingKey};
use verifiers::{VerifierClaims, Measurement, Certificate};

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("Failed to initialize attestation")]
    InitializationError,
    #[error("Failed to generate quote")]
    QuoteGenerationError,
    #[error("Failed to verify quote")]
    QuoteVerificationError,
    #[error("Invalid measurement")]
    InvalidMeasurement,
    #[error("Unsupported attestation type")]
    UnsupportedType,
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid evidence")]
    InvalidEvidence,
    #[error("Serialization error")]
    SerializationError,
    #[error("Time error")]
    TimeError,
    #[error("Missing URL")]
    MissingUrl,
    #[error("Missing token")]
    MissingToken,
    #[error("JWT error")]
    JwtError,
    #[error("Unimplemented")]
    Unimplemented,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MeasurementType {
    TDX,
    SGX,
    SEV,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationParams {
    pub measurement_type: MeasurementType,
    pub nonce: Option<Vec<u8>>,
    pub additional_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    pub measurement_type: MeasurementType,
    pub quote: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

pub trait AttestationService {
    fn initialize(&mut self, params: AttestationParams) -> Result<(), AttestationError>;
    fn generate_quote(&self, data: &[u8]) -> Result<Vec<u8>, AttestationError>;
    fn verify_quote(&self, quote: &[u8]) -> Result<bool, AttestationError>;
    fn get_report(&self) -> Result<AttestationReport, AttestationError>;
}

pub struct TDXAttestationService {
    params: Option<AttestationParams>,
    tdx_quote_generator: tdx_attest::QuoteGenerator,
}

impl TDXAttestationService {
    pub fn new() -> Self {
        Self {
            params: None,
            tdx_quote_generator: tdx_attest::QuoteGenerator::new(),
        }
    }
}

impl AttestationService for TDXAttestationService {
    fn initialize(&mut self, params: AttestationParams) -> Result<(), AttestationError> {
        match params.measurement_type {
            MeasurementType::TDX => {
                self.params = Some(params);
                Ok(())
            }
            _ => Err(AttestationError::UnsupportedType),
        }
    }

    fn generate_quote(&self, data: &[u8]) -> Result<Vec<u8>, AttestationError> {
        let params = self.params.as_ref().ok_or(AttestationError::InitializationError)?;
        
        let quote = self.tdx_quote_generator
            .generate_quote(data)
            .map_err(|_| AttestationError::QuoteGenerationError)?;
            
        Ok(quote)
    }

    fn verify_quote(&self, quote: &[u8]) -> Result<bool, AttestationError> {
        let params = self.params.as_ref().ok_or(AttestationError::InitializationError)?;
        
        // Verify TDX quote using the TDX Quote Verification Library
        let result = tdx_attest::verify_quote(quote)
            .map_err(|_| AttestationError::QuoteVerificationError)?;
            
        Ok(result)
    }

    fn get_report(&self) -> Result<AttestationReport, AttestationError> {
        let params = self.params.as_ref().ok_or(AttestationError::InitializationError)?;
        
        let quote = self.generate_quote(&[])?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Ok(AttestationReport {
            measurement_type: params.measurement_type.clone(),
            quote,
            signature: vec![], // TODO: Implement signature generation
            timestamp,
        })
    }
}

pub struct SGXAttestationService {
    params: Option<AttestationParams>,
}

impl SGXAttestationService {
    pub fn new() -> Self {
        Self { params: None }
    }
}

impl AttestationService for SGXAttestationService {
    fn initialize(&mut self, params: AttestationParams) -> Result<(), AttestationError> {
        match params.measurement_type {
            MeasurementType::SGX => {
                self.params = Some(params);
                Ok(())
            }
            _ => Err(AttestationError::UnsupportedType),
        }
    }

    // TODO: Implement SGX-specific quote generation and verification
    fn generate_quote(&self, _data: &[u8]) -> Result<Vec<u8>, AttestationError> {
        Err(AttestationError::UnsupportedType)
    }

    fn verify_quote(&self, _quote: &[u8]) -> Result<bool, AttestationError> {
        Err(AttestationError::UnsupportedType)
    }

    fn get_report(&self) -> Result<AttestationReport, AttestationError> {
        Err(AttestationError::UnsupportedType)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Device {
    CPU = 1,
    GPU = 2,
    SWITCH = 4,
    OS = 8,
    DPU = 16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Environment {
    Test = 0,
    Local = 1,
    Remote = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VerifierField {
    Name = 0,
    Device = 1,
    Environment = 2,
    Url = 3,
    Policy = 4,
    JwtToken = 5,
}

pub mod verifiers {
    use super::*;

    pub trait Verifier {
        fn name(&self) -> &str;
        fn get_evidence(&self, ppcie_mode: bool) -> Result<Evidence, AttestationError>;
        fn verify(&self, evidence: &Evidence) -> Result<bool, AttestationError>;
        fn get_claims(&self) -> Result<HashMap<String, Value>, AttestationError>;
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub enum Evidence {
        GpuLocal(VerifierClaims),
        GpuRemote(VerifierClaims),
        NvSwitchLocal(VerifierClaims),
        NvSwitchRemote(VerifierClaims),
    }

    pub struct GpuLocalVerifier {
        // TODO: Implement GPU local verifier
    }

    impl GpuLocalVerifier {
        pub fn new(_evidence: &str) -> Result<Self, AttestationError> {
            Ok(Self {})
        }
    }

    impl Verifier for GpuLocalVerifier {
        fn name(&self) -> &str {
            "GPU Local Verifier"
        }

        fn get_evidence(&self, _ppcie_mode: bool) -> Result<Evidence, AttestationError> {
            // TODO: Implement evidence generation
            Ok(Evidence::GpuLocal(VerifierClaims {}))
        }

        fn verify(&self, evidence: &Evidence) -> Result<bool, AttestationError> {
            // TODO: Implement verification logic
            Ok(true)
        }

        fn get_claims(&self) -> Result<HashMap<String, Value>, AttestationError> {
            // TODO: Implement claims generation
            Ok(HashMap::new())
        }
    }

    pub struct GpuRemoteVerifier {
        // TODO: Implement GPU remote verifier
    }

    impl GpuRemoteVerifier {
        pub fn new(_url: &str, _evidence: &str) -> Result<Self, AttestationError> {
            Ok(Self {})
        }
    }

    impl Verifier for GpuRemoteVerifier {
        fn name(&self) -> &str {
            "GPU Remote Verifier"
        }

        fn get_evidence(&self, _ppcie_mode: bool) -> Result<Evidence, AttestationError> {
            // TODO: Implement evidence generation
            Ok(Evidence::GpuRemote(VerifierClaims {}))
        }

        fn verify(&self, evidence: &Evidence) -> Result<bool, AttestationError> {
            // TODO: Implement verification logic
            Ok(true)
        }

        fn get_claims(&self) -> Result<HashMap<String, Value>, AttestationError> {
            // TODO: Implement claims generation
            Ok(HashMap::new())
        }
    }

    pub struct NvSwitchLocalVerifier {
        // TODO: Implement NVSwitch local verifier
    }

    impl NvSwitchLocalVerifier {
        pub fn new(_evidence: &str) -> Result<Self, AttestationError> {
            Ok(Self {})
        }
    }

    impl Verifier for NvSwitchLocalVerifier {
        fn name(&self) -> &str {
            "NVSwitch Local Verifier"
        }

        fn get_evidence(&self, _ppcie_mode: bool) -> Result<Evidence, AttestationError> {
            // TODO: Implement evidence generation
            Ok(Evidence::NvSwitchLocal(VerifierClaims {}))
        }

        fn verify(&self, evidence: &Evidence) -> Result<bool, AttestationError> {
            // TODO: Implement verification logic
            Ok(true)
        }

        fn get_claims(&self) -> Result<HashMap<String, Value>, AttestationError> {
            // TODO: Implement claims generation
            Ok(HashMap::new())
        }
    }

    pub struct NvSwitchRemoteVerifier {
        // TODO: Implement NVSwitch remote verifier
    }

    impl NvSwitchRemoteVerifier {
        pub fn new(_url: &str, _evidence: &str) -> Result<Self, AttestationError> {
            Ok(Self {})
        }
    }

    impl Verifier for NvSwitchRemoteVerifier {
        fn name(&self) -> &str {
            "NVSwitch Remote Verifier"
        }

        fn get_evidence(&self, _ppcie_mode: bool) -> Result<Evidence, AttestationError> {
            // TODO: Implement evidence generation
            Ok(Evidence::NvSwitchRemote(VerifierClaims {}))
        }

        fn verify(&self, evidence: &Evidence) -> Result<bool, AttestationError> {
            // TODO: Implement verification logic
            Ok(true)
        }

        fn get_claims(&self) -> Result<HashMap<String, Value>, AttestationError> {
            // TODO: Implement claims generation
            Ok(HashMap::new())
        }
    }
}

pub struct Attestation {
    name: Option<String>,
    nonce_server: Option<String>,
    static_nonce: Option<String>,
    tokens: HashMap<String, String>,
    verifiers: Vec<Box<dyn verifiers::Verifier>>,
}

impl Attestation {
    pub fn new(name: Option<String>) -> Self {
        Self {
            name,
            nonce_server: None,
            static_nonce: None,
            tokens: HashMap::new(),
            verifiers: Vec::new(),
        }
    }

    pub fn set_name(&mut self, name: String) {
        self.name = Some(name);
    }

    pub fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn set_nonce_server(&mut self, url: String) {
        self.nonce_server = Some(url);
    }

    pub fn get_nonce_server(&self) -> Option<&str> {
        self.nonce_server.as_deref()
    }

    pub fn add_verifier(
        &mut self,
        device: Device,
        env: Environment,
        url: Option<String>,
        evidence: &str,
    ) -> Result<(), AttestationError> {
        let verifier: Box<dyn verifiers::Verifier> = match device {
            Device::GPU => match env {
                Environment::Local => Box::new(verifiers::GpuLocalVerifier::new(evidence)?),
                Environment::Remote => {
                    let url = url.ok_or(AttestationError::MissingUrl)?;
                    Box::new(verifiers::GpuRemoteVerifier::new(&url, evidence)?)
                }
                _ => return Err(AttestationError::UnsupportedEnvironment),
            },
            Device::SWITCH => match env {
                Environment::Local => Box::new(verifiers::NvSwitchLocalVerifier::new(evidence)?),
                Environment::Remote => {
                    let url = url.ok_or(AttestationError::MissingUrl)?;
                    Box::new(verifiers::NvSwitchRemoteVerifier::new(&url, evidence)?)
                }
                _ => return Err(AttestationError::UnsupportedEnvironment),
            },
            _ => return Err(AttestationError::UnsupportedDevice),
        };

        self.verifiers.push(verifier);
        Ok(())
    }

    pub fn clear_verifiers(&mut self) {
        self.verifiers.clear();
    }

    pub fn get_verifiers(&self) -> &[Box<dyn verifiers::Verifier>] {
        &self.verifiers
    }

    pub fn get_evidence(&self, ppcie_mode: bool) -> Result<Vec<verifiers::Evidence>, AttestationError> {
        let mut evidence_list = Vec::new();
        for verifier in &self.verifiers {
            let evidence = verifier.get_evidence(ppcie_mode)?;
            evidence_list.push(evidence);
        }
        Ok(evidence_list)
    }

    pub fn attest(&mut self, evidence_list: Vec<verifiers::Evidence>) -> Result<bool, AttestationError> {
        for (verifier, evidence) in self.verifiers.iter_mut().zip(evidence_list) {
            if !verifier.verify(&evidence)? {
                return Ok(false);
            }
        }
        
        let eat_token = self.create_eat()?;
        if let Some(name) = &self.name {
            self.set_token(name, &eat_token);
        }
        
        Ok(true)
    }

    fn create_eat(&self) -> Result<String, AttestationError> {
        let claims = self.create_verifier_claims()?;
        let token = self.generate_jwt(&claims)?;
        Ok(token)
    }

    fn create_verifier_claims(&self) -> Result<HashMap<String, Value>, AttestationError> {
        let mut claims = HashMap::new();
        for verifier in &self.verifiers {
            let verifier_claims = verifier.get_claims()?;
            claims.insert(verifier.name().to_string(), json!(verifier_claims));
        }
        Ok(claims)
    }

    fn generate_jwt(&self, claims: &HashMap<String, Value>) -> Result<String, AttestationError> {
        let header = json!({
            "alg": "ES256",
            "typ": "JWT"
        });

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AttestationError::TimeError)?
            .as_secs();

        let mut payload = json!({
            "iat": now,
            "exp": now + 3600,
            "iss": self.name.as_deref().unwrap_or("unknown"),
            "claims": claims
        });

        if let Some(nonce) = &self.static_nonce {
            payload["nonce"] = json!(nonce);
        }

        let token = encode(
            &header,
            &payload,
            &EncodingKey::from_ec_pem(PRIVATE_KEY.as_bytes())
                .map_err(|_| AttestationError::JwtError)?,
        )
        .map_err(|_| AttestationError::JwtError)?;

        Ok(token)
    }

    pub fn set_token(&mut self, name: &str, eat_token: &str) {
        self.tokens.insert(name.to_string(), eat_token.to_string());
    }

    pub fn get_token(&self, name: Option<&str>) -> Option<&str> {
        let name = name.or_else(|| self.name.as_deref())?;
        self.tokens.get(name).map(|s| s.as_str())
    }

    pub fn decode_token(&self, token: &str) -> Result<Value, AttestationError> {
        let validation = Validation::new(Algorithm::ES256);
        let key = DecodingKey::from_ec_pem(PUBLIC_KEY.as_bytes())
            .map_err(|_| AttestationError::JwtError)?;

        let token_data = decode::<Value>(token, &key, &validation)
            .map_err(|_| AttestationError::JwtError)?;

        Ok(token_data.claims)
    }

    pub fn validate_token(&self, policy: &str, name: Option<&str>) -> Result<bool, AttestationError> {
        let token = self.get_token(name).ok_or(AttestationError::MissingToken)?;
        self.validate_token_internal(policy, token)
    }

    fn validate_token_internal(&self, policy: &str, eat_token: &str) -> Result<bool, AttestationError> {
        let claims = self.decode_token(eat_token)?;
        
        // TODO: Implement policy validation logic
        // For now, we just verify the token signature and expiration
        Ok(true)
    }

    pub fn generate_nonce(&mut self) -> String {
        let nonce = format!("{}", Uuid::new_v4());
        self.static_nonce = Some(nonce.clone());
        nonce
    }

    pub fn get_nonce(&self) -> Option<&str> {
        self.static_nonce.as_deref()
    }

    pub fn set_nonce(&mut self, nonce: String) {
        self.static_nonce = Some(nonce);
    }

    pub fn reset(&mut self) {
        self.name = None;
        self.nonce_server = None;
        self.static_nonce = None;
        self.tokens.clear();
        self.verifiers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tdx_attestation() {
        let mut service = TDXAttestationService::new();
        let params = AttestationParams {
            measurement_type: MeasurementType::TDX,
            nonce: None,
            additional_data: None,
        };

        assert!(service.initialize(params).is_ok());
    }

    #[test]
    fn test_sgx_attestation() {
        let mut service = SGXAttestationService::new();
        let params = AttestationParams {
            measurement_type: MeasurementType::SGX,
            nonce: None,
            additional_data: None,
        };

        assert!(service.initialize(params).is_ok());
    }
}

const PRIVATE_KEY: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIObtRoY9v2T9j+JkQx5K3uZgJjN9m6jZ9ZQaJj0xvBhFoAoGCCqGSM49
AwEHoUQDQgAE9+JzjxWjyJ9K4ZvQ7aJjN9m6jZ9ZQaJj0xvBhFoA==
-----END EC PRIVATE KEY-----";

const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9+JzjxWjyJ9K4ZvQ7aJjN9m6jZ9ZQ
aJj0xvBhFoA==
-----END PUBLIC KEY-----";
