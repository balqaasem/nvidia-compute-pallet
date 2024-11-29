#![cfg_attr(not(feature = "std"), no_std)]

use rust_nvtrust_attestation::{AttestationReport, MeasurementType};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use sha2::{Sha256, Digest};
use x509_parser::prelude::*;
use rayon::prelude::*;

#[derive(Debug, Error)]
pub enum QuoteVerificationError {
    #[error("Invalid quote format")]
    InvalidQuoteFormat,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid measurement")]
    InvalidMeasurement,
    #[error("Invalid certificate")]
    InvalidCertificate,
    #[error("Expired quote")]
    ExpiredQuote,
    #[error("Unsupported quote type")]
    UnsupportedQuoteType,
    #[error("Verification error: {0}")]
    VerificationError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteVerificationConfig {
    pub allowed_measurements: Vec<Vec<u8>>,
    pub trusted_certificates: Vec<Vec<u8>>,
    pub max_quote_age_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteVerificationResult {
    pub is_valid: bool,
    pub measurement_valid: bool,
    pub signature_valid: bool,
    pub certificate_valid: bool,
    pub timestamp_valid: bool,
    pub verification_time: u64,
}

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

pub struct TDXQuoteVerifier {
    pub tdx_root_key: Vec<u8>,
}

impl TDXQuoteVerifier {
    pub fn new(tdx_root_key: Vec<u8>) -> Self {
        Self { tdx_root_key }
    }

    fn verify_tdx_quote(
        &self,
        quote: &[u8],
        config: &QuoteVerificationConfig,
    ) -> Result<QuoteVerificationResult, QuoteVerificationError> {
        // Parse TDX quote structure
        let (header, body, signature) = self.parse_tdx_quote(quote)?;
        
        // Verify quote signature using TDX root key
        let signature_valid = self.verify_signature(body, signature)?;
        
        // Verify measurement against allowed measurements
        let measurement = self.extract_measurement(body)?;
        let measurement_valid = config.allowed_measurements.contains(&measurement);
        
        // Verify certificate chain
        let certificate_valid = self.verify_certificate_chain(body, &config.trusted_certificates)?;
        
        // Verify timestamp
        let timestamp = self.extract_timestamp(body)?;
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp_valid = (current_time - timestamp) <= config.max_quote_age_seconds;
        
        Ok(QuoteVerificationResult {
            is_valid: signature_valid && measurement_valid && certificate_valid && timestamp_valid,
            measurement_valid,
            signature_valid,
            certificate_valid,
            timestamp_valid,
            verification_time: current_time,
        })
    }

    fn parse_tdx_quote(
        &self,
        quote: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), QuoteVerificationError> {
        if quote.len() < 64 {
            return Err(QuoteVerificationError::InvalidQuoteFormat);
        }

        // TDX quote format:
        // Header (16 bytes) | Body (variable) | Signature (64 bytes)
        let header = quote[..16].to_vec();
        let signature = quote[quote.len()-64..].to_vec();
        let body = quote[16..quote.len()-64].to_vec();

        Ok((header, body, signature))
    }

    fn verify_signature(
        &self,
        body: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, QuoteVerificationError> {
        // Create message hash
        let mut hasher = Sha256::new();
        hasher.update(&body);
        let message_hash = hasher.finalize();

        // Verify ECDSA signature using ring
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            &self.tdx_root_key,
        );

        public_key
            .verify(&message_hash, &signature)
            .map_err(|_| QuoteVerificationError::InvalidSignature)
            .map(|_| true)
    }

    fn extract_measurement(&self, body: Vec<u8>) -> Result<Vec<u8>, QuoteVerificationError> {
        // Extract measurement from TDX quote body
        // Format: [other_data (32 bytes) | measurement (48 bytes) | ...]
        if body.len() < 80 {
            return Err(QuoteVerificationError::InvalidQuoteFormat);
        }

        Ok(body[32..80].to_vec())
    }

    fn verify_certificate_chain(
        &self,
        body: Vec<u8>,
        trusted_certificates: &[Vec<u8>],
    ) -> Result<bool, QuoteVerificationError> {
        // Extract certificates from quote body
        let cert_data = self.extract_certificates(&body)?;
        
        // Parse certificates
        for cert_bytes in cert_data {
            let (_, cert) = X509Certificate::from_der(&cert_bytes)
                .map_err(|_| QuoteVerificationError::InvalidCertificate)?;
                
            // Verify certificate is trusted
            if !trusted_certificates.contains(&cert_bytes) {
                return Ok(false);
            }
            
            // Verify certificate is not expired
            let not_after = cert.validity().not_after.to_datetime();
            let current_time = std::time::SystemTime::now();
            if current_time > std::time::UNIX_EPOCH + std::time::Duration::from_secs(not_after.timestamp() as u64) {
                return Ok(false);
            }
        }
        
        Ok(true)
    }

    fn extract_certificates(&self, body: &[u8]) -> Result<Vec<Vec<u8>>, QuoteVerificationError> {
        // Extract certificate chain from quote body
        // Format depends on specific TDX quote format
        // This is a placeholder implementation
        Ok(vec![body.to_vec()])
    }

    fn extract_timestamp(&self, body: Vec<u8>) -> Result<u64, QuoteVerificationError> {
        // Extract timestamp from TDX quote body
        // Format: [other_data (80 bytes) | timestamp (8 bytes) | ...]
        if body.len() < 88 {
            return Err(QuoteVerificationError::InvalidQuoteFormat);
        }

        let timestamp_bytes = &body[80..88];
        let timestamp = u64::from_le_bytes(timestamp_bytes.try_into().unwrap());
        Ok(timestamp)
    }
}

impl QuoteVerifier for TDXQuoteVerifier {
    fn verify_quote(
        &self,
        quote: &[u8],
        config: &QuoteVerificationConfig,
    ) -> Result<QuoteVerificationResult, QuoteVerificationError> {
        self.verify_tdx_quote(quote, config)
    }
    
    fn verify_attestation_report(
        &self,
        report: &AttestationReport,
        config: &QuoteVerificationConfig,
    ) -> Result<QuoteVerificationResult, QuoteVerificationError> {
        match report.measurement_type {
            MeasurementType::TDX => self.verify_quote(&report.quote, config),
            _ => Err(QuoteVerificationError::UnsupportedQuoteType),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SEVQuoteHeader {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u32,
    pub signature_algo: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SEVQuoteBody {
    pub measurement: Vec<u8>,
    pub host_data: Vec<u8>,
    pub launch_tcb: u64,
    pub platform_info: Vec<u8>,
}

pub struct SEVQuoteVerifier {
    pub sev_root_key: Vec<u8>,
    pub platform_info: Option<Vec<u8>>,
}

impl SEVQuoteVerifier {
    pub fn new(sev_root_key: Vec<u8>) -> Self {
        Self {
            sev_root_key,
            platform_info: None,
        }
    }

    pub fn set_platform_info(&mut self, platform_info: Vec<u8>) {
        self.platform_info = Some(platform_info);
    }

    fn verify_sev_quote(
        &self,
        quote: &[u8],
        config: &QuoteVerificationConfig,
    ) -> Result<QuoteVerificationResult, QuoteVerificationError> {
        // Parse SEV quote structure
        let (header, body, signature) = self.parse_sev_quote(quote)?;
        
        // Verify quote signature
        let signature_valid = self.verify_signature(&header, &body, &signature)?;
        
        // Verify measurement
        let measurement = self.extract_measurement(&body)?;
        let measurement_valid = config.allowed_measurements.contains(&measurement);
        
        // Verify platform info
        let platform_valid = self.verify_platform_info(&body)?;
        
        // Verify TCB version
        let tcb_valid = self.verify_tcb_version(&body)?;
        
        // Get current timestamp
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Ok(QuoteVerificationResult {
            is_valid: signature_valid && measurement_valid && platform_valid && tcb_valid,
            measurement_valid,
            signature_valid,
            certificate_valid: platform_valid,
            timestamp_valid: tcb_valid,
            verification_time: current_time,
        })
    }

    fn parse_sev_quote(
        &self,
        quote: &[u8],
    ) -> Result<(SEVQuoteHeader, SEVQuoteBody, Vec<u8>), QuoteVerificationError> {
        if quote.len() < 128 {
            return Err(QuoteVerificationError::InvalidQuoteFormat);
        }

        // Parse header (first 16 bytes)
        let header_bytes = &quote[..16];
        let header = SEVQuoteHeader {
            version: u32::from_le_bytes(header_bytes[0..4].try_into().unwrap()),
            guest_svn: u32::from_le_bytes(header_bytes[4..8].try_into().unwrap()),
            policy: u32::from_le_bytes(header_bytes[8..12].try_into().unwrap()),
            signature_algo: u32::from_le_bytes(header_bytes[12..16].try_into().unwrap()),
        };

        // Parse body
        let body_start = 16;
        let body_end = quote.len() - 64; // Last 64 bytes are signature
        let body_bytes = &quote[body_start..body_end];
        
        let body = SEVQuoteBody {
            measurement: body_bytes[0..48].to_vec(),
            host_data: body_bytes[48..80].to_vec(),
            launch_tcb: u64::from_le_bytes(body_bytes[80..88].try_into().unwrap()),
            platform_info: body_bytes[88..].to_vec(),
        };

        // Get signature
        let signature = quote[body_end..].to_vec();

        Ok((header, body, signature))
    }

    fn verify_signature(
        &self,
        header: &SEVQuoteHeader,
        body: &SEVQuoteBody,
        signature: &[u8],
    ) -> Result<bool, QuoteVerificationError> {
        // Create message to verify
        let mut message = Vec::new();
        message.extend_from_slice(&header.version.to_le_bytes());
        message.extend_from_slice(&header.guest_svn.to_le_bytes());
        message.extend_from_slice(&header.policy.to_le_bytes());
        message.extend_from_slice(&header.signature_algo.to_le_bytes());
        message.extend_from_slice(&body.measurement);
        message.extend_from_slice(&body.host_data);
        message.extend_from_slice(&body.launch_tcb.to_le_bytes());
        message.extend_from_slice(&body.platform_info);

        // Create message hash
        let mut hasher = Sha256::new();
        hasher.update(&message);
        let message_hash = hasher.finalize();

        // Verify ECDSA signature
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            &self.sev_root_key,
        );

        public_key
            .verify(&message_hash, signature)
            .map_err(|_| QuoteVerificationError::InvalidSignature)
            .map(|_| true)
    }

    fn extract_measurement(&self, body: &SEVQuoteBody) -> Result<Vec<u8>, QuoteVerificationError> {
        if body.measurement.len() != 48 {
            return Err(QuoteVerificationError::InvalidMeasurement);
        }
        Ok(body.measurement.clone())
    }

    fn verify_platform_info(&self, body: &SEVQuoteBody) -> Result<bool, QuoteVerificationError> {
        match &self.platform_info {
            Some(expected_info) => Ok(&body.platform_info == expected_info),
            None => Ok(true), // Skip platform verification if no platform info is set
        }
    }

    fn verify_tcb_version(&self, body: &SEVQuoteBody) -> Result<bool, QuoteVerificationError> {
        // Verify that the TCB version is recent enough
        // This is a simplified check - in practice, you'd want to compare against a minimum TCB version
        Ok(body.launch_tcb > 0)
    }
}

impl QuoteVerifier for SEVQuoteVerifier {
    fn verify_quote(
        &self,
        quote: &[u8],
        config: &QuoteVerificationConfig,
    ) -> Result<QuoteVerificationResult, QuoteVerificationError> {
        self.verify_sev_quote(quote, config)
    }
    
    fn verify_attestation_report(
        &self,
        report: &AttestationReport,
        config: &QuoteVerificationConfig,
    ) -> Result<QuoteVerificationResult, QuoteVerificationError> {
        match report.measurement_type {
            MeasurementType::SEV => self.verify_quote(&report.quote, config),
            _ => Err(QuoteVerificationError::UnsupportedQuoteType),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SEVSNPQuoteHeader {
    pub version: u32,
    pub policy: u32,
    pub signature_algo: u32,
    pub platform_version: u32,
    pub platform_info: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SEVSNPQuoteBody {
    pub measurement: Vec<u8>,
    pub host_data: Vec<u8>,
    pub id_key_digest: Vec<u8>,
    pub author_key_digest: Vec<u8>,
    pub report_data: Vec<u8>,
    pub chip_id: Vec<u8>,
    pub committed_tcb: u64,
    pub current_tcb: u64,
    pub platform_info: Vec<u8>,
}

pub struct SEVSNPQuoteVerifier {
    pub snp_root_key: Vec<u8>,
    pub platform_info: Option<Vec<u8>>,
    pub min_platform_version: u32,
}

impl SEVSNPQuoteVerifier {
    pub fn new(snp_root_key: Vec<u8>) -> Self {
        Self {
            snp_root_key,
            platform_info: None,
            min_platform_version: 0,
        }
    }

    pub fn set_platform_info(&mut self, platform_info: Vec<u8>) {
        self.platform_info = Some(platform_info);
    }

    pub fn set_min_platform_version(&mut self, version: u32) {
        self.min_platform_version = version;
    }

    fn verify_snp_quote(
        &self,
        quote: &[u8],
        config: &QuoteVerificationConfig,
    ) -> Result<QuoteVerificationResult, QuoteVerificationError> {
        // Parse SEV-SNP quote structure
        let (header, body, signature) = self.parse_snp_quote(quote)?;
        
        // Verify platform version
        let platform_valid = header.platform_version >= self.min_platform_version;
        
        // Verify quote signature
        let signature_valid = self.verify_signature(&header, &body, &signature)?;
        
        // Verify measurement
        let measurement = self.extract_measurement(&body)?;
        let measurement_valid = config.allowed_measurements.contains(&measurement);
        
        // Verify TCB versions
        let tcb_valid = self.verify_tcb_versions(&body)?;
        
        // Verify platform info
        let platform_info_valid = self.verify_platform_info(&body)?;
        
        // Get current timestamp
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Ok(QuoteVerificationResult {
            is_valid: signature_valid && measurement_valid && tcb_valid && platform_valid && platform_info_valid,
            measurement_valid,
            signature_valid,
            certificate_valid: platform_info_valid,
            timestamp_valid: tcb_valid,
            verification_time: current_time,
        })
    }

    fn parse_snp_quote(
        &self,
        quote: &[u8],
    ) -> Result<(SEVSNPQuoteHeader, SEVSNPQuoteBody, Vec<u8>), QuoteVerificationError> {
        if quote.len() < 256 {
            return Err(QuoteVerificationError::InvalidQuoteFormat);
        }

        // Parse header (first 20 bytes)
        let header_bytes = &quote[..20];
        let header = SEVSNPQuoteHeader {
            version: u32::from_le_bytes(header_bytes[0..4].try_into().unwrap()),
            policy: u32::from_le_bytes(header_bytes[4..8].try_into().unwrap()),
            signature_algo: u32::from_le_bytes(header_bytes[8..12].try_into().unwrap()),
            platform_version: u32::from_le_bytes(header_bytes[12..16].try_into().unwrap()),
            platform_info: u32::from_le_bytes(header_bytes[16..20].try_into().unwrap()),
        };

        // Parse body
        let body_start = 20;
        let body_end = quote.len() - 64; // Last 64 bytes are signature
        let body_bytes = &quote[body_start..body_end];
        
        let body = SEVSNPQuoteBody {
            measurement: body_bytes[0..48].to_vec(),
            host_data: body_bytes[48..80].to_vec(),
            id_key_digest: body_bytes[80..112].to_vec(),
            author_key_digest: body_bytes[112..144].to_vec(),
            report_data: body_bytes[144..176].to_vec(),
            chip_id: body_bytes[176..208].to_vec(),
            committed_tcb: u64::from_le_bytes(body_bytes[208..216].try_into().unwrap()),
            current_tcb: u64::from_le_bytes(body_bytes[216..224].try_into().unwrap()),
            platform_info: body_bytes[224..].to_vec(),
        };

        // Get signature
        let signature = quote[body_end..].to_vec();

        Ok((header, body, signature))
    }

    fn verify_signature(
        &self,
        header: &SEVSNPQuoteHeader,
        body: &SEVSNPQuoteBody,
        signature: &[u8],
    ) -> Result<bool, QuoteVerificationError> {
        // Create message to verify
        let mut message = Vec::new();
        message.extend_from_slice(&header.version.to_le_bytes());
        message.extend_from_slice(&header.policy.to_le_bytes());
        message.extend_from_slice(&header.signature_algo.to_le_bytes());
        message.extend_from_slice(&header.platform_version.to_le_bytes());
        message.extend_from_slice(&header.platform_info.to_le_bytes());
        message.extend_from_slice(&body.measurement);
        message.extend_from_slice(&body.host_data);
        message.extend_from_slice(&body.id_key_digest);
        message.extend_from_slice(&body.author_key_digest);
        message.extend_from_slice(&body.report_data);
        message.extend_from_slice(&body.chip_id);
        message.extend_from_slice(&body.committed_tcb.to_le_bytes());
        message.extend_from_slice(&body.current_tcb.to_le_bytes());
        message.extend_from_slice(&body.platform_info);

        // Create message hash
        let mut hasher = Sha256::new();
        hasher.update(&message);
        let message_hash = hasher.finalize();

        // Verify ECDSA signature
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            &self.snp_root_key,
        );

        public_key
            .verify(&message_hash, signature)
            .map_err(|_| QuoteVerificationError::InvalidSignature)
            .map(|_| true)
    }

    fn extract_measurement(&self, body: &SEVSNPQuoteBody) -> Result<Vec<u8>, QuoteVerificationError> {
        if body.measurement.len() != 48 {
            return Err(QuoteVerificationError::InvalidMeasurement);
        }
        Ok(body.measurement.clone())
    }

    fn verify_tcb_versions(&self, body: &SEVSNPQuoteBody) -> Result<bool, QuoteVerificationError> {
        // Verify that current TCB is at least as recent as committed TCB
        if body.current_tcb < body.committed_tcb {
            return Ok(false);
        }

        // Additional TCB validation logic can be added here
        Ok(true)
    }

    fn verify_platform_info(&self, body: &SEVSNPQuoteBody) -> Result<bool, QuoteVerificationError> {
        match &self.platform_info {
            Some(expected_info) => Ok(&body.platform_info == expected_info),
            None => Ok(true), // Skip platform verification if no platform info is set
        }
    }
}

impl QuoteVerifier for SEVSNPQuoteVerifier {
    fn verify_quote(
        &self,
        quote: &[u8],
        config: &QuoteVerificationConfig,
    ) -> Result<QuoteVerificationResult, QuoteVerificationError> {
        self.verify_snp_quote(quote, config)
    }
    
    fn verify_attestation_report(
        &self,
        report: &AttestationReport,
        config: &QuoteVerificationConfig,
    ) -> Result<QuoteVerificationResult, QuoteVerificationError> {
        match report.measurement_type {
            MeasurementType::SEVSNP => self.verify_quote(&report.quote, config),
            _ => Err(QuoteVerificationError::UnsupportedQuoteType),
        }
    }
}

#[cfg(feature = "parallel")]
impl SEVSNPQuoteVerifier {
    pub fn verify_quotes_parallel(
        &self,
        quotes: &[&[u8]],
        config: &QuoteVerificationConfig,
    ) -> Vec<Result<QuoteVerificationResult, QuoteVerificationError>> {
        use rayon::prelude::*;

        quotes.par_iter()
            .map(|quote| self.verify_quote(quote, config))
            .collect()
    }

    pub fn batch_verify_quotes(
        &self,
        quotes: &[&[u8]],
        config: &QuoteVerificationConfig,
    ) -> Result<BatchVerificationResult, QuoteVerificationError> {
        use rayon::prelude::*;

        // Fast path: check minimum quote length
        if quotes.iter().any(|q| q.len() < 256) {
            return Err(QuoteVerificationError::InvalidQuoteFormat);
        }

        // Parse all quotes in parallel
        let parse_results: Vec<_> = quotes.par_iter()
            .map(|quote| {
                let (header, body, signature) = self.parse_snp_quote(quote)?;
                let measurement_valid = config.allowed_measurements.contains(&body.measurement.to_vec());
                Ok((header, body, signature, measurement_valid))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Batch validate all quotes in parallel
        let validation_results: Vec<_> = parse_results.par_iter()
            .map(|(header, body, signature, measurement_valid)| {
                let mut results = ValidationResults::default();
                results.measurement_valid = *measurement_valid;
                
                // Platform version check
                results.platform_valid = header.platform_version >= self.min_platform_version;

                // TCB version check
                results.tcb_valid = body.current_tcb >= body.committed_tcb;

                // Platform info check
                if let Some(expected_info) = &self.platform_info {
                    results.platform_valid &= &body.platform_info[..] == &expected_info[..];
                }

                // Only verify signature if other checks pass
                if results.platform_valid && results.tcb_valid && results.measurement_valid {
                    let mut message = Vec::with_capacity(
                        20 + 48 + 32 * 5 + 16 + body.platform_info.len()
                    );
                    
                    message.extend_from_slice(&header.version.to_le_bytes());
                    message.extend_from_slice(&header.policy.to_le_bytes());
                    message.extend_from_slice(&header.signature_algo.to_le_bytes());
                    message.extend_from_slice(&header.platform_version.to_le_bytes());
                    message.extend_from_slice(&header.platform_info.to_le_bytes());
                    message.extend_from_slice(&body.measurement);
                    message.extend_from_slice(&body.host_data);
                    message.extend_from_slice(&body.id_key_digest);
                    message.extend_from_slice(&body.author_key_digest);
                    message.extend_from_slice(&body.report_data);
                    message.extend_from_slice(&body.chip_id);
                    message.extend_from_slice(&body.committed_tcb.to_le_bytes());
                    message.extend_from_slice(&body.current_tcb.to_le_bytes());
                    message.extend_from_slice(&body.platform_info);

                    let mut hasher = Sha256::new();
                    hasher.update(&message);
                    let message_hash = hasher.finalize();

                    results.signature_valid = self.signature_verifier
                        .verify(&message_hash, signature)
                        .is_ok();
                }

                Ok(results)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Get current timestamp once
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Convert validation results to verification results
        let results: Vec<_> = validation_results.into_iter()
            .map(|v| QuoteVerificationResult {
                is_valid: v.all_valid(),
                measurement_valid: v.measurement_valid,
                signature_valid: v.signature_valid,
                certificate_valid: v.platform_valid,
                timestamp_valid: v.tcb_valid,
                verification_time: current_time,
            })
            .collect();

        Ok(BatchVerificationResult {
            results,
            batch_verification_time: current_time,
        })
    }
}

#[derive(Debug, Clone)]
pub struct BatchVerificationResult {
    pub results: Vec<QuoteVerificationResult>,
    pub batch_verification_time: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ValidationResults {
    pub measurement_valid: bool,
    pub signature_valid: bool,
    pub platform_valid: bool,
    pub tcb_valid: bool,
}

impl ValidationResults {
    pub fn all_valid(&self) -> bool {
        self.measurement_valid && self.signature_valid && self.platform_valid && self.tcb_valid
    }
}

pub struct ParallelQuoteVerifier {
    verifiers: Vec<Box<dyn QuoteVerifier + Send + Sync>>,
}

impl ParallelQuoteVerifier {
    pub fn new() -> Self {
        Self {
            verifiers: Vec::new(),
        }
    }

    pub fn add_verifier(&mut self, verifier: Box<dyn QuoteVerifier + Send + Sync>) {
        self.verifiers.push(verifier);
    }

    #[cfg(feature = "parallel")]
    pub fn verify_quotes_parallel(
        &self,
        quotes: &[Vec<u8>],
        config: &QuoteVerificationConfig,
    ) -> Vec<Result<QuoteVerificationResult, QuoteVerificationError>> {
        quotes.par_iter()
            .map(|quote| {
                self.verify_single_quote(quote, config)
            })
            .collect()
    }

    #[cfg(feature = "parallel")]
    pub fn verify_attestation_reports_parallel(
        &self,
        reports: &[AttestationReport],
        config: &QuoteVerificationConfig,
    ) -> Vec<Result<QuoteVerificationResult, QuoteVerificationError>> {
        reports.par_iter()
            .map(|report| {
                self.verify_single_report(report, config)
            })
            .collect()
    }

    fn verify_single_quote(
        &self,
        quote: &[u8],
        config: &QuoteVerificationConfig,
    ) -> Result<QuoteVerificationResult, QuoteVerificationError> {
        for verifier in &self.verifiers {
            if let Ok(result) = verifier.verify_quote(quote, config) {
                return Ok(result);
            }
        }
        Err(QuoteVerificationError::UnsupportedQuoteType)
    }

    fn verify_single_report(
        &self,
        report: &AttestationReport,
        config: &QuoteVerificationConfig,
    ) -> Result<QuoteVerificationResult, QuoteVerificationError> {
        for verifier in &self.verifiers {
            if let Ok(result) = verifier.verify_attestation_report(report, config) {
                return Ok(result);
            }
        }
        Err(QuoteVerificationError::UnsupportedQuoteType)
    }
}

#[cfg(feature = "parallel")]
impl TDXQuoteVerifier {
    pub fn verify_quotes_parallel(
        &self,
        quotes: &[&[u8]],
        config: &QuoteVerificationConfig,
    ) -> Vec<Result<QuoteVerificationResult, QuoteVerificationError>> {
        quotes.par_iter()
            .map(|quote| self.verify_quote(quote, config))
            .collect()
    }
}

#[cfg(feature = "parallel")]
impl SEVQuoteVerifier {
    pub fn verify_quotes_parallel(
        &self,
        quotes: &[&[u8]],
        config: &QuoteVerificationConfig,
    ) -> Vec<Result<QuoteVerificationResult, QuoteVerificationError>> {
        quotes.par_iter()
            .map(|quote| self.verify_quote(quote, config))
            .collect()
    }
}

pub struct SGXQuoteVerifier {
    pub sgx_root_key: Vec<u8>,
}

impl SGXQuoteVerifier {
    pub fn new(sgx_root_key: Vec<u8>) -> Self {
        Self { sgx_root_key }
    }
}

impl QuoteVerifier for SGXQuoteVerifier {
    fn verify_quote(
        &self,
        _quote: &[u8],
        _config: &QuoteVerificationConfig,
    ) -> Result<QuoteVerificationResult, QuoteVerificationError> {
        // TODO: Implement SGX quote verification
        Err(QuoteVerificationError::UnsupportedQuoteType)
    }
    
    fn verify_attestation_report(
        &self,
        report: &AttestationReport,
        config: &QuoteVerificationConfig,
    ) -> Result<QuoteVerificationResult, QuoteVerificationError> {
        match report.measurement_type {
            MeasurementType::SGX => self.verify_quote(&report.quote, config),
            _ => Err(QuoteVerificationError::UnsupportedQuoteType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> QuoteVerificationConfig {
        QuoteVerificationConfig {
            allowed_measurements: vec![vec![0; 48]], // Example measurement
            trusted_certificates: vec![vec![0; 32]], // Example certificate
            max_quote_age_seconds: 3600,
        }
    }

    #[test]
    fn test_tdx_quote_verification() {
        let tdx_root_key = vec![0; 32]; // Example key
        let verifier = TDXQuoteVerifier::new(tdx_root_key);
        let config = create_test_config();

        // Create a mock TDX quote
        let mut quote = vec![0; 128];
        quote[0..16].copy_from_slice(&[1; 16]); // Header
        quote[16..80].copy_from_slice(&[2; 64]); // Body with measurement
        quote[80..88].copy_from_slice(&0u64.to_le_bytes()); // Timestamp
        quote[88..].copy_from_slice(&[3; 40]); // Signature

        let result = verifier.verify_quote(&quote, &config);
        assert!(result.is_err()); // Should fail with invalid signature
    }

    #[test]
    fn test_sgx_quote_verification() {
        let sgx_root_key = vec![0; 32]; // Example key
        let verifier = SGXQuoteVerifier::new(sgx_root_key);
        let config = create_test_config();

        let quote = vec![0; 64]; // Example SGX quote
        let result = verifier.verify_quote(&quote, &config);
        assert!(result.is_err()); // Should return UnsupportedQuoteType
    }

    #[test]
    fn test_sev_quote_verification() {
        let sev_root_key = vec![0; 32]; // Example key
        let mut verifier = SEVQuoteVerifier::new(sev_root_key);
        let config = create_test_config();

        // Set platform info for testing
        verifier.set_platform_info(vec![0; 32]);

        // Create a mock SEV quote
        let mut quote = vec![0; 256];
        // Header
        quote[0..4].copy_from_slice(&1u32.to_le_bytes()); // version
        quote[4..8].copy_from_slice(&2u32.to_le_bytes()); // guest_svn
        quote[8..12].copy_from_slice(&3u32.to_le_bytes()); // policy
        quote[12..16].copy_from_slice(&1u32.to_le_bytes()); // signature_algo

        // Body
        quote[16..64].copy_from_slice(&[2; 48]); // measurement
        quote[64..96].copy_from_slice(&[3; 32]); // host_data
        quote[96..104].copy_from_slice(&1u64.to_le_bytes()); // launch_tcb
        quote[104..136].copy_from_slice(&[0; 32]); // platform_info

        // Signature
        quote[136..].copy_from_slice(&[4; 120]);

        let result = verifier.verify_quote(&quote, &config);
        assert!(result.is_err()); // Should fail with invalid signature
    }

    #[test]
    fn test_sev_snp_quote_verification() {
        let snp_root_key = vec![0; 32]; // Example key
        let mut verifier = SEVSNPQuoteVerifier::new(snp_root_key);
        let config = create_test_config();

        // Set platform info and version requirements
        verifier.set_platform_info(vec![0; 32]);
        verifier.set_min_platform_version(1);

        // Create a mock SEV-SNP quote
        let mut quote = vec![0; 512];
        // Header
        quote[0..4].copy_from_slice(&2u32.to_le_bytes()); // version
        quote[4..8].copy_from_slice(&3u32.to_le_bytes()); // policy
        quote[8..12].copy_from_slice(&1u32.to_le_bytes()); // signature_algo
        quote[12..16].copy_from_slice(&1u32.to_le_bytes()); // platform_version
        quote[16..20].copy_from_slice(&0u32.to_le_bytes()); // platform_info

        // Body
        quote[20..68].copy_from_slice(&[2; 48]); // measurement
        quote[68..100].copy_from_slice(&[3; 32]); // host_data
        quote[100..132].copy_from_slice(&[4; 32]); // id_key_digest
        quote[132..164].copy_from_slice(&[5; 32]); // author_key_digest
        quote[164..196].copy_from_slice(&[6; 32]); // report_data
        quote[196..228].copy_from_slice(&[7; 32]); // chip_id
        quote[228..236].copy_from_slice(&1u64.to_le_bytes()); // committed_tcb
        quote[236..244].copy_from_slice(&2u64.to_le_bytes()); // current_tcb
        quote[244..276].copy_from_slice(&[0; 32]); // platform_info

        // Signature
        quote[276..].copy_from_slice(&[8; 236]);

        let result = verifier.verify_quote(&quote, &config);
        assert!(result.is_err()); // Should fail with invalid signature
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn test_parallel_quote_verification() {
        let snp_root_key = vec![0; 32];
        let verifier = SEVSNPQuoteVerifier::new(snp_root_key);
        let config = create_test_config();

        // Create multiple test quotes
        let quotes: Vec<Vec<u8>> = (0..10)
            .map(|_| create_test_quote())
            .collect();

        let quote_refs: Vec<&[u8]> = quotes.iter()
            .map(|q| q.as_slice())
            .collect();

        // Verify quotes in parallel
        let results = verifier.verify_quotes_parallel(&quote_refs, &config);
        assert_eq!(results.len(), 10);

        // All should fail with invalid signature
        for result in results {
            assert!(result.is_err());
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn test_batch_quote_verification() {
        let snp_root_key = vec![0; 32];
        let verifier = SEVSNPQuoteVerifier::new(snp_root_key);
        let config = create_test_config();

        // Create multiple test quotes
        let quotes: Vec<Vec<u8>> = (0..10)
            .map(|_| create_test_quote())
            .collect();

        let quote_refs: Vec<&[u8]> = quotes.iter()
            .map(|q| q.as_slice())
            .collect();

        // Batch verify quotes
        let result = verifier.batch_verify_quotes(&quote_refs, &config);
        assert!(result.is_ok());

        let batch_result = result.unwrap();
        assert_eq!(batch_result.results.len(), 10);

        // All should be invalid due to signature verification
        for verification in batch_result.results {
            assert!(!verification.is_valid);
            assert!(!verification.signature_valid);
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn test_chunked_verification() {
        let snp_root_key = vec![0; 32];
        let verifier = SEVSNPQuoteVerifier::new(snp_root_key);
        let config = create_test_config();

        // Create multiple test quotes
        let quotes: Vec<Vec<u8>> = (0..100)
            .map(|_| create_test_quote())
            .collect();

        let quote_refs: Vec<&[u8]> = quotes.iter()
            .map(|q| q.as_slice())
            .collect();

        // Verify quotes in chunks
        let results = verifier.verify_quotes_chunked(&quote_refs, &config, 10);
        assert_eq!(results.len(), 100);

        // All should fail with invalid signature
        for result in results {
            assert!(result.is_err());
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn test_cached_batch_verification() {
        let snp_root_key = vec![0; 32];
        let verifier = SEVSNPQuoteVerifier::new(snp_root_key);
        let config = create_test_config();

        // Create multiple test quotes with some duplicate measurements
        let quotes: Vec<Vec<u8>> = (0..50)
            .map(|i| {
                let mut quote = create_test_quote();
                // Make every 5th quote have the same measurement
                if i % 5 == 0 {
                    quote[20..68].copy_from_slice(&[1; 48]);
                }
                quote
            })
            .collect();

        let quote_refs: Vec<&[u8]> = quotes.iter()
            .map(|q| q.as_slice())
            .collect();

        // Batch verify quotes with caching
        let result = verifier.batch_verify_quotes_with_cache(&quote_refs, &config, 20);
        assert!(result.is_ok());

        let batch_result = result.unwrap();
        assert_eq!(batch_result.results.len(), 50);

        // All should be invalid due to signature verification
        for verification in batch_result.results {
            assert!(!verification.is_valid);
            assert!(!verification.signature_valid);
        }
    }
}

fn create_test_quote() -> Vec<u8> {
    let mut quote = vec![0; 512];
    // Header
    quote[0..4].copy_from_slice(&2u32.to_le_bytes());
    quote[4..8].copy_from_slice(&3u32.to_le_bytes());
    quote[8..12].copy_from_slice(&1u32.to_le_bytes());
    quote[12..16].copy_from_slice(&1u32.to_le_bytes());
    quote[16..20].copy_from_slice(&0u32.to_le_bytes());

    // Body
    quote[20..68].copy_from_slice(&[2; 48]);
    quote[68..100].copy_from_slice(&[3; 32]);
    quote[100..132].copy_from_slice(&[4; 32]);
    quote[132..164].copy_from_slice(&[5; 32]);
    quote[164..196].copy_from_slice(&[6; 32]);
    quote[196..228].copy_from_slice(&[7; 32]);
    quote[228..236].copy_from_slice(&1u64.to_le_bytes());
    quote[236..244].copy_from_slice(&2u64.to_le_bytes());
    quote[244..276].copy_from_slice(&[0; 32]);

    // Signature
    quote[276..].copy_from_slice(&[8; 236]);
    quote
}
