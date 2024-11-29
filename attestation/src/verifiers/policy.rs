use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Deserialize};
use serde_json::Value;

use crate::{
    AttestationError,
    verifiers::{Evidence, VerifierClaims},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRequirements {
    pub required_measurements: HashSet<String>,
    pub allowed_algorithms: HashSet<String>,
    pub allowed_device_ids: HashSet<String>,
    pub max_age: Option<Duration>,
    pub require_certificates: bool,
}

pub struct PolicyValidatorBuilder {
    requirements: PolicyRequirements,
}

impl Default for PolicyValidatorBuilder {
    fn default() -> Self {
        Self {
            requirements: PolicyRequirements {
                required_measurements: HashSet::new(),
                allowed_algorithms: HashSet::new(),
                allowed_device_ids: HashSet::new(),
                max_age: None,
                require_certificates: false,
            },
        }
    }
}

impl PolicyValidatorBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn require_measurement(mut self, measurement_type: &str) -> Self {
        self.requirements.required_measurements.insert(measurement_type.to_string());
        self
    }

    pub fn allow_algorithm(mut self, algorithm: &str) -> Self {
        self.requirements.allowed_algorithms.insert(algorithm.to_string());
        self
    }

    pub fn allow_device_id(mut self, device_id: &str) -> Self {
        self.requirements.allowed_device_ids.insert(device_id.to_string());
        self
    }

    pub fn set_max_age(mut self, duration: Duration) -> Self {
        self.requirements.max_age = Some(duration);
        self
    }

    pub fn require_certificates(mut self, require: bool) -> Self {
        self.requirements.require_certificates = require;
        self
    }

    pub fn build(self) -> PolicyValidator {
        PolicyValidator {
            requirements: self.requirements,
        }
    }
}

pub struct PolicyValidator {
    requirements: PolicyRequirements,
}

impl PolicyValidator {
    pub fn validate(&self, evidence: &Evidence) -> Result<bool, AttestationError> {
        let claims = match evidence {
            Evidence::GpuLocal(claims) | Evidence::GpuRemote(claims) |
            Evidence::NvSwitchLocal(claims) | Evidence::NvSwitchRemote(claims) => claims,
        };

        // Validate device ID if any are specified
        if !self.requirements.allowed_device_ids.is_empty() &&
           !self.requirements.allowed_device_ids.contains(&claims.device_id) {
            return Ok(false);
        }

        // Validate timestamp if max age is specified
        if let Some(max_age) = self.requirements.max_age {
            let now = Utc::now();
            if now - claims.timestamp > max_age {
                return Ok(false);
            }
        }

        // Validate measurements
        if !self.requirements.required_measurements.is_empty() {
            // TODO: Implement actual measurement validation
            // For now, just check that measurements are present
            if claims.measurements.is_empty() {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn validate_multiple(&self, evidence_list: &[Evidence]) -> Result<bool, AttestationError> {
        for evidence in evidence_list {
            if !self.validate(evidence)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_evidence(device_id: &str) -> Evidence {
        Evidence::GpuLocal(VerifierClaims {
            device_id: device_id.to_string(),
            measurements: vec![0; 32],
            timestamp: Utc::now(),
            ppcie_mode: false,
        })
    }

    #[test]
    fn test_policy_builder() {
        let validator = PolicyValidatorBuilder::new()
            .require_measurement("PCR0")
            .allow_algorithm("SHA256")
            .allow_device_id("test-device")
            .set_max_age(Duration::hours(1))
            .require_certificates(true)
            .build();

        assert!(!validator.requirements.required_measurements.is_empty());
        assert!(!validator.requirements.allowed_algorithms.is_empty());
        assert!(!validator.requirements.allowed_device_ids.is_empty());
        assert!(validator.requirements.max_age.is_some());
        assert!(validator.requirements.require_certificates);
    }

    #[test]
    fn test_device_id_validation() {
        let validator = PolicyValidatorBuilder::new()
            .allow_device_id("test-device-1")
            .build();

        // Test allowed device ID
        let evidence1 = create_test_evidence("test-device-1");
        assert!(validator.validate(&evidence1).unwrap());

        // Test disallowed device ID
        let evidence2 = create_test_evidence("test-device-2");
        assert!(!validator.validate(&evidence2).unwrap());
    }

    #[test]
    fn test_age_validation() {
        let validator = PolicyValidatorBuilder::new()
            .set_max_age(Duration::hours(1))
            .build();

        let mut evidence = create_test_evidence("test-device");
        match &mut evidence {
            Evidence::GpuLocal(claims) => {
                // Set timestamp to 2 hours ago
                claims.timestamp = Utc::now() - Duration::hours(2);
            }
            _ => panic!("Wrong evidence type"),
        }

        // Evidence should be too old
        assert!(!validator.validate(&evidence).unwrap());
    }

    #[test]
    fn test_multiple_validation() {
        let validator = PolicyValidatorBuilder::new()
            .allow_device_id("test-device-1")
            .allow_device_id("test-device-2")
            .build();

        let evidence_list = vec![
            create_test_evidence("test-device-1"),
            create_test_evidence("test-device-2"),
        ];

        assert!(validator.validate_multiple(&evidence_list).unwrap());

        let invalid_evidence_list = vec![
            create_test_evidence("test-device-1"),
            create_test_evidence("invalid-device"),
        ];

        assert!(!validator.validate_multiple(&invalid_evidence_list).unwrap());
    }
}
