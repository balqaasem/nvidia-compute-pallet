use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Public},
    sign::Verifier as OpenSslVerifier,
};

use crate::{
    AttestationError,
    verifiers::{Verifier, Evidence, VerifierClaims},
};

#[derive(Debug)]
pub struct NvSwitchLocalVerifier {
    device_id: String,
    public_key: PKey<Public>,
}

impl NvSwitchLocalVerifier {
    pub fn new(device_id: String, public_key_pem: &str) -> Result<Self, AttestationError> {
        let public_key = PKey::public_key_from_pem(public_key_pem.as_bytes())
            .map_err(|_| AttestationError::InvalidKey)?;

        Ok(Self {
            device_id,
            public_key,
        })
    }

    fn collect_measurements(&self) -> Result<Vec<u8>, AttestationError> {
        // TODO: Implement actual NVSwitch measurement collection
        Ok(vec![0; 32]) // Placeholder 32-byte measurement
    }

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, AttestationError> {
        let mut verifier = OpenSslVerifier::new(MessageDigest::sha256(), &self.public_key)
            .map_err(|_| AttestationError::VerificationError)?;
        
        verifier.update(data)
            .map_err(|_| AttestationError::VerificationError)?;
            
        verifier.verify(signature)
            .map_err(|_| AttestationError::VerificationError)
    }
}

impl Verifier for NvSwitchLocalVerifier {
    fn name(&self) -> &str {
        "NVSwitch Local Verifier"
    }

    fn get_evidence(&self, ppcie_mode: bool) -> Result<Evidence, AttestationError> {
        let measurements = self.collect_measurements()?;
        
        let claims = VerifierClaims {
            device_id: self.device_id.clone(),
            measurements,
            timestamp: chrono::Utc::now(),
            ppcie_mode,
            // TODO: Add additional NVSwitch-specific claims
        };

        Ok(Evidence::NvSwitchLocal(claims))
    }

    fn verify(&self, evidence: &Evidence) -> Result<bool, AttestationError> {
        match evidence {
            Evidence::NvSwitchLocal(claims) => {
                // Verify device ID matches
                if claims.device_id != self.device_id {
                    return Ok(false);
                }

                // TODO: Implement actual measurement verification
                // For now, just check that measurements are present
                if claims.measurements.is_empty() {
                    return Ok(false);
                }

                // TODO: Verify signature when implemented
                Ok(true)
            }
            _ => Err(AttestationError::InvalidEvidence),
        }
    }

    fn get_claims(&self) -> Result<HashMap<String, Value>, AttestationError> {
        let mut claims = HashMap::new();
        claims.insert("device_id".to_string(), Value::String(self.device_id.clone()));
        claims.insert("verifier_type".to_string(), Value::String("nvswitch_local".to_string()));
        Ok(claims)
    }
}

#[derive(Debug)]
pub struct NvSwitchRemoteVerifier {
    url: String,
    device_id: String,
    public_key: PKey<Public>,
    client: reqwest::Client,
}

impl NvSwitchRemoteVerifier {
    pub fn new(url: String, device_id: String, public_key_pem: &str) -> Result<Self, AttestationError> {
        let public_key = PKey::public_key_from_pem(public_key_pem.as_bytes())
            .map_err(|_| AttestationError::InvalidKey)?;

        Ok(Self {
            url,
            device_id,
            public_key,
            client: reqwest::Client::new(),
        })
    }

    async fn fetch_measurements(&self) -> Result<Vec<u8>, AttestationError> {
        let response = self.client.get(&format!("{}/measurements/{}", self.url, self.device_id))
            .send()
            .await
            .map_err(|_| AttestationError::NetworkError)?;

        let measurements = response.bytes()
            .await
            .map_err(|_| AttestationError::NetworkError)?;

        Ok(measurements.to_vec())
    }

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, AttestationError> {
        let mut verifier = OpenSslVerifier::new(MessageDigest::sha256(), &self.public_key)
            .map_err(|_| AttestationError::VerificationError)?;
        
        verifier.update(data)
            .map_err(|_| AttestationError::VerificationError)?;
            
        verifier.verify(signature)
            .map_err(|_| AttestationError::VerificationError)
    }
}

impl Verifier for NvSwitchRemoteVerifier {
    fn name(&self) -> &str {
        "NVSwitch Remote Verifier"
    }

    fn get_evidence(&self, ppcie_mode: bool) -> Result<Evidence, AttestationError> {
        // Create runtime for async operations
        let rt = tokio::runtime::Runtime::new()
            .map_err(|_| AttestationError::RuntimeError)?;

        let measurements = rt.block_on(self.fetch_measurements())?;
        
        let claims = VerifierClaims {
            device_id: self.device_id.clone(),
            measurements,
            timestamp: chrono::Utc::now(),
            ppcie_mode,
            // TODO: Add additional NVSwitch-specific claims
        };

        Ok(Evidence::NvSwitchRemote(claims))
    }

    fn verify(&self, evidence: &Evidence) -> Result<bool, AttestationError> {
        match evidence {
            Evidence::NvSwitchRemote(claims) => {
                // Verify device ID matches
                if claims.device_id != self.device_id {
                    return Ok(false);
                }

                // TODO: Implement actual measurement verification
                // For now, just check that measurements are present
                if claims.measurements.is_empty() {
                    return Ok(false);
                }

                // TODO: Verify signature when implemented
                Ok(true)
            }
            _ => Err(AttestationError::InvalidEvidence),
        }
    }

    fn get_claims(&self) -> Result<HashMap<String, Value>, AttestationError> {
        let mut claims = HashMap::new();
        claims.insert("device_id".to_string(), Value::String(self.device_id.clone()));
        claims.insert("verifier_type".to_string(), Value::String("nvswitch_remote".to_string()));
        claims.insert("url".to_string(), Value::String(self.url.clone()));
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX
ZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS
oc/6es03NtnrbtxnMXLxMq6MgUQInKADUpxk+1YVDwfxOJxRtQWMiirdg+HUu3BA
mIAylv+YN/+/LCuMS4EQPWh8wUJ2zGsF1pP2eI6BvsYii3wEZ/6o2ykLMjHJ6Zk7
QIzDs9E6fxvxLZK2EpiL8MnZ1izI9oZUxqKC0GTLROJqVRBxY4/q2WsNdIN5Jvmk
wPqUk/B6tqPH24YvJq04PttjwfEUw8sE1LQjP6Ue0JrJkNHGNtz9E+9Acjz5LQID
AQAB
-----END PUBLIC KEY-----"#;

    #[test]
    fn test_nvswitch_local_verifier() {
        let verifier = NvSwitchLocalVerifier::new(
            "test-switch-0".to_string(),
            TEST_PUBLIC_KEY,
        ).unwrap();

        // Test evidence collection
        let evidence = verifier.get_evidence(false).unwrap();
        match evidence {
            Evidence::NvSwitchLocal(claims) => {
                assert_eq!(claims.device_id, "test-switch-0");
                assert!(!claims.measurements.is_empty());
            }
            _ => panic!("Wrong evidence type"),
        }

        // Test verification
        assert!(verifier.verify(&evidence).unwrap());
    }

    #[test]
    fn test_nvswitch_remote_verifier() {
        let verifier = NvSwitchRemoteVerifier::new(
            "https://attestation.example.com".to_string(),
            "test-switch-1".to_string(),
            TEST_PUBLIC_KEY,
        ).unwrap();

        // Test claims generation
        let claims = verifier.get_claims().unwrap();
        assert_eq!(claims.get("device_id").unwrap().as_str().unwrap(), "test-switch-1");
        assert_eq!(claims.get("verifier_type").unwrap().as_str().unwrap(), "nvswitch_remote");
    }
}
