pub mod error;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::ser::SerializeMap;
use serde::de::{Visitor, MapAccess};
use std::collections::BTreeMap;
use std::fmt;

/// AWS Nitro Enclaves Attestation Document
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AttestationDoc {
    pub module_id: String,
    pub timestamp: u64,
    pub digest: String,
    pub pcrs: BTreeMap<u32, Vec<u8>>,
    pub certificate: Vec<u8>,
    pub cabundle: Vec<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

impl AttestationDoc {
    /// Deserialize an AttestationDoc from raw CBOR bytes
    pub fn from_binary(bytes: &[u8]) -> Result<Self, ciborium::de::Error<std::io::Error>> {
        ciborium::from_reader(bytes)
    }

    /// Serialize an AttestationDoc to raw CBOR bytes
    pub fn to_binary(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)?;
        Ok(bytes)
    }
}

/// VeriAI Custom Claims (CWT Claims Set)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VeriClaims {
    pub model_hash: [u8; 32],
    pub input_hash: [u8; 32],
    pub output_hash: [u8; 32],
    pub client_nonce: [u8; 32],
    pub sequence_num: u64,
    pub attestation_report: Vec<u8>,
    pub attestation_type: u64, // 3 = Nitro
    pub attestation_timestamp: i64,
    pub sdk_version: String,
    pub enclave_pubkey: [u8; 32],
}

// Custom Claim Keys
pub const CLAIM_MODEL_HASH: i64 = 6000;
pub const CLAIM_INPUT_HASH: i64 = 6001;
pub const CLAIM_OUTPUT_HASH: i64 = 6002;
pub const CLAIM_CLIENT_NONCE: i64 = 6003;
pub const CLAIM_SEQUENCE_NUM: i64 = 6004;
pub const CLAIM_ATTESTATION_REPORT: i64 = 6005;
pub const CLAIM_ATTESTATION_TYPE: i64 = 6006;
pub const CLAIM_ATTESTATION_TIMESTAMP: i64 = 6007;
pub const CLAIM_SDK_VERSION: i64 = 6011;
pub const CLAIM_ENCLAVE_PUBKEY: i64 = 6012;

impl VeriClaims {
    /// Deserialize VeriClaims from raw CBOR bytes
    pub fn from_binary(bytes: &[u8]) -> Result<Self, ciborium::de::Error<std::io::Error>> {
        ciborium::from_reader(bytes)
    }

    /// Serialize VeriClaims to raw CBOR bytes
    pub fn to_binary(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)?;
        Ok(bytes)
    }
}

impl Serialize for VeriClaims {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(10))?;
        map.serialize_entry(&CLAIM_MODEL_HASH, &self.model_hash[..])?;
        map.serialize_entry(&CLAIM_INPUT_HASH, &self.input_hash[..])?;
        map.serialize_entry(&CLAIM_OUTPUT_HASH, &self.output_hash[..])?;
        map.serialize_entry(&CLAIM_CLIENT_NONCE, &self.client_nonce[..])?;
        map.serialize_entry(&CLAIM_SEQUENCE_NUM, &self.sequence_num)?;
        map.serialize_entry(&CLAIM_ATTESTATION_REPORT, &self.attestation_report)?;
        map.serialize_entry(&CLAIM_ATTESTATION_TYPE, &self.attestation_type)?;
        map.serialize_entry(&CLAIM_ATTESTATION_TIMESTAMP, &self.attestation_timestamp)?;
        map.serialize_entry(&CLAIM_SDK_VERSION, &self.sdk_version)?;
        map.serialize_entry(&CLAIM_ENCLAVE_PUBKEY, &self.enclave_pubkey[..])?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for VeriClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VeriClaimsVisitor;

        impl<'de> Visitor<'de> for VeriClaimsVisitor {
            type Value = VeriClaims;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a VeriClaims map")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut model_hash = None;
                let mut input_hash = None;
                let mut output_hash = None;
                let mut client_nonce = None;
                let mut sequence_num = None;
                let mut attestation_report = None;
                let mut attestation_type = None;
                let mut attestation_timestamp = None;
                let mut sdk_version = None;
                let mut enclave_pubkey = None;

                while let Some(key) = map.next_key::<i64>()? {
                    match key {
                        CLAIM_MODEL_HASH => {
                            let val: Vec<u8> = map.next_value()?;
                            let mut arr = [0u8; 32];
                            if val.len() == 32 {
                                arr.copy_from_slice(&val);
                                model_hash = Some(arr);
                            } else {
                                return Err(serde::de::Error::custom("invalid model-hash length"));
                            }
                        }
                        CLAIM_INPUT_HASH => {
                            let val: Vec<u8> = map.next_value()?;
                            let mut arr = [0u8; 32];
                            if val.len() == 32 {
                                arr.copy_from_slice(&val);
                                input_hash = Some(arr);
                            } else {
                                return Err(serde::de::Error::custom("invalid input-hash length"));
                            }
                        }
                        CLAIM_OUTPUT_HASH => {
                            let val: Vec<u8> = map.next_value()?;
                            let mut arr = [0u8; 32];
                            if val.len() == 32 {
                                arr.copy_from_slice(&val);
                                output_hash = Some(arr);
                            } else {
                                return Err(serde::de::Error::custom("invalid output-hash length"));
                            }
                        }
                        CLAIM_CLIENT_NONCE => {
                            let val: Vec<u8> = map.next_value()?;
                            let mut arr = [0u8; 32];
                            if val.len() == 32 {
                                arr.copy_from_slice(&val);
                                client_nonce = Some(arr);
                            } else {
                                return Err(serde::de::Error::custom("invalid client-nonce length"));
                            }
                        }
                        CLAIM_SEQUENCE_NUM => {
                            sequence_num = Some(map.next_value()?);
                        }
                        CLAIM_ATTESTATION_REPORT => {
                            attestation_report = Some(map.next_value()?);
                        }
                        CLAIM_ATTESTATION_TYPE => {
                            attestation_type = Some(map.next_value()?);
                        }
                        CLAIM_ATTESTATION_TIMESTAMP => {
                            attestation_timestamp = Some(map.next_value()?);
                        }
                        CLAIM_SDK_VERSION => {
                            sdk_version = Some(map.next_value()?);
                        }
                        CLAIM_ENCLAVE_PUBKEY => {
                            let val: Vec<u8> = map.next_value()?;
                            let mut arr = [0u8; 32];
                            if val.len() == 32 {
                                arr.copy_from_slice(&val);
                                enclave_pubkey = Some(arr);
                            } else {
                                return Err(serde::de::Error::custom("invalid enclave-pubkey length"));
                            }
                        }
                        reserved if (6008..=6010).contains(&reserved) => {
                            return Err(serde::de::Error::custom(format!("claim key {} is reserved", reserved)));
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                let model_hash = model_hash.ok_or_else(|| serde::de::Error::missing_field("model_hash"))?;
                let input_hash = input_hash.ok_or_else(|| serde::de::Error::missing_field("input_hash"))?;
                let output_hash = output_hash.ok_or_else(|| serde::de::Error::missing_field("output_hash"))?;
                let client_nonce = client_nonce.ok_or_else(|| serde::de::Error::missing_field("client_nonce"))?;
                let sequence_num = sequence_num.ok_or_else(|| serde::de::Error::missing_field("sequence_num"))?;
                let attestation_report = attestation_report.ok_or_else(|| serde::de::Error::missing_field("attestation_report"))?;
                let attestation_type = attestation_type.ok_or_else(|| serde::de::Error::missing_field("attestation_type"))?;
                let attestation_timestamp = attestation_timestamp.ok_or_else(|| serde::de::Error::missing_field("attestation_timestamp"))?;
                let sdk_version = sdk_version.ok_or_else(|| serde::de::Error::missing_field("sdk_version"))?;
                let enclave_pubkey = enclave_pubkey.ok_or_else(|| serde::de::Error::missing_field("enclave_pubkey"))?;

                Ok(VeriClaims {
                    model_hash,
                    input_hash,
                    output_hash,
                    client_nonce,
                    sequence_num,
                    attestation_report,
                    attestation_type,
                    attestation_timestamp,
                    sdk_version,
                    enclave_pubkey,
                })
            }
        }

        deserializer.deserialize_map(VeriClaimsVisitor)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VerificationCheck {
    pub name: String,
    pub status: String, // "passed" or "failed"
    pub details: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReceiptInfo {
    pub version: String,
    pub model_hash: String,
    pub input_hash: String,
    pub output_hash: String,
    pub sequence_num: u64,
    pub timestamp: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    pub valid: bool,
    pub receipt: Option<ReceiptInfo>,
    pub checks: Vec<VerificationCheck>,
    pub attestation_provider: String,
    pub verified_hardware: bool,
    pub error: Option<String>,
}
