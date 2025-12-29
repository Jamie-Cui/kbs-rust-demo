
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Attester type (SGX or TDX).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttesterType {
    #[serde(alias = "SGX")]
    Sgx,
    #[serde(alias = "TDX")]
    Tdx,
}

impl AttesterType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttesterType::Sgx => "SGX",
            AttesterType::Tdx => "TDX",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "SGX" => Some(AttesterType::Sgx),
            "TDX" => Some(AttesterType::Tdx),
            _ => None,
        }
    }
}

impl std::fmt::Display for AttesterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Claims from an attestation token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationTokenClaim {
    /// Attester type (SGX or TDX)
    #[serde(rename = "attester_type")]
    pub attester_type: AttesterType,

    /// TCB status of the attester
    #[serde(rename = "attester_tcb_status")]
    pub attester_tcb_status: String,

    /// Attestation held data (public key from workload)
    #[serde(rename = "attester_held_data")]
    pub attester_held_data: Option<String>,

    /// Policy IDs that matched
    #[serde(rename = "policy_ids_matched")]
    pub policy_ids_matched: Option<Vec<PolicyClaim>>,

    /// Policy IDs that didn't match
    #[serde(rename = "policy_ids_unmatched")]
    pub policy_ids_unmatched: Option<Vec<PolicyClaim>>,

    /// Verifier instance IDs
    #[serde(rename = "verifier_instance_ids")]
    pub verifier_instance_ids: Option<Vec<Uuid>>,

    /// SGX-specific claims
    #[serde(flatten)]
    pub sgx_claims: Option<SgxClaims>,

    /// TDX-specific claims
    #[serde(flatten)]
    pub tdx_claims: Option<TdxClaims>,

    /// Custom claims
    #[serde(rename = "policy_defined_claims")]
    pub policy_defined_claims: Option<serde_json::Value>,

    /// Advisory IDs
    #[serde(rename = "attester_advisory_ids")]
    pub attester_advisory_ids: Option<Vec<String>>,

    /// Version
    pub ver: String,
}

/// SGX-specific attestation claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SgxClaims {
    /// MRENCLAVE - measurement of the enclave
    #[serde(rename = "sgx_mrenclave")]
    pub sgx_mrenclave: String,

    /// MRSIGNER - measurement of the signer's public key
    #[serde(rename = "sgx_mrsigner")]
    pub sgx_mrsigner: String,

    /// ISV Product ID
    #[serde(rename = "sgx_isvprodid")]
    pub sgx_isvprodid: u16,

    /// ISV Security Version Number
    #[serde(rename = "sgx_isvsvn")]
    pub sgx_isvsvn: u16,

    /// Whether the enclave is debuggable
    #[serde(rename = "sgx_is_debuggable")]
    pub sgx_is_debuggable: bool,

    /// SGX report data
    #[serde(rename = "sgx_report_data")]
    pub sgx_report_data: Option<String>,

    /// SGX config ID
    #[serde(rename = "sgx_config_id")]
    pub sgx_config_id: Option<String>,

    /// Quote verification collateral
    #[serde(rename = "sgx_collateral")]
    pub sgx_collateral: Option<QuoteVerificationCollateral>,
}

/// TDX-specific attestation claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdxClaims {
    /// TDX TCB SVN
    #[serde(rename = "tdx_tee_tcb_svn")]
    pub tdx_tee_tcb_svn: String,

    /// MRSEAM - measurement of the SEAM module
    #[serde(rename = "tdx_mrseam")]
    pub tdx_mrseam: String,

    /// MRSIGNERSEAM - measurement of the SEAM signer's public key
    #[serde(rename = "tdx_mrsignerseam")]
    pub tdx_mrsignerseam: String,

    /// SEAM SVN
    #[serde(rename = "tdx_seamsvn")]
    pub tdx_seamsvn: u16,

    /// MRTD - measurement of the TD
    #[serde(rename = "tdx_mrtd")]
    pub tdx_mrtd: String,

    /// RTMR0
    #[serde(rename = "tdx_rtmr0")]
    pub tdx_rtmr0: String,

    /// RTMR1
    #[serde(rename = "tdx_rtmr1")]
    pub tdx_rtmr1: String,

    /// RTMR2
    #[serde(rename = "tdx_rtmr2")]
    pub tdx_rtmr2: String,

    /// RTMR3
    #[serde(rename = "tdx_rtmr3")]
    pub tdx_rtmr3: String,

    /// Whether the TD is debuggable
    #[serde(rename = "tdx_is_debuggable")]
    pub tdx_is_debuggable: bool,

    /// TD attributes
    #[serde(rename = "tdx_td_attributes")]
    pub tdx_td_attributes: Option<String>,

    /// SEAM attributes
    #[serde(rename = "tdx_seam_attributes")]
    pub tdx_seam_attributes: Option<String>,

    /// Report data
    #[serde(rename = "tdx_report_data")]
    pub tdx_report_data: Option<String>,

    /// Quote verification collateral
    #[serde(rename = "tdx_collateral")]
    pub tdx_collateral: Option<QuoteVerificationCollateral>,
}

/// Policy claim (policy ID that matched).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyClaim {
    /// Policy ID
    pub id: Uuid,

    /// Policy version
    pub version: String,
}

/// Quote verification collateral.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteVerificationCollateral {
    /// QE ID certificate hash
    #[serde(rename = "qeidcerthash")]
    pub qeidcerthash: Option<String>,

    /// QE ID CRL hash
    #[serde(rename = "qeidcrlhash")]
    pub qeidcrlhash: Option<String>,

    /// QE ID hash
    #[serde(rename = "qeidhash")]
    pub qeidhash: Option<String>,

    /// Quote hash
    #[serde(rename = "quotehash")]
    pub quotehash: Option<String>,

    /// TCB info certificate hash
    #[serde(rename = "tcbinfocerthash")]
    pub tcbinfocerthash: Option<String>,

    /// TCB info CRL hash
    #[serde(rename = "tcbinfocrlhash")]
    pub tcbinfocrlhash: Option<String>,

    /// TCB info hash
    #[serde(rename = "tcbinfohash")]
    pub tcbinfohash: Option<String>,
}

/// Verifier nonce from Intel Trust Authority (internal representation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierNonce {
    /// Nonce value (base64 encoded)
    pub val: String,

    /// Issued at timestamp (base64 encoded)
    pub iat: String,

    /// Signature (base64 encoded)
    pub signature: String,
}

/// Verifier nonce for API requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierNonceRequest {
    /// Nonce value (base64 encoded)
    pub val: String,

    /// Issued at timestamp (base64 encoded)
    pub iat: String,

    /// Signature (base64 encoded)
    pub signature: String,
}

/// Verifier nonce data in API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierNonceData {
    /// Nonce value (base64 encoded)
    pub val: String,

    /// Issued at timestamp (base64 encoded)
    pub iat: String,

    /// Signature (base64 encoded)
    pub signature: String,
}
