// Copyright (c) 2025 Jamie Cui
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


use super::*;

#[test]
fn test_attester_type_from_str() {
    assert_eq!(AttesterType::from_str("SGX"), Some(AttesterType::Sgx));
    assert_eq!(AttesterType::from_str("sgx"), Some(AttesterType::Sgx));
    assert_eq!(AttesterType::from_str("Sgx"), Some(AttesterType::Sgx));
    assert_eq!(AttesterType::from_str("TDX"), Some(AttesterType::Tdx));
    assert_eq!(AttesterType::from_str("tdx"), Some(AttesterType::Tdx));
    assert_eq!(AttesterType::from_str("Tdx"), Some(AttesterType::Tdx));
    assert_eq!(AttesterType::from_str("invalid"), None);
}

#[test]
fn test_attester_type_as_str() {
    assert_eq!(AttesterType::Sgx.as_str(), "SGX");
    assert_eq!(AttesterType::Tdx.as_str(), "TDX");
}

#[test]
fn test_attester_type_display() {
    assert_eq!(format!("{}", AttesterType::Sgx), "SGX");
    assert_eq!(format!("{}", AttesterType::Tdx), "TDX");
}

#[test]
fn test_attester_type_equality() {
    assert_eq!(AttesterType::Sgx, AttesterType::Sgx);
    assert_eq!(AttesterType::Tdx, AttesterType::Tdx);
    assert_ne!(AttesterType::Sgx, AttesterType::Tdx);
}

#[test]
fn test_attester_type_hash() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(AttesterType::Sgx);
    set.insert(AttesterType::Tdx);
    assert_eq!(set.len(), 2);

    // Inserting duplicate should not increase size
    set.insert(AttesterType::Sgx);
    assert_eq!(set.len(), 2);
}

#[test]
fn test_attestation_token_claim_serialization() {
    let claim = AttestationTokenClaim {
        attester_type: AttesterType::Sgx,
        attester_tcb_status: "UpToDate".to_string(),
        attester_held_data: Some("dGVzdC1kYXRh".to_string()),
        policy_ids_matched: None,
        policy_ids_unmatched: None,
        verifier_instance_ids: None,
        sgx_claims: None,
        tdx_claims: None,
        policy_defined_claims: None,
        attester_advisory_ids: None,
        ver: "1.0".to_string(),
    };

    let json = serde_json::to_string(&claim).unwrap();
    assert!(json.contains("SGX"));
    assert!(json.contains("UpToDate"));

    let parsed: AttestationTokenClaim = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.attester_type, AttesterType::Sgx);
    assert_eq!(parsed.attester_tcb_status, "UpToDate");
}

#[test]
fn test_sgx_claims_serialization() {
    let claims = SgxClaims {
        sgx_mrenclave: "abc123".to_string(),
        sgx_mrsigner: "def456".to_string(),
        sgx_isvprodid: 1,
        sgx_isvsvn: 2,
        sgx_is_debuggable: true,
        sgx_report_data: None,
        sgx_config_id: None,
        sgx_collateral: None,
    };

    let json = serde_json::to_string(&claims).unwrap();
    let parsed: SgxClaims = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.sgx_mrenclave, "abc123");
    assert_eq!(parsed.sgx_isvprodid, 1);
    assert!(parsed.sgx_is_debuggable);
}

#[test]
fn test_tdx_claims_serialization() {
    let claims = TdxClaims {
        tdx_tee_tcb_svn: "svn123".to_string(),
        tdx_mrseam: "mrseam".to_string(),
        tdx_mrsignerseam: "mrsigner".to_string(),
        tdx_seamsvn: 1,
        tdx_mrtd: "mrt d".to_string(),
        tdx_rtmr0: "rtmr0".to_string(),
        tdx_rtmr1: "rtmr1".to_string(),
        tdx_rtmr2: "rtmr2".to_string(),
        tdx_rtmr3: "rtmr3".to_string(),
        tdx_is_debuggable: false,
        tdx_td_attributes: None,
        tdx_seam_attributes: None,
        tdx_report_data: None,
        tdx_collateral: None,
    };

    let json = serde_json::to_string(&claims).unwrap();
    let parsed: TdxClaims = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.tdx_mrseam, "mrseam");
    assert_eq!(parsed.tdx_seamsvn, 1);
    assert!(!parsed.tdx_is_debuggable);
}

#[test]
fn test_verifier_nonce_serialization() {
    let nonce = VerifierNonce {
        val: "dmFsdWU=".to_string(),
        iat: "aWF0".to_string(),
        signature: "c2lnbmF0dXJl".to_string(),
    };

    let json = serde_json::to_string(&nonce).unwrap();
    let parsed: VerifierNonce = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.val, "dmFsdWU=");
    assert_eq!(parsed.iat, "aWF0");
    assert_eq!(parsed.signature, "c2lnbmF0dXJl");
}
