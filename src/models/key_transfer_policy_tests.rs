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
fn test_key_transfer_policy_serialization() {
    let policy = KeyTransferPolicy {
        id: Uuid::new_v4(),
        created_at: time::OffsetDateTime::now_utc(),
        attestation_type: AttesterType::Sgx,
        sgx: Some(SgxPolicy {
            attributes: Some(SgxAttributes {
                mrsigner: Some(vec!["mrsigner1".to_string(), "mrsigner2".to_string()]),
                isvprodid: Some(vec![1, 2]),
                mrenclave: Some(vec!["mrenclave1".to_string()]),
                isvsvn: Some(2),
                enforce_tcb_upto_date: Some(true),
            }),
            policy_ids: Some(vec![Uuid::new_v4(), Uuid::new_v4()]),
        }),
        tdx: None,
    };

    let json = serde_json::to_string(&policy).unwrap();
    assert!(json.contains("SGX"));

    let parsed: KeyTransferPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.attestation_type, AttesterType::Sgx);
    assert!(parsed.sgx.is_some());
    assert!(parsed.tdx.is_none());
}

#[test]
fn test_tdx_policy_serialization() {
    let policy = KeyTransferPolicy {
        id: Uuid::new_v4(),
        created_at: time::OffsetDateTime::now_utc(),
        attestation_type: AttesterType::Tdx,
        sgx: None,
        tdx: Some(TdxPolicy {
            attributes: Some(TdxAttributes {
                mrsignerseam: Some(vec!["mrsignerseam1".to_string()]),
                mrseam: Some(vec!["mrseam1".to_string()]),
                seamsvn: Some(1),
                mrtd: Some(vec!["mrtd1".to_string()]),
                rtmr0: Some("rtmr0".to_string()),
                rtmr1: Some("rtmr1".to_string()),
                rtmr2: Some("rtmr2".to_string()),
                rtmr3: Some("rtmr3".to_string()),
                enforce_tcb_upto_date: Some(false),
            }),
            policy_ids: Some(vec![Uuid::new_v4()]),
        }),
    };

    let json = serde_json::to_string(&policy).unwrap();
    assert!(json.contains("TDX"));

    let parsed: KeyTransferPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.attestation_type, AttesterType::Tdx);
    assert!(parsed.tdx.is_some());
    assert!(parsed.sgx.is_none());
}

#[test]
fn test_sgx_attributes_optional_fields() {
    let attributes = SgxAttributes {
        mrsigner: None,
        isvprodid: None,
        mrenclave: None,
        isvsvn: None,
        enforce_tcb_upto_date: None,
    };

    let json = serde_json::to_string(&attributes).unwrap();
    let parsed: SgxAttributes = serde_json::from_str(&json).unwrap();

    assert!(parsed.mrsigner.is_none());
    assert!(parsed.isvprodid.is_none());
    assert!(parsed.mrenclave.is_none());
    assert!(parsed.isvsvn.is_none());
    assert!(parsed.enforce_tcb_upto_date.is_none());
}

#[test]
fn test_tdx_attributes_optional_fields() {
    let attributes = TdxAttributes {
        mrsignerseam: None,
        mrseam: None,
        seamsvn: None,
        mrtd: None,
        rtmr0: None,
        rtmr1: None,
        rtmr2: None,
        rtmr3: None,
        enforce_tcb_upto_date: None,
    };

    let json = serde_json::to_string(&attributes).unwrap();
    let parsed: TdxAttributes = serde_json::from_str(&json).unwrap();

    assert!(parsed.mrsignerseam.is_none());
    assert!(parsed.mrseam.is_none());
    assert!(parsed.seamsvn.is_none());
    assert!(parsed.mrtd.is_none());
    assert!(parsed.rtmr0.is_none());
}

#[test]
fn test_key_transfer_policy_filter_criteria_default() {
    let criteria = KeyTransferPolicyFilterCriteria::default();
    // Just verify it can be created
    let _ = criteria;
}

#[test]
fn test_policy_with_both_sgx_and_tdx() {
    let policy = KeyTransferPolicy {
        id: Uuid::new_v4(),
        created_at: time::OffsetDateTime::now_utc(),
        attestation_type: AttesterType::Sgx,
        sgx: Some(SgxPolicy {
            attributes: None,
            policy_ids: Some(vec![]),
        }),
        tdx: Some(TdxPolicy {
            attributes: None,
            policy_ids: Some(vec![]),
        }),
    };

    // This is a valid state (though semantically odd)
    let json = serde_json::to_string(&policy).unwrap();
    let parsed: KeyTransferPolicy = serde_json::from_str(&json).unwrap();

    assert!(parsed.sgx.is_some());
    assert!(parsed.tdx.is_some());
}
