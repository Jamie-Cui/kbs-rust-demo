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


use crate::constant::TCB_STATUS_UP_TO_DATE;
use crate::error::{KbsError, KbsResult};
use crate::models::{
    AttestationTokenClaim, AttesterType, KeyTransferPolicy, PolicyClaim,
};

/// Validate attestation token claims against a key transfer policy.
pub fn validate_attestation_claims(
    claims: &AttestationTokenClaim,
    policy: &KeyTransferPolicy,
) -> KbsResult<()> {
    match policy.attestation_type {
        AttesterType::Sgx => {
            // Check if using policy ID matching
            if let Some(ref sgx_policy) = policy.sgx {
                if let Some(ref token_policy_ids) = claims.policy_ids_matched {
                    if let Some(ref policy_ids) = sgx_policy.policy_ids {
                        if is_policy_id_matched(token_policy_ids, policy_ids) {
                            return Ok(());
                        } else {
                            return Err(KbsError::Service(
                                crate::error::ServiceError::PolicyValidation(
                                    "No matching policy IDs".into(),
                                ),
                            ));
                        }
                    }
                }

                // Otherwise, validate against SGX attributes
                if let Some(ref attrs) = sgx_policy.attributes {
                    validate_sgx_claims(claims, attrs)?;
                }
            }
        }
        AttesterType::Tdx => {
            // Check if using policy ID matching
            if let Some(ref tdx_policy) = policy.tdx {
                if let Some(ref token_policy_ids) = claims.policy_ids_matched {
                    if let Some(ref policy_ids) = tdx_policy.policy_ids {
                        if is_policy_id_matched(token_policy_ids, policy_ids) {
                            return Ok(());
                        } else {
                            return Err(KbsError::Service(
                                crate::error::ServiceError::PolicyValidation(
                                    "No matching policy IDs".into(),
                                ),
                            ));
                        }
                    }
                }

                // Otherwise, validate against TDX attributes
                if let Some(ref attrs) = tdx_policy.attributes {
                    validate_tdx_claims(claims, attrs)?;
                }
            }
        }
    }

    Ok(())
}

/// Check if any policy ID matches.
fn is_policy_id_matched(token_ids: &[PolicyClaim], policy_ids: &[uuid::Uuid]) -> bool {
    token_ids
        .iter()
        .any(|t| policy_ids.contains(&t.id))
}

/// Validate SGX attestation claims.
fn validate_sgx_claims(
    claims: &AttestationTokenClaim,
    attrs: &crate::models::SgxAttributes,
) -> KbsResult<()> {
    let sgx_claims = claims
        .sgx_claims
        .as_ref()
        .ok_or_else(|| KbsError::Validation("Missing SGX claims in token".into()))?;

    // Validate MRSIGNER
    if let Some(ref mrsigner) = attrs.mrsigner {
        if !mrsigner.contains(&sgx_claims.sgx_mrsigner) {
            return Err(KbsError::Authorization(
                "MRSIGNER does not match policy".into(),
            ));
        }
    }

    // Validate MRENCLAVE
    if let Some(ref mrenclave) = attrs.mrenclave {
        if !mrenclave.contains(&sgx_claims.sgx_mrenclave) {
            return Err(KbsError::Authorization(
                "MRENCLAVE does not match policy".into(),
            ));
        }
    }

    // Validate ISVPRODID
    if let Some(ref isvprodid) = attrs.isvprodid {
        if !isvprodid.contains(&sgx_claims.sgx_isvprodid) {
            return Err(KbsError::Authorization(
                "ISVPRODID does not match policy".into(),
            ));
        }
    }

    // Validate ISVSVN
    if let Some(isvsvn) = attrs.isvsvn {
        if sgx_claims.sgx_isvsvn < isvsvn {
            return Err(KbsError::Authorization(
                "ISVSVN below minimum required version".into(),
            ));
        }
    }

    // Validate TCB status
    if let Some(true) = attrs.enforce_tcb_upto_date {
        if claims.attester_tcb_status != TCB_STATUS_UP_TO_DATE {
            return Err(KbsError::Authorization("TCB is not up-to-date".into()));
        }
    }

    Ok(())
}

/// Validate TDX attestation claims.
fn validate_tdx_claims(
    claims: &AttestationTokenClaim,
    attrs: &crate::models::TdxAttributes,
) -> KbsResult<()> {
    let tdx_claims = claims
        .tdx_claims
        .as_ref()
        .ok_or_else(|| KbsError::Validation("Missing TDX claims in token".into()))?;

    // Validate MRSIGNERSEAM
    if let Some(ref mrsignerseam) = attrs.mrsignerseam {
        if !mrsignerseam.contains(&tdx_claims.tdx_mrsignerseam) {
            return Err(KbsError::Authorization(
                "MRSIGNERSEAM does not match policy".into(),
            ));
        }
    }

    // Validate MRSEAM
    if let Some(ref mrseam) = attrs.mrseam {
        if !mrseam.contains(&tdx_claims.tdx_mrseam) {
            return Err(KbsError::Authorization(
                "MRSEAM does not match policy".into(),
            ));
        }
    }

    // Validate SEAMSVN
    if let Some(seamsvn) = attrs.seamsvn {
        if tdx_claims.tdx_seamsvn < seamsvn {
            return Err(KbsError::Authorization(
                "SEAMSVN below minimum required version".into(),
            ));
        }
    }

    // Validate MRTD
    if let Some(ref mrtd) = attrs.mrtd {
        if !mrtd.contains(&tdx_claims.tdx_mrtd) {
            return Err(KbsError::Authorization(
                "MRTD does not match policy".into(),
            ));
        }
    }

    // Validate RTMR0
    if let Some(ref rtmr0) = attrs.rtmr0 {
        if !rtmr0.is_empty() && tdx_claims.tdx_rtmr0 != *rtmr0 {
            return Err(KbsError::Authorization("RTMR0 does not match policy".into()));
        }
    }

    // Validate RTMR1
    if let Some(ref rtmr1) = attrs.rtmr1 {
        if !rtmr1.is_empty() && tdx_claims.tdx_rtmr1 != *rtmr1 {
            return Err(KbsError::Authorization("RTMR1 does not match policy".into()));
        }
    }

    // Validate RTMR2
    if let Some(ref rtmr2) = attrs.rtmr2 {
        if !rtmr2.is_empty() && tdx_claims.tdx_rtmr2 != *rtmr2 {
            return Err(KbsError::Authorization("RTMR2 does not match policy".into()));
        }
    }

    // Validate RTMR3
    if let Some(ref rtmr3) = attrs.rtmr3 {
        if !rtmr3.is_empty() && tdx_claims.tdx_rtmr3 != *rtmr3 {
            return Err(KbsError::Authorization("RTMR3 does not match policy".into()));
        }
    }

    // Validate TCB status
    if let Some(true) = attrs.enforce_tcb_upto_date {
        if claims.attester_tcb_status != TCB_STATUS_UP_TO_DATE {
            return Err(KbsError::Authorization("TCB is not up-to-date".into()));
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "validation_tests.rs"]
mod validation_tests;
