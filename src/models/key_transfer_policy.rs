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


use crate::models::attestation::AttesterType;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Key transfer policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyTransferPolicy {
    /// Policy ID
    pub id: Uuid,

    /// Creation timestamp
    #[serde(rename = "created_at")]
    pub created_at: time::OffsetDateTime,

    /// Attestation type
    #[serde(rename = "attestation_type")]
    pub attestation_type: AttesterType,

    /// SGX policy
    pub sgx: Option<SgxPolicy>,

    /// TDX policy
    pub tdx: Option<TdxPolicy>,
}

/// SGX policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SgxPolicy {
    /// SGX attributes
    pub attributes: Option<SgxAttributes>,

    /// Policy IDs (matched by ITA)
    #[serde(rename = "policy_ids")]
    pub policy_ids: Option<Vec<Uuid>>,
}

/// SGX attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SgxAttributes {
    /// MRSIGNER - list of allowed signer measurements
    #[serde(rename = "mrsigner")]
    pub mrsigner: Option<Vec<String>>,

    /// ISVPRODID - list of allowed product IDs
    #[serde(rename = "isvprodid")]
    pub isvprodid: Option<Vec<u16>>,

    /// MRENCLAVE - list of allowed enclave measurements
    #[serde(rename = "mrenclave")]
    pub mrenclave: Option<Vec<String>>,

    /// ISVSVN - minimum security version number
    #[serde(rename = "isvsvn")]
    pub isvsvn: Option<u16>,

    /// Enforce TCB up-to-date
    #[serde(rename = "enforce_tcb_upto_date")]
    pub enforce_tcb_upto_date: Option<bool>,
}

/// TDX policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdxPolicy {
    /// TDX attributes
    pub attributes: Option<TdxAttributes>,

    /// Policy IDs (matched by ITA)
    #[serde(rename = "policy_ids")]
    pub policy_ids: Option<Vec<Uuid>>,
}

/// TDX attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdxAttributes {
    /// MRSIGNERSEAM - list of allowed SEAM signer measurements
    #[serde(rename = "mrsignerseam")]
    pub mrsignerseam: Option<Vec<String>>,

    /// MRSEAM - list of allowed SEAM measurements
    #[serde(rename = "mrseam")]
    pub mrseam: Option<Vec<String>>,

    /// SEAMSVN - minimum SEAM security version number
    #[serde(rename = "seamsvn")]
    pub seamsvn: Option<u16>,

    /// MRTD - list of allowed TD measurements
    #[serde(rename = "mrtd")]
    pub mrtd: Option<Vec<String>>,

    /// RTMR0
    pub rtmr0: Option<String>,

    /// RTMR1
    pub rtmr1: Option<String>,

    /// RTMR2
    pub rtmr2: Option<String>,

    /// RTMR3
    pub rtmr3: Option<String>,

    /// Enforce TCB up-to-date
    #[serde(rename = "enforce_tcb_upto_date")]
    pub enforce_tcb_upto_date: Option<bool>,
}

/// Key transfer policy filter criteria (empty for now).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyTransferPolicyFilterCriteria;

#[cfg(test)]
#[path = "key_transfer_policy_tests.rs"]
mod key_transfer_policy_tests;
