/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

//! Key transfer policy service.

use async_trait::async_trait;
use std::sync::Arc;

use crate::error::{KbsError, KbsResult};
use crate::models::{
    AttesterType, KeyTransferPolicy, KeyTransferPolicyFilterCriteria, SgxAttributes,
    TdxAttributes,
};
use crate::repositories::KeyTransferPolicyStore;

/// Key transfer policy service trait.
#[async_trait]
pub trait KeyTransferPolicyService: Send + Sync {
    /// Create a new key transfer policy.
    async fn create_policy(&self, policy: KeyTransferPolicy) -> KbsResult<KeyTransferPolicy>;

    /// Search for policies.
    async fn search_policies(
        &self,
        criteria: KeyTransferPolicyFilterCriteria,
    ) -> KbsResult<Vec<KeyTransferPolicy>>;

    /// Delete a policy.
    async fn delete_policy(&self, id: uuid::Uuid) -> KbsResult<()>;

    /// Get a policy by ID.
    async fn get_policy(&self, id: uuid::Uuid) -> KbsResult<KeyTransferPolicy>;
}

/// Implementation of the key transfer policy service.
pub struct KeyTransferPolicyServiceImpl<P>
where
    P: KeyTransferPolicyStore,
{
    policy_store: Arc<P>,
}

impl<P> KeyTransferPolicyServiceImpl<P>
where
    P: KeyTransferPolicyStore,
{
    /// Create a new key transfer policy service.
    pub fn new(policy_store: Arc<P>) -> Self {
        Self { policy_store }
    }

    /// Validate a key transfer policy.
    fn validate_policy(&self, policy: &KeyTransferPolicy) -> KbsResult<()> {
        // Must have exactly one attestation type
        match policy.attestation_type {
            AttesterType::Sgx => {
                if policy.sgx.is_none() {
                    return Err(KbsError::Validation(
                        "SGX policy must have sgx attributes".into(),
                    ));
                }

                // If using policy IDs, attributes can be optional
                let sgx = policy.sgx.as_ref().unwrap();

                // Must have either attributes or policy_ids (or both)
                if sgx.attributes.is_none() && sgx.policy_ids.is_none() {
                    return Err(KbsError::Validation(
                        "SGX policy must have either attributes or policy_ids".into(),
                    ));
                }

                // Validate attributes if present
                if let Some(ref attrs) = sgx.attributes {
                    self.validate_sgx_attributes(attrs)?;
                }
            }
            AttesterType::Tdx => {
                if policy.tdx.is_none() {
                    return Err(KbsError::Validation(
                        "TDX policy must have tdx attributes".into(),
                    ));
                }

                let tdx = policy.tdx.as_ref().unwrap();

                // Must have either attributes or policy_ids (or both)
                if tdx.attributes.is_none() && tdx.policy_ids.is_none() {
                    return Err(KbsError::Validation(
                        "TDX policy must have either attributes or policy_ids".into(),
                    ));
                }

                // Validate attributes if present
                if let Some(ref attrs) = tdx.attributes {
                    self.validate_tdx_attributes(attrs)?;
                }
            }
        }

        Ok(())
    }

    /// Validate SGX attributes.
    fn validate_sgx_attributes(&self, attrs: &SgxAttributes) -> KbsResult<()> {
        // MRSIGNER must be a valid hex string
        if let Some(ref mrsigner) = attrs.mrsigner {
            for m in mrsigner {
                if m.len() != 64 {
                    return Err(KbsError::Validation(
                        "MRSIGNER must be 64 characters (32 bytes hex)".into(),
                    ));
                }
                hex::decode(m).map_err(|_| {
                    KbsError::Validation("MRSIGNER must be valid hexadecimal".into())
                })?;
            }
        }

        // MRENCLAVE must be a valid hex string
        if let Some(ref mrenclave) = attrs.mrenclave {
            for m in mrenclave {
                if m.len() != 64 {
                    return Err(KbsError::Validation(
                        "MRENCLAVE must be 64 characters (32 bytes hex)".into(),
                    ));
                }
                hex::decode(m).map_err(|_| {
                    KbsError::Validation("MRENCLAVE must be valid hexadecimal".into())
                })?;
            }
        }

        Ok(())
    }

    /// Validate TDX attributes.
    fn validate_tdx_attributes(&self, attrs: &TdxAttributes) -> KbsResult<()> {
        // MRSIGNERSEAM must be a valid hex string
        if let Some(ref mrsignerseam) = attrs.mrsignerseam {
            for m in mrsignerseam {
                hex::decode(m).map_err(|_| {
                    KbsError::Validation("MRSIGNERSEAM must be valid hexadecimal".into())
                })?;
            }
        }

        // MRSEAM must be a valid hex string
        if let Some(ref mrseam) = attrs.mrseam {
            for m in mrseam {
                hex::decode(m).map_err(|_| {
                    KbsError::Validation("MRSEAM must be valid hexadecimal".into())
                })?;
            }
        }

        // MRTD must be a valid hex string
        if let Some(ref mrtd) = attrs.mrtd {
            for m in mrtd {
                hex::decode(m).map_err(|_| {
                    KbsError::Validation("MRTD must be valid hexadecimal".into())
                })?;
            }
        }

        // RTMRs must be valid hex strings
        for rtmr in [&attrs.rtmr0, &attrs.rtmr1, &attrs.rtmr2, &attrs.rtmr3] {
            if let Some(ref r) = rtmr {
                if !r.is_empty() {
                    hex::decode(r).map_err(|_| {
                        KbsError::Validation("RTMR must be valid hexadecimal".into())
                    })?;
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<P> KeyTransferPolicyService for KeyTransferPolicyServiceImpl<P>
where
    P: KeyTransferPolicyStore,
{
    async fn create_policy(&self, mut policy: KeyTransferPolicy) -> KbsResult<KeyTransferPolicy> {
        // Validate the policy
        self.validate_policy(&policy)?;

        // Generate ID if not present
        if policy.id == uuid::Uuid::nil() {
            policy.id = uuid::Uuid::new_v4();
        }

        // Set created_at if not present
        if policy.created_at == time::OffsetDateTime::from_unix_timestamp(0).unwrap() {
            policy.created_at = time::OffsetDateTime::now_utc();
        }

        let created = self.policy_store.create(&policy).await?;

        Ok(created)
    }

    async fn search_policies(
        &self,
        criteria: KeyTransferPolicyFilterCriteria,
    ) -> KbsResult<Vec<KeyTransferPolicy>> {
        self.policy_store.search(&criteria).await
    }

    async fn delete_policy(&self, id: uuid::Uuid) -> KbsResult<()> {
        self.policy_store.delete(id).await
    }

    async fn get_policy(&self, id: uuid::Uuid) -> KbsResult<KeyTransferPolicy> {
        self.policy_store.retrieve(id).await
    }
}
