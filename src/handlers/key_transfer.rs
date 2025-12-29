
use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Json, Response},
};
use uuid::Uuid;
use crate::error::KbsError;
use crate::handlers::AppState;
use crate::models::{KeyTransferRequest, VerifierNonce};

/// POST /keys/:id/transfer - Transfer a key.
pub async fn transfer_key(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    Json(request): Json<KeyTransferRequest>,
) -> Result<Response, KbsError> {
    // Check if this is a no-attestation transfer (just public key)
    if request.attestation_token.is_none()
        && request.quote.is_none()
        && request.nonce.is_none()
    {
        // Get the public key from the request body
        // The public key should be in the request body as a raw string (base64 or PEM)
        let public_key = request
            .user_data
            .ok_or_else(|| KbsError::Validation("Public key is required".into()))?;

        let public_key_str = String::from_utf8(public_key)
            .map_err(|_| KbsError::Validation("Public key must be valid UTF-8".into()))?;

        let response = state
            .key_transfer_service
            .transfer_key_without_attestation(id, &public_key_str)
            .await?;

        return Ok(Json(response).into_response());
    }

    // Attestation-based transfer
    let attestation_type = params.get("attestation_type").cloned();
    let response = state
        .key_transfer_service
        .transfer_key_with_evidence(id, attestation_type, request)
        .await?;

    Ok(Json(response).into_response())
}

/// GET /keys/:id/nonce - Get a nonce for background verification.
pub async fn get_nonce(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<VerifierNonce>, KbsError> {
    let nonce = state.key_transfer_service.get_nonce(id).await?;
    Ok(Json(nonce))
}
