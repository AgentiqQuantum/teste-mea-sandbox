# -*- coding: utf-8 -*-
from __future__ import annotations

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

from .models import KeyCreateRequest, KeyRecord, KeyStatus
from .vault import vault

app = FastAPI(title="MEA API Key Vault")


class KeyCreateResponse(BaseModel):
    key_id: str
    key_prefix: str
    client_name: str
    status: KeyStatus
    created_at: float
    expires_at: float
    usage_count: int
    raw_key: str


class KeyValidateRequest(BaseModel):
    api_key: str


class KeyValidateResponse(BaseModel):
    valid: bool
    client: str | None = None


class RevokeResponse(BaseModel):
    key_id: str
    status: KeyStatus


class MetricsResponse(BaseModel):
    active_keys: int
    revoked_keys: int
    expired_keys: int
    validation_count: int


@app.post("/keys/create", status_code=status.HTTP_201_CREATED, response_model=KeyCreateResponse)
def create_key(req: KeyCreateRequest) -> KeyCreateResponse:
    raw_key, record = vault.create_key(req.client_name, req.expires_in_days)
    return KeyCreateResponse(
        key_id=record.key_id,
        key_prefix=record.key_prefix,
        client_name=record.client_name,
        status=record.status,
        created_at=record.created_at,
        expires_at=record.expires_at,
        usage_count=record.usage_count,
        raw_key=raw_key,
    )


@app.post("/keys/validate", response_model=KeyValidateResponse)
def validate_key(req: KeyValidateRequest) -> KeyValidateResponse:
    valid, client = vault.validate_key(req.api_key)
    if not valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired key")
    return KeyValidateResponse(valid=True, client=client)


@app.post("/keys/{key_id}/revoke", response_model=RevokeResponse)
def revoke_key(key_id: str) -> RevokeResponse:
    if not vault.revoke_key(key_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found or already revoked")
    record = vault._keys[key_id]
    return RevokeResponse(key_id=key_id, status=record.status)


@app.get("/metrics", response_model=MetricsResponse)
def get_metrics() -> MetricsResponse:
    m = vault.metrics()
    return MetricsResponse(**m)
