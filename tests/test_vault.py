# -*- coding: utf-8 -*-
import asyncio
import time

import pytest

from api.vault import vault
from api.models import KeyCreateRequest, KeyStatus


@pytest.fixture(autouse=True)
def reset_vault():
    vault._keys_by_hash.clear()
    vault._id_to_hash.clear()
    vault._validation_count = 0
    yield
    vault._keys_by_hash.clear()
    vault._id_to_hash.clear()
    vault._validation_count = 0


def test_create_and_validate_success():
    req = KeyCreateRequest(client_name="test", expires_in_days=1, rate_limit_per_minute=10)
    raw_key, record = vault.create_key(req.client_name, req.expires_in_days, req.rate_limit_per_minute)
    assert record.status == KeyStatus.ACTIVE
    valid, client, code = vault.validate_key(raw_key)
    assert valid
    assert client == "test"
    assert code == 200
    assert record.usage_count == 1


def test_expired_key():
    req = KeyCreateRequest(client_name="test", expires_in_days=0, rate_limit_per_minute=10)
    raw_key, record = vault.create_key(req.client_name, req.expires_in_days, req.rate_limit_per_minute)
    record.expires_at = time.time() - 1
    valid, client, code = vault.validate_key(raw_key)
    assert not valid
    assert code == 401
    assert record.status == KeyStatus.EXPIRED


def test_revoked_key():
    req = KeyCreateRequest(client_name="test", expires_in_days=1, rate_limit_per_minute=10)
    raw_key, record = vault.create_key(req.client_name, req.expires_in_days, req.rate_limit_per_minute)
    assert vault.revoke_key(record.key_id)
    valid, client, code = vault.validate_key(raw_key)
    assert not valid
    assert code == 401
    assert record.status == KeyStatus.REVOKED


def test_rate_limit_exceeded():
    req = KeyCreateRequest(client_name="test", expires_in_days=1, rate_limit_per_minute=2)
    raw_key, record = vault.create_key(req.client_name, req.expires_in_days, req.rate_limit_per_minute)
    for _ in range(2):
        valid, client, code = vault.validate_key(raw_key)
        assert valid
        assert code == 200
    valid, client, code = vault.validate_key(raw_key)
    assert not valid
    assert code == 429
    assert record.usage_count == 2


@pytest.mark.asyncio
async def test_concurrent_validations():
    req = KeyCreateRequest(client_name="concurrent", expires_in_days=1, rate_limit_per_minute=1000)
    raw_key, record = vault.create_key(req.client_name, req.expires_in_days, req.rate_limit_per_minute)

    async def validate_once():
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, vault.validate_key, raw_key)

    tasks = [validate_once() for _ in range(50)]
    results = await asyncio.gather(*tasks)
    successes = sum(1 for v, _, c in results if v and c == 200)
    assert successes == 50
    assert record.usage_count == 50
