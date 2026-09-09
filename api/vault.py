# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from threading import RLock
from typing import Dict, Tuple

from .models import KeyRecord, KeyStatus


class ApiKeyVault:
    def __init__(self) -> None:
        # Busca O(1) direta por hash
        self._keys_by_hash: Dict[str, KeyRecord] = {}
        self._id_to_hash: Dict[str, str] = {}
        self._lock = RLock()
        self._validation_count: int = 0

    def create_key(
        self, client_name: str, days: int, rate_limit: int
    ) -> Tuple[str, KeyRecord]:
        raw_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        key_id = str(uuid.uuid4())
        key_prefix = raw_key[:8]
        now = time.time()
        expires_at = now + days * 86400
        record = KeyRecord(
            key_id=key_id,
            key_prefix=key_prefix,
            key_hash=key_hash,
            client_name=client_name,
            status=KeyStatus.ACTIVE,
            created_at=now,
            expires_at=expires_at,
            usage_count=0,
            rate_limit_per_minute=rate_limit,
            _last_reset_ts=now,
            _current_window_count=0,
        )
        with self._lock:
            self._keys_by_hash[key_hash] = record
            self._id_to_hash[key_id] = key_hash
        return raw_key, record

    def _enforce_rate_limit(self, record: KeyRecord) -> bool:
        now = time.time()
        if now - record._last_reset_ts >= 60:
            record._last_reset_ts = now
            record._current_window_count = 0
        if record._current_window_count >= record.rate_limit_per_minute:
            return False
        record._current_window_count += 1
        return True

    def validate_key(self, raw_api_key: str) -> Tuple[bool, str, int]:
        key_hash = hashlib.sha256(raw_api_key.encode()).hexdigest()
        with self._lock:
            record = self._keys_by_hash.get(key_hash)  # ⚡ BUSCA O(1) INSTANTÂNEA
            if not record:
                return False, "", 401
            if record.status != KeyStatus.ACTIVE:
                return False, "", 401
            if record.expires_at < time.time():
                record.status = KeyStatus.EXPIRED
                return False, "", 401
            if not self._enforce_rate_limit(record):
                return False, "", 429  # Too Many Requests
            record.usage_count += 1
            self._validation_count += 1
            return True, record.client_name, 200

    def revoke_key(self, key_id: str) -> bool:
        with self._lock:
            key_hash = self._id_to_hash.get(key_id)
            if not key_hash:
                return False
            record = self._keys_by_hash.get(key_hash)
            if record and record.status == KeyStatus.ACTIVE:
                record.status = KeyStatus.REVOKED
                return True
        return False

    def metrics(self) -> Dict[str, int]:
        with self._lock:
            active = sum(1 for r in self._keys_by_hash.values() if r.status == KeyStatus.ACTIVE)
            revoked = sum(1 for r in self._keys_by_hash.values() if r.status == KeyStatus.REVOKED)
            expired = sum(1 for r in self._keys_by_hash.values() if r.status == KeyStatus.EXPIRED)
            return {
                "active_keys": active,
                "revoked_keys": revoked,
                "expired_keys": expired,
                "validation_count": self._validation_count,
            }


# Instância Singleton do Cofre
vault = ApiKeyVault()
