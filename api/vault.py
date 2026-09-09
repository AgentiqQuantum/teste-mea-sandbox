# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from threading import Lock
from typing import Dict, Tuple

from .models import KeyRecord, KeyStatus


class ApiKeyVault:
    def __init__(self) -> None:
        self._keys: Dict[str, KeyRecord] = {}
        self._lock = Lock()
        self._validation_count: int = 0

    def create_key(self, client_name: str, days: int) -> Tuple[str, KeyRecord]:
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
        )
        with self._lock:
            self._keys[key_id] = record
        return raw_key, record

    def validate_key(self, raw_api_key: str) -> Tuple[bool, str]:
        key_hash = hashlib.sha256(raw_api_key.encode()).hexdigest()
        with self._lock:
            for record in self._keys.values():
                if record.key_hash == key_hash:
                    if record.status != KeyStatus.ACTIVE:
                        return False, ""
                    if record.expires_at < time.time():
                        record.status = KeyStatus.EXPIRED
                        return False, ""
                    record.usage_count += 1
                    self._validation_count += 1
                    return True, record.client_name
        return False, ""

    def revoke_key(self, key_id: str) -> bool:
        with self._lock:
            record = self._keys.get(key_id)
            if record and record.status == KeyStatus.ACTIVE:
                record.status = KeyStatus.REVOKED
                return True
        return False

    def metrics(self) -> Dict[str, int]:
        with self._lock:
            active = sum(1 for r in self._keys.values() if r.status == KeyStatus.ACTIVE)
            revoked = sum(1 for r in self._keys.values() if r.status == KeyStatus.REVOKED)
            expired = sum(1 for r in self._keys.values() if r.status == KeyStatus.EXPIRED)
            return {
                "active_keys": active,
                "revoked_keys": revoked,
                "expired_keys": expired,
                "validation_count": self._validation_count,
            }


# Instância Singleton para compartilhamento de estado em RAM
vault = ApiKeyVault()
