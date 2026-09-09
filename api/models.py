# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class KeyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


@dataclass
class KeyCreateRequest:
    client_name: str
    expires_in_days: int = 30
    rate_limit_per_minute: int = 60


@dataclass
class KeyRecord:
    key_id: str
    key_prefix: str
    key_hash: str
    client_name: str
    status: KeyStatus
    created_at: float
    expires_at: float
    usage_count: int
