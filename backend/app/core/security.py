"""AgentFence Security Core: Cryptography, Tokens, Audit Hashing & Replay Protection
"""
import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple, List
import jwt
from app.core.config import settings

class SecurityEngine:
    def __init__(self, secret_key: str = settings.SECRET_KEY, algorithm: str = settings.ALGORITHM):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.issuer = settings.TOKEN_ISSUER
        self.default_audience = settings.DEFAULT_AUDIENCE
        # In-memory atomic replay store (jti -> timestamp consumed)
        self._consumed_jtis: Dict[str, float] = {}

    def generate_id(self, prefix: str = "") -> str:
        uid = uuid.uuid4().hex
        return f"{prefix}_{uid[:12]}" if prefix else uid

    # --- Hash-based password / secret verification ---
    def hash_secret(self, secret: str) -> str:
        return hashlib.sha256(f"{secret}:{self.secret_key}".encode("utf-8")).hexdigest()

    def verify_secret(self, secret: str, hashed: str) -> bool:
        expected = self.hash_secret(secret)
        return hmac.compare_digest(expected, hashed)

    # --- Identity Token Issuance & Verification ---
    def create_identity_token(
        self,
        subject: str,
        tenant_id: str,
        role: str,
        principal_type: str = "user", # user | agent
        agent_id: Optional[str] = None,
        expires_delta: Optional[timedelta] = None,
        audience: Optional[str] = None
    ) -> str:
        now = datetime.now(timezone.utc)
        exp = now + (expires_delta or timedelta(minutes=settings.DEFAULT_TOKEN_EXPIRY_MINUTES))
        payload = {
            "iss": self.issuer,
            "sub": subject,
            "tid": tenant_id,
            "role": role,
            "ptyp": principal_type,
            "aid": agent_id,
            "aud": audience or self.default_audience,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": self.generate_id("idtok")
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def verify_identity_token(self, token: str, expected_audience: Optional[str] = None) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        try:
            aud = expected_audience or self.default_audience
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=aud
            )
            return True, payload, "Valid identity token"
        except jwt.ExpiredSignatureError:
            return False, None, "Identity token expired"
        except jwt.InvalidAudienceError:
            return False, None, f"Audience mismatch for identity token"
        except jwt.InvalidIssuerError:
            return False, None, "Invalid token issuer"
        except jwt.InvalidSignatureError:
            return False, None, "Invalid cryptographic signature"
        except Exception as e:
            return False, None, f"Identity token verification failed: {str(e)}"

    # --- Signed Delegation Credential Issuance & Verification ---
    def create_delegation_credential(
        self,
        delegation_id: str,
        parent_delegation_id: Optional[str],
        original_user_id: str,
        delegating_agent_id: str,
        receiving_agent_id: str,
        tenant_id: str,
        permitted_tools: List[str],
        permitted_actions: List[str],
        resource_restrictions: List[str],
        max_depth: int,
        current_depth: int,
        audience: Optional[str] = None,
        expires_in_minutes: int = 30,
        is_single_use: bool = False,
        custom_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=expires_in_minutes)
        jti = self.generate_id("del_jti")

        payload = {
            "iss": self.issuer,
            "sub": receiving_agent_id,
            "aud": audience or self.default_audience,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": jti,
            "del_id": delegation_id,
            "pdel_id": parent_delegation_id,
            "orig_uid": original_user_id,
            "del_aid": delegating_agent_id,
            "rcv_aid": receiving_agent_id,
            "tid": tenant_id,
            "tools": permitted_tools,
            "actions": permitted_actions,
            "resources": resource_restrictions,
            "max_depth": max_depth,
            "cur_depth": current_depth,
            "single_use": is_single_use,
            "claims": custom_claims or {}
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def verify_delegation_credential(
        self,
        token: str,
        expected_audience: Optional[str] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        try:
            aud = expected_audience or self.default_audience
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                audience=aud
            )
            return True, payload, "Valid delegation token"
        except jwt.ExpiredSignatureError:
            return False, None, "Delegation credential has expired"
        except jwt.InvalidAudienceError:
            return False, None, "Delegation audience mismatch"
        except jwt.InvalidIssuerError:
            return False, None, "Invalid delegation issuer"
        except jwt.InvalidSignatureError:
            return False, None, "Delegation signature verification failed / tampered"
        except Exception as e:
            return False, None, f"Delegation token invalid: {str(e)}"

    # --- Atomic Replay Tracking ---
    def check_and_consume_jti(self, jti: str, exp_timestamp: float) -> Tuple[bool, str]:
        now = time.time()
        # Clean up expired items periodically
        if len(self._consumed_jtis) > 1000:
            self._consumed_jtis = {k: v for k, v in self._consumed_jtis.items() if v > now}

        if jti in self._consumed_jtis:
            return False, f"Replay attack detected: credential with jti '{jti}' was already consumed"

        # Record consumption with expiration
        self._consumed_jtis[jti] = exp_timestamp
        return True, "Replay check passed"

    # --- Hash-Linked Tamper-Evident Audit Logging ---
    @staticmethod
    def calculate_audit_hash(
        previous_hash: str,
        request_id: str,
        timestamp: str,
        tenant_id: str,
        user_id: Optional[str],
        agent_id: Optional[str],
        tool_name: str,
        requested_action: str,
        resource_id: Optional[str],
        decision: str,
        denial_reason: Optional[str]
    ) -> str:
        record_content = (
            f"{previous_hash}|{request_id}|{timestamp}|{tenant_id}|"
            f"{user_id or ''}|{agent_id or ''}|{tool_name}|{requested_action}|"
            f"{resource_id or ''}|{decision}|{denial_reason or ''}"
        )
        return hashlib.sha256(record_content.encode("utf-8")).hexdigest()

security_engine = SecurityEngine()
