"""用于外部 JWE SSO 认证与账号自动创建的服务。"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from flask import Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from werkzeug.exceptions import Unauthorized

from configs import dify_config
from constants.languages import get_valid_language
from extensions.ext_database import db
from libs.helper import extract_remote_ip
from libs.jwe import JweDecodeError, decode_compact_jwe, parse_jwe_key, parse_rfc3339_nanos
from models import Account, AccountIntegrate, Tenant, TenantAccountJoin
from services.account_service import AccountService, TenantService, TokenPair

logger = logging.getLogger(__name__)

_PROVIDER = "external_jwe"


class ExternalAuthPayload(BaseModel):
    """外部 JWE 令牌解码后的载荷。"""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    expiration: datetime = Field(alias="Expiration")
    staff_id: int = Field(alias="StaffId")
    login_name: str = Field(alias="LoginName")

    @field_validator("expiration", mode="before")
    @classmethod
    def _parse_expiration(cls, value: str) -> datetime:
        if isinstance(value, datetime):
            return value
        return parse_rfc3339_nanos(value)

    @field_validator("login_name")
    @classmethod
    def _validate_login_name(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("login_name is required")
        return value.strip()


@dataclass(frozen=True)
class ExternalAuthResult:
    account: Account
    token_pair: TokenPair
    payload: ExternalAuthPayload


class ExternalAuthService:
    """使用外部 JWE Cookie 进行认证并自动创建账号。"""

    @classmethod
    def authenticate_request(cls, request: Request) -> ExternalAuthResult | None:
        if not dify_config.EXTERNAL_AUTH_ENABLED:
            return None

        cookie_name = dify_config.EXTERNAL_AUTH_COOKIE_NAME
        token = request.cookies.get(cookie_name)
        if not token:
            return None

        payload = cls._decode_payload(token)
        cls._validate_expiration(payload.expiration)

        account = cls._get_or_create_account(payload, request)
        token_pair = AccountService.login(account=account, ip_address=extract_remote_ip(request))
        return ExternalAuthResult(account=account, token_pair=token_pair, payload=payload)

    @classmethod
    def _decode_payload(cls, token: str) -> ExternalAuthPayload:
        raw_key = dify_config.EXTERNAL_AUTH_JWE_KEY
        if not raw_key:
            raise Unauthorized("External auth JWE key is not configured.")

        try:
            key = parse_jwe_key(raw_key)
            payload = decode_compact_jwe(token, key).plaintext
        except JweDecodeError as exc:
            logger.warning("Failed to decode external auth token", exc_info=True)
            raise Unauthorized("Invalid external auth token.") from exc

        return ExternalAuthPayload.model_validate(payload)

    @classmethod
    def _validate_expiration(cls, expiration: datetime) -> None:
        now = datetime.now(UTC)
        exp = expiration.astimezone(UTC)
        if exp <= now:
            raise Unauthorized("External auth token expired.")

    @classmethod
    def _get_or_create_account(cls, payload: ExternalAuthPayload, request: Request) -> Account:
        email = cls._resolve_email(payload.login_name)
        account = AccountService.get_account_by_email_with_case_fallback(email)
        if not account:
            language = cls._resolve_language(request)
            account = AccountService.create_account(
                email=email,
                name=payload.login_name,
                interface_language=language,
                password=None,
                is_setup=True,
            )
        cls._ensure_external_identity(account, payload)
        cls._ensure_tenant_membership(account)
        return account

    @classmethod
    def _resolve_email(cls, login_name: str) -> str:
        if "@" in login_name:
            return login_name

        domain = dify_config.EXTERNAL_AUTH_EMAIL_DOMAIN
        if not domain:
            raise Unauthorized("External auth email domain is not configured.")
        return f"{login_name}@{domain}"

    @classmethod
    def _resolve_language(cls, request: Request) -> str:
        accept_language = request.headers.get("Accept-Language", "")
        language = accept_language.split(",")[0].strip() if accept_language else ""
        return get_valid_language(language)

    @classmethod
    def _ensure_external_identity(cls, account: Account, payload: ExternalAuthPayload) -> None:
        existing = (
            db.session.query(AccountIntegrate).filter_by(account_id=account.id, provider=_PROVIDER).one_or_none()
        )
        if existing:
            if existing.open_id != str(payload.staff_id):
                existing.open_id = str(payload.staff_id)
                db.session.add(existing)
                db.session.commit()
            return

        account_integrate = AccountIntegrate(
            account_id=account.id,
            provider=_PROVIDER,
            open_id=str(payload.staff_id),
            encrypted_token="",
        )
        db.session.add(account_integrate)
        db.session.commit()

    @classmethod
    def _ensure_tenant_membership(cls, account: Account) -> None:
        tenant_id = dify_config.EXTERNAL_AUTH_DEFAULT_TENANT_ID
        if tenant_id:
            tenant = db.session.query(Tenant).where(Tenant.id == tenant_id).one_or_none()
            if not tenant:
                raise Unauthorized("External auth tenant not found.")

            join = (
                db.session.query(TenantAccountJoin)
                .filter_by(tenant_id=tenant.id, account_id=account.id)
                .one_or_none()
            )
            if not join:
                TenantService.create_tenant_member(tenant, account, role="normal")
                join = (
                    db.session.query(TenantAccountJoin)
                    .filter_by(tenant_id=tenant.id, account_id=account.id)
                    .one_or_none()
                )

            if join and not join.current:
                db.session.query(TenantAccountJoin).filter_by(account_id=account.id).update({"current": False})
                join.current = True
                db.session.commit()
            account.set_tenant_id(tenant.id)
            return

        TenantService.create_owner_tenant_if_not_exist(account=account, is_setup=True)
