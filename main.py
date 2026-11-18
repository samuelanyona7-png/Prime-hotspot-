import os
import sys
import re
import time
import uuid
import json
import base64
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from collections import defaultdict

import jwt
import pyotp
from fastapi import FastAPI, Request, Depends, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from sqlalchemy import (
    create_engine, Column, String, Integer, Numeric, Boolean,
    DateTime, Text, ForeignKey, UniqueConstraint, Index, inspect, func
)
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# ==========================================================
# SECTION 1: CONFIGURATION & ROLE PERMISSIONS
# ==========================================================

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("prime-hotspot-billing")

APP_NAME = os.getenv("APP_NAME", "PRIME HOTSPOT BILLING").strip()
APP_ENV = os.getenv("APP_ENV", "development").strip()
API_V1_PREFIX = "/api/v1"

DATABASE_URL = (os.getenv("DATABASE_URL") or "sqlite:///./prime_hotspot.db").strip()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql://" + DATABASE_URL[len("postgres://"):]

JWT_SECRET = (os.getenv("JWT_SECRET") or "dev-only-change-in-production-64-chars-secret").strip()
ENCRYPTION_KEY = (os.getenv("ENCRYPTION_KEY") or "").strip()
BOOTSTRAP_SECRET = (os.getenv("BOOTSTRAP_SECRET") or "").strip()
CORS_ORIGINS_RAW = (os.getenv("CORS_ORIGINS") or "http://localhost:5173,http://127.0.0.1:8000").strip()
CORS_ORIGINS = [o.strip() for o in CORS_ORIGINS_RAW.split(",") if o.strip()]

ACCESS_TOKEN_MINUTES = 30
REFRESH_TOKEN_DAYS = 7
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300

ROLE_PERMISSIONS = {
    "ISP_ADMIN": ["*"],
    "MANAGER": ["routers:read", "routers:write", "packages:read", "packages:write", "customers:read", "customers:write", "vouchers:read", "vouchers:write", "payments:read", "payments:write", "staff:read", "branches:read", "branches:write", "reports:read"],
    "CASHIER": ["customers:read", "customers:write", "vouchers:read", "vouchers:write", "payments:read", "payments:write"],
    "TECH_SUPPORT": ["routers:read", "routers:write", "customers:read", "customers:write", "packages:read"],
    "ACCOUNTANT": ["payments:read", "reports:read", "packages:read"],
    "VOUCHER_AGENT": ["vouchers:read", "vouchers:write", "packages:read"],
    "READ_ONLY": ["routers:read", "packages:read", "customers:read", "vouchers:read", "payments:read", "reports:read"],
}

# ==========================================================
# SECTION 2: SECURITY (ARGON2ID, FERNET, JWT, TOTP, RATE LIMIT)
# ==========================================================

_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
_failed_logins = defaultdict(list)


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return _ph.verify(password_hash, plain_password)
    except VerifyMismatchError:
        return False


def _get_fernet() -> Fernet:
    if ENCRYPTION_KEY:
        key = ENCRYPTION_KEY.encode("utf-8")
    else:
        digest = hashlib.sha256(JWT_SECRET.encode("utf-8")).digest()
        key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_secret(value: str) -> str:
    return _get_fernet().encrypt(value.encode("utf-8")).decode("utf-8") if value else ""


def decrypt_secret(token: str) -> str:
    return _get_fernet().decrypt(token.encode("utf-8")).decode("utf-8") if token else ""


def create_jwt_token(payload: dict, expires_delta: timedelta) -> str:
    now = datetime.now(timezone.utc)
    to_encode = {**payload, "iat": int(now.timestamp()), "exp": int((now + expires_delta).timestamp())}
    return jwt.encode(to_encode, JWT_SECRET, algorithm="HS256")


def decode_jwt_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def check_rate_limit(key: str):
    now = time.time()
    recent = [ts for ts in _failed_logins[key] if now - ts < LOCKOUT_SECONDS]
    _failed_logins[key] = recent
    if len(recent) >= MAX_LOGIN_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many failed login attempts. Try again later.")


def record_failed_login(key: str):
    _failed_logins[key].append(time.time())


def clear_failed_logins(key: str):
    _failed_logins.pop(key, None)


# ==========================================================
# SECTION 3: DATABASE ENGINE & MODELS (SYSTEM 1 & SYSTEM 2)
# ==========================================================

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def gen_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class PlatformAdmin(Base):
    __tablename__ = "platform_admins"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(150), nullable=False)
    password_hash = Column(Text, nullable=False)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret_enc = Column(Text, default="", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class PlatformPaymentConfig(Base):
    """SYSTEM 2 ONLY: Platform owner collection (Till, PayBill, Airtel, Bank, PayHero)."""
    __tablename__ = "platform_payment_configs"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    method_type = Column(String(40), nullable=False)
    label = Column(String(120), nullable=False)
    country_code = Column(String(5), default="KE", nullable=False)
    till_number = Column(String(50), default="")
    paybill_number = Column(String(50), default="")
    account_reference = Column(String(80), default="")
    bank_name = Column(String(120), default="")
    bank_account_number = Column(String(80), default="")
    account_holder_name = Column(String(150), default="")
    credentials_enc = Column(Text, default="")
    instructions = Column(Text, default="")
    is_default = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class SubscriptionPlan(Base):
    __tablename__ = "subscription_plans"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    code = Column(String(32), unique=True, nullable=False)
    name = Column(String(100), nullable=False)
    monthly_price_kes = Column(Numeric(12, 2), nullable=False)
    annual_price_kes = Column(Numeric(12, 2), nullable=False)
    max_routers = Column(Integer, default=2, nullable=False)
    max_customers = Column(Integer, default=200, nullable=False)
    max_staff = Column(Integer, default=2, nullable=False)
    allow_pppoe = Column(Boolean, default=False, nullable=False)
    allow_api = Column(Boolean, default=False, nullable=False)
    allow_script = Column(Boolean, default=True, nullable=False)
    allow_sms = Column(Boolean, default=False, nullable=False)
    allow_whatsapp = Column(Boolean, default=False, nullable=False)
    allow_telegram = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)


class ISPTenant(Base):
    __tablename__ = "isp_tenants"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    business_name = Column(String(180), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    country_code = Column(String(5), default="KE", nullable=False)
    currency = Column(String(10), default="KES", nullable=False)
    owner_email = Column(String(255), nullable=False)
    owner_phone = Column(String(40), nullable=False)
    status = Column(String(30), default="TRIAL", nullable=False)
    referred_by_tenant_id = Column(String(36), ForeignKey("isp_tenants.id"), nullable=True)
    custom_domain = Column(String(255), nullable=True)
    portal_branding_json = Column(Text, default="{}")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class TenantSubscription(Base):
    __tablename__ = "subscriptions"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), unique=True, nullable=False)
    plan_id = Column(String(36), ForeignKey("subscription_plans.id"), nullable=False)
    billing_cycle = Column(String(20), default="MONTHLY", nullable=False)
    custom_price_kes = Column(Numeric(12, 2), nullable=True)
    status = Column(String(30), default="TRIAL", nullable=False)
    starts_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    grace_until = Column(DateTime(timezone=True), nullable=True)


class SaaSInvoice(Base):
    __tablename__ = "saas_invoices"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    invoice_number = Column(String(50), unique=True, nullable=False)
    amount = Column(Numeric(12, 2), nullable=False)
    currency = Column(String(10), default="KES", nullable=False)
    status = Column(String(30), default="UNPAID", nullable=False)
    due_at = Column(DateTime(timezone=True), nullable=False)
    paid_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class SaaSPayment(Base):
    """SYSTEM 2 ONLY: Money paid BY ISPs TO PRIME HOTSPOT BILLING."""
    __tablename__ = "saas_payments"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    invoice_id = Column(String(36), ForeignKey("saas_invoices.id"), nullable=True)
    payment_method = Column(String(40), nullable=False)
    amount = Column(Numeric(12, 2), nullable=False)
    currency = Column(String(10), default="KES", nullable=False)
    external_ref = Column(String(120), unique=True, nullable=False)
    provider_ref = Column(String(120), nullable=True)
    proof_url = Column(Text, nullable=True)
    status = Column(String(30), default="PENDING", nullable=False)
    approved_by_admin_id = Column(String(36), ForeignKey("platform_admins.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class Branch(Base):
    __tablename__ = "branches"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    location = Column(String(200), default="")


class Role(Base):
    __tablename__ = "roles"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    name = Column(String(60), nullable=False)
    permissions_json = Column(Text, default="[]", nullable=False)


class StaffUser(Base):
    __tablename__ = "staff_users"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    role_id = Column(String(36), ForeignKey("roles.id"), nullable=False)
    branch_id = Column(String(36), ForeignKey("branches.id"), nullable=True)
    email = Column(String(255), nullable=False)
    full_name = Column(String(150), nullable=False)
    password_hash = Column(Text, nullable=False)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret_enc = Column(Text, default="", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_staff_tenant_email"),)


class MikroTikRouter(Base):
    __tablename__ = "mikrotik_routers"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    branch_id = Column(String(36), ForeignKey("branches.id"), nullable=True)
    name = Column(String(120), nullable=False)
    host = Column(String(255), nullable=False)
    api_port = Column(Integer, default=8728, nullable=False)
    use_ssl = Column(Boolean, default=False, nullable=False)
    integration_mode = Column(String(20), default="API", nullable=False)
    hardware_model = Column(String(100), default="")
    routeros_version = Column(String(40), default="")
    architecture = Column(String(40), default="")
    identity = Column(String(120), default="")
    capabilities_json = Column(Text, default="{}")
    status = Column(String(30), default="OFFLINE", nullable=False)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class RouterCredential(Base):
    __tablename__ = "router_credentials"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    router_id = Column(String(36), ForeignKey("mikrotik_routers.id", ondelete="CASCADE"), unique=True, nullable=False)
    username_enc = Column(Text, nullable=False)
    password_enc = Column(Text, nullable=False)
    radius_secret_enc = Column(Text, default="")
    agent_token_hash = Column(Text, default="")


class RouterConfiguration(Base):
    __tablename__ = "router_configurations"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    router_id = Column(String(36), ForeignKey("mikrotik_routers.id", ondelete="CASCADE"), nullable=False)
    config_type = Column(String(40), nullable=False)
    script_body = Column(Text, nullable=False)
    verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class InternetPackage(Base):
    __tablename__ = "internet_packages"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    branch_id = Column(String(36), ForeignKey("branches.id"), nullable=True)
    service_type = Column(String(20), nullable=False)
    name = Column(String(120), nullable=False)
    price = Column(Numeric(12, 2), nullable=False)
    duration_minutes = Column(Integer, nullable=False)
    upload_kbps = Column(Integer, default=0, nullable=False)
    download_kbps = Column(Integer, default=0, nullable=False)
    data_limit_mb = Column(Integer, default=0, nullable=False)
    device_limit = Column(Integer, default=1, nullable=False)
    is_visible = Column(Boolean, default=True, nullable=False)


class Customer(Base):
    __tablename__ = "customers"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    router_id = Column(String(36), ForeignKey("mikrotik_routers.id"), nullable=True)
    package_id = Column(String(36), ForeignKey("internet_packages.id"), nullable=True)
    account_number = Column(String(60), nullable=False)
    full_name = Column(String(150), nullable=False)
    phone = Column(String(40), nullable=False)
    connection_type = Column(String(20), default="HOTSPOT", nullable=False)
    username = Column(String(100), nullable=False)
    secret_enc = Column(Text, default="")
    status = Column(String(30), default="INACTIVE", nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    __table_args__ = (UniqueConstraint("tenant_id", "account_number", name="uq_customer_tenant_acct"),)


class NetworkSession(Base):
    __tablename__ = "network_sessions"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    router_id = Column(String(36), ForeignKey("mikrotik_routers.id", ondelete="CASCADE"), nullable=False)
    customer_id = Column(String(36), ForeignKey("customers.id"), nullable=True)
    session_key = Column(String(120), nullable=False)
    mac_address = Column(String(32), default="")
    ip_address = Column(String(64), default="")
    bytes_in = Column(Integer, default=0, nullable=False)
    bytes_out = Column(Integer, default=0, nullable=False)
    started_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    ended_at = Column(DateTime(timezone=True), nullable=True)


class Voucher(Base):
    __tablename__ = "vouchers"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    package_id = Column(String(36), ForeignKey("internet_packages.id", ondelete="CASCADE"), nullable=False)
    code = Column(String(40), nullable=False)
    agent_staff_id = Column(String(36), ForeignKey("staff_users.id"), nullable=True)
    max_uses = Column(Integer, default=1, nullable=False)
    uses_count = Column(Integer, default=0, nullable=False)
    status = Column(String(20), default="UNUSED", nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    __table_args__ = (UniqueConstraint("tenant_id", "code", name="uq_voucher_tenant_code"),)


class VoucherRedemption(Base):
    __tablename__ = "voucher_redemptions"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    voucher_id = Column(String(36), ForeignKey("vouchers.id", ondelete="CASCADE"), nullable=False)
    customer_id = Column(String(36), ForeignKey("customers.id"), nullable=True)
    mac_address = Column(String(32), default="")
    redeemed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class ISPPaymentConfig(Base):
    """SYSTEM 1 ONLY: Each ISP's own payment methods & encrypted credentials."""
    __tablename__ = "isp_payment_configs"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(40), nullable=False)
    country_code = Column(String(5), default="KE", nullable=False)
    till_number = Column(String(50), default="")
    paybill_number = Column(String(50), default="")
    account_reference = Column(String(80), default=
