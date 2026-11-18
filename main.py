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
    account_reference = Column(String(80), default="")
    bank_name = Column(String(120), default="")
    bank_account_number = Column(String(80), default="")
    account_holder_name = Column(String(150), default="")
    credentials_enc = Column(Text, default="")
    instructions = Column(Text, default="")
    is_active = Column(Boolean, default=True, nullable=False)


class CustomerPayment(Base):
    """SYSTEM 1 ONLY: Money paid BY WiFi customers TO an ISP."""
    __tablename__ = "customer_payments"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    customer_id = Column(String(36), ForeignKey("customers.id"), nullable=True)
    package_id = Column(String(36), ForeignKey("internet_packages.id"), nullable=True)
    provider = Column(String(40), nullable=False)
    phone = Column(String(40), default="")
    amount = Column(Numeric(12, 2), nullable=False)
    currency = Column(String(10), default="KES", nullable=False)
    external_ref = Column(String(120), unique=True, nullable=False)
    provider_ref = Column(String(120), nullable=True)
    proof_url = Column(Text, nullable=True)
    status = Column(String(30), default="PENDING", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class PaymentEvent(Base):
    __tablename__ = "payment_events"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    system_scope = Column(String(20), nullable=False)
    external_ref = Column(String(120), nullable=False, index=True)
    event_type = Column(String(50), nullable=False)
    details = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class PaymentCallback(Base):
    __tablename__ = "payment_callbacks"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    system_scope = Column(String(20), nullable=False)
    provider = Column(String(40), nullable=False)
    external_ref = Column(String(120), default="", index=True)
    payload_json = Column(Text, nullable=False)
    verified = Column(Boolean, default=False, nullable=False)
    received_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class NotificationConfig(Base):
    __tablename__ = "notification_configs"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    channel = Column(String(20), nullable=False)
    provider = Column(String(40), nullable=False)
    credentials_enc = Column(Text, default="")
    sender_id = Column(String(60), default="")
    is_active = Column(Boolean, default=True, nullable=False)


class NotificationTemplate(Base):
    __tablename__ = "notification_templates"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    event_name = Column(String(60), nullable=False)
    channel = Column(String(20), nullable=False)
    body_template = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)


class DeliveryLog(Base):
    __tablename__ = "delivery_logs"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    channel = Column(String(20), nullable=False)
    event_name = Column(String(60), nullable=False)
    recipient = Column(String(120), nullable=False)
    status = Column(String(30), nullable=False)
    provider_response = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class SupportTicket(Base):
    __tablename__ = "support_tickets"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    subject = Column(String(200), nullable=False)
    message = Column(Text, nullable=False)
    status = Column(String(30), default="OPEN", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String(36), primary_key=True, default=gen_uuid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    actor_type = Column(String(30), nullable=False)
    actor_id = Column(String(36), nullable=False)
    action = Column(String(80), nullable=False)
    ip_address = Column(String(64), default="")
    details = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


Index("ix_cust_pay_tenant_status", CustomerPayment.tenant_id, CustomerPayment.status)
Index("ix_saas_pay_tenant_status", SaaSPayment.tenant_id, SaaSPayment.status)


def write_audit(db: Session, actor_type: str, actor_id: str, action: str, tenant_id: str | None = None, ip: str = "", details: str = ""):
    db.add(AuditLog(tenant_id=tenant_id, actor_type=actor_type, actor_id=actor_id, action=action, ip_address=ip, details=details[:500]))


def seed_default_plans():
    db = SessionLocal()
    try:
        if db.query(SubscriptionPlan).count() == 0:
            db.add_all([
                SubscriptionPlan(code="STARTER", name="Starter", monthly_price_kes=1500, annual_price_kes=15000, max_routers=2, max_customers=200, max_staff=2, allow_pppoe=False, allow_api=False, allow_script=True, allow_sms=False, allow_whatsapp=False, allow_telegram=False),
                SubscriptionPlan(code="BUSINESS", name="Business", monthly_price_kes=3500, annual_price_kes=35000, max_routers=5, max_customers=1000, max_staff=5, allow_pppoe=True, allow_api=True, allow_script=True, allow_sms=True, allow_whatsapp=False, allow_telegram=True),
                SubscriptionPlan(code="PROFESSIONAL", name="Professional", monthly_price_kes=7500, annual_price_kes=75000, max_routers=15, max_customers=5000, max_staff=15, allow_pppoe=True, allow_api=True, allow_script=True, allow_sms=True, allow_whatsapp=True, allow_telegram=True),
                SubscriptionPlan(code="ENTERPRISE", name="Enterprise", monthly_price_kes=15000, annual_price_kes=150000, max_routers=100, max_customers=50000, max_staff=100, allow_pppoe=True, allow_api=True, allow_script=True, allow_sms=True, allow_whatsapp=True, allow_telegram=True),
            ])
            db.commit()
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
    seed_default_plans()


# ==========================================================
# SECTION 4: AUTHENTICATION & MULTI-TENANT RBAC GUARDS
# ==========================================================

def get_bearer_claims(authorization: str = Header(default="")) -> dict:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    return decode_jwt_token(authorization.split(" ", 1)[1].strip())


def require_platform_admin(claims: dict = Depends(get_bearer_claims), db: Session = Depends(get_db)):
    if claims.get("actor_type") != "PLATFORM_ADMIN" or claims.get("token_use") != "access":
        raise HTTPException(status_code=403, detail="Super Admin access required")
    admin = db.query(PlatformAdmin).filter(PlatformAdmin.id == claims.get("sub"), PlatformAdmin.is_active == True).first()
    if not admin:
        raise HTTPException(status_code=401, detail="Admin account inactive or missing")
    return admin


class TenantContext:
    def __init__(self, tenant: ISPTenant, sub: TenantSubscription | None, plan: SubscriptionPlan | None, actor_id: str, role_name: str, permissions: list[str], is_support_impersonation: bool = False):
        self.tenant = tenant
        self.subscription = sub
        self.plan = plan
        self.actor_id = actor_id
        self.role_name = role_name
        self.permissions = permissions
        self.is_support_impersonation = is_support_impersonation


def require_tenant_perm(permission: str):
    def _dep(claims: dict = Depends(get_bearer_claims), db: Session = Depends(get_db)) -> TenantContext:
        if claims.get("token_use") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        actor_type = claims.get("actor_type")
        tenant_id = claims.get("tenant_id")
        if actor_type not in ("STAFF", "SUPPORT_IMPERSONATION") or not tenant_id:
            raise HTTPException(status_code=403, detail="ISP tenant token required")
        tenant = db.query(ISPTenant).filter(ISPTenant.id == tenant_id).first()
        if not tenant or tenant.status == "SUSPENDED":
            raise HTTPException(status_code=403, detail="Tenant account unavailable or suspended")
        sub = db.query(TenantSubscription).filter(TenantSubscription.tenant_id == tenant.id).first()
        plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.id == sub.plan_id).first() if sub else None

        if actor_type == "STAFF":
            staff = db.query(StaffUser).filter(StaffUser.id == claims.get("sub"), StaffUser.tenant_id == tenant.id, StaffUser.is_active == True).first()
            if not staff:
                raise HTTPException(status_code=401, detail="Staff account inactive")
            role = db.query(Role).filter(Role.id == staff.role_id, Role.tenant_id == tenant.id).first()
            perms = json.loads(role.permissions_json) if role else []
            if "*" not in perms and permission not in perms:
                raise HTTPException(status_code=403, detail=f"Missing permission: {permission}")
            return TenantContext(tenant, sub, plan, staff.id, role.name if role else "STAFF", perms, False)

        return TenantContext(tenant, sub, plan, claims.get("sub", "support"), "SUPPORT_IMPERSONATION", ["*"], True)
    return _dep


# ==========================================================
# SECTION 5: PYDANTIC REQUEST SCHEMAS
# ==========================================================

class PlatformBootstrapIn(BaseModel):
    email: str
    full_name: str
    password: str = Field(min_length=8)
    bootstrap_secret: str = ""


class LoginIn(BaseModel):
    email: str
    password: str
    totp_code: str = ""


class ISPLoginIn(LoginIn):
    tenant_slug: str


class ISPRegisterIn(BaseModel):
    business_name: str
    slug: str = ""
    country_code: str = "KE"
    currency: str = "KES"
    owner_name: str
    owner_email: str
    owner_phone: str
    password: str = Field(min_length=8)
    plan_code: str = "STARTER"
    referred_by_slug: str = ""


class TenantUpdateIn(BaseModel):
    status: str | None = None
    plan_code: str | None = None
    extend_days: int | None = None
    custom_price_kes: float | None = None


class PlanUpdateIn(BaseModel):
    monthly_price_kes: float | None = None
    annual_price_kes: float | None = None
    max_routers: int | None = None
    max_customers: int | None = None
    max_staff: int | None = None
    allow_pppoe: bool | None = None
    allow_api: bool | None = None
    allow_sms: bool | None = None
    allow_whatsapp: bool | None = None
    allow_telegram: bool | None = None


class PlatformPayCfgIn(BaseModel):
    method_type: str
    label: str
    country_code: str = "KE"
    till_number: str = ""
    paybill_number: str = ""
    account_reference: str = ""
    bank_name: str = ""
    bank_account_number: str = ""
    account_holder_name: str = ""
    credentials_json: str = ""
    instructions: str = ""
    is_default: bool = False


class BranchIn(BaseModel):
    name: str
    location: str = ""


class StaffCreateIn(BaseModel):
    email: str
    full_name: str
    password: str = Field(min_length=8)
    role_name: str = "CASHIER"
    branch_id: str | None = None


class PackageIn(BaseModel):
    service_type: str = "HOTSPOT"
    name: str
    price: float
    duration_minutes: int
    upload_kbps: int = 2048
    download_kbps: int = 5120
    data_limit_mb: int = 0
    device_limit: int = 1
    branch_id: str | None = None


class ISPPayCfgIn(BaseModel):
    provider: str
    country_code: str = "KE"
    till_number: str = ""
    paybill_number: str = ""
    account_reference: str = ""
    bank_name: str = ""
    bank_account_number: str = ""
    account_holder_name: str = ""
    credentials_json: str = ""
    instructions: str = ""


# ==========================================================
# SECTION 6: FASTAPI APP & ROUTES (STAGES 3-6)
# ==========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    log.info("%s initialized (env=%s)", APP_NAME, APP_ENV)
    yield


app = FastAPI(title=APP_NAME, version="0.2.0", docs_url=f"{API_V1_PREFIX}/docs", openapi_url=f"{API_V1_PREFIX}/openapi.json", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    res = await call_next(request)
    res.headers["X-Content-Type-Options"] = "nosniff"
    res.headers["X-Frame-Options"] = "DENY"
    res.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return res


@app.get("/", response_class=HTMLResponse)
def landing():
    return """<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PRIME HOTSPOT BILLING</title>
<style>
body{margin:0;font-family:system-ui,sans-serif;background:#0a1128;color:#fff;display:grid;place-items:center;min-height:100vh;padding:16px}
.box{background:#111c3a;border:1px solid #10b981;border-radius:18px;padding:26px;max-width:500px;text-align:center}
.tag{display:inline-block;background:#10b981;color:#052e16;font-weight:800;padding:4px 12px;border-radius:999px;font-size:12px}
a{display:inline-block;margin-top:16px;padding:10px 18px;background:#10b981;color:#052e16;border-radius:10px;text-decoration:none;font-weight:700}
</style></head><body>
<div class="box"><span class="tag">STAGES 1–6 LIVE</span>
<h1>PRIME HOTSPOT BILLING</h1>
<p>Auth, MFA, Super Admin Control Plane, Multi-Tenant Isolation &amp; ISP Dashboards active.</p>
<a href="/api/v1/docs">Open Swagger API Docs</a></div></body></html>"""


@app.get("/health")
def health():
    return {"status": "healthy", "service": APP_NAME, "stages": "1-6"}


# ---------- STAGE 3: AUTHENTICATION & MFA ----------

@app.post(f"{API_V1_PREFIX}/auth/platform/bootstrap")
def platform_bootstrap(body: PlatformBootstrapIn, db: Session = Depends(get_db)):
    if db.query(PlatformAdmin).count() > 0:
        raise HTTPException(status_code=403, detail="Platform owner already registered")
    if BOOTSTRAP_SECRET and body.bootstrap_secret != BOOTSTRAP_SECRET:
        raise HTTPException(status_code=403, detail="Invalid bootstrap secret")
    admin = PlatformAdmin(email=body.email.lower().strip(), full_name=body.full_name.strip(), password_hash=hash_password(body.password))
    db.add(admin)
    db.flush()
    write_audit(db, "PLATFORM_ADMIN", admin.id, "BOOTSTRAP_OWNER")
    db.commit()
    return {"id": admin.id, "email": admin.email}


@app.post(f"{API_V1_PREFIX}/auth/platform/login")
def platform_login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else ""
    rl_key = f"admin:{ip}:{body.email.lower().strip()}"
    check_rate_limit(rl_key)
    admin = db.query(PlatformAdmin).filter(PlatformAdmin.email == body.email.lower().strip(), PlatformAdmin.is_active == True).first()
    if not admin or not verify_password(body.password, admin.password_hash):
        record_failed_login(rl_key)
        write_audit(db, "SYSTEM", "unknown", "FAILED_ADMIN_LOGIN", ip=ip, details=body.email)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if admin.mfa_enabled:
        secret = decrypt_secret(admin.mfa_secret_enc)
        if not body.totp_code or not pyotp.TOTP(secret).verify(body.totp_code, valid_window=1):
            record_failed_login(rl_key)
            raise HTTPException(status_code=401, detail="Valid TOTP MFA code required")
    clear_failed_logins(rl_key)
    write_audit(db, "PLATFORM_ADMIN", admin.id, "LOGIN_SUCCESS", ip=ip)
    db.commit()
    return {
        "access_token": create_jwt_token({"sub": admin.id, "actor_type": "PLATFORM_ADMIN", "token_use": "access"}, timedelta(minutes=ACCESS_TOKEN_MINUTES)),
        "refresh_token": create_jwt_token({"sub": admin.id, "actor_type": "PLATFORM_ADMIN", "token_use": "refresh"}, timedelta(days=REFRESH_TOKEN_DAYS)),
        "token_type": "bearer",
    }


@app.post(f"{API_V1_PREFIX}/auth/platform/mfa/setup")
def platform_mfa_setup(admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    secret = pyotp.random_base32()
    admin.mfa_secret_enc = encrypt_secret(secret)
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=admin.email, issuer_name=APP_NAME)
    return {"secret": secret, "otpauth_uri": uri}


@app.post(f"{API_V1_PREFIX}/auth/platform/mfa/enable")
def platform_mfa_enable(totp_code: str = Query(...), admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    secret = decrypt_secret(admin.mfa_secret_enc)
    if not secret or not pyotp.TOTP(secret).verify(totp_code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")
    admin.mfa_enabled = True
    write_audit(db, "PLATFORM_ADMIN", admin.id, "MFA_ENABLED")
    db.commit()
    return {"mfa_enabled": True}


def _create_isp_tenant_bundle(db: Session, body: ISPRegisterIn, initial_status: str = "TRIAL") -> dict:
    slug = re.sub(r"[^a-z0-9-]+", "-", (body.slug or body.business_name).lower()).strip("-")[:80]
    if not slug or db.query(ISPTenant).filter(ISPTenant.slug == slug).first():
        raise HTTPException(status_code=409, detail="Business slug already exists or invalid")
    plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.code == body.plan_code.upper()).first()
    if not plan:
        raise HTTPException(status_code=400, detail="Invalid subscription plan code")

    ref_id = None
    if body.referred_by_slug:
        ref_t = db.query(ISPTenant).filter(ISPTenant.slug == body.referred_by_slug.strip().lower()).first()
        if ref_t:
            ref_id = ref_t.id

    tenant = ISPTenant(
        business_name=body.business_name.strip(), slug=slug, country_code=body.country_code.upper(),
        currency=body.currency.upper(), owner_email=body.owner_email.lower().strip(),
        owner_phone=body.owner_phone.strip(), status=initial_status, referred_by_tenant_id=ref_id,
    )
    db.add(tenant)
    db.flush()

    db.add(Branch(tenant_id=tenant.id, name="Main Branch", location=body.country_code.upper()))
    admin_role = None
    for rname, perms in ROLE_PERMISSIONS.items():
        r = Role(tenant_id=tenant.id, name=rname, permissions_json=json.dumps(perms))
        db.add(r)
        if rname == "ISP_ADMIN":
            db.flush()
            admin_role = r

    owner = StaffUser(tenant_id=tenant.id, role_id=admin_role.id, email=body.owner_email.lower().strip(), full_name=body.owner_name.strip(), password_hash=hash_password(body.password))
    db.add(owner)
    db.add(TenantSubscription(tenant_id=tenant.id, plan_id=plan.id, status=initial_status, expires_at=utcnow() + timedelta(days=14)))
    write_audit(db, "SYSTEM", tenant.id, "TENANT_CREATED", tenant_id=tenant.id, details=f"slug={slug}")
    db.commit()
    return {"tenant_id": tenant.id, "slug": tenant.slug, "status": tenant.status, "plan": plan.code}


@app.post(f"{API_V1_PREFIX}/auth/isp/register")
def isp_register(body: ISPRegisterIn, db: Session = Depends(get_db)):
    return _create_isp_tenant_bundle(db, body, initial_status="TRIAL")


@app.post(f"{API_V1_PREFIX}/auth/isp/login")
def isp_login(body: ISPLoginIn, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else ""
    rl_key = f"isp:{ip}:{body.tenant_slug}:{body.email.lower().strip()}"
    check_rate_limit(rl_key)
    tenant = db.query(ISPTenant).filter(ISPTenant.slug == body.tenant_slug.lower().strip()).first()
    if not tenant:
        record_failed_login(rl_key)
        raise HTTPException(status_code=401, detail="Invalid tenant or credentials")
    if tenant.status == "SUSPENDED":
        raise HTTPException(status_code=403, detail="Tenant account is suspended")
    staff = db.query(StaffUser).filter(StaffUser.tenant_id == tenant.id, StaffUser.email == body.email.lower().strip(), StaffUser.is_active == True).first()
    if not staff or not verify_password(body.password, staff.password_hash):
        record_failed_login(rl_key)
        write_audit(db, "SYSTEM", tenant.id, "FAILED_ISP_LOGIN", tenant_id=tenant.id, ip=ip, details=body.email)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid tenant or credentials")
    role = db.query(Role).filter(Role.id == staff.role_id).first()
    clear_failed_logins(rl_key)
    write_audit(db, "STAFF", staff.id, "ISP_LOGIN", tenant_id=tenant.id, ip=ip)
    db.commit()
    claims = {"sub": staff.id, "actor_type": "STAFF", "tenant_id": tenant.id, "role": role.name if role else "STAFF"}
    return {
        "access_token": create_jwt_token({**claims, "token_use": "access"}, timedelta(minutes=ACCESS_TOKEN_MINUTES)),
        "refresh_token": create_jwt_token({**claims, "token_use": "refresh"}, timedelta(days=REFRESH_TOKEN_DAYS)),
        "tenant": {"id": tenant.id, "slug": tenant.slug, "business_name": tenant.business_name, "role": claims["role"]},
    }


@app.post(f"{API_V1_PREFIX}/auth/refresh")
def refresh_token(claims: dict = Depends(get_bearer_claims)):
    if claims.get("token_use") != "refresh":
        raise HTTPException(status_code=401, detail="Refresh token required")
    new_claims = {k: v for k, v in claims.items() if k not in ("iat", "exp", "token_use")}
    return {"access_token": create_jwt_token({**new_claims, "token_use": "access"}, timedelta(minutes=ACCESS_TOKEN_MINUTES))}


# ---------- STAGE 4: SUPER ADMIN MASTER CONTROL PLANE ----------

@app.get(f"{API_V1_PREFIX}/superadmin/overview")
def superadmin_overview(admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    saas_rev = db.query(func.coalesce(func.sum(SaaSPayment.amount), 0)).filter(SaaSPayment.status == "CONFIRMED").scalar()
    return {
        "total_isps": db.query(ISPTenant).count(),
        "active_subscriptions": db.query(TenantSubscription).filter(TenantSubscription.status == "ACTIVE").count(),
        "trial_accounts": db.query(TenantSubscription).filter(TenantSubscription.status == "TRIAL").count(),
        "expired_subscriptions": db.query(TenantSubscription).filter(TenantSubscription.status == "EXPIRED").count(),
        "total_platform_revenue_kes": float(saas_rev or 0),
        "outstanding_invoices": db.query(SaaSInvoice).filter(SaaSInvoice.status == "UNPAID").count(),
        "connected_routers": db.query(MikroTikRouter).filter(MikroTikRouter.status == "ONLINE").count(),
        "offline_routers": db.query(MikroTikRouter).filter(MikroTikRouter.status != "ONLINE").count(),
        "total_customers": db.query(Customer).count(),
        "active_sessions": db.query(NetworkSession).filter(NetworkSession.ended_at == None).count(),
        "open_support_tickets": db.query(SupportTicket).filter(SupportTicket.status == "OPEN").count(),
    }


@app.get(f"{API_V1_PREFIX}/superadmin/tenants")
def superadmin_list_tenants(admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    rows = db.query(ISPTenant).order_by(ISPTenant.created_at.desc()).all()
    return [{"id": t.id, "business_name": t.business_name, "slug": t.slug, "status": t.status, "country": t.country_code, "owner_email": t.owner_email} for t in rows]


@app.post(f"{API_V1_PREFIX}/superadmin/tenants")
def superadmin_create_tenant(body: ISPRegisterIn, admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    return _create_isp_tenant_bundle(db, body, initial_status="ACTIVE")


@app.patch(f"{API_V1_PREFIX}/superadmin/tenants/{{tenant_id}}")
def superadmin_update_tenant(tenant_id: str, body: TenantUpdateIn, admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    tenant = db.query(ISPTenant).filter(ISPTenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    sub = db.query(TenantSubscription).filter(TenantSubscription.tenant_id == tenant.id).first()
    if body.status:
        tenant.status = body.status.upper()
        if sub:
            sub.status = body.status.upper()
    if body.plan_code and sub:
        plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.code == body.plan_code.upper()).first()
        if not plan:
            raise HTTPException(status_code=404, detail="Plan not found")
        sub.plan_id = plan.id
    if body.extend_days and sub:
        base_dt = max(utcnow(), sub.expires_at if sub.expires_at.tzinfo else sub.expires_at.replace(tzinfo=timezone.utc))
        sub.expires_at = base_dt + timedelta(days=body.extend_days)
    if body.custom_price_kes is not None and sub:
        sub.custom_price_kes = body.custom_price_kes
    write_audit(db, "PLATFORM_ADMIN", admin.id, "UPDATE_TENANT", tenant_id=tenant.id)
    db.commit()
    return {"tenant_id": tenant.id, "status": tenant.status}


@app.post(f"{API_V1_PREFIX}/superadmin/tenants/{{tenant_id}}/support-token")
def superadmin_support_access(tenant_id: str, admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    tenant = db.query(ISPTenant).filter(ISPTenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    write_audit(db, "PLATFORM_ADMIN", admin.id, "SUPPORT_IMPERSONATION", tenant_id=tenant.id)
    db.commit()
    tok = create_jwt_token({"sub": admin.id, "actor_type": "SUPPORT_IMPERSONATION", "tenant_id": tenant.id, "token_use": "access"}, timedelta(minutes=15))
    return {"support_access_token": tok, "expires_in_minutes": 15}


@app.get(f"{API_V1_PREFIX}/superadmin/plans")
def superadmin_get_plans(admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    return [{"code": p.code, "name": p.name, "monthly_price_kes": float(p.monthly_price_kes), "annual_price_kes": float(p.annual_price_kes), "max_routers": p.max_routers, "max_customers": p.max_customers, "max_staff": p.max_staff, "allow_pppoe": p.allow_pppoe, "allow_api": p.allow_api, "allow_sms": p.allow_sms, "allow_whatsapp": p.allow_whatsapp, "allow_telegram": p.allow_telegram} for p in db.query(SubscriptionPlan).all()]


@app.patch(f"{API_V1_PREFIX}/superadmin/plans/{{plan_code}}")
def superadmin_edit_plan(plan_code: str, body: PlanUpdateIn, admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.code == plan_code.upper()).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(plan, k, v)
    write_audit(db, "PLATFORM_ADMIN", admin.id, "EDIT_SAAS_PLAN", details=plan.code)
    db.commit()
    return {"code": plan.code, "monthly_price_kes": float(plan.monthly_price_kes)}


@app.get(f"{API_V1_PREFIX}/superadmin/payment-configs")
def superadmin_list_pay_cfgs(admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    """SYSTEM 2 ONLY: Platform owner's SaaS subscription collection methods."""
    cfgs = db.query(PlatformPaymentConfig).all()
    return [{"id": c.id, "method_type": c.method_type, "label": c.label, "till_number": c.till_number, "paybill_number": c.paybill_number, "bank_name": c.bank_name, "is_default": c.is_default, "is_active": c.is_active} for c in cfgs]


@app.post(f"{API_V1_PREFIX}/superadmin/payment-configs")
def superadmin_add_pay_cfg(body: PlatformPayCfgIn, admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    if body.is_default:
        db.query(PlatformPaymentConfig).update({"is_default": False})
    cfg = PlatformPaymentConfig(
        method_type=body.method_type.upper(), label=body.label, country_code=body.country_code.upper(),
        till_number=body.till_number, paybill_number=body.paybill_number, account_reference=body.account_reference,
        bank_name=body.bank_name, bank_account_number=body.bank_account_number, account_holder_name=body.account_holder_name,
        credentials_enc=encrypt_secret(body.credentials_json), instructions=body.instructions, is_default=body.is_default,
    )
    db.add(cfg)
    write_audit(db, "PLATFORM_ADMIN", admin.id, "ADD_PLATFORM_PAYMENT_CFG", details=cfg.method_type)
    db.commit()
    return {"id": cfg.id, "method_type": cfg.method_type}


@app.get(f"{API_V1_PREFIX}/superadmin/audit-logs")
def superadmin_audit_logs(admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()
    return [{"id": l.id, "actor_type": l.actor_type, "actor_id": l.actor_id, "action": l.action, "tenant_id": l.tenant_id, "details": l.details, "created_at": l.created_at.isoformat()} for l in logs]


# ---------- STAGE 5 & 6: MULTI-TENANT ISP DASHBOARD ----------

@app.get(f"{API_V1_PREFIX}/isp/dashboard")
def isp_dashboard(ctx: TenantContext = Depends(require_tenant_perm("reports:read")), db: Session = Depends(get_db)):
    tid = ctx.tenant.id
    cust_rev = db.query(func.coalesce(func.sum(CustomerPayment.amount), 0)).filter(CustomerPayment.tenant_id == tid, CustomerPayment.status == "CONFIRMED").scalar()
    return {
        "tenant": {"id": tid, "business_name": ctx.tenant.business_name, "slug": ctx.tenant.slug, "status": ctx.tenant.status, "currency": ctx.tenant.currency},
        "actor": {"role": ctx.role_name, "support_mode": ctx.is_support_impersonation},
        "subscription": {"plan": ctx.plan.code if ctx.plan else None, "status": ctx.subscription.status if ctx.subscription else None, "expires_at": ctx.subscription.expires_at.isoformat() if ctx.subscription else None},
        "metrics": {
            "branches": db.query(Branch).filter(Branch.tenant_id == tid).count(),
            "routers_total": db.query(MikroTikRouter).filter(MikroTikRouter.tenant_id == tid).count(),
            "packages": db.query(InternetPackage).filter(InternetPackage.tenant_id == tid).count(),
            "customers": db.query(Customer).filter(Customer.tenant_id == tid).count(),
            "vouchers": db.query(Voucher).filter(Voucher.tenant_id == tid).count(),
            "customer_revenue": float(cust_rev or 0),
        },
    }


@app.get(f"{API_V1_PREFIX}/isp/branches")
def isp_list_branches(ctx: TenantContext = Depends(require_tenant_perm("branches:read")), db: Session = Depends(get_db)):
    return [{"id": b.id, "name": b.name, "location": b.location} for b in db.query(Branch).filter(Branch.tenant_id == ctx.tenant.id).all()]


@app.post(f"{API_V1_PREFIX}/isp/branches")
def isp_create_branch(body: BranchIn, ctx: TenantContext = Depends(require_tenant_perm("branches:write")), db: Session = Depends(get_db)):
    b = Branch(tenant_id=ctx.tenant.id, name=body.name.strip(), location=body.location.strip())
    db.add(b)
    db.commit()
    return {"id": b.id, "name": b.name}


@app.get(f"{API_V1_PREFIX}/isp/staff")
def isp_list_staff(ctx: TenantContext = Depends(require_tenant_perm("staff:read")), db: Session = Depends(get_db)):
    rows = db.query(StaffUser, Role).join(Role, StaffUser.role_id == Role.id).filter(StaffUser.tenant_id == ctx.tenant.id).all()
    return [{"id": s.id, "email": s.email, "full_name": s.full_name, "role": r.name, "is_active": s.is_active} for s, r in rows]


@app.post(f"{API_V1_PREFIX}/isp/staff")
def isp_create_staff(body: StaffCreateIn, ctx: TenantContext = Depends(require_tenant_perm("*")), db: Session = Depends(get_db)):
    if ctx.plan and db.query(StaffUser).filter(StaffUser.tenant_id == ctx.tenant.id).count() >= ctx.plan.max_staff:
        raise HTTPException(status_code=403, detail="Plan staff limit reached")
    role = db.query(Role).filter(Role.tenant_id == ctx.tenant.id, Role.name == body.role_name.upper()).first()
    if not role:
        raise HTTPException(status_code=400, detail="Invalid role name")
    if db.query(StaffUser).filter(StaffUser.tenant_id == ctx.tenant.id, StaffUser.email == body.email.lower().strip()).first():
        raise HTTPException(status_code=409, detail="Staff email already exists")
    s = StaffUser(tenant_id=ctx.tenant.id, role_id=role.id, branch_id=body.branch_id, email=body.email.lower().strip(), full_name=body.full_name.strip(), password_hash=hash_password(body.password))
    db.add(s)
    write_audit(db, "STAFF", ctx.actor_id, "CREATE_STAFF", tenant_id=ctx.tenant.id, details=s.email)
    db.commit()
    return {"id": s.id, "email": s.email, "role": role.name}


@app.get(f"{API_V1_PREFIX}/isp/packages")
def isp_list_packages(ctx: TenantContext = Depends(require_tenant_perm("packages:read")), db: Session = Depends(get_db)):
    pkgs = db.query(InternetPackage).filter(InternetPackage.tenant_id == ctx.tenant.id).all()
    return [{"id": p.id, "service_type": p.service_type, "name": p.name, "price": float(p.price), "duration_minutes": p.duration_minutes, "upload_kbps": p.upload_kbps, "download_kbps": p.download_kbps} for p in pkgs]


@app.post(f"{API_V1_PREFIX}/isp/packages")
def isp_create_package(body: PackageIn, ctx: TenantContext = Depends(require_tenant_perm("packages:write")), db: Session = Depends(get_db)):
    stype = body.service_type.upper()
    if stype == "PPPOE" and ctx.plan and not ctx.plan.allow_pppoe:
        raise HTTPException(status_code=403, detail="Current SaaS plan does not include PPPoE")
    pkg = InternetPackage(tenant_id=ctx.tenant.id, branch_id=body.branch_id, service_type=stype, name=body.name.strip(), price=body.price, duration_minutes=body.duration_minutes, upload_kbps=body.upload_kbps, download_kbps=body.download_kbps, data_limit_mb=body.data_limit_mb, device_limit=body.device_limit)
    db.add(pkg)
    db.commit()
    return {"id": pkg.id, "name": pkg.name, "service_type": pkg.service_type}


@app.get(f"{API_V1_PREFIX}/isp/payment-configs")
def isp_list_pay_cfgs(ctx: TenantContext = Depends(require_tenant_perm("payments:read")), db: Session = Depends(get_db)):
    """SYSTEM 1 ONLY: ISP's own WiFi customer collection configs."""
    cfgs = db.query(ISPPaymentConfig).filter(ISPPaymentConfig.tenant_id == ctx.tenant.id).all()
    return [{"id": c.id, "provider": c.provider, "till_number": c.till_number, "paybill_number": c.paybill_number, "bank_name": c.bank_name, "is_active": c.is_active} for c in cfgs]


@app.post(f"{API_V1_PREFIX}/isp/payment-configs")
def isp_add_pay_cfg(body: ISPPayCfgIn, ctx: TenantContext = Depends(require_tenant_perm("payments:write")), db: Session = Depends(get_db)):
    cfg = ISPPaymentConfig(
        tenant_id=ctx.tenant.id, provider=body.provider.upper(), country_code=body.country_code.upper(),
        till_number=body.till_number, paybill_number=body.paybill_number, account_reference=body.account_reference,
        bank_name=body.bank_name, bank_account_number=body.bank_account_number, account_holder_name=body.account_holder_name,
        credentials_enc=encrypt_secret(body.credentials_json), instructions=body.instructions,
    )
    db.add(cfg)
    write_audit(db, "STAFF", ctx.actor_id, "ADD_ISP_PAYMENT_CFG", tenant_id=ctx.tenant.id, details=cfg.provider)
    db.commit()
    return {"id": cfg.id, "provider": cfg.provider}


# ==========================================================
# SECTION 7: AUTOMATED TESTS (STAGES 1–6)
# ==========================================================

def run_stage_tests():
    from fastapi.testclient import TestClient
    if DATABASE_URL.startswith("sqlite:///./"):
        db_file = DATABASE_URL.replace("sqlite:///./", "")
        if os.path.exists(db_file):
            os.remove(db_file)
    _failed_logins.clear()
    init_db()

    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        # 1. Bootstrap Super Admin & MFA
        r = client.post(f"{API_V1_PREFIX}/auth/platform/bootstrap", json={"email": "owner@primehotspot.co.ke", "full_name": "Platform Owner", "password": "OwnerPassword#2026"})
        assert r.status_code == 200
        adm_tok = client.post(f"{API_V1_PREFIX}/auth/platform/login", json={"email": "owner@primehotspot.co.ke", "password": "OwnerPassword#2026"}).json()["access_token"]
        adm_hdr = {"Authorization": f"Bearer {adm_tok}"}

        mfa_secret = client.post(f"{API_V1_PREFIX}/auth/platform/mfa/setup", headers=adm_hdr).json()["secret"]
        assert client.post(f"{API_V1_PREFIX}/auth/platform/mfa/enable?totp_code={pyotp.TOTP(mfa_secret).now()}", headers=adm_hdr).status_code == 200
        assert client.post(f"{API_V1_PREFIX}/auth/platform/login", json={"email": "owner@primehotspot.co.ke", "password": "OwnerPassword#2026", "totp_code": pyotp.TOTP(mfa_secret).now()}).status_code == 200

        # 2. Brute force rate-limit check
        for _ in range(5):
            client.post(f"{API_V1_PREFIX}/auth/platform/login", json={"email": "owner@primehotspot.co.ke", "password": "wrong"})
        assert client.post(f"{API_V1_PREFIX}/auth/platform/login", json={"email": "owner@primehotspot.co.ke", "password": "wrong"}).status_code == 429

        # 3. Register two isolated ISP tenants
        assert client.post(f"{API_V1_PREFIX}/auth/isp/register", json={"business_name": "Savanna WiFi", "slug": "savanna", "owner_name": "Ali", "owner_email": "ali@savanna.ke", "owner_phone": "0712000001", "password": "IspPass#2026", "plan_code": "BUSINESS"}).status_code == 200
        assert client.post(f"{API_V1_PREFIX}/auth/isp/register", json={"business_name": "Rift Fiber", "slug": "rift", "owner_name": "Joy", "owner_email": "joy@rift.ke", "owner_phone": "0712000002", "password": "IspPass#2026", "plan_code": "STARTER"}).status_code == 200

        tok_a = client.post(f"{API_V1_PREFIX}/auth/isp/login", json={"tenant_slug": "savanna", "email": "ali@savanna.ke", "password": "IspPass#2026"}).json()["access_token"]
        tok_b = client.post(f"{API_V1_PREFIX}/auth/isp/login", json={"tenant_slug": "rift", "email": "joy@rift.ke", "password": "IspPass#2026"}).json()["access_token"]
        hdr_a, hdr_b = {"Authorization": f"Bearer {tok_a}"}, {"Authorization": f"Bearer {tok_b}"}

        # 4. Tenant isolation & RBAC & Plan gating
        assert client.post(f"{API_V1_PREFIX}/isp/packages", headers=hdr_a, json={"service_type": "HOTSPOT", "name": "24 Hours", "price": 50, "duration_minutes": 1440}).status_code == 200
        assert client.post(f"{API_V1_PREFIX}/isp/packages", headers=hdr_b, json={"service_type": "PPPOE", "name": "Home 10Mbps", "price": 2000, "duration_minutes": 43200}).status_code == 403  # Starter blocks PPPoE
        assert len(client.get(f"{API_V1_PREFIX}/isp/packages", headers=hdr_b).json()) == 0  # Tenant B cannot see Tenant A's packages
        assert client.get(f"{API_V1_PREFIX}/superadmin/overview", headers=hdr_a).status_code == 403  # ISP cannot access Super Admin

        # 5. Staff RBAC check (CASHIER cannot create packages)
        assert client.post(f"{API_V1_PREFIX}/isp/staff", headers=hdr_a, json={"email": "cashier@savanna.ke", "full_name": "Cashier", "password": "Cashier#2026", "role_name": "CASHIER"}).status_code == 200
        tok_c = client.post(f"{API_V1_PREFIX}/auth/isp/login", json={"tenant_slug": "savanna", "email": "cashier@savanna.ke", "password": "Cashier#2026"}).json()["access_token"]
        assert client.post(f"{API_V1_PREFIX}/isp/packages", headers={"Authorization": f"Bearer {tok_c}"}, json={"service_type": "HOTSPOT", "name": "X", "price": 10, "duration_minutes": 60}).status_code == 403

        # 6. Super Admin overview & System 2 vs System 1 separation
        assert client.post(f"{API_V1_PREFIX}/superadmin/payment-configs", headers=adm_hdr, json={"method_type": "MPESA_TILL", "label": "Owner Till", "till_number": "6076817", "is_default": True}).status_code == 200
        assert client.post(f"{API_V1_PREFIX}/isp/payment-configs", headers=hdr_a, json={"provider": "MPESA_TILL", "till_number": "999888"}).status_code == 200
        assert len(client.get(f"{API_V1_PREFIX}/isp/payment-configs", headers=hdr_b).json()) == 0
        ov = client.get(f"{API_V1_PREFIX}/superadmin/overview", headers=adm_hdr).json()
        assert ov["total_isps"] == 2 and ov["trial_accounts"] == 2

    print("ALL STAGES 1-6 TESTS PASSED (Auth, TOTP MFA, Rate Limit, Super Admin, Multi-Tenancy, RBAC, Plan Gates).")


if __name__ == "__main__":
    if "--test" in sys.argv:
        run_stage_tests()
    else:
        import uvicorn
        uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
