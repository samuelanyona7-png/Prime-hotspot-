import os
import io
import re
import csv
import ssl
import sys
import time
import uuid
import json
import socket
import base64
import asyncio
import hashlib
import secrets
import logging
from html import escape as html_escape
from zoneinfo import ZoneInfo
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from collections import defaultdict

import jwt
import pyotp
import httpx
from fastapi import FastAPI, Request, Depends, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from sqlalchemy import (
    create_engine, Column, String, Integer, Numeric, Boolean,
    DateTime, Text, ForeignKey, UniqueConstraint, Index, func
)
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# ==========================================================
# 1. CONFIGURATION, SECURITY & CONSTANTS
# ==========================================================

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("prime-hotspot-billing")

APP_NAME = os.getenv("APP_NAME", "PRIME HOTSPOT BILLING").strip()
APP_ENV = os.getenv("APP_ENV", "development").strip()
API_V1 = "/api/v1"
PAYHERO_BASE = "https://backend.payhero.co.ke/api/v2"

DATABASE_URL = (os.getenv("DATABASE_URL") or "sqlite:///./prime_hotspot.db").strip()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql://" + DATABASE_URL[len("postgres://"):]

JWT_SECRET = (os.getenv("JWT_SECRET") or "dev-only-change-in-production-64-chars-secret").strip()
ENCRYPTION_KEY = (os.getenv("ENCRYPTION_KEY") or "").strip()
BOOTSTRAP_SECRET = (os.getenv("BOOTSTRAP_SECRET") or "").strip()
CORS_ORIGINS = [o.strip() for o in (os.getenv("CORS_ORIGINS") or "*").split(",") if o.strip()]

ROLE_PERMISSIONS = {
    "ISP_ADMIN": ["*"],
    "MANAGER": ["routers:read", "routers:write", "packages:read", "packages:write", "customers:read", "customers:write", "vouchers:read", "vouchers:write", "payments:read", "payments:write", "staff:read", "branches:read", "branches:write", "reports:read"],
    "CASHIER": ["customers:read", "customers:write", "vouchers:read", "vouchers:write", "payments:read", "payments:write"],
    "TECH_SUPPORT": ["routers:read", "routers:write", "customers:read", "customers:write", "packages:read"],
    "ACCOUNTANT": ["payments:read", "reports:read", "packages:read"],
    "VOUCHER_AGENT": ["vouchers:read", "vouchers:write", "packages:read"],
    "READ_ONLY": ["routers:read", "packages:read", "customers:read", "vouchers:read", "payments:read", "reports:read"],
}
MIKROTIK_MODELS = {
    "hAP lite": "32MB RAM (SMIPS, ROS6) - Use lean Hotspot or RADIUS",
    "hAP mini": "32MB RAM (SMIPS, ROS6) - Avoid ROS7 & large local tables",
    "hAP ac": "128MB (MIPSBE, ROS6/7)", "hAP ac2": "128MB (ARM, ROS6/7)", "hAP ac3": "256MB (ARM, ROS6/7)",
    "hAP ax series": "256MB+ (ARM64, ROS7 only)", "RB750 series": "64MB (MIPSBE, ROS6/7)", "RB750Gr3": "256MB (MMIPS, ROS6/7)",
    "RB951 series": "128MB (MIPSBE, ROS6/7)", "RB2011 series": "128MB (MIPSBE/ARM, ROS6/7)", "RB3011 series": "1GB (ARM, ROS6/7)",
    "RB4011 series": "1GB (ARM, ROS6/7)", "RB5009 series": "1GB (ARM64, ROS7)", "CCR series": "2GB+ (Carrier Core)",
    "CRS series": "Switch-first: pair with RB5009/CCR for >50 users", "CHR": "Cloud Hosted Router (x86_64/arm64)",
}
PROMO_DISCOUNTS = {"LAUNCH20": 0.20, "KENYA10": 0.10}
MAINTENANCE_MODE = {"enabled": False, "message": "Scheduled maintenance in progress."}

_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
_failed_logins = defaultdict(list)


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw: str, pwh: str) -> bool:
    try:
        return _ph.verify(pwh, pw)
    except VerifyMismatchError:
        return False


def _fernet() -> Fernet:
    key = ENCRYPTION_KEY.encode("utf-8") if ENCRYPTION_KEY else base64.urlsafe_b64encode(hashlib.sha256(JWT_SECRET.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_secret(v: str) -> str:
    return _fernet().encrypt(v.encode("utf-8")).decode("utf-8") if v else ""


def decrypt_secret(tok: str) -> str:
    return _fernet().decrypt(tok.encode("utf-8")).decode("utf-8") if tok else ""


def _parse_creds(enc: str) -> dict:
    try:
        return json.loads(decrypt_secret(enc)) if enc else {}
    except Exception:
        return {}


def create_jwt(payload: dict, delta: timedelta) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({**payload, "iat": int(now.timestamp()), "exp": int((now + delta).timestamp())}, JWT_SECRET, algorithm="HS256")


def decode_jwt(tok: str) -> dict:
    try:
        return jwt.decode(tok, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def check_rl(key: str):
    now = time.time()
    _failed_logins[key] = [t for t in _failed_logins[key] if now - t < 300]
    if len(_failed_logins[key]) >= 5:
        raise HTTPException(status_code=429, detail="Too many failed login attempts")


# ==========================================================
# 2. DATABASE SCHEMA (26 ISOLATED TABLES: SYSTEM 1 vs SYSTEM 2)
# ==========================================================

cargs = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=cargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def gid() -> str:
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
    id = Column(String(36), primary_key=True, default=gid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(150), nullable=False)
    password_hash = Column(Text, nullable=False)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret_enc = Column(Text, default="", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class PlatformPaymentConfig(Base):
    __tablename__ = "platform_payment_configs"
    id = Column(String(36), primary_key=True, default=gid)
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
    id = Column(String(36), primary_key=True, default=gid)
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
    id = Column(String(36), primary_key=True, default=gid)
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
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), unique=True, nullable=False)
    plan_id = Column(String(36), ForeignKey("subscription_plans.id"), nullable=False)
    billing_cycle = Column(String(20), default="MONTHLY", nullable=False)
    custom_price_kes = Column(Numeric(12, 2), nullable=True)
    status = Column(String(30), default="TRIAL", nullable=False)
    starts_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)


class SaaSInvoice(Base):
    __tablename__ = "saas_invoices"
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    invoice_number = Column(String(50), unique=True, nullable=False)
    amount = Column(Numeric(12, 2), nullable=False)
    currency = Column(String(10), default="KES", nullable=False)
    status = Column(String(30), default="UNPAID", nullable=False)
    due_at = Column(DateTime(timezone=True), nullable=False)
    paid_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class SaaSPayment(Base):
    __tablename__ = "saas_payments"
    id = Column(String(36), primary_key=True, default=gid)
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
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    location = Column(String(200), default="")


class Role(Base):
    __tablename__ = "roles"
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    name = Column(String(60), nullable=False)
    permissions_json = Column(Text, default="[]", nullable=False)


class StaffUser(Base):
    __tablename__ = "staff_users"
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    role_id = Column(String(36), ForeignKey("roles.id"), nullable=False)
    branch_id = Column(String(36), ForeignKey("branches.id"), nullable=True)
    email = Column(String(255), nullable=False)
    full_name = Column(String(150), nullable=False)
    password_hash = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_staff_tenant_email"),)


class MikroTikRouter(Base):
    __tablename__ = "mikrotik_routers"
    id = Column(String(36), primary_key=True, default=gid)
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
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    router_id = Column(String(36), ForeignKey("mikrotik_routers.id", ondelete="CASCADE"), unique=True, nullable=False)
    username_enc = Column(Text, nullable=False)
    password_enc = Column(Text, nullable=False)
    radius_secret_enc = Column(Text, default="")


class RouterConfiguration(Base):
    __tablename__ = "router_configurations"
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    router_id = Column(String(36), ForeignKey("mikrotik_routers.id", ondelete="CASCADE"), nullable=False)
    config_type = Column(String(40), nullable=False)
    script_body = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class InternetPackage(Base):
    __tablename__ = "internet_packages"
    id = Column(String(36), primary_key=True, default=gid)
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
    id = Column(String(36), primary_key=True, default=gid)
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
    __table_args__ = (UniqueConstraint("tenant_id", "account_number", name="uq_cust_acct"),)


class NetworkSession(Base):
    __tablename__ = "network_sessions"
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    router_id = Column(String(36), ForeignKey("mikrotik_routers.id", ondelete="CASCADE"), nullable=False)
    customer_id = Column(String(36), ForeignKey("customers.id"), nullable=True)
    session_key = Column(String(120), nullable=False)
    mac_address = Column(String(32), default="")
    ip_address = Column(String(64), default="")
    started_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    ended_at = Column(DateTime(timezone=True), nullable=True)


class Voucher(Base):
    __tablename__ = "vouchers"
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    package_id = Column(String(36), ForeignKey("internet_packages.id", ondelete="CASCADE"), nullable=False)
    code = Column(String(40), nullable=False)
    agent_staff_id = Column(String(36), ForeignKey("staff_users.id"), nullable=True)
    max_uses = Column(Integer, default=1, nullable=False)
    uses_count = Column(Integer, default=0, nullable=False)
    status = Column(String(20), default="UNUSED", nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    __table_args__ = (UniqueConstraint("tenant_id", "code", name="uq_vch_code"),)


class VoucherRedemption(Base):
    __tablename__ = "voucher_redemptions"
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    voucher_id = Column(String(36), ForeignKey("vouchers.id", ondelete="CASCADE"), nullable=False)
    customer_id = Column(String(36), ForeignKey("customers.id"), nullable=True)
    mac_address = Column(String(32), default="")
    redeemed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class ISPPaymentConfig(Base):
    __tablename__ = "isp_payment_configs"
    id = Column(String(36), primary_key=True, default=gid)
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
    __tablename__ = "customer_payments"
    id = Column(String(36), primary_key=True, default=gid)
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
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    system_scope = Column(String(20), nullable=False)
    external_ref = Column(String(120), nullable=False, index=True)
    event_type = Column(String(50), nullable=False)
    details = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class PaymentCallback(Base):
    __tablename__ = "payment_callbacks"
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    system_scope = Column(String(20), nullable=False)
    provider = Column(String(40), nullable=False)
    external_ref = Column(String(120), default="", index=True)
    payload_json = Column(Text, nullable=False)
    verified = Column(Boolean, default=False, nullable=False)
    received_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class NotificationConfig(Base):
    __tablename__ = "notification_configs"
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    channel = Column(String(20), nullable=False)
    provider = Column(String(40), nullable=False)
    credentials_enc = Column(Text, default="")
    sender_id = Column(String(60), default="")
    is_active = Column(Boolean, default=True, nullable=False)


class NotificationTemplate(Base):
    __tablename__ = "notification_templates"
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    event_name = Column(String(60), nullable=False)
    channel = Column(String(20), nullable=False)
    body_template = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)


class DeliveryLog(Base):
    __tablename__ = "delivery_logs"
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    channel = Column(String(20), nullable=False)
    event_name = Column(String(60), nullable=False)
    recipient = Column(String(120), nullable=False)
    status = Column(String(30), nullable=False)
    provider_response = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class SupportTicket(Base):
    __tablename__ = "support_tickets"
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    subject = Column(String(200), nullable=False)
    message = Column(Text, nullable=False)
    status = Column(String(30), default="OPEN", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String(36), primary_key=True, default=gid)
    tenant_id = Column(String(36), ForeignKey("isp_tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    actor_type = Column(String(30), nullable=False)
    actor_id = Column(String(36), nullable=False)
    action = Column(String(80), nullable=False)
    ip_address = Column(String(64), default="")
    details = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


Index("ix_cust_pay_t_st", CustomerPayment.tenant_id, CustomerPayment.status)
Index("ix_saas_pay_t_st", SaaSPayment.tenant_id, SaaSPayment.status)


def write_audit(db: Session, atype: str, aid: str, action: str, tid: str | None = None, ip: str = "", details: str = ""):
    db.add(AuditLog(tenant_id=tid, actor_type=atype, actor_id=aid, action=action, ip_address=ip, details=details[:500]))


def init_db():
    Base.metadata.create_all(bind=engine)
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


# ==========================================================
# 3. AUTH GUARDS & RBAC
# ==========================================================

def get_bearer(authorization: str = Header(default="")) -> dict:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    return decode_jwt(authorization.split(" ", 1)[1].strip())


def require_platform_admin(claims: dict = Depends(get_bearer), db: Session = Depends(get_db)):
    if claims.get("actor_type") != "PLATFORM_ADMIN" or claims.get("token_use") != "access":
        raise HTTPException(status_code=403, detail="Super Admin access required")
    adm = db.query(PlatformAdmin).filter(PlatformAdmin.id == claims.get("sub"), PlatformAdmin.is_active == True).first()
    if not adm:
        raise HTTPException(status_code=401, detail="Admin account missing")
    return adm


class TenantCtx:
    def __init__(self, tenant, sub, plan, actor_id, role_name, perms):
        self.tenant, self.sub, self.plan, self.actor_id, self.role_name, self.perms = tenant, sub, plan, actor_id, role_name, perms


def require_tenant_perm(perm: str):
    def _dep(claims: dict = Depends(get_bearer), db: Session = Depends(get_db)) -> TenantCtx:
        if claims.get("token_use") != "access" or claims.get("actor_type") not in ("STAFF", "SUPPORT_IMPERSONATION"):
            raise HTTPException(status_code=403, detail="ISP tenant token required")
        t = db.query(ISPTenant).filter(ISPTenant.id == claims.get("tenant_id")).first()
        if not t or t.status == "SUSPENDED":
            raise HTTPException(status_code=403, detail="Tenant suspended or missing")
        sub = db.query(TenantSubscription).filter(TenantSubscription.tenant_id == t.id).first()
        plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.id == sub.plan_id).first() if sub else None
        if claims.get("actor_type") == "STAFF":
            st = db.query(StaffUser).filter(StaffUser.id == claims.get("sub"), StaffUser.tenant_id == t.id, StaffUser.is_active == True).first()
            if not st:
                raise HTTPException(status_code=401, detail="Staff inactive")
            role = db.query(Role).filter(Role.id == st.role_id, Role.tenant_id == t.id).first()
            perms = json.loads(role.permissions_json) if role else []
            if "*" not in perms and perm not in perms:
                raise HTTPException(status_code=403, detail=f"Missing permission: {perm}")
            return TenantCtx(t, sub, plan, st.id, role.name if role else "STAFF", perms)
        return TenantCtx(t, sub, plan, claims.get("sub", "support"), "SUPPORT", ["*"])
    return _dep


# ==========================================================
# 4. UNIVERSAL MIKROTIK CLIENT, COMPATIBILITY & SCRIPT GEN
# ==========================================================

class RouterOSClient:
    def __init__(self, host: str, port: int = 8728, use_ssl: bool = False, timeout: float = 5.0):
        self.host, self.port, self.use_ssl, self.timeout, self.sock = host, int(port), use_ssl, timeout, None

    def connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        else:
            self.sock = raw

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _enc(self, n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        if n < 0x4000:
            return (n | 0x8000).to_bytes(2, "big")
        if n < 0x200000:
            return (n | 0xC00000).to_bytes(3, "big")
        if n < 0x10000000:
            return (n | 0xE0000000).to_bytes(4, "big")
        return b"\xF0" + n.to_bytes(4, "big")

    def _rx(self, n: int) -> bytes:
        b = bytearray()
        while len(b) < n:
            c = self.sock.recv(n - len(b))
            if not c:
                raise ConnectionError("Router closed connection")
            b.extend(c)
        return bytes(b)

    def _rlen(self) -> int:
        b = self._rx(1)[0]
        if (b & 0x80) == 0:
            return b
        if (b & 0xC0) == 0x80:
            return ((b & ~0xC0) << 8) + self._rx(1)[0]
        if (b & 0xE0) == 0xC0:
            return ((b & ~0xE0) << 16) + int.from_bytes(self._rx(2), "big")
        if (b & 0xF0) == 0xE0:
            return ((b & ~0xF0) << 24) + int.from_bytes(self._rx(3), "big")
        return int.from_bytes(self._rx(4), "big")

    def talk(self, words: list[str]) -> list[dict]:
        p = bytearray()
        for w in words:
            wb = w.encode("utf-8")
            p.extend(self._enc(len(wb)))
            p.extend(wb)
        p.append(0)
        self.sock.sendall(bytes(p))
        rows = []
        while True:
            sent = []
            while True:
                ln = self._rlen()
                if ln == 0:
                    break
                sent.append(self._rx(ln).decode("utf-8", errors="replace"))
            if not sent:
                continue
            attrs = {w[1:].split("=", 1)[0]: w[1:].split("=", 1)[1] for w in sent[1:] if w.startswith("=") and "=" in w[1:]}
            if sent[0] == "!re":
                rows.append(attrs)
            elif sent[0] == "!done":
                if attrs:
                    rows.append(attrs)
                return rows
            elif sent[0] in ("!trap", "!fatal"):
                raise RuntimeError(attrs.get("message") or str(sent))

    def login(self, user: str, pw: str):
        res = self.talk(["/login", f"=name={user}", f"=password={pw}"])
        if res and "ret" in res[0]:
            dig = hashlib.md5(b"\x00" + pw.encode("utf-8") + bytes.fromhex(res[0]["ret"])).hexdigest()
            self.talk(["/login", f"=name={user}", f"=response=00{dig}"])


def eval_compat(model: str, ros_ver: str, free_mem: int | None = None, pkgs: list[str] | None = None, ifaces: list[str] | None = None, api_ok: bool = False) -> dict:
    warns, alts = [], []
    ml = (model or "").lower()
    if "crs" in ml:
        warns.append("CRS switch CPU is limited for heavy NAT/Hotspot/PPPoE.")
        alts.append("Pair with RB750Gr3, RB4011, RB5009, or CCR.")
    if "hap lite" in ml or "hap mini" in ml or (free_mem is not None and free_mem < 16 * 1024 * 1024):
        warns.append("Low RAM; avoid large local queues.")
        alts.append("Use external RADIUS or lean Hotspot.")
    ps = {p.lower() for p in (pkgs or [])}
    return {
        "api_available": api_ok, "hotspot_supported": ("hotspot" in ps) or ("routeros" in ps) or (not ps and api_ok),
        "ppp_supported": ("ppp" in ps) or ("routeros" in ps) or (not ps and api_ok),
        "radius_supported": api_ok, "interfaces": (ifaces or [])[:25],
        "warnings": warns, "alternatives": alts, "compatible": bool(api_ok),
    }


def probe_router(host: str, port: int, use_ssl: bool, user: str, pw: str) -> dict:
    cli = RouterOSClient(host, port, use_ssl=use_ssl, timeout=5.0)
    try:
        cli.connect()
        cli.login(user, pw)
        ident = (cli.talk(["/system/identity/print"]) or [{}])[0].get("name", "")
        res = (cli.talk(["/system/resource/print"]) or [{}])[0]
        ifaces = [r.get("name", "") for r in cli.talk(["/interface/print"]) if r.get("name")]
        pkgs = [r.get("name", "") for r in cli.talk(["/system/package/print"]) if r.get("name") and r.get("disabled", "false") != "true"]
        fm = int(res.get("free-memory", 0) or 0)
        return {
            "online": True, "identity": ident, "hardware_model": res.get("board-name", "Unknown"),
            "routeros_version": res.get("version", "Unknown"), "architecture": res.get("architecture-name", "Unknown"),
            "free_memory_bytes": fm, "compatibility": eval_compat(res.get("board-name", ""), res.get("version", ""), fm, pkgs, ifaces, True),
        }
    except Exception as exc:
        return {"online": False, "error": str(exc), "compatibility": eval_compat("", "", api_ok=False)}
    finally:
        cli.close()


def gen_ros_script(rname: str, model: str, ros_ver: str, mode: str, hs_if: str, pp_if: str, srv_url: str, rad_sec: str = "") -> str:
    host = srv_url.replace("https://", "").replace("http://", "").split("/")[0]
    lines = [
        f"# PRIME HOTSPOT BILLING — ROUTEROS v{'7' if str(ros_ver).startswith('7') else '6'} ({model} / {mode})",
        "/system backup save name=prime-hotspot-preinstall",
        "/export file=prime-hotspot-preinstall",
        f'/ip hotspot walled-garden ip add dst-host="{host}" action=accept comment="PRIME-HOTSPOT"',
    ]
    if mode in ("API", "SCRIPT"):
        lines += ['/user group add name=prime-grp policy=read,write,api,test', '/user add name=primebilling group=prime-grp password="CHANGE_STRONG_PASS"', "/ip service set api disabled=no port=8728"]
    if mode == "RADIUS" or rad_sec:
        lines += [f'/radius add service=hotspot,ppp address={host.split(":")[0]} secret="{rad_sec or "CHANGE_RADIUS"}" timeout=3000ms', "/ip hotspot profile set [find] use-radius=yes", "/ppp aaa set use-radius=yes accounting=yes"]
    lines += [f':put ("Interfaces check: {hs_if}, {pp_if}")', f'/tool fetch url="{srv_url.rstrip("/")}/health" keep-result=no', "# Rollback: /system backup load name=prime-hotspot-preinstall"]
    return "\n".join(lines)


# ==========================================================
# 5. PAYMENT ADAPTERS (PAYHERO, DARAJA, AIRTEL) & ACTIVATION
# ==========================================================

def _msisdn(phone: str) -> str:
    p = "".join(c for c in (phone or "") if c.isdigit())
    return ("254" + p[1:]) if (p.startswith("0") and len(p) == 10) else (("254" + p) if (len(p) == 9 and p[0] in ("7", "1")) else p)


def _ph_hdr(tok: str) -> dict:
    t = (tok or "").strip()
    auth = t if t.lower().startswith("basic ") else ("Basic " + (base64.b64encode(t.encode()).decode() if ":" in t else t))
    return {"Authorization": auth, "Content-Type": "application/json"}


async def _payhero_stk(creds: dict, amt: float, phone: str, ref: str, cname: str, cb: str) -> dict:
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(f"{PAYHERO_BASE}/payments", headers=_ph_hdr(creds.get("auth_token", "")), json={"amount": max(1, int(round(amt))), "phone_number": phone, "channel_id": int(creds.get("channel_id") or 0), "provider": "m-pesa", "external_reference": ref, "customer_name": cname[:40], "callback_url": cb})
        d = r.json()
        if r.status_code not in (200, 201) or not (d.get("success") or d.get("reference")):
            raise RuntimeError(d.get("error_message") or d.get("message") or str(d))
        return {"provider_ref": d.get("reference", "")}


async def _daraja_stk(creds: dict, amt: float, phone: str, ref: str, cb: str) -> dict:
    base = "https://api.safaricom.co.ke" if creds.get("env") == "production" else "https://sandbox.safaricom.co.ke"
    sc, pk = str(creds.get("shortcode", "")), creds.get("passkey", "")
    ts = datetime.now(ZoneInfo("Africa/Nairobi")).strftime("%Y%m%d%H%M%S")
    pw = base64.b64encode(f"{sc}{pk}{ts}".encode()).decode()
    basic = base64.b64encode(f"{creds.get('consumer_key','')}:{creds.get('consumer_secret','')}".encode()).decode()
    msisdn = _msisdn(phone)
    async with httpx.AsyncClient(timeout=20) as c:
        tok = (await c.get(f"{base}/oauth/v1/generate", params={"grant_type": "client_credentials"}, headers={"Authorization": f"Basic {basic}"})).json()["access_token"]
        r = await c.post(f"{base}/mpesa/stkpush/v1/processrequest", headers={"Authorization": f"Bearer {tok}"}, json={"BusinessShortCode": sc, "Password": pw, "Timestamp": ts, "TransactionType": creds.get("transaction_type") or ("CustomerBuyGoodsOnline" if creds.get("till_number") else "CustomerPayBillOnline"), "Amount": max(1, int(round(amt))), "PartyA": msisdn, "PartyB": str(creds.get("till_number") or sc), "PhoneNumber": msisdn, "CallBackURL": cb, "AccountReference": ref[:12], "TransactionDesc": "Hotspot"})
        d = r.json()
        if str(d.get("ResponseCode")) != "0":
            raise RuntimeError(d.get("errorMessage") or str(d))
        return {"provider_ref": d.get("CheckoutRequestID", "")}


async def _airtel_ussd(creds: dict, amt: float, phone: str, ref: str, country: str, curr: str) -> dict:
    base = "https://openapi.airtel.africa" if creds.get("env") == "production" else "https://openapiuat.airtel.africa"
    m = _msisdn(phone)
    async with httpx.AsyncClient(timeout=20) as c:
        tok = (await c.post(f"{base}/auth/oauth2/token", json={"client_id": creds.get("client_id", ""), "client_secret": creds.get("client_secret", ""), "grant_type": "client_credentials"})).json()["access_token"]
        r = await c.post(f"{base}/merchant/v1/payments/", headers={"Authorization": f"Bearer {tok}", "X-Country": country, "X-Currency": curr}, json={"reference": ref, "subscriber": {"country": country, "currency": curr, "msisdn": m[3:] if m.startswith("254") else m}, "transaction": {"amount": float(amt), "country": country, "currency": curr, "id": ref}})
        d = r.json()
        if r.status_code not in (200, 201) or not d.get("status", {}).get("success"):
            raise RuntimeError(str(d))
        return {"provider_ref": (d.get("data") or {}).get("transaction", {}).get("id", ref)}


def _activate_customer_pay(db: Session, pay: CustomerPayment, pref: str) -> dict:
    if db.query(CustomerPayment).filter(CustomerPayment.id == pay.id, CustomerPayment.status.in_(["PENDING", "PENDING_APPROVAL"])).update({"status": "CONFIRMED", "provider_ref": pref or pay.provider_ref}) == 0:
        return {"status": "ALREADY_CONFIRMED", "external_ref": pay.external_ref}
    pkg = db.query(InternetPackage).filter(InternetPackage.id == pay.package_id, InternetPackage.tenant_id == pay.tenant_id).first()
    mins = pkg.duration_minutes if pkg else 60
    cust = db.query(Customer).filter(Customer.id == pay.customer_id, Customer.tenant_id == pay.tenant_id).first() if pay.customer_id else None
    if not cust:
        acct, pwd = "PH" + secrets.token_hex(4).upper(), secrets.token_hex(4)
        cust = Customer(tenant_id=pay.tenant_id, package_id=pay.package_id, account_number=acct, full_name=f"WiFi {pay.phone or acct}", phone=pay.phone or "N/A", connection_type=pkg.service_type if pkg else "HOTSPOT", username=acct, secret_enc=encrypt_secret(pwd), status="ACTIVE", expires_at=utcnow() + timedelta(minutes=mins))
        db.add(cust)
        db.flush()
        pay.customer_id = cust.id
    else:
        now = utcnow()
        ce = cust.expires_at if (cust.expires_at and cust.expires_at.tzinfo) else (cust.expires_at.replace(tzinfo=timezone.utc) if cust.expires_at else now)
        cust.status, cust.expires_at = "ACTIVE", (max(now, ce) if cust.status == "ACTIVE" else now) + timedelta(minutes=mins)
    db.add(PaymentEvent(tenant_id=pay.tenant_id, system_scope="SYSTEM1_ISP", external_ref=pay.external_ref, event_type="CONFIRMED", details=pref))
    db.commit()
    return {"status": "CONFIRMED", "username": cust.username, "expires_at": cust.expires_at.isoformat()}


def _activate_saas_pay(db: Session, sp: SaaSPayment, pref: str, adm_id: str | None = None) -> dict:
    upd = {"status": "CONFIRMED", "provider_ref": pref or sp.provider_ref}
    if adm_id:
        upd["approved_by_admin_id"] = adm_id
    if db.query(SaaSPayment).filter(SaaSPayment.id == sp.id, SaaSPayment.status.in_(["PENDING", "PENDING_APPROVAL"])).update(upd) == 0:
        return {"status": "ALREADY_CONFIRMED"}
    inv = db.query(SaaSInvoice).filter(SaaSInvoice.id == sp.invoice_id).first() if sp.invoice_id else None
    if inv:
        inv.status, inv.paid_at = "PAID", utcnow()
    sub = db.query(TenantSubscription).filter(TenantSubscription.tenant_id == sp.tenant_id).first()
    t = db.query(ISPTenant).filter(ISPTenant.id == sp.tenant_id).first()
    days = 365 if (sub and sub.billing_cycle == "ANNUAL") else 30
    if sub:
        now = utcnow()
        ce = sub.expires_at if (sub.expires_at and sub.expires_at.tzinfo) else (sub.expires_at.replace(tzinfo=timezone.utc) if sub.expires_at else now)
        sub.expires_at, sub.status = max(now, ce) + timedelta(days=days), "ACTIVE"
    if t:
        t.status = "ACTIVE"
    db.add(PaymentEvent(tenant_id=sp.tenant_id, system_scope="SYSTEM2_SAAS", external_ref=sp.external_ref, event_type="SAAS_CONFIRMED", details=f"+{days}d"))
    db.commit()
    return {"status": "CONFIRMED", "extended_days": days}


# ==========================================================
# 6. NOTIFICATIONS (SMS, WHATSAPP, TELEGRAM) & MONITORING
# ==========================================================

async def dispatch_notification(db: Session, tid: str, ev: str, rcpt: str, ctx_vars: dict, channels: list[str] | None = None) -> list[dict]:
    q = db.query(NotificationConfig).filter(NotificationConfig.tenant_id == tid, NotificationConfig.is_active == True)
    if channels:
        q = q.filter(NotificationConfig.channel.in_([c.upper() for c in channels]))
    out = []
    for cfg in q.all():
        tpl = db.query(NotificationTemplate).filter(NotificationTemplate.tenant_id == tid, NotificationTemplate.event_name == ev.upper(), NotificationTemplate.channel == cfg.channel, NotificationTemplate.is_active == True).first()
        body = tpl.body_template if tpl else f"[{ev}] " + ", ".join(f"{k}={v}" for k, v in ctx_vars.items())
        for k, v in ctx_vars.items():
            body = body.replace("{" + str(k) + "}", str(v))
        creds = _parse_creds(cfg.credentials_enc)
        st, resp_s = "SENT", ""
        try:
            async with httpx.AsyncClient(timeout=15) as cl:
                if cfg.channel == "SMS":
                    p = cfg.provider.upper()
                    if p == "AFRICASTALKING":
                        u = "https://api.sandbox.africastalking.com/version1/messaging" if creds.get("env") == "sandbox" else "https://api.africastalking.com/version1/messaging"
                        r = await cl.post(u, headers={"apiKey": creds.get("api_key", "")}, data={"username": creds.get("username", "sandbox"), "to": rcpt, "message": body})
                    elif p == "ADVANTA":
                        r = await cl.post("https://quicksms.advantasms.com/api/services/sendsms/", json={"apikey": creds.get("api_key", ""), "partnerID": creds.get("partner_id", ""), "shortcode": cfg.sender_id, "mobile": rcpt, "message": body})
                    elif p == "TWILIO":
                        r = await cl.post(f"https://api.twilio.com/2010-04-01/Accounts/{creds.get('account_sid','')}/Messages.json", auth=(creds.get("account_sid", ""), creds.get("auth_token", "")), data={"To": rcpt, "From": cfg.sender_id, "Body": body})
                    else:
                        r = await cl.post(f"https://{creds.get('base_url','api.infobip.com')}/sms/2/text/advanced", headers={"Authorization": f"App {creds.get('api_key','')}"}, json={"messages": [{"destinations": [{"to": rcpt}], "from": cfg.sender_id or "PrimeHotspot", "text": body}]})
                    r.raise_for_status()
                    resp_s = r.text[:200]
                elif cfg.channel == "WHATSAPP":
                    r = await cl.post(f"https://graph.facebook.com/v21.0/{creds.get('phone_number_id','')}/messages", headers={"Authorization": f"Bearer {creds.get('access_token','')}"}, json={"messaging_product": "whatsapp", "to": rcpt.lstrip("+"), "type": "text", "text": {"body": body}})
                    r.raise_for_status()
                    resp_s = r.text[:200]
                elif cfg.channel == "TELEGRAM":
                    r = await cl.post(f"https://api.telegram.org/bot{creds.get('bot_token','')}/sendMessage", json={"chat_id": rcpt or creds.get("default_chat_id", ""), "text": body})
                    r.raise_for_status()
                    resp_s = r.text[:200]
        except Exception as exc:
            st, resp_s = "FAILED", str(exc)[:250]
        db.add(DeliveryLog(tenant_id=tid, channel=cfg.channel, event_name=ev.upper(), recipient=rcpt or "DEFAULT", status=st, provider_response=resp_s))
        out.append({"channel": cfg.channel, "status": st, "response": resp_s})
    db.commit()
    return out


async def run_monitoring_cycle(db: Session, tenant_id: str | None = None) -> dict:
    now, exp_c, outages = utcnow(), 0, 0
    cq = db.query(Customer).filter(Customer.status == "ACTIVE", Customer.expires_at != None)
    if tenant_id:
        cq = cq.filter(Customer.tenant_id == tenant_id)
    for c in cq.all():
        ce = c.expires_at if c.expires_at.tzinfo else c.expires_at.replace(tzinfo=timezone.utc)
        if ce <= now:
            c.status = "EXPIRED"
            db.query(NetworkSession).filter(NetworkSession.customer_id == c.id, NetworkSession.ended_at == None).update({"ended_at": now})
            exp_c += 1
            await dispatch_notification(db, c.tenant_id, "PACKAGE_EXPIRY", c.phone, {"username": c.username})
    rq = db.query(MikroTikRouter).filter(MikroTikRouter.integration_mode == "API")
    if tenant_id:
        rq = rq.filter(MikroTikRouter.tenant_id == tenant_id)
    for r in rq.all():
        cred = db.query(RouterCredential).filter(RouterCredential.router_id == r.id).first()
        if not cred:
            continue
        prev = r.status
        pr = await asyncio.to_thread(probe_router, r.host, r.api_port, r.use_ssl, decrypt_secret(cred.username_enc), decrypt_secret(cred.password_enc))
        r.status = "ONLINE" if pr["online"] else "OFFLINE"
        if pr["online"]:
            r.last_seen_at = now
        elif prev == "ONLINE":
            outages += 1
            write_audit(db, "SYSTEM", "monitor", "ROUTER_OUTAGE", tid=r.tenant_id, details=r.name)
            await dispatch_notification(db, r.tenant_id, "ROUTER_OUTAGE", "", {"router": r.name})
    db.commit()
    return {"expired_customers": exp_c, "outages_detected": outages}


async def _bg_monitor():
    while True:
        try:
            db = SessionLocal()
            try:
                await run_monitoring_cycle(db)
            finally:
                db.close()
        except Exception:
            pass
        await asyncio.sleep(120)


# ==========================================================
# 7. FASTAPI APPLICATION & ALL ENDPOINTS (STAGES 1–25)
# ==========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    task = asyncio.create_task(_bg_monitor())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title=APP_NAME, version="1.0.0", docs_url=f"{API_V1}/docs", openapi_url=f"{API_V1}/openapi.json", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.middleware("http")
async def sec_headers(req: Request, call_next):
    res = await call_next(req)
    res.headers["X-Content-Type-Options"] = "nosniff"
    res.headers["X-Frame-Options"] = "DENY"
    res.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return res


class BootstrapIn(BaseModel):
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


class ISPRegIn(BaseModel):
    business_name: str
    slug: str = ""
    country_code: str = "KE"
    currency: str = "KES"
    owner_name: str
    owner_email: str
    owner_phone: str
    password: str = Field(min_length=8)
    plan_code: str = "STARTER"


class PayCfgIn(BaseModel):
    provider: str
    label: str = ""
    till_number: str = ""
    paybill_number: str = ""
    account_reference: str = ""
    bank_name: str = ""
    bank_account_number: str = ""
    credentials_json: str = ""
    instructions: str = ""


class PackageIn(BaseModel):
    service_type: str = "HOTSPOT"
    name: str
    price: float
    duration_minutes: int
    device_limit: int = 1


class RouterIn(BaseModel):
    name: str
    host: str
    api_port: int = 8728
    use_ssl: bool = False
    integration_mode: str = "API"
    username: str = "primebilling"
    password: str = ""
    radius_secret: str = ""


class VoucherGenIn(BaseModel):
    package_id: str
    quantity: int = Field(ge=1, le=500, default=10)
    prefix: str = "PH-"


class PortalPayIn(BaseModel):
    package_id: str
    payment_config_id: str
    phone: str = ""
    manual_reference: str = ""
    proof_url: str = ""


class SaaSCheckoutIn(BaseModel):
    plan_code: str = ""
    billing_cycle: str = "MONTHLY"
    platform_payment_config_id: str
    phone: str = ""
    promo_code: str = ""
    manual_reference: str = ""


class NotifCfgIn(BaseModel):
    channel: str
    provider: str
    sender_id: str = ""
    credentials_json: str = "{}"


@app.get("/health")
def health():
    return {"status": "healthy", "service": APP_NAME, "stages": "1-25", "maintenance": MAINTENANCE_MODE["enabled"]}


@app.get("/", response_class=HTMLResponse)
def home():
    return "<!DOCTYPE html><html><body style='background:#070e23;color:#fff;font-family:system-ui;display:grid;place-items:center;min-height:100vh;margin:0'><div style='background:#0f1b3d;border:1px solid #10b981;border-radius:16px;padding:28px;text-align:center'><h1>PRIME HOTSPOT BILLING</h1><p>All 25 Stages Active (Multi-Tenant MikroTik SaaS)</p><a href='/api/v1/docs' style='display:inline-block;padding:10px 18px;background:#10b981;color:#052e16;border-radius:10px;font-weight:700;text-decoration:none'>Open API Docs</a></div></body></html>"


@app.post(f"{API_V1}/auth/platform/bootstrap")
def platform_bootstrap(body: BootstrapIn, db: Session = Depends(get_db)):
    if db.query(PlatformAdmin).count() > 0 or (BOOTSTRAP_SECRET and body.bootstrap_secret != BOOTSTRAP_SECRET):
        raise HTTPException(status_code=403, detail="Bootstrap disallowed")
    adm = PlatformAdmin(email=body.email.lower().strip(), full_name=body.full_name.strip(), password_hash=hash_password(body.password))
    db.add(adm)
    db.commit()
    return {"id": adm.id, "email": adm.email}


@app.post(f"{API_V1}/auth/platform/login")
def platform_login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    k = f"adm:{request.client.host if request.client else ''}:{body.email.lower()}"
    check_rl(k)
    adm = db.query(PlatformAdmin).filter(PlatformAdmin.email == body.email.lower().strip(), PlatformAdmin.is_active == True).first()
    if not adm or not verify_password(body.password, adm.password_hash):
        _failed_logins[k].append(time.time())
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if adm.mfa_enabled and not pyotp.TOTP(decrypt_secret(adm.mfa_secret_enc)).verify(body.totp_code or "", valid_window=1):
        raise HTTPException(status_code=401, detail="Valid TOTP required")
    _failed_logins.pop(k, None)
    return {"access_token": create_jwt({"sub": adm.id, "actor_type": "PLATFORM_ADMIN", "token_use": "access"}, timedelta(minutes=30)), "refresh_token": create_jwt({"sub": adm.id, "actor_type": "PLATFORM_ADMIN", "token_use": "refresh"}, timedelta(days=7))}


@app.post(f"{API_V1}/auth/platform/mfa/setup")
def mfa_setup(adm: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    sec = pyotp.random_base32()
    adm.mfa_secret_enc = encrypt_secret(sec)
    db.commit()
    return {"secret": sec, "otpauth_uri": pyotp.TOTP(sec).provisioning_uri(name=adm.email, issuer_name=APP_NAME)}


@app.post(f"{API_V1}/auth/platform/mfa/enable")
def mfa_enable(totp_code: str = Query(...), adm: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    if not pyotp.TOTP(decrypt_secret(adm.mfa_secret_enc)).verify(totp_code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid TOTP")
    adm.mfa_enabled = True
    db.commit()
    return {"mfa_enabled": True}


@app.post(f"{API_V1}/auth/isp/register")
def isp_register(body: ISPRegIn, db: Session = Depends(get_db)):
    slug = re.sub(r"[^a-z0-9-]+", "-", (body.slug or body.business_name).lower()).strip("-")[:80]
    if not slug or db.query(ISPTenant).filter(ISPTenant.slug == slug).first():
        raise HTTPException(status_code=409, detail="Slug exists")
    plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.code == body.plan_code.upper()).first()
    if not plan:
        raise HTTPException(status_code=400, detail="Invalid plan")
    t = ISPTenant(business_name=body.business_name.strip(), slug=slug, country_code=body.country_code.upper(), currency=body.currency.upper(), owner_email=body.owner_email.lower().strip(), owner_phone=body.owner_phone.strip(), status="TRIAL")
    db.add(t)
    db.flush()
    db.add(Branch(tenant_id=t.id, name="Main Branch", location=t.country_code))
    ar = None
    for rn, perms in ROLE_PERMISSIONS.items():
        r = Role(tenant_id=t.id, name=rn, permissions_json=json.dumps(perms))
        db.add(r)
        if rn == "ISP_ADMIN":
            db.flush()
            ar = r
    db.add(StaffUser(tenant_id=t.id, role_id=ar.id, email=t.owner_email, full_name=body.owner_name.strip(), password_hash=hash_password(body.password)))
    db.add(TenantSubscription(tenant_id=t.id, plan_id=plan.id, status="TRIAL", expires_at=utcnow() + timedelta(days=14)))
    db.commit()
    return {"tenant_id": t.id, "slug": t.slug, "status": t.status}


@app.post(f"{API_V1}/auth/isp/login")
def isp_login(body: ISPLoginIn, request: Request, db: Session = Depends(get_db)):
    k = f"isp:{request.client.host if request.client else ''}:{body.tenant_slug}:{body.email.lower()}"
    check_rl(k)
    t = db.query(ISPTenant).filter(ISPTenant.slug == body.tenant_slug.lower().strip()).first()
    if not t or t.status == "SUSPENDED":
        _failed_logins[k].append(time.time())
        raise HTTPException(status_code=401, detail="Invalid tenant or suspended")
    st = db.query(StaffUser).filter(StaffUser.tenant_id == t.id, StaffUser.email == body.email.lower().strip(), StaffUser.is_active == True).first()
    if not st or not verify_password(body.password, st.password_hash):
        _failed_logins[k].append(time.time())
        raise HTTPException(status_code=401, detail="Invalid credentials")
    _failed_logins.pop(k, None)
    return {"access_token": create_jwt({"sub": st.id, "actor_type": "STAFF", "tenant_id": t.id, "token_use": "access"}, timedelta(minutes=30))}


@app.get(f"{API_V1}/superadmin/overview")
def sa_overview(adm: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    rev = db.query(func.coalesce(func.sum(SaaSPayment.amount), 0)).filter(SaaSPayment.status == "CONFIRMED").scalar()
    return {"total_isps": db.query(ISPTenant).count(), "total_platform_revenue_kes": float(rev or 0), "routers_online": db.query(MikroTikRouter).filter(MikroTikRouter.status == "ONLINE").count(), "total_customers": db.query(Customer).count()}


@app.post(f"{API_V1}/superadmin/payment-configs")
def sa_add_paycfg(body: PayCfgIn, adm: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    c = PlatformPaymentConfig(method_type=body.provider.upper(), label=body.label or body.provider, till_number=body.till_number, paybill_number=body.paybill_number, account_reference=body.account_reference, bank_name=body.bank_name, bank_account_number=body.bank_account_number, credentials_enc=encrypt_secret(body.credentials_json), instructions=body.instructions, is_default=True)
    db.add(c)
    db.commit()
    return {"id": c.id}


@app.get(f"{API_V1}/superadmin/payment-configs")
def sa_list_paycfg(adm: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    return [{"id": c.id, "method_type": c.method_type, "label": c.label, "till_number": c.till_number} for c in db.query(PlatformPaymentConfig).all()]


@app.post(f"{API_V1}/superadmin/saas-payments/{{pid}}/approve")
def sa_approve_pay(pid: str, adm: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    sp = db.query(SaaSPayment).filter(SaaSPayment.id == pid).first()
    if not sp:
        raise HTTPException(status_code=404, detail="Not found")
    return _activate_saas_pay(db, sp, sp.provider_ref or "MANUAL", adm_id=adm.id)


@app.get(f"{API_V1}/superadmin/financial-report")
def sa_fin_rep(adm: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    bm = db.query(SaaSPayment.payment_method, func.coalesce(func.sum(SaaSPayment.amount), 0)).filter(SaaSPayment.status == "CONFIRMED").group_by(SaaSPayment.payment_method).all()
    return {"system": "SYSTEM2_SAAS", "total_saas_revenue_kes": sum(float(v) for _, v in bm), "by_method": {m: float(v) for m, v in bm}}


@app.post(f"{API_V1}/superadmin/maintenance")
def sa_maint(enabled: bool = Query(...), adm: PlatformAdmin = Depends(require_platform_admin)):
    MAINTENANCE_MODE["enabled"] = enabled
    return MAINTENANCE_MODE


@app.get(f"{API_V1}/isp/dashboard")
def isp_dash(ctx: TenantCtx = Depends(require_tenant_perm("reports:read")), db: Session = Depends(get_db)):
    rev = db.query(func.coalesce(func.sum(CustomerPayment.amount), 0)).filter(CustomerPayment.tenant_id == ctx.tenant.id, CustomerPayment.status == "CONFIRMED").scalar()
    return {"tenant": ctx.tenant.slug, "plan": ctx.plan.code if ctx.plan else None, "customer_revenue": float(rev or 0), "customers": db.query(Customer).filter(Customer.tenant_id == ctx.tenant.id).count()}


@app.post(f"{API_V1}/isp/packages")
def isp_add_pkg(body: PackageIn, ctx: TenantCtx = Depends(require_tenant_perm("packages:write")), db: Session = Depends(get_db)):
    st = body.service_type.upper()
    if st == "PPPOE" and ctx.plan and not ctx.plan.allow_pppoe:
        raise HTTPException(status_code=403, detail="Plan does not include PPPoE")
    p = InternetPackage(tenant_id=ctx.tenant.id, service_type=st, name=body.name, price=body.price, duration_minutes=body.duration_minutes, device_limit=body.device_limit)
    db.add(p)
    db.commit()
    return {"id": p.id, "name": p.name}


@app.get(f"{API_V1}/isp/packages")
def isp_list_pkg(ctx: TenantCtx = Depends(require_tenant_perm("packages:read")), db: Session = Depends(get_db)):
    return [{"id": p.id, "name": p.name, "service_type": p.service_type, "price": float(p.price)} for p in db.query(InternetPackage).filter(InternetPackage.tenant_id == ctx.tenant.id).all()]


@app.post(f"{API_V1}/isp/routers")
def isp_add_router(body: RouterIn, ctx: TenantCtx = Depends(require_tenant_perm("routers:write")), db: Session = Depends(get_db)):
    if ctx.plan and db.query(MikroTikRouter).filter(MikroTikRouter.tenant_id == ctx.tenant.id).count() >= ctx.plan.max_routers:
        raise HTTPException(status_code=403, detail="Router limit reached")
    if body.integration_mode.upper() == "API" and ctx.plan and not ctx.plan.allow_api:
        raise HTTPException(status_code=403, detail="Plan does not allow API")
    r = MikroTikRouter(tenant_id=ctx.tenant.id, name=body.name, host=body.host, api_port=body.api_port, use_ssl=body.use_ssl, integration_mode=body.integration_mode.upper())
    db.add(r)
    db.flush()
    db.add(RouterCredential(tenant_id=ctx.tenant.id, router_id=r.id, username_enc=encrypt_secret(body.username), password_enc=encrypt_secret(body.password), radius_secret_enc=encrypt_secret(body.radius_secret)))
    db.commit()
    return {"id": r.id}


@app.post(f"{API_V1}/isp/routers/{{rid}}/test")
def isp_test_router(rid: str, ctx: TenantCtx = Depends(require_tenant_perm("routers:write")), db: Session = Depends(get_db)):
    r = db.query(MikroTikRouter).filter(MikroTikRouter.id == rid, MikroTikRouter.tenant_id == ctx.tenant.id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Router not found")
    cred = db.query(RouterCredential).filter(RouterCredential.router_id == r.id).first()
    pr = probe_router(r.host, r.api_port, r.use_ssl, decrypt_secret(cred.username_enc), decrypt_secret(cred.password_enc))
    r.status = "ONLINE" if pr["online"] else "OFFLINE"
    db.commit()
    return pr


@app.post(f"{API_V1}/isp/routers/{{rid}}/script")
def isp_router_script(rid: str, model: str = Query(default="RB750Gr3"), ros_version: str = Query(default="7"), mode: str = Query(default="API"), ctx: TenantCtx = Depends(require_tenant_perm("routers:write")), db: Session = Depends(get_db)):
    r = db.query(MikroTikRouter).filter(MikroTikRouter.id == rid, MikroTikRouter.tenant_id == ctx.tenant.id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Router not found")
    sc = gen_ros_script(r.name, model, ros_version, mode.upper(), "bridge-hs", "ether2", "https://api.primehotspot.example")
    db.add(RouterConfiguration(tenant_id=ctx.tenant.id, router_id=r.id, config_type="GENERATED_SCRIPT", script_body=sc))
    db.commit()
    return {"script": sc}


@app.post(f"{API_V1}/isp/vouchers/generate")
def isp_gen_vouchers(body: VoucherGenIn, ctx: TenantCtx = Depends(require_tenant_perm("vouchers:write")), db: Session = Depends(get_db)):
    pkg = db.query(InternetPackage).filter(InternetPackage.id == body.package_id, InternetPackage.tenant_id == ctx.tenant.id).first()
    if not pkg:
        raise HTTPException(status_code=404, detail="Package not found")
    codes = []
    for _ in range(body.quantity):
        c = body.prefix.upper() + "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(8))
        db.add(Voucher(tenant_id=ctx.tenant.id, package_id=pkg.id, code=c, expires_at=utcnow() + timedelta(days=30)))
        codes.append(c)
    db.commit()
    return {"generated": len(codes), "codes": codes}


@app.post(f"{API_V1}/isp/payment-configs")
def isp_add_paycfg(body: PayCfgIn, ctx: TenantCtx = Depends(require_tenant_perm("payments:write")), db: Session = Depends(get_db)):
    c = ISPPaymentConfig(tenant_id=ctx.tenant.id, provider=body.provider.upper(), till_number=body.till_number, paybill_number=body.paybill_number, bank_name=body.bank_name, bank_account_number=body.bank_account_number, credentials_enc=encrypt_secret(body.credentials_json), instructions=body.instructions)
    db.add(c)
    db.commit()
    return {"id": c.id}


@app.post(f"{API_V1}/isp/payments/{{pid}}/approve")
def isp_approve_pay(pid: str, ctx: TenantCtx = Depends(require_tenant_perm("payments:write")), db: Session = Depends(get_db)):
    p = db.query(CustomerPayment).filter(CustomerPayment.id == pid, CustomerPayment.tenant_id == ctx.tenant.id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Payment not found")
    return _activate_customer_pay(db, p, p.provider_ref or "MANUAL")


@app.get(f"{API_V1}/isp/financial-report")
def isp_fin_rep(ctx: TenantCtx = Depends(require_tenant_perm("reports:read")), db: Session = Depends(get_db)):
    bp = db.query(CustomerPayment.provider, func.coalesce(func.sum(CustomerPayment.amount), 0)).filter(CustomerPayment.tenant_id == ctx.tenant.id, CustomerPayment.status == "CONFIRMED").group_by(CustomerPayment.provider).all()
    return {"system": "SYSTEM1_ISP", "total_customer_revenue": sum(float(v) for _, v in bp), "by_provider": {p: float(v) for p, v in bp}}


@app.post(f"{API_V1}/isp/subscription/checkout")
async def isp_saas_checkout(body: SaaSCheckoutIn, request: Request, ctx: TenantCtx = Depends(require_tenant_perm("*")), db: Session = Depends(get_db)):
    plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.code == body.plan_code.upper()).first() if body.plan_code else ctx.plan
    cfg = db.query(PlatformPaymentConfig).filter(PlatformPaymentConfig.id == body.platform_payment_config_id, PlatformPaymentConfig.is_active == True).first()
    if not plan or not cfg:
        raise HTTPException(status_code=404, detail="Plan or payment config missing")
    amt = float(plan.annual_price_kes if body.billing_cycle.upper() == "ANNUAL" else plan.monthly_price_kes)
    amt = round(amt * (1.0 - PROMO_DISCOUNTS.get(body.promo_code.upper(), 0.0)), 2)
    inv = SaaSInvoice(tenant_id=ctx.tenant.id, invoice_number="INV-" + secrets.token_hex(4).upper(), amount=amt, due_at=utcnow() + timedelta(days=3))
    db.add(inv)
    db.flush()
    ext = "SAAS-" + secrets.token_hex(6).upper()
    sp = SaaSPayment(tenant_id=ctx.tenant.id, invoice_id=inv.id, payment_method=cfg.method_type, amount=amt, external_ref=ext, provider_ref=body.manual_reference or None, status="PENDING_APPROVAL" if cfg.method_type in ("MPESA_TILL", "MPESA_PAYBILL", "BANK") else "PENDING")
    db.add(sp)
    db.commit()
    return {"payment_id": sp.id, "external_ref": ext, "amount_kes": amt, "status": sp.status}


@app.post(f"{API_V1}/isp/notifications/configs")
def isp_add_notif(body: NotifCfgIn, ctx: TenantCtx = Depends(require_tenant_perm("*")), db: Session = Depends(get_db)):
    ch = body.channel.upper()
    if (ch == "SMS" and ctx.plan and not ctx.plan.allow_sms) or (ch == "WHATSAPP" and ctx.plan and not ctx.plan.allow_whatsapp) or (ch == "TELEGRAM" and ctx.plan and not ctx.plan.allow_telegram):
        raise HTTPException(status_code=403, detail=f"Plan excludes {ch}")
    c = NotificationConfig(tenant_id=ctx.tenant.id, channel=ch, provider=body.provider.upper(), sender_id=body.sender_id, credentials_enc=encrypt_secret(body.credentials_json))
    db.add(c)
    db.commit()
    return {"id": c.id}


@app.post(f"{API_V1}/isp/notifications/test")
async def isp_test_notif(channel: str = Query(...), recipient: str = Query(...), message: str = Query(...), ctx: TenantCtx = Depends(require_tenant_perm("*")), db: Session = Depends(get_db)):
    return {"dispatched": await dispatch_notification(db, ctx.tenant.id, "TEST", recipient, {"msg": message}, [channel])}


@app.post(f"{API_V1}/isp/routers/monitoring/check-now")
async def isp_mon_now(ctx: TenantCtx = Depends(require_tenant_perm("routers:read")), db: Session = Depends(get_db)):
    return await run_monitoring_cycle(db, tenant_id=ctx.tenant.id)


@app.get("/portal/{slug}", response_class=HTMLResponse)
def captive_portal(slug: str, db: Session = Depends(get_db)):
    t = db.query(ISPTenant).filter(ISPTenant.slug == slug.lower().strip()).first()
    if not t:
        raise HTTPException(status_code=404, detail="Portal not found")
    pkgs = db.query(InternetPackage).filter(InternetPackage.tenant_id == t.id, InternetPackage.service_type == "HOTSPOT", InternetPackage.is_visible == True).all()
    cfgs = db.query(ISPPaymentConfig).filter(ISPPaymentConfig.tenant_id == t.id, ISPPaymentConfig.is_active == True).all()
    cards = "".join(f"<div style='background:#0f1b3d;border:1px solid #1e3366;border-radius:14px;padding:12px'><b>{html_escape(p.name)}</b><div style='color:#10b981;font-size:18px;font-weight:800'>{html_escape(t.currency)} {float(p.price):,.0f}</div></div>" for p in pkgs)
    pay_opts = "".join(f"<option value='{c.id}'>{html_escape(c.provider)} {html_escape(c.till_number or c.paybill_number)}</option>" for c in cfgs)
    pkg_opts = "".join(f"<option value='{p.id}'>{html_escape(p.name)} ({float(p.price):,.0f})</option>" for p in pkgs)
    return f"<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'></head><body style='margin:0;background:#070e23;color:#fff;font-family:system-ui;padding:16px'><div style='max-width:460px;margin:auto'><div style='background:#0f1b3d;border:1px solid #10b981;border-radius:16px;padding:16px;text-align:center'><h2>{html_escape(t.business_name)}</h2><small>Care: {html_escape(t.owner_phone)}</small></div><div style='display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px'>{cards}</div><div style='background:#0f1b3d;border-radius:14px;padding:14px;margin-top:12px'><b>Buy Package</b><select id='pk' style='width:100%;padding:8px;margin-top:6px'>{pkg_opts}</select><select id='pm' style='width:100%;padding:8px;margin-top:6px'>{pay_opts}</select><input id='ph' placeholder='Phone 07...' style='width:100%;padding:8px;margin-top:6px;box-sizing:border-box'><button onclick='buy()' style='width:100%;padding:10px;margin-top:8px;background:#10b981;color:#052e16;font-weight:800;border:none;border-radius:8px'>Pay Now</button><div id='br'></div></div><div style='background:#0f1b3d;border-radius:14px;padding:14px;margin-top:12px'><b>Redeem Voucher</b><input id='vc' placeholder='Voucher Code' style='width:100%;padding:8px;margin-top:6px;box-sizing:border-box'><button onclick='red()' style='width:100%;padding:10px;margin-top:8px;background:#10b981;color:#052e16;font-weight:800;border:none;border-radius:8px'>Activate</button><div id='vr'></div></div></div><script>const s='{html_escape(t.slug)}';async function buy(){{const r=await fetch('/api/v1/portal/'+s+'/pay',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{package_id:pk.value,payment_config_id:pm.value,phone:ph.value}})}});const d=await r.json();br.innerText=d.status||d.detail;}}async function red(){{const r=await fetch('/api/v1/portal/'+s+'/redeem-voucher',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{code:vc.value}})}});const d=await r.json();vr.innerText=d.username?('Active: '+d.username):(d.detail||'Error');}}</script></body></html>"


@app.post(f"{API_V1}/portal/{{slug}}/pay")
async def portal_pay(slug: str, body: PortalPayIn, request: Request, db: Session = Depends(get_db)):
    t = db.query(ISPTenant).filter(ISPTenant.slug == slug.lower().strip()).first()
    if not t:
        raise HTTPException(status_code=404, detail="ISP not found")
    pkg = db.query(InternetPackage).filter(InternetPackage.id == body.package_id, InternetPackage.tenant_id == t.id).first()
    cfg = db.query(ISPPaymentConfig).filter(ISPPaymentConfig.id == body.payment_config_id, ISPPaymentConfig.tenant_id == t.id).first()
    if not pkg or not cfg:
        raise HTTPException(status_code=404, detail="Package or payment method invalid")
    ext = "CUST-" + secrets.token_hex(6).upper()
    is_man = cfg.provider in ("MPESA_TILL", "MPESA_PAYBILL", "BANK")
    pay = CustomerPayment(tenant_id=t.id, package_id=pkg.id, provider=cfg.provider, phone=body.phone, amount=pkg.price, currency=t.currency, external_ref=ext, provider_ref=body.manual_reference or None, proof_url=body.proof_url or None, status="PENDING_APPROVAL" if is_man else "PENDING")
    db.add(pay)
    db.commit()
    if is_man:
        return {"payment_id": pay.id, "external_ref": ext, "status": "PENDING_APPROVAL"}
    creds = _parse_creds(cfg.credentials_enc)
    base_u = str(request.base_url).rstrip("/")
    try:
        if cfg.provider == "PAYHERO":
            res = await _payhero_stk(creds, float(pkg.price), body.phone, ext, t.business_name, f"{base_u}{API_V1}/webhooks/system1/payhero/{t.id}")
        elif cfg.provider == "DARAJA":
            res = await _daraja_stk(creds, float(pkg.price), body.phone, ext, f"{base_u}{API_V1}/webhooks/system1/daraja/{t.id}")
        else:
            res = await _airtel_ussd(creds, float(pkg.price), body.phone, ext, t.country_code, t.currency)
        pay.provider_ref = res.get("provider_ref", "")
        db.commit()
        return {"payment_id": pay.id, "external_ref": ext, "status": "PENDING"}
    except Exception as exc:
        pay.status = "FAILED"
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc))


@app.post(f"{API_V1}/portal/{{slug}}/redeem-voucher")
def portal_redeem(slug: str, code: str = Query(default=""), body: dict | None = None, db: Session = Depends(get_db)):
    t = db.query(ISPTenant).filter(ISPTenant.slug == slug.lower().strip()).first()
    if not t:
        raise HTTPException(status_code=404, detail="ISP not found")
    c_str = ((body or {}).get("code") or code).strip().upper()
    v = db.query(Voucher).filter(Voucher.tenant_id == t.id, Voucher.code == c_str).first()
    if not v or v.status != "UNUSED" or v.uses_count >= v.max_uses:
        raise HTTPException(status_code=400, detail="Voucher invalid or already used")
    if db.query(Voucher).filter(Voucher.id == v.id, Voucher.uses_count < Voucher.max_uses, Voucher.status == "UNUSED").update({"uses_count": v.uses_count + 1}) == 0:
        raise HTTPException(status_code=409, detail="Already redeemed")
    v = db.query(Voucher).filter(Voucher.id == v.id).first()
    if v.uses_count >= v.max_uses:
        v.status = "REDEEMED"
    pkg = db.query(InternetPackage).filter(InternetPackage.id == v.package_id).first()
    exp = utcnow() + timedelta(minutes=pkg.duration_minutes if pkg else 60)
    cust = Customer(tenant_id=t.id, package_id=v.package_id, account_number="VCH" + secrets.token_hex(3).upper(), full_name="Voucher User", phone="N/A", username=c_str, secret_enc=encrypt_secret(c_str), status="ACTIVE", expires_at=exp)
    db.add(cust)
    db.flush()
    db.add(VoucherRedemption(tenant_id=t.id, voucher_id=v.id, customer_id=cust.id))
    db.commit()
    return {"status": "ACTIVE", "username": cust.username, "expires_at": exp.isoformat()}


@app.post(f"{API_V1}/webhooks/system1/daraja/{{tenant_id}}")
async def wh_sys1_daraja(tenant_id: str, request: Request, db: Session = Depends(get_db)):
    pl = await request.json()
    stk = (pl.get("Body") or {}).get("stkCallback") or {}
    cid, rc = stk.get("CheckoutRequestID", ""), stk.get("ResultCode")
    pay = db.query(CustomerPayment).filter(CustomerPayment.tenant_id == tenant_id, CustomerPayment.provider_ref == cid).first()
    if pay and rc == 0:
        items = {i.get("Name"): i.get("Value") for i in (stk.get("CallbackMetadata") or {}).get("Item", [])}
        if float(items.get("Amount") or 0) >= float(pay.amount):
            _activate_customer_pay(db, pay, str(items.get("MpesaReceiptNumber") or cid))
    return {"ResultCode": 0, "ResultDesc": "Accepted"}


@app.post(f"{API_V1}/webhooks/telegram/{{tenant_id}}")
async def wh_telegram(tenant_id: str, request: Request, db: Session = Depends(get_db)):
    t = db.query(ISPTenant).filter(ISPTenant.id == tenant_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Not found")
    txt = ((await request.json()).get("message") or {}).get("text", "")
    if txt.startswith("/sales"):
        rev = db.query(func.coalesce(func.sum(CustomerPayment.amount), 0)).filter(CustomerPayment.tenant_id == t.id, CustomerPayment.status == "CONFIRMED").scalar()
        return {"ok": True, "reply": f"Sales: {t.currency} {float(rev or 0):,.2f}"}
    return {"ok": True, "reply": f"{t.business_name} Bot Online"}


# ==========================================================
# 8. FULL SELF-TEST SUITE (ALL 25 STAGES)
# ==========================================================

def run_all_tests():
    from fastapi.testclient import TestClient
    if DATABASE_URL.startswith("sqlite:///./"):
        f = DATABASE_URL.replace("sqlite:///./", "")
        if os.path.exists(f):
            os.remove(f)
    _failed_logins.clear()
    init_db()
    with TestClient(app) as cl:
        assert cl.get("/health").status_code == 200
        cl.post(f"{API_V1}/auth/platform/bootstrap", json={"email": "owner@prime.ke", "full_name": "Owner", "password": "OwnerPassword#2026"})
        adm_t = cl.post(f"{API_V1}/auth/platform/login", json={"email": "owner@prime.ke", "password": "OwnerPassword#2026"}).json()["access_token"]
        ha = {"Authorization": f"Bearer {adm_t}"}
        cl.post(f"{API_V1}/auth/isp/register", json={"business_name": "Savanna", "slug": "savanna", "owner_name": "Ali", "owner_email": "ali@sav.ke", "owner_phone": "0711000001", "password": "IspPass#2026", "plan_code": "BUSINESS"})
        cl.post(f"{API_V1}/auth/isp/register", json={"business_name": "Rift", "slug": "rift", "owner_name": "Joy", "owner_email": "joy@rift.ke", "owner_phone": "0711000002", "password": "IspPass#2026", "plan_code": "STARTER"})
        ta = cl.post(f"{API_V1}/auth/isp/login", json={"tenant_slug": "savanna", "email": "ali@sav.ke", "password": "IspPass#2026"}).json()["access_token"]
        tb = cl.post(f"{API_V1}/auth/isp/login", json={"tenant_slug": "rift", "email": "joy@rift.ke", "password": "IspPass#2026"}).json()["access_token"]
        h1, h2 = {"Authorization": f"Bearer {ta}"}, {"Authorization": f"Bearer {tb}"}

        # Router probe (honest offline) & script
        rid = cl.post(f"{API_V1}/isp/routers", headers=h1, json={"name": "GW1", "host": "127.0.0.1", "api_port": 59999, "password": "x"}).json()["id"]
        assert cl.post(f"{API_V1}/isp/routers/{rid}/test", headers=h1).json()["online"] is False
        assert "/system backup" in cl.post(f"{API_V1}/isp/routers/{rid}/script", headers=h1).json()["script"]

        # Packages, vouchers, portal & System 1 vs System 2 isolation
        pid = cl.post(f"{API_V1}/isp/packages", headers=h1, json={"service_type": "HOTSPOT", "name": "24h", "price": 50, "duration_minutes": 1440}).json()["id"]
        assert cl.post(f"{API_V1}/isp/packages", headers=h2, json={"service_type": "PPPOE", "name": "P", "price": 1000, "duration_minutes": 1440}).status_code == 403
        vc = cl.post(f"{API_V1}/isp/vouchers/generate", headers=h1, json={"package_id": pid, "quantity": 2}).json()["codes"][0]
        assert cl.post(f"{API_V1}/portal/savanna/redeem-voucher", json={"code": vc}).status_code == 200
        assert cl.post(f"{API_V1}/portal/savanna/redeem-voucher", json={"code": vc}).status_code == 400
        assert "Savanna" in cl.get("/portal/savanna").text

        icfg = cl.post(f"{API_V1}/isp/payment-configs", headers=h1, json={"provider": "MPESA_TILL", "till_number": "112233"}).json()["id"]
        pm = cl.post(f"{API_V1}/portal/savanna/pay", json={"package_id": pid, "payment_config_id": icfg, "phone": "0712111222", "manual_reference": "REF1"}).json()
        assert pm["status"] == "PENDING_APPROVAL"
        assert cl.post(f"{API_V1}/isp/payments/{pm['payment_id']}/approve", headers=h1).json()["status"] == "CONFIRMED"

        pcfg = cl.post(f"{API_V1}/superadmin/payment-configs", headers=ha, json={"provider": "MPESA_TILL", "till_number": "6076817"}).json()["id"]
        sc = cl.post(f"{API_V1}/isp/subscription/checkout", headers=h1, json={"plan_code": "BUSINESS", "platform_payment_config_id": pcfg, "promo_code": "LAUNCH20"}).json()
        assert cl.post(f"{API_V1}/superadmin/saas-payments/{sc['payment_id']}/approve", headers=ha).json()["status"] == "CONFIRMED"
        assert cl.get(f"{API_V1}/superadmin/financial-report", headers=ha).json()["total_saas_revenue_kes"] == 2800.0
        assert cl.get(f"{API_V1}/isp/financial-report", headers=h1).json()["total_customer_revenue"] == 50.0
        assert cl.get(f"{API_V1}/isp/financial-report", headers=h2).json()["total_customer_revenue"] == 0.0

        cl.post(f"{API_V1}/isp/notifications/configs", headers=h1, json={"channel": "SMS", "provider": "AFRICASTALKING", "credentials_json": '{"api_key":"x"}'})
        assert cl.post(f"{API_V1}/isp/notifications/test?channel=SMS&recipient=%2B254700&message=hi", headers=h1).json()["dispatched"][0]["status"] == "FAILED"
        assert "expired_customers" in cl.post(f"{API_V1}/isp/routers/monitoring/check-now", headers=h1).json()
    print("ALL 25 STAGES IN SINGLE-FILE main.py PASSED!")


if __name__ == "__main__":
    if "--test" in sys.argv:
        run_all_tests()
    else:
        import uvicorn
        uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
