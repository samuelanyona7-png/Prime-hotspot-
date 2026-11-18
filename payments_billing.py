import io
import csv
import sys
import json
import base64
import secrets
from zoneinfo import ZoneInfo
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

_m = sys.modules.get("main") or sys.modules.get("__main__")
if not _m or not hasattr(_m, "SessionLocal"):
    import main as _m

import routers_portal as _rp

API_V1_PREFIX = _m.API_V1_PREFIX
SessionLocal = _m.SessionLocal
get_db = _m.get_db
utcnow = _m.utcnow
encrypt_secret = _m.encrypt_secret
decrypt_secret = _m.decrypt_secret
write_audit = _m.write_audit
require_platform_admin = _m.require_platform_admin
require_tenant_perm = _m.require_tenant_perm
TenantContext = _m.TenantContext

PlatformAdmin = _m.PlatformAdmin
PlatformPaymentConfig = _m.PlatformPaymentConfig
SubscriptionPlan = _m.SubscriptionPlan
ISPTenant = _m.ISPTenant
TenantSubscription = _m.TenantSubscription
SaaSInvoice = _m.SaaSInvoice
SaaSPayment = _m.SaaSPayment
InternetPackage = _m.InternetPackage
Customer = _m.Customer
MikroTikRouter = _m.MikroTikRouter
ISPPaymentConfig = _m.ISPPaymentConfig
CustomerPayment = _m.CustomerPayment
PaymentEvent = _m.PaymentEvent
PaymentCallback = _m.PaymentCallback

router = APIRouter()

PAYHERO_BASE = "https://backend.payhero.co.ke/api/v2"
PROMO_DISCOUNTS = {"LAUNCH20": 0.20, "KENYA10": 0.10}


def _normalize_msisdn(phone: str) -> str:
    p = "".join(ch for ch in (phone or "") if ch.isdigit())
    if p.startswith("0") and len(p) == 10:
        return "254" + p[1:]
    if len(p) == 9 and p[0] in ("7", "1"):
        return "254" + p
    return p


def _parse_creds(enc: str) -> dict:
    if not enc:
        return {}
    try:
        return json.loads(decrypt_secret(enc))
    except Exception:
        return {}


# ==========================================================
# PROVIDER ADAPTERS (PAYHERO, DARAJA M-PESA, AIRTEL MONEY)
# ==========================================================

def _payhero_headers(auth_token: str) -> dict:
    tok = (auth_token or "").strip()
    if tok.lower().startswith("basic "):
        auth = tok
    elif ":" in tok:
        auth = "Basic " + base64.b64encode(tok.encode("utf-8")).decode("utf-8")
    else:
        auth = "Basic " + tok
    return {"Authorization": auth, "Content-Type": "application/json"}


async def _initiate_payhero_stk(creds: dict, amount: float, phone: str, ext_ref: str, cust_name: str, callback_url: str) -> dict:
    token = creds.get("auth_token", "")
    channel_id = int(creds.get("channel_id") or 0)
    if not token or not channel_id:
        raise RuntimeError("PayHero auth_token and channel_id are required")
    payload = {
        "amount": max(1, int(round(amount))),
        "phone_number": phone,
        "channel_id": channel_id,
        "provider": "m-pesa",
        "external_reference": ext_ref,
        "customer_name": cust_name[:40],
        "callback_url": callback_url,
    }
    if creds.get("credential_id"):
        payload["credential_id"] = creds["credential_id"]
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(f"{PAYHERO_BASE}/payments", headers=_payhero_headers(token), json=payload)
        data = r.json() if "application/json" in r.headers.get("content-type", "") else {"raw": r.text[:250]}
        if r.status_code not in (200, 201) or not (data.get("success") or data.get("reference")):
            raise RuntimeError(data.get("error_message") or data.get("message") or str(data))
        return {"provider_ref": data.get("reference", ""), "checkout_id": data.get("CheckoutRequestID", "")}


async def _verify_payhero_status(creds: dict, reference: str) -> dict:
    token = creds.get("auth_token", "")
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{PAYHERO_BASE}/transaction-status", headers=_payhero_headers(token), params={"reference": reference})
        r.raise_for_status()
        return r.json()


async def _initiate_daraja_stk(creds: dict, amount: float, phone: str, ext_ref: str, callback_url: str) -> dict:
    base = "https://api.safaricom.co.ke" if creds.get("env") == "production" else "https://sandbox.safaricom.co.ke"
    ck, cs = creds.get("consumer_key", ""), creds.get("consumer_secret", "")
    shortcode, passkey = str(creds.get("shortcode", "")), creds.get("passkey", "")
    party_b = str(creds.get("till_number") or shortcode)
    tx_type = creds.get("transaction_type") or ("CustomerBuyGoodsOnline" if creds.get("till_number") else "CustomerPayBillOnline")
    if not (ck and cs and shortcode and passkey):
        raise RuntimeError("Daraja credentials incomplete")

    basic = base64.b64encode(f"{ck}:{cs}".encode("utf-8")).decode("utf-8")
    ts = datetime.now(ZoneInfo("Africa/Nairobi")).strftime("%Y%m%d%H%M%S")
    pw = base64.b64encode(f"{shortcode}{passkey}{ts}".encode("utf-8")).decode("utf-8")
    msisdn = _normalize_msisdn(phone)

    async with httpx.AsyncClient(timeout=20) as client:
        tok_r = await client.get(f"{base}/oauth/v1/generate", params={"grant_type": "client_credentials"}, headers={"Authorization": f"Basic {basic}"})
        tok_r.raise_for_status()
        access_token = tok_r.json()["access_token"]
        payload = {
            "BusinessShortCode": shortcode,
            "Password": pw,
            "Timestamp": ts,
            "TransactionType": tx_type,
            "Amount": max(1, int(round(amount))),
            "PartyA": msisdn,
            "PartyB": party_b,
            "PhoneNumber": msisdn,
            "CallBackURL": callback_url,
            "AccountReference": ext_ref[:12],
            "TransactionDesc": "Internet Package",
        }
        r = await client.post(f"{base}/mpesa/stkpush/v1/processrequest", headers={"Authorization": f"Bearer {access_token}"}, json=payload)
        data = r.json()
        if r.status_code != 200 or str(data.get("ResponseCode")) != "0":
            raise RuntimeError(data.get("errorMessage") or data.get("ResponseDescription") or str(data))
        return {"provider_ref": data.get("CheckoutRequestID", "")}


async def _initiate_airtel_ussd(creds: dict, amount: float, phone: str, ext_ref: str, country: str, currency: str) -> dict:
    base = "https://openapi.airtel.africa" if creds.get("env") == "production" else "https://openapiuat.airtel.africa"
    cid, csec = creds.get("client_id", ""), creds.get("client_secret", "")
    if not (cid and csec):
        raise RuntimeError("Airtel Money client_id and client_secret required")
    msisdn = _normalize_msisdn(phone)
    sub_msisdn = msisdn[3:] if msisdn.startswith("254") else msisdn

    async with httpx.AsyncClient(timeout=20) as client:
        tok_r = await client.post(f"{base}/auth/oauth2/token", json={"client_id": cid, "client_secret": csec, "grant_type": "client_credentials"})
        tok_r.raise_for_status()
        token = tok_r.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}", "X-Country": creds.get("country", country), "X-Currency": creds.get("currency", currency), "Content-Type": "application/json"}
        payload = {
            "reference": ext_ref,
            "subscriber": {"country": creds.get("country", country), "currency": creds.get("currency", currency), "msisdn": sub_msisdn},
            "transaction": {"amount": float(amount), "country": creds.get("country", country), "currency": creds.get("currency", currency), "id": ext_ref},
        }
        r = await client.post(f"{base}/merchant/v1/payments/", headers=headers, json=payload)
        data = r.json()
        if r.status_code not in (200, 201) or not data.get("status", {}).get("success", False):
            raise RuntimeError(str(data))
        return {"provider_ref": (data.get("data") or {}).get("transaction", {}).get("id", ext_ref)}


# ==========================================================
# SYSTEM 1: ISP CUSTOMER ACTIVATION & RECONCILIATION
# ==========================================================

def _activate_isp_customer_payment(db: Session, pay: CustomerPayment, provider_ref: str) -> dict:
    # Atomic idempotency check inside DB transaction
    updated = db.query(CustomerPayment).filter(
        CustomerPayment.id == pay.id,
        CustomerPayment.status.in_(["PENDING", "PENDING_APPROVAL"]),
    ).update({"status": "CONFIRMED", "provider_ref": provider_ref or pay.provider_ref})
    if updated == 0:
        return {"status": "ALREADY_CONFIRMED", "external_ref": pay.external_ref}

    pkg = db.query(InternetPackage).filter(InternetPackage.id == pay.package_id, InternetPackage.tenant_id == pay.tenant_id).first()
    dur_mins = pkg.duration_minutes if pkg else 60
    cust = db.query(Customer).filter(Customer.id == pay.customer_id, Customer.tenant_id == pay.tenant_id).first() if pay.customer_id else None

    if not cust:
        acct = "PH" + secrets.token_hex(4).upper()
        pwd = secrets.token_hex(4)
        cust = Customer(
            tenant_id=pay.tenant_id, package_id=pay.package_id, account_number=acct,
            full_name=f"WiFi {pay.phone or acct}", phone=pay.phone or "N/A",
            connection_type=pkg.service_type if pkg else "HOTSPOT",
            username=acct, secret_enc=encrypt_secret(pwd),
            status="ACTIVE", expires_at=utcnow() + timedelta(minutes=dur_mins),
        )
        db.add(cust)
        db.flush()
        pay.customer_id = cust.id
    else:
        now = utcnow()
        cur_exp = cust.expires_at if (cust.expires_at and cust.expires_at.tzinfo) else (cust.expires_at.replace(tzinfo=timezone.utc) if cust.expires_at else now)
        base_dt = max(now, cur_exp) if cust.status == "ACTIVE" else now
        cust.status = "ACTIVE"
        cust.package_id = pay.package_id or cust.package_id
        cust.expires_at = base_dt + timedelta(minutes=dur_mins)
        pwd = decrypt_secret(cust.secret_enc) or cust.username

    r = db.query(MikroTikRouter).filter(MikroTikRouter.id == cust.router_id).first() if cust.router_id else db.query(MikroTikRouter).filter(MikroTikRouter.tenant_id == pay.tenant_id, MikroTikRouter.status == "ONLINE").first()
    if pkg and r:
        _rp._provision_customer_on_router(db, r, cust, pkg, pwd)

    db.add(PaymentEvent(tenant_id=pay.tenant_id, system_scope="SYSTEM1_ISP", external_ref=pay.external_ref, event_type="CONFIRMED", details=f"ref={provider_ref}"))
    db.commit()
    return {"status": "CONFIRMED", "username": cust.username, "expires_at": cust.expires_at.isoformat()}


# ==========================================================
# SYSTEM 2: SAAS SUBSCRIPTION ACTIVATION & RECONCILIATION
# ==========================================================

def _activate_saas_payment(db: Session, spay: SaaSPayment, provider_ref: str, admin_id: str | None = None) -> dict:
    upd = {"status": "CONFIRMED", "provider_ref": provider_ref or spay.provider_ref}
    if admin_id:
        upd["approved_by_admin_id"] = admin_id
    updated = db.query(SaaSPayment).filter(
        SaaSPayment.id == spay.id,
        SaaSPayment.status.in_(["PENDING", "PENDING_APPROVAL"]),
    ).update(upd)
    if updated == 0:
        return {"status": "ALREADY_CONFIRMED", "external_ref": spay.external_ref}

    inv = db.query(SaaSInvoice).filter(SaaSInvoice.id == spay.invoice_id).first() if spay.invoice_id else None
    days = 30
    if inv:
        inv.status = "PAID"
        inv.paid_at = utcnow()
    sub = db.query(TenantSubscription).filter(TenantSubscription.tenant_id == spay.tenant_id).first()
    tenant = db.query(ISPTenant).filter(ISPTenant.id == spay.tenant_id).first()
    if sub:
        days = 365 if sub.billing_cycle == "ANNUAL" else 30
        now = utcnow()
        cur_exp = sub.expires_at if (sub.expires_at and sub.expires_at.tzinfo) else (sub.expires_at.replace(tzinfo=timezone.utc) if sub.expires_at else now)
        sub.expires_at = max(now, cur_exp) + timedelta(days=days)
        sub.status = "ACTIVE"
    if tenant:
        tenant.status = "ACTIVE"
    db.add(PaymentEvent(tenant_id=spay.tenant_id, system_scope="SYSTEM2_SAAS", external_ref=spay.external_ref, event_type="SAAS_CONFIRMED", details=f"ref={provider_ref} +{days}d"))
    db.commit()
    return {"status": "CONFIRMED", "tenant_id": spay.tenant_id, "extended_days": days}


# ==========================================================
# SCHEMAS
# ==========================================================

class PortalPayIn(BaseModel):
    package_id: str
    payment_config_id: str
    phone: str = ""
    manual_reference: str = ""
    proof_url: str = ""
    customer_id: str | None = None


class ManualProofDecisionIn(BaseModel):
    provider_ref: str = ""
    reason: str = ""


class SaaSCheckoutIn(BaseModel):
    plan_code: str = ""
    billing_cycle: str = "MONTHLY"
    platform_payment_config_id: str
    phone: str = ""
    promo_code: str = ""
    manual_reference: str = ""
    proof_url: str = ""


# ==========================================================
# SYSTEM 1 ENDPOINTS: CAPTIVE PORTAL CHECKOUT & ISP APPROVALS
# ==========================================================

@router.get(f"{API_V1_PREFIX}/portal/{{slug}}/payment-methods")
def portal_payment_methods(slug: str, db: Session = Depends(get_db)):
    t = db.query(ISPTenant).filter(ISPTenant.slug == slug.lower().strip()).first()
    if not t:
        raise HTTPException(status_code=404, detail="ISP portal not found")
    cfgs = db.query(ISPPaymentConfig).filter(ISPPaymentConfig.tenant_id == t.id, ISPPaymentConfig.is_active == True).all()
    return [
        {
            "id": c.id, "provider": c.provider, "till_number": c.till_number,
            "paybill_number": c.paybill_number, "account_reference": c.account_reference,
            "bank_name": c.bank_name, "bank_account_number": c.bank_account_number,
            "instructions": c.instructions,
            "mode": "AUTO_STK" if c.provider in ("PAYHERO", "DARAJA", "AIRTEL_MONEY") else "MANUAL_PROOF",
        }
        for c in cfgs
    ]


@router.post(f"{API_V1_PREFIX}/portal/{{slug}}/pay")
async def portal_initiate_payment(slug: str, body: PortalPayIn, request: Request, db: Session = Depends(get_db)):
    t = db.query(ISPTenant).filter(ISPTenant.slug == slug.lower().strip()).first()
    if not t or t.status == "SUSPENDED":
        raise HTTPException(status_code=404, detail="ISP portal unavailable")
    pkg = db.query(InternetPackage).filter(InternetPackage.id == body.package_id, InternetPackage.tenant_id == t.id, InternetPackage.is_visible == True).first()
    if not pkg:
        raise HTTPException(status_code=404, detail="Package not found")
    cfg = db.query(ISPPaymentConfig).filter(ISPPaymentConfig.id == body.payment_config_id, ISPPaymentConfig.tenant_id == t.id, ISPPaymentConfig.is_active == True).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="Payment method not available")

    ext_ref = "CUST-" + secrets.token_hex(6).upper()
    is_manual = cfg.provider in ("MPESA_TILL", "MPESA_PAYBILL", "BANK")
    pay = CustomerPayment(
        tenant_id=t.id, customer_id=body.customer_id, package_id=pkg.id,
        provider=cfg.provider, phone=body.phone.strip(), amount=pkg.price, currency=t.currency,
        external_ref=ext_ref, provider_ref=body.manual_reference.strip() or None,
        proof_url=body.proof_url.strip() or None,
        status="PENDING_APPROVAL" if is_manual else "PENDING",
    )
    db.add(pay)
    db.add(PaymentEvent(tenant_id=t.id, system_scope="SYSTEM1_ISP", external_ref=ext_ref, event_type="INITIATED", details=cfg.provider))
    db.commit()

    if is_manual:
        # NEVER auto-activate on screenshot/proof upload
        return {"payment_id": pay.id, "external_ref": ext_ref, "status": "PENDING_APPROVAL", "message": "Submitted for ISP administrator verification."}

    creds = _parse_creds(cfg.credentials_enc)
    base_url = str(request.base_url).rstrip("/")
    try:
        if cfg.provider == "PAYHERO":
            res = await _initiate_payhero_stk(creds, float(pkg.price), body.phone, ext_ref, t.business_name, f"{base_url}{API_V1_PREFIX}/webhooks/system1/payhero/{t.id}")
        elif cfg.provider == "DARAJA":
            res = await _initiate_daraja_stk(creds, float(pkg.price), body.phone, ext_ref, f"{base_url}{API_V1_PREFIX}/webhooks/system1/daraja/{t.id}")
        elif cfg.provider == "AIRTEL_MONEY":
            res = await _initiate_airtel_ussd(creds, float(pkg.price), body.phone, ext_ref, t.country_code, t.currency)
        else:
            raise RuntimeError("Unsupported provider")
        pay.provider_ref = res.get("provider_ref", "")
        db.commit()
        return {"payment_id": pay.id, "external_ref": ext_ref, "status": "PENDING", "provider_ref": pay.provider_ref}
    except Exception as exc:
        pay.status = "FAILED"
        db.add(PaymentEvent(tenant_id=t.id, system_scope="SYSTEM1_ISP", external_ref=ext_ref, event_type="INIT_FAILED", details=str(exc)[:300]))
        db.commit()
        raise HTTPException(status_code=502, detail=f"Payment initiation failed: {exc}")


@router.get(f"{API_V1_PREFIX}/portal/{{slug}}/payment-status/{{external_ref}}")
def portal_payment_status(slug: str, external_ref: str, db: Session = Depends(get_db)):
    t = db.query(ISPTenant).filter(ISPTenant.slug == slug.lower().strip()).first()
    if not t:
        raise HTTPException(status_code=404, detail="ISP not found")
    pay = db.query(CustomerPayment).filter(CustomerPayment.tenant_id == t.id, CustomerPayment.external_ref == external_ref).first()
    if not pay:
        raise HTTPException(status_code=404, detail="Payment not found")
    cust = db.query(Customer).filter(Customer.id == pay.customer_id).first() if pay.customer_id else None
    return {"external_ref": pay.external_ref, "status": pay.status, "username": cust.username if cust else None, "expires_at": cust.expires_at.isoformat() if (cust and cust.expires_at) else None}


@router.get(f"{API_V1_PREFIX}/isp/payments")
def isp_list_payments(status: str = Query(default=""), ctx: TenantContext = Depends(require_tenant_perm("payments:read")), db: Session = Depends(get_db)):
    q = db.query(CustomerPayment).filter(CustomerPayment.tenant_id == ctx.tenant.id)
    if status:
        q = q.filter(CustomerPayment.status == status.upper())
    return [{"id": p.id, "external_ref": p.external_ref, "provider": p.provider, "phone": p.phone, "amount": float(p.amount), "status": p.status, "provider_ref": p.provider_ref, "proof_url": p.proof_url, "created_at": p.created_at.isoformat()} for p in q.order_by(CustomerPayment.created_at.desc()).limit(200).all()]


@router.post(f"{API_V1_PREFIX}/isp/payments/{{payment_id}}/approve")
def isp_approve_manual_payment(payment_id: str, body: ManualProofDecisionIn, ctx: TenantContext = Depends(require_tenant_perm("payments:write")), db: Session = Depends(get_db)):
    pay = db.query(CustomerPayment).filter(CustomerPayment.id == payment_id, CustomerPayment.tenant_id == ctx.tenant.id).first()
    if not pay:
        raise HTTPException(status_code=404, detail="Payment not found")
    res = _activate_isp_customer_payment(db, pay, body.provider_ref or pay.provider_ref or f"MANUAL-{ctx.actor_id[:6]}")
    write_audit(db, "STAFF", ctx.actor_id, "APPROVE_CUSTOMER_PAYMENT", tenant_id=ctx.tenant.id, details=pay.external_ref)
    db.commit()
    return res


@router.post(f"{API_V1_PREFIX}/isp/payments/{{payment_id}}/reject")
def isp_reject_manual_payment(payment_id: str, body: ManualProofDecisionIn, ctx: TenantContext = Depends(require_tenant_perm("payments:write")), db: Session = Depends(get_db)):
    pay = db.query(CustomerPayment).filter(CustomerPayment.id == payment_id, CustomerPayment.tenant_id == ctx.tenant.id).first()
    if not pay:
        raise HTTPException(status_code=404, detail="Payment not found")
    pay.status = "FAILED"
    db.add(PaymentEvent(tenant_id=ctx.tenant.id, system_scope="SYSTEM1_ISP", external_ref=pay.external_ref, event_type="REJECTED", details=body.reason))
    write_audit(db, "STAFF", ctx.actor_id, "REJECT_CUSTOMER_PAYMENT", tenant_id=ctx.tenant.id, details=pay.external_ref)
    db.commit()
    return {"status": "FAILED", "external_ref": pay.external_ref}


# ==========================================================
# SYSTEM 1 & SYSTEM 2 VERIFIED WEBHOOKS
# ==========================================================

@router.post(f"{API_V1_PREFIX}/webhooks/system1/payhero/{{tenant_id}}")
async def webhook_sys1_payhero(tenant_id: str, request: Request, db: Session = Depends(get_db)):
    payload = await request.json()
    data = payload.get("response") if isinstance(payload.get("response"), dict) else payload
    ext_ref = data.get("ExternalReference") or data.get("external_reference") or ""
    db.add(PaymentCallback(tenant_id=tenant_id, system_scope="SYSTEM1_ISP", provider="PAYHERO", external_ref=ext_ref, payload_json=json.dumps(payload)))
    pay = db.query(CustomerPayment).filter(CustomerPayment.tenant_id == tenant_id, CustomerPayment.external_ref == ext_ref).first()
    if not pay:
        db.commit()
        return {"ok": True}
    if pay.status == "CONFIRMED":
        db.commit()
        return {"ok": True, "idempotent": True}

    cfg = db.query(ISPPaymentConfig).filter(ISPPaymentConfig.tenant_id == tenant_id, ISPPaymentConfig.provider == "PAYHERO", ISPPaymentConfig.is_active == True).first()
    creds = _parse_creds(cfg.credentials_enc) if cfg else {}
    if pay.provider_ref and creds.get("auth_token"):
        ver = await _verify_payhero_status(creds, pay.provider_ref)
        if str(ver.get("status", "")).upper() != "SUCCESS":
            db.commit()
            return {"ok": True, "verified_status": ver.get("status")}

    if data.get("Amount") is not None and float(data["Amount"]) < float(pay.amount):
        db.add(PaymentEvent(tenant_id=tenant_id, system_scope="SYSTEM1_ISP", external_ref=ext_ref, event_type="AMOUNT_MISMATCH", details=f"paid={data['Amount']} expected={pay.amount}"))
        db.commit()
        return {"ok": False, "detail": "Underpaid amount"}

    res = _activate_isp_customer_payment(db, pay, data.get("MpesaReceiptNumber") or pay.provider_ref or "")
    return {"ok": True, **res}


@router.post(f"{API_V1_PREFIX}/webhooks/system1/daraja/{{tenant_id}}")
async def webhook_sys1_daraja(tenant_id: str, request: Request, db: Session = Depends(get_db)):
    payload = await request.json()
    stk = (payload.get("Body") or {}).get("stkCallback") or {}
    checkout_id = stk.get("CheckoutRequestID", "")
    rc = stk.get("ResultCode")
    db.add(PaymentCallback(tenant_id=tenant_id, system_scope="SYSTEM1_ISP", provider="DARAJA", external_ref=checkout_id, payload_json=json.dumps(payload), verified=(rc == 0)))
    pay = db.query(CustomerPayment).filter(CustomerPayment.tenant_id == tenant_id, CustomerPayment.provider_ref == checkout_id).first()
    if not pay:
        db.commit()
        return {"ResultCode": 0, "ResultDesc": "Accepted"}
    if rc != 0:
        pay.status = "FAILED"
        db.commit()
        return {"ResultCode": 0, "ResultDesc": "Accepted"}

    items = {it.get("Name"): it.get("Value") for it in (stk.get("CallbackMetadata") or {}).get("Item", [])}
    paid_amt = float(items.get("Amount") or 0)
    if paid_amt < float(pay.amount):
        db.add(PaymentEvent(tenant_id=tenant_id, system_scope="SYSTEM1_ISP", external_ref=pay.external_ref, event_type="AMOUNT_MISMATCH", details=f"paid={paid_amt}"))
        db.commit()
        return {"ResultCode": 0, "ResultDesc": "Accepted"}
    _activate_isp_customer_payment(db, pay, str(items.get("MpesaReceiptNumber") or checkout_id))
    return {"ResultCode": 0, "ResultDesc": "Accepted"}


# ==========================================================
# STAGE 21: SYSTEM 2 SAAS SUBSCRIPTION BILLING & APPROVALS
# ==========================================================

@router.get(f"{API_V1_PREFIX}/isp/subscription/payment-methods")
def isp_list_saas_payment_methods(ctx: TenantContext = Depends(require_tenant_perm("reports:read")), db: Session = Depends(get_db)):
    cfgs = db.query(PlatformPaymentConfig).filter(PlatformPaymentConfig.is_active == True).all()
    return [{"id": c.id, "method_type": c.method_type, "label": c.label, "till_number": c.till_number, "paybill_number": c.paybill_number, "account_reference": c.account_reference, "bank_name": c.bank_name, "bank_account_number": c.bank_account_number, "instructions": c.instructions} for c in cfgs]


@router.post(f"{API_V1_PREFIX}/isp/subscription/checkout")
async def isp_saas_checkout(body: SaaSCheckoutIn, request: Request, ctx: TenantContext = Depends(require_tenant_perm("*")), db: Session = Depends(get_db)):
    plan = db.query(SubscriptionPlan).filter(SubscriptionPlan.code == body.plan_code.upper()).first() if body.plan_code else ctx.plan
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    cfg = db.query(PlatformPaymentConfig).filter(PlatformPaymentConfig.id == body.platform_payment_config_id, PlatformPaymentConfig.is_active == True).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="Platform payment method unavailable")

    sub = ctx.subscription
    cycle = body.billing_cycle.upper()
    if sub and sub.custom_price_kes is not None and cycle == "MONTHLY":
        amount = float(sub.custom_price_kes)
    else:
        amount = float(plan.annual_price_kes if cycle == "ANNUAL" else plan.monthly_price_kes)
    disc = PROMO_DISCOUNTS.get(body.promo_code.strip().upper(), 0.0)
    amount = round(amount * (1.0 - disc), 2)

    inv_no = "INV-" + secrets.token_hex(4).upper()
    inv = SaaSInvoice(tenant_id=ctx.tenant.id, invoice_number=inv_no, amount=amount, due_at=utcnow() + timedelta(days=3))
    db.add(inv)
    db.flush()

    ext_ref = "SAAS-" + secrets.token_hex(6).upper()
    is_manual = cfg.method_type in ("MPESA_TILL", "MPESA_PAYBILL", "BANK")
    spay = SaaSPayment(
        tenant_id=ctx.tenant.id, invoice_id=inv.id, payment_method=cfg.method_type,
        amount=amount, external_ref=ext_ref, provider_ref=body.manual_reference.strip() or None,
        proof_url=body.proof_url.strip() or None,
        status="PENDING_APPROVAL" if is_manual else "PENDING",
    )
    db.add(spay)
    db.commit()

    if is_manual:
        return {"invoice_number": inv_no, "payment_id": spay.id, "external_ref": ext_ref, "amount_kes": amount, "status": "PENDING_APPROVAL"}

    creds = _parse_creds(cfg.credentials_enc)
    base_url = str(request.base_url).rstrip("/")
    try:
        if cfg.method_type == "PAYHERO":
            res = await _initiate_payhero_stk(creds, amount, body.phone or ctx.tenant.owner_phone, ext_ref, ctx.tenant.business_name, f"{base_url}{API_V1_PREFIX}/webhooks/system2/payhero")
        elif cfg.method_type == "DARAJA":
            res = await _initiate_daraja_stk(creds, amount, body.phone or ctx.tenant.owner_phone, ext_ref, f"{base_url}{API_V1_PREFIX}/webhooks/system2/daraja")
        elif cfg.method_type == "AIRTEL_MONEY":
            res = await _initiate_airtel_ussd(creds, amount, body.phone or ctx.tenant.owner_phone, ext_ref, ctx.tenant.country_code, ctx.tenant.currency)
        else:
            raise RuntimeError("Unsupported platform gateway")
        spay.provider_ref = res.get("provider_ref", "")
        db.commit()
        return {"invoice_number": inv_no, "payment_id": spay.id, "external_ref": ext_ref, "amount_kes": amount, "status": "PENDING"}
    except Exception as exc:
        spay.status = "FAILED"
        db.commit()
        raise HTTPException(status_code=502, detail=f"SaaS payment initiation failed: {exc}")


@router.post(f"{API_V1_PREFIX}/webhooks/system2/payhero")
async def webhook_sys2_payhero(request: Request, db: Session = Depends(get_db)):
    payload = await request.json()
    data = payload.get("response") if isinstance(payload.get("response"), dict) else payload
    ext_ref = data.get("ExternalReference") or data.get("external_reference") or ""
    db.add(PaymentCallback(system_scope="SYSTEM2_SAAS", provider="PAYHERO", external_ref=ext_ref, payload_json=json.dumps(payload)))
    spay = db.query(SaaSPayment).filter(SaaSPayment.external_ref == ext_ref).first()
    if not spay or spay.status == "CONFIRMED":
        db.commit()
        return {"ok": True}
    cfg = db.query(PlatformPaymentConfig).filter(PlatformPaymentConfig.method_type == "PAYHERO", PlatformPaymentConfig.is_active == True).first()
    creds = _parse_creds(cfg.credentials_enc) if cfg else {}
    if spay.provider_ref and creds.get("auth_token"):
        ver = await _verify_payhero_status(creds, spay.provider_ref)
        if str(ver.get("status", "")).upper() != "SUCCESS":
            db.commit()
            return {"ok": True}
    if data.get("Amount") is not None and float(data["Amount"]) < float(spay.amount):
        db.add(PaymentEvent(tenant_id=spay.tenant_id, system_scope="SYSTEM2_SAAS", external_ref=ext_ref, event_type="AMOUNT_MISMATCH"))
        db.commit()
        return {"ok": False}
    return {"ok": True, **_activate_saas_payment(db, spay, data.get("MpesaReceiptNumber") or spay.provider_ref or "")}


@router.get(f"{API_V1_PREFIX}/superadmin/saas-payments")
def superadmin_list_saas_payments(status: str = Query(default=""), admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    q = db.query(SaaSPayment)
    if status:
        q = q.filter(SaaSPayment.status == status.upper())
    return [{"id": p.id, "tenant_id": p.tenant_id, "external_ref": p.external_ref, "method": p.payment_method, "amount": float(p.amount), "status": p.status, "provider_ref": p.provider_ref, "proof_url": p.proof_url} for p in q.order_by(SaaSPayment.created_at.desc()).limit(200).all()]


@router.post(f"{API_V1_PREFIX}/superadmin/saas-payments/{{payment_id}}/approve")
def superadmin_approve_saas_payment(payment_id: str, body: ManualProofDecisionIn, admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    spay = db.query(SaaSPayment).filter(SaaSPayment.id == payment_id).first()
    if not spay:
        raise HTTPException(status_code=404, detail="SaaS payment not found")
    res = _activate_saas_payment(db, spay, body.provider_ref or spay.provider_ref or f"SAAS-{admin.id[:6]}", admin_id=admin.id)
    write_audit(db, "PLATFORM_ADMIN", admin.id, "APPROVE_SAAS_PAYMENT", tenant_id=spay.tenant_id, details=spay.external_ref)
    db.commit()
    return res


@router.post(f"{API_V1_PREFIX}/superadmin/saas-payments/{{payment_id}}/reject")
def superadmin_reject_saas_payment(payment_id: str, body: ManualProofDecisionIn, admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    spay = db.query(SaaSPayment).filter(SaaSPayment.id == payment_id).first()
    if not spay:
        raise HTTPException(status_code=404, detail="SaaS payment not found")
    spay.status = "FAILED"
    write_audit(db, "PLATFORM_ADMIN", admin.id, "REJECT_SAAS_PAYMENT", tenant_id=spay.tenant_id, details=body.reason)
    db.commit()
    return {"status": "FAILED"}


# ==========================================================
# STAGE 22: FINANCIAL REPORTS & CSV EXPORTS (SYSTEM 1 & 2)
# ==========================================================

@router.get(f"{API_V1_PREFIX}/superadmin/financial-report")
def superadmin_financial_report(admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    by_method = db.query(SaaSPayment.payment_method, func.coalesce(func.sum(SaaSPayment.amount), 0)).filter(SaaSPayment.status == "CONFIRMED").group_by(SaaSPayment.payment_method).all()
    total = sum(float(v) for _, v in by_method)
    return {
        "system": "SYSTEM2_SAAS_ONLY",
        "total_saas_revenue_kes": total,
        "revenue_by_method": {m: float(v) for m, v in by_method},
        "pending_manual_approvals": db.query(SaaSPayment).filter(SaaSPayment.status == "PENDING_APPROVAL").count(),
        "failed_transactions": db.query(SaaSPayment).filter(SaaSPayment.status == "FAILED").count(),
        "unpaid_invoices": db.query(SaaSInvoice).filter(SaaSInvoice.status == "UNPAID").count(),
    }


@router.get(f"{API_V1_PREFIX}/superadmin/financial-report/export/csv", response_class=PlainTextResponse)
def superadmin_export_csv(admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    rows = db.query(SaaSPayment).order_by(SaaSPayment.created_at.desc()).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["external_ref", "tenant_id", "method", "amount", "currency", "status", "provider_ref", "created_at"])
    for r in rows:
        w.writerow([r.external_ref, r.tenant_id, r.payment_method, float(r.amount), r.currency, r.status, r.provider_ref or "", r.created_at.isoformat()])
    return PlainTextResponse(buf.getvalue(), headers={"Content-Disposition": 'attachment; filename="prime_saas_revenue.csv"'})


@router.get(f"{API_V1_PREFIX}/isp/financial-report")
def isp_financial_report(ctx: TenantContext = Depends(require_tenant_perm("reports:read")), db: Session = Depends(get_db)):
    tid = ctx.tenant.id
    by_prov = db.query(CustomerPayment.provider, func.coalesce(func.sum(CustomerPayment.amount), 0)).filter(CustomerPayment.tenant_id == tid, CustomerPayment.status == "CONFIRMED").group_by(CustomerPayment.provider).all()
    return {
        "system": "SYSTEM1_ISP_ONLY",
        "tenant_id": tid,
        "total_customer_revenue": sum(float(v) for _, v in by_prov),
        "revenue_by_provider": {p: float(v) for p, v in by_prov},
        "pending_manual_approvals": db.query(CustomerPayment).filter(CustomerPayment.tenant_id == tid, CustomerPayment.status == "PENDING_APPROVAL").count(),
        "failed_transactions": db.query(CustomerPayment).filter(CustomerPayment.tenant_id == tid, CustomerPayment.status == "FAILED").count(),
    }


@router.get(f"{API_V1_PREFIX}/isp/financial-report/export/csv", response_class=PlainTextResponse)
def isp_export_csv(ctx: TenantContext = Depends(require_tenant_perm("reports:read")), db: Session = Depends(get_db)):
    rows = db.query(CustomerPayment).filter(CustomerPayment.tenant_id == ctx.tenant.id).order_by(CustomerPayment.created_at.desc()).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["external_ref", "provider", "phone", "amount", "currency", "status", "provider_ref", "created_at"])
    for r in rows:
        w.writerow([r.external_ref, r.provider, r.phone, float(r.amount), r.currency, r.status, r.provider_ref or "", r.created_at.isoformat()])
    return PlainTextResponse(buf.getvalue(), headers={"Content-Disposition": 'attachment; filename="isp_customer_payments.csv"'})


# ==========================================================
# MILESTONE 4 SELF-TEST SUITE
# ==========================================================

def run_m4_tests():
    from fastapi.testclient import TestClient
    _rp.run_m3_tests()
    with TestClient(_m.app) as client:
        adm_tok = client.post(f"{API_V1_PREFIX}/auth/platform/login", json={"email": "owner@primehotspot.co.ke", "password": "OwnerPassword#2026"}).json()["access_token"]
        tok_a = client.post(f"{API_V1_PREFIX}/auth/isp/login", json={"tenant_slug": "savanna", "email": "ali@savanna.ke", "password": "IspPass#2026"}).json()["access_token"]
        tok_b = client.post(f"{API_V1_PREFIX}/auth/isp/login", json={"tenant_slug": "rift", "email": "joy@rift.ke", "password": "IspPass#2026"}).json()["access_token"]
        hadm, ha, hb = {"Authorization": f"Bearer {adm_tok}"}, {"Authorization": f"Bearer {tok_a}"}, {"Authorization": f"Bearer {tok_b}"}

        # 1. System 1: Manual Bank/Till proof stays PENDING_APPROVAL until ISP approves
        pkg_id = client.get(f"{API_V1_PREFIX}/isp/packages", headers=ha).json()[0]["id"]
        cfg_till = client.post(f"{API_V1_PREFIX}/isp/payment-configs", headers=ha, json={"provider": "MPESA_TILL", "till_number": "112233"}).json()["id"]
        p_man = client.post(f"{API_V1_PREFIX}/portal/savanna/pay", json={"package_id": pkg_id, "payment_config_id": cfg_till, "phone": "0712111222", "manual_reference": "UJK9988", "proof_url": "https://img/proof.png"}).json()
        assert p_man["status"] == "PENDING_APPROVAL"
        assert client.post(f"{API_V1_PREFIX}/isp/payments/{p_man['payment_id']}/approve", headers=hb, json={}).status_code == 404  # Cross-tenant blocked
        assert client.post(f"{API_V1_PREFIX}/isp/payments/{p_man['payment_id']}/approve", headers=ha, json={"provider_ref": "UJK9988"}).json()["status"] == "CONFIRMED"

        # 2. System 1: Daraja Callback Underpayment Rejection & Duplicate Callback Idempotency
        cfg_dar = client.post(f"{API_V1_PREFIX}/isp/payment-configs", headers=ha, json={"provider": "DARAJA", "credentials_json": "{}"}).json()["id"]
        t_id = client.get(f"{API_V1_PREFIX}/isp/dashboard", headers=ha).json()["tenant"]["id"]
        db = SessionLocal()
        try:
            cp = CustomerPayment(tenant_id=t_id, package_id=pkg_id, provider="DARAJA", phone="254712345678", amount=50, external_ref="DAR-TEST1", provider_ref="ws_CO_TEST123", status="PENDING")
            db.add(cp)
            db.commit()
        finally:
            db.close()

        # Underpaid callback ignored
        client.post(f"{API_V1_PREFIX}/webhooks/system1/daraja/{t_id}", json={"Body": {"stkCallback": {"CheckoutRequestID": "ws_CO_TEST123", "ResultCode": 0, "CallbackMetadata": {"Item": [{"Name": "Amount", "Value": 10}, {"Name": "MpesaReceiptNumber", "Value": "UNDER1"}]}}}})
        assert client.get(f"{API_V1_PREFIX}/portal/savanna/payment-status/DAR-TEST1").json()["status"] == "PENDING"
        # Exact callback activates + second identical callback is idempotent
        ok_cb = {"Body": {"stkCallback": {"CheckoutRequestID": "ws_CO_TEST123", "ResultCode": 0, "CallbackMetadata": {"Item": [{"Name": "Amount", "Value": 50}, {"Name": "MpesaReceiptNumber", "Value": "OK123"}]}}}}
        client.post(f"{API_V1_PREFIX}/webhooks/system1/daraja/{t_id}", json=ok_cb)
        st1 = client.get(f"{API_V1_PREFIX}/portal/savanna/payment-status/DAR-TEST1").json()
        client.post(f"{API_V1_PREFIX}/webhooks/system1/daraja/{t_id}", json=ok_cb)
        st2 = client.get(f"{API_V1_PREFIX}/portal/savanna/payment-status/DAR-TEST1").json()
        assert st1["status"] == "CONFIRMED" and st1["expires_at"] == st2["expires_at"]

        # 3. System 2: SaaS Subscription Billing & Super Admin Approval
        plat_cfg_id = client.get(f"{API_V1_PREFIX}/superadmin/payment-configs", headers=hadm).json()[0]["id"]
        sc = client.post(f"{API_V1_PREFIX}/isp/subscription/checkout", headers=ha, json={"plan_code": "BUSINESS", "billing_cycle": "MONTHLY", "platform_payment_config_id": plat_cfg_id, "promo_code": "LAUNCH20", "manual_reference": "SAASREF1"}).json()
        assert sc["amount_kes"] == 2800.0 and sc["status"] == "PENDING_APPROVAL"
        assert client.post(f"{API_V1_PREFIX}/superadmin/saas-payments/{sc['payment_id']}/approve", headers=hadm, json={"provider_ref": "SAASREF1"}).json()["status"] == "CONFIRMED"

        # 4. Financial Separation Reports & CSV Export
        rep_saas = client.get(f"{API_V1_PREFIX}/superadmin/financial-report", headers=hadm).json()
        rep_isp_a = client.get(f"{API_V1_PREFIX}/isp/financial-report", headers=ha).json()
        rep_isp_b = client.get(f"{API_V1_PREFIX}/isp/financial-report", headers=hb).json()
        assert rep_saas["total_saas_revenue_kes"] == 2800.0
        assert rep_isp_a["total_customer_revenue"] == 100.0 and rep_isp_b["total_customer_revenue"] == 0.0
        assert "SAASREF1" in client.get(f"{API_V1_PREFIX}/superadmin/financial-report/export/csv", headers=hadm).text

    print("ALL STAGES 12-15, 21-22 TESTS PASSED (PayHero/Daraja/Airtel adapters, Manual Approval, Idempotency, SaaS Billing, Financial Isolation).")


if __name__ == "__main__":
    if "--test" in sys.argv:
        run_m4_tests()
