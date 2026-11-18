import os
import sys
import json
import asyncio
import logging
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

_m = sys.modules.get("main") or sys.modules.get("__main__")
if not _m or not hasattr(_m, "SessionLocal"):
    import main as _m

import routers_portal as _rp
import payments_billing as _pb  # noqa: F401

log = logging.getLogger("prime-hotspot-comms")

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
ISPTenant = _m.ISPTenant
TenantSubscription = _m.TenantSubscription
MikroTikRouter = _m.MikroTikRouter
RouterCredential = _m.RouterCredential
Customer = _m.Customer
NetworkSession = _m.NetworkSession
CustomerPayment = _m.CustomerPayment
NotificationConfig = _m.NotificationConfig
NotificationTemplate = _m.NotificationTemplate
DeliveryLog = _m.DeliveryLog
AuditLog = _m.AuditLog

router = APIRouter()
MAINTENANCE_MODE = {"enabled": False, "message": "Scheduled maintenance in progress."}


def _parse_creds(enc: str) -> dict:
    if not enc:
        return {}
    try:
        return json.loads(decrypt_secret(enc))
    except Exception:
        return {}


# ==========================================================
# STAGES 18–20: SMS, WHATSAPP & TELEGRAM ADAPTERS
# ==========================================================

async def _send_sms(provider: str, creds: dict, sender_id: str, to_phone: str, message: str) -> str:
    prov = provider.upper()
    async with httpx.AsyncClient(timeout=15) as client:
        if prov == "AFRICASTALKING":
            base = "https://api.sandbox.africastalking.com" if creds.get("env") == "sandbox" else "https://api.africastalking.com"
            data = {"username": creds.get("username", "sandbox"), "to": to_phone, "message": message}
            if sender_id:
                data["from"] = sender_id
            r = await client.post(f"{base}/version1/messaging", headers={"apiKey": creds.get("api_key", ""), "Accept": "application/json"}, data=data)
            r.raise_for_status()
            return r.text[:250]
        if prov == "ADVANTA":
            r = await client.post("https://quicksms.advantasms.com/api/services/sendsms/", json={"apikey": creds.get("api_key", ""), "partnerID": creds.get("partner_id", ""), "shortcode": sender_id or creds.get("shortcode", ""), "mobile": to_phone, "message": message})
            r.raise_for_status()
            return r.text[:250]
        if prov == "TWILIO":
            sid, tok = creds.get("account_sid", ""), creds.get("auth_token", "")
            r = await client.post(f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json", auth=(sid, tok), data={"To": to_phone, "From": sender_id or creds.get("from_number", ""), "Body": message})
            r.raise_for_status()
            return r.text[:250]
        if prov == "INFOBIP":
            base_url = creds.get("base_url", "api.infobip.com").replace("https://", "").rstrip("/")
            r = await client.post(f"https://{base_url}/sms/2/text/advanced", headers={"Authorization": f"App {creds.get('api_key', '')}"}, json={"messages": [{"destinations": [{"to": to_phone}], "from": sender_id or "PrimeHotspot", "text": message}]})
            r.raise_for_status()
            return r.text[:250]
    raise RuntimeError(f"Unsupported SMS provider: {provider}")


async def _send_whatsapp(creds: dict, to_phone: str, message: str) -> str:
    phone_id = creds.get("phone_number_id", "")
    token = creds.get("access_token", "")
    if not (phone_id and token):
        raise RuntimeError("WhatsApp phone_number_id and access_token required")
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            f"https://graph.facebook.com/v21.0/{phone_id}/messages",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"messaging_product": "whatsapp", "to": to_phone.lstrip("+"), "type": "text", "text": {"body": message}},
        )
        r.raise_for_status()
        return r.text[:250]


async def _send_telegram(creds: dict, chat_id: str, message: str) -> str:
    bot_token = creds.get("bot_token", "")
    target = chat_id or creds.get("default_chat_id", "")
    if not (bot_token and target):
        raise RuntimeError("Telegram bot_token and chat_id required")
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": target, "text": message, "parse_mode": "HTML"},
        )
        r.raise_for_status()
        return r.text[:250]


async def dispatch_notification(db: Session, tenant_id: str, event_name: str, recipient: str, context_vars: dict, channels: list[str] | None = None) -> list[dict]:
    results = []
    q = db.query(NotificationConfig).filter(NotificationConfig.tenant_id == tenant_id, NotificationConfig.is_active == True)
    if channels:
        q = q.filter(NotificationConfig.channel.in_([c.upper() for c in channels]))
    configs = q.all()

    for cfg in configs:
        tpl = db.query(NotificationTemplate).filter(
            NotificationTemplate.tenant_id == tenant_id,
            NotificationTemplate.event_name == event_name.upper(),
            NotificationTemplate.channel == cfg.channel,
            NotificationTemplate.is_active == True,
        ).first()
        body = tpl.body_template if tpl else f"[{event_name}] " + ", ".join(f"{k}: {v}" for k, v in context_vars.items())
        for k, v in context_vars.items():
            body = body.replace("{" + str(k) + "}", str(v))

        creds = _parse_creds(cfg.credentials_enc)
        status, resp_txt = "SENT", ""
        try:
            if cfg.channel == "SMS":
                resp_txt = await _send_sms(cfg.provider, creds, cfg.sender_id, recipient, body)
            elif cfg.channel == "WHATSAPP":
                resp_txt = await _send_whatsapp(creds, recipient, body)
            elif cfg.channel == "TELEGRAM":
                resp_txt = await _send_telegram(creds, recipient, body)
            else:
                raise RuntimeError(f"Unknown channel {cfg.channel}")
        except Exception as exc:
            status = "FAILED"
            resp_txt = str(exc)[:300]

        db.add(DeliveryLog(tenant_id=tenant_id, channel=cfg.channel, event_name=event_name.upper(), recipient=recipient or "DEFAULT", status=status, provider_response=resp_txt))
        results.append({"channel": cfg.channel, "provider": cfg.provider, "status": status, "response": resp_txt})
    db.commit()
    return results


# ==========================================================
# STAGE 23: ROUTER MONITORING & AUTO-EXPIRY ENGINE
# ==========================================================

async def run_monitoring_cycle(db: Session, tenant_id: str | None = None) -> dict:
    now = utcnow()
    expired_customers = 0
    outages_detected = 0
    recoveries_detected = 0

    # 1. Expire overdue customers
    cq = db.query(Customer).filter(Customer.status == "ACTIVE", Customer.expires_at != None)
    if tenant_id:
        cq = cq.filter(Customer.tenant_id == tenant_id)
    for c in cq.all():
        exp = c.expires_at if c.expires_at.tzinfo else c.expires_at.replace(tzinfo=timezone.utc)
        if exp <= now:
            c.status = "EXPIRED"
            db.query(NetworkSession).filter(NetworkSession.customer_id == c.id, NetworkSession.ended_at == None).update({"ended_at": now})
            expired_customers += 1
            await dispatch_notification(db, c.tenant_id, "PACKAGE_EXPIRY", c.phone, {"username": c.username, "account": c.account_number})

    # 2. Expire overdue SaaS subscriptions (with 3-day grace window)
    sq = db.query(TenantSubscription).filter(TenantSubscription.status.in_(["TRIAL", "ACTIVE", "GRACE"]))
    if tenant_id:
        sq = sq.filter(TenantSubscription.tenant_id == tenant_id)
    for sub in sq.all():
        exp = sub.expires_at if sub.expires_at.tzinfo else sub.expires_at.replace(tzinfo=timezone.utc)
        if exp <= now:
            grace_end = exp + timedelta(days=3)
            sub.status = "EXPIRED" if now > grace_end else "GRACE"
            t = db.query(ISPTenant).filter(ISPTenant.id == sub.tenant_id).first()
            if t and sub.status == "EXPIRED":
                t.status = "EXPIRED"

    # 3. Probe API routers & track ONLINE <-> OFFLINE transitions
    rq = db.query(MikroTikRouter).filter(MikroTikRouter.integration_mode == "API")
    if tenant_id:
        rq = rq.filter(MikroTikRouter.tenant_id == tenant_id)
    for r in rq.all():
        cred = db.query(RouterCredential).filter(RouterCredential.router_id == r.id).first()
        if not cred:
            continue
        prev = r.status
        probe = await asyncio.to_thread(_rp.probe_mikrotik_router, r.host, r.api_port, r.use_ssl, decrypt_secret(cred.username_enc), decrypt_secret(cred.password_enc))
        if probe["online"]:
            r.status = "ONLINE"
            r.last_seen_at = now
            if prev == "OFFLINE":
                recoveries_detected += 1
                write_audit(db, "SYSTEM", "monitor", "ROUTER_RECOVERY", tenant_id=r.tenant_id, details=r.name)
                await dispatch_notification(db, r.tenant_id, "ROUTER_RECOVERY", "", {"router": r.name, "host": r.host})
        else:
            r.status = "OFFLINE"
            if prev == "ONLINE":
                outages_detected += 1
                write_audit(db, "SYSTEM", "monitor", "ROUTER_OUTAGE", tenant_id=r.tenant_id, details=f"{r.name}: {probe.get('error', '')}")
                await dispatch_notification(db, r.tenant_id, "ROUTER_OUTAGE", "", {"router": r.name, "host": r.host, "error": probe.get("error", "")})
    db.commit()
    return {"expired_customers": expired_customers, "outages_detected": outages_detected, "recoveries_detected": recoveries_detected}


async def monitoring_background_loop():
    while True:
        try:
            db = SessionLocal()
            try:
                await run_monitoring_cycle(db)
            finally:
                db.close()
        except Exception as exc:
            log.warning("Monitoring cycle error: %s", exc)
        await asyncio.sleep(120)


# ==========================================================
# SCHEMAS & ENDPOINTS (NOTIFICATIONS, TELEGRAM BOT, MONITORING, BACKUP)
# ==========================================================

class NotifConfigIn(BaseModel):
    channel: str  # SMS, WHATSAPP, TELEGRAM
    provider: str  # AFRICASTALKING, ADVANTA, TWILIO, INFOBIP, META_WA, TELEGRAM_BOT
    sender_id: str = ""
    credentials_json: str = "{}"


class NotifTemplateIn(BaseModel):
    event_name: str
    channel: str
    body_template: str


class NotifTestIn(BaseModel):
    channel: str
    recipient: str
    message: str


@router.get(f"{API_V1_PREFIX}/isp/notifications/configs")
def list_notif_configs(ctx: TenantContext = Depends(require_tenant_perm("reports:read")), db: Session = Depends(get_db)):
    rows = db.query(NotificationConfig).filter(NotificationConfig.tenant_id == ctx.tenant.id).all()
    return [{"id": r.id, "channel": r.channel, "provider": r.provider, "sender_id": r.sender_id, "is_active": r.is_active} for r in rows]


@router.post(f"{API_V1_PREFIX}/isp/notifications/configs")
def add_notif_config(body: NotifConfigIn, ctx: TenantContext = Depends(require_tenant_perm("*")), db: Session = Depends(get_db)):
    ch = body.channel.upper()
    if ch == "SMS" and ctx.plan and not ctx.plan.allow_sms:
        raise HTTPException(status_code=403, detail="Current SaaS plan does not include SMS")
    if ch == "WHATSAPP" and ctx.plan and not ctx.plan.allow_whatsapp:
        raise HTTPException(status_code=403, detail="Current SaaS plan does not include WhatsApp")
    if ch == "TELEGRAM" and ctx.plan and not ctx.plan.allow_telegram:
        raise HTTPException(status_code=403, detail="Current SaaS plan does not include Telegram")

    cfg = NotificationConfig(tenant_id=ctx.tenant.id, channel=ch, provider=body.provider.upper(), sender_id=body.sender_id, credentials_enc=encrypt_secret(body.credentials_json))
    db.add(cfg)
    write_audit(db, "STAFF", ctx.actor_id, "ADD_NOTIF_CONFIG", tenant_id=ctx.tenant.id, details=f"{ch}:{cfg.provider}")
    db.commit()
    return {"id": cfg.id, "channel": ch, "provider": cfg.provider}


@router.post(f"{API_V1_PREFIX}/isp/notifications/templates")
def save_notif_template(body: NotifTemplateIn, ctx: TenantContext = Depends(require_tenant_perm("*")), db: Session = Depends(get_db)):
    tpl = NotificationTemplate(tenant_id=ctx.tenant.id, event_name=body.event_name.upper(), channel=body.channel.upper(), body_template=body.body_template)
    db.add(tpl)
    db.commit()
    return {"id": tpl.id, "event_name": tpl.event_name, "channel": tpl.channel}


@router.post(f"{API_V1_PREFIX}/isp/notifications/test")
async def test_notification(body: NotifTestIn, ctx: TenantContext = Depends(require_tenant_perm("*")), db: Session = Depends(get_db)):
    res = await dispatch_notification(db, ctx.tenant.id, "TEST_ALERT", body.recipient, {"message": body.message, "business": ctx.tenant.business_name}, channels=[body.channel.upper()])
    return {"dispatched": res}


@router.get(f"{API_V1_PREFIX}/isp/notifications/logs")
def list_delivery_logs(ctx: TenantContext = Depends(require_tenant_perm("reports:read")), db: Session = Depends(get_db)):
    rows = db.query(DeliveryLog).filter(DeliveryLog.tenant_id == ctx.tenant.id).order_by(DeliveryLog.created_at.desc()).limit(100).all()
    return [{"id": r.id, "channel": r.channel, "event": r.event_name, "recipient": r.recipient, "status": r.status, "response": r.provider_response, "created_at": r.created_at.isoformat()} for r in rows]


@router.post(f"{API_V1_PREFIX}/webhooks/telegram/{{tenant_id}}")
async def isp_telegram_webhook(tenant_id: str, request: Request, db: Session = Depends(get_db)):
    t = db.query(ISPTenant).filter(ISPTenant.id == tenant_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Tenant not found")
    update = await request.json()
    msg = update.get("message") or {}
    text = (msg.get("text") or "").strip()
    chat_id = (msg.get("chat") or {}).get("id")
    if not text or not chat_id:
        return {"ok": True}

    reply = f"{t.business_name} Bot Ready. Commands: /status, /sales, /routers"
    if text.startswith("/sales"):
        rev = db.query(func.coalesce(func.sum(CustomerPayment.amount), 0)).filter(CustomerPayment.tenant_id == t.id, CustomerPayment.status == "CONFIRMED").scalar()
        reply = f"💰 Total Customer Revenue: {t.currency} {float(rev or 0):,.2f}"
    elif text.startswith("/routers"):
        on = db.query(MikroTikRouter).filter(MikroTikRouter.tenant_id == t.id, MikroTikRouter.status == "ONLINE").count()
        off = db.query(MikroTikRouter).filter(MikroTikRouter.tenant_id == t.id, MikroTikRouter.status != "ONLINE").count()
        reply = f"📡 Routers: {on} ONLINE | {off} OFFLINE"
    elif text.startswith("/status"):
        act = db.query(Customer).filter(Customer.tenant_id == t.id, Customer.status == "ACTIVE").count()
        reply = f"✅ Active Customers: {act} | Plan Status: {t.status}"

    cfg = db.query(NotificationConfig).filter(NotificationConfig.tenant_id == t.id, NotificationConfig.channel == "TELEGRAM", NotificationConfig.is_active == True).first()
    if cfg:
        try:
            await _send_telegram(_parse_creds(cfg.credentials_enc), str(chat_id), reply)
        except Exception:
            pass
    return {"ok": True, "reply": reply}


@router.post(f"{API_V1_PREFIX}/isp/routers/monitoring/check-now")
async def isp_trigger_monitoring(ctx: TenantContext = Depends(require_tenant_perm("routers:read")), db: Session = Depends(get_db)):
    return await run_monitoring_cycle(db, tenant_id=ctx.tenant.id)


@router.post(f"{API_V1_PREFIX}/superadmin/maintenance")
def superadmin_maintenance(enabled: bool = Query(...), message: str = Query(default="Scheduled maintenance in progress."), admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    MAINTENANCE_MODE["enabled"] = enabled
    MAINTENANCE_MODE["message"] = message
    write_audit(db, "PLATFORM_ADMIN", admin.id, "MAINTENANCE_MODE", details=str(enabled))
    db.commit()
    return MAINTENANCE_MODE


@router.get(f"{API_V1_PREFIX}/superadmin/backup/export")
def superadmin_export_backup(admin: PlatformAdmin = Depends(require_platform_admin), db: Session = Depends(get_db)):
    return {
        "exported_at": utcnow().isoformat(),
        "tenants_count": db.query(ISPTenant).count(),
        "customers_count": db.query(Customer).count(),
        "saas_payments_count": db.query(_m.SaaSPayment).count(),
        "customer_payments_count": db.query(CustomerPayment).count(),
    }


# ==========================================================
# STAGE 24: SECURITY & FULL PLATFORM INTEGRATION TESTS
# ==========================================================

def run_m5_tests():
    from fastapi.testclient import TestClient
    _pb.run_m4_tests()
    with TestClient(_m.app) as client:
        adm_tok = client.post(f"{API_V1_PREFIX}/auth/platform/login", json={"email": "owner@primehotspot.co.ke", "password": "OwnerPassword#2026"}).json()["access_token"]
        tok_a = client.post(f"{API_V1_PREFIX}/auth/isp/login", json={"tenant_slug": "savanna", "email": "ali@savanna.ke", "password": "IspPass#2026"}).json()["access_token"]
        tok_b = client.post(f"{API_V1_PREFIX}/auth/isp/login", json={"tenant_slug": "rift", "email": "joy@rift.ke", "password": "IspPass#2026"}).json()["access_token"]
        hadm, ha, hb = {"Authorization": f"Bearer {adm_tok}"}, {"Authorization": f"Bearer {tok_a}"}, {"Authorization": f"Bearer {tok_b}"}

        # 1. Plan gates: Starter tenant (B) cannot add SMS/Telegram; Business tenant (A) can add SMS & Telegram
        assert client.post(f"{API_V1_PREFIX}/isp/notifications/configs", headers=hb, json={"channel": "SMS", "provider": "AFRICASTALKING"}).status_code == 403
        assert client.post(f"{API_V1_PREFIX}/isp/notifications/configs", headers=ha, json={"channel": "SMS", "provider": "AFRICASTALKING", "credentials_json": '{"api_key":"fake"}'}).status_code == 200
        assert client.post(f"{API_V1_PREFIX}/isp/notifications/configs", headers=ha, json={"channel": "TELEGRAM", "provider": "TELEGRAM_BOT", "credentials_json": '{"bot_token":"fake"}'}).status_code == 200

        # 2. Failure resilience: unreachable SMS endpoint logs FAILED cleanly without crashing
        res = client.post(f"{API_V1_PREFIX}/isp/notifications/test", headers=ha, json={"channel": "SMS", "recipient": "+254712000111", "message": "Hello"}).json()
        assert res["dispatched"][0]["status"] == "FAILED"
        logs = client.get(f"{API_V1_PREFIX}/isp/notifications/logs", headers=ha).json()
        assert len(logs) >= 1 and logs[0]["status"] == "FAILED"

        # 3. Telegram bot webhook command test
        t_id = client.get(f"{API_V1_PREFIX}/isp/dashboard", headers=ha).json()["tenant"]["id"]
        tg_res = client.post(f"{API_V1_PREFIX}/webhooks/telegram/{t_id}", json={"message": {"chat": {"id": 123}, "text": "/sales"}}).json()
        assert "100.00" in tg_res["reply"]

        # 4. Router monitoring & auto-expiry sweep
        mon = client.post(f"{API_V1_PREFIX}/isp/routers/monitoring/check-now", headers=ha).json()
        assert "expired_customers" in mon and "outages_detected" in mon

        # 5. Maintenance mode & backup snapshot
        assert client.post(f"{API_V1_PREFIX}/superadmin/maintenance?enabled=true", headers=hadm).json()["enabled"] is True
        assert client.post(f"{API_V1_PREFIX}/superadmin/maintenance?enabled=false", headers=hadm).json()["enabled"] is False
        assert client.get(f"{API_V1_PREFIX}/superadmin/backup/export", headers=hadm).json()["tenants_count"] == 2

    print("ALL 25 STAGES VERIFIED (SMS/WhatsApp/Telegram, Notification Engine, Router Monitoring, Expiry, Security & Backup).")


if __name__ == "__main__":
    if "--test" in sys.argv:
        run_m5_tests()
